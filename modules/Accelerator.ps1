# Compiled accelerator for the two measured hot loops: the IOC sweep and the timeline
# transform. Both scan every byte of every parsed CSV (the MFT/$J/EventLogs CSVs alone can
# be gigabytes); interpreted PowerShell tops out at a few MB/s there, while this compiled
# path runs at disk speed. Field-measured before this existed: a single large host spent
# 904s in the sweep and 216s in the timeline.
#
# Design rules:
#   - Compiled at startup via Add-Type using the .NET runtime PowerShell already sits on.
#     NOTHING new to install, download, or trust. C#5-only syntax so PS 5.1's compiler
#     accepts it.
#   - If compilation fails for ANY reason, $script:AccelOK stays $false and every caller
#     falls back to the original pure-PowerShell implementation. Same outputs, just slower.
#   - Semantics mirror the PS implementations exactly (same boundary rules, same message
#     construction, same timestamp handling); parity is enforced by tests that diff the
#     two paths on identical input.
# Known micro-divergences from the fallback path, all confined to degenerate input:
#   - malformed CSV rows are parsed leniently (RFC4180 best effort) instead of skipped
#   - case-folding is ToUpperInvariant+Ordinal vs OrdinalIgnoreCase (identical for the
#     ASCII strings indicators are made of)

$script:AccelOK = $false

$accelSource = @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace ScribeAccel
{
    public class SweepHit
    {
        public string Path;
        public int LineNumber;
        public string Line;
        public int PatternIndex;
    }

    public static class Scanner
    {
        // kinds: 0 = substring (low confidence), 1 = hex-boundary (hashes),
        //        2 = ip-boundary, 3 = domain-boundary
        // Boundary rules replicate the sweep's lookarounds exactly:
        //   hex:    (?<![0-9A-Fa-f]) pat (?![0-9A-Fa-f])
        //   ip:     (?<![\d.])       pat (?![\d.])
        //   domain: (?<![A-Za-z0-9-]) pat (?![A-Za-z0-9-])(?!\.[A-Za-z0-9])
        //           i.e. a preceding '.' IS allowed (evil.com matches c2.evil.com - a
        //           domain indicator covers its subdomains), while a trailing
        //           '.<alnum>' is NOT (evil.com must not match evil.com.br, a different
        //           registrable domain). See Get-DomainBoundaryPattern in
        //           modules\Invoke-Detections.ps1 - these two must stay in lockstep.
        public static List<SweepHit> ScanFiles(string[] files, string[] patterns, int[] kinds, int maxParallel)
        {
            string[] upat = new string[patterns.Length];
            for (int i = 0; i < patterns.Length; i++) upat[i] = patterns[i].ToUpperInvariant();

            ConcurrentBag<SweepHit> bag = new ConcurrentBag<SweepHit>();
            ParallelOptions opt = new ParallelOptions();
            opt.MaxDegreeOfParallelism = (maxParallel < 1) ? 1 : maxParallel;

            Parallel.ForEach(files, opt, delegate(string file)
            {
                try
                {
                    // Encoding: a BOM is honored (UTF-8/UTF-16 XMLs decode correctly). A
                    // BOM-less file is decoded as Latin-1: every byte maps 1:1 to a char,
                    // so an ASCII indicator can NEVER be hidden by an invalid-UTF8 byte
                    // sequence swallowing its neighbours (strict UTF-8 folds bad sequences
                    // into U+FFFD and can consume adjacent ASCII). This makes the scan
                    // byte-faithful for ASCII indicators - stricter than both Select-String
                    // (ANSI fallback) and plain UTF-8 reading.
                    Encoding enc = Encoding.GetEncoding(28591);   // Latin-1
                    bool hasBom = false;
                    using (FileStream probe = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        byte[] b = new byte[3];
                        int n = probe.Read(b, 0, 3);
                        if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) hasBom = true;        // UTF-8
                        else if (n >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF))) hasBom = true; // UTF-16
                    }
                    StreamReader r = hasBom
                        ? new StreamReader(file, Encoding.UTF8, true, 1 << 16)     // BOM auto-detect
                        : new StreamReader(file, enc, false, 1 << 16);             // byte-preserving
                    using (r)
                    {
                        string line;
                        int ln = 0;
                        while ((line = r.ReadLine()) != null)
                        {
                            ln++;
                            if (line.Length == 0) continue;
                            string up = line.ToUpperInvariant();
                            for (int p = 0; p < upat.Length; p++)
                            {
                                if (ContainsPattern(up, upat[p], kinds[p]))
                                {
                                    SweepHit h = new SweepHit();
                                    h.Path = file;
                                    h.LineNumber = ln;
                                    h.Line = line;
                                    h.PatternIndex = p;
                                    bag.Add(h);
                                }
                            }
                        }
                    }
                }
                catch (Exception) { }   // unreadable file: contributes no hits, same as Select-String -EA SilentlyContinue
            });

            // deterministic output regardless of scan parallelism
            List<SweepHit> list = new List<SweepHit>(bag);
            list.Sort(delegate(SweepHit a, SweepHit b)
            {
                int c = string.CompareOrdinal(a.Path, b.Path);
                if (c != 0) return c;
                if (a.LineNumber != b.LineNumber) return a.LineNumber - b.LineNumber;
                return a.PatternIndex - b.PatternIndex;
            });
            return list;
        }

        private static bool ContainsPattern(string up, string pat, int kind)
        {
            int start = 0;
            while (true)
            {
                int i = up.IndexOf(pat, start, StringComparison.Ordinal);
                if (i < 0) return false;
                if (kind == 0) return true;
                char prev = (i > 0) ? up[i - 1] : '\0';
                int after = i + pat.Length;
                char next = (after < up.Length) ? up[after] : '\0';
                bool ok;
                if (kind == 1)      ok = !IsHexChar(prev) && !IsHexChar(next);
                else if (kind == 2) ok = !IsIpChar(prev)  && !IsIpChar(next);
                else
                {
                    ok = !IsDomPrev(prev) && !IsDomNext(next);
                    // (?!\.[A-Za-z0-9]) - reject a longer registrable domain such as
                    // evil.com.br while still allowing a trailing root dot ('evil.com.')
                    if (ok && next == '.')
                    {
                        char next2 = ((after + 1) < up.Length) ? up[after + 1] : '\0';
                        if (IsAlnum(next2)) ok = false;
                    }
                }
                if (ok) return true;
                start = i + 1;   // occurrence failed the boundary test; try the next one
            }
        }
        // checks run on the UPPERCASED line; the classes are case-symmetric so this is
        // identical to testing the original characters
        private static bool IsHexChar(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); }
        private static bool IsIpChar(char c)  { return (c >= '0' && c <= '9') || c == '.'; }
        private static bool IsAlnum(char c)   { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'); }
        // '.' is NOT in IsDomPrev: a preceding dot is a LABEL BOUNDARY, so evil.com
        // matches c2.evil.com (a domain indicator covers its subdomains).
        private static bool IsDomPrev(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '-'; }
        private static bool IsDomNext(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '-'; }
    }

    public static class Timeline
    {
        // Streams one parsed CSV into the (already open) timeline writer.
        // Returns rows written, or -1 when none of the mapped timestamp columns exist
        // (same contract as the PowerShell implementation).
        public static int TransformCsv(
            string csvPath, string artifact, string hostName,
            string[] mTs, string[] mDesc, string[] mPath, string[] mName,
            string[] mExtra, string[] mEid, string[] mChan,
            long startTicks, long endTicks, TextWriter writer)
        {
            using (StreamReader r = new StreamReader(csvPath, Encoding.UTF8, true, 1 << 16))
            {
                List<string> hdr = ReadRecord(r);
                if (hdr == null) return 0;
                Dictionary<string, int> idx = new Dictionary<string, int>(StringComparer.Ordinal);
                for (int i = 0; i < hdr.Count; i++) if (!idx.ContainsKey(hdr[i])) idx.Add(hdr[i], i);

                List<int> use = new List<int>();
                for (int m = 0; m < mTs.Length; m++) if (idx.ContainsKey(mTs[m])) use.Add(m);
                if (use.Count == 0) return -1;

                string fileLeaf = System.IO.Path.GetFileName(csvPath);
                CultureInfo inv = CultureInfo.InvariantCulture;
                DateTimeStyles styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
                int written = 0;
                string lastRaw = null; DateTime lastVal = DateTime.MinValue; bool lastOk = false;
                StringBuilder sb = new StringBuilder(1024);
                StringBuilder outLine = new StringBuilder(2048);

                List<string> f;
                while ((f = ReadRecord(r)) != null)
                {
                    if (f.Count == 0) continue;
                    for (int u = 0; u < use.Count; u++)
                    {
                        int m = use[u];
                        int ti = idx[mTs[m]];
                        if (ti >= f.Count) continue;
                        string raw = f[ti];
                        if (string.IsNullOrEmpty(raw)) continue;

                        DateTime dt; bool ok;
                        if (raw == lastRaw) { ok = lastOk; dt = lastVal; }   // burst memo
                        else
                        {
                            ok = DateTime.TryParseExact(raw, "yyyy-MM-dd HH:mm:ss.fffffff", inv, styles, out dt);
                            if (!ok) ok = DateTime.TryParse(raw, inv, styles, out dt);
                            lastRaw = raw; lastVal = dt; lastOk = ok;
                        }
                        if (!ok) continue;
                        if (startTicks > 0 && dt.Ticks < startTicks) continue;
                        if (endTicks > 0 && dt.Ticks > endTicks) continue;

                        string pv = GetField(f, idx, mPath[m]);
                        string nv = GetField(f, idx, mName[m]);
                        string ev = GetField(f, idx, mEid[m]);
                        string cv = GetField(f, idx, mChan[m]);
                        string xv = GetField(f, idx, mExtra[m]);

                        sb.Length = 0;
                        if (pv.Length > 0) { sb.Append(pv).Append('\\').Append(nv); }
                        else if (nv.Length > 0) { sb.Append(nv); }
                        if (ev.Length > 0) { if (sb.Length > 0) sb.Append(" | "); sb.Append("EID ").Append(ev); }
                        if (cv.Length > 0) { if (sb.Length > 0) sb.Append(" | "); sb.Append(cv); }
                        if (xv.Length > 0) { if (sb.Length > 0) sb.Append(" | "); sb.Append(xv); }
                        string msg = (sb.Length > 0) ? sb.ToString() : fileLeaf;
                        if (msg.Length > 800) msg = msg.Substring(0, 800);

                        outLine.Length = 0;
                        AppendQ(outLine, msg); outLine.Append(',');
                        AppendQ(outLine, dt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", inv)); outLine.Append(',');
                        AppendQ(outLine, mDesc[m]); outLine.Append(',');
                        AppendQ(outLine, "triage:" + artifact); outLine.Append(',');
                        AppendQ(outLine, hostName); outLine.Append(',');
                        AppendQ(outLine, artifact);
                        writer.WriteLine(outLine.ToString());
                        written++;
                    }
                }
                return written;
            }
        }

        private static string GetField(List<string> f, Dictionary<string, int> idx, string col)
        {
            if (string.IsNullOrEmpty(col)) return "";
            int ci;
            if (!idx.TryGetValue(col, out ci)) return "";
            if (ci >= f.Count) return "";
            string v = f[ci];
            return (v == null) ? "" : v;
        }

        // Export-Csv semantics: quote everything, double embedded quotes
        private static void AppendQ(StringBuilder sb, string v)
        {
            sb.Append('"');
            if (v != null)
            {
                for (int i = 0; i < v.Length; i++)
                {
                    char c = v[i];
                    if (c == '"') sb.Append("\"\"");
                    else sb.Append(c);
                }
            }
            sb.Append('"');
        }

        // RFC4180 record reader: quoted fields, "" escapes, embedded commas/newlines.
        // Returns null at end of stream.
        private static List<string> ReadRecord(TextReader r)
        {
            int c = r.Read();
            if (c < 0) return null;
            List<string> fields = new List<string>();
            StringBuilder cur = new StringBuilder();
            bool inQ = false;
            while (true)
            {
                if (c < 0) { fields.Add(cur.ToString()); return fields; }
                char ch = (char)c;
                if (inQ)
                {
                    if (ch == '"')
                    {
                        int n = r.Peek();
                        if (n == '"') { cur.Append('"'); r.Read(); }
                        else inQ = false;
                    }
                    else cur.Append(ch);
                }
                else
                {
                    if (ch == '"' && cur.Length == 0) inQ = true;
                    else if (ch == ',') { fields.Add(cur.ToString()); cur.Length = 0; }
                    else if (ch == '\r')
                    {
                        if (r.Peek() == '\n') r.Read();
                        fields.Add(cur.ToString()); return fields;
                    }
                    else if (ch == '\n') { fields.Add(cur.ToString()); return fields; }
                    else cur.Append(ch);
                }
                c = r.Read();
            }
        }
    }
}
'@

try {
    if (-not ('ScribeAccel.Scanner' -as [type])) {
        Add-Type -TypeDefinition $accelSource -ErrorAction Stop
    }
    $script:AccelOK = $true
} catch {
    $script:AccelOK = $false
    Write-Log ("  [i] compiled accelerator unavailable ({0}) - using the PowerShell fallback (slower, same results)" -f $_.Exception.Message.Split("`n")[0]) DarkGray
}

# scan threads = cores / parallel workers, so N workers never oversubscribe the box
function Get-AccelDop {
    $workers = 1
    if ($env:SCRIBE_PARALLEL_HOSTS) {
        [void][int]::TryParse($env:SCRIBE_PARALLEL_HOSTS, [ref]$workers)
        if ($workers -lt 1) { $workers = 1 }
    }
    $cores = [Environment]::ProcessorCount
    return [Math]::Max(1, [int][Math]::Floor($cores / $workers))
}
