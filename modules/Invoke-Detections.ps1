# IOC load + sweep. Indicators are typed at load; hashes/IPs/domains match on word
# boundaries (high confidence), plain strings are substring matches (low confidence).
# MatchTime comes from the artifact's known timestamp column (Get-TimelineFieldMap),
# tagged with its semantic - never from a regex over the raw line.
# Sigma is handled in Invoke-Hayabusa.ps1.

# Boundary rules for a DOMAIN indicator. Deliberately asymmetric, because DNS names are:
#
#   LEFT  - a domain indicator covers its subdomains. Everyone in threat intel reads
#           'evil.com' as also meaning 'c2.evil.com' and 'cdn.evil.com'. So the character
#           before the match may be a DOT (a label boundary) or any non-hostname
#           character - but NOT a letter/digit/hyphen, which would make it part of the
#           same label ('notevil.com' must not match 'evil.com').
#   RIGHT - a domain indicator does NOT cover longer registrable domains. 'evil.com.br'
#           is a different owner, so a trailing '.<alnum>' continuation must be rejected,
#           as must a label continuation ('evil.community').
#
# The previous rules were wrong in both directions: the lookbehind excluded '.', so every
# subdomain was a FALSE NEGATIVE (a clean sweep over a compromised host), while the
# lookahead allowed '.', so 'evil.com.br' was a FALSE POSITIVE.
#
# ScribeAccel.Scanner.ContainsPattern (modules\Accelerator.ps1) implements the same rules
# for the compiled path; tests\Detections.Tests.ps1 diffs the two on identical input.
function Get-DomainBoundaryPattern {
    param([Parameter(Mandatory)][string]$Domain)
    return '(?<![A-Za-z0-9-])' + [regex]::Escape($Domain) + '(?![A-Za-z0-9-])(?!\.[A-Za-z0-9])'
}

# The EVIDENCE FAMILY a swept file belongs to. Purpose: an IOC that appears in three
# derived views of ONE underlying source is one piece of evidence, not three.
#
# The event-log family is the concrete case D3 flags: EvtxECmd's EventLogs.csv, Hayabusa's
# Detections.csv, and Hayabusa's DFIR_Timeline.csv are all rendered from the SAME .evtx
# files and all land in <out>\EventLogs\. One malicious event therefore produces up to
# three hit rows; left ungrouped, the risk score's volume AND corroboration terms both
# reward that duplication as though three independent artifacts agreed. Grouping by family
# lets the sweep keep every row (nothing hidden) while counting corroboration honestly.
#
# Everything else keys off its own artifact output folder, so all of one artifact's CSVs
# (e.g. MFT's several outputs) are one family - the natural, correct grouping.
function Get-EvidenceFamily {
    param([string]$FilePath)
    $leaf   = Split-Path $FilePath -Leaf
    $parent = Split-Path (Split-Path $FilePath -Parent) -Leaf
    if ($parent -ieq 'EventLogs' -or
        $leaf -in @('EventLogs.csv','Hayabusa_Detections.csv','Hayabusa_DFIR_Timeline.csv')) {
        return 'EventLog(evtx)'
    }
    if ($parent) { return $parent }
    return $leaf
}

# Tag each hit with DuplicateInFamily. A hit is a duplicate when the SAME indicator, at the
# SAME event time, in the SAME family, already appeared in a DIFFERENT source file - i.e.
# the same underlying event seen through another view. This is deliberately conservative:
#   - two DISTINCT events (different times) in one family stay two primaries - real repetition
#   - a hit with no resolvable time can't be matched across views, so it stays primary
#     (better to slightly over-count than to silently drop a hit)
# Nothing is removed; IOC_Hits.csv keeps every row. Counting/corroboration downstream use
# the primary rows (DuplicateInFamily = $false).
function Set-DuplicateFlags {
    param([System.Collections.Generic.List[object]]$Hits)
    $seen = @{}   # "host|ioc|family|time" -> first source file that carried it
    foreach ($h in $Hits) {
        $fam = Get-EvidenceFamily $h.File
        Add-Member -InputObject $h -NotePropertyName EvidenceFamily -NotePropertyValue $fam -Force
        $dup = $false
        if ($h.MatchTime) {
            $k = ('{0}|{1}|{2}|{3}' -f $h.Host, $h.IOC, $fam, $h.MatchTime)
            if ($seen.ContainsKey($k)) {
                if ($seen[$k] -ne [string]$h.File) { $dup = $true }   # same event, different view
            } else {
                $seen[$k] = [string]$h.File
            }
        }
        Add-Member -InputObject $h -NotePropertyName DuplicateInFamily -NotePropertyValue $dup -Force
    }
}

function Import-Iocs {
    param([string[]]$IocFiles)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($spec in $IocFiles) {
        $files = @()
        if (Test-Path -LiteralPath $spec -PathType Container) {
            $files = Get-ChildItem -LiteralPath $spec -File -ErrorAction SilentlyContinue
        } else {
            $files = Get-ChildItem -Path $spec -File -ErrorAction SilentlyContinue
        }
        foreach ($f in $files) {
            Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue |
                ForEach-Object { $_.Trim() } |
                Where-Object {
                    $_ -and ($_ -notmatch '^\s*#') -and ($_ -notmatch '^\s*//') -and
                    ($_ -notmatch '^\s*[-=*_]{3,}\s*$')
                } |
                ForEach-Object {
                    if ($_.Length -ge 5) { $list.Add($_) } else { $script:IocDroppedShort++ }
                }
        }
    }
    if ($script:IocDroppedShort) {
        Write-Log ("  [!] {0} indicator(s) shorter than 5 chars were DROPPED (too generic to sweep - would match everywhere)" -f $script:IocDroppedShort) Yellow
        $script:IocDroppedShort = 0
    }
    $uniq = @($list | Select-Object -Unique)

    # classify: the type decides how it is matched and the confidence it carries
    $typed = foreach ($i in $uniq) {
        $type = 'string'
        if     ($i -match '^[0-9a-fA-F]{64}$')                { $type = 'sha256' }
        elseif ($i -match '^[0-9a-fA-F]{40}$')                { $type = 'sha1' }
        elseif ($i -match '^[0-9a-fA-F]{32}$')                { $type = 'md5' }
        elseif ($i -match '^\d{1,3}(\.\d{1,3}){3}$')          { $type = 'ip' }
        elseif ($i -match '^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$' -and $i -notmatch '[\\/]') { $type = 'domain' }
        [pscustomobject]@{ Indicator = $i; Type = $type }
    }
    $typed = @($typed)

    $risky = @($typed | Where-Object { $_.Type -eq 'string' -and $_.Indicator -match '^[0-9a-fA-F]{8,}$' })
    if ($risky.Count) {
        Write-Log ("  [!] {0} indicator(s) are partial hex (not 32/40/64 chars) and may false-positive on GUIDs/device IDs:" -f $risky.Count) Yellow
        foreach ($r in ($risky | Select-Object -First 5)) { Write-Log "      $($r.Indicator)" Yellow }
    }
    return $typed
}

# Resolve MatchTime + its semantic from a matched CSV line using the artifact's field map.
# Perf: the header's column INDEX map is cached per file, and the hit line is split with
# Split-CsvLine - no ConvertFrom-Csv pipeline (parser + PSCustomObject) per hit. On a run
# with thousands of hits this was a measurable share of the sweep. Behavior is unchanged:
# a line that fails to parse yields an empty time, exactly as before.
function Get-MatchTimeFromLine {
    param([string]$CsvPath, [string]$Line, [hashtable]$HeaderCache)
    $art = Split-Path (Split-Path $CsvPath -Parent) -Leaf
    $maps = Get-TimelineFieldMap -Artifact $art

    if (-not $HeaderCache.ContainsKey($CsvPath)) {
        $hdrLine = Get-Content -LiteralPath $CsvPath -TotalCount 1 -ErrorAction SilentlyContinue
        $idx = @{}
        if ($hdrLine) {
            $hf = Split-CsvLine ([string]$hdrLine)
            for ($i = 0; $i -lt $hf.Count; $i++) { if (-not $idx.ContainsKey($hf[$i])) { $idx[$hf[$i]] = $i } }
        }
        $HeaderCache[$CsvPath] = $idx
    }
    $idx = $HeaderCache[$CsvPath]
    if ($idx.Count -eq 0) { return @{ Time = ''; Semantic = '' } }

    $f = Split-CsvLine $Line
    if ($f.Count -eq 0) { return @{ Time = ''; Semantic = '' } }

    foreach ($m in @($maps)) {
        if (-not $idx.ContainsKey($m.ts)) { continue }
        $ci = $idx[$m.ts]
        if ($ci -ge $f.Count) { continue }
        $v = $f[$ci]
        if ($v) {
            $dt = ConvertTo-DateTimeSafe $v
            if ($dt) { return @{ Time = $dt.ToString('yyyy-MM-dd HH:mm:ss'); Semantic = $m.desc } }
        }
    }
    # generic fallbacks (e.g. Hayabusa CSVs inside EventLogs)
    foreach ($c in @('Timestamp','TimeCreated','datetime')) {
        if (-not $idx.ContainsKey($c)) { continue }
        $ci = $idx[$c]
        if ($ci -ge $f.Count) { continue }
        $v = $f[$ci]
        if ($v) {
            $dt = ConvertTo-DateTimeSafe $v
            if ($dt) { return @{ Time = $dt.ToString('yyyy-MM-dd HH:mm:ss'); Semantic = "$art $c" } }
        }
    }
    return @{ Time = ''; Semantic = '' }
}

function Invoke-IocSweep {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        $Iocs,                     # typed objects from Import-Iocs
        [string]$HostName = ''
    )
    Write-Rule; Write-Log "IOC SWEEP (parsed CSVs + raw copied files)" Cyan

    # always start clean: a stale IOC_Hits.csv must never survive into a report
    $outFile = Join-Path $OutputPath 'IOC_Hits.csv'
    if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue }
    $hdrLine = '"Host","MatchTime","TimeSemantic","Confidence","IOC","Source","Line","File","EvidenceFamily","DuplicateInFamily"'

    $iocList = @($Iocs)
    if ($iocList.Count -eq 0) {
        $hdrLine | Set-Content -LiteralPath $outFile
        Write-Log "  no IOCs supplied - skipping (Sigma still applies)" DarkGray
        return @()
    }

    # build match sets: boundary regex for hash/ip/domain, literal substring for strings
    $rxMap  = @{}
    $strMap = @{}
    foreach ($i in $iocList) {
        switch ($i.Type) {
            { $_ -in 'sha256','sha1','md5' } { $rxMap['(?<![0-9A-Fa-f])' + [regex]::Escape($i.Indicator) + '(?![0-9A-Fa-f])'] = $i }
            'ip'     { $rxMap['(?<![\d.])'         + [regex]::Escape($i.Indicator) + '(?![\d.])']         = $i }
            'domain' { $rxMap[(Get-DomainBoundaryPattern $i.Indicator)] = $i }
            default  { $strMap[$i.Indicator] = $i }
        }
    }

    # targets: parsed CSVs, plus raw copied text files (task XML etc.) which would
    # otherwise be invisible to the sweep
    # excluded: our own derived outputs. On an in-place re-run, files from the PREVIOUS run
    # (visibility, telemetry) are still present and must not become sweep targets.
    $csvs = @(Get-ChildItem -LiteralPath $OutputPath -Recurse -Filter *.csv -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('IOC_Hits.csv','Artifact_Coverage.csv','Visibility_Windows.csv','_Performance.csv') -and
                           $_.Name -notmatch '_filtered\.csv$' -and
                           $_.Name -notmatch 'Timeline_Timesketch\.csv$' })
    $raws = @(Get-ChildItem -LiteralPath $OutputPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.xml','.txt','.log','.job','') -and
                           $_.FullName -notmatch '\\_logs\\' -and
                           $_.Name -ne '_Summary.txt' -and         # our own output: on an in-place
                           $_.Name -ne '_BATCH_Summary.txt' -and   # re-run it must not self-hit
                           $_.Name -notlike '$*' -and $_.Length -gt 0 -and $_.Length -lt 20MB })

    $hits = New-Object System.Collections.Generic.List[object]
    $headerCache = @{}

    foreach ($set in @(
        @{ Files = $csvs; Kind = 'csv' },
        @{ Files = $raws; Kind = 'raw' }
    )) {
        if (-not $set.Files -or @($set.Files).Count -eq 0) { continue }
        $paths = @($set.Files | Select-Object -ExpandProperty FullName)

        # ---- compiled path: multi-pattern scan at disk speed (see modules/Accelerator.ps1).
        # Emits every (line, indicator) pair directly with the same boundary semantics as the
        # regex path below, so no per-line re-test is needed. Field-measured motivation: 34
        # indicators over one big host's CSVs cost 904s via Select-String.
        if ($script:AccelOK) {
            $pat = New-Object System.Collections.Generic.List[string]
            $kinds = New-Object System.Collections.Generic.List[int]
            $iocRef = New-Object System.Collections.Generic.List[object]
            foreach ($i in $iocList) {
                $pat.Add([string]$i.Indicator)
                $iocRef.Add($i)
                $k = 0
                switch ($i.Type) {
                    { $_ -in 'sha256','sha1','md5' } { $k = 1 }
                    'ip'     { $k = 2 }
                    'domain' { $k = 3 }
                }
                $kinds.Add($k)
            }
            $res = $null
            try {
                $res = [ScribeAccel.Scanner]::ScanFiles([string[]]$paths, $pat.ToArray(), $kinds.ToArray(), (Get-AccelDop))
            } catch {
                Write-Log ("  [!] accelerated scan failed ({0}) - falling back to Select-String" -f $_.Exception.Message) Yellow
                $res = $null
            }
            if ($null -ne $res) {
                $timeCache = @{}
                foreach ($h in $res) {
                    $ioc = $iocRef[$h.PatternIndex]
                    $conf = if ($kinds[$h.PatternIndex] -eq 0) { 'low (substring)' } else { 'high (boundary)' }
                    $mt = @{ Time = ''; Semantic = '' }
                    if ($set.Kind -eq 'csv') {
                        $tk = "$($h.Path)|$($h.LineNumber)"
                        if (-not $timeCache.ContainsKey($tk)) {
                            $timeCache[$tk] = Get-MatchTimeFromLine -CsvPath $h.Path -Line $h.Line -HeaderCache $headerCache
                        }
                        $mt = $timeCache[$tk]
                    }
                    $hits.Add([pscustomobject]@{
                        Host = $HostName; MatchTime = $mt.Time; TimeSemantic = $mt.Semantic
                        Confidence = $conf; IOC = $ioc.Indicator
                        Source = (Split-Path $h.Path -Leaf); Line = $h.LineNumber; File = $h.Path
                    })
                }
                continue   # next set
            }
            # $res -eq $null: fall through to the Select-String path below
        }

        # One combined alternation per chunk instead of one pattern per indicator: Select-String
        # evaluates its -Pattern list sequentially per line, so N indicators cost N passes over
        # every line of every CSV (the MFT CSV alone can be hundreds of MB). A single alternation
        # is one pass, and .NET optimizes literal alternations well. Semantics unchanged: hit
        # lines are re-tested per indicator below exactly as before, and Select-String stays
        # case-insensitive in both forms. Falls back to the original per-pattern scan on any
        # failure building the combined pattern.
        $allPatterns = @(@($strMap.Keys | ForEach-Object { [regex]::Escape($_) }) + @($rxMap.Keys))
        # List, not array += : at outbreak-scale hit counts, += re-copies the whole array per
        # chunk (O(n^2)); List.Add is amortized O(1)
        $found = New-Object System.Collections.Generic.List[object]
        $combinedOk = $false
        try {
            $chunkSize = 150
            for ($ci = 0; $ci -lt $allPatterns.Count; $ci += $chunkSize) {
                $chunk = @($allPatterns[$ci..([Math]::Min($ci + $chunkSize - 1, $allPatterns.Count - 1))])
                $rxCombined = '(' + ($chunk -join ')|(') + ')'
                [void](New-Object regex $rxCombined)   # validate before handing to Select-String
                foreach ($m in @(Select-String -LiteralPath $paths -Pattern $rxCombined -ErrorAction SilentlyContinue)) { $found.Add($m) }
            }
            $combinedOk = $true
        } catch { $found.Clear() }
        if (-not $combinedOk) {
            if ($strMap.Keys.Count) { foreach ($m in @(Select-String -LiteralPath $paths -SimpleMatch -Pattern @($strMap.Keys) -ErrorAction SilentlyContinue)) { $found.Add($m) } }
            if ($rxMap.Keys.Count)  { foreach ($m in @(Select-String -LiteralPath $paths -Pattern @($rxMap.Keys) -ErrorAction SilentlyContinue)) { $found.Add($m) } }
        }

        # Select-String reports only the FIRST matching pattern per line, but one CSV row often
        # carries several indicators (an Amcache row has both the filename and the SHA1). The
        # scan found the hit lines; now re-test just those lines against the full indicator set
        # so every matching IOC gets its own row. Cost is per hit line, not per file.
        $seen = @{}
        foreach ($h in $found) {
            $lineKey = "$($h.Path)|$($h.LineNumber)"
            if ($seen.ContainsKey($lineKey)) { continue }   # same line found by both scans
            $seen[$lineKey] = $true

            $lineIocs = @()
            foreach ($s in $strMap.Keys) {
                if ($h.Line.IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $lineIocs += ,@($strMap[$s], 'low (substring)')
                }
            }
            foreach ($rx in $rxMap.Keys) {
                if ($h.Line -match $rx) { $lineIocs += ,@($rxMap[$rx], 'high (boundary)') }
            }
            if (-not $lineIocs.Count) { continue }

            $mt = @{ Time = ''; Semantic = '' }
            if ($set.Kind -eq 'csv') { $mt = Get-MatchTimeFromLine -CsvPath $h.Path -Line $h.Line -HeaderCache $headerCache }

            foreach ($li in $lineIocs) {
                $hits.Add([pscustomobject]@{
                    Host = $HostName; MatchTime = $mt.Time; TimeSemantic = $mt.Semantic
                    Confidence = $li[1]; IOC = $li[0].Indicator
                    Source = (Split-Path $h.Path -Leaf); Line = $h.LineNumber; File = $h.Path
                })
            }
        }
    }

    # D3: mark same-event-across-views duplicates so counts/corroboration stay honest
    Set-DuplicateFlags -Hits $hits
    $primary = @($hits | Where-Object { -not $_.DuplicateInFamily })
    $dupCount = $hits.Count - $primary.Count

    # warn on pathological indicators before the analyst faces 80k rows (primary rows only -
    # the triple-view duplication must not by itself trip the 'too generic' warning)
    foreach ($g in ($primary | Group-Object IOC | Where-Object Count -gt 1000)) {
        Write-Log ("  [!] indicator '{0}' produced {1} hits - likely too generic, consider removing it" -f $g.Name, $g.Count) Yellow
    }

    # column order: the two D3 columns go at the end so existing IOC_Hits.csv consumers
    # (Splunk/Timesketch pipelines keyed on the original columns) keep working
    $exportCols = @('Host','MatchTime','TimeSemantic','Confidence','IOC','Source','Line','File','EvidenceFamily','DuplicateInFamily')
    if ($hits.Count) { $hits | Select-Object $exportCols | Export-Csv -NoTypeInformation -Path $outFile }
    else             { $hdrLine | Set-Content -LiteralPath $outFile }

    $col = if ($hits.Count) { 'Red' } else { 'Green' }
    $low = @($hits | Where-Object Confidence -like 'low*').Count
    Write-Log ("  IOC hits: {0}  (high-confidence: {1}, substring: {2})" -f $hits.Count, ($hits.Count - $low), $low) $col
    if ($dupCount -gt 0) {
        Write-Log ("  of these, {0} are the same event seen through multiple views (EventLogs + Hayabusa) - flagged DuplicateInFamily; {1} distinct" -f $dupCount, $primary.Count) DarkYellow
    }
    return $hits
}
