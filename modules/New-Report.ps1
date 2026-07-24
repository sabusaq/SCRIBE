# Fill the findings report template from a host's run output. Fully automatic: every token
# is always replaced (worst case with 'None'), so the report is ready to read as generated.

function Get-HtmlEnc {
    param($v)
    if ($null -eq $v) { return '' }
    if ($v -is [array]) { $v = ($v -join ' ') }
    $s = [string]$v
    return $s.Replace([string]'&', [string]'&amp;').Replace([string]'<', [string]'&lt;').Replace([string]'>', [string]'&gt;')
}

function Get-FileHref {
    param([string]$Path)
    if (-not $Path) { return '' }
    $u = 'file:///' + ($Path -replace '\\','/')
    try { return [uri]::EscapeUriString($u) } catch { return '' }
}

function ConvertTo-HtmlTable {
    param($Rows, $Columns, $Max = 50, [string]$MoreNote = '')
    $rows = @($Rows)
    $cols = @($Columns | Where-Object { $_ })
    $Max = [int]$Max
    if ($rows.Count -eq 0 -or $cols.Count -eq 0) { return '<p><i>None.</i></p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(Get-HtmlEnc ([string]$c))</th>") }
    [void]$sb.Append('</tr>')
    foreach ($r in ($rows | Select-Object -First $Max)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $cell = $r.$c
            if ($cell -is [array]) { $cell = ($cell -join ' ') }
            [void]$sb.Append("<td>$(Get-HtmlEnc ([string]$cell))</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table>')
    if ($rows.Count -gt $Max) { [void]$sb.Append("<p class='small'>Showing $Max of $($rows.Count) rows$MoreNote.</p>") }
    return [string]$sb.ToString()
}

function New-TriageReport {
    param(
        [Parameter(Mandatory)][string]$HostOutput,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$TemplatePath,
        [string]$Layout = '',
        [int]$IocCount = 0,
        [string]$Verdict = ''
    )
    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        Write-Log "  [!] report template not found: $TemplatePath" Yellow
        return
    }
    $html = [string](Get-Content -LiteralPath $TemplatePath -Raw)
    if (-not $html) { Write-Log "  [!] report template empty/unreadable: $TemplatePath" Yellow; return }

  try {
    # --- coverage ---
    $covCsv = Join-Path $HostOutput 'Artifact_Coverage.csv'
    $cov = @(); if (Test-Path -LiteralPath $covCsv) { $cov = @(Import-Csv -LiteralPath $covCsv) }
    $covTable = ConvertTo-HtmlTable -Rows $cov -Columns @('Artifact','State','Purpose')
    $blind = @($cov | Where-Object { $_.State -ne 'Parsed' })
    $blindTable = ConvertTo-HtmlTable -Rows $blind -Columns @('Artifact','State','Purpose')
    $parsedCount = @($cov | Where-Object State -eq 'Parsed').Count

    # --- IOC hits ---
    $iocCsv = Join-Path $HostOutput 'IOC_Hits.csv'
    $hits = @(); if (Test-Path -LiteralPath $iocCsv) { $hits = @(Import-Csv -LiteralPath $iocCsv) }
    $shown = @(@($hits) | Select-Object -First 60)
    $sbT = New-Object System.Text.StringBuilder
    if (@($hits).Count) {
        [void]$sbT.Append('<table><tr><th>Time (UTC)</th><th>Time semantic</th><th>Confidence</th><th>Indicator</th><th>Source (line)</th></tr>')
        $hi = 0
        foreach ($h in $shown) {
            $hi++
            $rcls = if ($h.Confidence -like 'high*') { " class='hi-row'" } else { '' }
            $srcTxt = "$(Get-HtmlEnc $h.Source):$(Get-HtmlEnc ([string]$h.Line))"
            # jump to the evidence detail lower in THIS page
            $srcCell = "<a href='#hit$hi'>$srcTxt &#8595;</a>"
            [void]$sbT.Append("<tr$rcls id='row$hi'><td>$(Get-HtmlEnc $h.MatchTime)</td><td>$(Get-HtmlEnc $h.TimeSemantic)</td><td>$(Get-HtmlEnc $h.Confidence)</td><td>$(Get-HtmlEnc $h.IOC)</td><td>$srcCell</td></tr>")
        }
        [void]$sbT.Append('</table>')
        if (@($hits).Count -gt 60) { [void]$sbT.Append("<p class='small'>Showing 60 of $(@($hits).Count) rows - see IOC_Hits.csv.</p>") }
        [void]$sbT.Append("<p class='small'>Click a source to jump to that hit's evidence line below. 'Time semantic' states which clock the time is - e.g. 'Registry Key Write' is a key-write time, not execution; 'MFT `$SI Created' is file creation per `$SI (timestompable); 'Prefetch Last Run' is actual execution. Only compare like with like.</p>")
    } else { [void]$sbT.Append('<p><i>None.</i></p>') }
    $iocTable = [string]$sbT.ToString()

    # evidence detail: the actual CSV line for each shown hit, anchored for the jump.
    # Perf: hits are grouped BY FILE and each file is read once, collecting every wanted
    # line in a single sequential pass with early exit. The previous per-hit scan restarted
    # from line 1 for every hit - O(hits x line-number), up to 60 re-reads of a multi-GB
    # MFT CSV when hits sat deep in the file.
    $lineLookup = @{}    # "<file>|<line>" -> text
    $byFile = @{}        # file -> hashtable of wanted [int] line numbers
    foreach ($h in $shown) {
        if (-not $h.File -or -not $h.Line) { continue }
        $ln = 0
        if (-not [int]::TryParse([string]$h.Line, [ref]$ln) -or $ln -le 0) { continue }
        $fKey = [string]$h.File
        if (-not $byFile.ContainsKey($fKey)) { $byFile[$fKey] = @{} }
        $byFile[$fKey][$ln] = $true
    }
    foreach ($fKey in @($byFile.Keys)) {
        if (-not (Test-Path -LiteralPath $fKey)) { continue }
        $need = $byFile[$fKey]
        $remaining = $need.Count
        $cur = 0
        try {
            foreach ($rl in [System.IO.File]::ReadLines($fKey)) {
                $cur++
                if ($need.ContainsKey($cur)) {
                    $lineLookup["$fKey|$cur"] = $rl
                    $remaining--
                    if ($remaining -le 0) { break }
                }
            }
        } catch { }
    }
    $sbE = New-Object System.Text.StringBuilder
    if (@($shown).Count) {
        $hi = 0
        foreach ($h in $shown) {
            $hi++
            $lineText = ''
            $ln = 0
            if ($h.File -and [int]::TryParse([string]$h.Line, [ref]$ln)) {
                $k = "$([string]$h.File)|$ln"
                if ($lineLookup.ContainsKey($k)) { $lineText = $lineLookup[$k] }
            }
            if (-not $lineText) { $lineText = '(line not retrievable)' }
            [void]$sbE.Append("<div class='evi' id='hit$hi'><b>#$hi &nbsp; $(Get-HtmlEnc $h.IOC)</b> &nbsp; <span class='small'>$(Get-HtmlEnc $h.Source) line $(Get-HtmlEnc ([string]$h.Line)) &middot; $(Get-HtmlEnc $h.TimeSemantic) $(Get-HtmlEnc $h.MatchTime)</span> &nbsp; <a class='small' href='#row$hi'>&#8593; back</a><pre>$(Get-HtmlEnc $lineText)</pre></div>")
        }
    }
    $eviBlock = [string]$sbE.ToString()
    if (@($hits | Where-Object Source -match 'Amcache').Count) {
        $iocTable += '<p class="small">Amcache caveats: an Amcache entry proves presence, not execution; and Amcache stores the SHA1 of only the first ~31&nbsp;MB of a file, so hash indicators for larger files never match here - an Amcache miss is not evidence of absence.</p>'
    }
    if (@($hits | Where-Object Confidence -like 'low*').Count) {
        $iocTable += '<p class="small">Rows marked <i>low (substring)</i> are plain substring matches - verify before drawing conclusions from them.</p>'
    }
    $uniqIocs = @($hits | Select-Object -ExpandProperty IOC -Unique)
    $iocArtifacts = @($hits | Select-Object -ExpandProperty Source -Unique)
    $times = @($hits | ForEach-Object { ConvertTo-DateTimeSafe $_.MatchTime } | Where-Object { $_ } | Sort-Object)

    # --- detections: first 5 crit/high, tolerant of hayabusa column variants ---
    # single streamed pass: count crit/high + keep first 5 + first 5 overall, never materialize the file
    # int counters instead of .Count on generic List instances: PSv5.1's member binding can throw
    # 'Argument types do not match' on that construct. try/catch: this section may never kill the report.
    $detCsv = Join-Path $HostOutput 'EventLogs\Hayabusa_Detections.csv'
    $dets = @(); $detCols = @(); $critHighTotal = 0; $detNote = ''
    if (Test-Path -LiteralPath $detCsv) {
      try {
        $cols = $null; $lvlCol = $null
        $first5 = New-Object System.Collections.ArrayList
        $ch5    = New-Object System.Collections.ArrayList
        $nFirst = 0; $nCh = 0
        Import-Csv -LiteralPath $detCsv | ForEach-Object {
            if ($null -eq $cols) {
                $cols = @($_.PSObject.Properties.Name)
                $lvlCol = [string]($cols | Where-Object { $_ -match 'level' } | Select-Object -First 1)
            }
            if ($nFirst -lt 5) { [void]$first5.Add($_); $nFirst++ }
            if ($lvlCol -and ([string]$_.$lvlCol -match 'crit|high')) {
                $critHighTotal++
                if ($nCh -lt 5) { [void]$ch5.Add($_); $nCh++ }
            }
        }
        if ($nCh -gt 0) { $dets = @($ch5.ToArray()) } elseif ($nFirst -gt 0) { $dets = @($first5.ToArray()) }
        if ($cols) {
            $want = @('Timestamp','RuleTitle',$lvlCol,'Computer','Details','Channel','EventID') |
                    Where-Object { $_ -and ($cols -contains $_) } | Select-Object -Unique
            $detCols = if (@($want).Count -ge 3) { @($want | Select-Object -First 4) } else { @($cols | Select-Object -First 4) }
        }
      } catch {
        $dets = @(); $detCols = @()
        $detNote = "detections table could not be built ($($_.Exception.Message)) - open EventLogs\Hayabusa_Detections.csv directly"
      }
    }
    if (-not @($detCols).Count) { $detCols = @('RuleTitle') }
    $detTable = ConvertTo-HtmlTable -Rows $dets -Columns @($detCols) -Max 5
    if ($detNote) { $detTable += "<p class='small'>[!] $(Get-HtmlEnc $detNote)</p>" }

    # --- visibility windows ---
    $visCsv = Join-Path $HostOutput 'Visibility_Windows.csv'
    $vis = @(); if (Test-Path -LiteralPath $visCsv) { $vis = @(Import-Csv -LiteralPath $visCsv) }
    $visTable = ConvertTo-HtmlTable -Rows $vis -Columns @('Artifact','VisibleFrom','VisibleTo','Note') -Max 40

    # --- verdict banner + auto executive summary ---
    if ($hits.Count -gt 0) {
        $vClass = 'verdict-bad'
        $vLine  = "IOC MATCHES FOUND - $($hits.Count) match(es). Review required."
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<p>The host <b>$(Get-HtmlEnc $HostName)</b> shows <b>$($hits.Count)</b> IOC match(es) ")
        [void]$sb.Append("against the supplied indicator set ($IocCount indicators), across ")
        [void]$sb.Append("$(@($iocArtifacts).Count) artifact source(s): $(Get-HtmlEnc ($iocArtifacts -join ', ')). ")
        [void]$sb.Append("$(@($uniqIocs).Count) distinct indicator(s) matched.")
        if ($times.Count) {
            [void]$sb.Append(" Earliest matched activity: <b>$($times[0].ToString('yyyy-MM-dd HH:mm:ss'))</b>")
            if ($times.Count -gt 1) { [void]$sb.Append(", latest: <b>$($times[-1].ToString('yyyy-MM-dd HH:mm:ss'))</b>") }
            [void]$sb.Append('.')
        }
        if ($critHighTotal) { [void]$sb.Append(" Hayabusa flagged <b>$critHighTotal</b> critical/high Sigma detection(s).") }
        [void]$sb.Append("</p><p>Details: section 3 (matches), section 4 (detections), section 5 (what this collection could not show).</p>")
        $exec = $sb.ToString()
    } elseif ($parsedCount -eq 0 -or $Verdict -match 'INCONCLUSIVE') {
        $vClass = 'verdict-warn'
        $vLine  = 'INCONCLUSIVE - core artifacts were not parsed.'
        $exec   = "<p>No conclusion can be drawn for <b>$(Get-HtmlEnc $HostName)</b>: the core artifacts were not available or not parsed (see sections 2 and 5). A 'no findings' result on this run does not mean the host is clean.</p>"
    } elseif (@($blind).Count -gt 0) {
        $vClass = 'verdict-warn'
        $vLine  = "No IOC matches - but $(@($blind).Count) artifact(s) were not analyzed (blind spots)."
        $exec   = "<p>No matches against the supplied indicator set ($IocCount indicators) were found on <b>$(Get-HtmlEnc $HostName)</b> across $parsedCount parsed artifact(s). However, $(@($blind).Count) artifact(s) could not be analyzed (section 5) - this result cannot be read as a clean host."
        if ($critHighTotal) { $exec += " Hayabusa flagged <b>$critHighTotal</b> critical/high Sigma detection(s) worth review (section 4)." }
        $exec += "</p>"
    } else {
        $vClass = 'verdict-ok'
        $vLine  = 'No IOC matches in the parsed artifacts.'
        $exec   = "<p>No matches against the supplied indicator set ($IocCount indicators) were found on <b>$(Get-HtmlEnc $HostName)</b> across $parsedCount parsed artifact(s)."
        if ($critHighTotal) { $exec += " Hayabusa flagged <b>$critHighTotal</b> critical/high Sigma detection(s) that are worth review (section 4)." }
        $exec += " Blind spots, if any, are listed in section 5.</p>"
    }

    $map = [ordered]@{
        '{{HOST}}'             = (Get-HtmlEnc $HostName)
        '{{DATE}}'             = (Get-Date -Format 'yyyy-MM-dd')
        '{{LAYOUT}}'           = (Get-HtmlEnc $Layout)
        '{{IOC_COUNT}}'        = [string]$IocCount
        '{{VERDICT_CLASS}}'    = $vClass
        '{{VERDICT_LINE}}'     = (Get-HtmlEnc $vLine)
        '{{EXEC_SUMMARY}}'     = $exec
        '{{COVERAGE_TABLE}}'   = $covTable
        '{{IOC_HIT_COUNT}}'    = [string]$hits.Count
        '{{IOC_TABLE}}'        = $iocTable
        '{{DETECTIONS_TABLE}}' = $detTable
        '{{BLINDSPOTS_TABLE}}' = $blindTable
        '{{VISIBILITY_TABLE}}' = $visTable
        '{{EVIDENCE_LINES}}'   = $eviBlock
    }
    foreach ($k in $map.Keys) {
        $v = $map[$k]
        if ($v -is [array]) { $v = ($v -join '') }
        $ks = [string]$k
        $vs = [string]$v
        # explicit (string,string) overload - never let it bind to Replace(char,char)
        $html = $html.Replace($ks, $vs)
    }

    $out = Join-Path $HostOutput 'Findings_Report.html'
    $html | Set-Content -LiteralPath $out -Encoding UTF8
    Write-Log "  -> Findings_Report.html  (ready to read; open in Word for .docx, print for PDF)" Green
    return $out
  } catch {
    $ln = if ($_.InvocationInfo) { $_.InvocationInfo.ScriptLineNumber } else { '?' }
    $tx = if ($_.InvocationInfo) { ([string]$_.InvocationInfo.Line).Trim() } else { '' }
    Write-Log ("  [!] report build failed at line {0}: {1}  <<{2}>>" -f $ln, $_.Exception.Message, $tx) Yellow
    return
  }
}

# --- risk scoring (transparent, mechanical - the formula is printed in the report) ---

# streamed crit/high count from a Hayabusa detections CSV
function Get-CritHighCount {
    param([string]$DetCsv)
    if (-not (Test-Path -LiteralPath $DetCsv)) { return 0 }
    $n = 0
    $p = New-CsvParser -Path $DetCsv
    try {
        if ($p.EndOfData) { return 0 }
        $hdr = $p.ReadFields()
        $li = -1
        for ($i = 0; $i -lt $hdr.Count; $i++) { if ($hdr[$i] -match 'level') { $li = $i; break } }
        if ($li -lt 0) { return 0 }
        while (-not $p.EndOfData) {
            $f = $null
            try { $f = $p.ReadFields() } catch { continue }
            if ($f -and $li -lt $f.Count -and $f[$li] -match 'crit|high') { $n++ }
        }
    } finally { $p.Close() }
    return $n
}

# 0-100 from measurable signals. Not a verdict - an evidence-weighting to rank hosts for review.
function Get-HostRiskScore {
    param($Hits, [int]$CritHigh)
    # D3: an IOC seen in three views of ONE source (EventLogs.csv + the two Hayabusa CSVs)
    # is one piece of evidence. Score on PRIMARY hits only, and measure breadth by evidence
    # FAMILY, not by source file - otherwise the triple-view rendering inflates both the
    # volume term and the corroboration term. IOC_Hits.csv keeps every row; this just counts
    # honestly. Rows from an older IOC_Hits.csv without the column are all treated as primary.
    $all = @($Hits)
    $h  = @($all | Where-Object { [string]$_.DuplicateInFamily -ne 'True' })
    $hi = @($h | Where-Object { $_.Confidence -like 'high*' })
    $lo = @($h | Where-Object { $_.Confidence -like 'low*' })
    $distinctHi = @($hi | Select-Object -ExpandProperty IOC -Unique).Count
    $distinctLo = @($lo | Select-Object -ExpandProperty IOC -Unique).Count
    # breadth = distinct evidence families hit; fall back to Source for older CSVs that
    # predate the EvidenceFamily column
    $famVals = @($h | ForEach-Object { if ($_.PSObject.Properties['EvidenceFamily'] -and $_.EvidenceFamily) { $_.EvidenceFamily } else { $_.Source } })
    $arts = @($famVals | Select-Object -Unique).Count

    # exact-match indicators are the strongest signal and MUST keep climbing with count:
    # 1st distinct = 25, then +12 each. 1->25, 2->37, 3->49, 4->61, 5->73, capped 80.
    $hiScore = 0
    if ($distinctHi -ge 1) { $hiScore = [Math]::Min(80, 25 + (($distinctHi - 1) * 12)) }
    $score  = 0
    $score += $hiScore
    $score += [Math]::Min(12, [int]($h.Count / 5))       # raw volume (primary hits), capped
    $score += [Math]::Min(8,  $distinctLo * 2)           # substring corroboration, weakly weighted
    $score += [Math]::Min(25, [int]($CritHigh / 2))      # Sigma crit/high detections
    if ($arts -ge 3) { $score += 10 } elseif ($arts -eq 2) { $score += 5 }   # multi-FAMILY corroboration
    $score = [Math]::Min(100, $score)

    $band = if ($score -ge 70) { 'CRITICAL' } elseif ($score -ge 45) { 'HIGH' }
            elseif ($score -ge 25) { 'MEDIUM' } elseif ($score -ge 10) { 'LOW' } else { 'MINIMAL' }
    return @{ Score = $score; Band = $band; DistinctHigh = $distinctHi; DistinctLow = $distinctLo; ArtifactKinds = $arts }
}

# Batch-level report: per-host briefs with risk ranking + the global activity timeline.
function New-GlobalReport {
    param(
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$TemplatePath,
        [string]$Layout = ''
    )
    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        Write-Log "  [!] global report template not found: $TemplatePath" Yellow
        return
    }
    $html = [string](Get-Content -LiteralPath $TemplatePath -Raw)
    if (-not $html) { Write-Log "  [!] global report template empty/unreadable: $TemplatePath" Yellow; return }

    $covCsv = Join-Path $OutputRoot '_GLOBAL_Coverage.csv'
    $rows = @(); if (Test-Path -LiteralPath $covCsv) { $rows = @(Import-Csv -LiteralPath $covCsv) }
    $ok       = @($rows | Where-Object Status -eq 'OK')
    $fail     = @($rows | Where-Object { $_.Status -like 'FAILED*' })
    $hitHosts = @($rows | Where-Object { [int]$_.IocHits -gt 0 })

    # per-host evidence + risk
    $cards = New-Object System.Collections.Generic.List[object]
    $allHits = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $hits = @(); $critHigh = 0
        if ($r.Status -eq 'OK' -and $r.Output) {
            $hCsv = Join-Path $r.Output 'IOC_Hits.csv'
            if (Test-Path -LiteralPath $hCsv) { $hits = @(Import-Csv -LiteralPath $hCsv) }
            $critHigh = Get-CritHighCount -DetCsv (Join-Path $r.Output 'EventLogs\Hayabusa_Detections.csv')
        }
        foreach ($h in $hits) {
            $dt = ConvertTo-DateTimeSafe $h.MatchTime
            $allHits.Add([pscustomobject]@{
                Sort = $(if ($dt) { $dt } else { [datetime]::MaxValue })
                Time = $(if ($dt) { $dt.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                Host = $r.Host; Confidence = $h.Confidence; IOC = $h.IOC
                Artifact = $h.Source; Semantic = $h.TimeSemantic
                File = $h.File; Line = $h.Line
            })
        }
        $risk = Get-HostRiskScore -Hits $hits -CritHigh $critHigh
        $times = @($hits | ForEach-Object { ConvertTo-DateTimeSafe $_.MatchTime } | Where-Object { $_ } | Sort-Object)
        $blind = [int]$r.NotCollected + [int]$r.ToolMissing + [int]$r.Skipped
        $cards.Add([pscustomobject]@{
            Host = $r.Host; Status = $r.Status; Result = $r.Result
            Score = $(if ($r.Status -eq 'OK') { $risk.Score } else { -1 })
            Band  = $(if ($r.Status -eq 'OK') { $risk.Band } else { 'N/A' })
            Hits = @($hits).Count
            HiHits = @($hits | Where-Object { $_.Confidence -like 'high*' }).Count
            DistinctHigh = $risk.DistinctHigh; DistinctLow = $risk.DistinctLow
            CritHigh = $critHigh; ArtifactKinds = $risk.ArtifactKinds
            Parsed = $r.Parsed; Blind = $blind
            First = $(if ($times.Count) { $times[0].ToString('yyyy-MM-dd HH:mm') } else { '' })
            Last  = $(if ($times.Count) { $times[-1].ToString('yyyy-MM-dd HH:mm') } else { '' })
            Seconds = $r.Seconds
        })
    }

    # --- host briefs table, risk-ranked ---
    $bandClass = @{ CRITICAL='band-crit'; HIGH='band-high'; MEDIUM='band-med'; LOW='band-low'; MINIMAL='band-min'; 'N/A'='band-na' }
    $sb = New-Object System.Text.StringBuilder
    if ($cards.Count) {
        [void]$sb.Append('<table><tr><th>Risk</th><th>Host</th><th>Status</th><th>IOC hits (exact)</th><th>Distinct IOCs (exact/substr)</th><th>Sigma crit/high</th><th>Artifact kinds hit</th><th>Coverage</th><th>Matched activity window</th><th>Detail</th></tr>')
        foreach ($c in ($cards | Sort-Object Score -Descending)) {
            $cls = $bandClass[$c.Band]
            $scoreTxt = if ($c.Score -ge 0) { "$($c.Score) $($c.Band)" } else { 'N/A (failed)' }
            $win = if ($c.First) { "$($c.First) &rarr; $($c.Last)" } else { '-' }
            $cov = "$($c.Parsed) parsed" + $(if ([int]$c.Blind -gt 0) { ", <span class='blind'>$($c.Blind) blind</span>" } else { '' })
            [void]$sb.Append("<tr><td class='$cls'>$(Get-HtmlEnc $scoreTxt)</td><td><b>$(Get-HtmlEnc $c.Host)</b></td><td>$(Get-HtmlEnc $c.Status)</td>")
            [void]$sb.Append("<td>$($c.Hits) ($($c.HiHits))</td><td>$($c.DistinctHigh) / $($c.DistinctLow)</td><td>$($c.CritHigh)</td><td>$($c.ArtifactKinds)</td>")
            [void]$sb.Append("<td>$cov</td><td>$win</td><td><code>$(Get-HtmlEnc $c.Host)\Findings_Report.html</code></td></tr>")
        }
        [void]$sb.Append('</table>')
    } else { [void]$sb.Append('<p><i>None.</i></p>') }
    $hostsTable = [string]$sb.ToString()

    # --- per-host activity timelines, risk order ---
    $maxPerHost = 60
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in ($cards | Sort-Object Score -Descending)) {
        $cls = $bandClass[$c.Band]
        $scoreTxt = if ($c.Score -ge 0) { "$($c.Band) ($($c.Score))" } else { 'N/A - analysis failed' }
        [void]$sb.Append("<h3>$(Get-HtmlEnc $c.Host) &nbsp; <span class='$cls' style='padding:2px 8px;'>Risk: $(Get-HtmlEnc $scoreTxt)</span></h3>")
        if ($c.Status -ne 'OK') {
            [void]$sb.Append("<p><i>Not analyzed: $(Get-HtmlEnc $c.Result)</i></p>")
            continue
        }
        $hHits   = @($allHits | Where-Object { $_.Host -eq $c.Host })
        $timed   = @($hHits | Where-Object { $_.Time } | Sort-Object Sort)
        $untimed = @($hHits | Where-Object { -not $_.Time }).Count
        if ($timed.Count) {
            [void]$sb.Append('<table><tr><th>Time (UTC)</th><th>Confidence</th><th>Indicator</th><th>Artifact</th><th>Time semantic</th></tr>')
            foreach ($t in ($timed | Select-Object -First $maxPerHost)) {
                $rcls = if ($t.Confidence -like 'high*') { " class='hi-row'" } else { '' }
                $href = Get-FileHref ([string]$t.File)
                $artTxt = "$(Get-HtmlEnc $t.Artifact):$(Get-HtmlEnc ([string]$t.Line))"
                $artCell = if ($href) { "<a href='$href' title='$(Get-HtmlEnc ([string]$t.File))'>$artTxt</a>" } else { $artTxt }
                [void]$sb.Append("<tr$rcls><td>$(Get-HtmlEnc $t.Time)</td><td>$(Get-HtmlEnc $t.Confidence)</td><td>$(Get-HtmlEnc $t.IOC)</td><td>$artCell</td><td>$(Get-HtmlEnc $t.Semantic)</td></tr>")
            }
            [void]$sb.Append('</table>')
            $n = "Showing $([Math]::Min($timed.Count, $maxPerHost)) of $($timed.Count) time-attributable event(s)"
            if ($untimed) { $n += " ($untimed without an extractable timestamp)" }
            $n += ". Full detail: <code>$(Get-HtmlEnc $c.Host)\IOC_Hits.csv</code>."
            [void]$sb.Append("<p class='small'>$n</p>")
        } else {
            [void]$sb.Append('<p><i>No time-attributable IOC activity on this host.</i></p>')
        }
    }
    $hostTimelines = [string]$sb.ToString()

    # --- indicators across hosts ---
    $mtxCsv = Join-Path $OutputRoot '_GLOBAL_IOC_Matrix.csv'
    $mtx = @(); if (Test-Path -LiteralPath $mtxCsv) { $mtx = @(Import-Csv -LiteralPath $mtxCsv) }
    $iocSpread = @($mtx | Group-Object IOC | ForEach-Object {
        [pscustomobject]@{
            IOC = $_.Name
            HostCount = @($_.Group | Select-Object -ExpandProperty Host -Unique).Count
            Hosts = (@($_.Group | Select-Object -ExpandProperty Host -Unique) -join ', ')
            TotalHits = ($_.Group | Measure-Object -Property Hits -Sum).Sum
        }
    } | Sort-Object HostCount -Descending)
    $iocSpreadTable = ConvertTo-HtmlTable -Rows $iocSpread -Columns @('IOC','HostCount','Hosts','TotalHits') -Max 30

    $top = @($cards | Where-Object { $_.Score -ge 0 } | Sort-Object Score -Descending | Select-Object -First 1)
    $topLine = if ($top.Count -and $top[0].Score -gt 0) { "Highest-risk host: <b>$(Get-HtmlEnc $top[0].Host)</b> (score $($top[0].Score), $($top[0].Band))." }
               elseif ($cards.Count) { 'No host scored above MINIMAL.' } else { '' }

    $map = [ordered]@{
        '{{DATE}}'                  = (Get-Date -Format 'yyyy-MM-dd')
        '{{LAYOUT}}'                = (Get-HtmlEnc $Layout)
        '{{TOTAL}}'                 = [string]$rows.Count
        '{{OK_COUNT}}'              = [string]$ok.Count
        '{{FAIL_COUNT}}'            = [string]$fail.Count
        '{{HIT_HOSTS}}'             = [string]$hitHosts.Count
        '{{TOP_RISK_LINE}}'         = [string]$topLine
        '{{HOSTS_TABLE}}'           = $hostsTable
        '{{HOST_TIMELINES}}'        = $hostTimelines
        '{{IOC_SPREAD_TABLE}}'      = [string]$iocSpreadTable
    }
    foreach ($k in $map.Keys) {
        $v = $map[$k]
        if ($v -is [array]) { $v = ($v -join '') }
        $ks = [string]$k; $vs = [string]$v
        $html = $html.Replace($ks, $vs)
    }

    $out = Join-Path $OutputRoot '_GLOBAL_Findings_Report.html'
    $html | Set-Content -LiteralPath $out -Encoding UTF8
    Write-Log "  -> _GLOBAL_Findings_Report.html  (risk-ranked hosts + global activity timeline)" Green
    return $out
}
