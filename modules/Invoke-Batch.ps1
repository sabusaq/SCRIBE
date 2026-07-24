# Batch mode: for each collection in a folder, run the host pipeline, then aggregate.
# A failed collection is logged and skipped, not fatal. Outputs the _GLOBAL_* files.
# -MaxParallelHosts N runs collections in N child processes (each the unmodified
# single-host pipeline); default 1 = today's serial behavior.

# Cheap identity of the INPUT itself (size + last-write for archives). The params hash alone
# cannot see a re-collected archive dropped in under the same filename - resume must never
# skip a host whose evidence changed. Folders are analyzed in place and their root mtime does
# not reflect nested changes on NTFS, so for folders this is only a weak path identity;
# use -Rerun after replacing an extracted folder's contents.
function Get-InputFingerprint {
    param($Item)
    try {
        $fi = Get-Item -LiteralPath $Item.Path -ErrorAction Stop
        if ($Item.Kind -eq 'Archive') {
            return ('arc|{0}|{1}' -f $fi.Length, $fi.LastWriteTimeUtc.Ticks)
        }
        return ('dir|{0}' -f $fi.LastWriteTimeUtc.Ticks)
    } catch { return 'unknown' }
}

# resume marker: proves this host output came from a completed run with the SAME parameters
# and the SAME input (fingerprint above)
function Write-HostCompleteMarker {
    param([string]$HostOutput, [string]$ParamsHash, [string]$InputFingerprint, $Row)
    @{ paramsHash = $ParamsHash
       inputFingerprint = $InputFingerprint
       completedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
       row = $Row } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $HostOutput '.triage-complete.json') -Encoding UTF8
}

# returns the prior run's batch row if the host is complete under the same params AND the
# same input, else $null. Markers from versions without inputFingerprint fail the check and
# re-run once - correctness over convenience.
function Test-HostComplete {
    param([string]$HostOutput, [string]$ParamsHash, [string]$InputFingerprint)
    $m = Join-Path $HostOutput '.triage-complete.json'
    if (-not (Test-Path -LiteralPath $m)) { return $null }
    try { $j = Get-Content -LiteralPath $m -Raw | ConvertFrom-Json } catch { return $null }
    if ($j.paramsHash -ne $ParamsHash) { return $null }
    if ($j.inputFingerprint -ne $InputFingerprint) { return $null }
    return [pscustomobject]@{
        Host = $j.row.Host; Source = $j.row.Source; Kind = $j.row.Kind
        Status = $j.row.Status; Result = $j.row.Result; IocHits = [int]$j.row.IocHits
        Parsed = [int]$j.row.Parsed; NotCollected = [int]$j.row.NotCollected
        ToolMissing = [int]$j.row.ToolMissing; Skipped = [int]$j.row.Skipped; Output = $j.row.Output
        Seconds = $(if ($j.row.Seconds) { [double]$j.row.Seconds } else { 0 })
    }
}

# extract + analyze + cleanup for ONE labeled collection. Shared by the serial loop and
# by worker processes - the unit of parallelism is this whole function.
function Invoke-OneCollection {
    param(
        $Item, [string]$HostLabel, [string]$OutputRoot, [string]$WorkDir,
        [string]$SevenZip, [switch]$KeepExtracted, [switch]$KeepOnHit,
        [string]$ArchivePassword, [string]$LogDir, $RunHost, [string]$ParamsHash,
        [string]$InputFingerprint
    )
    $row = [ordered]@{
        Host = $HostLabel; Source = $Item.Name; Kind = $Item.Kind; Status = ''; Result = ''
        IocHits = 0; Parsed = 0; NotCollected = 0; ToolMissing = 0; Skipped = 0; Output = ''; Seconds = 0
    }
    $hostSw = [System.Diagnostics.Stopwatch]::StartNew()
    $collRoot = $null
    $extractedPath = $null      # set only for archives (safe to delete)

    if ($Item.Kind -eq 'Archive') {
        $ex = Expand-Collection -ArchivePath $Item.Path -DestRoot $WorkDir -SevenZip $SevenZip -LogDir $LogDir -Password $ArchivePassword
        if (-not $ex.Ok) {
            Write-Log ("  [X] {0}" -f $ex.Message) Red
            $row.Status = 'FAILED-EXTRACT'; $row.Result = $ex.Message
            $row.Seconds = [math]::Round($hostSw.Elapsed.TotalSeconds, 1)
            return [pscustomobject]$row
        }
        Write-Log ("  extracted -> {0}" -f $ex.Dest) DarkGray
        $extractedPath = $ex.Dest
        $collRoot = Get-CollectionRoot -ExtractedPath $ex.Dest
    } else {
        Write-Log ("  analyzing in place -> {0}" -f $Item.Path) DarkGray
        $collRoot = Get-CollectionRoot -ExtractedPath $Item.Path
    }

    $hostOut = Join-Path $OutputRoot $HostLabel
    try {
        $res = & $RunHost $collRoot $hostOut $HostLabel
        # a function returns ALL pipeline output; pick the element that is the result object
        if ($res -is [array]) {
            $res = @($res | Where-Object {
                ($_ -is [hashtable] -and $_.ContainsKey('Ok')) -or
                ($_ -and $_.PSObject -and $_.PSObject.Properties['Ok'])
            } | Select-Object -Last 1)[0]
        }
        if ($res -and $res.Ok) {
            $row.Status       = 'OK'
            $row.Result       = $res.Verdict
            $row.IocHits      = $res.IocHitCount
            $row.Parsed       = $res.Parsed
            $row.NotCollected = $res.NotCollected
            $row.ToolMissing  = $res.ToolMissing
            $row.Skipped      = $res.Skipped
            $row.Output       = $hostOut
        } else {
            $row.Status = 'FAILED-ANALYZE'
            $row.Result = if ($res) { $res.Message } else { 'analysis returned nothing' }
            Write-Log ("  [X] {0}" -f $row.Result) Red
        }
    } catch {
        $row.Status = 'FAILED-ANALYZE'
        $where = ''
        if ($_.InvocationInfo) { $where = (" (line {0}: {1})" -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) }
        $row.Result = "$($_.Exception.Message)$where"
        Write-Log ("  [X] analyze error: {0}" -f $row.Result) Red
    }

    # completion marker enables resume: skip this host next run if params AND input match
    if ($row.Status -eq 'OK' -and $ParamsHash) {
        $row.Seconds = [math]::Round($hostSw.Elapsed.TotalSeconds, 1)
        Write-HostCompleteMarker -HostOutput $hostOut -ParamsHash $ParamsHash `
                                 -InputFingerprint $InputFingerprint -Row ([pscustomobject]$row)
    }

    # cleanup: ONLY delete what WE extracted. -KeepOnHit retains extractions with IOC hits.
    $hadHit = ([int]$row.IocHits -gt 0)
    if ($extractedPath -and -not $KeepExtracted -and -not ($KeepOnHit -and $hadHit)) {
        Remove-Item -LiteralPath $extractedPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  cleaned up extracted files" DarkGray
    } elseif ($extractedPath -and $KeepOnHit -and $hadHit) {
        Write-Log "  kept extracted files (IOC hits - pivot here)" Yellow
    }
    $row.Seconds = [math]::Round($hostSw.Elapsed.TotalSeconds, 1)
    Write-Log ("  host wall time: {0}s" -f $row.Seconds) DarkGray
    return [pscustomobject]$row
}

function Invoke-Batch {
    param(
        [Parameter(Mandatory)][string]$BatchFolder,
        [Parameter(Mandatory)][string]$Layout,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)]$RunHost,          # scriptblock: analyze one collection
        [string]$WorkDir,
        [string]$SevenZip,
        [switch]$KeepExtracted,
        [switch]$KeepOnHit,
        [string]$ArchivePassword,
        [string]$TimelineMode = 'none',
        $TlStart = $null,
        $TlEnd = $null,
        [int]$MaxParallelHosts = 1,
        [switch]$Rerun,
        [string]$ParamsHash,
        $WorkerCli = $null
    )

    $batchSw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $WorkDir) { $WorkDir = Join-Path $OutputRoot '_extracted' }
    $logDir = Join-Path $OutputRoot '_logs'
    New-Item -ItemType Directory -Force -Path $OutputRoot, $logDir | Out-Null

    # Build a unified work list. Each item is either an ARCHIVE (extract first) or a
    # FOLDER (already-extracted collection - analyze in place). A mixed folder works.
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($a in (Get-ArchiveFiles -Folder $BatchFolder)) {
        $items.Add([pscustomobject]@{ Kind = 'Archive'; Name = $a.Name; Path = $a.FullName })
    }
    foreach ($d in (Get-ChildItem -LiteralPath $BatchFolder -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        # skip our own scratch/output folders
        if ($d.Name -match '^(_extracted|_logs|_Analysis|_TriageAnalysis)$') { continue }
        if ($d.FullName -eq $OutputRoot) { continue }
        $items.Add([pscustomobject]@{ Kind = 'Folder'; Name = $d.Name; Path = $d.FullName })
    }

    if ($items.Count -eq 0) {
        Write-Log "Nothing to analyze in $BatchFolder" Red
        Write-Log "  Expected archives ($($script:ArchiveExts -join ', ')) and/or already-extracted collection folders." Yellow
        return
    }

    $nArc = @($items | Where-Object Kind -eq 'Archive').Count
    $nDir = @($items | Where-Object Kind -eq 'Folder').Count
    if ($nArc) { New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null }

    Write-Log "`n#### BATCH MODE ####" Cyan
    Write-Log ("Collections : {0}  ({1} archive(s), {2} extracted folder(s))" -f $items.Count, $nArc, $nDir) DarkGray
    Write-Log ("Layout      : {0} (applied to all)" -f $Layout) DarkGray
    if ($nArc) {
        Write-Log ("Work dir    : {0}" -f $WorkDir) DarkGray
        Write-Log ("Cleanup     : {0}" -f $(if ($KeepExtracted) { 'keep extracted' } else { 'delete extracted after analysis' })) DarkGray
    }
    Write-Log "Note        : already-extracted folders are analyzed IN PLACE and never deleted." DarkGray

    # labels assigned up front (collision-guarded) so serial and parallel share one implementation
    $usedLabels = @{}
    $labeled = New-Object System.Collections.Generic.List[object]
    foreach ($it in $items) {
        $base = if ($it.Kind -eq 'Archive') {
            [System.IO.Path]::GetFileNameWithoutExtension($it.Name) -replace '\.tar$',''
        } else { $it.Name }
        $hostLabel = $base
        # strip collector naming down to the hostname: '<prefix>_Aralez_<HOST>_<date>_<time>'
        # (any collector prefix), then the generic '<HOST>_<date>_<time>' pattern
        if ($base -match '(?:^|_)Aralez_(.+?)_\d{4}-\d{2}-\d{2}[_T]\d{2}-\d{2}-\d{2}$') { $hostLabel = $Matches[1] }
        elseif ($base -match '^(.+?)_\d{4}-\d{2}-\d{2}[_T]\d{2}-\d{2}-\d{2}$')          { $hostLabel = $Matches[1] }
        if ($usedLabels.ContainsKey($hostLabel)) { $hostLabel = $base }
        $n = 2; $try = $hostLabel
        while ($usedLabels.ContainsKey($try)) { $try = "{0}_{1}" -f $hostLabel, $n; $n++ }
        $hostLabel = $try; $usedLabels[$hostLabel] = $true
        $labeled.Add([pscustomobject]@{ Item = $it; Label = $hostLabel; Fp = (Get-InputFingerprint -Item $it) })
    }

    $batchRows = New-Object System.Collections.Generic.List[object]

    # resume: a host completed in a prior run with the SAME params AND the SAME input is
    # reused, not re-analyzed
    $pending = New-Object System.Collections.Generic.List[object]
    foreach ($li in $labeled) {
        $prev = $null
        if (-not $Rerun -and $ParamsHash) {
            $prev = Test-HostComplete -HostOutput (Join-Path $OutputRoot $li.Label) -ParamsHash $ParamsHash `
                                      -InputFingerprint $li.Fp
        }
        if ($prev) {
            Write-Log ("[skip] {0}  - complete from a prior run with identical parameters (-Rerun to force)" -f $li.Label) DarkGray
            $batchRows.Add($prev)
        } else {
            $pending.Add($li)
        }
    }

    if ($MaxParallelHosts -le 1 -or $pending.Count -le 1) {
        # ---- serial (default: today's exact behavior) ----
        $i = 0
        foreach ($li in $pending) {
            $i++
            Write-Rule
            Write-Log ("[{0}/{1}] {2}  ({3})" -f $i, $pending.Count, $li.Item.Name, $li.Item.Kind) Cyan
            $row = Invoke-OneCollection -Item $li.Item -HostLabel $li.Label -OutputRoot $OutputRoot -WorkDir $WorkDir `
                       -SevenZip $SevenZip -KeepExtracted:$KeepExtracted -KeepOnHit:$KeepOnHit `
                       -ArchivePassword $ArchivePassword -LogDir $logDir -RunHost $RunHost -ParamsHash $ParamsHash `
                       -InputFingerprint $li.Fp
            $batchRows.Add($row)
        }
    } else {
        # ---- parallel: N child processes, each running the unmodified single-host pipeline ----
        # Per-host console output goes to _logs\<host>.console.log; the orchestrator prints
        # compact progress lines. Process isolation: one host's crash cannot touch another.
        Write-Rule
        Write-Log ("PARALLEL: {0} worker process(es), {1} pending host(s)" -f $MaxParallelHosts, $pending.Count) Cyan
        $jobsDir = Join-Path $logDir 'jobs'
        New-Item -ItemType Directory -Force -Path $jobsDir | Out-Null

        # Secrets and tuning travel via the inherited process ENVIRONMENT, not the job file:
        # - the archive password never touches disk (job files used to carry it in plaintext)
        # - workers use the parallelism level to budget Hayabusa's two concurrent passes
        if ($ArchivePassword) { $env:SCRIBE_ARCHIVE_PW = $ArchivePassword }
        $env:SCRIBE_PARALLEL_HOSTS = [string]$MaxParallelHosts

        # Largest collections FIRST: with more hosts than workers, wall time = when the last
        # host finishes, and a giant host starting late is pure added wall time (classic
        # makespan scheduling). Archives are sized by file length; folders by a recursive
        # sum (one enumeration per collection, done once here).
        $sized = foreach ($li in $pending) {
            $sz = [long]0
            try {
                if ($li.Item.Kind -eq 'Archive') {
                    $sz = (Get-Item -LiteralPath $li.Item.Path -ErrorAction Stop).Length
                } else {
                    $sz = [long]((Get-ChildItem -LiteralPath $li.Item.Path -Recurse -File -ErrorAction SilentlyContinue |
                                  Measure-Object -Property Length -Sum).Sum)
                }
            } catch { $sz = [long]0 }
            [pscustomobject]@{ Li = $li; Size = $sz }
        }
        $queue = New-Object System.Collections.Generic.Queue[object]
        foreach ($s in ($sized | Sort-Object Size -Descending)) { $queue.Enqueue($s.Li) }
        $running = New-Object System.Collections.Generic.List[object]
        $done = 0; $totalP = $pending.Count

        while ($queue.Count -gt 0 -or $running.Count -gt 0) {
            while ($queue.Count -gt 0 -and $running.Count -lt $MaxParallelHosts) {
                $li = $queue.Dequeue()
                $safe = Get-SafeName $li.Label
                $jobPath = Join-Path $jobsDir ($safe + '.job.json')
                $resPath = Join-Path $jobsDir ($safe + '.result.json')
                if (Test-Path -LiteralPath $resPath) { Remove-Item -LiteralPath $resPath -Force -ErrorAction SilentlyContinue }
                @{
                    Item = @{ Kind = $li.Item.Kind; Name = $li.Item.Name; Path = $li.Item.Path }
                    HostLabel = $li.Label; OutputRoot = $OutputRoot; WorkDir = $WorkDir
                    SevenZip = $SevenZip; KeepExtracted = [bool]$KeepExtracted; KeepOnHit = [bool]$KeepOnHit
                    ParamsHash = $ParamsHash; InputFingerprint = $li.Fp; ResultPath = $resPath
                    Cli = $WorkerCli
                } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jobPath -Encoding UTF8

                $conLog = Join-Path $logDir ($safe + '.console.log')
                $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $script:TriageScriptPath + '"'),'-WorkerJob',('"' + $jobPath + '"'))
                try {
                    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $args -PassThru -WindowStyle Hidden `
                                -RedirectStandardOutput $conLog -RedirectStandardError ($conLog -replace '\.console\.log$','.console.err.log') -ErrorAction Stop
                    $running.Add(@{ Label = $li.Label; Item = $li.Item; Proc = $proc; ResPath = $resPath; ConLog = $conLog })
                    Write-Log ("[start {0}/{1}] {2}" -f ($done + $running.Count), $totalP, $li.Label) Cyan
                } catch {
                    $done++
                    Remove-Item -LiteralPath $jobPath -Force -ErrorAction SilentlyContinue
                    $batchRows.Add([pscustomobject]@{
                        Host = $li.Label; Source = $li.Item.Name; Kind = $li.Item.Kind
                        Status = 'FAILED-WORKER'; Result = "could not start worker: $($_.Exception.Message)"
                        IocHits = 0; Parsed = 0; NotCollected = 0; ToolMissing = 0; Skipped = 0; Output = ''; Seconds = 0
                    })
                }
            }
            Start-Sleep -Milliseconds 1500
            for ($k = $running.Count - 1; $k -ge 0; $k--) {
                $w = $running[$k]
                if (-not $w.Proc.HasExited) { continue }
                $running.RemoveAt($k); $done++
                # job spec no longer carries secrets (password moved to the env), but tidy up anyway
                $jobFile = $w.ResPath -replace '\.result\.json$', '.job.json'
                Remove-Item -LiteralPath $jobFile -Force -ErrorAction SilentlyContinue
                $row = $null
                if (Test-Path -LiteralPath $w.ResPath) {
                    try {
                        $j = Get-Content -LiteralPath $w.ResPath -Raw | ConvertFrom-Json
                        $row = [pscustomobject]@{
                            Host = $j.Host; Source = $j.Source; Kind = $j.Kind; Status = $j.Status; Result = $j.Result
                            IocHits = [int]$j.IocHits; Parsed = [int]$j.Parsed; NotCollected = [int]$j.NotCollected
                            ToolMissing = [int]$j.ToolMissing; Skipped = [int]$j.Skipped; Output = $j.Output
                            Seconds = $(if ($j.Seconds) { [double]$j.Seconds } else { [math]::Round(($w.Proc.ExitTime - $w.Proc.StartTime).TotalSeconds, 1) })
                        }
                    } catch { $row = $null }
                }
                if (-not $row) {
                    $row = [pscustomobject]@{
                        Host = $w.Label; Source = $w.Item.Name; Kind = $w.Item.Kind
                        Status = 'FAILED-WORKER'; Result = "worker exited $($w.Proc.ExitCode) without a result - see _logs\$(Split-Path $w.ConLog -Leaf)"
                        IocHits = 0; Parsed = 0; NotCollected = 0; ToolMissing = 0; Skipped = 0; Output = ''
                        Seconds = [math]::Round(($w.Proc.ExitTime - $w.Proc.StartTime).TotalSeconds, 1)
                    }
                }
                $batchRows.Add($row)
                $col = if ([int]$row.IocHits -gt 0) { 'Red' } elseif ($row.Status -ne 'OK') { 'Yellow' } else { 'Green' }
                Write-Log ("[done {0}/{1}] {2,-24} {3}  ({4} IOC hit(s), {5}s)  log: _logs\{6}" -f `
                           $done, $totalP, $row.Host, $row.Status, $row.IocHits, $row.Seconds, (Split-Path $w.ConLog -Leaf)) $col
                if ($row.Status -ne 'OK' -and $row.Result) {
                    Write-Log ("        reason: {0}" -f $row.Result) Yellow
                }
            }
        }

        # scrub the inherited env once workers are done
        Remove-Item Env:\SCRIBE_ARCHIVE_PW    -ErrorAction SilentlyContinue
        Remove-Item Env:\SCRIBE_PARALLEL_HOSTS -ErrorAction SilentlyContinue
    }

    # =======================================================================
    # GLOBAL AGGREGATION
    # =======================================================================
    Write-Rule; Write-Log "GLOBAL AGGREGATION" Cyan

    # --- 1) global IOC timeline: every hit, every host, time-sorted ---
    # Only read IOC_Hits.csv from the per-host output folders WE created this run (batchRows),
    # so stale files elsewhere in OutputRoot can never contaminate the aggregate.
    $allHits = New-Object System.Collections.Generic.List[object]
    foreach ($br in $batchRows) {
        if ($br.Status -ne 'OK' -or -not $br.Output) { continue }
        $hitsCsv = Join-Path $br.Output 'IOC_Hits.csv'
        if (-not (Test-Path -LiteralPath $hitsCsv)) { continue }
        Import-Csv -LiteralPath $hitsCsv -ErrorAction SilentlyContinue | ForEach-Object {
            $allHits.Add([pscustomobject]@{
                MatchTime    = $_.MatchTime
                TimeSemantic = $_.TimeSemantic
                Confidence   = $_.Confidence
                Host         = $br.Host       # the ARCHIVE name - authoritative, never the 'C' folder
                Source       = $br.Source
                IOC          = $_.IOC
                Artifact     = $_.Source
                Line         = $_.Line
                File         = $_.File
                # D3: carry the family + dedup flag from the per-host sweep. Older per-host
                # CSVs without these columns are treated as primary (non-duplicate).
                EvidenceFamily    = $(if ($_.PSObject.Properties['EvidenceFamily']) { $_.EvidenceFamily } else { '' })
                DuplicateInFamily = $(if ($_.PSObject.Properties['DuplicateInFamily']) { $_.DuplicateInFamily } else { '' })
            })
        }
    }

    if ($allHits.Count) {
        # precompute the sort key once per row (scriptblock sort keys re-evaluate per comparison)
        foreach ($h in $allHits) {
            $d = ConvertTo-DateTimeSafe $h.MatchTime
            $h | Add-Member -NotePropertyName _sk -NotePropertyValue $(if ($d) { $d } else { [datetime]::MaxValue }) -Force
        }
        $sorted = $allHits | Sort-Object _sk, Host, IOC
        $sorted | Select-Object * -ExcludeProperty _sk |
            Export-Csv -NoTypeInformation -Path (Join-Path $OutputRoot '_GLOBAL_IOC_Timeline.csv')
        Write-Log ("  -> _GLOBAL_IOC_Timeline.csv  ({0} hits across {1} host(s))" -f `
                   $allHits.Count, (@($allHits | Select-Object -ExpandProperty Host -Unique).Count)) Red

        # --- 2) IOC matrix: per host x IOC, first/last seen + count ---
        # D3: 'Hits' counts DISTINCT hits (primary rows) so the same event rendered in
        # EventLogs + both Hayabusa views is one, not three; 'AllHits' keeps the raw total
        # for transparency. First/last-seen still consider every row's timestamp.
        $matrix = $allHits | Group-Object Host, IOC | ForEach-Object {
            $times = $_.Group | ForEach-Object { $_._sk } | Where-Object { $_ -ne [datetime]::MaxValue } | Sort-Object
            $prim  = @($_.Group | Where-Object { [string]$_.DuplicateInFamily -ne 'True' })
            $fams  = @($_.Group | ForEach-Object { if ($_.EvidenceFamily) { $_.EvidenceFamily } else { $_.Artifact } } | Select-Object -Unique)
            [pscustomobject]@{
                Host      = $_.Group[0].Host
                Source    = $_.Group[0].Source
                IOC       = $_.Group[0].IOC
                Hits      = $prim.Count
                AllHits   = $_.Count
                FirstSeen = $(if ($times) { $times[0].ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                LastSeen  = $(if ($times) { $times[-1].ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                Families  = ($fams -join '; ')
                Artifacts = (($_.Group | Select-Object -ExpandProperty Artifact -Unique) -join '; ')
            }
        } | Sort-Object FirstSeen, Host
        $matrix | Export-Csv -NoTypeInformation -Path (Join-Path $OutputRoot '_GLOBAL_IOC_Matrix.csv')
        Write-Log "  -> _GLOBAL_IOC_Matrix.csv    (host x IOC: first/last seen)" Red

        # console: earliest hit per host = likely infection order
        Write-Log "`n  Earliest observed artifact time per host (mixed timestamp semantics - NOT reliable infection order):" Yellow
        $matrix | Where-Object FirstSeen | Group-Object Host | ForEach-Object {
            $first = ($_.Group | Sort-Object FirstSeen | Select-Object -First 1)
            [pscustomobject]@{ Host = $_.Name; FirstSeen = $first.FirstSeen; IOC = $first.IOC }
        } | Sort-Object FirstSeen | ForEach-Object {
            Write-Log ("    {0}  {1,-22}  {2}" -f $_.FirstSeen, $_.Host, $_.IOC) Yellow
        }
    } else {
        Write-Log "  no IOC hits on any host" Green
    }

    # --- 3) coverage matrix ---
    $batchRows | Export-Csv -NoTypeInformation -Path (Join-Path $OutputRoot '_GLOBAL_Coverage.csv')
    Write-Log "`n  -> _GLOBAL_Coverage.csv      (per-host result + coverage)" Green

    # --- 4) global super-timeline (Timesketch CSV) across all hosts ---
    # PERF (the old hotspot): per-host timelines are now built INSIDE each host's analysis -
    # i.e. in parallel across worker processes - and this step only MERGES the already-built
    # Timeline_Timesketch.csv files by streaming their bytes (skip each header after the
    # first; identical schema, and the 'host' column keeps rows separable). The transform
    # cost scales with -MaxParallelHosts; the merge is sequential I/O at disk speed.
    # Fallback: a host missing its per-host file (e.g. resumed from a pre-update run) is
    # rebuilt individually - never silently dropped from the global timeline.
    if ($TimelineMode -eq 'global') {
        $gTl = Join-Path $OutputRoot '_GLOBAL_Timeline_Timesketch.csv'
        if (Test-Path -LiteralPath $gTl) { Remove-Item -LiteralPath $gTl -Force -ErrorAction SilentlyContinue }
        $tlSw = [System.Diagnostics.Stopwatch]::StartNew()

        # header first (matches Build-HostTimeline's header exactly; per-host files are
        # BOM-less UTF-8, so raw byte concatenation below is safe)
        $enc = New-Object System.Text.UTF8Encoding($false)
        $hdrText = "`"message`",`"datetime`",`"timestamp_desc`",`"data_type`",`"host`",`"source_short`"`r`n"
        [System.IO.File]::WriteAllText($gTl, $hdrText, $enc)
        $hdrBytes = [long]$enc.GetByteCount($hdrText)

        $merged = 0; $rebuilt = 0; $bytes = [long]0
        foreach ($br in $batchRows) {
            if ($br.Status -ne 'OK' -or -not $br.Output) { continue }
            $per = Join-Path $br.Output 'Timeline_Timesketch.csv'
            $hasPer = (Test-Path -LiteralPath $per) -and ((Get-Item -LiteralPath $per -ErrorAction SilentlyContinue).Length -gt 0)
            if ($hasPer) {
                $in  = $null; $out = $null
                try {
                    $in  = [System.IO.File]::OpenRead($per)
                    # skip the per-host header line (single physical line, we wrote it)
                    $b = 0
                    while (($b = $in.ReadByte()) -ne -1) { if ($b -eq 10) { break } }
                    if ($in.Position -lt $in.Length) {
                        $out = [System.IO.File]::Open($gTl, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
                        $in.CopyTo($out)
                        $bytes += ($in.Length - $in.Position)
                    }
                    $merged++
                } catch {
                    Write-Log ("  [!] global timeline: merge failed for {0} ({1}) - rebuilding this host" -f $br.Host, $_.Exception.Message) Yellow
                    $hasPer = $false
                } finally {
                    if ($in)  { $in.Close() }
                    if ($out) { $out.Close() }
                }
            }
            if (-not $hasPer) {
                # rebuild just this host into the global file (appends; header already present)
                $n = Build-HostTimeline -HostOutput $br.Output -HostName $br.Host -OutFile $gTl -Start $TlStart -End $TlEnd
                if ($n -gt 0) { $rebuilt++ }
            }
        }
        $tlSw.Stop()
        $gLen = (Get-Item -LiteralPath $gTl -ErrorAction SilentlyContinue).Length
        if ($gLen -gt $hdrBytes) {   # more than just the header
            Write-Log ("  -> _GLOBAL_Timeline_Timesketch.csv  ({0:n1} MB; merged {1} host timeline(s){2} in {3}s)" -f `
                       ($gLen / 1MB), $merged, $(if ($rebuilt) { ", rebuilt $rebuilt" } else { '' }), [math]::Round($tlSw.Elapsed.TotalSeconds, 1)) Green
        } else {
            Write-Log "  global timeline: no rows in window" DarkGray
        }
    }

    # --- 4) summary ---
    $batchSw.Stop()
    $wall = [math]::Round($batchSw.Elapsed.TotalSeconds, 1)
    $hostSum = [math]::Round((($batchRows | Measure-Object -Property Seconds -Sum).Sum), 1)
    $ok      = @($batchRows | Where-Object Status -eq 'OK').Count
    $failed  = @($batchRows | Where-Object { $_.Status -like 'FAILED*' }).Count
    $withIoc = @($batchRows | Where-Object { [int]$_.IocHits -gt 0 }).Count

    $summary = @"
BATCH SUMMARY
=============
Collections        : $($items.Count)  ($nArc archive(s), $nDir folder(s))
Analyzed OK        : $ok
Failed             : $failed
Hosts with IOC hits: $withIoc
Layout             : $Layout
Wall time          : ${wall}s total  (sum of per-host times: ${hostSum}s$(if ($MaxParallelHosts -gt 1) { " - parallelism saved $([math]::Round($hostSum - $wall, 1))s" }))

Read:
  _GLOBAL_IOC_Timeline.csv  - all IOC hits, all hosts, time-sorted (times carry a TimeSemantic column; do not treat as infection order)
  _GLOBAL_IOC_Matrix.csv    - per host x IOC: first seen / last seen / count
  _GLOBAL_Coverage.csv      - per host: result + coverage (FAILED rows listed here)

NOTE: hosts with low coverage or FAILED status are BLIND SPOTS, not clean results.
"@
    $summary | Set-Content -Path (Join-Path $OutputRoot '_BATCH_Summary.txt')
    Write-Rule
    Write-Log $summary $(if ($withIoc) { 'Red' } else { 'Green' })

    if ($failed) { Write-Log "  [!] $failed archive(s) FAILED - see _GLOBAL_Coverage.csv" Yellow }
    if ($nArc -and -not $KeepExtracted) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}
