# Run Hayabusa: Sigma detections + a full event timeline. Non-fatal if hayabusa is missing.

function Invoke-Hayabusa {
    param(
        [Parameter(Mandatory)][string]$WinevtDir,   # ...\Windows\System32\winevt\Logs
        [Parameter(Mandatory)][string]$OutDir,      # per-host EventLogs folder
        [Parameter(Mandatory)][string]$LogDir,
        [string]$HayabusaExe,
        [switch]$AllRules,
        [string]$MinLevel = 'informational',
        [switch]$SkipDfirTimeline
    )
    if (-not $HayabusaExe -or -not (Test-Path -LiteralPath $HayabusaExe)) {
        Write-Log "  - Hayabusa : not found (set -Hayabusa or tools.hayabusaPath)" DarkGray
        return
    }
    if (-not (Test-Path -LiteralPath $WinevtDir)) {
        Write-Log "  - Hayabusa : winevt\Logs not present" DarkGray
        return
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $rules = Join-Path (Split-Path $HayabusaExe -Parent) 'rules'

    $common = @('-w','-C','-U','-m',$MinLevel)
    if ($AllRules) { $common += @('--enable-deprecated-rules','--enable-noisy-rules','--enable-unsupported-rules') }
    if (Test-Path -LiteralPath $rules) { $common += @('-r',$rules) }

    # Two passes over the same read-only input (different profiles; one invocation can't emit
    # both). Run them CONCURRENTLY - independent outputs, so this is safe and ~halves the step.
    #
    # EXCEPT under batch parallelism: Hayabusa is internally multi-threaded across all cores,
    # so N workers x 2 concurrent instances = 2N core-saturating processes fighting each
    # other. The orchestrator exports SCRIBE_PARALLEL_HOSTS; when 2 x workers would exceed
    # the core count, the two passes run sequentially instead (host-level parallelism is
    # already providing the speedup; doubling instances then only adds contention).
    $workers = 1
    if ($env:SCRIBE_PARALLEL_HOSTS) { [void][int]::TryParse($env:SCRIBE_PARALLEL_HOSTS, [ref]$workers); if ($workers -lt 1) { $workers = 1 } }
    $cores = 0
    [void][int]::TryParse([string]$env:NUMBER_OF_PROCESSORS, [ref]$cores)
    if ($cores -lt 1) { $cores = 4 }
    $runConcurrent = (($workers * 2) -le [Math]::Max(2, $cores))

    $detOut = Join-Path $OutDir 'Hayabusa_Detections.csv'
    $detArgs = @('csv-timeline','-d',$WinevtDir,'-o',$detOut) + $common

    if ($SkipDfirTimeline) {
        Invoke-Tool -Label 'Hayabusa' -ExePath $HayabusaExe -Arguments $detArgs -LogDir $LogDir | Out-Null
    } elseif (-not $runConcurrent) {
        # sequential passes: whole-CPU per pass, no cross-worker thrash
        $tlOut = Join-Path $OutDir 'Hayabusa_DFIR_Timeline.csv'
        $tlArgs = @('csv-timeline','-d',$WinevtDir,'-o',$tlOut,'-p','super-verbose') + $common
        Invoke-Tool -Label 'Hayabusa'     -ExePath $HayabusaExe -Arguments $detArgs -LogDir $LogDir | Out-Null
        Invoke-Tool -Label 'HayabusaDFIR' -ExePath $HayabusaExe -Arguments $tlArgs  -LogDir $LogDir | Out-Null
        if (Test-Path -LiteralPath $tlOut) { Write-Log "  -> Hayabusa_DFIR_Timeline.csv  (full DFIR event timeline)" Green }
    } else {
        $tlOut = Join-Path $OutDir 'Hayabusa_DFIR_Timeline.csv'
        $tlArgs = @('csv-timeline','-d',$WinevtDir,'-o',$tlOut,'-p','super-verbose') + $common

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $procs = @()
        foreach ($job in @(
            @{ Label='Hayabusa';     Args=$detArgs; Out=$detOut },
            @{ Label='HayabusaDFIR'; Args=$tlArgs;  Out=$tlOut }
        )) {
            $safe = Get-SafeName $job.Label
            $log  = Join-Path $LogDir ("{0}.log" -f $safe)
            $cmd  = ($job.Args | ForEach-Object { ConvertTo-NativeArg $_ }) -join ' '
            try {
                $proc = Start-Process -FilePath $HayabusaExe -ArgumentList $cmd -NoNewWindow -PassThru `
                            -RedirectStandardOutput $log -RedirectStandardError ($log -replace '\.log$','.err.log') -ErrorAction Stop
                $null = $proc.Handle   # cache the handle or ExitCode is unavailable after exit
                Add-Content -LiteralPath $log -Value "`n---`nCMD: `"$HayabusaExe`" $cmd" -ErrorAction SilentlyContinue
                $procs += @{ Label = $job.Label; Proc = $proc; Out = $job.Out }
            } catch {
                Write-Log ("  + {0,-16} ERROR: {1}" -f $job.Label, $_.Exception.Message) Yellow
            }
        }
        foreach ($p in $procs) {
            $p.Proc.WaitForExit()
            $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)   # elapsed since launch (both ran concurrently)
            $ec = $null; try { $ec = $p.Proc.ExitCode } catch { }
            # success = the output file exists and is non-empty; exit code is advisory
            $produced = (Test-Path -LiteralPath $p.Out) -and ((Get-Item -LiteralPath $p.Out -ErrorAction SilentlyContinue).Length -gt 0)
            $st = if ($produced) { 'OK' } elseif ($null -ne $ec) { "ExitCode=$ec" } else { 'no output' }
            $col = if ($st -eq 'OK') { 'Green' } else { 'Yellow' }
            Write-Log ("  + {0,-16} {1,7}s  {2}  (concurrent)" -f $p.Label, $secs, $st) $col
            if ($script:PerfRows -ne $null) {
                $script:PerfRows.Add([pscustomobject]@{
                    Host = $script:PerfHost; Step = $p.Label; Seconds = $secs; Status = $st
                    Exe = (Split-Path $HayabusaExe -Leaf)
                })
            }
        }
        if (Test-Path -LiteralPath $tlOut) { Write-Log "  -> Hayabusa_DFIR_Timeline.csv  (full DFIR event timeline)" Green }
    }

    if (Test-Path -LiteralPath $detOut) {
        # raw line count - never Import-Csv just to count
        $n = 0; foreach ($l in [System.IO.File]::ReadLines($detOut)) { $n++ }
        if ($n -gt 0) { $n-- }   # header
        Write-Log ("  -> Hayabusa_Detections.csv     ({0} Sigma detections)" -f $n) Green
    }
}
