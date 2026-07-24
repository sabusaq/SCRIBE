# Pre-flight disk capacity check for batch mode.
# Peak usage depends on cleanup mode: with delete-after-analysis the peak is the largest
# single archive expanded; with -KeepExtracted it's everything expanded at once.
# Triage archives typically expand 2-4x; we use 3x plus a flat per-host output estimate.

function Test-Capacity {
    param(
        [Parameter(Mandatory)][string]$BatchFolder,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$KeepExtracted,
        [int]$Parallel = 1,
        [switch]$Force
    )
    $expansionFactor = 3
    $outputPerHostMB = 500          # parsed CSVs + hayabusa output, rough upper bound
    $safetyMarginGB  = 2

    $archives = @(Get-ArchiveFiles -Folder $BatchFolder)
    $folders  = @(Get-ChildItem -LiteralPath $BatchFolder -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -notmatch '^(_extracted|_logs|_Analysis|_TriageAnalysis)$' })

    $archiveBytes = ($archives | Measure-Object Length -Sum).Sum
    if (-not $archiveBytes) { $archiveBytes = 0 }
    $largest = ($archives | Measure-Object Length -Maximum).Maximum
    if (-not $largest) { $largest = 0 }

    $hostCount = $archives.Count + $folders.Count

    if ($KeepExtracted) { $extractPeak = $archiveBytes * $expansionFactor }
    else {
        # with N parallel workers, up to N extractions exist at once
        $n = [Math]::Max(1, [Math]::Min($Parallel, [Math]::Max(1, $archives.Count)))
        $extractPeak = $largest * $expansionFactor * $n
    }
    $outputEst = $hostCount * $outputPerHostMB * 1MB
    $needed    = $extractPeak + $outputEst + ($safetyMarginGB * 1GB)

    # free space on the OUTPUT drive (extraction workdir lives under it)
    $full = $OutputPath
    try { $full = (Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop).Path } catch { }
    $rootPath = [System.IO.Path]::GetPathRoot($full)          # e.g. 'C:\'
    $free = $null
    if ($rootPath -and $rootPath.Length -ge 1) {
        $free = (Get-PSDrive -Name $rootPath.Substring(0,1) -ErrorAction SilentlyContinue).Free
    }
    if ($null -eq $free) {
        Write-Log "  [!] capacity: couldn't read free space for '$rootPath' - skipping check" Yellow
        return $true
    }

    $fmt = { param($b) '{0:n1} GB' -f ($b / 1GB) }
    Write-Log ("Capacity  : need ~{0} (peak extract {1} + outputs {2} + margin) / free {3}" -f `
        (& $fmt $needed), (& $fmt $extractPeak), (& $fmt $outputEst), (& $fmt $free)) DarkGray

    if ($free -ge $needed) { return $true }

    Write-Log "[X] Not enough disk space on the output drive." Red
    Write-Log ("    Estimated peak need : {0}  (mode: {1})" -f (& $fmt $needed), $(if($KeepExtracted){'keep-extracted: ALL archives expanded'}else{'delete-after: largest archive expanded'})) Yellow
    Write-Log ("    Free                : {0}" -f (& $fmt $free)) Yellow
    Write-Log "    Free up space, use a different -OutputPath drive, or re-run with -Force to override." Yellow
    if ($Force) {
        Write-Log "  [!] -Force set: continuing despite the capacity warning." Yellow
        return $true
    }
    return $false
}
