# Coverage report + result. Single neutral posture: the engine reports matches and coverage,
# it never declares a host infected. A no-match result with any blind spot is flagged amber.

function Write-CoverageReport {
    param(
        [Parameter(Mandatory)]$Coverage,
        [Parameter(Mandatory)]$IocHitCount,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$HostName = ''
    )

    Write-Rule; Write-Log "ARTIFACT COVERAGE" Cyan
    foreach ($c in $Coverage) {
        $mark = switch ($c.State) {
            'Parsed'             {'x'} 'SkippedByConfig' {'~'} 'PresentNotAnalyzed' {'~'}
            'ToolMissing'        {'!'} 'ParseFailed'     {'!'} 'NoOutput' {'!'} default {' '}
        }
        $col = switch ($c.State) {
            'Parsed'             {'DarkGray'} 'SkippedByConfig' {'DarkYellow'} 'PresentNotAnalyzed' {'DarkYellow'}
            'ToolMissing'        {'Red'}      'ParseFailed'     {'Red'} 'NoOutput' {'Red'} default {'Yellow'}
        }
        Write-Log ("  [{0}] {1,-16} {2}" -f $mark, $c.Artifact, $c.State) $col
    }
    $Coverage | Select-Object @{n='Host';e={$HostName}}, Artifact, State, Purpose, Path |
        Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath 'Artifact_Coverage.csv')

    $parsed   = @($Coverage | Where-Object State -eq 'Parsed').Count
    $missing  = @($Coverage | Where-Object State -eq 'NotInCollection').Count
    $skipped  = @($Coverage | Where-Object State -eq 'SkippedByConfig').Count
    $toolless = @($Coverage | Where-Object State -eq 'ToolMissing').Count
    $failed   = @($Coverage | Where-Object { $_.State -in 'ParseFailed','NoOutput' }).Count
    $total    = $Coverage.Count
    $blind    = $missing + $skipped + $toolless + $failed

    # Core set for a meaningful result. EventLogs included: a logs-only collection is still
    # probative. Prefetch is NOT core - it is disabled by default on Windows Server.
    $core = @('MFT','Amcache','UsnJrnl','EventLogs')
    $coreParsed = @($Coverage | Where-Object { $_.Artifact -in $core -and $_.State -eq 'Parsed' }).Count
    $noCore = ($coreParsed -eq 0)

    $pfMissing = @($Coverage | Where-Object { $_.Artifact -eq 'Prefetch' -and $_.State -eq 'NotInCollection' }).Count -gt 0

    if ($IocHitCount -gt 0) {
        $verdict = "$IocHitCount IOC MATCH(ES) - review"
        $vc = 'Red'
    } elseif ($noCore) {
        $verdict = 'INCONCLUSIVE - no core artifacts (MFT/Amcache/UsnJrnl/EventLogs) were parsed'
        $vc = 'Red'
    } elseif ($blind -gt 0) {
        $verdict = "No IOC matches - BLIND SPOTS PRESENT ($blind artifact(s) not analyzed; see coverage)"
        $vc = 'Yellow'
    } else {
        $verdict = 'No IOC matches in the parsed artifacts'
        $vc = 'Green'
    }

    $summary = @"
HOST      : $HostName
RESULT    : $verdict
Coverage  : $parsed parsed / $missing not-collected / $toolless tool-missing / $failed parse-failed / $skipped skipped  (of $total)
IOC hits  : $IocHitCount
Note      : anything not 'Parsed' is a BLIND SPOT, not a clean result.
$(if($pfMissing){"Note      : Prefetch missing may be expected - it is disabled by default on Windows Server.`n"})$(if($toolless){"WARNING   : $toolless artifact(s) had no parser tool. Set -ToolsPath.`n"})$(if($noCore){"WARNING   : no core artifacts were parsed - this result is NOT meaningful.`n"})Output    : $OutputPath
"@
    $summary | Set-Content -Path (Join-Path $OutputPath '_Summary.txt')
    Write-Rule
    Write-Log "#### RESULT: $verdict ####" $vc
    Write-Log $summary $vc
    return $verdict
}
