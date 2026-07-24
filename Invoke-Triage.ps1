<#
.SYNOPSIS
  SCRIBE.
  Parses a pre-collected Windows triage package (or a whole FOLDER OF ARCHIVES), sweeps IOCs,
  runs Sigma detection, builds timelines, and reports honestly what it could and could not see.

.DESCRIPTION
  Case-agnostic. You select the collection layout; the engine validates it, parses in-scope
  artifacts (config-driven), sweeps optional IOCs, and reports coverage honestly.

  BATCH MODE (-BatchFolder): point at a folder of archives (.zip/.7z/.tar.gz/...). Each is
  extracted, analyzed, and cleaned up, then results are aggregated into a GLOBAL IOC TIMELINE
  showing which IOC matched on which host and when - the outbreak spread view.

.PARAMETER HostArtifacts
  Single-host mode: path to one unzipped collection (or drive root for -Layout Raw).

.PARAMETER BatchFolder
  Batch mode: a folder containing MULTIPLE COLLECTIONS. Each may be an archive
  (.zip/.7z/.tar.gz/...) OR an already-extracted collection folder - a mix of both is fine.
  Archives are extracted to a work dir (and deleted after analysis unless -KeepExtracted).
  Already-extracted folders are analyzed IN PLACE and are NEVER deleted.
  One -Layout applies to all. Results are aggregated into a global IOC timeline/matrix.

.PARAMETER Layout
  Auto (default) | Aralez | KAPE | CyLR | Velociraptor | Raw. Auto tries every known
  drive-root pattern and prints how it resolved; name a layout to force a structure.

.PARAMETER ToolsPath
  Folder containing the Eric Zimmerman tools (searched recursively). Overrides config.json.
  REQUIRED tools: MFTECmd, AmcacheParser, PECmd, EvtxECmd, RECmd (+Kroll_Batch.reb).
  OPTIONAL (extended/full tiers): AppCompatCacheParser, SrumECmd, SBECmd, RBCmd, LECmd, JLECmd.

.PARAMETER SevenZipPath
  Path to 7z.exe. Only needed in batch mode for non-.zip archives. Auto-found if omitted.

.PARAMETER KeepExtracted
  Batch mode: keep extracted collections (default: delete after each host is analyzed).

.EXAMPLE
  .\Invoke-Triage.ps1 -HostArtifacts D:\case\HOST01 -Layout Aralez -ToolsPath C:\Tools\ZimmermanTools -IocFile .\iocs.txt

.EXAMPLE
  .\Invoke-Triage.ps1 -BatchFolder D:\evidence\archives -Layout Aralez -ToolsPath C:\Tools\ZimmermanTools -IocFile .\iocs.txt -OutputPath D:\out
#>
[CmdletBinding(DefaultParameterSetName='Single')]
param(
    [Parameter(ParameterSetName='Help')][switch]$Help,
    [Parameter(ParameterSetName='Single')][string]$HostArtifacts,
    [Parameter(ParameterSetName='Batch')][string]$BatchFolder,
    [Parameter(ParameterSetName='Single')]
    [Parameter(ParameterSetName='Batch')]
    [ValidateSet('Auto','Aralez','KAPE','CyLR','Velociraptor','Raw')][string]$Layout = 'Auto',
    [string]$ScopeConfig,
    [string[]]$IocFile,
    [ValidateSet('default','extended','full')][string]$Tier,
    [string]$OutputPath,
    [string]$HostName,
    [string]$ToolsPath,
    [string]$SevenZipPath,
    [string]$Hayabusa,
    [switch]$SkipHayabusa,
    [ValidateSet('none','case','global')][string]$Timeline = 'none',
    [string]$TimelineStart,
    [string]$TimelineEnd,
    [switch]$Report,
    [switch]$Force,
    [switch]$FilteredCopies,
    [switch]$Visibility,
    [switch]$Manifest,
    [switch]$KeepOnHit,
    [string]$ArchivePassword,
    [switch]$NoDiscover,
    [Parameter(ParameterSetName='Batch')][switch]$KeepExtracted,
    [Parameter(ParameterSetName='Batch')][string]$WorkDir,
    [Parameter(ParameterSetName='Batch')][int]$MaxParallelHosts = 1,
    [Parameter(ParameterSetName='Batch')][switch]$Rerun,
    [Parameter(ParameterSetName='Worker')][string]$WorkerJob
)
$ErrorActionPreference = 'Continue'
$root = Split-Path $MyInvocation.MyCommand.Path -Parent
$script:TriageScriptPath = $MyInvocation.MyCommand.Path

# --- worker mode (internal): restore the orchestrator's CLI params, then run one collection ---
$script:WorkerSpec = $null
if ($WorkerJob) {
    $script:WorkerSpec = Get-Content -LiteralPath $WorkerJob -Raw | ConvertFrom-Json
    $c = $script:WorkerSpec.Cli
    if ($c.Layout)   { $Layout = $c.Layout }
    if ($c.Tier)     { $Tier = $c.Tier }
    if ($c.Timeline) { $Timeline = $c.Timeline }
    $ToolsPath = $c.ToolsPath; $Hayabusa = $c.Hayabusa
    $IocFile = @($c.IocFile | Where-Object { $_ }); $ScopeConfig = $c.ScopeConfig
    $TimelineStart = $c.TimelineStart; $TimelineEnd = $c.TimelineEnd
    $Report = [bool]$c.Report; $FilteredCopies = [bool]$c.FilteredCopies
    $Visibility = [bool]$c.Visibility; $Manifest = [bool]$c.Manifest
    $NoDiscover = [bool]$c.NoDiscover
    $SkipHayabusa = [bool]$c.SkipHayabusa; $SevenZipPath = $c.SevenZipPath
    $OutputPath = $script:WorkerSpec.OutputRoot
    $HostArtifacts = $null; $BatchFolder = $null
}

# ===========================================================================
# -Help : print usage and exit (before loading modules/config)
# ===========================================================================
if ($Help -or (-not $HostArtifacts -and -not $BatchFolder -and -not $WorkerJob)) {
@"

DFIR TRIAGE ENGINE
==================
Parses a pre-collected Windows triage package, runs optional detections (IOC / Sigma),
builds a DFIR timeline, and reports honestly what it could and could NOT see.

USAGE
-----
  SINGLE HOST:
    .\Invoke-Triage.ps1 -HostArtifacts <path> -Layout <name> [options]

  BATCH (folder of archives and/or extracted collections):
    .\Invoke-Triage.ps1 -BatchFolder <path> -Layout <name> [options]

REQUIRED
--------
  -HostArtifacts <path>   One collection folder (single-host mode).
  -BatchFolder   <path>   Folder of collections: archives, extracted folders, or a mix.
  -Layout        <name>   Auto(default) | Aralez | KAPE | CyLR | Velociraptor | Raw
                          Optional - omit to auto-resolve the drive root.

TOOLS
-----
  -ToolsPath     <path>   Eric Zimmerman tools folder (searched recursively).
                          Core: MFTECmd, AmcacheParser, PECmd, EvtxECmd, RECmd(+Kroll_Batch.reb)
  -Hayabusa      <exe>    Hayabusa exe -> Sigma detections + full DFIR timeline. Optional.
  -SevenZipPath  <exe>    7z.exe, only for non-.zip archives in batch mode. Auto-found.

DETECTION
---------
  -IocFile   <path...>    IOC file(s) or a folder of them. Optional - Sigma still runs if empty.
                          One indicator per line (#=comment): hashes, filenames, IPs, domains, strings.

SCOPE
-----
  -Tier      <name>       default | extended | full        (default: default)
  -ScopeConfig <path>     JSON scope config: tier, add/skip artifacts, IOC files, time focus.
                          Schema + allowed keys: config\config-schema.json.
  -OutputPath  <path>     Where results go. Default: <input>\_Analysis

SWITCHES
--------
  -KeepExtracted          Batch: keep extracted archives (default: delete after analysis).
  -SkipHayabusa           Skip Sigma detections + DFIR timeline.
  -Timeline <mode>        Build a Timesketch-format super-timeline from ALL in-scope artifacts.
                          case   = one Timeline_Timesketch.csv per host
                          global = one _GLOBAL_Timeline_Timesketch.csv across all hosts (batch)
  -TimelineStart <utc>    Lower bound (ISO 8601), e.g. 2026-06-10T08:00:00
  -TimelineEnd   <utc>    Upper bound. Strongly recommended - full MFT timelines are huge.
                          Add -FilteredCopies to also write *_filtered.csv per artifact
                          (rows in the window only; the full CSVs stay untouched).
  -Report                 Write Findings_Report.html per host + _GLOBAL_Findings_Report.html
                          for a batch. Ready to read as generated; open in Word to save
                          as .docx, print for PDF.
  -Force                  Override the batch disk-capacity hard stop.
  -FilteredCopies         With a time window, also write *_filtered.csv per artifact (opt-in).
  -KeepOnHit              Batch: keep a host's extracted files when it matched IOCs (pivot).
  -ArchivePassword <pw>   Password for protected archives (e.g. 'infected').
  -Visibility             Write Visibility_Windows.csv per host: the time horizon each parsed
                          artifact can actually speak about (USN span, per-channel log depth).
  -Manifest               Write run-manifest.json per host: input/IOC hashes, tool versions,
                          parameters - the reproducibility record.
  -MaxParallelHosts <n>   Batch: analyze up to N collections in parallel child processes.
                          Default 1 (serial). Per-host console goes to _logs\<host>.console.log.
  -Rerun                  Batch: re-analyze hosts even if complete from a prior identical run.
  -NoDiscover             Disable the artifact-discovery fallback.
  -Help                   Show this page.

OUTPUT (read in this order)
---------------------------
  _Summary.txt             Result + coverage at a glance.
  IOC_Hits.csv             Every IOC match: when, which IOC, which artifact.
  Artifact_Coverage.csv    Parsed / NotInCollection / ToolMissing / NoOutput / Skipped.
  EventLogs\
    Hayabusa_Detections.csv     "Is anything BAD?"      <- start here if you know nothing
    Hayabusa_DFIR_Timeline.csv  "What HAPPENED, in order?"
    EventLogs.csv               "Show me EVERY event of type X"
  _logs\                   Per-tool logs incl. the exact CMD line run.

  BATCH also produces:
  _GLOBAL_IOC_Timeline.csv  All IOC hits, all hosts, time-sorted (the spread view).
  _GLOBAL_IOC_Matrix.csv    Per host x IOC: first seen / last seen / count.
  _GLOBAL_Coverage.csv      Per host: result + coverage (+ FAILED rows).

COVERAGE HONESTY
----------------
  'No hits' NEVER silently means 'clean'. Anything not parsed is reported as a BLIND SPOT:
  NotInCollection (not collected) | ToolMissing (no parser) | NoOutput (tool failed) |
  SkippedByConfig (you told it to). If no core artifact parsed, the result is INCONCLUSIVE.

EXAMPLES
--------
  # Single Aralez host with IOCs
  .\Invoke-Triage.ps1 -HostArtifacts "D:\case\HOST01" -Layout Aralez ``
    -ToolsPath "C:\Tools\ZimmermanTools" -IocFile ".\iocs.txt"

  # Batch with Sigma + DFIR timeline
  .\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -Layout Aralez ``
    -ToolsPath "C:\Tools\ZimmermanTools" -Hayabusa "C:\Tools\hayabusa\hayabusa.exe" ``
    -IocFile ".\iocs.txt" -OutputPath "D:\out"

  # Mounted image / Windows.old
  .\Invoke-Triage.ps1 -HostArtifacts "E:\mounted\C" -Layout Raw -ToolsPath "C:\Tools\ZimmermanTools"

MORE
----
  Full guide:  HELP.md    Layouts: docs-LAYOUTS.md    Scope schema: config\config-schema.json
  PowerShell:  Get-Help .\Invoke-Triage.ps1 -Full

"@ | Write-Host
    return
}

# --- validate: one input source only (Layout now defaults to Auto) ---
if ($HostArtifacts -and $BatchFolder) {
    Write-Host "[X] Use -HostArtifacts OR -BatchFolder, not both." -ForegroundColor Red; return
}
$inRoot = if ($BatchFolder) { $BatchFolder } else { $HostArtifacts }

# --- engine modules ---
. (Join-Path $root 'modules\Common.ps1')
. (Join-Path $root 'modules\Accelerator.ps1')
. (Join-Path $root 'modules\Resolve-Layout.ps1')
. (Join-Path $root 'modules\Expand-Collection.ps1')
. (Join-Path $root 'modules\Invoke-Parsing.ps1')
. (Join-Path $root 'modules\Invoke-Hayabusa.ps1')
. (Join-Path $root 'modules\Invoke-Detections.ps1')
. (Join-Path $root 'modules\Get-Coverage.ps1')
. (Join-Path $root 'modules\Get-Visibility.ps1')
. (Join-Path $root 'modules\Write-Manifest.ps1')
. (Join-Path $root 'modules\Build-Timeline.ps1')
. (Join-Path $root 'modules\Test-Capacity.ps1')
. (Join-Path $root 'modules\New-Report.ps1')
. (Join-Path $root 'modules\Invoke-Batch.ps1')

# --- config ---
$cfg       = Import-JsonConfig (Join-Path $root 'config\config.json')
$layouts   = Import-JsonConfig (Join-Path $root 'config\layouts.json')
$artifacts = Import-JsonConfig (Join-Path $root 'config\artifacts.json')
$parsers   = Import-JsonConfig (Join-Path $root 'config\parsers.json')

# Explicit -OutputPath inside the evidence tree: allowed (the analyst asked for it) but
# never silent. Segment-aware, so the normal sibling default ('<input>_Analysis') does
# not trip it the way a bare StartsWith comparison did.
if ($OutputPath -and $inRoot -and (Test-PathInside -Child $OutputPath -Parent $inRoot)) {
    Write-Log "[!] -OutputPath is INSIDE the evidence folder. This WRITES analysis files into the collection tree" Yellow
    Write-Log "    and modifies the evidence volume (new MFT/`$J records). On a write-blocked mount it will fail." Yellow
    Write-Log "    Recommended: point -OutputPath outside the evidence (proceeding since you set it explicitly)." Yellow
}

# startup signature - once per run, not per worker (workers log to per-host files)
if (-not $WorkerJob) {
    $bArt = @($artifacts.PSObject.Properties.Name | Where-Object { $_ -ne '_comment' }).Count
    $bPar = @($parsers.PSObject.Properties.Name  | Where-Object { $_ -ne '_comment' }).Count
    $bLay = @($layouts.PSObject.Properties.Name  | Where-Object { $_ -ne '_comment' }).Count
    $bMode = if ($BatchFolder) { 'batch' } else { 'single host' }
    Write-ScribeBanner -ArtifactCount $bArt -ParserCount $bPar -LayoutCount $bLay `
                       -Accel ([bool]$script:AccelOK) -Mode $bMode
}

$scope     = if ($ScopeConfig) { Import-JsonConfig $ScopeConfig } else { $null }
if ($scope) {
    # Enforce the schema's allowed keys. A typoed key ('skipArtifact') silently doing
    # nothing is worse than a hard stop - the analyst would believe scope was applied.
    $allowedKeys = @{
        meta  = @('layout','hostName','hypothesis')
        parse = @('tier','addArtifacts','skipArtifacts')
        hunt  = @('iocFiles','sigma')
        focus = @('timeStart','timeEnd')
    }
    foreach ($k in $scope.PSObject.Properties.Name) {
        if (-not $allowedKeys.ContainsKey($k)) {
            Write-Host "[X] ScopeConfig: unknown top-level key '$k'. Allowed: $($allowedKeys.Keys -join ', ') (see config\config-schema.json)." -ForegroundColor Red; return
        }
        $section = $scope.$k
        if ($section -is [System.Management.Automation.PSCustomObject]) {
            foreach ($sk in $section.PSObject.Properties.Name) {
                if ($allowedKeys[$k] -notcontains $sk) {
                    Write-Host "[X] ScopeConfig: unknown key '$k.$sk'. Allowed under '$k': $($allowedKeys[$k] -join ', ')." -ForegroundColor Red; return
                }
            }
        }
    }
    # precedence everywhere: CLI > scope > config default
    if ($Layout -eq 'Auto' -and $scope.meta.layout) { $Layout = [string]$scope.meta.layout }
    if (-not $TimelineStart -and $scope.focus.timeStart) { $TimelineStart = $scope.focus.timeStart }
    if (-not $TimelineEnd   -and $scope.focus.timeEnd)   { $TimelineEnd   = $scope.focus.timeEnd }
    if ($scope.hunt.sigma -eq $false) { $SkipHayabusa = $true }
}

# --- effective settings (CLI > scope > config default) ---
$effTier = if ($Tier) { $Tier } elseif ($scope.parse.tier) { $scope.parse.tier } else { $cfg.defaults.tier }
$addArt  = @(); if ($scope.parse.addArtifacts)  { $addArt  = $scope.parse.addArtifacts }
$skipArt = @(); if ($scope.parse.skipArtifacts) { $skipArt = $scope.parse.skipArtifacts }
$iocSpecs = @()
if ($IocFile)             { $iocSpecs += $IocFile }
if ($scope.hunt.iocFiles) { $iocSpecs += $scope.hunt.iocFiles }
if (-not $iocSpecs)       { $iocSpecs = @(Join-Path $root $cfg.detections.iocFolder) }

# --- tools (CLI > config). Resolved once, reused for every host. ---
$effToolsPath = if ($ToolsPath)    { $ToolsPath }    else { $cfg.tools.toolsPath }
$effSevenZip  = if ($SevenZipPath) { $SevenZipPath } else { $cfg.tools.sevenZipPath }

if (-not $effToolsPath -or -not (Test-Path -LiteralPath $effToolsPath)) {
    Write-Log "[X] ToolsPath not found: '$effToolsPath'" Red
    Write-Log "    Set it with -ToolsPath <folder>, or edit config\config.json (tools.toolsPath)." Yellow
    Write-Log "    Get the Eric Zimmerman tools: https://ericzimmerman.github.io/  (or Get-ZimmermanTools.ps1)" Yellow
    return
}
Write-Log "Tools     : $effToolsPath" DarkGray
$tools    = Get-ToolTable -ToolsPath $effToolsPath
$sevenZip = Resolve-SevenZip -ConfiguredPath $effSevenZip
$effHayabusa = if ($Hayabusa) { $Hayabusa } elseif ($cfg.tools.hayabusaPath) { $cfg.tools.hayabusaPath } else { $null }

# Sigma settings from config.json (detections.sigma). Missing keys fall back to the
# documented defaults so an older config file keeps working.
$sigmaCfg      = $cfg.detections.sigma
$sigmaAllRules = ($null -eq $sigmaCfg.allRules) -or [bool]$sigmaCfg.allRules
$sigmaMinLevel = if ($sigmaCfg.minLevel) { [string]$sigmaCfg.minLevel } else { 'informational' }
$sigmaDfirTl   = ($null -eq $sigmaCfg.buildDfirTimeline) -or [bool]$sigmaCfg.buildDfirTimeline

# --- preflight: report tool availability by importance, not one warning per artifact ---
$core = @{
    'MFTECmd'       = '$MFT / $J   (file existence + activity sequence)'
    'AmcacheParser' = 'Amcache     (SHA1 hashes -> IOC confirmation)'
    'PECmd'         = 'Prefetch    (execution evidence)'
    'EvtxECmd'      = 'Event logs'
    'RECmd'         = 'Registry    (services, run keys)'
}
$missingCore = @()
Write-Log "Preflight :" DarkGray
foreach ($t in $core.Keys) {
    if ($tools[$t]) { Write-Log ("  [x] {0,-14} {1}" -f $t, $core[$t]) DarkGray }
    else            { Write-Log ("  [ ] {0,-14} {1}" -f $t, $core[$t]) Yellow; $missingCore += $t }
}
if ($tools['RECmd'] -and -not $tools['krollBatch']) {
    Write-Log "  [!] RECmd found but Kroll_Batch.reb missing - registry parsing will be skipped." Yellow
}
if ($missingCore.Count) {
    Write-Log ("  [!] {0} core tool(s) missing - those artifacts will be SKIPPED (reported as blind spots)." -f $missingCore.Count) Yellow
}
if (-not $sevenZip) {
    Write-Log "  [ ] 7-Zip          (batch: only needed for non-.zip archives)" DarkGray
}

$iocs = Import-Iocs -IocFiles $iocSpecs
Write-Log ("IOCs      : {0} indicator(s) loaded" -f @($iocs).Count) DarkGray

# fingerprint of everything that changes analysis results - resume only skips a host when
# this matches its completion marker (a changed IOC list must never be skipped past)
$paramsHash = $null
if ($BatchFolder -or $WorkerJob) {
    $sigObj = @{
        Layout = $Layout; Tier = $effTier; IocSet = (Get-IocSetHash $iocs)
        Timeline = $Timeline; TlStart = $TimelineStart; TlEnd = $TimelineEnd
        SkipHayabusa = [bool]$SkipHayabusa; Report = [bool]$Report; FilteredCopies = [bool]$FilteredCopies
        Visibility = [bool]$Visibility; Manifest = [bool]$Manifest
        AddArtifacts = @($addArt); SkipArtifacts = @($skipArt); Discover = (-not $NoDiscover)
    }
    $sig = ($sigObj | ConvertTo-Json -Compress)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $paramsHash = ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sig))) -replace '-','')
}

# timeline window (parsed once)
$tlStart = if ($TimelineStart) { ConvertTo-DateTimeSafe $TimelineStart } else { $null }
$tlEnd   = if ($TimelineEnd)   { ConvertTo-DateTimeSafe $TimelineEnd }   else { $null }
if (($tlStart -or $tlEnd) -and $FilteredCopies) {
    Write-Log "  Window   : *_filtered.csv copies will be written per artifact (full CSVs kept)" DarkGray
}
if ($Timeline -ne 'none' -and -not $tlStart -and -not $tlEnd) {
    Write-Log "  [!] -Timeline set with no -TimelineStart/-TimelineEnd: full timeline may be very large (MFT)." Yellow
}

# ===========================================================================
# The single-host pipeline, reusable by both modes.
# Returns @{ Ok; Verdict; IocHitCount; Parsed; NotCollected; Skipped; Message }
# ===========================================================================
function Invoke-SingleHost {
    param([string]$CollectionPath, [string]$OutPath, [string]$Label)

    Write-Log "`n#### HOST : $Label ####" Cyan
    Start-PerfCapture -HostName $Label

    $resolved = Resolve-Layout -HostArtifacts $CollectionPath -LayoutName $Layout -Layouts $layouts
    if (-not $resolved.Ok) {
        Write-Log "[X] $($resolved.Message)" Red
        return @{ Ok = $false; Message = $resolved.Message }
    }
    Write-Log "[OK] $($resolved.Message)" Green

    $logDir = Join-Path $OutPath '_logs'
    New-Item -ItemType Directory -Force -Path $OutPath, $logDir | Out-Null

    $parse = Invoke-Parsing -Resolved $resolved -Tools $tools -Artifacts $artifacts -Parsers $parsers `
                            -OutputPath $OutPath -LogDir $logDir -Tier $effTier `
                            -AddArtifacts $addArt -SkipArtifacts $skipArt -Discover:(-not $NoDiscover)

    # --- Hayabusa: Sigma detections + full DFIR timeline from the event logs ---
    if (-not $SkipHayabusa) {
        $winevt = $resolved.SystemRoot.TrimEnd('\') + '\System32\winevt\Logs'
        if (-not (Test-Path -LiteralPath $winevt)) { $winevt = $resolved.SystemRoot.TrimEnd('\') + '\System32\winevt\logs' }
        $swStage = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-Hayabusa -WinevtDir $winevt -OutDir (Join-Path $OutPath 'EventLogs') -LogDir $logDir `
                        -HayabusaExe $effHayabusa -AllRules:$sigmaAllRules -MinLevel $sigmaMinLevel `
                        -SkipDfirTimeline:(-not $sigmaDfirTl)
        $swStage.Stop(); Add-PerfRow -Step 'Hayabusa(total)' -Seconds $swStage.Elapsed.TotalSeconds -Exe 'hayabusa'
    }

    $swStage = [System.Diagnostics.Stopwatch]::StartNew()
    $hits = Invoke-IocSweep -OutputPath $OutPath -Iocs $iocs -HostName $Label
    $swStage.Stop(); Add-PerfRow -Step 'IocSweep' -Seconds $swStage.Elapsed.TotalSeconds
    Write-Log ("  sweep wall time: {0}s" -f [math]::Round($swStage.Elapsed.TotalSeconds, 1)) DarkGray

    $verdict = Write-CoverageReport -Coverage $parse.Coverage -IocHitCount @($hits).Count `
                                    -OutputPath $OutPath -HostName $Label

    # Post-analysis steps. The verdict is already computed - a failure in any of these is
    # reported loudly (with the failing line) but NEVER fails the host.
    $post = @(
        @{ Name = 'visibility'; When = [bool]$Visibility; Run = {
            Get-VisibilityWindows -HostOutput $OutPath | Out-Null } }
        @{ Name = 'manifest'; When = [bool]$Manifest; Run = {
            Write-RunManifest -OutputPath $OutPath -Context @{
                HostName = $Label; Layout = $Layout; InputPath = $CollectionPath
                Params = @{ Tier=$effTier; Timeline=$Timeline; TimelineStart=$TimelineStart; TimelineEnd=$TimelineEnd
                            AddArtifacts=$addArt; SkipArtifacts=$skipArt; Discover=(-not $NoDiscover) }
                Tools = $tools; Hayabusa = $effHayabusa; Iocs = $iocs; IocFiles = $iocSpecs
            } | Out-Null } }
        # 'global' also builds the per-host file here: serial batch hosts feed the same
        # merge path as parallel workers (and a lone -HostArtifacts run with -Timeline
        # global now sensibly produces its per-host timeline instead of nothing)
        @{ Name = 'timeline'; When = ($Timeline -eq 'case' -or $Timeline -eq 'global'); Run = {
            $tlFile = Join-Path $OutPath 'Timeline_Timesketch.csv'
            if (Test-Path -LiteralPath $tlFile) { Remove-Item -LiteralPath $tlFile -Force -ErrorAction SilentlyContinue }
            $n = Build-HostTimeline -HostOutput $OutPath -HostName $Label -OutFile $tlFile -Start $tlStart -End $tlEnd
            if ($n) { Write-Log ("  -> Timeline_Timesketch.csv  ({0} rows)" -f $n) Green }
            else    { Write-Log "  timeline: no rows in window" DarkGray } } }
        @{ Name = 'report'; When = [bool]$Report; Run = {
            New-TriageReport -HostOutput $OutPath -HostName $Label `
                             -TemplatePath (Join-Path $root 'templates\report-template.html') `
                             -Layout $Layout -IocCount @($iocs).Count -Verdict $verdict | Out-Null } }
        @{ Name = 'filtered-copies'; When = ($FilteredCopies -and ($tlStart -or $tlEnd)); Run = {
            Export-FilteredArtifacts -HostOutput $OutPath -Start $tlStart -End $tlEnd } }
        @{ Name = 'perf-telemetry'; When = $true; Run = {
            Save-PerfCapture -OutputPath $OutPath } }
    )
    foreach ($step in $post) {
        if (-not $step.When) { continue }
        $swStep = [System.Diagnostics.Stopwatch]::StartNew()
        $stepStatus = 'OK'
        try { & $step.Run }
        catch {
            $stepStatus = "ERROR: $($_.Exception.Message)"
            $where = ''
            if ($_.InvocationInfo) { $where = (" (line {0}: {1})" -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) }
            Write-Log ("  [!] {0} step failed: {1}{2}" -f $step.Name, $_.Exception.Message, $where) Yellow
        }
        $swStep.Stop()
        if ($step.Name -ne 'perf-telemetry') {
            Add-PerfRow -Step $step.Name -Seconds $swStep.Elapsed.TotalSeconds -Status $stepStatus
            if ($swStep.Elapsed.TotalSeconds -ge 1) {
                Write-Log ("  {0} wall time: {1}s" -f $step.Name, [math]::Round($swStep.Elapsed.TotalSeconds, 1)) DarkGray
            }
        }
    }

    return @{
        Ok           = $true
        Verdict      = $verdict
        IocHitCount  = @($hits).Count
        Parsed       = @($parse.Coverage | Where-Object State -eq 'Parsed').Count
        NotCollected = @($parse.Coverage | Where-Object State -eq 'NotInCollection').Count
        ToolMissing  = @($parse.Coverage | Where-Object State -eq 'ToolMissing').Count
        Skipped      = @($parse.Coverage | Where-Object State -eq 'SkippedByConfig').Count
    }
}

# ===========================================================================
# Dispatch
# ===========================================================================
if ($WorkerJob) {
    # one collection, result to the orchestrator via JSON, then exit.
    # The archive password arrives via the inherited environment (never written to disk);
    # job specs from an older orchestrator that still carry it inline keep working.
    $wj = $script:WorkerSpec
    $wPw = if ($wj.ArchivePassword) { [string]$wj.ArchivePassword }
           elseif ($env:SCRIBE_ARCHIVE_PW) { $env:SCRIBE_ARCHIVE_PW } else { $null }
    $item = [pscustomobject]@{ Kind = $wj.Item.Kind; Name = $wj.Item.Name; Path = $wj.Item.Path }
    $row = Invoke-OneCollection -Item $item -HostLabel $wj.HostLabel -OutputRoot $wj.OutputRoot -WorkDir $wj.WorkDir `
               -SevenZip $wj.SevenZip -KeepExtracted:([bool]$wj.KeepExtracted) -KeepOnHit:([bool]$wj.KeepOnHit) `
               -ArchivePassword $wPw -LogDir (Join-Path $wj.OutputRoot '_logs') `
               -RunHost ${function:Invoke-SingleHost} -ParamsHash $wj.ParamsHash `
               -InputFingerprint ([string]$wj.InputFingerprint)
    $row | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $wj.ResultPath -Encoding UTF8
    return
}
if ($BatchFolder) {

    if (-not $OutputPath) {
        # never write into the evidence tree by default - use a sibling folder, and refuse
        # to guess when the input is a volume/share root (there is no sibling to use)
        $def = Resolve-DefaultOutputPath -InputPath $BatchFolder -Mode 'batch'
        if (-not $def.Ok) {
            Write-Log "[X] $($def.Reason)" Red
            Write-Log "    SCRIBE never writes analysis output into the evidence by default." Yellow
            Write-Log "    $($def.Suggestion)" Yellow
            return
        }
        $OutputPath = $def.Path
    }

    # hard stop if the output drive can't hold peak extraction + outputs (-Force overrides)
    if (-not (Test-Capacity -BatchFolder $BatchFolder -OutputPath $OutputPath `
                            -KeepExtracted:$KeepExtracted -Parallel $MaxParallelHosts -Force:$Force)) { return }

    # Guard: writing batch output straight into Desktop/Downloads/Documents scatters per-host
    # folders + _extracted + global CSVs among the user's files, and the IOC sweep can then
    # pick up unrelated/stale CSVs already sitting there. Insist on a dedicated subfolder.
    $risky = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", $env:USERPROFILE)
    $opFull = try { (Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop).Path } catch { $OutputPath }
    if ($risky -contains $opFull.TrimEnd('\')) {
        $suggest = Join-Path $opFull 'TriageOut'
        Write-Log "[X] -OutputPath '$opFull' is a top-level user folder." Red
        Write-Log "    Batch mode writes per-host folders, _extracted\, and global CSVs there," Yellow
        Write-Log "    which clutters it AND lets stale CSVs contaminate the IOC sweep." Yellow
        Write-Log "    Use a dedicated subfolder, e.g.:  -OutputPath `"$suggest`"" Yellow
        return
    }

    # everything a worker needs to reconstruct this run's analysis parameters
    $workerCli = @{
        Layout = $Layout; ToolsPath = $ToolsPath; Hayabusa = $Hayabusa; SevenZipPath = $SevenZipPath
        IocFile = @($IocFile); Tier = $Tier; ScopeConfig = $ScopeConfig
        # PERF: for -Timeline global, each WORKER builds its per-host timeline (= the
        # expensive transform, parallelized), and the orchestrator merely byte-merges the
        # per-host files. Previously workers got 'none' and the orchestrator rebuilt every
        # host's timeline serially after the parallel phase - the single slowest step of a
        # batch ran on one thread. Bonus: global mode now also leaves a per-host
        # Timeline_Timesketch.csv in each host folder.
        Timeline = $(if ($Timeline -eq 'global') { 'case' } else { $Timeline })
        TimelineStart = $TimelineStart; TimelineEnd = $TimelineEnd
        Report = [bool]$Report; FilteredCopies = [bool]$FilteredCopies
        Visibility = [bool]$Visibility; Manifest = [bool]$Manifest
        NoDiscover = [bool]$NoDiscover; SkipHayabusa = [bool]$SkipHayabusa
    }

    Invoke-Batch -BatchFolder $BatchFolder -Layout $Layout -OutputRoot $OutputPath `
                 -RunHost ${function:Invoke-SingleHost} -WorkDir $WorkDir `
                 -SevenZip $sevenZip -KeepExtracted:$KeepExtracted -KeepOnHit:$KeepOnHit `
                 -ArchivePassword $ArchivePassword `
                 -TimelineMode $Timeline -TlStart $tlStart -TlEnd $tlEnd `
                 -MaxParallelHosts $MaxParallelHosts -Rerun:$Rerun -ParamsHash $paramsHash -WorkerCli $workerCli

    # batch summary report across all hosts
    if ($Report) {
        New-GlobalReport -OutputRoot $OutputPath -Layout $Layout `
                         -TemplatePath (Join-Path $root 'templates\report-global-template.html') | Out-Null
    }

} else {

    if (-not $HostName)   { $HostName   = if ($scope.meta.hostName) { $scope.meta.hostName } else { Split-Path $HostArtifacts -Leaf } }
    if (-not $OutputPath) {
        # never write into the evidence tree by default - use a sibling folder, and refuse
        # to guess when the input is a volume/share root (there is no sibling to use)
        $def = Resolve-DefaultOutputPath -InputPath $HostArtifacts -Mode 'single'
        if (-not $def.Ok) {
            Write-Log "[X] $($def.Reason)" Red
            Write-Log "    SCRIBE never writes analysis output into the evidence by default." Yellow
            Write-Log "    $($def.Suggestion)" Yellow
            return
        }
        $OutputPath = $def.Path
    }
    Write-Log "Layout    : $Layout   Tier: $effTier" DarkGray

    $hostSw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-SingleHost -CollectionPath $HostArtifacts -OutPath $OutputPath -Label $HostName
    $hostSw.Stop()
    Write-Log ("Total wall time: {0}s" -f [math]::Round($hostSw.Elapsed.TotalSeconds, 1)) DarkGray
    if ($r.Ok) {
        Write-Log "`nRead: _Summary.txt -> IOC_Hits.csv -> Artifact_Coverage.csv -> per-artifact CSVs" DarkGray
    }
}
