# Shared helpers. Dot-sourced by Invoke-Triage.ps1. Targets PS 5.1.

function Write-Log {
    param([string]$Msg, [string]$Color = 'Gray')
    Write-Host $Msg -ForegroundColor $Color
}
function Write-Rule { Write-Log ('-' * 70) DarkGray }

# datetime or $null. Invariant culture + AssumeUniversal: analyst locale must not reorder
# timelines (06/01/2026 is ambiguous across cultures), and EZ/Hayabusa emit UTC.
#
# Perf: this runs once per timestamp CELL in every hot loop (timeline, filtered copies,
# visibility, sweep) - tens of millions of calls on a large MFT/UsnJrnl. Two optimizations,
# both semantics-preserving and both MEASURED (variants with a multi-format list were
# slower on unique-value workloads; a single exact format + fallback won on all workloads):
#   1. TryParseExact against the one fixed format the EZ tools emit; anything else -
#      e.g. Hayabusa's '+00:00' suffix - falls through to the original TryParse, so no
#      input that parsed before fails now.
#   2. A last-value memo: UsnJrnl/EventLog bursts repeat identical raw strings heavily.
$script:DtsLastRaw = $null
$script:DtsLastVal = $null
function ConvertTo-DateTimeSafe {
    param($Value)
    if (-not $Value) { return $null }
    $s = [string]$Value
    if ($s.Length -eq 0) { return $null }
    if ($s -eq $script:DtsLastRaw) { return $script:DtsLastVal }

    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
              [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ok = [datetime]::TryParseExact($s, 'yyyy-MM-dd HH:mm:ss.fffffff', $inv, $styles, [ref]$d)
    if (-not $ok) { $ok = [datetime]::TryParse($s, $inv, $styles, [ref]$d) }

    $script:DtsLastRaw = $s
    $script:DtsLastVal = if ($ok) { $d } else { $null }
    return $script:DtsLastVal
}

# ---------------------------------------------------------------- output path ----
# Decide the DEFAULT output folder for an input path, or refuse.
#
# The read-only guarantee is the product. A sibling folder ("<input>_Analysis") is safe
# because it is created NEXT TO the evidence, never inside it. That trick has no answer
# when the input is a VOLUME ROOT (E:\ or \\server\share): there is no sibling to create,
# and the previous behaviour - falling back to "<root>\_TriageAnalysis" - wrote analysis
# output INTO the evidence volume. On a mounted image that is either a hard failure
# (write blocker) or, worse, a silent modification of the evidence: new MFT records, new
# $J entries, new directory index pages. So: refuse to guess, and say why.
#
# Returns @{ Ok = [bool]; Path = [string]; Reason = [string]; Suggestion = [string] }
function Resolve-DefaultOutputPath {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [ValidateSet('single','batch')][string]$Mode = 'single'
    )
    $trim = ([string]$InputPath).TrimEnd('\','/')
    $param = if ($Mode -eq 'batch') { '-BatchFolder' } else { '-HostArtifacts' }

    # E:  /  E:\  - a drive root
    if ($trim -match '^[A-Za-z]:$') {
        return @{
            Ok         = $false
            Path       = $null
            Reason     = "$param is a DRIVE ROOT ('$trim\'). There is no sibling folder to write to, and defaulting to a folder on that volume would write analysis output onto the evidence itself."
            Suggestion = "Re-run with an explicit -OutputPath on a DIFFERENT volume, e.g.  -OutputPath `"$env:USERPROFILE\SCRIBE\$(Split-Path $trim -Leaf)`""
        }
    }
    # \\server\share - a UNC share root: same problem, and '<share>_Analysis' is not a valid path
    if ($trim -match '^\\\\[^\\]+\\[^\\]+$') {
        return @{
            Ok         = $false
            Path       = $null
            Reason     = "$param is a UNC SHARE ROOT ('$trim'). There is no sibling folder to write to, and SCRIBE will not write analysis output into the evidence share."
            Suggestion = "Re-run with an explicit -OutputPath outside the share, e.g.  -OutputPath `"$env:USERPROFILE\SCRIBE\out`""
        }
    }
    return @{ Ok = $true; Path = ($trim + '_Analysis'); Reason = ''; Suggestion = '' }
}

# Is $OutputPath inside $InputPath (i.e. would we write into the evidence tree)?
# Segment-aware: 'D:\case\HOST01_Analysis' is NOT inside 'D:\case\HOST01'.
function Test-PathInside {
    param([string]$Child, [string]$Parent)
    if (-not $Child -or -not $Parent) { return $false }
    $c = ([string]$Child).TrimEnd('\','/')
    $p = ([string]$Parent).TrimEnd('\','/')
    try { $c = [System.IO.Path]::GetFullPath($c) } catch { }
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { }
    $c = $c.TrimEnd('\','/'); $p = $p.TrimEnd('\','/')
    if ($c.Equals($p, 'OrdinalIgnoreCase')) { return $true }
    return $c.StartsWith($p + '\', 'OrdinalIgnoreCase')
}

# ---------------------------------------------------------------- robocopy ----
# Robocopy exit codes are BIT FLAGS, not a success/failure integer:
#   1 files copied, 2 extra files, 4 mismatched, 8 FAILURES (locked/denied/too long),
#   16 FATAL. Anything with bit 8 or 16 set means files were NOT copied. Everything
#   below 8 is success. Silently discarding this is how a completely failed
#   ScheduledTasks copy used to be recorded as 'Parsed'.
function Test-RobocopySuccess {
    param($ExitCode)
    if ($null -eq $ExitCode) { return $false }
    $n = 0
    if (-not [int]::TryParse([string]$ExitCode, [ref]$n)) { return $false }
    return ($n -ge 0 -and $n -lt 8)
}

# make a label safe to use as a filename
function Get-SafeName {
    param([string]$Name)
    return ($Name -replace '[:\\/*?"<>|]', '_')
}

# Load a JSON config file. Fails loudly on missing/invalid JSON. Returns a PSCustomObject.
# (Scope-config key validation happens in Invoke-Triage.ps1 against the documented schema.)
function Import-JsonConfig {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Config not found: $Path" }
    try   { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
    catch { throw "Invalid JSON in ${Path}: $($_.Exception.Message)" }
}

# find an exe under a root
function Resolve-Tool {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$ExeName)
    if (-not (Test-Path -LiteralPath $Root)) { return $null }
    $hit = Get-ChildItem -LiteralPath $Root -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName } else { return $null }
}

# resolve the EZ tools + Kroll batch under toolsPath - single enumeration, dictionary lookup
function Get-ToolTable {
    param([Parameter(Mandatory)][string]$ToolsPath)
    $needed = 'MFTECmd','PECmd','AmcacheParser','AppCompatCacheParser','SrumECmd',
              'RECmd','EvtxECmd','SBECmd','RBCmd','LECmd','JLECmd'
    $t = @{}
    foreach ($n in $needed) { $t[$n] = $null }
    $t['krollBatch'] = $null
    if (-not (Test-Path -LiteralPath $ToolsPath)) { return $t }

    $wanted = @{}
    foreach ($n in $needed) { $wanted["$n.exe"] = $n }
    $wanted['Kroll_Batch.reb'] = 'krollBatch'

    Get-ChildItem -LiteralPath $ToolsPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $wanted[$_.Name]
        if ($key -and -not $t[$key]) { $t[$key] = $_.FullName }
    }
    return $t
}

# Quote one arg for a native command line. PS5.1's splat doesn't quote spaces reliably,
# which splits paths like C:\Test Workplace\... - so we quote and pass verbatim via Start-Process.
function ConvertTo-NativeArg {
    param([string]$Value)
    if ($Value -eq $null) { return '""' }
    # already-safe tokens (flags like -f, --csv) need no quoting
    if ($Value -notmatch '[\s"]') { return $Value }
    # escape embedded quotes, then wrap
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

# run a tool, log its output, time it, don't throw
function Invoke-Tool {
    param(
        [string]$Label,
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$LogDir
    )
    $row = [ordered]@{ Step = $Label; Status = ''; Seconds = 0; Exit = $null }
    if (-not $ExePath)   { $row.Status = 'SKIP-NoTool';     Write-Log "  - $Label : tool missing" DarkGray; return [pscustomobject]$row }
    if (-not $Arguments) { $row.Status = 'SKIP-NoArtifact'; Write-Log "  - $Label : artifact missing" DarkGray; return [pscustomobject]$row }

    $safe    = Get-SafeName $Label
    $log     = Join-Path $LogDir ("{0}.log" -f $safe)
    $errLog  = Join-Path $LogDir ("{0}.err.log" -f $safe)
    $cmdLine = ($Arguments | ForEach-Object { ConvertTo-NativeArg $_ }) -join ' '

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = Start-Process -FilePath $ExePath -ArgumentList $cmdLine -NoNewWindow -Wait -PassThru `
                           -RedirectStandardOutput $log -RedirectStandardError $errLog -ErrorAction Stop
        $row.Exit   = $p.ExitCode
        $row.Status = if ($p.ExitCode -eq 0) { 'OK' } else { "ExitCode=$($p.ExitCode)" }
    } catch {
        $row.Status = "ERROR: $($_.Exception.Message)"
        Add-Content -LiteralPath $log -Value $_.Exception.ToString()
    }
    $sw.Stop()
    # record the exact command line so a failure is reproducible by hand
    Add-Content -LiteralPath $log -Value "`n---`nCMD: `"$ExePath`" $cmdLine" -ErrorAction SilentlyContinue

    $row.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $col = if ($row.Status -eq 'OK') { 'Green' } else { 'Yellow' }
    Write-Log ("  + {0,-16} {1,7}s  {2}" -f $Label, $row.Seconds, $row.Status) $col

    # telemetry: every timed step lands in _Performance.csv so optimizations are measured, not guessed
    if ($script:PerfRows -ne $null) {
        $script:PerfRows.Add([pscustomobject]@{
            Host = $script:PerfHost; Step = $Label; Seconds = $row.Seconds
            Status = $row.Status; Exe = (Split-Path $ExePath -Leaf)
        })
    }
    return [pscustomobject]$row
}

# start/flush the telemetry collector (per host)
function Start-PerfCapture {
    param([string]$HostName)
    $script:PerfRows = New-Object System.Collections.Generic.List[object]
    $script:PerfHost = $HostName
}
# record an internal (non-exe) stage - sweep, timeline, report, ... - so _Performance.csv
# covers the whole run, not just external parser invocations
function Add-PerfRow {
    param([string]$Step, $Seconds, [string]$Status = 'OK', [string]$Exe = 'internal')
    if ($null -ne $script:PerfRows) {
        [void]$script:PerfRows.Add([pscustomobject]@{
            Host = $script:PerfHost; Step = $Step
            Seconds = [math]::Round([double]$Seconds, 1); Status = $Status; Exe = $Exe
        })
    }
}
function Save-PerfCapture {
    param([string]$OutputPath)
    # int/array checks instead of .Count truthiness on the generic List: that construct has
    # thrown 'Argument types do not match' under PSv5.1 member binding (same fix as New-Report)
    if ($null -ne $script:PerfRows) {
        $rows = @($script:PerfRows.ToArray())
        if ($rows.Length -gt 0) {
            $rows | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath '_Performance.csv')
            $top = @($rows | Sort-Object Seconds -Descending | Select-Object -First 4)
            Write-Log ("  -> _Performance.csv  (slowest: {0})" -f (@($top | ForEach-Object { '{0} {1}s' -f $_.Step, $_.Seconds }) -join ', ')) DarkGray
        }
    }
    $script:PerfRows = $null
}

# ---------------------------------------------------------------- banner ----
# Startup signature (Metasploit-style). Pure 7-bit ASCII on purpose: box-drawing and
# block glyphs garble on classic conhost/OEM codepages, and a forensic tool's console
# output must stay paste-safe into tickets and reports.
$script:ScribeVersion = '1.0'
function Write-ScribeBanner {
    param(
        [int]$ArtifactCount = 0,
        [int]$ParserCount   = 0,
        [int]$LayoutCount   = 0,
        [bool]$Accel        = $false,
        [string]$Mode       = ''
    )
    $art = @'

      _____  _____ _____  _____ ____  ______
     / ____|/ ____|  __ \|_   _|  _ \|  ____|
    | (___ | |    | |__) | | | | |_) | |__
     \___ \| |    |  _  /  | | |  _ <|  __|
     ____) | |____| | \ \ _| |_| |_) | |____
    |_____/ \_____|_|  \_\_____|____/|______|

'@
    Write-Host $art -ForegroundColor Cyan
    $engine = if ($Accel) { 'compiled accelerator' } else { 'PowerShell fallback' }
    $w = 48   # inner width -> right-aligned closing brackets, Metasploit-style

    $l1 = ("SCRIBE v{0}" -f $script:ScribeVersion)
    Write-Host ("       =[ ") -NoNewline -ForegroundColor DarkGray
    Write-Host ($l1.PadRight($w)) -NoNewline -ForegroundColor Yellow
    Write-Host ("]") -ForegroundColor DarkGray

    $l2 = ("{0} artifact types - {1} parsers - {2} layouts" -f $ArtifactCount, $ParserCount, $LayoutCount)
    Write-Host ("+ -- --=[ ") -NoNewline -ForegroundColor DarkGray
    Write-Host ($l2.PadRight($w)) -NoNewline
    Write-Host ("]") -ForegroundColor DarkGray

    $l3 = ("engine: {0}{1}" -f $engine, $(if ($Mode) { " - mode: $Mode" } else { '' }))
    Write-Host ("+ -- --=[ ") -NoNewline -ForegroundColor DarkGray
    Write-Host ($l3.PadRight($w)) -NoNewline
    Write-Host ("]") -ForegroundColor DarkGray
    Write-Host ""
}
