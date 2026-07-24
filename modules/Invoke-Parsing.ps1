# Parse the in-scope artifacts (artifacts.json x tier) and return a coverage list.

function Expand-ParserArgs {
    param([string[]]$ArgTemplate, [hashtable]$Vars)
    $out = @()
    foreach ($a in $ArgTemplate) {
        $x = $a
        foreach ($k in $Vars.Keys) { $x = $x.Replace("{$k}", [string]$Vars[$k]) }
        $out += $x
    }
    return $out
}

function Invoke-Parsing {
    param(
        [Parameter(Mandatory)]$Resolved,       # output of Resolve-Layout
        [Parameter(Mandatory)]$Tools,          # tool table
        [Parameter(Mandatory)]$Artifacts,      # parsed artifacts.json
        [Parameter(Mandatory)]$Parsers,        # parsed parsers.json
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$LogDir,
        [string]$Tier = 'default',
        [string[]]$AddArtifacts = @(),
        [string[]]$SkipArtifacts = @(),
        [switch]$Discover
    )

    $tierOrder = @{ 'default' = 1; 'extended' = 2; 'full' = 3; 'optional' = 99 }
    $selTier   = $tierOrder[$Tier]
    $driveRoot = $Resolved.DriveRoot

    $coverage = New-Object System.Collections.Generic.List[object]
    $parseSummary = New-Object System.Collections.Generic.List[object]

    Write-Rule; Write-Log "PARSE" Cyan

    foreach ($name in ($Artifacts.PSObject.Properties.Name | Where-Object { $_ -ne '_comment' })) {
        $art = $Artifacts.$name
        $artTier = $tierOrder[$art.tier]; if (-not $artTier) { $artTier = 99 }

        # In scope if: within selected tier, OR explicitly added. Never if explicitly skipped.
        $inScope = ($artTier -le $selTier) -or ($AddArtifacts -contains $name)
        if ($SkipArtifacts -contains $name) {
            $coverage.Add([pscustomobject]@{ Artifact = $name; State = 'SkippedByConfig'; Path = ''; Purpose = $art.purpose })
            Write-Log "  ~ $name : skipped by config" DarkGray
            continue
        }
        if (-not $inScope) { continue }

        # Resolve the artifact path(s) - configured location first, discovery fallback if enabled
        $note = [ref]''
        # @(...) guards against PowerShell unrolling a single result into a bare string
        $paths = @(Resolve-ArtifactPath -DriveRoot $driveRoot -Patterns $art.paths -Discover:$Discover -DiscoveryNote $note)
        if (-not $paths -or $paths.Count -eq 0) {
            $coverage.Add([pscustomobject]@{ Artifact = $name; State = 'NotInCollection'; Path = ''; Purpose = $art.purpose })
            Write-Log "  . $name : not in collection" DarkGray
            continue
        }
        if ($note.Value) { Write-Log ("  ? {0} : {1}" -f $name, $note.Value) Yellow }

        $parserDef = $Parsers.($art.parser)
        if (-not $parserDef) { Write-Log "  [!] $name : parser '$($art.parser)' undefined" Yellow; continue }

        $artOut = Join-Path $OutputPath $name
        # clear prior outputs: parsers write timestamped filenames, so re-runs accumulate
        # stale CSVs that would double-count in the sweep and timeline
        if (Test-Path -LiteralPath $artOut) {
            Get-ChildItem -LiteralPath $artOut -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Force -Path $artOut | Out-Null

        if ($parserDef.type -eq 'copy') {
            # A copy is a parser like any other and gets the SAME honesty contract: it
            # reports Parsed only if the copy actually succeeded AND produced bytes.
            # Robocopy's exit code is a bit field - >= 8 means files were NOT copied
            # (locked, access denied, path too long). Discarding it, as this branch used
            # to, meant a completely failed ScheduledTasks copy still showed as covered:
            # a silent blind spot presented as coverage, which is the one thing this tool
            # exists to prevent.
            $copyLog  = Join-Path $LogDir (Get-SafeName "$name.log")
            if (Test-Path -LiteralPath $copyLog) { Remove-Item -LiteralPath $copyLog -Force -ErrorAction SilentlyContinue }
            $copyFail = @()
            $swCopy   = [System.Diagnostics.Stopwatch]::StartNew()

            foreach ($src in $paths) {
                if (Test-Path -LiteralPath $src -PathType Container) {
                    $global:LASTEXITCODE = 0
                    robocopy $src $artOut /E /NFL /NDL /NJH /NJS /NP *>> $copyLog
                    $rc = $global:LASTEXITCODE
                    Add-Content -LiteralPath $copyLog -Value "`n---`nCMD: robocopy `"$src`" `"$artOut`" /E /NFL /NDL /NJH /NJS /NP`nEXIT: $rc" -ErrorAction SilentlyContinue
                    if (-not (Test-RobocopySuccess $rc)) { $copyFail += ("{0} (robocopy exit {1})" -f $src, $rc) }
                } else {
                    try {
                        Copy-Item -LiteralPath $src -Destination $artOut -Force -ErrorAction Stop
                    } catch {
                        $copyFail += ("{0} ({1})" -f $src, $_.Exception.Message)
                        Add-Content -LiteralPath $copyLog -Value ("COPY FAILED: {0} -> {1}`n{2}" -f $src, $artOut, $_.Exception.ToString()) -ErrorAction SilentlyContinue
                    }
                }
            }
            $swCopy.Stop()

            # same empty-output check the tool-backed branch applies: a copy that wrote
            # nothing is NoOutput, not coverage
            $copied = @(Get-ChildItem -LiteralPath $artOut -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt 0 })

            $copyState = 'Parsed'
            if ($copyFail.Count)       { $copyState = 'ParseFailed' }
            elseif ($copied.Count -eq 0) { $copyState = 'NoOutput' }

            switch ($copyState) {
                'Parsed' {
                    Write-Log ("  + {0,-16} copied raw ({1} file(s))" -f $name, $copied.Count) Green
                }
                'NoOutput' {
                    Write-Log ("  [!] {0,-16} copy produced NO FILES - blind spot, see _logs\{0}.log" -f $name) Yellow
                }
                default {
                    Write-Log ("  [!] {0,-16} COPY FAILED - blind spot, see _logs\{0}.log" -f $name) Red
                    foreach ($cf in ($copyFail | Select-Object -First 3)) { Write-Log "      $cf" Red }
                    if ($copied.Count) { Write-Log ("      {0} file(s) were copied before the failure - PARTIAL, treat as incomplete." -f $copied.Count) Yellow }
                }
            }

            Add-PerfRow -Step $name -Seconds $swCopy.Elapsed.TotalSeconds -Status $copyState -Exe 'robocopy'
            $parseSummary.Add([pscustomobject]@{ Step = $name; Status = $copyState; Seconds = [math]::Round($swCopy.Elapsed.TotalSeconds,1); Exit = $null })
            $coverage.Add([pscustomobject]@{ Artifact = $name; State = $copyState; Path = ($paths -join ';'); Purpose = $art.purpose })
            continue
        }

        # tool-backed parser
        $toolPath = $Tools[$parserDef.tool]
        if (-not $toolPath) {
            Write-Log ("  [!] {0,-16} TOOL MISSING ({1}.exe) - blind spot" -f $name, $parserDef.tool) Yellow
            $coverage.Add([pscustomobject]@{ Artifact = $name; State = 'ToolMissing'; Path = ($paths -join ';'); Purpose = $art.purpose })
            continue
        }

        $vars = @{
            out         = $artOut
            software    = $Resolved.SoftwareHive
            system      = $Resolved.SystemHive
            krollBatch  = $Tools['krollBatch']
        }

        $ranOk = $false
        if ($parserDef.type -eq 'dir') {
            # Second line of defense against invoking the SAME tool twice on the SAME
            # physical input (see Resolve-ArtifactPath's identity-based dedup): re-dedupe
            # here too, by filesystem identity, immediately before dispatch. Cheap, and it
            # means this loop can never double-run a 'dir' parser (RECmd et al.) against
            # one hive even if a future path source returns duplicates in a new shape.
            $seenPaths = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            foreach ($p in $paths) {
                $full = $p
                try { $full = [System.IO.Path]::GetFullPath($p) } catch { }
                $key = $full.TrimEnd('\').ToLowerInvariant()
                if (-not $seenPaths.ContainsKey($key)) { $seenPaths[$key] = $p }
            }
            foreach ($p in ($seenPaths.Values | Sort-Object)) {
                $vars['in'] = $p
                $cmdArgs = Expand-ParserArgs -ArgTemplate $parserDef.args -Vars $vars
                $r = Invoke-Tool -Label $name -ExePath $toolPath -Arguments $cmdArgs -LogDir $LogDir
                $parseSummary.Add($r)
                if ($r.Status -eq 'OK') { $ranOk = $true }
            }
        } else {
            $inPath = $paths[0]
            # Sanity: the path must exist. Catches resolution bugs before they reach the tool
            # (a malformed value like "C" would otherwise produce "File C not found").
            if (-not (Test-Path -LiteralPath $inPath)) {
                Write-Log ("  [!] {0,-16} resolved path invalid: '{1}'" -f $name, $inPath) Red
                $coverage.Add([pscustomobject]@{ Artifact = $name; State = 'ParseFailed'; Path = $inPath; Purpose = $art.purpose })
                continue
            }
            $vars['in'] = $inPath
            $cmdArgs = Expand-ParserArgs -ArgTemplate $parserDef.args -Vars $vars
            $r = Invoke-Tool -Label $name -ExePath $toolPath -Arguments $cmdArgs -LogDir $LogDir
            $parseSummary.Add($r)
            if ($r.Status -eq 'OK') { $ranOk = $true }
        }

        $state = if ($ranOk) { 'Parsed' } else { 'ParseFailed' }

        # some tools exit 0 but write nothing (e.g. MFTECmd on a bad path) - treat empty as failure
        if ($state -eq 'Parsed') {
            $produced = @(Get-ChildItem -LiteralPath $artOut -Recurse -File -ErrorAction SilentlyContinue |
                          Where-Object { $_.Length -gt 0 })
            if ($produced.Count -eq 0) {
                $state = 'NoOutput'
                Write-Log ("  [!] {0,-16} tool ran but produced NO OUTPUT - check _logs\{0}.log" -f $name) Yellow
            }
        }

        $coverage.Add([pscustomobject]@{ Artifact = $name; State = $state; Path = ($paths -join ';'); Purpose = $art.purpose })
    }

    # multi-volume: additional volumes present but not analyzed are a coverage fact
    foreach ($v in @($Resolved.ExtraVolumes)) {
        $coverage.Add([pscustomobject]@{
            Artifact = "Volume:$v"; State = 'PresentNotAnalyzed'; Path = $v
            Purpose = "Additional drive volume present in the collection - NOT analyzed. Ransomware/staging on a data volume would be invisible. Re-run pointed at this volume to cover it."
        })
        Write-Log "  ~ Volume $v : present, not analyzed (only the system volume was parsed)" DarkYellow
    }

    # VSS presence is a coverage fact: shadow copies may hold pre-encryption state this
    # tool does not analyze. Say so instead of staying silent.
    if (Test-Path -LiteralPath ($driveRoot.TrimEnd('\') + '\System Volume Information')) {
        $coverage.Add([pscustomobject]@{
            Artifact = 'VSS'; State = 'PresentNotAnalyzed'; Path = 'System Volume Information'
            Purpose = 'Volume Shadow Copies - may contain pre-encryption/earlier state. Not analyzed by this tool.'
        })
        Write-Log "  ~ VSS : present in collection, not analyzed" DarkYellow
    }
    return [pscustomobject]@{ Coverage = $coverage; Summary = $parseSummary }
}
