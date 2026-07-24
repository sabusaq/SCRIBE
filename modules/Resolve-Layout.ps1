# Find and validate the drive root for a collection, given a layout from layouts.json.

# Normalize a config relative path (may use / or \) and join to a base.
# NOTE: we build the string directly instead of using Join-Path. Join-Path applies provider/
# wildcard semantics that mangle NTFS metadata names beginning with '$' (e.g. $MFT, $Extend).
function Join-Rel {
    param([string]$Base, [string]$Rel)
    $Rel = $Rel -replace '/', '\'
    if ($Rel -eq '.' -or $Rel -eq '') { return $Base }
    return ($Base.TrimEnd('\') + '\' + $Rel.TrimStart('\'))
}

# returns @{ Ok; DriveRoot; SystemRoot; SoftwareHive; SystemHive; Message }
function Resolve-Layout {
    param(
        [Parameter(Mandatory)][string]$HostArtifacts,
        [Parameter(Mandatory)][string]$LayoutName,
        [Parameter(Mandatory)]$Layouts   # parsed layouts.json
    )

    if (-not (Test-Path -LiteralPath $HostArtifacts)) {
        return @{ Ok = $false; Message = "HostArtifacts path does not exist: $HostArtifacts" }
    }
    $layout = $Layouts.$LayoutName
    if (-not $layout) {
        $valid = ($Layouts.PSObject.Properties.Name | Where-Object { $_ -ne '_comment' }) -join ', '
        return @{ Ok = $false; Message = "Unknown layout '$LayoutName'. Valid: $valid" }
    }

    $anchorRel = $layout.anchor
    # Candidate drive roots: try each configured driveRoot; the one whose (root + anchorTail) exists wins.
    # The anchor is expressed relative to the collection; the drive root is the folder that, once
    # stripped, leaves a normal Windows layout. We test each driveRoot for the anchor's final element.
    $anchorLeaf = ($anchorRel -replace '/', '\').Split('\')[-1]

    $candidates = @()
    foreach ($dr in $layout.driveRoots) { $candidates += (Join-Rel $HostArtifacts $dr) }
    $candidates += $HostArtifacts   # also try the folder itself

    $driveRoot = $null
    $how = ''
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $direct = Join-Rel $c $anchorLeaf
        if (Test-Path -LiteralPath $direct) { $driveRoot = $c; $how = "anchor '$anchorLeaf'"; break }
        if (Test-Path -LiteralPath (Join-Path $c 'Windows\System32')) { $driveRoot = $c; $how = 'Windows\System32'; break }
    }

    if (-not $driveRoot) {
        $tried = ($candidates | ForEach-Object { $_ }) -join "`n    "
        return @{
            Ok = $false
            Message = "Layout '$LayoutName' selected, but its anchor ('$anchorRel') / Windows\System32 was not found under any expected drive root.`n  Tried:`n    $tried`n  -> Check -Layout, or use -Layout Raw and point -HostArtifacts at the exact drive-root folder."
        }
    }

    $systemRoot = Join-Path $driveRoot 'Windows'
    $config = Join-Path $systemRoot 'System32\config'

    # multi-volume: additional drive roots (D:, E:, ...) beside the analyzed one are NOT parsed.
    # Report them so ransomware staging on a data volume is not silently invisible.
    $extraVolumes = @()
    $parent = Split-Path $driveRoot -Parent
    if ($parent) {
        foreach ($d in @('C','D','E','F','G')) {
            $cand = Join-Rel $parent $d
            if ((Test-Path -LiteralPath $cand) -and ($cand.TrimEnd('\') -ne $driveRoot.TrimEnd('\'))) {
                if ((Test-Path -LiteralPath (Join-Rel $cand '$MFT')) -or (Test-Path -LiteralPath (Join-Path $cand 'Users'))) {
                    $extraVolumes += $d
                }
            }
        }
    }

    $result = @{
        Ok           = $true
        DriveRoot    = $driveRoot
        SystemRoot   = $systemRoot
        SoftwareHive = (Join-Path $config 'SOFTWARE')
        SystemHive   = (Join-Path $config 'SYSTEM')
        ExtraVolumes = $extraVolumes
        Message      = "Layout '$LayoutName' -> drive root: $driveRoot  (matched via $how)"
    }
    return $result
}

# Resolve an artifact's path(s). Try the configured paths first; if none exist and -Discover
# is set, search by filename (skipping VSS/Windows.old/RegBack), shallowest match wins.
# {user} expands against each profile under Users\.
function Resolve-ArtifactPath {
    param(
        [Parameter(Mandatory)][string]$DriveRoot,
        [Parameter(Mandatory)][string[]]$Patterns,
        [switch]$Discover,
        [ref]$DiscoveryNote
    )
    $results = New-Object System.Collections.Generic.List[string]

    foreach ($p in $Patterns) {
        if ($p -match '\{user\}') {
            $usersDir = ($DriveRoot.TrimEnd('\') + '\Users')
            if (Test-Path -LiteralPath $usersDir) {
                foreach ($u in (Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue)) {
                    $cand = Join-Rel $DriveRoot ($p -replace '\{user\}', $u.Name)
                    if (Test-Path -LiteralPath $cand) { $results.Add($cand) }
                }
            }
        } else {
            $cand = Join-Rel $DriveRoot $p
            if (Test-Path -LiteralPath $cand) { $results.Add($cand) }
        }
    }

    if ($results.Count -gt 0) {
        # De-dupe by FILESYSTEM IDENTITY, not raw string equality. A string-only dedup
        # (Sort-Object -Unique) lets two superficially different path strings that resolve
        # to the SAME physical file both survive - e.g. one pattern reaching a hive via a
        # relative form with a different separator/case than another pattern's. When that
        # happens for a 'dir'-type parser (RECmd), the SAME hive gets parsed TWICE in one
        # run; RECmd creates a fresh timestamped output subfolder per invocation, so you end
        # up with two near-identical subfolders (e.g. Registry\20260723101926\ and
        # Registry\20260723133339\) - both then get swept, doubling matching IOC hits with
        # near-duplicates and doubling that artifact's parse time for nothing.
        # winevt/Logs and winevt/logs are the same folder on Windows: this dedup catches
        # that case too, and case-insensitively for the whole path, not just casing quirks.
        $seen = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        foreach ($r in $results) {
            $full = $r
            try { $full = [System.IO.Path]::GetFullPath($r) } catch { }
            $key = $full.TrimEnd('\').ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) { $seen[$key] = $r }   # first-seen string wins, for stable display
        }
        # leading comma stops PS unrolling a 1-element array into a bare string
        return ,@([string[]]($seen.Values | Sort-Object))
    }
    if (-not $Discover) { return ,@() }

    # --- discovery fallback: search by leaf name of the first non-{user} pattern ---
    $leaf = $null
    foreach ($p in $Patterns) {
        if ($p -notmatch '\{user\}') { $leaf = ($p -replace '/','\').Split('\')[-1]; break }
    }
    if (-not $leaf) { return ,@([string[]]$results) }

    # trees that commonly hold DUPLICATE/stale copies we must not silently parse as "the" artifact
    $noise = '(?i)\\(\$Recycle\.Bin|Windows\.old|RegBack|System Volume Information|\$Extend\\\$RmMetadata)\\'

    # one recursive walk per drive root, cached; every later discovery is a dictionary lookup.
    # The collection is read-only during analysis, so the index cannot go stale.
    if ($null -eq $script:DiscoveryIndex) { $script:DiscoveryIndex = @{} }
    if (-not $script:DiscoveryIndex.ContainsKey($DriveRoot)) {
        $idx = @{}
        Get-ChildItem -LiteralPath $DriveRoot -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch $noise } |
            ForEach-Object {
                $k = $_.Name.ToLowerInvariant()
                if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[string] }
                $idx[$k].Add($_.FullName)
            }
        $script:DiscoveryIndex[$DriveRoot] = $idx
        Write-Log ("  (discovery index built: {0} filenames)" -f $idx.Count) DarkGray
    }
    $idx = $script:DiscoveryIndex[$DriveRoot]
    $key = $leaf.ToLowerInvariant()
    $paths = @()
    if ($key -match '[\*\?]') {
        foreach ($k in $idx.Keys) { if ($k -like $key) { $paths += $idx[$k] } }
    } elseif ($idx.ContainsKey($key)) {
        $paths = @($idx[$key])
    }
    $found = @($paths | Sort-Object { ($_ -split '\\').Count } | ForEach-Object { Get-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue })

    if ($found) {
        $results.Add($found[0].FullName)
        if ($DiscoveryNote) {
            $msg = "discovered '$leaf' at $($found[0].FullName)"
            if (@($found).Count -gt 1) { $msg += " ($((@($found).Count)) candidates - using shallowest; review others)" }
            $DiscoveryNote.Value = $msg
        }
    }
    # comma-wrap: prevent PowerShell from unrolling a single-element array into a bare string
    return ,@([string[]]$results)
}
