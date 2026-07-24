# Archive extraction. Native for .zip, 7-Zip for the rest. Returns Ok=$false instead of throwing.

# Archive extensions we recognize. Multi-part (.tar.gz) handled by the double-extract below.
$script:ArchiveExts = @('.zip','.7z','.tar','.gz','.tgz','.rar','.xz','.bz2')

function Get-ArchiveFiles {
    param([Parameter(Mandatory)][string]$Folder)
    # bounded recursion: evidence drops often nest archives one folder down
    Get-ChildItem -LiteralPath $Folder -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object { $script:ArchiveExts -contains $_.Extension.ToLower() -and
                       $_.FullName -notmatch '\\(_extracted|_Analysis|_logs|_TriageAnalysis)\\' } |
        Sort-Object FullName
}

# Find 7z.exe: config path, PATH, or standard install locations.
function Resolve-SevenZip {
    param([string]$ConfiguredPath)
    if ($ConfiguredPath -and (Test-Path -LiteralPath $ConfiguredPath)) { return $ConfiguredPath }
    $cmd = Get-Command '7z.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

# Extract one archive to a destination folder.
# Returns @{ Ok; Dest; Message }
function Expand-Collection {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$DestRoot,
        [string]$SevenZip,
        [string]$LogDir,
        [string]$Password
    )
    $name = [System.IO.Path]::GetFileNameWithoutExtension($ArchivePath)
    # .tar.gz / .tar.bz2 -> strip the inner .tar too
    if ($name -match '\.tar$') { $name = $name -replace '\.tar$','' }
    $dest = Join-Path $DestRoot $name
    $ext  = [System.IO.Path]::GetExtension($ArchivePath).ToLower()

    if (Test-Path -LiteralPath $dest) {
        return @{ Ok = $true; Dest = $dest; Message = "already extracted (reusing $dest)" }
    }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $log = if ($LogDir) { Join-Path $LogDir ("extract_" + (Get-SafeName $name) + ".log") } else { $null }

    try {
        if ($ext -eq '.zip' -and -not $Password) {
            # Native first (no dependency). Falls back to 7z if it chokes (e.g. paths >260, odd entries).
            try {
                Expand-Archive -LiteralPath $ArchivePath -DestinationPath $dest -Force -ErrorAction Stop
                return @{ Ok = $true; Dest = $dest; Message = 'extracted (Expand-Archive)' }
            } catch {
                if (-not $SevenZip) { throw }   # no fallback available
                # fall through to 7z below
            }
        }

        if (-not $SevenZip) {
            return @{ Ok = $false; Dest = $dest; Message = "7-Zip not found; cannot extract '$ext'. Install 7-Zip or set tools.sevenZipPath in config.json." }
        }

        # 7z handles zip/7z/tar/gz/rar/xz/bz2. For .tar.gz/.tgz we extract twice.
        $pw = if ($Password) { "-p$Password" } else { '-p' }
        & $SevenZip x $ArchivePath "-o$dest" $pw -y *> $log
        if ($LASTEXITCODE -ne 0) {
            return @{ Ok = $false; Dest = $dest; Message = "7z failed (exit $LASTEXITCODE) - see $log" }
        }
        # if a single .tar landed inside, unwrap it
        $innerTar = Get-ChildItem -LiteralPath $dest -Filter *.tar -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($innerTar) {
            & $SevenZip x $innerTar.FullName "-o$dest" -y *> $log
            Remove-Item -LiteralPath $innerTar.FullName -Force -ErrorAction SilentlyContinue
        }
        return @{ Ok = $true; Dest = $dest; Message = 'extracted (7-Zip)' }

    } catch {
        return @{ Ok = $false; Dest = $dest; Message = "extract error: $($_.Exception.Message)" }
    }
}

# Some archives wrap the collection in an extra folder. Descend through single-child wrappers,
# but stop once we hit something that looks like a drive root (has C/D, $MFT, or Windows).
function Test-IsCollectionRoot {
    param([string]$Path)
    # a drive-letter folder present? (Aralez/KAPE/CyLR style)
    foreach ($d in @('C','D','E','C%3A','D%3A')) {
        if (Test-Path -LiteralPath ($Path.TrimEnd('\') + '\' + $d)) { return $true }
    }
    # or we're already AT a drive root?
    if (Test-Path -LiteralPath ($Path.TrimEnd('\') + '\$MFT'))    { return $true }
    if (Test-Path -LiteralPath ($Path.TrimEnd('\') + '\Windows')) { return $true }
    if (Test-Path -LiteralPath ($Path.TrimEnd('\') + '\uploads')) { return $true }   # Velociraptor
    return $false
}

function Get-CollectionRoot {
    param([Parameter(Mandatory)][string]$ExtractedPath)
    $cur = $ExtractedPath
    for ($i = 0; $i -lt 4; $i++) {
        # STOP: this already looks like a collection/drive root - do not descend further.
        if (Test-IsCollectionRoot -Path $cur) { return $cur }

        $dirs  = @(Get-ChildItem -LiteralPath $cur -Directory -Force -ErrorAction SilentlyContinue)
        $files = @(Get-ChildItem -LiteralPath $cur -File -Force -ErrorAction SilentlyContinue)
        # only descend through a pure single-folder wrapper
        if ($dirs.Count -eq 1 -and $files.Count -eq 0) { $cur = $dirs[0].FullName; continue }
        break
    }
    return $cur
}
