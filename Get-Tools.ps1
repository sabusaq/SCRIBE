<#
.SYNOPSIS
  SCRIBE tool bootstrapper. Downloads the external parsers SCRIBE drives into
  .\tools\ inside this folder, so the project becomes self-contained:

    tools\ZimmermanTools\   Eric Zimmerman's parsers (via his official
                            Get-ZimmermanTools.ps1 updater)
    tools\hayabusa\         Hayabusa latest official GitHub release
                            (includes the Sigma rules)

  Everything comes from the official sources at run time - nothing is bundled
  in this repository, so you always get current parsers, maps, and rules.
  Re-run any time to update. Requires internet access; PowerShell 5.1+.

.PARAMETER SkipZimmerman
  Do not download / update Eric Zimmerman's tools.

.PARAMETER SkipHayabusa
  Do not download / update Hayabusa.

.EXAMPLE
  .\Get-Tools.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipZimmerman,
    [switch]$SkipHayabusa
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$toolsRoot = Join-Path $PSScriptRoot 'tools'
$ezDest    = Join-Path $toolsRoot 'ZimmermanTools'
$hayaDest  = Join-Path $toolsRoot 'hayabusa'
New-Item -ItemType Directory -Path $toolsRoot -Force | Out-Null

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# ---------------------------------------------------- Eric Zimmerman tools ---
if (-not $SkipZimmerman) {
    Write-Step "Eric Zimmerman's tools -> $ezDest"
    New-Item -ItemType Directory -Path $ezDest -Force | Out-Null

    # Official updater script from Eric's GitHub. It downloads the current
    # .net 6/9 builds and can be re-run to update in place.
    $updater = Join-Path $ezDest 'Get-ZimmermanTools.ps1'
    Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1' `
        -OutFile $updater
    & $updater -Dest $ezDest

    $found = @(Get-ChildItem -Path $ezDest -Recurse -Include 'MFTECmd.exe','PECmd.exe','AmcacheParser.exe','EvtxECmd.exe','RECmd.exe' -ErrorAction SilentlyContinue)
    if ($found.Count -ge 5) {
        Write-Host "    OK - core parsers present ($($found.Count) found)." -ForegroundColor Green
    } else {
        Write-Warning "Only $($found.Count)/5 core parsers found. Re-run, or fetch manually from https://ericzimmerman.github.io/"
    }
    Write-Host "    Note: the parsers need the .NET Desktop Runtime. If one fails to start later,"
    Write-Host "    install it from https://dotnet.microsoft.com/download and re-run SCRIBE."
}

# --------------------------------------------------------------- Hayabusa ----
if (-not $SkipHayabusa) {
    Write-Step "Hayabusa (latest official release) -> $hayaDest"

    $rel = Invoke-RestMethod -UseBasicParsing -Uri 'https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest' `
                             -Headers @{ 'User-Agent' = 'scribe-get-tools' }
    $asset = $rel.assets | Where-Object { $_.name -match 'win-x64\.zip$' -and $_.name -notmatch 'live-response' } | Select-Object -First 1
    if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -match 'win.*\.zip$' } | Select-Object -First 1 }
    if (-not $asset) { throw "Could not find a Windows zip asset in the latest Hayabusa release ($($rel.tag_name))." }

    Write-Host "    $($rel.tag_name)  ($([math]::Round($asset.size/1MB,1)) MB)  $($asset.name)"
    $zip = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $zip

    if (Test-Path $hayaDest) { Remove-Item $hayaDest -Recurse -Force }
    New-Item -ItemType Directory -Path $hayaDest -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $hayaDest)
    Remove-Item $zip -Force

    # normalize: some releases name the exe hayabusa-x.y.z-win-x64.exe
    $exe = Get-ChildItem -Path $hayaDest -Recurse -Filter 'hayabusa*.exe' | Select-Object -First 1
    if ($exe) {
        if ($exe.Name -ne 'hayabusa.exe') {
            Copy-Item $exe.FullName (Join-Path $exe.DirectoryName 'hayabusa.exe') -Force
        }
        Write-Host "    OK - $((Get-ChildItem $hayaDest -Recurse -Filter 'hayabusa.exe' | Select-Object -First 1).FullName)" -ForegroundColor Green
    } else {
        Write-Warning "hayabusa executable not found after extraction - check $hayaDest"
    }
}

# ---------------------------------------------------------------- summary ----
Write-Step 'Done'
Write-Host @"
Tool locations (auto-detected by Start-ScribeUI.ps1, or pass on the command line):

  -ToolsPath  $ezDest
  -Hayabusa   $(Get-ChildItem $hayaDest -Recurse -Filter 'hayabusa.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName)

Optional, not downloaded by this script:
  7-Zip (only for non-.zip archives in batch mode)  https://www.7-zip.org/

For real engagements, consider verifying downloads against the hashes published
on the official pages. Re-run this script any time to update parsers and rules.
"@
