# Run manifest for reproducibility / chain of custody. Records WHAT was analyzed and with
# WHAT logic: input hashes, IOC-set hash, tool file-versions, Hayabusa rule count, parameters.
# Two analysts can compare manifests to prove they ran the same evidence through the same tools.

function Get-FileHashSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

function Get-ExeVersion {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Item -LiteralPath $Path).VersionInfo.FileVersion } catch { return $null }
}

# Hash of the effective IOC set (sorted indicators) - a fingerprint of the hunt logic.
function Get-IocSetHash {
    param($Iocs)
    $list = @($Iocs | ForEach-Object { $_.Indicator } | Sort-Object)
    if (-not $list.Count) { return $null }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($list -join "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','')
}

function Write-RunManifest {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$Context   # HostName, Layout, InputPath, Params, Tools, Hayabusa, Iocs, IocFiles
    )
    # tool binaries and rules are invariant across a batch - hash once, reuse per host
    if ($null -eq $script:MfToolsCache) { $script:MfToolsCache = @{} }
    $cacheKey = (@($Context.Tools.Values | Where-Object { $_ }) | Sort-Object) -join '|'
    if ($script:MfToolsCache.ContainsKey($cacheKey)) {
        $tools = $script:MfToolsCache[$cacheKey]
    } else {
        $tools = @{}
        foreach ($t in $Context.Tools.Keys) {
            if ($Context.Tools[$t]) { $tools[$t] = @{ path = $Context.Tools[$t]; version = (Get-ExeVersion $Context.Tools[$t]); sha256 = (Get-FileHashSafe $Context.Tools[$t]) } }
        }
        $script:MfToolsCache[$cacheKey] = $tools
    }

    $inputHash = $null
    # file inputs (archives) are always hashed - the manifest exists to prove WHAT was
    # analyzed; folder inputs have no single-file hash and record hashed=false
    if ($Context.InputPath -and (Test-Path -LiteralPath $Context.InputPath -PathType Leaf)) {
        $inputHash = Get-FileHashSafe $Context.InputPath
    }

    if ($null -eq $script:MfHayaCache) { $script:MfHayaCache = @{} }
    $hk = [string]$Context.Hayabusa
    if ($script:MfHayaCache.ContainsKey($hk)) {
        $hayaVer = $script:MfHayaCache[$hk].Version; $ruleCount = $script:MfHayaCache[$hk].Rules
    } else {
        $hayaVer = Get-ExeVersion $Context.Hayabusa
        $ruleCount = $null
        if ($Context.Hayabusa) {
            $rulesDir = Join-Path (Split-Path $Context.Hayabusa -Parent) 'rules'
            if (Test-Path -LiteralPath $rulesDir) {
                $ruleCount = @(Get-ChildItem -LiteralPath $rulesDir -Filter *.yml -Recurse -ErrorAction SilentlyContinue).Count
            }
        }
        $script:MfHayaCache[$hk] = @{ Version = $hayaVer; Rules = $ruleCount }
    }

    $manifest = [ordered]@{
        tool           = 'scribe'
        schemaVersion  = 1
        generatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        host           = $Context.HostName
        layout         = $Context.Layout
        input = [ordered]@{
            path       = $Context.InputPath
            sha256     = $inputHash
            hashed     = [bool]$inputHash
        }
        iocSet = [ordered]@{
            files      = @($Context.IocFiles)
            count      = @($Context.Iocs).Count
            sha256     = (Get-IocSetHash $Context.Iocs)
        }
        tools          = $tools
        hayabusa = [ordered]@{
            path       = $Context.Hayabusa
            version    = $hayaVer
            ruleCount  = $ruleCount
        }
        parameters     = $Context.Params
        environment = [ordered]@{
            psVersion  = $PSVersionTable.PSVersion.ToString()
            os         = [System.Environment]::OSVersion.VersionString
            user       = $env:USERNAME
            machine    = $env:COMPUTERNAME
        }
    }

    $out = Join-Path $OutputPath 'run-manifest.json'
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $out -Encoding UTF8
    Write-Log "  -> run-manifest.json  (inputs, tool versions, IOC-set hash, parameters)" Green
    return $out
}
