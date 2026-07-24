# Example run

`sample-iocs.txt` is a small, fictional IOC list (documentation-safe hashes, RFC 5737
IP ranges, `example.com` domains). Use it to see the IOC sweep and output format, then
replace it with your real indicators.

```powershell
# single host
.\Invoke-Triage.ps1 -HostArtifacts "D:\case\HOST01" -ToolsPath "C:\Tools\ZimmermanTools" `
  -IocFile ".\examples\sample-iocs.txt" -OutputPath "D:\out"

# batch (folder of collections)
.\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -ToolsPath "C:\Tools\ZimmermanTools" `
  -Hayabusa "C:\Tools\hayabusa\hayabusa.exe" -IocFile ".\examples\sample-iocs.txt" -OutputPath "D:\out"
```

Results land in `-OutputPath`: read `_Summary.txt`, then `IOC_Hits.csv`, then
`EventLogs\Hayabusa_Detections.csv`. Batch runs also produce the `_GLOBAL_*` files.
