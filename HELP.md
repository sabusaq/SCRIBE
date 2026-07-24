# SCRIBE — Help & Usage

Usage reference for SCRIBE. Parses a pre-collected Windows triage package, sweeps IOCs, runs Sigma detection, builds timelines, and reports artifact coverage.

---

## Contents
1. [Install & requirements](#1-install--requirements)
2. [The two modes](#2-the-two-modes)
3. [Parameters](#3-parameters)
4. [Collection layouts](#4-collection-layouts)
5. [Artifact tiers](#5-artifact-tiers)
6. [IOCs](#6-iocs)
7. [Understanding the output](#7-understanding-the-output)
8. [The three event-log files](#8-the-three-event-log-files)
9. [Coverage & the honesty model](#9-coverage--the-honesty-model)
10. [Scope configs](#10-scope-configs)
11. [Troubleshooting](#11-troubleshooting)
12. [Examples](#12-examples)

---

## 1. Install & requirements

1. Unzip the repo. **Keep the folder structure intact** — `Invoke-Triage.ps1` in the root, with `modules\` and `config\` beside it:
   ```
   scribe\
   ├── Invoke-Triage.ps1
   ├── Start-ScribeUI.ps1   (graphical launcher)
   ├── Get-Tools.ps1        (downloads external parsers into tools\)
   ├── modules\   (the engine)
   └── config\    (what you edit)
   ```
2. Get the tools — one command fetches them from their official sources into `tools\`:
   ```powershell
   .\Get-Tools.ps1
   ```
   (or click **Download tools** in `Start-ScribeUI.ps1`). This pulls Eric Zimmerman's tools
   via his official updater and the latest Hayabusa release with Sigma rules. **7-Zip**
   (optional, batch mode with non-.zip archives only) — https://www.7-zip.org/.
   Re-run `Get-Tools.ps1` any time to update parsers, maps, and rules.
3. Allow the scripts to run this session:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```

**Required tools** (core / `default` tier): `MFTECmd`, `AmcacheParser`, `PECmd`, `EvtxECmd`, `RECmd` (+ `Kroll_Batch.reb`).
**Optional** (extended/full tiers): `AppCompatCacheParser`, `SrumECmd`, `SBECmd`, `RBCmd`, `LECmd`, `JLECmd`.

Windows PowerShell **5.1+** — runs on a live box, no install.

---

## 2. The two modes

### Single host
Analyze one already-extracted collection.
```powershell
.\Invoke-Triage.ps1 -HostArtifacts "D:\case\HOST01" -Layout Aralez `
  -ToolsPath "C:\Tools\ZimmermanTools" -IocFile ".\iocs.txt"
```

### Batch (multiple collections)
Point at a folder of collections — **archives, already-extracted folders, or a mix**. Each is analyzed and the results are aggregated across hosts.
```powershell
.\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -Layout Aralez `
  -ToolsPath "C:\Tools\ZimmermanTools" -Hayabusa "C:\Tools\hayabusa\hayabusa.exe" `
  -IocFile ".\iocs.txt" -OutputPath "D:\out"
```
- Archives (`.zip/.7z/.tar.gz/.rar`) are extracted, analyzed, then the extracted copy is **deleted** (`-KeepExtracted` to retain).
- Already-extracted folders are analyzed **in place** and **never deleted**.
- A corrupt/unreadable collection is marked `FAILED` and the batch **continues**.

---

## 3. Parameters

| Parameter | Mode | Description |
|---|---|---|
| `-HostArtifacts <path>` | single | One collection folder (or drive root for `-Layout Raw`). |
| `-BatchFolder <path>` | batch | Folder of collections (archives/folders/mixed). |
| `-Layout <name>` | both | `Auto` (default)｜`Aralez`｜`KAPE`｜`CyLR`｜`Velociraptor`｜`Raw`. `Auto` tries every known drive-root pattern and prints how it resolved; name one to force a structure. |
| `-ToolsPath <path>` | both | Eric Zimmerman tools folder (searched recursively). Overrides config. |
| `-IocFile <path...>` | both | IOC file(s) or a folder of them. Optional — empty still runs Sigma. |
| `-Hayabusa <path>` | both | Hayabusa exe (Sigma detections + DFIR timeline). Optional. |
| `-Tier <name>` | both | `default｜extended｜full`. Default `default`. |
| `-OutputPath <path>` | both | Where results go. Default: `<input>\_Analysis` (a sibling of the evidence, never inside it). **Required** when the input is a volume root (`E:\`) or a UNC share root (`\\server\share`) — there is no sibling folder, and SCRIBE will not default output onto the evidence volume. Point it at another volume. |
| `-HostName <label>` | single | Label for the host in outputs. Default: the collection folder name. |
| `-ScopeConfig <path>` | both | JSON scope config: tier, add/skip artifacts, IOC files, time focus. Allowed keys are enforced — see `config\config-schema.json`. |
| `-Timeline <mode>` | both | `case` (one Timesketch timeline per host) or `global` (one across a batch). |
| `-TimelineStart/-TimelineEnd` | both | ISO 8601 UTC bounds for the timeline. Bound it — a full-MFT timeline is millions of rows. |
| `-FilteredCopies` | both | With a time window, also write `*_filtered.csv` per artifact (full CSVs untouched). |
| `-Report` | both | `Findings_Report.html` per host, plus `_GLOBAL_Findings_Report.html` for a batch. |
| `-Visibility` | both | Write `Visibility_Windows.csv`: the time horizon each parsed artifact can speak about. |
| `-Manifest` | both | Write `run-manifest.json`: input/IOC/tool hashes and parameters (reproducibility record). |
| `-SevenZipPath <path>` | batch | 7z.exe for non-.zip archives. Auto-found if omitted. |
| `-ArchivePassword <pw>` | batch | Password for protected archives (e.g. `infected`). |
| `-KeepExtracted` | batch | Keep extracted archive folders (default: delete after analysis). |
| `-KeepOnHit` | batch | Keep a host's extracted files when it matched IOCs (for pivoting). |
| `-MaxParallelHosts <n>` | batch | Analyze up to N collections in parallel child processes. Default 1. |
| `-Rerun` | batch | Re-analyze hosts even if complete from a prior identical run. |
| `-Force` | batch | Override the disk-capacity hard stop. |
| `-SkipHayabusa` | both | Skip Sigma + DFIR timeline. |
| `-NoDiscover` | both | Disable the artifact-discovery fallback. |

Run `Get-Help .\Invoke-Triage.ps1 -Full` for the built-in help.

---

## 4. Collection layouts

`-Layout` defaults to `Auto`, which tries every known drive-root pattern and announces how it resolved. Name a layout to force a structure; the engine validates it and stops loudly if the anchor isn't found — it never silently parses nothing.

| Layout | Use for | Looks like |
|---|---|---|
| `Aralez` | Kaspersky GERT Aralez | `<folder>\C\$MFT`, `\C\Windows\...` |
| `KAPE` | KAPE `--tdest` output | `<machine>\C\...` (drive folder may be `C%3A`) |
| `CyLR` | CyLR collection | per-host folder, `\C\...` |
| `Velociraptor` | Velociraptor collector | `uploads\auto\C:\...` |
| `Raw` | mounted image, `Windows.old`, or any drive root | folder that **is** the drive root |

Wrong layout → the engine tells you what it tried and suggests `-Layout Raw`. To add/adjust a layout, edit `config\layouts.json` (one-line change).

---

## 5. Artifact tiers

Default parses the confirm/deny set fast; add more when you need depth. Tiers live in `config\artifacts.json`.

| Tier | Artifacts |
|---|---|
| `default` | MFT, UsnJrnl ($J), Amcache, Prefetch, Registry, Scheduled Tasks, Event Logs |
| `extended` | + Shimcache, SRUM, Shellbags, Recycle Bin |
| `full` | + LNK, Jump Lists, NTUSER |
| *optional* | `$LogFile`, `$Secure`, `$Boot` — add explicitly |

Add a one-off artifact without changing tier via a scope config (`parse.addArtifacts`). To support a brand-new artifact, add an entry to `config\artifacts.json` — no code change.

---

## 6. IOCs

Drop lists into a file or a folder; pass with `-IocFile`. One indicator per line, `#` for comments. Types: **hashes** (MD5/SHA1/SHA256), **filenames**, **IPs**, **domains**, or any **string** (a path fragment like `\Temp\`, a command like `Add-MpPreference`).

Indicators are **typed at load** and the type sets the match rule and the confidence:

| Type | Match rule | Confidence in `IOC_Hits.csv` |
|---|---|---|
| hash / IP | word-boundary match (can't hit inside a longer hex string or IP) | `high (boundary)` |
| domain | boundary match that **covers subdomains** (`evil.com` matches `c2.evil.com`) but not a different registrable domain (`evil.com` does **not** match `evil.com.br`) | `high (boundary)` |
| everything else | case-insensitive substring | `low (substring)` |

The sweep runs across **every parsed CSV** (plus raw copied files like task XML) and records **which host, which IOC, which artifact, and when** — `MatchTime` is taken from the artifact's known timestamp column and tagged with its semantic (`TimeSemantic`), never scraped from the raw line. If one CSV row carries several indicators (an Amcache row has both the filename and the SHA1), each gets its own hit row.

Because the event logs are analysed in three views (`EventLogs.csv` plus Hayabusa's detections and DFIR timeline), one event can appear as several hit rows. `IOC_Hits.csv` therefore carries an **`EvidenceFamily`** column (the shared source, e.g. `EventLog(evtx)`) and a **`DuplicateInFamily`** flag marking same-event-across-views repeats. All rows are kept; risk scoring and the global matrix count only the primary (non-duplicate) rows, so the same event never inflates corroboration.

> **Tip:** SHA1 is what matches the Amcache column. On metadata-only collections (no binaries), hash-level confirmation comes from Amcache's SHA1, so include SHA1s.
>
> **Warning:** short/partial hex (not 32/40/64 chars) matches legitimate Windows GUIDs and device IDs — the tool warns about these. Remove them or expect false positives.

An **empty IOC set is valid** — Sigma (via Hayabusa) still runs and flags suspicious activity.

---

## 7. Understanding the output

Per host (`<OutputPath>\<HOST>\`):

| File | What it answers |
|---|---|
| `_Summary.txt` | Result + coverage at a glance. **Read first.** |
| `IOC_Hits.csv` | Every IOC match: MatchTime, IOC, artifact, line, file. |
| `Artifact_Coverage.csv` | What was parsed / not collected / tool-missing / skipped. |
| `EventLogs\` | Parsed event logs + Hayabusa outputs (see §8). |
| `<Artifact>\` | Per-artifact parsed CSVs (MFT, Amcache, Prefetch, Registry, …). |
| `_logs\` | Per-tool logs incl. the exact command line run. |

Batch adds, at `<OutputPath>\`:

| File | What it answers |
|---|---|
| `_GLOBAL_IOC_Timeline.csv` | **Every IOC hit, all hosts, time-sorted** — the spread view. |
| `_GLOBAL_IOC_Matrix.csv` | Per host × IOC: first seen / last seen / count. |
| `_GLOBAL_Coverage.csv` | Per host: result + coverage (+ `FAILED` rows). |
| `_BATCH_Summary.txt` | Human summary + earliest hit per host (spread order). |

---

## 8. The three event-log files

All three come from the **same** event logs, at increasing levels of filtering. Under `<HOST>\EventLogs\`:

| File | Question | Size | Open it when… |
|---|---|---|---|
| **Hayabusa_Detections.csv** | "Is anything **bad**?" | small | **you know nothing** — triage entry point. Sort by severity, read criticals/highs. |
| **Hayabusa_DFIR_Timeline.csv** | "What **happened**, in order?" | medium | you found something and need the sequence/story. |
| **EventLogs.csv** | "Show me **every** event of type X" | large | pivoting on a specific detail — every 4624, every mention of a filename. |

- **Detections** = only events a Sigma rule flagged (the noise is gone).
- **DFIR Timeline** = chronological security-relevant events (the narrative).
- **EventLogs** = every event, unfiltered (the searchable haystack).

A critical event appears in all three. Workflow: **Detections → DFIR Timeline → EventLogs.**

---

## 9. Coverage & the honesty model

The core promise: **"no hits" never silently means "clean."** Every artifact ends in one state:

| State | Meaning |
|---|---|
| `Parsed` | Tool ran and produced output. Trustworthy. |
| `NotInCollection` | The artifact wasn't in the collection. **Blind spot.** |
| `ToolMissing` | The parser tool wasn't found. **Blind spot** — set `-ToolsPath`. |
| `NoOutput` | Tool ran but wrote nothing (bad input). **Blind spot** — check `_logs\`. |
| `ParseFailed` | Tool errored / path invalid. **Blind spot.** |
| `SkippedByConfig` | You told it to skip. **Deliberate blind spot.** |

If **none** of MFT/Amcache/UsnJrnl/EventLogs parsed, the result is `INCONCLUSIVE` — the run isn't meaningful and says so. This is the feature that separates *clean* from *couldn't see*.

---

## 10. Scope configs

A scope config is a small JSON file that captures a run's analysis scope in one reviewable, reusable place — what to parse, what to hunt, and the time focus. Useful when a team wants every host in a case analyzed identically, or when re-running with the same scope weeks later.

```json
{
  "meta":  { "layout": "KAPE", "hypothesis": "Ransomware" },
  "parse": { "tier": "default", "addArtifacts": ["SRUM", "Shellbags"] },
  "hunt":  { "iocFiles": ["detections/iocs/case42.txt"] },
  "focus": { "timeStart": "2026-06-01T00:00:00" }
}
```
```powershell
.\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -ScopeConfig ".\myscope.json"
```

The allowed keys are defined (and documented) in `config\config-schema.json`; unknown keys stop the run rather than being silently ignored. Precedence is CLI parameters > scope config > `config\config.json` defaults. `meta.hypothesis` is documentation only — it changes nothing about the parsing.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `... is not recognized ... modules\Common.ps1` | Folder structure broken. `modules\` and `config\` must sit beside `Invoke-Triage.ps1`. Re-extract, keep structure. |
| `ToolsPath not found` | Set `-ToolsPath` to your Zimmerman folder, or edit `config\config.json`. |
| Every artifact `ToolMissing` | Wrong `-ToolsPath`, or tools not downloaded. |
| `Layout ... anchor not found` | Wrong `-Layout`. Check the "Tried:" paths; use `-Layout Raw` at the exact drive root. |
| Artifact `NoOutput` (esp. MFT 0.1s) | Tool ran but failed. Open `_logs\<artifact>.log` — the exact `CMD:` line is at the bottom; run it by hand to see the error. |
| Thousands of IOC hits on a GUID-looking string | A short/partial-hex "IOC" matching device GUIDs. Remove it (the preflight warns which). |
| Output refuses to write to Desktop | Guard against polluting user folders + sweeping stale CSVs. Use a dedicated subfolder. |
| Hayabusa `- not found` | Pass `-Hayabusa <exe>` or set `tools.hayabusaPath`. Keep its `rules\` folder beside the exe. |

Every failed tool logs its exact command line to `_logs\<tool>.log` — copy the `CMD:` line to reproduce and diagnose by hand.

---

## 12. Examples

```powershell
# Single Aralez host, your IOCs
.\Invoke-Triage.ps1 -HostArtifacts "D:\case\DESKTOP-01" -Layout Aralez `
  -ToolsPath "C:\Tools\ZimmermanTools" -IocFile ".\iocs.txt"

# Batch: mixed folder of zips + extracted folders, with Sigma/DFIR timeline
.\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -Layout Aralez `
  -ToolsPath "C:\Tools\ZimmermanTools" -Hayabusa "C:\Tools\hayabusa\hayabusa.exe" `
  -IocFile ".\iocs.txt" -OutputPath "D:\out"

# KAPE collection, deeper artifact set, no IOCs (Sigma-only hunt)
.\Invoke-Triage.ps1 -HostArtifacts "D:\kape\WKS-7" -Layout KAPE `
  -ToolsPath "C:\Tools\ZimmermanTools" -Tier extended -Hayabusa "C:\Tools\hayabusa\hayabusa.exe"

# Mounted image / Windows.old as a raw drive root
.\Invoke-Triage.ps1 -HostArtifacts "E:\mounted\C" -Layout Raw `
  -ToolsPath "C:\Tools\ZimmermanTools" -IocFile ".\iocs.txt"

# Scope-config run (shared, reviewable scope)
.\Invoke-Triage.ps1 -BatchFolder "D:\evidence" -Layout Aralez -ScopeConfig ".\myscope.json"

# Skip Hayabusa for a fast pass
.\Invoke-Triage.ps1 -HostArtifacts "D:\case\HOST01" -Layout Aralez `
  -ToolsPath "C:\Tools\ZimmermanTools" -SkipHayabusa
```

---

*To extend the engine (new artifacts, parsers, layouts), edit the JSON under `config\` — see the `_comment` header in each file. For the scope-config contract, see `config\config-schema.json`.*
