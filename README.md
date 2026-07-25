<h1 align="center">SCRIBE</h1>

<p align="center">
  Analyze Windows forensic triage collections from one host or an entire fleet with a single workflow.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#pipeline">Pipeline</a> ·
  <a href="#coverage-and-verdicts">Coverage</a> ·
  <a href="#features">Features</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#faq">FAQ</a>
</p>

<p align="center">
  <!-- Badge placeholders: replace OWNER/REPO after publishing -->
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey" alt="Windows">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
  <!-- <img src="https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg" alt="CI"> -->
</p>

---

## Overview

SCRIBE analyzes Windows forensic triage collections produced by KAPE, Velociraptor, CyLR, Aralez, or taken from a mounted image. Given one collection — or a folder containing many — it:

1. **Parses** standard Windows artifacts (MFT, UsnJrnl, Amcache, Prefetch, registry, event logs, and more) using Eric Zimmerman's tools.
2. **Sweeps** an IOC list (hashes, IPs, domains, filenames, path fragments) across every parsed artifact.
3. **Detects** activity with Sigma rules via Hayabusa.
4. **Builds timelines** per host, or one global timeline across a batch.
5. **Reports** in HTML, with hosts ranked by a risk score whose formula is printed in the report.

Every artifact ends the run in an explicit state — parsed, not present in the collection, tool missing, parse failed, or skipped by configuration. Nothing is dropped silently. If no core artifact could be parsed, the result is reported as `INCONCLUSIVE` rather than clean.

SCRIBE runs on stock Windows PowerShell 5.1. There is no installer, no agent, and no network dependency during analysis.

<!-- SCREENSHOT PLACEHOLDER: hero GIF — batch folder in, ranked findings report out (docs/img/hero.gif) -->


## Scope

**In scope:** offline analysis of Windows endpoint triage collections.


## Pipeline

```
   Triage collections (1 … N)          IOC list
   .zip / .7z / .tar.gz / .rar         hashes, IPs, domains,
   or extracted folders                filenames, path fragments
              │                              │
              └───────────────┬──────────────┘
                              ▼
                    ┌───────────────────┐
                    │  Resolve layout   │  KAPE / Velociraptor / CyLR /
                    └─────────┬─────────┘  Aralez / Raw — auto-detected
                              ▼
                    ┌───────────────────┐
                    │  Parse artifacts  │  MFT · UsnJrnl · Amcache · Prefetch
                    │  (EZ Tools)       │  Registry · EventLogs · SRUM · LNK …
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │ Sigma detection   │  Hayabusa + DFIR event timeline
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │    IOC sweep      │  typed matching, confidence-labelled
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │ Coverage verdict  │  CLEAN · IOC MATCH · INCONCLUSIVE
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │    Timelines      │  per-host and global, Timesketch CSV
                    └─────────┬─────────┘
                              ▼
        ┌─────────────────────┴─────────────────────┐
        ▼                     ▼                     ▼
  HTML findings         Global IOC             Run manifest
  report                timeline +             (hashes, tool
                        host × IOC matrix      versions, params)
```

Single-host pipeline: resolve layout → parse artifacts → Hayabusa → IOC sweep → coverage verdict → post-steps (visibility windows, manifest, timeline, report, filtered copies). Batch mode wraps that pipeline per collection and adds cross-host aggregation.

<!-- SCREENSHOT PLACEHOLDER: architecture/pipeline diagram (docs/img/pipeline.png) -->

## Design rationale

Two problems motivate the tool.

**Repetition.** Taking a collection from archive to analyzable output requires extraction, identifying the collector layout, locating the drive root, and running five to ten parsers with tool-specific flags and output paths — per host. The work is mechanical and scales linearly with the number of endpoints.

**Silent failure.** When a parser fails, or a collection contains fewer artifacts than expected, the output is indistinguishable from a genuinely clean host: no hits. This makes it possible to report "no evidence of compromise" over a blind spot.

SCRIBE addresses the first by running the pipeline from a single command, and the second by recording and reporting the outcome of every artifact, so that a no-hit result is accompanied by a statement of what was actually examined.

## Requirements

- **Windows** with **PowerShell 5.1+** (preinstalled on Windows 10/11 and Server 2016+). SCRIBE itself requires no other runtime.
- **Eric Zimmerman's tools** — the parsers. Fetched by `Get-Tools.ps1`. These require the [.NET Desktop Runtime](https://dotnet.microsoft.com/download).
- **Hayabusa** — optional, required for Sigma detections. Also fetched by `Get-Tools.ps1`.
- **7-Zip** — optional, required only for non-`.zip` archives in batch mode.

Binaries are not committed to this repository. Parsers, EvtxECmd maps, and Sigma rules are updated frequently and should be obtained from their official sources.

## Installation

1. Download the latest release zip from [Releases](../../releases) and verify its SHA-256 against the value in the release notes.
2. Unblock it before extracting — Windows marks downloaded files, and PowerShell will otherwise refuse to run them:
   ```powershell
   Unblock-File -Path .\scribe-*.zip
   ```
   Then extract, keeping the folder structure intact.
3. Allow scripts for the current session:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```
4. Fetch the external parsers (once; re-run at any time to update):
   ```powershell
   .\Get-Tools.ps1
   ```
   This retrieves Eric Zimmerman's tools via the official updater and the latest Hayabusa release with Sigma rules into the project's `tools\` folder, which is auto-detected.

There is nothing further to install.

For air-gapped environments, run `Get-Tools.ps1` on a connected machine and copy the `tools\` folder across. Analysis does not use the network.

## Quick start

**Graphical launcher.** Select paths and options; the UI displays the exact command it will run, and settings persist between sessions.

```powershell
.\Start-ScribeUI.ps1
```

<!-- SCREENSHOT PLACEHOLDER: the UI with paths filled in and the command preview visible (docs/img/ui.png) -->

**Single host:**

```powershell
.\Invoke-Triage.ps1 -HostArtifacts D:\case\HOST01 -IocFile .\iocs.txt -Report
```

**Batch — a folder of collections (archives, folders, or a mix):**

```powershell
.\Invoke-Triage.ps1 -BatchFolder D:\evidence -IocFile .\iocs.txt `
  -Hayabusa .\tools\hayabusa\hayabusa.exe -OutputPath D:\out -Report
```

`-Layout` defaults to `Auto`. Run `.\Invoke-Triage.ps1 -Help` for the full parameter list, or see [HELP.md](HELP.md) for the complete guide.

## Coverage and verdicts

Every artifact known to SCRIBE ends each run in exactly one of five states, recorded in `Artifact_Coverage.csv`, shown in the console, and included in the HTML report:

| State | Meaning | Implication |
|---|---|---|
| `Parsed` | Analyzed; its contents were swept. | Actual coverage. |
| `NotInCollection` | The collector did not capture it. | Blind spot — adjust the collection profile. |
| `ToolMissing` | The parser was not found under `-ToolsPath`. | Blind spot — run `Get-Tools.ps1`. |
| `ParseFailed` | The parser ran and failed. The command line is in `_logs\`. | Blind spot — reproducible by hand. |
| `Skipped` | Excluded by tier or scope configuration. | Known, intentional gap. |

The run verdict follows from those states and the sweep result:

```
   core artifacts parsed?              IOC hits?
   (MFT / Amcache / UsnJrnl / EventLogs)
              │                             │
       ┌──────┴──────┐              ┌───────┴───────┐
      no            yes            yes              no
       │             └───────┬──────┘               │
       ▼                     ▼                      ▼
  INCONCLUSIVE         IOC MATCH(ES)          NO HITS, reported
  (insufficient        (review)               alongside the
   coverage to                                coverage summary
   conclude)
```

Two related outputs constrain what can be concluded from a run:

- **Visibility windows** (`-Visibility`) record the time range each artifact can speak about. The USN journal wraps and event logs roll, so an artifact covering only recent days cannot support a statement about events before that period.
- **Unanalyzed volumes and VSS presence** are surfaced rather than assumed absent, indicating when a collection contains evidence that was not analyzed.

<!-- SCREENSHOT PLACEHOLDER: console coverage block with the [x]/[~]/[!] states (docs/img/coverage.png) -->

## Features

**Analysis**

- **Single-command pipeline** — parse, IOC sweep, Sigma detection, timeline, and HTML report for a host in one invocation, with parser flags and output locations handled consistently across every host.
- **Artifact parsing via Eric Zimmerman's tools** — MFT, UsnJrnl, Amcache, Prefetch, registry, event logs, and others, invoked identically on every collection.
- **Sigma detection via Hayabusa** — community detection rules applied to event logs without writing rules, plus Hayabusa's DFIR event timeline. Useful when a case begins without indicators.
- **Typed IOC matching** — hashes, IPs, and domains match on word boundaries and are labelled *high confidence*; other strings match as substrings and are labelled *low confidence*. The label is carried into `IOC_Hits.csv` and the report, so substring coincidences remain distinguishable from exact matches.

**Batch handling**

- **Batch mode** over a folder of collections: `.zip`, `.7z`, `.tar.gz`, `.rar`, extracted folders, password-protected archives, or a mix. A failure on one host is recorded and the batch continues.
- **Resume and parallelism** — interrupted runs continue from where they stopped. A re-collected archive under the same filename is re-analyzed rather than skipped. `-MaxParallelHosts` runs collections in isolated worker processes.
- **Pre-flight capacity check** — batch mode estimates peak extraction plus output size before starting.

**Cross-host correlation**

- **Global IOC timeline** — every hit across every host, time-sorted, for establishing sequence and spread.
- **Host × indicator matrix** — first seen, last seen, and count per host/IOC pair.
- **Per-host coverage table across the batch** — distinguishes hosts with no findings from hosts that could not be adequately analyzed.

**Reproducibility and evidence handling**

- **Risk ranking** — a mechanical 0–100 score, with its formula printed in the report. No machine learning and no hidden weights.
- **Run manifest** (`-Manifest`) — input hashes, IOC-set hash, tool versions and hashes, and all parameters, so two runs can be compared directly.
- **Read-only treatment of evidence** — output is written to a sibling `_Analysis` folder or the specified `-OutputPath`, never inside the collection. Batch mode deletes only what it extracted itself.
- **Command logging** — every tool invocation writes its exact command line to `_logs\<artifact>.log`.
- **UTC throughout** — parsers are invoked in UTC mode and timestamps are parsed culture-invariantly, so locale cannot reorder a timeline.

**Interfaces and extension**

- **Timesketch-compatible super-timelines** — per host or global, with optional time-window bounding and filtered per-artifact copies.
- **GUI and CLI over one engine** — the UI builds and displays the command line it executes.
- **Configuration rather than code** — artifacts, parsers, collection layouts, tiers, and detection scope are defined in editable JSON. Supporting a new artifact or collector is a configuration change.

## Supported artifacts

| Tier | Artifacts | Parser |
|---|---|---|
| `default` | $MFT, UsnJrnl ($J), Amcache, Prefetch, Registry (system hives, Kroll batch), Scheduled Tasks (raw copy), Event Logs | MFTECmd, AmcacheParser, PECmd, RECmd, EvtxECmd |
| `extended` | + Shimcache, SRUM, Shellbags, Recycle Bin | AppCompatCacheParser, SrumECmd, SBECmd, RBCmd |
| `full` | + LNK files, Jump Lists, NTUSER.DAT (per user) | LECmd, JLECmd, RECmd |
| *optional* | $LogFile, $Secure, $Boot — added explicitly via scope config | MFTECmd / raw copy |

Adding an artifact is a JSON entry in `config/artifacts.json`; no code change is required.

## Supported triage collections

| Layout | Collector |
|---|---|
| `Auto` *(default)* | Tries every known drive-root pattern and reports how it resolved |
| `KAPE` | Kroll Artifact Parser and Extractor (`--tdest` output, including `C%3A` encoded drives) |
| `Velociraptor` | Velociraptor offline collector (`uploads/...` structures) |
| `CyLR` | CyLR collections |
| `Aralez` | Kaspersky GERT Aralez |
| `Raw` | A mounted image, `Windows.old`, or any folder that is itself the drive root |

Collectors not listed here can usually be supported with a single block added to `config/layouts.json`. Pull requests adding layouts are welcome.

## Examples

```powershell
# Sweep known IOCs across a set of collections and produce per-host and global
# reports, bounded to an incident window
.\Invoke-Triage.ps1 -BatchFolder D:\evidence -IocFile .\ransom-iocs.txt `
  -Hayabusa .\tools\hayabusa\hayabusa.exe -Report -Timeline global `
  -TimelineStart 2026-06-01T00:00:00 -TimelineEnd 2026-06-15T00:00:00

# No indicators available: parse everything and rely on Sigma detections
.\Invoke-Triage.ps1 -HostArtifacts D:\case\HOST01 `
  -Hayabusa .\tools\hayabusa\hayabusa.exe -Report

# Mounted image or Windows.old
.\Invoke-Triage.ps1 -HostArtifacts E:\mounted\C -Layout Raw -OutputPath D:\out -Report

# Password-protected archives, four hosts in parallel, retaining extractions with hits
.\Invoke-Triage.ps1 -BatchFolder D:\evidence -ArchivePassword infected `
  -MaxParallelHosts 4 -KeepOnHit -IocFile .\iocs.txt -OutputPath D:\out

# Reproducibility record and per-artifact time horizons
.\Invoke-Triage.ps1 -HostArtifacts D:\case\HOST01 -IocFile .\iocs.txt -Manifest -Visibility
```

A sample IOC file is provided in [`examples/sample-iocs.txt`](examples/sample-iocs.txt).

## Output

**Per host:**

```
HOST01\
  _Summary.txt              result and coverage at a glance
  IOC_Hits.csv              every match: time, indicator, confidence, artifact
  Artifact_Coverage.csv     Parsed / NotInCollection / ToolMissing / ParseFailed / Skipped
  Findings_Report.html      findings report                              (-Report)
  Visibility_Windows.csv    time range each artifact can speak about     (-Visibility)
  run-manifest.json         input/IOC/tool hashes and parameters         (-Manifest)
  Timeline_Timesketch.csv   super-timeline                               (-Timeline)
  MFT\  UsnJrnl\  Amcache\  Prefetch\  Registry\  EventLogs\  ...   per-artifact CSVs
  _logs\                    per-tool logs, including the exact command line run
```

**Batch adds:**

```
_GLOBAL_IOC_Timeline.csv        all hits, all hosts, time-sorted
_GLOBAL_IOC_Matrix.csv          host × IOC: first seen / last seen / count
_GLOBAL_Coverage.csv            per-host result and coverage (failed hosts listed here)
_GLOBAL_Findings_Report.html    risk-ranked batch report                     (-Report)
_BATCH_Summary.txt              batch summary
```

**Example `_Summary.txt`:**

```
HOST      : WKS-FINANCE-01
RESULT    : 3 IOC MATCH(ES) - review
Coverage  : 7 parsed / 1 not-collected / 0 tool-missing / 0 parse-failed / 0 skipped  (of 8)
IOC hits  : 3
Note      : anything not 'Parsed' is a BLIND SPOT, not a clean result.
```

<!-- SCREENSHOT PLACEHOLDER: HTML findings report, verdict banner + risk score (docs/img/report.png) -->
<!-- SCREENSHOT PLACEHOLDER: _GLOBAL_IOC_Matrix.csv open in Timeline Explorer (docs/img/matrix.png) -->

## Repository layout

```
Invoke-Triage.ps1          entry point (CLI) — dispatch, config, preflight
Start-ScribeUI.ps1         graphical launcher — builds and runs the same command
Get-Tools.ps1              fetches external parsers from their official sources
modules/
  Resolve-Layout.ps1       find and validate the drive root for a collection layout
  Expand-Collection.ps1    archive extraction (native zip / 7-Zip), wrapper unwrapping
  Invoke-Parsing.ps1       run the configured parsers per artifact; build coverage
  Invoke-Hayabusa.ps1      Sigma detections and DFIR event timeline
  Invoke-Detections.ps1    IOC load, typing, and sweep across parsed output
  Get-Coverage.ps1         coverage report and verdict
  Get-Visibility.ps1       per-artifact visibility windows
  Build-Timeline.ps1       Timesketch super-timeline and windowed artifact copies
  Invoke-Batch.ps1         batch orchestration, parallel workers, resume, aggregation
  New-Report.ps1           per-host and global HTML findings reports, risk score
  Write-Manifest.ps1       run-manifest.json (reproducibility record)
  Test-Capacity.ps1        pre-flight disk-capacity check for batch mode
  Accelerator.ps1          optional compiled (C#) fast path for the sweep and timeline;
                           falls back to pure PowerShell automatically
  Common.ps1               shared helpers: logging, timestamps, tool table, telemetry
config/
  artifacts.json           artifact catalog: paths, parser, tier, purpose
  parsers.json             parser command templates (tool flags are changed here)
  layouts.json             collection-format layouts (add your collector here)
  config.json              defaults: tool paths, tier, Sigma settings
  config-schema.json       allowed keys for -ScopeConfig files
```

## Configuration

All engine behaviour is defined in editable JSON under `config/`:

| File | Controls | Typical edit |
|---|---|---|
| `config.json` | Tool paths, default tier, Sigma settings | Set `tools.toolsPath` to omit `-ToolsPath` |
| `artifacts.json` | Which artifacts exist, their paths, parser, and tier | Add a new artifact (copy a block) |
| `parsers.json` | The command line used for each parser | Change a tool's flags |
| `layouts.json` | Collection folder structures | Add a collector layout |
| `config-schema.json` | Allowed keys for `-ScopeConfig` files | Reference only |

Per-run scope — tier, added or skipped artifacts, IOC files, time focus — can be captured in a JSON scope config and passed with `-ScopeConfig`, allowing a hunt to be repeated identically. Precedence is **CLI > scope config > `config.json`**.

> **Contract for custom parsers:** any tool wired into `parsers.json` must emit UTC timestamps. SCRIBE treats all parsed timestamps as UTC; a parser emitting local time would skew timelines without warning.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| *"running scripts is disabled on this system"* | Execution policy. Run `Set-ExecutionPolicy -Scope Process Bypass`, and `Unblock-File` the downloaded files — see [Installation](#installation). |
| *Layout … anchor was not found* | Wrong layout or an unusual structure. The message lists every path attempted. Use `-Layout Raw` with `-HostArtifacts` pointing at the exact drive-root folder, or extend `config/layouts.json`. |
| `TOOL MISSING` next to an artifact | The parser was not found under `-ToolsPath`. Run `.\Get-Tools.ps1`, or set `tools.toolsPath` in `config.json`. The artifact is reported as a blind spot, not skipped silently. |
| A parser fails to start | Eric Zimmerman's tools require the .NET Desktop Runtime — https://dotnet.microsoft.com/download. |
| *7-Zip not found* in batch mode | Required only for non-`.zip` archives. Install from https://www.7-zip.org/ or set `tools.sevenZipPath`. |
| Result is `INCONCLUSIVE` | No core artifact (MFT / Amcache / UsnJrnl / EventLogs) was parsed. Check `Artifact_Coverage.csv` and `_logs\`; the collection may be thin or the tools missing. This is intended behaviour — a host with no usable coverage is not reported as clean. |
| Batch stops with a capacity error | The output drive cannot hold peak extraction plus outputs. Free space, use a larger drive via `-OutputPath`, or override with `-Force`. |
| Timeline is very large | Bound it with `-TimelineStart` / `-TimelineEnd`. A full-MFT timeline can run to millions of rows. |
| A host was skipped as *"complete from a prior run"* | Resume behaviour. Use `-Rerun` to force re-analysis; always do this after replacing an extracted folder's contents in place. |

Every tool invocation logs its exact command line to `_logs\<artifact>.log`, so any failure can be reproduced manually.

## FAQ

**Does SCRIBE collect evidence?**
No. It analyzes collections produced by KAPE, Velociraptor, CyLR, Aralez, or taken from a mounted image. It is used alongside an existing collector.

**Is it a replacement for Eric Zimmerman's tools or Hayabusa?**
No. It is an orchestration, correlation, coverage, and reporting layer over them. The parsing and detection engines are the original tools, fetched from their official sources.

**What does `INCONCLUSIVE` mean?**
If no core artifact could be parsed, a no-hit result is reported as inconclusive rather than clean, because the run did not examine enough evidence to support a conclusion.

**How is the risk score calculated?**
Mechanically, and the formula is printed in the report so it can be checked. There is no machine learning and there are no hidden weights.

**Does it require internet access?**
Analysis runs entirely offline. The network is used only by `Get-Tools.ps1`.

**Will it modify evidence?**
No. Output is written to a sibling `_Analysis` folder or the specified `-OutputPath`, never inside the collection. Batch mode deletes only what it extracted itself.

**What about macOS/Linux endpoints, or cloud and identity compromise?**
Out of scope. SCRIBE analyzes Windows endpoint artifacts, and its output states this rather than implying broader coverage.

**What timezone are timestamps in?**
UTC throughout. Parsers are invoked in UTC mode and timestamps are parsed culture-invariantly.

**Why PowerShell 5.1?**
It is present on every supported Windows system by default, including restricted hosts where software cannot be installed.

**How long does a run take?**
Runtime is determined mainly by collection size and the underlying parsers. `-MaxParallelHosts` and the optional compiled accelerator affect throughput on large batches.

## Contributing

Contributions are welcome, particularly configuration-only ones:

- **New collection layouts** (`config/layouts.json`) — the lowest-effort contribution with the widest benefit.
- **New artifacts and parsers** (`config/artifacts.json`, `config/parsers.json`).
- **Bug reports** with `_logs\` output attached, scrubbed of case data.

## Acknowledgments

SCRIBE depends on the following projects:

- **[Eric Zimmerman](https://ericzimmerman.github.io/)** — the parsers (MFTECmd, AmcacheParser, PECmd, EvtxECmd, RECmd, and others).
- **[Yamato Security — Hayabusa](https://github.com/Yamato-Security/hayabusa)** — Sigma detection and the DFIR event timeline.
- **[SigmaHQ](https://github.com/SigmaHQ/sigma)** — the detection rules.
- The authors of **KAPE, Velociraptor, CyLR, and Aralez** — the collectors SCRIBE consumes.

None of these projects endorse SCRIBE.

## License

[MIT](LICENSE). No warranty. See the file for the full text.

This is a community project maintained in spare time. Issues with clear reproduction steps and logs are addressed first.
