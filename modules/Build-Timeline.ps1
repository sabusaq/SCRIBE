# Timesketch super-timeline + windowed artifact copies. Streamed I/O throughout:
# TextFieldParser (correct quoted-CSV handling) + StreamWriter. Import-Csv's per-row object
# construction does not survive multi-million-row MFT/UsnJrnl files.

Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue

function Get-TimelineFieldMap {
    param([string]$Artifact)
    switch ($Artifact) {
        'MFT' { return @(
            @{ ts='Created0x10';          desc='MFT $SI Created';   path='ParentPath';  name='FileName' }
            @{ ts='LastModified0x10';     desc='MFT $SI Modified';  path='ParentPath';  name='FileName' }
            @{ ts='LastAccess0x10';       desc='MFT $SI Accessed';  path='ParentPath';  name='FileName' }
            @{ ts='LastRecordChange0x10'; desc='MFT $SI Changed';   path='ParentPath';  name='FileName' }
            @{ ts='Created0x30';          desc='MFT $FN Created';   path='ParentPath';  name='FileName' }
        )}
        'UsnJrnl' { return @(
            @{ ts='UpdateTimestamp'; desc='UsnJrnl'; path='ParentPath'; name='Name'; extra='UpdateReasons' }
        )}
        'Amcache' { return @(
            @{ ts='FileKeyLastWriteTimestamp'; desc='Amcache Key Write';    path='FullPath'; name='Name'; extra='SHA1' }
            @{ ts='KeyLastWriteTimestamp';     desc='Amcache Key Write';    name='Name' }
            @{ ts='DriverLastWriteTime';       desc='Amcache Driver Write'; name='DriverName' }
        )}
        'Prefetch' { return @(
            @{ ts='LastRun';       desc='Prefetch Last Run'; name='ExecutableName'; extra='RunCount' }
            @{ ts='PreviousRun0';  desc='Prefetch Run';      name='ExecutableName' }
            @{ ts='PreviousRun1';  desc='Prefetch Run';      name='ExecutableName' }
            @{ ts='RunTime';       desc='Prefetch Run';      name='ExecutableName' }
        )}
        'Registry' { return @(
            @{ ts='LastWriteTimestamp'; desc='Registry Key Write'; path='KeyPath'; name='ValueName'; extra='ValueData' }
        )}
        'EventLogs' { return @(
            @{ ts='TimeCreated'; desc='EventLog'; name='MapDescription'; extra='Payload'; eid='EventId'; chan='Channel' }
        )}
        default { return @() }
    }
}

# CSV writing: quote everything, double embedded quotes (matches Export-Csv semantics)
function ConvertTo-CsvField {
    param([string]$v)
    if ($null -eq $v) { $v = '' }
    return '"' + $v.Replace('"','""') + '"'
}

function New-CsvParser {
    param([string]$Path)
    $p = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($Path)
    $p.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $p.SetDelimiters(',')
    $p.HasFieldsEnclosedInQuotes = $true
    return $p
}

# Split ONE physical CSV line into fields (quoted-CSV rules). Used by the IOC sweep to read
# a single hit line without spinning up a ConvertFrom-Csv pipeline per hit. Returns @() on
# malformed input (e.g. one physical line of a record that spans lines) - the caller treats
# that exactly like the previous parse-failure path.
function Split-CsvLine {
    param([string]$Line)
    if ($null -eq $Line -or $Line.Length -eq 0) { return ,@() }
    $sr = New-Object System.IO.StringReader($Line)
    $p = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($sr)
    $p.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $p.SetDelimiters(',')
    $p.HasFieldsEnclosedInQuotes = $true
    try {
        if ($p.EndOfData) { return ,@() }
        $f = $p.ReadFields()
        if ($null -eq $f) { return ,@() }
        return ,$f
    } catch { return ,@() }
    finally { $p.Close() }
}

# Stream one parsed CSV into the open timeline writer. Returns rows written.
function Add-ArtifactToTimeline {
    param(
        [string]$Csv, [string]$Artifact, [string]$HostName,
        [System.IO.StreamWriter]$Writer,
        [Nullable[datetime]]$Start, [Nullable[datetime]]$End
    )
    $maps = @(Get-TimelineFieldMap -Artifact $Artifact)
    if (-not $maps.Count -or -not (Test-Path -LiteralPath $Csv)) { return 0 }

    # ---- compiled path (modules/Accelerator.ps1): same transform at disk speed. The maps,
    # window, message construction, and output format are identical to the loop below;
    # parity is test-enforced. Field-measured motivation: 216s of interpreted per-row work
    # on one big host.
    if ($script:AccelOK) {
        $mTs = New-Object System.Collections.Generic.List[string]
        $mDesc = New-Object System.Collections.Generic.List[string]
        $mPath = New-Object System.Collections.Generic.List[string]
        $mName = New-Object System.Collections.Generic.List[string]
        $mExtra = New-Object System.Collections.Generic.List[string]
        $mEid = New-Object System.Collections.Generic.List[string]
        $mChan = New-Object System.Collections.Generic.List[string]
        foreach ($m in $maps) {
            $mTs.Add([string]$m.ts);      $mDesc.Add([string]$m.desc)
            $mPath.Add([string]$m.path);  $mName.Add([string]$m.name)
            $mExtra.Add([string]$m.extra); $mEid.Add([string]$m.eid); $mChan.Add([string]$m.chan)
        }
        # PS auto-unwraps [Nullable[datetime]]: $Start here is a plain datetime (or $null),
        # so .Value does not exist - Ticks must be read directly. (.Value.Ticks silently
        # yielded $null -> 0 -> NO WINDOW; caught by the parity gate.)
        $st = if ($null -ne $Start) { ([datetime]$Start).Ticks } else { [long]0 }
        $en = if ($null -ne $End)   { ([datetime]$End).Ticks }   else { [long]0 }
        try {
            return [ScribeAccel.Timeline]::TransformCsv(
                $Csv, $Artifact, $HostName,
                $mTs.ToArray(), $mDesc.ToArray(), $mPath.ToArray(), $mName.ToArray(),
                $mExtra.ToArray(), $mEid.ToArray(), $mChan.ToArray(),
                $st, $en, $Writer)
        } catch {
            Write-Log ("  [!] accelerated timeline failed on {0} ({1}) - falling back" -f (Split-Path $Csv -Leaf), $_.Exception.Message) Yellow
            # fall through to the PowerShell loop
        }
    }

    $written = 0
    $p = New-CsvParser -Path $Csv
    try {
        if ($p.EndOfData) { return 0 }
        $hdr = $p.ReadFields()
        $idx = @{}
        for ($i = 0; $i -lt $hdr.Count; $i++) { if (-not $idx.ContainsKey($hdr[$i])) { $idx[$hdr[$i]] = $i } }

        # secondary parser outputs legitimately lack the mapped columns - skip them silently
        # here; Build-HostTimeline warns once per ARTIFACT if no file at all matched.
        $usable = @($maps | Where-Object { $idx.ContainsKey($_.ts) })
        if (-not $usable.Count) { return -1 }

        while (-not $p.EndOfData) {
            $f = $null
            try { $f = $p.ReadFields() } catch { continue }   # malformed line: skip it, not the file
            if (-not $f) { continue }
            foreach ($m in $usable) {
                $ti = $idx[$m.ts]
                if ($ti -ge $f.Count) { continue }
                $tsRaw = $f[$ti]
                if (-not $tsRaw) { continue }
                $dt = ConvertTo-DateTimeSafe $tsRaw
                if (-not $dt) { continue }
                if ($Start -and $dt -lt $Start) { continue }
                if ($End   -and $dt -gt $End)   { continue }

                $parts = @()
                $pv = ''; $nv = ''; $ev = ''; $cv = ''; $xv = ''
                if ($m.path  -and $idx.ContainsKey($m.path)  -and $idx[$m.path]  -lt $f.Count) { $pv = $f[$idx[$m.path]] }
                if ($m.name  -and $idx.ContainsKey($m.name)  -and $idx[$m.name]  -lt $f.Count) { $nv = $f[$idx[$m.name]] }
                if ($m.eid   -and $idx.ContainsKey($m.eid)   -and $idx[$m.eid]   -lt $f.Count) { $ev = $f[$idx[$m.eid]] }
                if ($m.chan  -and $idx.ContainsKey($m.chan)  -and $idx[$m.chan]  -lt $f.Count) { $cv = $f[$idx[$m.chan]] }
                if ($m.extra -and $idx.ContainsKey($m.extra) -and $idx[$m.extra] -lt $f.Count) { $xv = $f[$idx[$m.extra]] }
                if ($pv) { $parts += ("{0}\{1}" -f $pv, $nv) } elseif ($nv) { $parts += $nv }
                if ($ev) { $parts += ("EID {0}" -f $ev) }
                if ($cv) { $parts += $cv }
                if ($xv) { $parts += $xv }
                $msg = ($parts -join ' | ')
                if (-not $msg) { $msg = (Split-Path $Csv -Leaf) }
                if ($msg.Length -gt 800) { $msg = $msg.Substring(0, 800) }

                $Writer.WriteLine(
                    (ConvertTo-CsvField $msg) + ',' +
                    (ConvertTo-CsvField ($dt.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))) + ',' +
                    (ConvertTo-CsvField $m.desc) + ',' +
                    (ConvertTo-CsvField ("triage:$Artifact")) + ',' +
                    (ConvertTo-CsvField $HostName) + ',' +
                    (ConvertTo-CsvField $Artifact))
                $written++
            }
        }
    } finally { $p.Close() }
    return $written
}

# Build a per-host timeline into $OutFile (appends - the global timeline spans hosts).
# Returns rows written.
function Build-HostTimeline {
    param(
        [string]$HostOutput, [string]$HostName, [string]$OutFile,
        [Nullable[datetime]]$Start, [Nullable[datetime]]$End
    )
    $newFile = -not (Test-Path -LiteralPath $OutFile) -or ((Get-Item -LiteralPath $OutFile -ErrorAction SilentlyContinue).Length -eq 0)
    $enc = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($OutFile, $true, $enc)
    $written = 0
    try {
        if ($newFile) { $writer.WriteLine('"message","datetime","timestamp_desc","data_type","host","source_short"') }
        foreach ($dir in (Get-ChildItem -LiteralPath $HostOutput -Directory -ErrorAction SilentlyContinue)) {
            $maps = Get-TimelineFieldMap -Artifact $dir.Name
            if (-not $maps) { continue }
            $filesSeen = 0; $filesMatched = 0
            foreach ($csv in (Get-ChildItem -LiteralPath $dir.FullName -Filter *.csv -File -ErrorAction SilentlyContinue |
                              Where-Object { $_.Name -notmatch '_filtered\.csv$' })) {
                $filesSeen++
                $r = Add-ArtifactToTimeline -Csv $csv.FullName -Artifact $dir.Name -HostName $HostName `
                                            -Writer $writer -Start $Start -End $End
                if ($r -ge 0) { $filesMatched++; $written += $r }
            }
            if ($filesSeen -gt 0 -and $filesMatched -eq 0) {
                Write-Log ("  [!] {0}: no expected timestamp columns in ANY of its {1} CSV(s) - parser schema changed? No timeline rows from this artifact." -f `
                           $dir.Name, $filesSeen) Yellow
            }
        }
    } finally { $writer.Close() }
    return $written
}

# Windowed copies of the parsed CSVs (<name>_filtered.csv, same folder). Streamed; the full
# CSVs are never modified. A row is kept if ANY known timestamp column falls in the window.
function Export-FilteredArtifacts {
    param(
        [string]$HostOutput,
        [Nullable[datetime]]$Start, [Nullable[datetime]]$End
    )
    if (-not $Start -and -not $End) { return }
    $made = 0
    $enc = New-Object System.Text.UTF8Encoding($false)
    foreach ($dir in (Get-ChildItem -LiteralPath $HostOutput -Directory -ErrorAction SilentlyContinue)) {
        $maps = Get-TimelineFieldMap -Artifact $dir.Name
        if (-not $maps) { continue }
        $tsCols = @($maps | ForEach-Object { $_.ts } | Select-Object -Unique)
        foreach ($csv in (Get-ChildItem -LiteralPath $dir.FullName -Filter *.csv -File -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -notmatch '_filtered\.csv$' })) {
            $out = Join-Path $dir.FullName ($csv.BaseName + '_filtered.csv')
            if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
            $kept = 0
            $p = New-CsvParser -Path $csv.FullName
            $w = $null
            try {
                if ($p.EndOfData) { continue }
                $hdr = $p.ReadFields()
                $idx = @{}
                for ($i = 0; $i -lt $hdr.Count; $i++) { if (-not $idx.ContainsKey($hdr[$i])) { $idx[$hdr[$i]] = $i } }
                $use = @($tsCols | Where-Object { $idx.ContainsKey($_) })
                if (-not $use.Count) { continue }
                $w = New-Object System.IO.StreamWriter($out, $false, $enc)
                $w.WriteLine((($hdr | ForEach-Object { ConvertTo-CsvField $_ }) -join ','))
                while (-not $p.EndOfData) {
                    $f = $null
                    try { $f = $p.ReadFields() } catch { continue }
                    if (-not $f) { continue }
                    $in = $false
                    foreach ($c in $use) {
                        $ci = $idx[$c]
                        if ($ci -ge $f.Count) { continue }
                        $v = $f[$ci]
                        if (-not $v) { continue }
                        $dt = ConvertTo-DateTimeSafe $v
                        if (-not $dt) { continue }
                        if ($Start -and $dt -lt $Start) { continue }
                        if ($End   -and $dt -gt $End)   { continue }
                        $in = $true; break
                    }
                    if ($in) {
                        $w.WriteLine((($f | ForEach-Object { ConvertTo-CsvField $_ }) -join ','))
                        $kept++
                    }
                }
            } finally { $p.Close(); if ($w) { $w.Close() } }
            if ($kept) { $made++ }
            else { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
        }
    }
    if ($made) { Write-Log ("  -> {0} *_filtered.csv file(s) written (window applied; full CSVs untouched)" -f $made) Green }
}
