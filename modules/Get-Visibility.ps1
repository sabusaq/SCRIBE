# Per-artifact visibility windows. Extends coverage from "did the parser run" to "what can
# this evidence actually prove". A parsed artifact still has a time horizon: the USN journal
# wraps, event logs roll, prefetch is capped. Reporting that horizon prevents a whole class of
# "file X never existed" / "no activity before date Y" wrong conclusions.

# Min/max of a timestamp column across a CSV. Streamed - never materializes the file.
function Get-CsvTimeSpan {
    param([string]$Csv, [string[]]$TimeColumns)
    if (-not (Test-Path -LiteralPath $Csv)) { return $null }
    $min = [datetime]::MaxValue; $max = [datetime]::MinValue; $seen = $false
    $p = New-CsvParser -Path $Csv
    try {
        if ($p.EndOfData) { return $null }
        $hdr = $p.ReadFields()
        $idx = @{}
        for ($i = 0; $i -lt $hdr.Count; $i++) { if (-not $idx.ContainsKey($hdr[$i])) { $idx[$hdr[$i]] = $i } }
        $cols = @($TimeColumns | Where-Object { $idx.ContainsKey($_) } | ForEach-Object { $idx[$_] })
        if (-not $cols.Count) { return $null }
        while (-not $p.EndOfData) {
            $f = $null
            try { $f = $p.ReadFields() } catch { continue }
            if (-not $f) { continue }
            foreach ($ci in $cols) {
                if ($ci -ge $f.Count) { continue }
                $dt = ConvertTo-DateTimeSafe $f[$ci]
                if ($dt) { if ($dt -lt $min) { $min = $dt }; if ($dt -gt $max) { $max = $dt }; $seen = $true }
            }
        }
    } finally { $p.Close() }
    if (-not $seen) { return $null }
    return @{ First = $min; Last = $max }
}

function Get-VisibilityWindows {
    param([Parameter(Mandatory)][string]$HostOutput)
    $rows = New-Object System.Collections.Generic.List[object]

    $add = {
        param($Artifact, $Note, $First, $Last)
        $rows.Add([pscustomobject]@{
            Artifact = $Artifact
            VisibleFrom = $(if ($First) { $First.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
            VisibleTo   = $(if ($Last)  { $Last.ToString('yyyy-MM-dd HH:mm:ss') }  else { '' })
            Note = $Note
        })
    }

    # UsnJrnl: the classic "journal wrapped" trap
    $j = Join-Path $HostOutput 'UsnJrnl\UsnJrnl.csv'
    if (Test-Path -LiteralPath $j) {
        $sp = Get-CsvTimeSpan -Csv $j -TimeColumns @('UpdateTimestamp')
        if ($sp) { & $add 'UsnJrnl' 'File-activity visibility is limited to this window; the journal wraps. A missing file event before VisibleFrom proves nothing.' $sp.First $sp.Last }
    }

    # MFT $SI span (whole-disk history context)
    $mft = Join-Path $HostOutput 'MFT\MFT.csv'
    if (Test-Path -LiteralPath $mft) {
        $sp = Get-CsvTimeSpan -Csv $mft -TimeColumns @('Created0x10','LastModified0x10')
        if ($sp) { & $add 'MFT' 'Filesystem metadata span ($SI). $SI is timestompable; corroborate with $FN.' $sp.First $sp.Last }
    }

    # Prefetch execution span
    $pf = Join-Path $HostOutput 'Prefetch\Prefetch.csv'
    if (Test-Path -LiteralPath $pf) {
        $sp = Get-CsvTimeSpan -Csv $pf -TimeColumns @('LastRun','PreviousRun0')
        if ($sp) { & $add 'Prefetch' 'Execution-evidence window. Prefetch is capped and disabled on Server.' $sp.First $sp.Last }
    }

    # Event logs: oldest/newest per channel (streamed)
    $elc = Join-Path $HostOutput 'EventLogs\EventLogs.csv'
    if (Test-Path -LiteralPath $elc) {
        $perChan = @{}
        $p = New-CsvParser -Path $elc
        try {
            if (-not $p.EndOfData) {
                $hdr = $p.ReadFields()
                $idx = @{}
                for ($i = 0; $i -lt $hdr.Count; $i++) { if (-not $idx.ContainsKey($hdr[$i])) { $idx[$hdr[$i]] = $i } }
                $iCh = if ($idx.ContainsKey('Channel')) { $idx['Channel'] } else { -1 }
                $iMd = if ($idx.ContainsKey('MapDescription')) { $idx['MapDescription'] } else { -1 }
                $iTc = if ($idx.ContainsKey('TimeCreated')) { $idx['TimeCreated'] } else { -1 }
                if ($iTc -ge 0) {
                    while (-not $p.EndOfData) {
                        $f = $null
                        try { $f = $p.ReadFields() } catch { continue }
                        if (-not $f -or $iTc -ge $f.Count) { continue }
                        $ch = if ($iCh -ge 0 -and $iCh -lt $f.Count -and $f[$iCh]) { $f[$iCh] }
                              elseif ($iMd -ge 0 -and $iMd -lt $f.Count) { $f[$iMd] } else { $null }
                        $dt = ConvertTo-DateTimeSafe $f[$iTc]
                        if ($ch -and $dt) {
                            if (-not $perChan.ContainsKey($ch)) { $perChan[$ch] = @{ First=$dt; Last=$dt } }
                            else { if ($dt -lt $perChan[$ch].First) { $perChan[$ch].First=$dt }; if ($dt -gt $perChan[$ch].Last) { $perChan[$ch].Last=$dt } }
                        }
                    }
                }
            }
        } finally { $p.Close() }
        foreach ($ch in ($perChan.Keys | Sort-Object)) {
            & $add ("EventLog:$ch") 'Log rolls; events before VisibleFrom are gone.' $perChan[$ch].First $perChan[$ch].Last
        }
    }

    if ($rows.Count) {
        $rows | Export-Csv -NoTypeInformation -Path (Join-Path $HostOutput 'Visibility_Windows.csv')
        Write-Log ("  -> Visibility_Windows.csv  ({0} artifact horizon(s))" -f $rows.Count) Green
    }
    return $rows
}
