<#
.SYNOPSIS
  SCRIBE UI - a lightweight graphical front-end for Invoke-Triage.ps1.
  Builds the exact command line for you (shown live at the bottom - no hidden behavior),
  then runs it in a normal PowerShell window so you see the engine's real output.

  Requires nothing beyond stock Windows PowerShell 5.1 (WPF is built in).
  Run:  .\Start-ScribeUI.ps1
#>

[CmdletBinding()] param()

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$engine = Join-Path $PSScriptRoot 'Invoke-Triage.ps1'
if (-not (Test-Path $engine)) {
    [System.Windows.MessageBox]::Show("Invoke-Triage.ps1 not found next to this script.`nKeep Start-ScribeUI.ps1 in the SCRIBE folder.", 'SCRIBE', 'OK', 'Error') | Out-Null
    return
}

# ---------------------------------------------------------------- XAML -------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SCRIBE" Width="1200" Height="780" MinWidth="980" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="#F3F3F3"
        FontFamily="Segoe UI" FontSize="13" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <SolidColorBrush x:Key="Accent"    Color="#0067C0"/>
    <SolidColorBrush x:Key="Ink"       Color="#1B1B1B"/>
    <SolidColorBrush x:Key="InkSoft"   Color="#5C5B58"/>
    <SolidColorBrush x:Key="CardEdge"  Color="#E4E2DF"/>

    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="15"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,0,0,10"/>
    </Style>
    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource InkSoft}"/>
      <Setter Property="Margin" Value="2,8,0,3"/>
    </Style>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="{StaticResource CardEdge}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="8"/>
      <Setter Property="Padding" Value="16,14"/>
      <Setter Property="Margin" Value="0,0,0,14"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="2,6,0,6"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="ToolTipService.ShowDuration" Value="20000"/>
      <Setter Property="ToolTipService.InitialShowDelay" Value="350"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Height" Value="30"/>
      <Setter Property="Padding" Value="7,4"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="BorderBrush" Value="#D6D4D1"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="5">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"
                            VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter Property="BorderBrush" Value="#0067C0"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Height" Value="30"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Height" Value="32"/>
      <Setter Property="Padding" Value="14,0"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="BorderBrush" Value="#D6D4D1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="#F5F9FD"/>
                <Setter TargetName="bd" Property="BorderBrush" Value="#0067C0"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BtnPrimary" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#0067C0"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#0067C0"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="38"/>
      <Setter Property="Padding" Value="22,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="#0B5CA8"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BrowseBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Width" Value="34"/>
      <Setter Property="Height" Value="30"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="Margin" Value="6,0,0,0"/>
      <Setter Property="Content" Value="..."/>
    </Style>
  </Window.Resources>

  <DockPanel>

    <!-- header -->
    <Border DockPanel.Dock="Top" Background="White" BorderBrush="{StaticResource CardEdge}"
            BorderThickness="0,0,0,1" Padding="24,16">
      <DockPanel>
        <StackPanel>
          <TextBlock Text="SCRIBE" FontSize="22" FontWeight="SemiBold"/>
        </StackPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" HorizontalAlignment="Right"
                    VerticalAlignment="Center">
          <RadioButton x:Name="ModeSingle" Content="Single host" IsChecked="True" GroupName="mode"
                       Margin="0,0,16,0" VerticalContentAlignment="Center"
                       ToolTip="Analyze one collection folder (already extracted) or a mounted drive."/>
          <RadioButton x:Name="ModeBatch" Content="Batch folder" GroupName="mode"
                       VerticalContentAlignment="Center"
                       ToolTip="Analyze a folder containing many hosts' collections (archives, folders, or a mix). Produces the global cross-host timeline, IOC matrix and risk ranking."/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- footer -->
    <Border DockPanel.Dock="Bottom" Background="White" BorderBrush="{StaticResource CardEdge}"
            BorderThickness="0,1,0,0" Padding="24,12">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition/><RowDefinition/>
        </Grid.RowDefinitions>
        <DockPanel Grid.Row="0" Margin="0,0,0,10">
          <TextBlock DockPanel.Dock="Left" Text="Command preview" Foreground="{StaticResource InkSoft}"
                     VerticalAlignment="Center" Margin="0,0,10,0"/>
          <TextBox x:Name="Preview" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
                   Background="#FAF9F8" Height="52" TextWrapping="Wrap"
                   VerticalScrollBarVisibility="Auto"
                   ToolTip="This is the exact command the Run button executes - nothing hidden. Copy it to reuse in scripts or your case notes."/>
        </DockPanel>
        <DockPanel Grid.Row="1">
          <TextBlock x:Name="Status" DockPanel.Dock="Left" VerticalAlignment="Center"
                     Foreground="{StaticResource InkSoft}"/>
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnOpenOut" Content="Open output" Style="{StaticResource Btn}" Margin="0,0,10,0"
                    ToolTip="Open the effective output folder in Explorer: the one set above, or the default _Analysis folder next to the evidence."/>
            <Button x:Name="BtnReset" Content="Reset" Style="{StaticResource Btn}" Margin="0,0,10,0"/>
            <Button x:Name="BtnCopy"  Content="Copy command" Style="{StaticResource Btn}" Margin="0,0,10,0"
                    ToolTip="Copy the exact command to the clipboard (Ctrl+Shift+C)."/>
            <Button x:Name="BtnRun"   Content="Run  &#8594;" Style="{StaticResource BtnPrimary}"
                    ToolTip="Run in a new PowerShell window (Ctrl+Enter)."/>
          </StackPanel>
        </DockPanel>
      </Grid>
    </Border>

    <!-- body -->
    <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="24,18,24,4">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/><ColumnDefinition Width="14"/>
          <ColumnDefinition Width="*"/><ColumnDefinition Width="14"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- column 1 : evidence -->
        <StackPanel Grid.Column="0">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="&#128193;  Evidence" Style="{StaticResource CardTitle}"/>
              <TextBlock x:Name="LblInput" Text="Collection folder / mounted drive" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrInput" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbInput"
                         ToolTip="Single host: the extracted collection folder or a mounted image / drive root.&#10;Batch: a folder whose children are many hosts' collections (zip / 7z / folders)."/>
              </DockPanel>
              <TextBlock Text="Output folder" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrOut" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbOut" ToolTip="Where reports and parsed CSVs are written. Never inside the evidence tree. Empty = engine default: an _Analysis folder next to the evidence."/>
              </DockPanel>
              <TextBlock Text="Archive password (optional)" Style="{StaticResource FieldLabel}"/>
              <TextBox x:Name="TbArcPw" ToolTip="Batch mode: password for protected collection archives (e.g. the classic 'infected')."/>
            </StackPanel>
          </Border>

          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="&#127919;  Indicators" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="IOC file(s)" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrIoc" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbIoc"
                         ToolTip="One indicator per line: hashes, IPs, domains, file names, path fragments. Select several files at once - they are combined. Optional: empty still runs Sigma detection. Try examples\sample-iocs.txt first."/>
              </DockPanel>
            </StackPanel>
          </Border>
        </StackPanel>

        <!-- column 2 : tools + scope -->
        <StackPanel Grid.Column="2">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,10">
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                  <Button x:Name="BtnGetTools" Content="Download tools" Style="{StaticResource Btn}"
                          Height="26" Padding="10,0" Margin="0,0,6,0"
                          ToolTip="Runs Get-Tools.ps1: fetches Eric Zimmerman's tools and the latest Hayabusa release from their official sources into this project's tools\ folder. Re-run any time to update."/>
                  <Button x:Name="BtnDetect" Content="Detect" Style="{StaticResource Btn}"
                          Height="26" Padding="10,0"
                          ToolTip="Look for tools in this project's tools\ folder and fill the paths below."/>
                </StackPanel>
                <TextBlock Text="&#128295;  Tools" Style="{StaticResource CardTitle}" Margin="0"/>
              </DockPanel>
              <TextBlock Text="Eric Zimmerman tools folder" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrTools" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbTools"
                         ToolTip="Folder containing MFTECmd, AmcacheParser, PECmd, EvtxECmd, RECmd (searched recursively). Empty = value from config\config.json. Missing tools are reported as blind spots, never silently skipped."/>
              </DockPanel>
              <TextBlock Text="Hayabusa executable (optional)" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrHaya" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbHaya" ToolTip="Path to hayabusa.exe for Sigma rule detection over event logs. Leave empty to rely on config, or tick the skip box below."/>
              </DockPanel>
              <CheckBox x:Name="CkSkipHaya" Content="Skip Sigma detection (Hayabusa)"
                        ToolTip="Run without Sigma detections. The report will mark the detection stage as skipped - not clean."/>
              <TextBlock Text="7-Zip executable (optional)" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="Br7z" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="Tb7z" ToolTip="Only needed for non-zip archives (7z, tar, ...) in batch mode."/>
              </DockPanel>
            </StackPanel>
          </Border>

          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="&#128269;  Scope" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="Artifact tier" Style="{StaticResource FieldLabel}"/>
              <ComboBox x:Name="CbTier"
                        ToolTip="How many artifact types to parse. default = core triage set, extended = adds secondary artifacts, full = everything configured. Empty = engine default."/>
              <TextBlock Text="Scope config JSON (optional)" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrScope" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbScope"
                         ToolTip="A JSON file bundling tier, artifacts to add/skip, IOC files and time focus into one reusable per-case profile. Keys are validated against config\config-schema.json."/>
              </DockPanel>
              <CheckBox x:Name="CkNoDiscover" Content="Config-listed artifacts only"
                        ToolTip="Disable the artifact-discovery fallback: strictly parse what config\artifacts.json lists, nothing found opportunistically."/>
              <TextBlock Text="Timeline (Timesketch format)" Style="{StaticResource FieldLabel}"/>
              <ComboBox x:Name="CbTimeline"
                        ToolTip="One CSV containing every parsed artifact merged and time-sorted, in Timesketch import format. case = Timeline_Timesketch.csv per host (use this for a single host). global = batch only: additionally _GLOBAL_Timeline_Timesketch.csv merging every host. Upload is manual: import the CSV with Timesketch's importer / web UI (or your own Elasticsearch ingest). Bound the window below - a full-MFT timeline is millions of rows."/>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                  <TextBlock Text="Timeline start" Style="{StaticResource FieldLabel}"/>
                  <TextBox x:Name="TbTlStart" ToolTip="Optional. Limit the timeline window, e.g. 2026-06-01"/>
                </StackPanel>
                <StackPanel Grid.Column="2">
                  <TextBlock Text="Timeline end" Style="{StaticResource FieldLabel}"/>
                  <TextBox x:Name="TbTlEnd" ToolTip="Optional. e.g. 2026-07-20"/>
                </StackPanel>
              </Grid>
            </StackPanel>
          </Border>
        </StackPanel>

        <!-- column 3 : options -->
        <StackPanel Grid.Column="4">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="&#128196;  Output options" Style="{StaticResource CardTitle}"/>
              <CheckBox x:Name="CkReport" Content="HTML findings report" IsChecked="True"
                        ToolTip="Write the Findings_Report.html per host (and the global report in batch mode) - coverage, IOC hits, detections, timeline, and the printed risk-score formula."/>
              <CheckBox x:Name="CkManifest" Content="Run manifest (audit record)"
                        ToolTip="Write a machine-readable manifest of the run: tool versions, config, inputs, hashes. Useful for case files and reproducibility."/>
              <CheckBox x:Name="CkVisibility" Content="Evidence visibility windows"
                        ToolTip="Report each artifact's time horizon, so you know how far back each source can actually see."/>
              <CheckBox x:Name="CkFiltered" Content="Filtered copies of hit rows"
                        ToolTip="Also write CSVs containing only the rows that matched IOCs - quick to attach to a ticket."/>
            </StackPanel>
          </Border>

          <Border Style="{StaticResource Card}" x:Name="CardBatch">
            <StackPanel>
              <TextBlock Text="&#128230;  Batch" Style="{StaticResource CardTitle}"/>
              <TextBlock Text="Parallel hosts" Style="{StaticResource FieldLabel}"/>
              <TextBox x:Name="TbParallel" Text="1"
                       ToolTip="How many hosts to process at once in child processes. Raise on fast disks / many cores; 1 is the safe default."/>
              <CheckBox x:Name="CkKeepExtracted" Content="Keep extracted archives"
                        ToolTip="Keep the extracted working copies after analysis (default: deleted to save space)."/>
              <CheckBox x:Name="CkKeepOnHit" Content="Keep extracted evidence for hosts with hits"
                        ToolTip="Space-saving middle ground: extracted files are kept only for hosts that matched IOCs, so you can pivot deeper on them; clean hosts' extractions are deleted."/>
              <CheckBox x:Name="CkRerun" Content="Re-run already-processed hosts"
                        ToolTip="By default, hosts already complete from a prior identical run are skipped; tick to force reprocessing."/>
              <CheckBox x:Name="CkForce" Content="Override disk-capacity stop"
                        ToolTip="The engine refuses to start a batch when free disk space looks insufficient for extraction + parsing. Tick only if you know better than the estimate."/>
              <TextBlock Text="Work directory (optional)" Style="{StaticResource FieldLabel}"/>
              <DockPanel>
                <Button x:Name="BrWork" DockPanel.Dock="Right" Style="{StaticResource BrowseBtn}"/>
                <TextBox x:Name="TbWork" ToolTip="Where archives are extracted while processing. Point it at your fastest disk."/>
              </DockPanel>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>
    </ScrollViewer>
  </DockPanel>
</Window>
'@

# ------------------------------------------------------------- build window --
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xaml)))
$c = @{}
foreach ($name in @(
    'ModeSingle','ModeBatch','LblInput','TbInput','BrInput','TbOut','BrOut',
    'TbIoc','BrIoc','TbArcPw','TbTools','BrTools','TbHaya','BrHaya','CkSkipHaya','Tb7z','Br7z',
    'BtnGetTools','BtnDetect',
    'CbTier','CbTimeline','TbTlStart','TbTlEnd','TbScope','BrScope',
    'CkReport','CkManifest','CkVisibility','CkFiltered',
    'CkForce','CkNoDiscover','CkKeepOnHit',
    'CardBatch','TbParallel','CkKeepExtracted','CkRerun','TbWork','BrWork',
    'Preview','Status','BtnOpenOut','BtnReset','BtnCopy','BtnRun')) {
    $c[$name] = $window.FindName($name)
}

'(config default)','default','extended','full'    | ForEach-Object { [void]$c.CbTier.Items.Add($_) }
$c.CbTier.SelectedIndex = 0
'none','case','global'                            | ForEach-Object { [void]$c.CbTimeline.Items.Add($_) }
$c.CbTimeline.SelectedIndex = 0

# ------------------------------------------------------------- helpers -------
function Quote([string]$s) { "'" + ($s -replace "'", "''") + "'" }

# path-probe cache (see Update-Ui) + keystroke debounce: TextChanged only restarts the
# timer; the full UI refresh (incl. the one filesystem probe) runs 350ms after typing stops.
$script:PathProbe = @{ Text = $null; Ok = $false }
$script:Debounce = New-Object System.Windows.Threading.DispatcherTimer
$script:Debounce.Interval = [TimeSpan]::FromMilliseconds(350)
$script:Debounce.Add_Tick({ $script:Debounce.Stop(); Update-Ui })

# ---- settings persistence: everything except the archive password (a secret) ----
$script:SettingsPath = Join-Path $env:APPDATA 'SCRIBE\ui-settings.json'
$script:PersistText  = @('TbInput','TbOut','TbIoc','TbTools','TbHaya','Tb7z',
                         'TbTlStart','TbTlEnd','TbScope','TbParallel','TbWork')
$script:PersistCheck = @('CkSkipHaya','CkReport','CkManifest','CkVisibility','CkFiltered',
                         'CkForce','CkNoDiscover','CkKeepOnHit','CkKeepExtracted','CkRerun')

function Save-UiSettings {
    try {
        $s = [ordered]@{
            mode   = $(if ($c.ModeBatch.IsChecked) { 'batch' } else { 'single' })
            text   = @{}
            checks = @{}
            combos = @{}
            win    = @{ w = [int]$window.Width; h = [int]$window.Height }
        }
        foreach ($n in $script:PersistText)  { $s.text[$n]   = [string]$c[$n].Text }
        foreach ($n in $script:PersistCheck) { $s.checks[$n] = [bool]$c[$n].IsChecked }
        foreach ($n in @('CbTier','CbTimeline')) { $s.combos[$n] = [string]$c[$n].SelectedItem }
        $dir = Split-Path $script:SettingsPath -Parent
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        ($s | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $script:SettingsPath -Encoding UTF8
    } catch { }   # persistence must never break the app
}

function Restore-UiSettings {
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return }
    try {
        $s = Get-Content -LiteralPath $script:SettingsPath -Raw | ConvertFrom-Json
        if ([string]$s.mode -eq 'batch') { $c.ModeBatch.IsChecked = $true } else { $c.ModeSingle.IsChecked = $true }
        foreach ($n in $script:PersistText)  { $v = $s.text.$n;   if ($null -ne $v) { $c[$n].Text = [string]$v } }
        foreach ($n in $script:PersistCheck) { $v = $s.checks.$n; if ($null -ne $v) { $c[$n].IsChecked = [bool]$v } }
        foreach ($n in @('CbTier','CbTimeline')) {
            $v = [string]$s.combos.$n
            if ($v -and ($c[$n].Items -contains $v)) { $c[$n].SelectedItem = $v }
        }
        if ([double]$s.win.w -ge 980) { $window.Width  = [double]$s.win.w }
        if ([double]$s.win.h -ge 640) { $window.Height = [double]$s.win.h }
    } catch { }
    if (-not $c.TbParallel.Text.Trim()) { $c.TbParallel.Text = '1' }
}

# ---- drag & drop: drop a folder/file from Explorer straight onto a path box ----
function Enable-PathDrop {
    param([System.Windows.Controls.TextBox]$Tb)
    $Tb.AllowDrop = $true
    $Tb.Add_PreviewDragOver({
        param($s, $e)
        $e.Effects = if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) {
            [Windows.DragDropEffects]::Copy } else { [Windows.DragDropEffects]::None }
        $e.Handled = $true
    })
    $Tb.Add_PreviewDrop({
        param($s, $e)
        if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) {
            $paths = @($e.Data.GetData([Windows.DataFormats]::FileDrop))
            if ($paths.Count) {
                # the IOC box accepts several files at once (same ';' convention as Browse)
                $s.Text = if ($s.Name -eq 'TbIoc' -and $paths.Count -gt 1) { $paths -join ';' } else { [string]$paths[0] }
            }
            $e.Handled = $true
        }
    })
}

# effective output folder = explicit box, else the engine's default (sibling _Analysis)
function Get-EffectiveOutputPath {
    if ($c.TbOut.Text.Trim()) { return $c.TbOut.Text.Trim() }
    $in = $c.TbInput.Text.Trim()
    if (-not $in) { return $null }
    $trim = $in.TrimEnd('\','/')
    # Mirrors Resolve-DefaultOutputPath in modules\Common.ps1: a drive root or UNC share
    # root has no sibling folder, and the engine REFUSES to default there rather than
    # write analysis output onto the evidence volume. Report 'no default' so the UI can
    # tell the user to set one instead of showing a path the engine will never use.
    if ($trim -match '^[A-Za-z]:$' -or $trim -match '^\\\\[^\\]+\\[^\\]+$') { return $null }
    return ($trim + '_Analysis')
}

function Invoke-RunCommand {
    if (-not $c.BtnRun.IsEnabled) { return }
    $cmd = Build-Command
    $c.Status.Text = 'Launched in a new PowerShell window. This window can stay open.'
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-Command', $cmd
    )
}
function Copy-CommandToClipboard {
    [System.Windows.Clipboard]::SetText($c.Preview.Text)
    $c.Status.Text = 'Command copied to clipboard.'
}

function Detect-Tools {
    $toolsRoot = Join-Path $PSScriptRoot 'tools'
    $ez = Join-Path $toolsRoot 'ZimmermanTools'
    if ((-not $c.TbTools.Text.Trim()) -and (Test-Path $ez)) { $c.TbTools.Text = $ez }
    if (-not $c.TbHaya.Text.Trim()) {
        $exe = Get-ChildItem -Path (Join-Path $toolsRoot 'hayabusa') -Recurse -Filter 'hayabusa.exe' `
                             -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exe) { $c.TbHaya.Text = $exe.FullName }
    }
    if (-not $c.Tb7z.Text.Trim()) {
        $sz = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
              Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if ($sz) { $c.Tb7z.Text = $sz }
    }
}

function Build-Command {
    $isBatch = [bool]$c.ModeBatch.IsChecked
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('& ' + (Quote $engine))

    if ($c.TbInput.Text.Trim()) {
        $parts.Add(($(if ($isBatch) { '-BatchFolder ' } else { '-HostArtifacts ' }) + (Quote $c.TbInput.Text.Trim())))
    }
    if ($c.TbOut.Text.Trim())   { $parts.Add('-OutputPath ' + (Quote $c.TbOut.Text.Trim())) }

    if ($c.TbIoc.Text.Trim()) {
        $files = $c.TbIoc.Text.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if ($files) { $parts.Add('-IocFile ' + (($files | ForEach-Object { Quote $_ }) -join ',')) }
    }
    if ($c.TbArcPw.Text)        { $parts.Add('-ArchivePassword ' + (Quote $c.TbArcPw.Text)) }

    if ($c.TbTools.Text.Trim()) { $parts.Add('-ToolsPath ' + (Quote $c.TbTools.Text.Trim())) }
    if ($c.CkSkipHaya.IsChecked) { $parts.Add('-SkipHayabusa') }
    elseif ($c.TbHaya.Text.Trim()) { $parts.Add('-Hayabusa ' + (Quote $c.TbHaya.Text.Trim())) }
    if ($c.Tb7z.Text.Trim())    { $parts.Add('-SevenZipPath ' + (Quote $c.Tb7z.Text.Trim())) }

    if ($c.CbTier.SelectedIndex -gt 0)     { $parts.Add('-Tier ' + $c.CbTier.SelectedItem) }
    if ($c.TbScope.Text.Trim())            { $parts.Add('-ScopeConfig ' + (Quote $c.TbScope.Text.Trim())) }
    if ($c.CbTimeline.SelectedItem -ne 'none') {
        $parts.Add('-Timeline ' + $c.CbTimeline.SelectedItem)
        if ($c.TbTlStart.Text.Trim()) { $parts.Add('-TimelineStart ' + (Quote $c.TbTlStart.Text.Trim())) }
        if ($c.TbTlEnd.Text.Trim())   { $parts.Add('-TimelineEnd '   + (Quote $c.TbTlEnd.Text.Trim())) }
    }

    if ($c.CkReport.IsChecked)     { $parts.Add('-Report') }
    if ($c.CkManifest.IsChecked)   { $parts.Add('-Manifest') }
    if ($c.CkVisibility.IsChecked) { $parts.Add('-Visibility') }
    if ($c.CkFiltered.IsChecked)   { $parts.Add('-FilteredCopies') }
    if ($c.CkNoDiscover.IsChecked) { $parts.Add('-NoDiscover') }

    if ($isBatch) {
        $n = 0
        if ([int]::TryParse($c.TbParallel.Text.Trim(), [ref]$n) -and $n -gt 1) { $parts.Add("-MaxParallelHosts $n") }
        if ($c.CkKeepExtracted.IsChecked) { $parts.Add('-KeepExtracted') }
        if ($c.CkKeepOnHit.IsChecked)     { $parts.Add('-KeepOnHit') }
        if ($c.CkRerun.IsChecked)         { $parts.Add('-Rerun') }
        if ($c.CkForce.IsChecked)         { $parts.Add('-Force') }
        if ($c.TbWork.Text.Trim())        { $parts.Add('-WorkDir ' + (Quote $c.TbWork.Text.Trim())) }
    }
    ($parts -join ' ')
}

$script:UiBusy = $false
function Update-Ui {
    # Reentrancy guard: this function rewrites UI state (e.g. the timeline dropdown's items),
    # and those writes fire change events whose handlers call Update-Ui again mid-rewrite -
    # unguarded, that recurses until call depth overflow.
    if ($script:UiBusy) { return }
    $script:UiBusy = $true
    try {
    $isBatch = [bool]$c.ModeBatch.IsChecked

    # 'global' is built by the batch orchestrator only - offering it in single mode
    # silently produces nothing. Keep the list honest to the mode.
    $wanted = if ($isBatch) { @('none','case','global') } else { @('none','case') }
    if (@($c.CbTimeline.Items).Count -ne $wanted.Count) {
        $keep = [string]$c.CbTimeline.SelectedItem
        $c.CbTimeline.Items.Clear()
        foreach ($i in $wanted) { [void]$c.CbTimeline.Items.Add($i) }
        $c.CbTimeline.SelectedItem = if ($wanted -contains $keep) { $keep } else { 'case' }
    }
    $c.LblInput.Text = if ($isBatch) { 'Folder of collections (one child per host)' } else { 'Collection folder / mounted drive' }
    $c.CardBatch.IsEnabled  = $isBatch
    $c.CardBatch.Opacity    = if ($isBatch) { 1 } else { 0.45 }
    $c.TbHaya.IsEnabled     = -not $c.CkSkipHaya.IsChecked
    $c.Preview.Text = Build-Command

    # Path existence probe, CACHED by text: evidence usually sits on a UNC share, where a
    # synchronous Test-Path per keystroke can block the UI thread for seconds. The probe
    # hits the filesystem only when the text actually changed (and TextChanged events are
    # debounced before reaching here at all).
    $inTxt = $c.TbInput.Text.Trim()
    if ($inTxt -ne $script:PathProbe.Text) {
        $script:PathProbe.Text = $inTxt
        $script:PathProbe.Ok   = [bool]($inTxt -and (Test-Path -LiteralPath $inTxt -ErrorAction SilentlyContinue))
    }

    # A drive/share root input has no sibling folder for the default output, and the engine
    # refuses to write onto the evidence volume - so an explicit output folder is REQUIRED.
    # Catch it here rather than letting the analyst launch a run that stops immediately.
    $rootInput = ($inTxt -and (($inTxt.TrimEnd('\','/') -match '^[A-Za-z]:$') -or ($inTxt.TrimEnd('\','/') -match '^\\\\[^\\]+\\[^\\]+$')))
    $needsOut  = ($rootInput -and -not $c.TbOut.Text.Trim())

    $c.Status.Text = if (-not $inTxt) { 'Pick the evidence path to enable Run.' }
                     elseif (-not $script:PathProbe.Ok) { 'Evidence path does not exist (yet).' }
                     elseif ($needsOut) {
                         'Evidence is a volume root - set an Output folder on another volume (SCRIBE will not write onto the evidence).' }
                     elseif (($c.CbTimeline.SelectedItem -ne 'none') -and -not ($c.TbTlStart.Text.Trim() -or $c.TbTlEnd.Text.Trim())) {
                         'Ready. Timeline has no start/end - a full-MFT timeline can be millions of rows.' }
                     elseif (-not $c.TbHaya.Text.Trim() -and -not $c.CkSkipHaya.IsChecked) {
                         'Ready. No Hayabusa path - Sigma detection will be reported as a blind spot.' }
                     else { 'Ready.' }
    $c.BtnRun.IsEnabled = ([bool]$inTxt -and -not $needsOut)
    } finally { $script:UiBusy = $false }
}

function Pick-Folder([System.Windows.Controls.TextBox]$target) {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($target.Text -and (Test-Path $target.Text)) { $dlg.SelectedPath = $target.Text }
    if ($dlg.ShowDialog() -eq 'OK') { $target.Text = $dlg.SelectedPath }
}
function Pick-File([System.Windows.Controls.TextBox]$target, [string]$filter, [bool]$multi = $false) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = $filter; $dlg.Multiselect = $multi
    if ($dlg.ShowDialog() -eq 'OK') {
        $target.Text = if ($multi) { $dlg.FileNames -join ';' } else { $dlg.FileName }
    }
}

# ------------------------------------------------------------- wire events ---
$c.BrInput.Add_Click({ Pick-Folder $c.TbInput })
$c.BrOut.Add_Click(  { Pick-Folder $c.TbOut })
$c.BrTools.Add_Click({ Pick-Folder $c.TbTools })
$c.BrWork.Add_Click( { Pick-Folder $c.TbWork })
$c.BrIoc.Add_Click(  { Pick-File $c.TbIoc  'IOC lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*' $true })
$c.BrScope.Add_Click({ Pick-File $c.TbScope 'Scope config (*.json)|*.json|All files (*.*)|*.*' })
$c.BrHaya.Add_Click( { Pick-File $c.TbHaya 'hayabusa.exe|hayabusa*.exe|Executables (*.exe)|*.exe' })
$c.Br7z.Add_Click(   { Pick-File $c.Tb7z   '7z.exe|7z.exe|Executables (*.exe)|*.exe' })

$c.BtnGetTools.Add_Click({
    $getTools = Join-Path $PSScriptRoot 'Get-Tools.ps1'
    if (-not (Test-Path $getTools)) {
        $c.Status.Text = 'Get-Tools.ps1 not found next to this script.'
        return
    }
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File', $getTools
    )
    $c.Status.Text = 'Downloading in a new window. When it finishes, click Detect.'
})

$c.BtnDetect.Add_Click({
    Detect-Tools
    Update-Ui
    $c.Status.Text = if ($c.TbTools.Text) { 'Tools detected and filled in.' } else { 'No tools\ folder found - click Download tools first.' }
})

foreach ($tb in @($c.TbInput,$c.TbOut,$c.TbIoc,$c.TbArcPw,$c.TbTools,$c.TbHaya,$c.Tb7z,
                  $c.TbTlStart,$c.TbTlEnd,$c.TbScope,$c.TbParallel,$c.TbWork)) {
    # debounced: restart the timer per keystroke; Update-Ui runs when typing pauses
    $tb.Add_TextChanged({ $script:Debounce.Stop(); $script:Debounce.Start() })
}
foreach ($tb in @($c.TbInput,$c.TbOut,$c.TbIoc,$c.TbTools,$c.TbHaya,$c.Tb7z,$c.TbScope,$c.TbWork)) {
    Enable-PathDrop $tb
}
foreach ($ck in @($c.CkSkipHaya,$c.CkReport,$c.CkManifest,$c.CkVisibility,$c.CkFiltered,
                  $c.CkForce,$c.CkNoDiscover,$c.CkKeepOnHit,$c.CkKeepExtracted,$c.CkRerun)) {
    $ck.Add_Checked({ Update-Ui }); $ck.Add_Unchecked({ Update-Ui })
}
foreach ($cb in @($c.CbTier,$c.CbTimeline)) { $cb.Add_SelectionChanged({ Update-Ui }) }
$c.ModeSingle.Add_Checked({ Update-Ui }); $c.ModeBatch.Add_Checked({ Update-Ui })

$c.BtnCopy.Add_Click({ Copy-CommandToClipboard })

$c.BtnOpenOut.Add_Click({
    $p = Get-EffectiveOutputPath
    if ($p -and (Test-Path -LiteralPath $p)) {
        Start-Process explorer.exe -ArgumentList ('"' + $p + '"')
        $c.Status.Text = "Opened: $p"
    } elseif ($p) { $c.Status.Text = "Output folder does not exist yet: $p" }
    else          { $c.Status.Text = 'Set the evidence path first.' }
})

# keyboard shortcuts: Ctrl+Enter = Run, Ctrl+Shift+C = copy command
$window.Add_PreviewKeyDown({
    param($s, $e)
    $mods  = [System.Windows.Input.Keyboard]::Modifiers
    $ctrl  = ($mods -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
    $shift = ($mods -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0
    if ($ctrl -and $e.Key -eq [System.Windows.Input.Key]::Return) { Invoke-RunCommand; $e.Handled = $true }
    elseif ($ctrl -and $shift -and $e.Key -eq [System.Windows.Input.Key]::C) { Copy-CommandToClipboard; $e.Handled = $true }
})

$window.Add_Closed({ Save-UiSettings })

$c.BtnReset.Add_Click({
    foreach ($tb in @($c.TbInput,$c.TbOut,$c.TbIoc,$c.TbArcPw,$c.TbTools,$c.TbHaya,$c.Tb7z,
                      $c.TbTlStart,$c.TbTlEnd,$c.TbScope,$c.TbWork)) { $tb.Text = '' }
    $c.TbParallel.Text = '1'
    foreach ($ck in @($c.CkSkipHaya,$c.CkManifest,$c.CkVisibility,$c.CkFiltered,
                      $c.CkForce,$c.CkNoDiscover,$c.CkKeepOnHit,$c.CkKeepExtracted,$c.CkRerun)) { $ck.IsChecked = $false }
    $c.CkReport.IsChecked = $true
    $c.CbTier.SelectedIndex = 0; $c.CbTimeline.SelectedIndex = 0
    $c.ModeSingle.IsChecked = $true
    Update-Ui
})

$c.BtnRun.Add_Click({ Invoke-RunCommand })

Restore-UiSettings      # last session's settings (never the archive password)
Detect-Tools            # fills only fields still empty after restore
Update-Ui
[void]$window.ShowDialog()
