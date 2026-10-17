#Requires -RunAsAdministrator
<#
Used-laptop health check (Windows 10/11, PowerShell 5.1+).
Run in elevated PowerShell:
  Set-ExecutionPolicy -Scope Process Bypass
  .\laptop-health-check.ps1
Options: -StressSeconds 180  -SkipStress  -SkipIntegrity (skips sfc/DISM, ~15 min)
Plug in AC power. Report lands on Desktop\HealthReport_<date>\.
#>
param(
    [int]$StressSeconds = 120,
    [switch]$SkipStress,
    [switch]$SkipIntegrity
)

$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path ([Environment]::GetFolderPath('Desktop')) ("HealthReport_{0:yyyyMMdd_HHmm}" -f (Get-Date))
New-Item -ItemType Directory -Path $out -Force | Out-Null
$report = Join-Path $out 'report.txt'
$script:Results = @()

function Log($m) { Add-Content -Path $report -Value $m; Write-Host $m }
function Section($t) { Log ''; Log ('=' * 60); Log $t; Log ('=' * 60) }
function Verdict($status, $name, $detail) {
    $script:Results += [pscustomobject]@{ Status = $status; Check = $name; Detail = $detail }
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$status]
    $line = '[{0}] {1} - {2}' -f $status, $name, $detail
    Add-Content -Path $report -Value $line
    Write-Host $line -ForegroundColor $color
}

Add-Type -TypeDefinition @'
using System;
using System.Threading;
using System.Diagnostics;
public static class HC {
    static volatile bool stop;
    public static long AllocatedMb;
    public static void StartCpu(int seconds) {
        stop = false;
        for (int i = 0; i < Environment.ProcessorCount; i++) {
            Thread t = new Thread(delegate() {
                double x = 1.0001;
                Stopwatch sw = Stopwatch.StartNew();
                while (!stop && sw.Elapsed.TotalSeconds < seconds) {
                    for (int k = 0; k < 1000000; k++) { x = Math.Sqrt(x * 1.0000001 + Math.Sin(x)); }
                }
            });
            t.IsBackground = true;
            t.Start();
        }
    }
    public static void StopCpu() { stop = true; }
    // returns number of mismatched 64-bit words
    public static long RamTest(int totalMb) {
        int chunks = totalMb / 64;
        long[][] mem = new long[chunks][];
        int n = 0;
        try { for (; n < chunks; n++) mem[n] = new long[8 * 1024 * 1024]; }
        catch (OutOfMemoryException) { }
        AllocatedMb = n * 64L;
        long errors = 0;
        long[] pats = new long[] { unchecked((long)0xAAAAAAAAAAAAAAAAUL), 0x5555555555555555L, -1L, 0L };
        for (int p = 0; p <= pats.Length; p++) {
            for (int c = 0; c < n; c++) {
                long[] a = mem[c];
                for (int i = 0; i < a.Length; i++) a[i] = (p < pats.Length) ? pats[p] : ((long)c << 32) ^ i;
            }
            for (int c = 0; c < n; c++) {
                long[] a = mem[c];
                for (int i = 0; i < a.Length; i++) {
                    long want = (p < pats.Length) ? pats[p] : ((long)c << 32) ^ i;
                    if (a[i] != want) errors++;
                }
            }
        }
        return errors;
    }
}
'@

# ---------------------------------------------------------------- 1. identity
Section '1. SYSTEM IDENTITY'
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
Log ("Model:   {0} {1}" -f $cs.Manufacturer, $cs.Model)
Log ("Serial:  {0}   (check warranty/ownership on maker's site)" -f $bios.SerialNumber)
Log ("BIOS:    {0} {1} ({2:yyyy-MM-dd})" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)
Log ("OS:      {0} build {1}, installed {2:yyyy-MM-dd}" -f $os.Caption, $os.BuildNumber, $os.InstallDate)

$dsreg = (dsregcmd /status) -join "`n"
if ($cs.PartOfDomain) { Verdict 'FAIL' 'Domain joined' "Joined to $($cs.Domain) - corporate laptop, ask seller to remove" }
elseif ($dsreg -match 'AzureAdJoined\s*:\s*YES') { Verdict 'FAIL' 'Entra/Azure AD joined' 'Org-managed, may be remotely lockable/wipeable' }
elseif ($dsreg -match 'MdmUrl\s*:\s*\S+') { Verdict 'WARN' 'MDM enrollment' 'Device management URL present - check Settings > Accounts > Access work or school' }
else { Verdict 'PASS' 'Not org-managed' 'No domain/Entra/MDM signs' }

$lic = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.Name -like 'Windows*' -and $_.PartialProductKey } | Select-Object -First 1
if ($lic.LicenseStatus -eq 1) { Verdict 'PASS' 'Windows activation' 'Licensed' } else { Verdict 'WARN' 'Windows activation' 'Not activated' }

# ---------------------------------------------------------------- 2. security
Section '2. SECURITY STATE'
if (Confirm-SecureBootUEFI) { Verdict 'PASS' 'Secure Boot' 'On' } else { Verdict 'WARN' 'Secure Boot' 'Off/unsupported' }
$tpm = Get-Tpm
if ($tpm.TpmPresent -and $tpm.TpmReady) { Verdict 'PASS' 'TPM' 'Present and ready' } else { Verdict 'WARN' 'TPM' 'Missing or not ready' }
$bl = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq 'On' }
if ($bl) { Verdict 'WARN' 'BitLocker' "On for $($bl.MountPoint -join ',') - need recovery key if anything changes; get it from seller" } else { Verdict 'INFO' 'BitLocker' 'Off' }
$mp = Get-MpComputerStatus
if ($mp) { Verdict 'INFO' 'Defender' "RealTime=$($mp.RealTimeProtectionEnabled), signatures $($mp.AntivirusSignatureLastUpdated)" }
Log 'Tip: if seller left their data, factory-reset (Settings > Recovery > Reset this PC > Remove everything) before use.'

# ---------------------------------------------------------------- 3. battery
Section '3. BATTERY'
powercfg /batteryreport /output "$out\battery-report.html" | Out-Null
$design = (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).DesignedCapacity | Select-Object -First 1
$full = (Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity).FullChargedCapacity | Select-Object -First 1
$cycles = (Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount).CycleCount | Select-Object -First 1
if ($design -and $full) {
    $health = [math]::Round(100 * $full / $design, 1)
    $d = "Design $design mWh, now $full mWh = $health% health" + $(if ($cycles) { ", $cycles cycles" } else { '' })
    if ($health -ge 80) { Verdict 'PASS' 'Battery health' $d } elseif ($health -ge 60) { Verdict 'WARN' 'Battery health' $d } else { Verdict 'FAIL' 'Battery health' $d }
} else { Verdict 'INFO' 'Battery' 'No data (desktop, or firmware does not expose it). See battery-report.html' }
$bat = Get-CimInstance Win32_Battery
if ($bat) { Log ("Status: {0}, charge {1}%" -f $bat.Status, $bat.EstimatedChargeRemaining) }

# ---------------------------------------------------------------- 4. storage
Section '4. STORAGE'
foreach ($pd in Get-PhysicalDisk) {
    $rc = $pd | Get-StorageReliabilityCounter
    $d = '{0} {1} {2:N0}GB health={3} wear={4}% temp={5}C poweron={6}h readErr={7} writeErr={8}' -f `
        $pd.FriendlyName, $pd.MediaType, ($pd.Size / 1GB), $pd.HealthStatus, $rc.Wear, $rc.Temperature, $rc.PowerOnHours, $rc.ReadErrorsTotal, $rc.WriteErrorsTotal
    if ($pd.HealthStatus -ne 'Healthy' -or $rc.ReadErrorsUncorrected -or $rc.WriteErrorsUncorrected) { Verdict 'FAIL' "Disk $($pd.DeviceId)" $d }
    elseif ($rc.Wear -gt 70 -or $rc.Temperature -gt 70) { Verdict 'WARN' "Disk $($pd.DeviceId)" $d }
    else { Verdict 'PASS' "Disk $($pd.DeviceId)" $d }
}
foreach ($v in Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }) {
    $scan = Repair-Volume -DriveLetter $v.DriveLetter -Scan
    if ($scan -eq 'NoErrorsFound') { Verdict 'PASS' "Filesystem $($v.DriveLetter):" 'No errors' } else { Verdict 'FAIL' "Filesystem $($v.DriveLetter):" "chkdsk scan: $scan" }
}
$tmp = Join-Path $env:TEMP 'hc_speed.tmp'
$buf = New-Object byte[] (4MB)
(New-Object Random).NextBytes($buf)
$sw = [Diagnostics.Stopwatch]::StartNew()
$fs = New-Object IO.FileStream($tmp, 'Create', 'Write', 'None', 4MB, [IO.FileOptions]::WriteThrough)
1..256 | ForEach-Object { $fs.Write($buf, 0, $buf.Length) }
$fs.Close(); $sw.Stop()
Remove-Item $tmp -Force
$mbps = [math]::Round(1024 / $sw.Elapsed.TotalSeconds)
if ($mbps -lt 100) { Verdict 'WARN' 'Disk write speed' "$mbps MB/s (HDD-class or failing)" } else { Verdict 'PASS' 'Disk write speed' "$mbps MB/s" }

# ---------------------------------------------------------------- 5. RAM
Section '5. MEMORY'
$dimms = Get-CimInstance Win32_PhysicalMemory
foreach ($m in $dimms) { Log ("DIMM {0}: {1:N0}GB {2}MHz {3} {4}" -f $m.DeviceLocator, ($m.Capacity / 1GB), $m.Speed, $m.Manufacturer, $m.PartNumber) }
$freeMb = [int]($os.FreePhysicalMemory / 1024)
$testMb = [int]([math]::Min($freeMb * 0.6, 8192))
$testMb = $testMb - ($testMb % 64)
if ($testMb -ge 128) {
    Log "Pattern-testing $testMb MB (partial; full test = MemTest86 from USB)..."
    $errs = [HC]::RamTest($testMb)
    if ($errs -eq 0) { Verdict 'PASS' 'RAM quick test' "$([HC]::AllocatedMb) MB, 0 errors" } else { Verdict 'FAIL' 'RAM quick test' "$errs bad words in $([HC]::AllocatedMb) MB" }
} else { Verdict 'WARN' 'RAM quick test' 'Not enough free memory to test' }
Log 'For full coverage run MemTest86 overnight, or `mdsched.exe` (reboots).'

# ---------------------------------------------------------------- 6. CPU
Section '6. CPU & THERMALS'
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
Log ("{0}, {1} cores / {2} threads, max {3} MHz" -f $cpu.Name.Trim(), $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors, $cpu.MaxClockSpeed)
function Get-Temp {
    $t = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature
    if ($t) { ($t | ForEach-Object { ($_.CurrentTemperature / 10) - 273.15 } | Measure-Object -Maximum).Maximum }
}
if ($SkipStress) { Log 'Stress skipped.' } else {
    Log "Stress test $StressSeconds s on all threads. Listen for fan; feel for hot spots."
    $idleTemp = Get-Temp
    [HC]::StartCpu($StressSeconds)
    $temps = @(); $clocks = @(); $loads = @()
    $end = (Get-Date).AddSeconds($StressSeconds)
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds 5
        $c = Get-CimInstance Win32_Processor | Select-Object -First 1
        $clocks += $c.CurrentClockSpeed; $loads += $c.LoadPercentage
        $t = Get-Temp; if ($t) { $temps += $t }
        Write-Host ("  load {0}%  clock {1} MHz  temp {2}" -f $c.LoadPercentage, $c.CurrentClockSpeed, $(if ($t) { '{0:N0}C' -f $t } else { 'n/a' }))
    }
    [HC]::StopCpu()
    $minClock = ($clocks | Measure-Object -Minimum).Minimum
    $maxTemp = if ($temps) { ($temps | Measure-Object -Maximum).Maximum } else { $null }
    if ($maxTemp) {
        $d = "Peak {0:N0}C (idle {1:N0}C)" -f $maxTemp, $idleTemp
        if ($maxTemp -ge 95) { Verdict 'FAIL' 'CPU temp under load' "$d - dried paste/clogged fan likely" } elseif ($maxTemp -ge 85) { Verdict 'WARN' 'CPU temp under load' $d } else { Verdict 'PASS' 'CPU temp under load' $d }
    } else { Verdict 'INFO' 'CPU temp' 'Not exposed to Windows; use HWiNFO64 sensors during stress' }
    if ($minClock -lt 0.5 * $cpu.MaxClockSpeed) { Verdict 'WARN' 'CPU throttling' "Min clock $minClock MHz vs max $($cpu.MaxClockSpeed) MHz" } else { Verdict 'PASS' 'CPU throttling' "Min clock $minClock MHz held" }
}

# ---------------------------------------------------------------- 7. GPU / display
Section '7. GPU & DISPLAY'
foreach ($g in Get-CimInstance Win32_VideoController) {
    $d = '{0} driver {1} ({2}) {3}x{4}' -f $g.Name, $g.DriverVersion, $g.DriverDate, $g.CurrentHorizontalResolution, $g.CurrentVerticalResolution
    if ($g.Status -eq 'OK') { Verdict 'PASS' 'GPU' $d } else { Verdict 'FAIL' 'GPU' "$d status=$($g.Status)" }
}
foreach ($m in Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID) {
    $name = -join ($m.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })
    Log "Monitor: $name"
}
Log 'MANUAL: open https://lcdtest.eu or monteon.com/dead-pixel-test, cycle full-screen colors for dead pixels/backlight bleed.'

# ---------------------------------------------------------------- 8. devices
Section '8. DEVICES & PERIPHERALS'
$bad = Get-PnpDevice -PresentOnly | Where-Object { $_.Status -notin 'OK', 'Unknown' }
if ($bad) { $bad | ForEach-Object { Verdict 'FAIL' 'Device problem' "$($_.FriendlyName) [$($_.Class)] status=$($_.Status)" } } else { Verdict 'PASS' 'Device Manager' 'No devices with errors' }
foreach ($cls in @(@('Camera', 'Camera/Image'), @('Bluetooth', 'Bluetooth'), @('AudioEndpoint', 'Audio in/out'), @('Net', 'Network'), @('Biometric', 'Fingerprint/IR'))) {
    $n = @(Get-PnpDevice -Class $cls[0] -PresentOnly -Status OK).Count
    if ($n) { Verdict 'PASS' $cls[1] "$n device(s)" } elseif ($cls[0] -eq 'Biometric') { Verdict 'INFO' $cls[1] 'None' } else { Verdict 'WARN' $cls[1] 'None detected' }
}
$wifi = netsh wlan show interfaces
if ($wifi -match 'State') { Verdict 'PASS' 'Wi-Fi radio' 'Present' } else { Verdict 'WARN' 'Wi-Fi radio' 'No WLAN interface' }
$ping = Test-Connection 1.1.1.1 -Count 10 -ErrorAction SilentlyContinue
if ($ping) { $loss = 10 - @($ping).Count; if ($loss -gt 1) { Verdict 'WARN' 'Network ping' "$loss/10 lost" } else { Verdict 'PASS' 'Network ping' "$loss/10 lost" } } else { Verdict 'INFO' 'Network ping' 'No connectivity (connect to Wi-Fi and rerun)' }

# ---------------------------------------------------------------- 9. event log
Section '9. EVENT LOG (last 30 days)'
$since = (Get-Date).AddDays(-30)
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $since }
$crit = @{
    'Disk errors'      = ($ev | Where-Object { $_.ProviderName -in 'disk', 'Ntfs', 'volmgr', 'stornvme', 'storahci' }).Count
    'Hardware (WHEA)'  = ($ev | Where-Object { $_.ProviderName -like '*WHEA*' }).Count
    'Unexpected power' = ($ev | Where-Object { $_.Id -eq 41 -and $_.ProviderName -like '*Kernel-Power*' }).Count
    'Bluescreens'      = ($ev | Where-Object { $_.Id -eq 1001 -and $_.ProviderName -like '*WER*' }).Count
}
foreach ($k in $crit.Keys) {
    $n = [int]$crit[$k]
    if ($n -eq 0) { Verdict 'PASS' $k '0' } elseif ($n -le 3) { Verdict 'WARN' $k "$n" } else { Verdict 'FAIL' $k "$n" }
}
$ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { Log ("  {0,4} x {1}" -f $_.Count, $_.Name) }
$dumps = @(Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue).Count
if ($dumps) { Verdict 'WARN' 'Crash dumps' "$dumps minidump(s) in C:\Windows\Minidump" }

# ---------------------------------------------------------------- 10. integrity
Section '10. WINDOWS INTEGRITY'
if ($SkipIntegrity) { Log 'Skipped.' } else {
    Log 'DISM scan (several minutes)...'
    $dism = (DISM /Online /Cleanup-Image /ScanHealth) -join "`n"
    if ($dism -match 'No component store corruption detected') { Verdict 'PASS' 'DISM component store' 'Clean' } else { Verdict 'WARN' 'DISM component store' 'Corruption or scan failure - see DISM log' }
    Log 'sfc /scannow (several minutes)...'
    $sfcFile = Join-Path $out 'sfc.txt'
    cmd /c "sfc /scannow > `"$sfcFile`""
    $sfc = (Get-Content $sfcFile -Encoding Unicode) -join ' '
    if ($sfc -match 'did not find any integrity violations') { Verdict 'PASS' 'SFC' 'No violations' }
    elseif ($sfc -match 'successfully repaired') { Verdict 'WARN' 'SFC' 'Found and repaired files' }
    else { Verdict 'WARN' 'SFC' 'Unrepaired problems or scan failed' }
}

# ---------------------------------------------------------------- 11. software
Section '11. INSTALLED SOFTWARE & STARTUP'
$apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
$apps | Export-Csv "$out\installed-software.csv" -NoTypeInformation
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Export-Csv "$out\startup-items.csv" -NoTypeInformation
Verdict 'INFO' 'Software' "$($apps.Count) programs listed in installed-software.csv; review for remote-access/stalkerware (AnyDesk, TeamViewer, RAT tools)"

# ---------------------------------------------------------------- summary
Section 'SUMMARY'
$script:Results | Export-Csv "$out\results.csv" -NoTypeInformation
$script:Results | Where-Object { $_.Status -in 'FAIL', 'WARN' } | ForEach-Object { Log ("[{0}] {1}: {2}" -f $_.Status, $_.Check, $_.Detail) }
$f = @($script:Results | Where-Object Status -eq 'FAIL').Count
$w = @($script:Results | Where-Object Status -eq 'WARN').Count
Log ''
Log "FAIL=$f WARN=$w PASS=$(@($script:Results | Where-Object Status -eq 'PASS').Count)"
Log ''
Log 'MANUAL CHECKLIST (script cannot do these):'
Log ' [ ] Every key (keyboard-test.space), trackpad + both buttons, fingerprint reader'
Log ' [ ] Speakers L/R, headphone jack, mic, webcam'
Log ' [ ] Every USB/HDMI/charger/SD port with a real device; charger holds a charge'
Log ' [ ] Hinge smooth, lid closes flat, no cracks, no screw damage, no bulge under trackpad'
Log ' [ ] Fans spin, no grinding; no BIOS/admin password (press F2/Del at boot)'
Log ' [ ] MemTest86 overnight for full RAM verification'
Log ' [ ] Serial number vs maker warranty page; ask for original charger/receipt'
Log ''
Log "Report folder: $out"
Start-Process explorer.exe $out
