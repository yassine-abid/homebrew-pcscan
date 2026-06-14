<#
  pcscan.ps1 - portable defensive PC health, security & investigation scan (Windows)

  Read-only investigation of YOUR OWN PC: network, system hardening, persistence,
  browser extensions, malware (Microsoft Defender), forensic quick-look, and a
  baseline/diff to catch anything new since last time.

  Interactive:   pcscan                      (banner + menu)
  Direct flags:  pcscan -Full | -Quick | -Net | -System | -Persist
                        -Browser | -Malware | -Forensics
                        -Diff | -SaveBaseline | -Report

  Nothing here modifies the system. Run as Administrator for fuller results
  (system services, security event log, full Defender control) - not required.
#>
[CmdletBinding()]
param(
  [switch]$Full, [switch]$Quick, [switch]$Net, [switch]$System, [switch]$Persist,
  [switch]$Browser, [switch]$Malware, [switch]$Forensics,
  [switch]$Diff, [switch]$SaveBaseline, [switch]$Report
)
$ErrorActionPreference = 'SilentlyContinue'

$PcDir    = Join-Path $env:USERPROFILE 'pcscan'
$Baseline = Join-Path $PcDir 'baseline.txt'
$BadPattern = 'curl |wget |Invoke-WebRequest|IEX|Invoke-Expression|FromBase64String|DownloadString|-enc |/dev/tcp|nc -e'

# ---------- findings engine ----------
$script:Findings = New-Object System.Collections.ArrayList
function Reset-Findings { $script:Findings.Clear() | Out-Null }
function Crit($m){ [void]$script:Findings.Add(@{S='CRIT';M=$m}) }
function Warn($m){ [void]$script:Findings.Add(@{S='WARN';M=$m}) }
function Info($m){ [void]$script:Findings.Add(@{S='INFO';M=$m}) }

function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }
function L($t){ Write-Host "  $t" }
function Is-PrivateIp($ip){
  return ($ip -match '^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|fe80|fd)')
}
function Is-Admin {
  try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { return $false }
}

# =====================================================================
# BANNER
# =====================================================================
function Banner {
  $art = @'
   ████ ████ ████ ████ ████ █  █
   █  █ █    █    █    █  █ ██ █
   ████ █    ████ █    ████ █ ██
   █    █       █ █    █  █ █  █
   █    ████ ████ ████ █  █ █  █
'@
  Write-Host $art -ForegroundColor Magenta
  Write-Host "   defensive health · security · investigation" -ForegroundColor DarkGray
  $adm = if (Is-Admin) { 'admin' } else { 'user' }
  Write-Host ("   {0} · windows · {1} · {2}`n" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm'), $adm) -ForegroundColor Green
}

# =====================================================================
# 1. NETWORK
# =====================================================================
function Scan-Network {
  Section "Network: interfaces & gateway"
  Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } |
    ForEach-Object { L ("{0,-14} {1}" -f $_.InterfaceAlias, $_.IPAddress) }
  $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop | Select-Object -First 1
  if ($gw) { L "gateway: $gw" }

  Section "Network: DNS resolvers"
  $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -Unique
  foreach ($d in $dns) {
    L $d
    switch -Regex ($d) {
      '^45\.90\.(28|30)\.' { Info "DNS via NextDNS ($d) - filtering/privacy service. Fine if you set it up." }
      '^1\.(1\.1\.1|0\.0\.1)' { Info "DNS via Cloudflare ($d)." }
      '^8\.8\.(8\.8|4\.4)' { Info "DNS via Google ($d)." }
      '^9\.9\.9\.' { Info "DNS via Quad9 ($d)." }
      default { if ($d -ne $gw -and $d -ne '127.0.0.1') { Info "DNS resolver $d - confirm this is one you configured." } }
    }
  }

  Section "Network: hosts file overrides"
  $hosts = "$env:WINDIR\System32\drivers\etc\hosts"
  $extra = Get-Content $hosts | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s' }
  if ($extra) {
    $extra | ForEach-Object { L $_ }
    Warn "hosts file has custom redirects. Verify each line - attackers use this to redirect banking/update domains (ad-block lists are also common & benign)."
  } else { L "(none - default file)" }

  Section "Network: listening ports"
  $listen = Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique
  $extCount = 0
  foreach ($c in $listen) {
    $p = (Get-Process -Id $c.OwningProcess).ProcessName
    L ("{0,-22} {1}:{2}" -f $p, $c.LocalAddress, $c.LocalPort)
    if ($c.LocalAddress -in @('0.0.0.0','::')) { $extCount++ }
  }
  if ($extCount -gt 0) { Info "$extCount service(s) listen on all interfaces (reachable from the LAN). Investigate anything you don't recognize." }

  if (-not $script:QuickMode) {
    Section "Network: LAN neighbors"
    Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -in @('Reachable','Stale') } |
      ForEach-Object { L ("{0,-16} {1}" -f $_.IPAddress, $_.LinkLayerAddress) }

    Section "Network: established outbound connections"
    $conns = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' }
    $unusual = 0
    foreach ($c in $conns | Select-Object -First 40) {
      $p = (Get-Process -Id $c.OwningProcess).ProcessName
      L ("{0,-18} {1}:{2}" -f $p, $c.RemoteAddress, $c.RemotePort)
      if (($c.RemotePort -notin 80,443,53) -and -not (Is-PrivateIp $c.RemoteAddress)) { $unusual++ }
    }
    if ($unusual -gt 0) { Warn "$unusual connection(s) to public IPs on non-web ports. Usually fine (games, sync, VPN) but a known place C2/malware hides - check the process if unfamiliar." }
  }

  Section "Network: proxy configuration"
  $pr = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  if ($pr.ProxyEnable -eq 1) {
    L "Proxy: $($pr.ProxyServer)"
    Warn "A system proxy is ACTIVE. If you didn't set this, it can intercept your traffic (MITM). Verify it."
  } else { L "(no proxy set)" }
}

# =====================================================================
# 2. SYSTEM HARDENING
# =====================================================================
function Scan-System {
  Section "System: security protections"
  $fw = Get-NetFirewallProfile
  foreach ($p in $fw) {
    if ($p.Enabled) { Write-Host ("  Firewall ({0}): " -f $p.Name) -NoNewline; Write-Host "ON" -ForegroundColor Green }
    else { Write-Host ("  Firewall ({0}): " -f $p.Name) -NoNewline; Write-Host "OFF" -ForegroundColor Red; Warn "Firewall profile '$($p.Name)' is OFF." }
  }
  $mp = Get-MpComputerStatus
  if ($mp) {
    if ($mp.RealTimeProtectionEnabled) { Write-Host "  Defender real-time: " -NoNewline; Write-Host "ON" -ForegroundColor Green }
    else { Write-Host "  Defender real-time: " -NoNewline; Write-Host "OFF" -ForegroundColor Red; Crit "Microsoft Defender real-time protection is OFF." }
    L "  Defender signatures: $($mp.AntivirusSignatureVersion) (updated $($mp.AntivirusSignatureLastUpdated))"
  }
  $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
  if ($uac -eq 1) { Write-Host "  UAC: " -NoNewline; Write-Host "enabled" -ForegroundColor Green } else { Write-Host "  UAC: " -NoNewline; Write-Host "DISABLED" -ForegroundColor Red; Warn "User Account Control is disabled." }
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
  if ($bl -and $bl.ProtectionStatus -eq 'On') { Write-Host "  BitLocker ($env:SystemDrive): " -NoNewline; Write-Host "on" -ForegroundColor Green }
  else { Write-Host "  BitLocker ($env:SystemDrive): " -NoNewline; Write-Host "off" -ForegroundColor Yellow; Warn "BitLocker disk encryption is OFF on the system drive." }
}

# =====================================================================
# 3. PERSISTENCE
# =====================================================================
function Scan-Persistence {
  Section "Persistence: Run keys (registry autostart)"
  $keys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
  )
  foreach ($k in $keys) {
    $vals = Get-ItemProperty $k
    if ($vals) {
      $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        L ("{0}  ->  {1}" -f $_.Name, $_.Value)
        if ($_.Value -match $BadPattern) { Crit "Run key '$($_.Name)' contains a downloader/exec pattern - inspect it." }
      }
    }
  }
  Section "Persistence: Startup folders"
  foreach ($d in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                   "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")) {
    Get-ChildItem $d -ErrorAction SilentlyContinue | ForEach-Object { L $_.Name }
  }
  Section "Persistence: Scheduled tasks (non-Microsoft)"
  Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } |
    ForEach-Object { L ("{0}{1}" -f $_.TaskPath, $_.TaskName) }
  Info "Review the autostart entries above - persistence is the #1 place malware hides."
}

# =====================================================================
# 4. BROWSERS
# =====================================================================
function Scan-Browsers {
  Section "Browsers: installed extensions"
  # Firefox / Zen (XPI files)
  foreach ($b in @(@{P="$env:APPDATA\Mozilla\Firefox\Profiles";N='Firefox'},
                   @{P="$env:APPDATA\zen\Profiles";N='Zen'})) {
    if (Test-Path $b.P) {
      Get-ChildItem $b.P -Directory | ForEach-Object {
        $ext = Join-Path $_.FullName 'extensions'
        if (Test-Path $ext) {
          $xpis = Get-ChildItem $ext -Filter *.xpi
          L ("{0} [{1}]: {2} extension(s)" -f $b.N, $_.Name, $xpis.Count)
          $xpis | ForEach-Object { L ("  - " + ($_.BaseName)) }
        }
      }
    }
  }
  # Chromium family (extension IDs as folder names)
  foreach ($b in @(@{P="$env:LOCALAPPDATA\Google\Chrome\User Data";N='Chrome'},
                   @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data";N='Edge'},
                   @{P="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";N='Brave'})) {
    if (Test-Path $b.P) {
      Get-ChildItem $b.P -Directory | ForEach-Object {
        $ext = Join-Path $_.FullName 'Extensions'
        if (Test-Path $ext) { Get-ChildItem $ext -Directory | ForEach-Object { L ("{0}: {1}" -f $b.N, $_.Name) } }
      }
    }
  }
  Info "Cross-check every extension against the official store. Unknown/sideloaded extensions are a top vector for data theft & ad injection."
}

# =====================================================================
# 5. MALWARE (Microsoft Defender)
# =====================================================================
function Scan-Malware {
  Section "Malware: Microsoft Defender status"
  $mp = Get-MpComputerStatus
  if ($mp) {
    L "Antivirus enabled:   $($mp.AntivirusEnabled)"
    L "Real-time enabled:   $($mp.RealTimeProtectionEnabled)"
    L "Signature version:   $($mp.AntivirusSignatureVersion)  (updated $($mp.AntivirusSignatureLastUpdated))"
    L "Last quick scan:     $($mp.QuickScanEndTime)"
  } else { Warn "Could not read Defender status." }

  Section "Malware: recent threat detections"
  $threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
  if ($threats) {
    foreach ($t in $threats) {
      $name = (Get-MpThreat | Where-Object { $_.ThreatID -eq $t.ThreatID }).ThreatName
      L ("{0}  {1}  {2}" -f $t.InitialDetectionTime, $name, ($t.Resources -join ','))
    }
    Crit "Defender has logged threat detections (above). Confirm each was remediated (Get-MpThreat)."
  } else { L "(no threat history - clean)" }

  Section "Malware: executables in temp folders"
  $found = 0
  foreach ($d in @($env:TEMP, "$env:WINDIR\Temp")) {
    Get-ChildItem $d -Recurse -Include *.exe,*.dll,*.scr,*.ps1,*.bat,*.vbs -Depth 2 -ErrorAction SilentlyContinue |
      Select-Object -First 15 | ForEach-Object { Write-Host "  exec: $($_.FullName)" -ForegroundColor Yellow; $found++ }
  }
  if ($found -gt 0) { Info "$found executable/script file(s) in temp folders. Installers use these too, but malware loves them - verify unfamiliar ones." } else { L "(none)" }

  if ($script:Deep) {
    Section "Malware: Defender quick scan"
    L "Running Defender quick scan (this can take a few minutes)..."
    Start-MpScan -ScanType QuickScan
    L "Quick scan complete. Re-checking threat history:"
    $after = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5
    if ($after) { $after | ForEach-Object { Write-Host "  $($_.InitialDetectionTime) threat detected" -ForegroundColor Red }; Crit "Quick scan found threats - run Get-MpThreat for detail." }
    else { Write-Host "  No threats found." -ForegroundColor Green }
  }
}

# =====================================================================
# 6. FORENSIC QUICK-LOOK
# =====================================================================
function Scan-Forensics {
  Section "Forensics: files modified in sensitive dirs (last 3 days)"
  $since = (Get-Date).AddDays(-3)
  $dirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:TEMP", "$env:USERPROFILE\Downloads")
  $cnt = 0
  foreach ($d in $dirs) {
    Get-ChildItem $d -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since } |
      Select-Object -First 15 | ForEach-Object { L $_.FullName; $cnt++ }
  }
  if ($cnt -eq 0) { L "(nothing changed recently)" }

  Section "Forensics: processes running from temp/user paths"
  $bad = 0
  Get-Process | Where-Object { $_.Path } | ForEach-Object {
    if ($_.Path -match '\\Temp\\|\\AppData\\Local\\Temp|\\Downloads\\|\\Public\\') {
      Write-Host "  PID $($_.Id)  $($_.Path)" -ForegroundColor Red; $bad++
    }
  }
  if ($bad -gt 0) { Crit "$bad process(es) running from temp/Downloads/Public. Legit software rarely does this - investigate." } else { L "(none)" }

  Section "Forensics: local users & administrators"
  L ("users: " + ((Get-LocalUser | Where-Object Enabled | Select-Object -ExpandProperty Name) -join ', '))
  L ("admins: " + ((Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name) -join ', '))

  Section "Forensics: recent successful logons (event 4624)"
  if (Is-Admin) {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 6 -ErrorAction SilentlyContinue |
      ForEach-Object { L ("{0}  {1}" -f $_.TimeCreated, ($_.Properties[5].Value)) }
    $fail = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count
    if ($fail -gt 0) { Warn "$fail failed logon attempts (event 4625) in the last 24h - possible brute force." }
  } else { L "(run as Administrator to read the security log)" }
  Info "Forensic quick-look complete. None of these alone proves compromise - they're leads. Cross-check anything flagged."
}

# =====================================================================
# SNAPSHOT / DIFF
# =====================================================================
function Snapshot {
  $lines = New-Object System.Collections.ArrayList
  (Get-DnsClientServerAddress -AddressFamily IPv4 | Select -ExpandProperty ServerAddresses -Unique) | ForEach-Object { [void]$lines.Add("DNS $_") }
  Get-Content "$env:WINDIR\System32\drivers\etc\hosts" | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s' } | ForEach-Object { [void]$lines.Add("HOSTS $_") }
  Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object { [void]$lines.Add("PORT $((Get-Process -Id $_.OwningProcess).ProcessName) $($_.LocalAddress):$($_.LocalPort)") }
  foreach ($k in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    $v = Get-ItemProperty $k; if ($v) { $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [void]$lines.Add("RUNKEY $($_.Name)") } }
  }
  Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | ForEach-Object { [void]$lines.Add("TASK $($_.TaskPath)$($_.TaskName)") }
  foreach ($b in @(@{P="$env:APPDATA\Mozilla\Firefox\Profiles";N='Firefox'},@{P="$env:APPDATA\zen\Profiles";N='Zen'})) {
    if (Test-Path $b.P) { Get-ChildItem $b.P -Directory | ForEach-Object { $e=Join-Path $_.FullName 'extensions'; if (Test-Path $e) { Get-ChildItem $e -Filter *.xpi | ForEach-Object { [void]$lines.Add("EXT $($_.Name)") } } } }
  }
  $lines | Sort-Object -Unique
}
function Save-Baseline {
  New-Item -ItemType Directory -Force -Path $PcDir | Out-Null
  Snapshot | Set-Content $Baseline
  Write-Host "Baseline saved: $Baseline ($((Get-Content $Baseline).Count) lines)" -ForegroundColor Green
}
function Run-Diff {
  New-Item -ItemType Directory -Force -Path $PcDir | Out-Null
  if (-not (Test-Path $Baseline)) { Save-Baseline; Write-Host "No baseline existed - created one now. Run -Diff again later." -ForegroundColor Yellow; return }
  $when = (Get-Item $Baseline).LastWriteTime
  $old = Get-Content $Baseline
  $cur = Snapshot
  Section "Diff vs baseline (taken $when)"
  $added   = Compare-Object $old $cur | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject
  $removed = Compare-Object $old $cur | Where-Object SideIndicator -eq '<=' | Select-Object -ExpandProperty InputObject
  if (-not $added -and -not $removed) { Write-Host "  No changes since baseline." -ForegroundColor Green }
  else {
    $added   | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }
    $removed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Info "NEW (+) items are the priority - a new port, extension, or autostart you didn't add is the strongest signal something changed."
  }
}

# =====================================================================
# SUMMARY
# =====================================================================
function Print-Summary {
  $nc = ($script:Findings | Where-Object S -eq 'CRIT').Count
  $nw = ($script:Findings | Where-Object S -eq 'WARN').Count
  $ni = ($script:Findings | Where-Object S -eq 'INFO').Count
  Write-Host "`n== Findings summary ==" -ForegroundColor Cyan
  Write-Host ("  {0} critical  {1} warnings  {2} info`n" -f $nc,$nw,$ni)
  foreach ($sev in 'CRIT','WARN','INFO') {
    $col = @{CRIT='Red';WARN='Yellow';INFO='DarkGray'}[$sev]
    $script:Findings | Where-Object S -eq $sev | ForEach-Object { Write-Host ("  [{0}] {1}" -f $sev.ToLower(),$_.M) -ForegroundColor $col }
  }
  Write-Host ""
  if ($nc -gt 0) { Write-Host "Result: review the CRITICAL items above." -ForegroundColor Red }
  elseif ($nw -gt 0) { Write-Host "Result: no critical issues; check the warnings." -ForegroundColor Yellow }
  else { Write-Host "Result: clean - no critical or warning findings." -ForegroundColor Green }
}

# ---------- run helpers ----------
function Run-Full    { $script:QuickMode=$false; Reset-Findings; Scan-Network; Scan-System; Scan-Persistence; Scan-Browsers; Scan-Malware; Scan-Forensics; Print-Summary }
function Run-Quick   { $script:QuickMode=$true;  Reset-Findings; Scan-Network; Scan-System; Scan-Persistence; Scan-Browsers; Scan-Malware; Print-Summary }
function Run-Section($fn){ Reset-Findings; & $fn; Print-Summary }
function Run-Report  {
  New-Item -ItemType Directory -Force -Path $PcDir | Out-Null
  $f = Join-Path $PcDir ("report-{0}.txt" -f (Get-Date -Format 'yyyy-MM-dd_HHmm'))
  Run-Full *>&1 | Out-File $f
  Write-Host "Report saved: $f" -ForegroundColor Green
}

# =====================================================================
# MENU
# =====================================================================
function Menu {
  while ($true) {
    Clear-Host; Banner
    Write-Host "  MENU" -ForegroundColor Cyan
    Write-Host "    [1] Full scan            (everything + forensics)"
    Write-Host "    [2] Quick scan           (skips LAN + deep forensics)"
    Write-Host "    [3] Network              (interfaces, DNS, hosts, ports, C2 check)"
    Write-Host "    [4] System hardening     (firewall, Defender, UAC, BitLocker)"
    Write-Host "    [5] Persistence          (Run keys, startup, scheduled tasks)"
    Write-Host "    [6] Browser extensions   (Firefox, Zen, Chrome, Edge, Brave)"
    Write-Host "    [7] Malware / virus scan (Defender status + quick scan)" -ForegroundColor Magenta
    Write-Host "    [8] Forensic quick-look  (recent files, rogue procs, users, logons)" -ForegroundColor Magenta
    Write-Host "    [9] Diff vs baseline     (what changed since last baseline)" -ForegroundColor Blue
    Write-Host "    [s] Save / update baseline" -ForegroundColor Blue
    Write-Host "    [r] Save full report to file" -ForegroundColor Blue
    Write-Host "    [0] Exit`n" -ForegroundColor Red
    $c = Read-Host "  Choose"
    Write-Host ""
    switch ($c) {
      '1' { Run-Full }
      '2' { Run-Quick }
      '3' { Run-Section Scan-Network }
      '4' { Run-Section Scan-System }
      '5' { Run-Section Scan-Persistence }
      '6' { Run-Section Scan-Browsers }
      '7' { $script:Deep=$true; Run-Section Scan-Malware; $script:Deep=$false }
      '8' { Run-Section Scan-Forensics }
      '9' { Run-Diff; Print-Summary }
      's' { Save-Baseline }
      'r' { Run-Report }
      '0' { Write-Host "bye." -ForegroundColor DarkGray; return }
      default { Write-Host "  invalid choice" -ForegroundColor Red }
    }
    Read-Host "`n  press Enter to return to the menu" | Out-Null
  }
}

# =====================================================================
# DISPATCH
# =====================================================================
$script:QuickMode = $false; $script:Deep = $false
if     ($Full)         { Banner; Run-Full }
elseif ($Quick)        { Banner; Run-Quick }
elseif ($Net)          { Banner; Run-Section Scan-Network }
elseif ($System)       { Banner; Run-Section Scan-System }
elseif ($Persist)      { Banner; Run-Section Scan-Persistence }
elseif ($Browser)      { Banner; Run-Section Scan-Browsers }
elseif ($Malware)      { Banner; $script:Deep=$true; Run-Section Scan-Malware }
elseif ($Forensics)    { Banner; Run-Section Scan-Forensics }
elseif ($Diff)         { Banner; Run-Diff; Print-Summary }
elseif ($SaveBaseline) { Save-Baseline }
elseif ($Report)       { Run-Report }
else                   { Menu }
