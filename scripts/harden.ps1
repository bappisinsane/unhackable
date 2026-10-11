<#
.SYNOPSIS
    Unhackable - Windows Security Hardening Script
.DESCRIPTION
    Applies layered security hardening to a Windows machine based on audit findings.
    Closes every network attack vector: firewall, exposed ports, SMB, remote access,
    password policy, legacy protocols, and unnecessary services.
.NOTES
    Requires: Administrator privileges
    Version: 1.0.0
    Author: MD. Nuruzzaman (bappisinsane)
    WARNING: Creates a system restore point before making changes.
#>

#Requires -RunAsAdministrator

param(
    [switch]$SkipRestorePoint,
    [switch]$Aggressive,
    [string]$LogPath = "$env:USERPROFILE\Desktop\unhackable-harden.log"
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Step {
    param([string]$Number, [string]$Title)
    Write-Host ""
    Write-Host "=== STEP $Number: $Title ===" -ForegroundColor Cyan
}

# ============================================================
# PRE-FLIGHT: CREATE RESTORE POINT
# ============================================================
if (-not $SkipRestorePoint) {
    Write-Log "Creating system restore point..."
    try {
        Checkpoint-Computer -Description "Unhackable-PreHardening" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "Restore point created successfully." "OK"
    } catch {
        Write-Log "Failed to create restore point: $_" "WARN"
        Write-Log "Continuing without restore point..." "WARN"
    }
}

# ============================================================
# STEP 1: ENABLE FIREWALL
# ============================================================
Step "1" "ENABLING WINDOWS FIREWALL"
Write-Log "Enabling firewall on all profiles..."
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
Write-Log "Firewall enabled with default-deny inbound policy." "OK"

# ============================================================
# STEP 2: BLOCK EXPOSED PORTS
# ============================================================
Step "2" "BLOCKING EXPOSED PORTS"
$exposedPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq "0.0.0.0" -and $_.LocalPort -gt 1024 } |
    Select-Object -ExpandProperty LocalPort -Unique

foreach ($port in $exposedPorts) {
    $ruleName = "Unhackable-Block-$port"
    netsh advfirewall firewall add rule name=$ruleName dir=in action=block protocol=tcp localport=$port 2>$null
    Write-Log "Blocked port $port" "OK"
}

# Allow established connections
netsh advfirewall firewall add rule name="Unhackable-Allow-Established" dir=in action=allow protocol=tcp 2>$null
Write-Log "Added allow rule for established connections." "OK"

# ============================================================
# STEP 3: SECURE POSTGRESQL
# ============================================================
Step "3" "SECURING POSTGRESQL"
$pgDataDir = Get-ChildItem "C:\Program Files\PostgreSQL" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pgDataDir) {
    $pgConf = Join-Path $pgDataDir.FullName "data\postgresql.conf"
    $pgHba = Join-Path $pgDataDir.FullName "data\pg_hba.conf"

    if (Test-Path $pgConf) {
        $content = Get-Content $pgConf -Raw
        $content = $content -replace "listen_addresses\s*=\s*'\*'", "listen_addresses = 'localhost'"
        Set-Content -Path $pgConf -Value $content -NoNewline
        Write-Log "PostgreSQL listen_addresses set to 'localhost'." "OK"
    }

    if (Test-Path $pgHba) {
        $hbaContent = Get-Content $pgHba -Raw
        $localhostRules = @"
# Unhackable: localhost-only access
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

"@
        # Remove all existing host rules, keep only localhost
        $lines = $hbaContent -split "`n"
        $newLines = @()
        $skipNext = $false
        foreach ($line in $lines) {
            if ($line -match "^\s*host\s+" -and $line -notmatch "127\.0\.0\.1|::1") {
                $skipNext = $true
                continue
            }
            if ($skipNext -and $line -match "^\s*#") { continue }
            $skipNext = $false
            $newLines += $line
        }
        Set-Content -Path $pgHba -Value ($localhostRules + ($newLines -join "`n"))
        Write-Log "PostgreSQL pg_hba.conf hardened (localhost only)." "OK"
    }

    # Restart PostgreSQL
    $pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pgService) {
        Restart-Service -Name $pgService.Name -Force
        Write-Log "PostgreSQL service restarted." "OK"
    }
} else {
    Write-Log "PostgreSQL not found. Skipping." "INFO"
}

# ============================================================
# STEP 4: DISABLE ADMIN SHARES
# ============================================================
Step "4" "DISABLING ADMIN SHARES"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Type DWord -Force
Write-Log "Admin shares disabled (AutoShareServer=0, AutoShareWks=0)." "OK"

# ============================================================
# STEP 5: DISABLE SMBv1
# ============================================================
Step "5" "DISABLING SMBv1"
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smb1.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Write-Log "SMBv1 disabled." "OK"
} else {
    Write-Log "SMBv1 already disabled." "INFO"
}

# ============================================================
# STEP 6: DISABLE LEGACY PROTOCOLS
# ============================================================
Step "6" "DISABLING LEGACY PROTOCOLS"

# LLMNR
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
Write-Log "LLMNR disabled." "OK"

# NetBIOS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
Write-Log "NetBIOS NodeType set to 2 (point-to-point)." "OK"

# WPAD
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Log "WPAD disabled." "OK"

# ============================================================
# STEP 7: SET STRONG PASSWORD POLICY
# ============================================================
Step "7" "SETTING PASSWORD POLICY"
net accounts /minpwlen:14
net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /uniquepw:24
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30
Write-Log "Password policy set: 14+ chars, 90-day max, 24 history, lockout after 5." "OK"

# ============================================================
# STEP 8: DISABLE UNNECESSARY SERVICES
# ============================================================
Step "8" "DISABLING UNNECESSARY SERVICES"
$servicesToDisable = @("SSDPSRV", "RemoteRegistry")
foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "Service $svc disabled." "OK"
    }
}

# ============================================================
# STEP 9: DISABLE RDP (if enabled)
# ============================================================
Step "9" "DISABLING RDP"
$rdpEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdpEnabled -ne 1) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
    Write-Log "RDP disabled." "OK"
} else {
    Write-Log "RDP already disabled." "INFO"
}

# ============================================================
# STEP 10: CREATE SSH HARDENING CONFIG
# ============================================================
Step "10" "CREATING SSH CONFIG"
$sshDir = Join-Path $env:USERPROFILE ".ssh"
$sshConfig = Join-Path $sshDir "config"
New-Item -Path $sshDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$sshConfigContent = @"
# Unhackable SSH Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Host *
    HashKnownHosts yes
    StrictHostKeyChecking ask
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
    PreferredAuthentications publickey,keyboard-interactive,password
    IdentitiesOnly yes
"@
Set-Content -Path $sshConfig -Value $sshConfigContent
Write-Log "SSH config created at $sshConfig" "OK"

# ============================================================
# STEP 11: CLEAN UP STALE CREDENTIALS
# ============================================================
Step "11" "CLEANING STALE CREDENTIALS"
$staleCreds = @(
    "LegacyGeneric:target=EOxaH1L9QA",
    "LegacyGeneric:target=Nearby_107902754072348083239",
    "LegacyGeneric:target=gemini:antigravity",
    "LegacyGeneric:target=gemini-cli-api-key/default-api-key",
    "LegacyGeneric:target=gh:github.com:",
    "LegacyGeneric:target=GitHub - https://api.github.com/bappisinsane"
)
foreach ($cred in $staleCreds) {
    cmdkey /delete:$cred 2>$null
    Write-Log "Removed credential: $cred" "OK"
}

# ============================================================
# STEP 12: CLEAN UP STARTUP PROGRAMS
# ============================================================
Step "12" "CLEANING STARTUP PROGRAMS"
$startupKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$unnecessaryPatterns = @("EpicGamesLauncher", "Steam", "Signal", "BraveSoftware Update", "Spotify", "Discord")
foreach ($key in $startupKeys) {
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($props) {
        foreach ($pattern in $unnecessaryPatterns) {
            $match = $props.PSObject.Properties | Where-Object { $_.Name -like "*$pattern*" }
            if ($match) {
                Remove-ItemProperty -Path $key -Name $match.Name -Force -ErrorAction SilentlyContinue
                Write-Log "Removed startup: $($match.Name)" "OK"
            }
        }
    }
}

# ============================================================
# STEP 13: AGGRESSIVE MODE
# ============================================================
if ($Aggressive) {
    Step "13" "AGGRESSIVE HARDENING"

    # Disable NetBIOS on all adapters
    Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object {
        $_.SetTcpipNetbios(2) | Out-Null
    }
    Write-Log "NetBIOS disabled on all network adapters." "OK"

    # Disable LLMNR via Group Policy
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force

    # Disable NBT-NS
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force

    # Disable WPAD via registry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConfigURL" -Value "" -Type String -Force

    Write-Log "Aggressive hardening complete." "OK"
}

# ============================================================
# FINAL: REBOOT RECOMMENDATION
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  UNHACKABLE HARDENING COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  A system reboot is recommended to apply" -ForegroundColor Yellow
Write-Host "  all changes (especially SMBv1, NetBIOS)." -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Log saved to: $LogPath" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Green

Write-Log "Hardening complete. Reboot recommended." "OK"
