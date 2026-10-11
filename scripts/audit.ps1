<#
.SYNOPSIS
    Unhackable - Windows Security Audit Script
.DESCRIPTION
    Comprehensive security audit for Windows machines. Identifies exposed services,
    open ports, weak configurations, and misconfigurations across all major attack vectors.
    Outputs a structured JSON report.
.NOTES
    Requires: Administrator privileges
    Version: 1.0.0
    Author: MD. Nuruzzaman (bappisinsane)
#>

#Requires -RunAsAdministrator

param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\unhackable-audit.json",
    [switch]$Quiet
)

$script:AuditResults = @{
    Timestamp   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    ComputerName = $env:COMPUTERNAME
    OS          = (Get-WmiObject Win32_OperatingSystem).Caption
    Findings    = @()
    Summary     = @{
        Critical = 0
        High     = 0
        Medium   = 0
        Low      = 0
        Info     = 0
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [string]$Severity,
        [string]$Remediation,
        [string]$CurrentValue = "",
        [string]$ExpectedValue = ""
    )

    $script:AuditResults.Findings += [PSCustomObject]@{
        Category      = $Category
        Title         = $Title
        Description   = $Description
        Severity      = $Severity
        Remediation   = $Remediation
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
    }

    switch ($Severity) {
        "Critical" { $script:AuditResults.Summary.Critical++ }
        "High"     { $script:AuditResults.Summary.High++ }
        "Medium"   { $script:AuditResults.Summary.Medium++ }
        "Low"      { $script:AuditResults.Summary.Low++ }
        "Info"     { $script:AuditResults.Summary.Info++ }
    }
}

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    if (-not $Quiet) {
        $color = switch ($Status) {
            "OK"      { "Green" }
            "WARN"    { "Yellow" }
            "FAIL"    { "Red" }
            "INFO"    { "Cyan" }
            default   { "White" }
        }
        Write-Host "[$Status] $Message" -ForegroundColor $color
    }
}

# ============================================================
# 1. FIREWALL STATUS
# ============================================================
Write-Status "Checking firewall status..."
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $fwProfiles) {
    if ($profile.Enabled -eq $false) {
        Add-Finding -Category "Firewall" -Title "Firewall Disabled: $($profile.Name)" `
            -Description "The $($profile.Name) firewall profile is disabled. All inbound traffic is unfiltered." `
            -Severity "Critical" `
            -Remediation "Enable firewall: netsh advfirewall set allprofiles state on" `
            -CurrentValue "Disabled" -ExpectedValue "Enabled"
        Write-Status "Firewall $($profile.Name): DISABLED" "FAIL"
    } else {
        Write-Status "Firewall $($profile.Name): Enabled" "OK"
    }
}

# ============================================================
# 2. OPEN PORTS INVENTORY
# ============================================================
Write-Status "Scanning open ports..."
$listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" }

$excludedPorts = @(135, 445, 139)  # Windows core - checked separately
foreach ($port in $listeningPorts) {
    if ($excludedPorts -contains $port.LocalPort) { continue }

    $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
    $procName = if ($process) { $process.ProcessName } else { "Unknown" }

    # Flag non-essential services on all interfaces
    $essentialPorts = @(3389, 5985, 5986)  # RDP, WinRM (should be disabled but known)
    if ($port.LocalPort -notin $essentialPorts -and $port.LocalPort -gt 1024) {
        Add-Finding -Category "Network" -Title "Exposed Port: $($port.LocalPort)" `
            -Description "Port $($port.LocalPort) ($($procName)) is listening on all interfaces (0.0.0.0). Accessible from any network." `
            -Severity "High" `
            -Remediation "Block inbound: netsh advfirewall firewall add rule name='Block-$($port.LocalPort)' dir=in action=block protocol=tcp localport=$($port.LocalPort)" `
            -CurrentValue "0.0.0.0:$($port.LocalPort)" -ExpectedValue "127.0.0.1:$($port.LocalPort) or blocked"
        Write-Status "Port $($port.LocalPort) ($procName): EXPOSED" "WARN"
    }
}

# ============================================================
# 3. DATABASE SERVICES
# ============================================================
Write-Status "Checking database services..."
$dbPorts = @{
    5432  = "PostgreSQL"
    3306  = "MySQL"
    1433  = "MSSQL"
    27017 = "MongoDB"
    6379  = "Redis"
    9200  = "Elasticsearch"
}

foreach ($port in $dbPorts.Keys) {
    $conn = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } |
        Select-Object -First 1

    if ($conn) {
        $dbName = $dbPorts[$port]
        Add-Finding -Category "Database" -Title "$dbName Exposed on Port $port" `
            -Description "$dbName is listening on all interfaces. Unauthorized access or brute-force attacks are possible." `
            -Severity "Critical" `
            -Remediation "Bind to localhost: Edit config to set bind address to 127.0.0.1, or block port $port via firewall" `
            -CurrentValue "0.0.0.0:$port" -ExpectedValue "127.0.0.1:$port"
        Write-Status "$dbName on port $port: EXPOSED" "FAIL"
    }
}

# ============================================================
# 4. SMB AND NETWORK SHARING
# ============================================================
Write-Status "Checking SMB and network sharing..."
$smbShares = Get-SmbShare -ErrorAction SilentlyContinue
$adminShares = $smbShares | Where-Object { $_.Name -match '\$' -or $_.Name -eq "IPC$" }

if ($adminShares) {
    $shareNames = ($adminShares | ForEach-Object { $_.Name }) -join ", "
    Add-Finding -Category "SMB" -Title "Admin Shares Exposed" `
        -Description "Default admin shares are accessible: $shareNames. These allow remote access to drives and pipes." `
        -Severity "Critical" `
        -Remediation "Disable admin shares: reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v AutoShareServer /t REG_DWORD /d 0 /f" `
        -CurrentValue $shareNames -ExpectedValue "No admin shares"
    Write-Status "Admin shares: $shareNames" "FAIL"
} else {
    Write-Status "No admin shares found" "OK"
}

# SMB protocol version
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smb1.State -eq "Enabled") {
    Add-Finding -Category "SMB" -Title "SMBv1 Protocol Enabled" `
        -Description "SMBv1 is enabled. This legacy protocol has critical vulnerabilities (EternalBlue, WannaCry)." `
        -Severity "Critical" `
        -Remediation "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
        -CurrentValue "Enabled" -ExpectedValue "Disabled"
    Write-Status "SMBv1: ENABLED" "FAIL"
}

# ============================================================
# 5. REMOTE ACCESS SERVICES
# ============================================================
Write-Status "Checking remote access services..."
$rdpEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdpEnabled -ne 1) {
    Add-Finding -Category "RemoteAccess" -Title "RDP Enabled" `
        -Description "Remote Desktop Protocol is enabled. Exposes the machine to brute-force and credential stuffing attacks." `
        -Severity "Critical" `
        -Remediation "Disable RDP: reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f" `
        -CurrentValue "Enabled" -ExpectedValue "Disabled"
    Write-Status "RDP: ENABLED" "FAIL"
} else {
    Write-Status "RDP: Disabled" "OK"
}

$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm.Status -eq "Running") {
    Add-Finding -Category "RemoteAccess" -Title "WinRM Running" `
        -Description "Windows Remote Management is running. Allows remote command execution via PowerShell remoting." `
        -Severity "High" `
        -Remediation "Stop and disable WinRM: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled" `
        -CurrentValue "Running" -ExpectedValue "Stopped/Disabled"
    Write-Status "WinRM: RUNNING" "FAIL"
}

# ============================================================
# 6. PASSWORD POLICY
# ============================================================
Write-Status "Checking password policy..."
$pwPolicy = net accounts
$minPwLen = [int](($pwPolicy | Select-String "Minimum password length").ToString().Split(":")[1].Trim())
$maxPwAge = [int](($pwPolicy | Select-String "Maximum password age").ToString().Split(":")[1].Trim().Split(" ")[0])
$lockoutThreshold = [int](($pwPolicy | Select-String "Lockout threshold").ToString().Split(":")[1].Trim())

if ($minPwLen -lt 14) {
    Add-Finding -Category "Authentication" -Title "Weak Password Policy" `
        -Description "Minimum password length is $minPwLen. NIST recommends 14+ characters for high-security environments." `
        -Severity "High" `
        -Remediation "Set strong policy: net accounts /minpwlen:14 /maxpwage:90 /lockoutthreshold:5" `
        -CurrentValue "Min length: $minPwLen" -ExpectedValue "Min length: 14+"
    Write-Status "Password policy: WEAK (min=$minPwLen)" "WARN"
} else {
    Write-Status "Password policy: Strong (min=$minPwLen)" "OK"
}

if ($lockoutThreshold -gt 5 -or $lockoutThreshold -eq 0) {
    Add-Finding -Category "Authentication" -Title "No Account Lockout" `
        -Description "Account lockout threshold is $lockoutThreshold. Brute-force attacks are not mitigated." `
        -Severity "High" `
        -Remediation "Set lockout: net accounts /lockoutthreshold:5 /lockoutduration:30" `
        -CurrentValue "Threshold: $lockoutThreshold" -ExpectedValue "Threshold: 5"
    Write-Status "Account lockout: DISABLED" "WARN"
}

# ============================================================
# 7. PROTOCOL HARDENING
# ============================================================
Write-Status "Checking protocol hardening..."

# LLMNR
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($llmnr.EnableMulticast -ne 0) {
    Add-Finding -Category "Protocol" -Title "LLMNR Enabled" `
        -Description "Link-Local Multicast Name Resolution is enabled. Vulnerable to NBT-NS poisoning and credential relay attacks." `
        -Severity "Medium" `
        -Remediation "Disable LLMNR: reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v EnableMulticast /t REG_DWORD /d 0 /f" `
        -CurrentValue "Enabled" -ExpectedValue "Disabled"
    Write-Status "LLMNR: ENABLED" "WARN"
} else {
    Write-Status "LLMNR: Disabled" "OK"
}

# NetBIOS
$netbios = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -ErrorAction SilentlyContinue
if ($netbios.NodeType -ne 2) {
    Add-Finding -Category "Protocol" -Title "NetBIOS Broadcasts Enabled" `
        -Description "NetBIOS NodeType is $($netbios.NodeType). Broadcast-based name resolution exposes the machine to network discovery." `
        -Severity "Medium" `
        -Remediation "Set NodeType to 2: reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' /v NodeType /t REG_DWORD /d 2 /f" `
        -CurrentValue "NodeType: $($netbios.NodeType)" -ExpectedValue "NodeType: 2"
    Write-Status "NetBIOS: Broadcasts enabled" "WARN"
}

# WPAD
$wpad = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue
if ($wpad.WpadOverride -ne 1) {
    Add-Finding -Category "Protocol" -Title "WPAD Not Disabled" `
        -Description "Web Proxy Auto-Discovery is not explicitly disabled. Vulnerable to proxy hijacking and MITM attacks." `
        -Severity "Medium" `
        -Remediation "Disable WPAD: reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' /v WpadOverride /t REG_DWORD /d 1 /f" `
        -CurrentValue "Not disabled" -ExpectedValue "Disabled"
    Write-Status "WPAD: Not disabled" "WARN"
}

# ============================================================
# 8. ANTIVIRUS STATUS
# ============================================================
Write-Status "Checking antivirus status..."
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    if (-not $defender.AntivirusEnabled) {
        Add-Finding -Category "Antivirus" -Title "Windows Defender Disabled" `
            -Description "Windows Defender real-time protection is disabled. The machine has no active malware scanning." `
            -Severity "Critical" `
            -Remediation "Enable Defender: Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -CurrentValue "Disabled" -ExpectedValue "Enabled"
        Write-Status "Defender: DISABLED" "FAIL"
    } else {
        Write-Status "Defender: Enabled" "OK"
    }

    if (-not $defender.RealTimeProtectionEnabled) {
        Add-Finding -Category "Antivirus" -Title "Real-Time Protection Off" `
            -Description "Real-time protection is disabled. Malware is not scanned on access." `
            -Severity "Critical" `
            -Remediation "Enable: Set-MpPreference -DisableRealtimeMonitoring `$false" `
            -CurrentValue "Off" -ExpectedValue "On"
        Write-Status "Real-time protection: OFF" "FAIL"
    }
}

# ============================================================
# 9. USER ACCOUNTS
# ============================================================
Write-Status "Checking user accounts..."
$users = Get-LocalUser -ErrorAction SilentlyContinue
$adminUsers = $users | Where-Object { $_.Enabled -and $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }
foreach ($user in $adminUsers) {
    $isAdmin = (Get-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction SilentlyContinue)
    if ($isAdmin -and $user.Name -ne $env:USERNAME) {
        Add-Finding -Category "Accounts" -Title "Additional Admin User: $($user.Name)" `
            -Description "User $($user.Name) has administrative privileges. Increases attack surface." `
            -Severity "Medium" `
            -Remediation "Review if needed: net localgroup administrators $($user.Name) /delete" `
            -CurrentValue "Admin" -ExpectedValue "Standard user"
        Write-Status "Extra admin: $($user.Name)" "WARN"
    }
}

# ============================================================
# 10. CREDENTIAL MANAGER
# ============================================================
Write-Status "Checking stored credentials..."
$creds = cmdkey /list 2>$null
$stalePatterns = @("Nearby_", "gemini:antigravity", "EOxaH1L9QA")
foreach ($pattern in $stalePatterns) {
    if ($creds -match $pattern) {
        Add-Finding -Category "Credentials" -Title "Stale Credential: $pattern" `
            -Description "A potentially stale or unnecessary credential is stored in Windows Credential Manager." `
            -Severity "Low" `
            -Remediation "Remove: cmdkey /delete:$pattern" `
            -CurrentValue "Present" -ExpectedValue "Removed"
        Write-Status "Stale credential: $pattern" "WARN"
    }
}

# ============================================================
# 11. STARTUP PROGRAMS
# ============================================================
Write-Status "Checking startup programs..."
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
                Add-Finding -Category "Startup" -Title "Unnecessary Startup: $($match.Name)" `
                    -Description "$($match.Name) runs at startup. Increases boot time and attack surface." `
                    -Severity "Low" `
                    -Remediation "Remove: reg delete '$key' /v '$($match.Name)' /f" `
                    -CurrentValue "Present" -ExpectedValue "Removed"
                Write-Status "Startup: $($match.Name)" "INFO"
            }
        }
    }
}

# ============================================================
# 12. WINDOWS UPDATES
# ============================================================
Write-Status "Checking Windows updates..."
$lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$daysSince = (Get-Date) - $lastUpdate.InstalledOn
if ($daysSince.Days -gt 30) {
    Add-Finding -Category "Updates" -Title "Stale Windows Updates" `
        -Description "Last update was $($lastUpdate.InstalledOn.ToString('yyyy-MM-dd')) ($($daysSince.Days) days ago). Known vulnerabilities may be unpatched." `
        -Severity "Medium" `
        -Remediation "Run Windows Update: Start-Process 'ms-settings:windowsupdate'" `
        -CurrentValue "$($daysSince.Days) days ago" -ExpectedValue "< 30 days"
    Write-Status "Last update: $($daysSince.Days) days ago" "WARN"
} else {
    Write-Status "Last update: $($daysSince.Days) days ago" "OK"
}

# ============================================================
# OUTPUT
# ============================================================
$json = $script:AuditResults | ConvertTo-Json -Depth 10
$json | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  UNHACKABLE AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Critical: $($script:AuditResults.Summary.Critical)" -ForegroundColor Red
Write-Host "  High:     $($script:AuditResults.Summary.High)" -ForegroundColor Yellow
Write-Host "  Medium:   $($script:AuditResults.Summary.Medium)" -ForegroundColor DarkYellow
Write-Host "  Low:      $($script:AuditResults.Summary.Low)" -ForegroundColor Gray
Write-Host "  Info:     $($script:AuditResults.Summary.Info)" -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Report saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

return $script:AuditResults
