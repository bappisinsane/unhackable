# 🔒 Unhackable

**Windows Security Audit & Hardening — Because "it'll be fine" is not a security strategy.**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bappisinsane/unhackable)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-red.svg)](https://github.com/bappisinsane/unhackable)
[![Author](https://img.shields.io/badge/author-bappisinsane-purple.svg)](https://github.com/bappisinsane)

---

## What is Unhackable?

Unhackable is a **comprehensive Windows security audit and hardening toolkit** that identifies every way your machine is vulnerable to network attacks — then patches them all in one go.

Think of it as a digital locksmith. It checks every door, window, and ventilation shaft in your system, then welds them shut.

### What it finds:
- 🔥 Disabled firewalls
- 🔥 Exposed databases (PostgreSQL, MySQL, MongoDB, Redis)
- 🔥 Open ports listening on all interfaces
- 🔥 SMB admin shares & legacy protocols
- 🔥 Weak password policies
- 🔥 Unnecessary services & startup programs
- 🔥 Stale credentials in Credential Manager
- 🔥 Missing Windows updates

### What it fixes:
- ✅ Enables Windows Firewall with default-deny inbound
- ✅ Blocks all exposed ports
- ✅ Binds databases to localhost only
- ✅ Disables admin shares, SMBv1, LLMNR, NetBIOS, WPAD
- ✅ Sets NIST-compliant password policy (14+ chars, lockout after 5)
- ✅ Disables unnecessary services (UPnP, Remote Registry)
- ✅ Creates hardened SSH config
- ✅ Cleans stale credentials & startup bloat

---

## Quick Start

### Prerequisites
- Windows 10 or 11 (Pro/Enterprise recommended)
- **Administrator privileges** (required)
- PowerShell 5.1+

### Audit (Read-Only)
```powershell
# Download and run the audit
git clone https://github.com/bappisinsane/unhackable.git
cd unhackable
.\scripts\audit.ps1
```

This generates a detailed JSON report at `~/Desktop/unhackable-audit.json` with every vulnerability found, categorized by severity.

### Harden (Apply Fixes)
```powershell
# Apply all security fixes
.\scripts\harden.ps1

# Aggressive mode (disables NetBIOS on all adapters, extra protocol hardening)
.\scripts\harden.ps1 -Aggressive

# Skip restore point creation
.\scripts\harden.ps1 -SkipRestorePoint
```

> ⚠️ **The hardening script creates a system restore point before making changes.** You can roll back if anything breaks.

---

## What Gets Hardened

| Category | Before | After |
|---|---|---|
| **Firewall** | OFF on all profiles | ON, default-deny inbound |
| **PostgreSQL** | `listen_addresses = '*'` | `listen_addresses = 'localhost'` |
| **Admin Shares** | C$, D$, E$, ADMIN$, IPC$ | All removed |
| **SMBv1** | Enabled | Disabled |
| **LLMNR** | Enabled (poisonable) | Disabled |
| **NetBIOS** | Broadcast mode | Point-to-point only |
| **WPAD** | Auto-discovery | Disabled |
| **Password Policy** | Min 0 chars, no lockout | Min 14 chars, lockout after 5 |
| **UPnP (SSDPSRV)** | Running | Disabled |
| **RemoteRegistry** | Running | Disabled + Stopped |
| **RDP** | Enabled | Disabled |
| **SSH Config** | None | Hardened with keep-alive, strict host checking |
| **Startup Programs** | 10+ bloatware | Cleaned to essentials |
| **Stale Credentials** | 6+ stale entries | Removed |

---

## Audit Output Example

```json
{
  "Timestamp": "2026-10-11T15:30:00Z",
  "ComputerName": "DESKTOP-SPKH7HK",
  "OS": "Windows 11 Pro",
  "Findings": [
    {
      "Category": "Firewall",
      "Title": "Firewall Disabled: Public",
      "Severity": "Critical",
      "Remediation": "Enable firewall: netsh advfirewall set allprofiles state on"
    },
    {
      "Category": "Database",
      "Title": "PostgreSQL Exposed on Port 5432",
      "Severity": "Critical",
      "Remediation": "Bind to localhost: Edit config to set bind address to 127.0.0.1"
    }
  ],
  "Summary": {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1
  }
}
```

---

## Advanced Usage

### Run Audit Remotely
```powershell
# Audit without modifying anything
.\scripts\audit.ps1 -OutputPath "C:\audit.json" -Quiet
```

### Schedule Periodic Audits
```powershell
# Create a scheduled task to audit weekly
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\unhackable\scripts\audit.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -At 9am -DaysOfWeek Sunday
Register-ScheduledTask -TaskName "Unhackable-Weekly-Audit" -Action $action -Trigger $trigger
```

### Integrate with CI/CD
```powershell
# In your pipeline
.\scripts\audit.ps1 -Quiet
$audit = Get-Content "$env:USERPROFILE\Desktop\unhackable-audit.json" | ConvertFrom-Json
if ($audit.Summary.Critical -gt 0) {
    Write-Error "Critical vulnerabilities found! Failing build."
    exit 1
}
```

---

## Security Vectors Covered

| Vector | Covered |
|---|---|
| Firewall bypass | ✅ |
| Database exposure | ✅ |
| SMB exploitation | ✅ |
| RDP brute-force | ✅ |
| LLMNR/NBT-NS poisoning | ✅ |
| WPAD hijacking | ✅ |
| Credential theft | ✅ |
| Malware persistence (startup) | ✅ |
| Unpatched vulnerabilities | ✅ |
| Weak authentication | ✅ |
| SSH downgrade attacks | ✅ |

---

## Contributing

Found a vulnerability this doesn't catch? Open an issue or submit a PR.

```bash
git checkout -b feature/new-check
# Add your check to scripts/audit.ps1
git commit -am "Add check for XYZ vulnerability"
git push origin feature/new-check
```

---

## License

MIT — Use it, modify it, share it. Just don't blame us when your machine becomes the most secure workstation in the building.

---

## Disclaimer

> This tool is provided as-is for educational and defensive security purposes. Always test in a safe environment before applying to production systems. The authors are not responsible for any damage or data loss. Create a system restore point before running the hardening script.

---

<div align="center">

**⭐ Star this repo if it made your machine harder to hack.**

*"The measure of a secure system is not the absence of vulnerabilities, but the presence of layered defenses."*

</div>
