# Network Management Scripts

Network configuration and VPN management for Windows.

## Scripts

| Script | Purpose |
|--------|---------|
| [Set-StaticIP.ps1](Set-StaticIP.ps1) | Configure static IP, DNS, and gateway |
| [Manage-VPN.ps1](Manage-VPN.ps1) | VPN connection management and auto-reconnect |

## Quick Examples

```powershell
# Set static IP
.\Set-StaticIP.ps1 -InterfaceAlias "Ethernet" -IPAddress "192.168.1.100" -Gateway "192.168.1.1"

# Connect VPN
.\Manage-VPN.ps1 -Connect -ProfileName "Work VPN"

# Monitor VPN with auto-reconnect
.\Manage-VPN.ps1 -Monitor -ProfileName "Work VPN" -AutoReconnect
```

---
**Last Updated**: 2025-12-26
