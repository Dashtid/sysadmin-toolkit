# Network Management Scripts

One-shot helpers for network configuration.

> **Scope note (2026-06-14):** `Manage-VPN.ps1` was removed in the ghost-code cull — the OpenVPN GUI client covers single-user VPN management more reliably.

## Scripts

| Script | Purpose |
|--------|---------|
| [Set-StaticIP.ps1](Set-StaticIP.ps1) | Configure static IP, DNS, and gateway on a named interface |

## Quick Example

```powershell
.\Set-StaticIP.ps1 -InterfaceAlias "Ethernet" -IPAddress "192.168.1.100" -Gateway "192.168.1.1"
```

---
**Last Updated**: 2026-06-14
