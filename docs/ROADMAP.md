# Roadmap

Strategic direction for the Windows Sysadmin Toolkit.

> **2026-06-14:** this document was rewritten after the ghost-code cull. The pre-cull Tier 1-5 structure (Monitoring / Backup / Network / Cloud / Observability) no longer reflects the codebase. See [BACKLOG.md](../BACKLOG.md) for the audit summary and rationale.
>
> **2026-09-26:** the Linux tier (GPU exporter, disk cleanup, headless server setup) was removed; the toolkit is Windows-only. See [CHANGELOG.md](../CHANGELOG.md).

## Scope

The toolkit deliberately does **not** try to cover everything a sysadmin might do. It covers the gaps in the author's existing stack:

- **Native Windows tools** already cover monitoring (Task Manager, Performance Monitor, Reliability Monitor, Event Viewer), backup (File History/OneDrive), VPN (OpenVPN GUI), WSL (`wsl.exe`), and network audit (Settings).
- **A separate repo (`defensive-toolkit`)** handles security hardening.

What's left for this toolkit:

| Area | Why it's here |
|------|---------------|
| Windows first-time setup | Re-imaging happens; package lists need to survive |
| Weekly Windows update automation | One scheduled task with retry/exclude logic |
| Pre-rebuild dev-environment snapshot | OneDrive doesn't sync VSCode/Terminal/Git/SSH configs the way I want |
| Docker Desktop convenience helper | Wraps the 5 things I actually do with Docker Desktop |
| One-shot static IP | Settings UI is fine, but scripted is easier when I'm setting up a fresh box |
| Common-issue repair | DNS/network/Windows Update fix-it routines I've needed enough times to script |

## Active initiatives

**None. The toolkit is in maintenance mode** — this is deliberate, not a gap. See [BACKLOG.md](../BACKLOG.md) for the tactical list; its "Active work" section is empty by design.

Two initiatives were tentatively planned during the 2026-06-14 cull and **cancelled the same day on reflection** (they now live in BACKLOG's Cancelled list):

1. **Shrink the survivors** — `system-updates.ps1`, `Manage-Docker.ps1`, `Repair-CommonIssues.ps1`, `Set-StaticIP.ps1` were candidates for aggressive LOC trims. The scripts work; the targets were aesthetic, not functional. If one needs a fix from real failure later, shrink as part of that fix — not as a standalone sprint.
2. **Replace `fresh-windows-setup.ps1` with a `winget configure` YAML** — the declarative path is real, but the bespoke script works and its trigger (re-imaging) fires every 1-3 years. Deferred until the next rebuild forces the choice.

The strategic test is the one BACKLOG codifies: a script that goes 6 months without a `fix:` commit from real failure is a candidate for archival, not for a refactor sprint.

## Not planned

| Initiative | Why not |
|------------|---------|
| Re-adding monitoring/reporting/security tiers | Native Windows tools + defensive-toolkit already cover this. Single-user machine monitoring has no consumer. |
| Re-adding full backup tier | OneDrive + browser sync cover this. Single-user machine backups duplicate consumer SaaS. |
| Re-adding Linux scripts | The Linux tier was removed on 2026-09-26 because nothing used it. Anything Linux-side belongs with the machine it runs on, not here. |
| Cloud (Azure/AWS) wrappers | Each cloud has its own CLI/SDK; wrapping them in PowerShell adds maintenance burden without value. |
| "Behavioral coverage" sprints for scripts with no usage signal | The 2026-06-14 cull deleted exactly this category of work. New policy: a script with no `fix:` commit from real failure in 6 months is a candidate for archival, not test scaffolding. |

## Test policy

Tests cover what survives. The ratio target is **smoke tests for the setup scripts** (they DO run on fresh machines) and **unit tests for the lib modules** (CommonFunctions / ErrorHandling are imported everywhere). The pre-cull 0.65 test:prod ratio was a symptom — not a goal.

---
**Last Updated**: 2026-09-26
