# Windows Automated Update Scripts

This repository contains PowerShell scripts for automating system maintenance tasks on Windows, including package updates via Chocolatey and Windows Updates. The scripts are designed to be run at startup or on demand, with logging and administrative privilege escalation.

## Contents

- **startup_script.ps1**  
  Main script that:

  - Checks for and requests administrative privileges if needed.
  - Logs all actions and output to a dated log file in a `logs` directory.
  - Upgrades all installed Chocolatey packages.
  - Checks for and installs available Windows Updates using the `PSWindowsUpdate` module.
  - Cleans up log files older than 30 days.

- **schedule_task.ps1**  
  Script to register `startup_script.ps1` as a scheduled task that runs at user logon with highest privileges and a hidden window.

## Usage

### 1. Running the Startup Script Manually

Open PowerShell 7+ as Administrator and run:

```powershell
pwsh -File .\startup_script.ps1
```

### 2. Scheduling the Script to Run at Logon

Run the following command as Administrator to register the scheduled task:

```powershell
pwsh -File .\schedule_task.ps1
```

This will ensure `startup_script.ps1` runs automatically at every user logon.

## Requirements

- PowerShell 7 or later (`pwsh`)
- Chocolatey package manager installed
- PSWindowsUpdate PowerShell module (installed automatically if missing)
- Administrative privileges to install updates and manage scheduled tasks

## Features

- **Automatic Privilege Elevation:** Prompts for admin rights if not already running as administrator.
- **Comprehensive Logging:** All actions and outputs are logged to timestamped files in a `logs` directory.
- **Chocolatey Updates:** Automatically upgrades all Chocolatey packages.
- **Windows Updates:** Checks for and installs available Windows Updates.
- **Log Maintenance:** Deletes log files older than 30 days to save disk space.

## Notes

- The script will not proceed if run in PowerShell versions older than 7.
- If Chocolatey is not installed, the script will prompt you to install it first.
- Windows Updates are installed non-interactively and will not automatically reboot the system.
- All logs are stored in a `logs` folder next to the script.

## License

MIT License

---

_Maintained by David Dashti. For questions or suggestions, please open an issue or contact me._
