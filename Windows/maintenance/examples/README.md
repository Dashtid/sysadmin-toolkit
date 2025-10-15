# Scheduled Task Examples

Example XML files for Windows Task Scheduler to automate system maintenance.

## weekly-updates-task.xml

**Purpose:** Weekly automated system updates on Sunday at 3:00 AM

**Features:**
- Runs system-updates.ps1 with full update capabilities
- Creates system restore points before updates
- Automatically reboots if updates require it
- Runs as SYSTEM account with highest privileges
- Only runs if network is available
- Won't start if on battery power
- Maximum execution time: 2 hours

**Installation:**

1. **Edit the XML file** - Update the paths to match your installation:
   ```xml
   <Command>C:\Program Files\PowerShell\7\pwsh.exe</Command>
   <Arguments>-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\sysadmin-toolkit\Windows\maintenance\system-updates.ps1" -AutoReboot</Arguments>
   <WorkingDirectory>C:\path\to\sysadmin-toolkit\Windows\maintenance</WorkingDirectory>
   ```

2. **Import the task:**
   ```powershell
   Register-ScheduledTask -Xml (Get-Content weekly-updates-task.xml | Out-String) -TaskName "Weekly System Updates"
   ```

   Or use Task Scheduler GUI:
   - Open Task Scheduler (taskschd.msc)
   - Right-click "Task Scheduler Library" → "Import Task"
   - Select weekly-updates-task.xml
   - Edit paths in the Actions tab
   - Click OK

3. **Test the task:**
   ```powershell
   Start-ScheduledTask -TaskName "Weekly System Updates"
   ```

4. **View task history:**
   ```powershell
   Get-ScheduledTask -TaskName "Weekly System Updates" | Get-ScheduledTaskInfo
   ```

## Customization Options

### Change Schedule

Edit the `<CalendarTrigger>` section:

**Daily at 2 AM:**
```xml
<ScheduleByDay>
  <DaysInterval>1</DaysInterval>
</ScheduleByDay>
```

**Monthly (first Sunday):**
```xml
<ScheduleByMonth>
  <DaysOfWeek>
    <Sunday />
  </DaysOfWeek>
  <Weeks>
    <Week>1</Week>
  </Weeks>
  <Months>
    <January /><February /><March /><April /><May /><June />
    <July /><August /><September /><October /><November /><December />
  </Months>
</ScheduleByMonth>
```

### Disable AutoReboot

Remove `-AutoReboot` from the arguments:
```xml
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\sysadmin-toolkit\Windows\maintenance\system-updates.ps1"</Arguments>
```

### Skip Specific Updates

Add parameters to skip certain update types:
```xml
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\sysadmin-toolkit\Windows\maintenance\system-updates.ps1" -SkipWinget -AutoReboot</Arguments>
```

### Use Configuration File

Instead of command-line parameters, use a config.json file:
```xml
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\sysadmin-toolkit\Windows\maintenance\system-updates.ps1" -ConfigFile "C:\path\to\config.json"</Arguments>
```

## Monitoring Scheduled Tasks

### Check Task Status
```powershell
Get-ScheduledTask -TaskName "Weekly System Updates"
```

### View Last Run Result
```powershell
Get-ScheduledTaskInfo -TaskName "Weekly System Updates" | Select-Object LastRunTime, LastTaskResult, NextRunTime
```

### View Task History (Event Viewer)
```powershell
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" | Where-Object { $_.Message -like "*Weekly System Updates*" } | Select-Object -First 10
```

### Check Logs
```powershell
# View latest update log
Get-ChildItem C:\path\to\sysadmin-toolkit\logs\ -Filter "system-updates_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 50
```

## Security Notes

- Task runs as SYSTEM account (S-1-5-18) with highest privileges
- Ensure script directory has appropriate NTFS permissions
- Config files should not be world-readable
- Log files may contain sensitive information - protect accordingly
- Consider using a dedicated service account instead of SYSTEM for production

## Troubleshooting

### Task runs but no updates happen
- Check execution policy: `Get-ExecutionPolicy -List`
- Verify PowerShell 7 path: `Test-Path "C:\Program Files\PowerShell\7\pwsh.exe"`
- Review transcript logs in the logs directory

### Task fails with "Cannot find path"
- Ensure all paths in the XML are absolute (not relative)
- Verify working directory exists
- Check that script file exists at specified path

### Task doesn't run at scheduled time
- Check if "Run whether user is logged on or not" is selected
- Ensure "Wake the computer to run this task" is unchecked (unless needed)
- Verify triggers are enabled
- Check if "StartWhenAvailable" is true

---

**Last Updated:** 2025-10-15
