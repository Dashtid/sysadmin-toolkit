# Scheduled Task Examples

> **Recommended approach:** Use [../Install-SystemUpdatesTask.ps1](../Install-SystemUpdatesTask.ps1) instead.
> It uses `Register-ScheduledTask` with the toolkit's resolved path, no placeholders, and laptop-friendly
> defaults. The XML below is for users who prefer the Task Scheduler GUI.

## weekly-updates-task.xml

**Purpose:** Weekly automated system updates on Sunday at 10:00.

**Features:**

- Runs system-updates.ps1 with full update capabilities
- Creates system restore points before updates
- Runs as the importing user with HighestAvailable privileges (not SYSTEM -- see note below)
- Only runs if network is available
- Battery-friendly: starts and continues on battery power
- Maximum execution time: 3 hours

### Why not SYSTEM?

`winget upgrade --all` running under the SYSTEM account misses user-scope packages -- a documented winget
limitation. For dev environments, the importing user with elevated rights is the correct default. The XML
ships with `LogonType=InteractiveToken` and a `REPLACE_USER_SID` placeholder for that reason.

**Installation:**

1. **Get your user SID:**

   ```powershell
   (New-Object Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
   ```

2. **Edit the XML file** -- replace `REPLACE_USER_SID` with your SID and `REPLACE_TOOLKIT_PATH` with the
   absolute path to your sysadmin-toolkit clone. Adjust `StartBoundary` to a date in the future.

3. **Import the task:**

   ```powershell
   Register-ScheduledTask -Xml (Get-Content weekly-updates-task.xml -Raw) -TaskName "Weekly System Updates"
   ```

   Or use Task Scheduler GUI:
   - Open Task Scheduler (taskschd.msc)
   - Right-click "Task Scheduler Library" -> "Import Task"
   - Select weekly-updates-task.xml
   - Edit paths in the Actions tab
   - Click OK

4. **Test the task:**

   ```powershell
   Start-ScheduledTask -TaskName "Weekly System Updates"
   ```

5. **View task history:**

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
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "REPLACE_TOOLKIT_PATH\Windows\maintenance\system-updates.ps1"</Arguments>
```

### Skip Specific Updates

Add parameters to skip certain update types:

```xml
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "REPLACE_TOOLKIT_PATH\Windows\maintenance\system-updates.ps1" -SkipWinget -AutoReboot</Arguments>
```

### Use Configuration File

Instead of command-line parameters, use a config.json file:

```xml
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "REPLACE_TOOLKIT_PATH\Windows\maintenance\system-updates.ps1" -ConfigFile "REPLACE_CONFIG_PATH"</Arguments>
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
Get-ChildItem REPLACE_TOOLKIT_PATH\logs\ -Filter "system-updates_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content -Tail 50
```

## Security Notes

- Default: task runs as the importing user with HighestAvailable privileges (winget-compatible)
- Ensure script directory has appropriate NTFS permissions
- Config files should not be world-readable
- Log files may contain sensitive information - protect accordingly
- If you switch to SYSTEM for headless scenarios, be aware that user-scope winget packages won't upgrade

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

**Last Updated:** 2026-05-15
