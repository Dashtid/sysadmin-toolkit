# System integrity check (DISM + SFC)
Write-Host "[i] Running DISM health check..."
DISM /Online /Cleanup-Image /RestoreHealth
Write-Host "[i] Running System File Checker..."
sfc /scannow
Write-Host "[+] System integrity check complete"
