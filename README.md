# laptop-health-check

PowerShell script to health-check a used Windows laptop: battery wear, disk SMART, RAM pattern test, CPU stress/thermals, device errors, event-log crashes, DISM/sfc, org-management (MDM/domain) detection.

Run in elevated PowerShell, plugged into AC:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\laptop-health-check.ps1            # -StressSeconds 300, -SkipStress, -SkipIntegrity
```

Report lands on Desktop\HealthReport_<date>\. Read-only except temp files; untested on many models, review before running.
