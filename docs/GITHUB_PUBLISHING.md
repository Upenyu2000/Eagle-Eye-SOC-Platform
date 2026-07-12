# GitHub Publishing

Target repository:

```text
https://github.com/Upenyu2000/Eagle-Eye-SOC-Platform
```

The repository must allow Git contents write access. From Windows PowerShell, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\publish_to_github.ps1
```

Git Credential Manager will request GitHub authentication when required. The script publishes only this standalone Eagle Eye project.
