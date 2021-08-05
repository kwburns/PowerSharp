# PowerSharp

A collection of Csharp projects wrapped with PowerShell.
```
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\SpoolSample.exe"))
```

## SpoolSample
Privilege Escalation via Spoolss service; works against Windows Server 2019, Windows Server 2012 R2, Windows 10. Requires SeImpersonate Privilege
@Credit to: https://github.com/leechristensen/SpoolSample

## PrintSpooferNet
Privilege Escalation via Spoolss service; works against Windows Server 2019, Windows Server 2012 R2, Windows 10. Requires SeImpersonate Privilege



