# PowerSharp

A collection of Csharp projects wrapped with PowerShell.

## SpoolSample
Privilege Escalation via Spoolss service; works against Windows Server 2019, Windows Server 2012 R2, Windows 10. Requires SeImpersonate Privilege
```
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\SpoolSample.exe"))
```

@Credit to: https://github.com/leechristensen/SpoolSample
