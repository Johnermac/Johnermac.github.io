---
title: "2 - Network Security"
classes: single
header:  
  teaser: "/assets/images/posts/2023-11-19-ecppt/ecppt-teaser.jpg"
  overlay_image: "/assets/images/main/menu.jpg"
  overlay_filter: 0.5  
ribbon: DarkSlateBlue
excerpt: "eCPPTv2"
description: "INE Security’s eCPPT is the only certification for professional-level Penetration testers that evaluates your ability to attack your target and provide thorough professional documentation and recommendations."
categories:
  - certs
  - ecppt
tags:
  - begginer
  - pentest
toc: true
---

# Information Gathering

Business:
	deals with collecting information regarding the type of business, its stakeholders, assets, products, services, employees and generally non-technical information;

Insfrastructure:
	networks, systems, domains, IP addresses, etc

## Can be Passive or Active

Passive or OSINT:
	web presence, partners, financial info, physical plants, infrastructure related information etc
	get information without exposing our presence.
	using publicly available resources (accessible by anyone)

Active:
	gather information about ports, services, running systems, net blocks etc
	active techniques can reveal the investigation to the organization through IDS or server logs so caution should be taken to prevent this.

## Mind mapping technology
```
FreeMind = http://freemind.sourceforge.net/wiki/index.php/Main_Page
Xmind = https://www.xmind.net/
```

## keep track of networks/vulns scans
```
Dradis = http://dradisframework.org/
Faraday = https://github.com/infobyte/faraday
Magitree = http://www.gremwell.com/what_is_magictree
```


## Search Engine



### Web Presence

- What they do
- what is their business purpose
- physical and logical locations
- employees and departments
- email and contact information
- alternative web sites and sub-domains
- press releases, new, comments, opinions

- start with the company name
company website
analyze information that is publicly available

### Google Dorks
```
https://www.exploit-db.com/google-hacking-database/
http://pdf.textfiles.com/security/googlehackers.pdf
http://www.googleguide.com/advanced_operators_reference.html
```

### Organization that operate globally
```
	DUNS number (duns and bradstreet)
	cage code (or ncage \for a non us business)
	https://www.sam.gov/
	http://www.sec.gov/edgar.shtml
```

- Partners: through the partners you can gather information such as the technology stack the organization uses (hardware and software), tools, systems etc

### Job Postings
Through career opportunities, you can gather information such as internal hierarchies, vacancies, projects, responsabilities, weak departments, financed projects, technology implementations and more.

List of websites that you can use to find job posts:
```
	http://www.linkedin.com/
	http://www.indeed.com/
	http://www.monster.com/
	http://www.careerbuilder.com/
	http://www.glassdoor.com/
	http://www.simplyhired.com/
	http://www.dice.com/
```

### Financial Information
you can find out if the organization:
	is going to invest in a specific technology
	might be subject to a possible merge with another organization
	has critical assets and business services
http://www.crunchbase.com/
crunchbase is a databse where you can find information about:
	Companies
	People
	Investors and financial information

http://www.inc.com/

### Documents and Files
such as:
	charts (detailing the corporate structure), database files, diagrams, papers, documentation, spredsheet etc
then:
	harvest emails, accounts (twitter, facebook etc), names, roles, etc
extract useful information in the metadata of the file

in google:
```
	site:[website] and filetype:[filetype]
```

Harvest files with tools:
FOCA: [windows based]
	https://www.elevenpaths.com/labstools/foca/index.html
TheHarvester:
	https://github.com/laramies/theHarvester
	theharvester -d [domain] -l [limits of results] -b google/bing/linkedin

### Cached and archival sites
waybackmachine
	http://www.archive.org/index.php

in google
```
	cache:URL
```


## Lab 2
*Target organization: University Campus.*

Scope: The scope is limited to the following domain and netblock:
```
    Netblock: 10.50.96.0/23

    Domain: foocampus.com
-  Task 1 : host discovery
	fping -a -g 10.50.96.0/23 2>/dev/null > hosts-up 
	nmap -sn 10.50.96.0/23
```

```
10.50.96.5
10.50.96.15
10.50.97.6
10.50.97.5
10.50.97.15
```

-  Task 2 : Host discovery no ping
```
//nmap -p 80,443,53,22 10.50.96,97.5.15.6 -T4
nmap -n -sn -PS22,135,443,445 10.50.96.0/23
	to not generate to much traffic, we will use argument -PS
	with this scan we discovered another ip
	10.50.97.17 > because it was probably blocking pings with firewall
```

-  Task 3 : difference
the second scan discovered a new host in the network, because it probably has firewall that is blocking pings

- Task 4 : dns
both have the port 53 open, so I assume its dns
```
nmap -sS -sU -p53 10.50.96.0/23
10.50.96.5
10.50.96.15
```


- task 5 : name server
we found 2 dns ips before, so we will focus on them

```
1) >>nslookup
2) >>server 10.50.96.5
3) >>set q=NS
4) >>foocampus.com
```


printsection()
```
foocampus.com   nameserver = ns1.foocampus.com
foocampus.com   nameserver = ns.foocampus.com

> server 10.50.96.5
Default server: 10.50.96.5
Address: 10.50.96.5#53
> ns.foocampus.com
Server:         10.50.96.5
Address:        10.50.96.5#53
```

### discovering new ips with nslookup
```
Name:   ns.foocampus.com
Address: 10.50.96.21
------------------------------------------
Name:   ns1.foocampus.com
Address: 10.50.96.22
```

- task 6 - MX Record
```
>> nslookup
>> server 10.50.96.5
>> set q=MX
>> foocampus.com

printsection()
foocampus.com   mail exchanger = 10 pop3.foocampus.com.
```

- task 7 : zone transfer
```bash
	dig @10.50.96.5 foocampus.com -t AXFR +nocookie
	host -t axfr foocampus.com 10.50.96.5

; <<>> DiG 9.17.19-1-Debian <<>> @10.50.96.5 foocampus.com -t AXFR +nocookie                                          
; (1 server found)                                                                                                    
;; global options: +cmd                                                                                               
foocampus.com.          3600    IN      SOA     foocampus.com. campusadmin. 47 900 600 86400 3600                     
foocampus.com.          3600    IN      NS      ns.foocampus.com.                                                     
foocampus.com.          3600    IN      NS      ns1.foocampus.com.                                                    
foocampus.com.          3600    IN      MX      10 pop3.foocampus.com.                                                
ftp.foocampus.com.      3600    IN      A       10.50.96.10                                                           
intranet.foocampus.com. 3600    IN      A       10.50.96.15                                                           
management.foocampus.com. 3600  IN      A       10.50.96.15                                                           
ns.foocampus.com.       3600    IN      A       10.50.96.21                                                           
ns1.foocampus.com.      3600    IN      A       10.50.96.22                                                           
pop3.foocampus.com.     3600    IN      A       10.50.96.60                                                           
www.foocampus.com.      3600    IN      A       10.50.96.15                                                           
foocampus.com.          3600    IN      SOA     foocampus.com. campusadmin. 47 900 600 86400 3600                     
;; Query time: 519 msec                                                                                               
;; SERVER: 10.50.96.5#53(10.50.96.5) (TCP)                                                                            
;; WHEN: Sat Dec 04 10:49:45 -03 2021                                                                                 
;; XFR size: 12 records (messages 12, bytes 685)
```

- task 8 - draw the network map

...

- task 9 - Report your findings
After scan the network, we discover various IPS addresses from DNS and through that we discover more IPs from ftp, intranet, name server, email server etc.

```
dig axfr -x 192.168 @192.214.31.3
```

> to show only reverse dns entries



network map of lab 2 - 10.50.96.0/23







## Social Media
with the help of social media, a pentester can gather:
```
	phone numbers
	addresses
	history
	CV
	opinions
	responsabilities
	project 
	etc
```

social media is useful in the following ways:
	learn about corporate culture, hierarchies, business processes, technologies, applications
	to build a network map of people (relationships)
	select the most appropriate targer For a social engineering attack

On linkedin you can perform  advanced search functions on people based upon:
	current title, position, location, company, etc

when you have limited access because maybe you dont have connection with the person etc:
	upgrade your linkedin account
	use a specific query in a search engine in order to find (if exists) the public linkedin profile of the target

> Why is building a network of people important?
	social engineering is the art of exploit trust relationships
	you can get to bob through a person he trusts etc

### people search
```
	http://www.pipl.com/
	http://www.spokeo.com/
	http://www.peoplefinders.com/
	http://www.crunchbase.com/
```

At this point we should have gathered:
```
	age, phone number, business, adresses, occupation, interests
	further we go to: emails, related docs, website owned, financial info
```




## Infrastructures
goal is retrieve data such as:
```
	domains
	netblocks or ip addresses
	mail servers
	ISP used
	any other technical information
```


The approach depends upon the SOE (Scope of Engagement)
Lets assume the below listed cases:
	case 1 - we have the name of the organization (full scope)
	case 2 - we only have specific net blocks to test

- case 1
This process aims to collect all the hostnames related to the organization and relative IP addresses
The process ends when we obtain:
	domains, dns servers in use, mail server, ip addresses

- First step
WHOIS = is a query/response protocol, used For querying an official domain registrer database in order to determine:
```
	the owner of a domain name
	ip address or range
	autonomous system
	technical contacts
	expiration date of the domain
```

The web based whois is there, normally runs on tcp port 43
	https://tools.ietf.org/html/rfc3912

- A Regional Internet Registry (RIR)
	organization that manages resources such as IP addresses and Autonomous System For a specific region.
There are five main RIR provides For WhoIs information:
```
	AFRINIC - africa
	APNIC - asia
	RIPE NCC - europe
	ARIN - north america
	LACNIC - south america
```

- information obtained from whois:
```
	Number Resource Records
	Network numbers (ip addresses) = NETs
	Autonomous system numbers = ASNs
	Organization records = ORGs
	Point of contact records = POCs
	Authoritative information \for Autonomous system numbers and registered outside of the RIR being queried
```

### Tools that allow you to use WHOIS:
```
	http://who.is/
	http://whois.domaintools.com/
	http://bgp.he.net/
	http://networking.ringofsaturn.com/Tools/whois.php
	http://www.networksolutions.com/whois/index.jsp
	http://www.betterwhois.com/
```

> What information did we get from WHOIS that can help determine the infrastructure of the organization?
	Name servers!
> These are servers that store all the dns related information (records) about the domain

- DNS = Domain Name System
	key aspect of information security as it binds a hostname to an IP address and many protocols such as SSL are as safe as the DNS protocol they bind to.
	contains textual records
	each record has a given type, each with a differente role






### DNS Queries 
> DNS queries produce listings called Resource Records.

- Resource Record
A Resource record starts with a domain name, usually a fully qualified domain name. If anything other than a fully qualified domain name is used, the name of the zone the record is in will automatically be appended to the end of the name.
- Time-To-Live (TTL)
recorded in seconds, defaults to the minimum value determined in the start of authority (SOA) record
- Record Class
Internet, Hesiod or Chaos
- Start of Authority (SOA)
Indicates the beginning of a zone and it should occur first in a zone file. There can be only one SOA record per zone. Defines certain values For the zone such as a serial number and various expiration timeouts.
- Name Server
Defines an authoritative name server For a zone. Defines and delegates authority to a name server For a childe zone. NS Records are the GLUE that binds the distributed database together,
- Address
The A record simply maps a hostname to an IP address. Zones with A records are called *forward* zones.
- Pointer
The PTR record maps an IP address to a Hostname. Zones with PTR records are called *reverse* zones.
- CNAME
The CNAME record maps an alias hostname to an A record hostname
- Mail Exchange (MX)
The MX record specifies a host that will accept email on behalf of a given host.
The specified host has an associated priority value A single host may have multiple MX records. The records For a Specific host make up a prioritized list.

### DNS Lookup 
> DNS lookup asks the DNS to resolve a given hostname to the corresponding IP.

```
nslookup <target-organization.com>
```

First u need to discover the IP addresses then try to resolve them.

#### Reverse DNS lookup
we will receive the IP address associated to a given domain name. This process queries For DNS pointer records (PTR).
command line:
```
	nslookup -type=PTR <ip address>
```

online tool:
	http://network-tools.com/nslook/

#### MX (Mail Exchange) lookup
we retrieve a list of servers responsible For delivering emails For that domain.
command line:
```
	nslookup -type=MX <domain>
```

only tools:
	http://www.dnsqueries.com/en/
	http://www.mxtoolbox.com/

#### Zone transfers
zone transfers are usually a misconfiguration of the remote DNS server. They should be enabled only For trusted IP addresses (usually trusted downtream name servers).
When zone transfers are enabled, we can enumerate the entire DNS record For that zone,
This includes all the sub domains of our domain (A records)

```
	nslookup -type=NS <domain.com>
```

There are usually two name servers, Take note of both of them.
```
	nslookup
	server <domain.com>
	ls -d <domain.com>
```

- Dig = http://linux.die.net/man/1/dig
is a poweful tool, we can learn both nslookup and dig


#### nsloolup & Dig commands
```
	                                                        // dig +nocmd <domain> mx +noall +answer 
	nslookup <target.com>                   // dig <target.com> +short
	nslookup -type=PTR <target.com> // dig <target.com> PTR
	nslookup -type=MX <target.com>  // dig <target.com> MX
	nslookup -type=NS <target.com>  // dig <target.com> NS
	nslookup                                         // dig axfr @target.com <target.com>
	- server <target.com>
	-- ls -d <target.com>
```

#### Fierce
```
	fierce -dns <domain.com>
	fierce -dns <domain.com> -dnsserver <dns server>
```

#### DNS Enum
```
	dnsenum <domain.com>
	dnsenum <domain> --dnsserver <dns server>
	dnsenum <domain> -f <list of hosts>
```

#### DNS Map - subdomain bruteforcer
```
	dnsmap <domain>
```

#### DNS Recon
```
	dnsrecon -d <domain>
```

### IP
Once we have found a number of host names related to the organization, we can move on with both determining their relative IP addresses and, potentially any Netblocks associated with the organization.
	First think, try to resolve all the hostnames we have, in order to determine what IP addresses are used by the organization.
```
   → nslookup ns.<target-organization.com> = hostname
```

	the dns will handle the query *our dns*
	then we should receive the IP address of the target

After getting the IP addresses:
	is this ip hosting only that given domain?
	who does this IP address belong to?

### subdomains 
on Bing search:
we can find subdomains that are bounded to the ip address of domain
```
	ip:<ip address>
```

there are tools:
```
	http://reverseip.domaintools.com/
	https://dnslytics.com/reverse-ip
	https://networkappers.com/tools/reverse-ip-checker
	https://www.robtex.com/
```

### netblock
Is a range of IP addresses. 
example: 
```
	192.168.0.0 - 192.168.255.255
	192.168.0.0/16 or 192.168.0.0 with 255.255.0.0 netmask
```

- AS - Autonomous System
Is made of one or more net blocks under the same administrative control
Big companies and ISP (internet service providers) have an autonomous system, while smaller companies will barely have a netblock.

> Run some WHOIS tool, to discover who is the owner of the IP addresses.

Some tools will automatically perform these operations:
```
	hostmap
	maltego
	foca
	fierce
	dmitry
```

- After getting a list of IP Addresses:
	we need to identify which of those are alive


### Here starts Case 2

- once we have a list of ip addresses we have to identify the devices and the roles played by each IP in the network.

First:
	Determine hosts that are alive
	Determine if they have an associated host name/domain

The most common technique to identify live hosts is ICMP ping sweep, the live hosts will return an ICMP ECHO reply.
Some tools:
	fping
	nmap
	hping3
	maltego

```
fping -a -g <ip/24>
	-a = alive / -g = generate list / -r = number of retries / -e = time required / 
```

```
nmap -sn <ip/24> 
	-sn = ping scan/sweep = no port
	--disable-arp-ping
	-PS = tcp flag with syn flag attached / -PS<port>
	-PA = tcp flag with ack / -PU = udp packet / -PY = tcp INIT packet / -PE = icmp echo request /
	-PM = icmp mask request / -PP = timestamp request / 
```


```
hping3 --icms-ts <192.168.1.x> 
	icmp-ts = timestamp / -c = count / -v = verbose / -S = syn flag / -p = port / -F = fin flag / 
	-U = urgent / -X = ecn flag / -Y = CWR flag / -P = PSH flag / -I = interface / -1 = icmp / 
	--rand-dest = to use with x as a wildcard / 
```

> maltego


*Nowadays, ICMP is often disabled on perimeter router and firewalls via Firewall*

-  Now that we know which host is alive
DNS server runs on:
```
	TCP port 53
	UDP port 53
```

To discover which host is running dns:
```
	nmap -sS -p 53 [netblock] = tcp
	nmap -sU -p 53 [netblock] = udp
```

> After getting the DNS servers, we can perform a reverse lookup to find out more information.
Its a cyclical process, when we find IPs we search For alives, search For DNS, services, etc

## Tools 
> Most common tools For information gathering:


- DNSdumpster = https://dnsdumpster.com/
```
	// not instrusive, create a map For easy visualization
```


- DNSEnum = https://github.com/fwaeytens/dnsenum
```
	// gather as much information as possible
	// --private = show and save private ips // --subfile <file> = write all valid subdomains to this file
	// -p <page> = number of google search pages to process
	// -s <value> = number of subdomains that will be scraped from google
	// -f <file> = read subdomains from this file to perform bruteforce
	// -u = update any file that may exist already // -r = recursive brute force
	// it comes with a wordlist file For bruteforce /usr/share/dnsenum
```


- DnsMap = https://github.com/makefu/dnsmap
```
	// uses the primary domain that we provide as a target and then brute forces all the subdomains
	// also comes with a wordlist
	// -w <wordlist // -r = using the built-in wordlist // path = to save the results in that path
```


- Foca = https://www.elevenpaths.com/labstools/foca/index.html
```
	// allows us to mine a ton of information about the target infrastructure
	// metadata = contains further information about the file, creation day, user who create, software used etc
```

More:
```
- Metagoofil
- Fierce	
- Maltego
- Dmitry
- Recon-ng
- Shodan = shodan.io // exploits.shodan.io
```


# Scanning

## Overview
> Now that we have basic information, we need information about devices in the target network.
```
PPS = Ports, Protocols and Services
	reference: http://www.iana.org/assignments/port-numbers
```


- The Three Way Handshake
```
	Sequence Number
	Acknowledgement numbers
	SYN and ACK flags
```

- Packet analyzer tools
- Hping = http://hping.org/
```
	// hping3 <ip> -p 80
	//-S = syn packet // -c <number> = count the packets // 
- Nping = https://nmap.org/nping/
```

> The flags we got as answers :
RA (Reset and Acknowledgement) = no service listening
SA (Syn and ACK) = the port is open



## Wireshark
> capture and inspect the whole traffic we receive/send in the network interface

### Filters
```
ip.addr==<ip>
ip.src==<ip> - source
ip.dst==<ip>  - destination
ip.addr==<ip> and (dns or http)
!= - negate/inverse
```

```
arp
http 
icmp 
http or dns
ssh
```

```
tcp.port==<port>
udp.port==<port>
tcp.flags.syn==1 and tcp.flags.ack==1 and ip.addr==<ip/network>
tcp contains *string*
```

- show packets to show full packet traffic information


## HPING Basics


hping3 -h
```
-S = SYN packet, its good For stealth because after receiving the syn/ack the OS closes the connection and does not finish the 3way handshake
-p = port
-c = count, its how many packets do you wanna send
--scan <1-100//80,139,445//all, known> = sets a range/set of ports we wanna scan
	!50 = we can put a exception to a port that we do not wanna scan
-2 or --udp = to scan udp ports
-FPU = (FIN, PSH, URG flags) to avoid firewalls, if u dont have anwers its because the port is open or filtered
	aka Xmas scan
```


### IDLE scan 

#### Finding the zombie

First we need to search For open ports on the host (zombie target):
```
	hping3 -S --scan known <zombie ip>
```

Estimate the host (zombie):
```
	hping3 -S -r -p <port> <zombie ip>
	// -r = tells the tool to display ID increments intead of the actual ID, if the IP ID increases by 1, its a viable candidate
	however: we have to validate if its a global or local increase. some hosts increase IP ID on a per host basis
```

- Craft a packet:
```
	hping3 -a <zombie IP> -S -p <target port> <target IP>
	// -a = spoof the zombie source address
	// -s = syn flag enabled
	// -p = destination port 
```

- Detect if its a good zombie:
```
	hping3 -S -r -p <port> <zombie ip>
	// if in the output the ID increment is +2, we can deduce that the [target port] on [target ip] is open.
```

> [+] info
we can run the 2 commands together:
first tab = we run the verication in the zombie host
second tab = the crafted packet, to discover if the target port is open
we will receive the answer is the first tab, its open if the value of ID is incremented by 1


idle scan - hping = stealth mode

![Alt text](/assets/images/posts/2023-11-19-ecppt/17.png){: .align-center}


### Detect Live Hosts and Ports

	firewalls made more difficult to scan ports
	based upon the type of discovery launched against the target, the level of noise produced varies.

- running a straight ping sweep of a network = surely its gonna be noisy
- a random TCP connect scan may appear normal to the administrators

- always depend on the scope document, time limited schedule etc

> Penetration testing takes times if u want to do it correctly


## NMAP (Network Mapper)
	network enumeration and auditing tool.
	https://nmap.org/book/man-port-scanning-techniques.html

ps: use nmap with root privileges, cause some scans require system access.

```
   → nmap <scan type> <options> <target>
```

### HOST DISCOVERY:
```
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OSs DNS resolver
  --traceroute: Trace hop path to each host
```


### SCAN TECHNIQUES:
```
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
```


#### -sS (TCP SYN scan)
	can be performed quickly and are not as obstrusive as other types of scans.
	its also the most accurate
	half-open scanning
	syn > syn/ack = port open / rst = closed > then our machine closes the connection with RST

#### -sT (TCP Connect scan)
	its the default type
	its also used in case ipv6 is running
	its less efficient, because it relies on the OS to perform the connection.
	it complete the 3w handshake, sending an ack flag before closing with rst/ack.

#### -sU (UDP scan)
	there are other services that run and communicate over UDP (DNS, SNMP, DHCP, etc)
	much slower

#### -sI (Idle scan) 'very stealthy mode'
	stealth technique that involves the presence of a zombie in the target network.
	a zombie is a host that is not sending or receiving any packets thus, the reason its called an idle scan.
	IP protocol implements a Fragmentation ID Header = https://tools.ietf.org/html/rfc791 and that many OS increase its value by 1 (For each packet).

- How to execute
Alors, we can scan a host without sending a single packet from our original IP address.
Thats awesome For *redteam, stealth* scopes;
```
	nmap -Pn -sI <zombie ip>:<zombie open port> <target ip> -v 
	// -Pn = prevents pings from the original (our) IP
	// -v = verbose
	// -sI = idle scan, using a zombie pc in the network to scan the target
	// we can specify the ports with -p
```

> For more information about idle scan
	http://nmap.org/book/idlescan.html

------------------------------------------------------------------------
#### -PE
	enables ICMP echo request host discovery


#### -n (Never do DNS resolution)
	The *-n* is another option we should use whenever possible if resolving IP addresses to hostnames is not required. Its an additional flag we can add to our Nmap scans to decrease our scan times, and also helps us stay a bit more *under the radar*, as reverse DNS lookup can generate more noise than necessary.

#### -b (FTP Bounce scan)
	another stealthy scan. https://en.wikipedia.org/wiki/FTP_bounce_attack
	this scan exploits a FTP server port command and if FTP server is vulnerable, allows us to launch port scans from the ftp server to other machines on the internet.
	we dont have direct access to on an internal network
	its way to hide our true source

#### -sN; -sF; -sX (TCP NULL, FIN, Xmas scans)
	http://www.rfc-editor.org/rfc/rfc793.txt - page 65

	They exploit a loophole in order to differentiate between open and closed ports.
	if a system compliant with the TCP RFC receives a packet that does not contain 
	the required bits (syn, rst, ack), it will return:
	-> a RST if the port is closed
	-> no response if the port is open
*As long as none of those three required bits are included (syn, rst, ack), other bits (fin, psh, urg) are acceptable.*
```
	-sN = Null scan : does not set any bits (tcp flag header is 0)
	-sF = FIN scan : Only sets the TCP FIN bit
	-sX = Xmas scan : Sets the FIN, PSH and URG flags, lighting the packet up like a christmas tree.
```

> Nowadays the stealth is these techniques have been eliminated, because stateful firewalls and IDS sensors.
Moreover, these scans cannot always determine if a port is open or filtered. So nmap will return a open/filtered result and you will have to test further to determine the actual state.

#### -sA (TCP ACK scan)
	its not used to determine open ports.
	its used to map out the rulesets of firewalls and determine if the devices are both stateful and which ports are filtered.
	the ACK bit its the only one set.
	Open/Closed ports will return a RST packet, nmap will mark as *unfiltered* = // there is no firewall
	ports that do not respond back, will then be labeled as *filtered* = // there is firewall blocking

#### -sO (IP protocol scan)
	enumerates the types of IP protocols that a target system supports
	are on the lookout For ICMP protocol unreachable messages
	if nmap receives any response in any protocol from the target host, nmap marks that protocol as open.

### OUTPUT Results
Nmap offers various options to output the results
we can save the results to inspect later or import them into tools such as:
	Dradis, Nessus, Faraday, Metasploit and so on.

The most used options:
```
-oN = The normal output will be stored into a file
-oX = Creates a XML output that can be easily parsed by various tools
-oG = Grepable output - deprecated. the output lists each host on one line.
-oA <file name> = output in the three major formats at once.
```

*There is also an advanced GUI called ZenMap = https://nmap.org/zenmap/*

> [+] info
we can use the option *--top-ports <number>* = to scan the most popular ports

> [+] info
show detailed list of every packet sent and received with nmap by using *--packet-trace* option
	https://nmap.org/book/man-output.html

> [+] info
TCP packet can be tagged with 6 different flags:
```
	Synchronize - SYN
	Finish - FIN
	Acknowledgement - ACK
	Push - PSH
	Reset - RST
	Urgent - URG
```

- And we can set the bit of the flag we wanna nmap scan with *--scanflags <flag>*


## Stealth mode - IDLE SCAN THEORY


-sI (Idle scan) 
	stealth technique that involves the presence of a zombie in the target network.
	a zombie is a host that is not sending or receiving any packets thus, the reason its called an idle scan.
	IP protocol implements a Fragmentation ID Header = https://tools.ietf.org/html/rfc791 and that many OS increase its value by 1 (For each packet).

### info about fragmentation
	Data must be encapsulated in order to be sent over the physical network link. In conjunction with this, the data has to be small enough to fit the format of the technology being used.
	the fragmentation process is basically, when data its too large it must be split into smaller messages.
	To the host be able to identify the fragments, its assigning a unique identifier to each fragment of the message called the *fragmentation ID*. This way the receiver knows the correct sequence of the fragments and can assemble them back into original message.
	by probing fragmentation IDs on the zombie, we can infer if a port is either open or closed on our target.

- pre-requisites:
	1. Find a zombie that assigns IP ID both incrementally and globally
	2. Find an idle zombie, meaning that there should be no other traffic on the zombie that will disturb the IP ID.

- How to find a good candidate zombie?
	OS fingerprinting with nmap / nmap nse option
	nmap will determine if the IP ID sequence generation is incremental (the one we need)
```
   → nmap -O -v <zombie ip>
   → nmap --script ipidseq <zombie ip> -p <zombie port>
```

- nmap shows the result > IP ID Sequence Generation is incremental, thus a good zombie

### before the attack
1. Probe the zombies IP ID and record its value
2. Forge a SYN packet with the source address of the zombie and send it to the port of our target host
	Depending on how the target reacts, it may or may not cause the zombie IP ID to be incremented.
3. Probe the zombies IP ID again and, pending upon the ID we can infer if the target port is open or closed

### once we discover a zombie
1. Probe the zombies IP ID by sendind a SYN/ACK to it
2. Since the communication is not expected, the zombie will send back a RST with its IP ID
3. Forge a SYN packets (IP spoofing) with the zombie source IP address and send it to the target we wish to scan.

#### if the port is open
4. The target sends back a SYN/ACK to the zombie
5. The zombie does not expect it therefore, it sends a RST back to the target and increments its IP ID
6. The attacker probes again the zombies IP ID
7. The zombie sends back a RST. The attacker sees that the IP ID is incremented by 2 (from the initial probe)

#### if the port is closed
4. The target sends back to the zombie a RST and the zombie simply ignores the packet leaving its IP ID intact
5. The attacker probes again the zombies IP ID
6. The zombie send back a RST and the attacker sees that the IP ID is incremented by only 1.

idle scan - open door:

![Alt text](/assets/images/posts/2023-11-19-ecppt/18.png){: .align-center}

idle scan - close door:

![Alt text](/assets/images/posts/2023-11-19-ecppt/19.png){: .align-center}


## Nmap NSE (Nmap Script Language)
> NSE allow us to write/use shared scripts that help automate various tasks
	The scripts are written in LUA programming language
	stored in /usr/share/nmap/scripts

- Usage
```
	-C or --script

--script-updatedb = to update nmap scripts
--script-help "smb*" and discovery = search For specific script
--script-help whois-domain
```

### domain info
```
--script whois-domain <ip> -sn = to run the whois script
```

### reconnaissance
```
--script smb-os-discovery = to run OS discovery
```

the same without NSE:
```
	-O = force nmap to perform OS fingerprint scan
	we can see, that the results of nse are much better
```

### smb shares
```
--script smb-enum-shares 

- run all authentication scripts
--script auth
```

> it will save time, but can be noisy cause it will execute a lot of scripts
```
- OS, workgroup, NetBIOS
--script default
```

## Extra scanning tools

Multi Plataform (Linux, Mac, Windows):
```
- Angry IP Scanner - http://angryip.org/
- Masscan = https://github.com/robertdavidgraham/masscan
```

Only Windows:
```
- SuperScan = http://www.mcafee.com/us/downloads/free-tools/superscan.aspx
```



## Service and OS Detection


### Banner Grabbing
> the message that the service, running on the targer host, sends back when another host tries to establish a connection to it.

tools:
```
	telnet, netcat, ncat 
	followed by <ip> <port>
```

### Probing services
	https://nmap.org/book/man-version-detection.html
```
	nmap -sV <options> <target ip>
```

### OS fingerprinting
	https://nmap.org/book/man-os-detection.html

passive:
	identifies the remote OS with packets that are received, without sending any packets.
active: 
	sends packets and waits For a response
	Nmap compares the results is obtains to its internal database of OS finferprints and, if there is a match, prints out the detected OS.
	https://nmap.org/book/osdetect.html
	http://phrack.org/issues/54/9.html#article
```
	nmap -O -n <target ip>
	-A = enables OS detection, version detection, script scanning and traceroute. good, but very noisy.
	--osscan-guess = guest the OS more aggressively
```

- There is a Passive option:
	P0f = http://lcamtuf.coredump.cx/p0f3/
	http://lcamtuf.coredump.cx/p0f3/README
```
	./p0f -i eth0
```



## Firewall / IDS Evasion
two main issues:
	becoming exposed
	obtaining incorrect results

### Fragmentation
	its the process of splitting a single packet into smaller ones
	this can disable the ability of some firewall and IDS systems to either apply their packet filtering rules or to process all the fragments.
```
	nmap -sS -f <target ip>
	// -sS = SYN scan // -f = fragment packets
	// --mtu = specify a custom offset size. must be a multiple of eight

	sudo nmap -f -sS -p 80,21,153,443 -Pn -n --disable-arp-ping

	--data-length 100 = add 100 bytes to our payload
	-f -f = this cause the fragmented bytes to be 16 bytes instead 8 bytes
```

### Decoys
	add noise to the IDS by sending scans from spoofed IP addresses. As a result, a list of forged IPs (decoys) will appear on the IDS, along with the real attacker IP. This confuses the analysts watching the system, making it harder to identify the actual attacker.

1. All decoys are up and running (otherwise its easy to determine the real attackers IP)
2. The real IP address should appear in random order to the IDS (otherwise its easy to infer the real attacker IP)
3. ISPs traversed by spoofed traffic let the traffic go through

```
	nmap -sS -D <decoy ip#1>,<decoy ip#2>,ME,<decoy ip#3> <target ip >
	// -D = decoy (no spaces after and before comas)
	-D RND:10  = 10 random decoys, even if they dont exist in the network

	hping3 --rand-source -S -p 80 <target ip> -c 3
	hping3 -a <spoofed ip> -S -p 80 <target ip> -c 3
```


### Timing
	slow down the scan in order to blend with other traffic in the logs of the Firewall/IDS
	you can define the interval between two scan probes, thus decreasing the chances to being noticed

```
	nmap -sS -T[0-5] <target ip>

	// -T0 - Paranoid - 5 min
	// -T1 - Sneaky   - 15 sec
	// -T2 - Polite      - 0,4 sec
	// -T3 - Normal   - default
	// -T4 - Aggressive - 10 millisec
	// -T5 - Insane    - 5 millisec
```

### Source Ports
	its used to abuse poorly configured firewalls that allow traffic coming from certain ports
	we can change our source port in order to bypass this restriction

```
	nmap -sS --source-port 53 <target ip>
	// using -sS or -sU
	// --source-port <port number> // -g <port number>

	// hping3 -S -s 53 -k -p 53 10.50.97.25
	// -k = keep this port // -s = source port
```


### Append random Data to the header payload
nmap
```
	--data-length <10>
```

hping
```
	--data <10>
```

### Mac address spoofing
nmap
```
	--spoof-mac apple/dell/etc = specify a vendor mac
	--spoof-mac 0 = specify a random mac
	--spoof-mac 00:11:22:33:44:55 = fixed mac
```

### Random Host
nmap
```
	mkdir host.list > insert some hosts
	// -iL host.list (use host of file) 
	// --randomize-hosts (host sequence scan is random)
```

hping
```
	--rand-dest 192.168.2.x
	-I <interface>
	-i u10 ( add 10 microseconds of delay between scans)
```


> more information about bypassing firewall / IDS
http://nmap.org/book/man-bypass-firewalls-ids.html




