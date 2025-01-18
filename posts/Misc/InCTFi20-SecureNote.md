---
title: Secure Note - InCTF Internationals 2020
date: 2020-08-14 20:08:25
author: 4lph4
author_url: <https://twitter.com/__4lph4__>
categories:
  - Misc
tags:
  - Master Challenge
  - InCTFi
---

**tl;dr**

+ Challenge involves Reversing, Web, and Crypto
+ Reverse the binary to get the endpoints
+ Trigger the XSS bug in the website and get admin cookie
+ Use Hash Length extension attack to get authenticated as admin and get the flag

<!--more-->

**Challenge points**: 1000
**No. of solves**: 1
**Challenge Author**: [r3x](https://twitter.com/Tr3x__) & [4lph4](https://twitter.com/__4lph4__)

## Challenge Description
Building Secure Applications is hard! But we tried. Can you get the flag from Secure Note?
You might need to dig deep into your skills for this one.
(PS: The challenge requires no automated testing tools! using them == instant ban)

The challenge file can be downloaded from [here](https://github.com/teambi0s/InCTFi/tree/master/2020/Misc/Secure-Note/Handout).


## RE part
We are given a binary and a GO web application initially. Endpoints of the website need to be figured out by reversing the GO binary. 

## Web Part
Website implements the following functionalities:
+ Register
+ Login
+ Add Note
+ View Note
+ Add a report
+ View report
+ Flag
+ Logout

Upon registering, every user will be given a user key. Also, the username of the user is stored in the cookie. After registering, on trying to access the flag, we get notified that admin access is required. Hence, to login as the admin one needs `admin username` and `admin key`. 

To get the admin username we have to exploit the XSS bug. XSS bug can be triggered by creating a note using /note/add having a payload to steal the admin cookie and reporting the note. When admin views the reported note, attacker will get the cookie.

The XSS bug is only triggered in the /report/note since it's printed out using `fmt.Printf` and not using go templates. This can be figured out by reversing the binary and looking at the endpoints.

So we have the admin username. Now we can spoof the admin username in the cookie. But we also require to give the secret key of the admin to get authenticated.
Note that - you cannot regiser another user containing the admin username at this point, since the /user/register checks if the username contains the admin username.

## Crypto part

On digging deeper one can notice that - 
`secret key = MD5(secret + username)`

We have the username of admin now, but we don't have the secret, so how can we get the user key? Another bug is that the check in the `/inCTF/flag` endpoint only checks whether the username conatins the admin_username.

MD5 is vulnerable to hash length extension attacks. We have to perform hash length extension attack to generate a new usename, key pair satisfying the conditions.

The length of the secret is not known so has to be brute forced.

Note that the session does not store the username - but takes it from the user cookie. This makes it possible for us to change the username in the cookie to whatever we want.

Steps to exploit 
- Register a new user with a random username
- note the secret_key of the new user
- generate a new key such that secret Md5(secret + username + padding + admin_username) == key
- Once we generate a new key, we change the local cookie to be base64(username + padding + admin_username)
- and we give the key as the parameter for the `/inCTF/flag` endpoint

## Flag

**FLAG**: `inctf{You_are_the_master_of_the_categories!}`

For further queries, please DM me on Twitter: <https://twitter.com/__4lph4__>.
