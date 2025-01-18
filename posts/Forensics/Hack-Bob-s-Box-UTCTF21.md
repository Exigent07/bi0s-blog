---
title: Hack Bob's Box - UTCTF21
date: 2021-03-15 10:24:47
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
 - Forensics
 - Network
tags:
 - UTCTF
 - FTP
 - Firefox History
---

**tl;dr**

+ Anonymous login to FTP server.
+ Retrieve SSH login username and password from Firefox History

<!--more-->

**Challenge Points**: 930
**No. of solves**: 85
**Solved by**: [g4rud4](https://twitter.com/NihithNihi), [f4lc0n](https://twitter.com/theevilsyn)

## Challenge Description

Hack Bob's box!

nmap is allowed for this problem only. However, you may only target `misc.utctf.live:8121` and `misc.utctf.live:8122` with nmap.

## Initial Analysis

We are given 2 servers where one has an FTP server and the other has SSH. We don't know the username and password for the SSH. Our 1st assumption was the FTP server might be having the details related to the SSH. We don't the username and password for the FTP server, let try if the FTP server is having any `anonymous user` login.

![anonymous-login-success](anonymous-login-success.png)

## Listing out files from FTP Server

Now we logged into the FTP server, lets see what all files present in this server. When we tried to `LIST` out the files in the server we got `425 No data connection` as a message. So we need to have a data connection for getting the data.

We have `PORT` command, for establishing a secondary connection for data transfer. **PORT** command has six number series(ex: `PORT 127,0,0,1,10,10`). 

Let us see what this decodes to:
+ The first four numbers indicate the client's IP
+ Next 2 numbers indicate the PORT number where the server establishes a connection to the client.
    + `num(5)*256 + num(6) = Port number` => `10*256 + 10 = 2570`

So let us try to set the connection to localhost on port 2570. But we got an error saying `500 I won't open a connection to 127.0.0.1 (only to 35.238.186.24)`. It is saying it can attempt to connect for local IP only.

Once we changed the localhost to our local IP, we got a reply saying it was successful. Then let us try to `LIST` the files present on the server. And we got the files listed out on localhost on port 2570.

![file listing](file-listing.png)

In the screenshot we can see that we have the `.ssh` folder, so let's see if we can retrieve the `PRIVATE` and `PUBLIC` key.

## Retrieving the Public and Private keys

Let us list out the contents of the `.ssh` folder.

![list-ssh-folder](list-ssh-folder.png)

So we got to know that we have the public and private keys present on the server. So let us dump those keys.

We have `RETR` command to extract the files from FTP server. On executing these two commands, `RETR .ssh/id_rsa` & `RETR .ssh/id_rsa.pub`.

**Private Key**:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

**Public Key**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxfP5AJNl4afX3QFRBF19E6rVCbL+9fNXEt6P3JUU396GM0uSi4TAlO3xQg2o6fbPAPdAWYzmMAmhsPJ1d7W3So8sQLRuiADLs7rlGLI3WvE0k6NswC/P0B2DYQ0yn0GBO4j9OXITnfKlWbNhh6RCGp30nEtncqYR0wZGgMxPywZxOCLYIX0Tn+63JrJOZ7SAv/v2w9TYY+HVy0t8Qi7wIFv33uIKsa6ov4jMLl8uwRPqDWTh5S3d1cMhHcIF0wyP9f5eR70Xz1cCRHb7KwVJiwuQvGLCzUAcgn6j0peRbc2fGg9RCiCYB/7mjsX1oisMoheRTTsPc84a3ewC8AHDIj32zKgzPg1iLeXtrfAtGQCAgizUerU8nUKZX1kTei2M4dnRUMj6npQ9MXIgVXUbFJeCo5xLUjrhJb9gXZ9kVx7n29M28JwJh3oCbfmwczAbCgmIyvF8rwpXEiH+eTxJG29H6QuhgQ+DR6+DYPtN//EfXNg2d94vP6adXNezphxM= matthewp@streetpizza.attlocal.net
```

From the public key, we can get the username of the ssh server we need to login to. So we got the private key and the username. 

Let us try to login to the ssh server. But unfortunately, that private key is not getting accepted, that it's not the correct private key or username.

Let us see what all files present in other folders.

## Listing and retrieving files from Other folders

We have `.mozilla`, `docs` & `favs` folder left. Let us see what all files were present in the `docs folder`.

### Docs folder

We have 3 files present in this folder. Let us retrieve the contents from them.

```bash
drwxr-xr-x    2 0          0                4096 Mar 12 18:53 .
drwxr-xr-x    1 0          0                4096 Mar 12 18:53 ..
-rw-rw-r--    1 0          0                 508 Mar 12 06:45 letter.txt
-rw-rw-r--    1 0          0                 435 Mar 12 06:45 notes.md
-rw-rw-r--    1 0          0                 251 Mar 12 06:45 todo.txt
```

Let us see what all contents present in these files.

**todo.txt**
```
|       Bob's TODO List       |
-------------------------------
-text jeff about gme
-think of a bday gift for tom
-sell my gme stocks
-look up how to sell organs
-figure out what a short is
-check my website is secure
```
**notes.md**
```md
# 1/3/2021 Group Meeting

## Georgia's project
- something about APIs ???
- apparently, I have to do something with some newfangled language called Rust >:(

## Security team
- don't click on those emails that say you won a new laptop
  - even if they say you're the millionth visitor
- rain on my parade more, why don't you

## My presentation
- seemed like people responded really well
  - silence means everyone understood I think
```
**letter.txt**
```
Dear RobinHood employee,

As a user of your application, I was extremely disappointed to
find out that your platform had colluded with Citadel Securities
to protect their interests in shorting $GME. I had a considerable
amount of my life savings invested in this stock, and now I am
having to make difficult decisions about how to pay rent this
month. Hopefully you can appreciate the difficulty that you have
caused me and reinstate my account so I can sell my remaining
shares.

Best,
Bob Bobberson
```

In all these files, we can see the details about a person named `Bob`. From Bob's `todo list` we can see some info about a website. So let us check the Firefox history.

## Retrieving details from Firefox's history

Firefox stores its history in a file named `places.sqlite`, by dumping it and opening it in an SQLite viewer, We see a request for a website `http://bobsite[.]com/login?user=bob&pass=i-l0v3-d0lph1n5`. Where can see the username as `bob` and password as `i-l0v3-d0lph1n5`. So let us use them as the ssh login credentials.

## Retrieving flag

As we got the username and password, and ssh'ed into that server, and traversing through the root directory we got the flag.

![flag](flag.png)

## Flag

utflag{red_teams_are_just_glorified_password_managers}