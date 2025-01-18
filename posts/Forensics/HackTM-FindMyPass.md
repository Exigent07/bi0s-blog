---
title: Find My Pass - HackTM CTF Quals 2020
date: 2020-02-09 18:02:39
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
 - Forensics
 - Memory
tags:
 - Windows Memory Analysis
 - HackTM
---

**tl;dr**

+ Memory dump analysis using Volatility.
+ Extracting Keepass Master Password from the memory.
+ Extracting flag from ZIP archive attached in the Keepass database.

<!--more-->

**Challenge points**: 474
**No. of solves**: 24
**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar)

## Challenge Description

![Challenge-descrption](Challenge_description.png)

The challenge file can be downloaded from [Google-Drive](https://mega.nz/#!IdUVwY6I!uJWGZ932xab44H4EJ-zVAqu6_UWNJcCVA4_PPXdqCyc
) or [Mega-Drive](https://drive.google.com/open?id=1hUlGqJZYgbWaEu7w0JnPMqgYdFr8qVJe).


## Initial Analysis

The challenge description tells us that the user lost his Keepass master password. So we need to retrieve the password from the memory and also it is provided that the database is also open when the memory dump was taken.

First, we need to find what OS his system was using. For this, I used the `imageinfo` plugin.

![Imageinfo](Imageinfo.png)

I chose the profile `Win7SP1x86`.

Since the description provides us with initial information stating that the Keepass database is open, one can easily expect that `Keepass.exe` will be running in the list of running processes.

![Pslist](Pslist.png)

![Pslist-Keepass](Pslist-Keepass.png)

So my thought process was correct and so the next step would be to extract the database file from the memory.

## Extracting the Keepass database

All KeePass database files have the extension `.kdbx`. So I used the `filescan` plugin to get the offset of the database.

![Filescan](filescan.png)

From the image above, we can see that the file `database.kdbx` is present at the offset `0x000000007df37c88`.

We can use the `dumpfiles` plugin to extract the file out.

![Dumpfiles](dumpfiles.png)

When I attempted to open the database, it asked for the master password. The challenge description tells us that the user forgot his password, which means that we have to recover it.

## Retrieving the Master Password

So one thing is certain. The database was "open" when the memory dump was taken. So we can also expect the master password to be loaded in the process's memory.

So let us use the `memdump` plugin to extract the process's memory. The process of interest, in this case, is the Keepass.exe with the `PID 3620`.

![Memdump](Memdump.png)

The password is obviously a readable ASCII character so let me extract what I need.

So for this, I extracted the readable data from the memory dump.

`strings -n 5 HackTM.vmem > new`

Now comes the tricky part. I now have to search where the Keepass database is loaded. It normally starts with an XML tag at the start.

![XML Header](XML-Keepass.png)

Going further down in the same file, I could see that an attachment (nothinghere.7z) was stored in the Keepass database. So this might be the file where our flag was stored.

![Nothinghere](Flag-details.png)

Going further down, I noticed a weird looking string (dmVZQmdzOlUrcEBlRj87dHQ3USVBIn) which I thought to be the password. So let us try it out.

Voila! It turns out that I got the master password. Now it is the final part - Getting the flag.

## Flag

As soon as I opened the database, I tried to retrieve the files present in the 7z archive. Unfortunately, the archive was password protected. At this stage, I pinged the admin asking whether brute force was needed to extract the flag. He told me that it wasn't needed and subsequently a hint was released which eventually implied that the user used the same password everywhere.

So now I tried the same password (database master password) on the archive. Yay! We successfully extracted the text file present in it and as expected, it contains the flag.

We also got the **FIRST BLOOD** in this challenge. So I was quite happy :)

**FLAG**: `HackTM{d14c02244b17f4f9dfc0f71ce7ab10e276a5880a05fca64d39a716bab92cda90}`

For further queries, feel free to message me on Twitter: https://twitter.com/_abhiramkumar