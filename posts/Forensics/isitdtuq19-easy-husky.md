---
title: Easy Husky - ISITDTU Quals 2019
date: 2019-07-08 20:36:07
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
  - Forensics
  - Memory
tags:
  - Windows Memory Analysis
---

**tl;dr** - Volatility + Corrupted file analysis
Full solution of Easy Husky challenge from ISITDTU Quals 2019.

<!--more-->

**Challenge Points**: 534  
**Challenge Solves**: 37  
**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar) & [Nihith](https://twitter.com/NihithNihi)  

**Challenge Description**:  
<img src = "Easy_husky.png" align = "left">

Okay, let us take a look at the challenge file. It is a WindowsXP memory dump.

Let us see the command history using the **cmdscan** plugin.

![Cmdscan](cmdscan.png)

They created a directory with the name **hu5ky_4nd_f0r3n51c**

Okay, let us have a look what files are present in the above-mentioned directory/folder.

![Filescan](filescan.png)

The file present in the folder is **f149999**

So let us dump the file by using the **dumpfiles** plugin.

![ghex](ghex.png)

As you can see it is reversed **RAR archive**. Just reverse the bytes to get the proper archive.

So after correcting the archive, we see that it is a locked archive. Hmm, have to search for the password.  
Luckily I guessed that the folder-name was in l33t, so it could be the password. Voila, and we got the flag.  

**ISITDTU{1_l0v3_huskyyyyyyy<3}**
