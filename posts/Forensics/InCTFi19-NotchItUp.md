---
title: Notch It Up - InCTF Internationals 2019
date: 2019-09-24 09:44:26
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
  - Forensics
  - Memory
tags:
  - Windows Memory Analysis
  - Volatility
  - InCTFi
---

**tl;dr**
+ Chrome history analysis
+ File recovery from the memory dump
+ Raw analysis of email content
+ Environment variables analysis
+ RAR password cracking
+ Corrupted file analysis

<!--more-->

**Challenge points**: 900
**No. of solves**: 11
**Challenge Authors**: [stuxn3t](https://twitter.com/_abhiramkumar/), [Sh4d0w](https://twitter.com/__Sh4d0w__) & [g4rud4](https://twitter.com/NihithNihi)

## Challenge Description

![Description](Notch_it_up_description.png)

You can download the challenge file at [**MEGA**](https://mega.nz/#!kypmTaLJ!cWChsh8CdTMTWt7Ae0oNiCFfrSXwK8vqEMGn0SO22JQ) or [**G-Drive**](https://drive.google.com/file/d/1bER4wmHP_LAMgdB52LGkb8x2Mf8hG3V6/view?usp=drivesdk)

## Writeup

We are provided with a **Windows 7** memory dump. Let us begin our initial level of analysis.

Let's start with the running processes.

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 pslist
```

![NotchItUp-pslist](pslist1.png)
![NotchItUp-pslist2](pslist2.png)

As seen above, we see chrome and firefox as active running processes. Let us see the history of google chrome here.
I have trimmed most of the content and only focussing on the relevant part of the history

```
$ volatility --plugins=volatility-plugins/ -f Challenge.raw --profile=Win7SP1x64 chromehistory
```
![NotchItUp-chromehistory](pastebin-link.png)

Hmm, we find an interesting **PasteBin** link. The link is: **https://pastebin.com/RSGSi1hk**

![NotchItUp-PasteBin](pastebin.png)

The Pastebin link contains another Google Docs link, lets head there. The docs link is: [click here](https://www.google.com/url?q=https://docs.google.com/document/d/1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk/edit?usp%3Dsharing&sa=D&source=hangouts&ust=1566208765722000&usg=AFQjCNHXd6Ck6F22MNQEsxdZo21JayPKug)

![Google-Doc](docs_with_mega_link.png)

The doc contains a lot of spam but we find one interesting link which leads us to a mega drive: **https://mega.nz/#!SrxQxYTQ**.

However, to download the file present in the mega drive, we need to find the KEY. However, the text in the Pastebin link tells us that "David sent the key in mail".

Okay, let me use the **Screenshot** plugin. Maybe it'll help.

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 screenshot -D .
```

![NotchItUp-Screenshots](screenshot.png)

We see that the browser window is open and also that GMail is open with the subject **Mega Drive Key**. Now it is the time to begin a little raw analysis. So a small intro. The data, when loaded into ram, is not encrypted, so basically, whatever you type in the browser window or load in it is saved as a sort of JSON data. So we just have to locate some JSON sort of data which contains our subject string "Mega Drive Key". Let us see if we can get the email data.

So what I did was use the command **strings**. Simple.
```
$ strings Challenge.raw | grep "Mega Drive Key"
```
![NotchItUp-strings](Mega-key.png)

So the key is **zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU**.

So we find a PNG image in the drive. However, PNG is corrupted. Fixing the IHDR of the image gives us the 1st part of the flag.

![NotchItUp-1stpart](flag1.png)

The first part is: **inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_**

Now moving onto the second part,
Let us use the filescan plugin to find what kind of open-files are present in the system.

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 filescan | grep Desktop
```
In the desktop of the system, we see a folder by the name **pr0t3ct3d**. It contains a RAR archive with the name **flag.rar**

![NotchItUp-filescan](filescan.png)

Let us dump the RAR archive with the help of the dumpfiles plugin.

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000005fcfc4b0 -D .
```
However, the archive is password protected. Also, brute-forcing for the password is not at all intended. So let us look for some other clues which may help us to get the password of the archive.

Using the **cmdscan** plugin, we see that **env** command has been used but that is an invalid command in windows command prompt. So let us look at the state of the Environment variables.

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 cmdscan
```
![cmdscan](cmdscan.png)

```
$ volatility -f Challenge.raw --profile=Win7SP1x64 envars
```

We observe a custom variable created named **RAR password**.

![NotchItUp-Env](envars.png)

So it gives out the password as **easypeasyvirus**. Now we get the last part of the flag.

![NotchItUp-flag2](flag2.png)

So now let us concatenate the 2 parts to finish off the challenge.

FLAG: **inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_aN_Am4zINg_!_i_gU3Ss???_}**
