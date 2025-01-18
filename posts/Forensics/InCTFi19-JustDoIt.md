---
title: Just Do It - InCTF Internationals 2019
date: 2019-09-24 09:43:08
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
+ Master File Table Analysis
+ Deleted file data recovery

<!--more-->

**Challenge points**: 271
**No. of solves**: 28
**Challenge Author**: [stuxn3t](https://twitter.com/_abhiramkumar/)

## Challenge Description

![challenge-Description](description.png)

You can download the challenge from [**Mega**](https://mega.nz/#!A6pARabZ!yS8_6WxfCcC8o544wAK8VVte46E9sPNAgth52hPQVOQ) or [**G-Drive**](https://drive.google.com/file/d/125Dm-5u2LiVqlFWMmpMbZGgpOwop8-G3/view).

## Writeup

This is a fairly simple challenge.

We are provided with a **Windows 7** memory dump. Let us begin our initial level of analysis.

```
$ volatility -f Mem_Evidence.raw --profile=Win7SP1x64 pslist
```
![pslist](pslist.png)

There is nothing quite interesting in the **pslist** output except for the **Sticky Note** process. Hmm, perhaps there is something written in it.

Just to keep it short, there was nothing important written in the clipboard. It was a small rabbit hole.

Now let us proceed to the files present in the system.

```
$ volatility -f Mem_Evidence.raw --profile=Win7SP1x64 filescan
```

![filescan](filescan.png)

There are interesting files present on the desktop. The files Important.txt & galf.jpeg are of special interest. Let us try to dump them :)

```
$ volatility -f Mem_Evidence.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003e8ad250 -D .
```
Now we have dumped the file **galf.jpeg**. However, doing basic steg techniques on the file yield nothing. So it is useless.

One important thing in the challenge and also the main exploit is to get the data present in the file **Important.txt**. However, dumpfiles will not be able to dump the required file as it has been deleted. However, its contents are still present in memory. If you fundamentally understand the Master File Table(MFT), you would know that we can access the data as long as the data blocks are overwritten.

For this, we take the help of the **mftparser** plugin.

```
$ volatility -f Mem_Evidence.raw --profile=Win7SP1x64 mftparser > mft_output.txt
```

So let us search for the data blocks of the file **Important.txt**

![mft](mft.png)

Aha! Now we see the characters of the flag separated by irregular number of spaces(Done intentionally).

So, the flag is: **inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}**
