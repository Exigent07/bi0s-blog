---
title: Investigation Continues - InCTF Internationals 2020
date: 2020-08-04 12:03:06
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
  - Forensics
  - Memory
tags:
  - Windows Memory Analysis
  - Windows Registry
  - Volatility
  - InCTFi
---

**tl;dr**

+ Extract Invalid Login timestamp from the windows registry.
+ Extract the timestamp of when a JPEG was opened.
+ Extract Google Chrome's last run time which was pinned to taskbar from windows registry.

<!--more-->

**Challenge points**: 872
**No. of solves**: 18
**Challenge Author**: [stuxn3t](https://twitter.com/_abhiramkumar)

## Challenge description

![Description](description.png)

You can download the file from here: [Google drive](https://drive.google.com/file/d/1rIo-oQ8xyyWGLO6pzsEYPeHxQ7DTa-e7/view).

## Initial analysis

We are provided with a Windows memory dump. I'll be using **Volatility** to analyze, extract relevant artefacts. I will also be discussing an alternate method to solve this challenge without using Volatility as well.

### Finding the profile

We shall use the `imageinfo` plugin to find the profile of the memory dump

`$ volatility -f windows.vmem imageinfo`
![imageinfo](imageinfo.png)

So let us use the profile as `Win7SP1x64`.

## Answering 1st question

Question 1: `When was the last time Adam entered an incorrect password to login?`

The windows registry hives store a lot of detail related to a user. Some of them include the `username`, `last login`, `last invalid login` etc... So, as far as the challenge is concerned, we need to dig up when Adam last entered an incorrect password.

So, first, we shall use volatility to list out the registry hives present in the memory.

`$ volatility -f windows.vmem --profile=Win7SP1x64 hivelist`
![hivelist](hivelist.png)

To collect the user account details, we dump the SAM registry hive.

`$ volatility -f windows.vmem --profile=Win7SP1x64 dumpregistry -o 0xfffff8a0018f0410 -D .`

![sam](dumpregsam.png)

We will use Eric Zimmerman's `Registry Explorer` to inspect the hive.

**PATH**: `SAM\Domains\Account\Users`

![sam2](samreg.png)

As noted from the above image, we can see that an incorrect password was last entered on `2020-07-22 09:05:11`. Converting it to the format of the challenge gives `22-07-2020_09:05:11`.

## Answering 2nd question

Question 2: `When was the file 1.jpg opened?`

There are 2 approaches to answer this question. Since we are using the windows registry, I will discuss extracting the timestamp from the registry.

### Using the NTUSER.DAT hive

This timestamp can be found in the `RecentDocs` subkey in the `NTUSER.DAT` hive.

**PATH**: `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.jpg`

![recent](recent.png)

So as highlighted in the above image the timestamp is `2020-07-21 18:38:33` and converting it the format gives `21-07-2020_18:38:33`.

### From the MFT

The alternate approach would be to use the `mftparser` plugin and extract the timestamp.

`$ volatility -f windows.vmem --profile=Win7SP1x64 mftparser | grep -C 5 "1.lnk"`

We search for `.lnk` files because they are created when a file is accessed. So that would be our best resource.

![mft](mft.png)

As you can see we get the same timestamp from both the resources.

## Answering 3rd question

Question 3: `When did Adam last use the taskbar to launch Chrome?`

The question does not ask when chrome was last run but when was it last launched from the **taskbar**. We will use the same `NTUSER.DAT` hive to collect the information.

**PATH**: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count`

![userassist](userassist.png)

The timestamp, in this case, would be `2020-07-21 17:37:18`

## Flag

Concatenating the 3 answers gives us the final flag.

**FLAG**: `inctf{22-07-2020_09:05:11_21-07-2020_18:38:33_21-07-2020_17:37:18}`

For further queries, please DM me on Twitter: <https://twitter.com/_abhiramkumar>

## References

+ Registry Explorer
  + <https://ericzimmerman.github.io/>
+ Volatility command reference
  + <https://github.com/volatilityfoundation/volatility/wiki/Command-Reference>
