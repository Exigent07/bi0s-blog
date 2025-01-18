---
title: Ermittlung - InCTF Internationals 2021
author: g4rud4
author_url: 'https://twitter.com/_Nihith'
date: 2021-08-16 19:00:00
tags:
 - InCTFi
 - Volatility
 - Windows Memory Analysis
categories:
 - Forensics
 - Memory
---

**tl;dr**

+ Finding Chat application
+ Extract unread message count from NTUSER.dat.
+ Extract the last executed timestamp of the chat application.
+ Extract the Version of the chat application.

<!--more-->

**Challenge Points**: 140
**Challenge Solves**: 45
**Challenge Author**: [g4rud4](https://twitter.com/_Nihith)

## Challenge Description

![Description](description.png)

Download the challenge file from [here](https://drive.google.com/drive/folders/1mwjdM44ZySk4HZG-aDY880MoqAdFjPkZ?usp=sharing)

**MD5 Hash**: `ermittlung.raw 110305F3CF71432B4DFAFD1538CDF850`

## Initial Analysis

We are given with a memory dump. So let us find out the profile.

### Finding Profile

```bash
$ volatility -f ermittlung.raw imageinfo
```

![volatility profile](imageinfo.png)

I will be using `WinXPSP2x86`, as the profile for this challenge.

### Scanning active processes

As we don't know what all processes were running during the memory capture. Let us check the active processes in the system for better understanding.

```bash
$ volatility -f ermittlung.raw --profile=WinXPSP2x86 pslist
```

![Pslist](pslist.png)

We observe `firefox.exe`, `msimn.exe` are running.

### Listing Firefox history

Let us use `firefoxhistory` plugin to check any suspicious url. You can get this from [superponible](https://github.com/superponible/volatility-plugins) github repo.

```bash
$ volatility --plugins=volatility-plugins -f ermittlung.raw --profile=WinXPSP2x86 firefoxhistory
```

![firefox history](firefox_history.png)

Well there is nothing much in it which we can make use of.

## Answering 1st Question

> 1. What is the name of the chat application program?

### Finding chat application

We found `msimn.exe`, which a quick Google search or via using the plugin `cmdline`, we can find, this excutable is part of `Outlook Express`.

```bash
$ volatility -f ermittlung.raw --profile=WinXPSP2x86 cmdline -p 2132
```

![cmdline](cmdline.png)

Other than this, we couldn't find any other chat applications running on the system. We got our answer to the 1st question. Which is `Outlook Express`

We got the name of the chat application. Now, let us find out when was the last time this application executed.

## Answering 2nd Question

> 2. When did the user last used this chat application?

### Finding Last execution time 

We can find answer for this in 2 ways, One by checking the `start time` from the pslist and another from registry.

#### PsList

![Last Execute PSLIST](pslist_le.png)

#### Registry

Using `UserAssist` from NTUSER.dat, we can also find the last executed time of Outlook Express. Let us use `userassist` plugin.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f ermittlung.raw --profile=WinXPSP2x86 userassist
```

![UserAssist](userassist.png)

As highlighted, we get the last execution time as `2020-07-27 12:26:17`. Converting that to the format mentioned in the description would result in `27-07-2020_12:26:17`.

## Answering 3rd Question

> 3. How many unread messages are there in the chat application that the user is using?

### Finding message count

We find the message count from NTUSER.dat registry hive. Let us dump the NTUSER.dat registry hive.

To dump the registry hive, 1st we need to find the virtual address of the NTUSER.dat. For that we can use `hivelist` plugin and list all hives.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f ermittlung.raw --profile=WinXPSP2x86 hivelist
```

![hivelist](hivelist.png)

NTUSER.dat is located at `0xe1aa5b60` offset, now we can use `dumpregistry` plugin to dump the registry hive.

```bash
$ volatility -f ermittlung.raw --profile=WinXPSP2x86 dumpregistry -o 0xe1aa5b60 -D output
```

![dump registry](dump_registry.png)

We can use our preferred registry viewer to open the dumped registry hive.

We can got to this `Software\Microsoft\Windows\CurrentVersion\UnreadMail\` hive, where we can find the count of unread messages under the email used in Outlook Express.

![Unread messages](unread_messages.png)

From the register, we get Message Count as `4`.

**Note**: We can also use volatility's `printkey` plugin to retrieve the Message Count from registry.

## Answering 4th Question

> 4. What is the current version of the chat application that's being used?

### Finding version of chat application

Version that the chat application is using can be found in NTUSER.dat or by dumping the process from memory and checking out the little endian strings.

#### From Registry

As we have already dumped NTUSER.dat registry hive, we can got this `Software\Microsoft\Outlook Express\5.0\Shared Settings\Setup` hive, and the sub-key `MigToLWPVer` gives us the version of the chat application being used on the system.

![version](version_registry.png)

#### From Process dump

From the pslist we can see that the executable is running at PID 2132. We can use `procdump` plugin and dump the process. 

```bash
$ volatility -f ermittlung.raw --profile=WinXPSP2x86 procdump -p 2132 -D output
```

![procdump](procdump.png)

Now, we can use `strings` commands, to get all the little endian strings from the dumped executable.

![le-strings](le_strings.png)

As highlighted, the version of the application is `6.0.2900.5512`.

## Flag

Concatinating all answer, we can get the flag.

**inctf{Outlook_Express_27-07-2020_12:26:17_4_6.0.2900.5512}**

For further queries, please DM on Twitter: https://twitter.com/_Nihith
