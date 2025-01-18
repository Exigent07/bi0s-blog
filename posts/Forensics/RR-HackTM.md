---
title: RR - HackTM CTF Quals 2020
date: 2020-02-09 17:39:02
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
 - Forensics
 - Disk
tags:
 - RAID Recovery
 - HackTM
---

**tl;dr**

+ RAID recovery
+ JPEG image extraction from lost disk

<!--more-->

**Challenge points**: 298
**No. of solves**: 67
**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar)

## Challenge Description

![Challenge Description](challenge-description.png)

The challenge file can be downloaded from [Google-Drive](https://drive.google.com/open?id=1hPBksCtm3a4wGs9cd8DYkM4mcV0aNCEJ
) or [Mega-Drive](https://mega.nz/#!1MEQRCpD!YfSQZQSmKn520Jh8DCBb2Xh0ndqF_kPjgZsQIYtvH8A).

## Initial Analysis

When I downloaded the files, I observed that one of the images had no data in it. Also, the description provides us with information that one of the drives was lost. So I obviously concluded that the challenge involved RAID recovery.

![ll](ll.png)

The concept of RAID recovery is quite simple. You can simply obtain/recover the lost drive by **`xoring`** the others and rebuilding the RAID files might give me the flag. So let us get into it.

## XORing the images

As you can see in the image below, the drive `2.img` has been lost. So we have to XOR `1.img` and `3.img` to recover the original image.

For this, I used a simple tool called [XorFiles](http://www.nirsoft.net/utils/xorfiles.html)

Using this tool, I Xor-ed `1.img`, `3.img` and obtained the new file.

![XorFiles](Xorfiles.png)

## Carving out the JPEG

I initially thought of rebuilding the whole image, mounting it and then accessing the flag. However, I did not do that. I observed the hexdump of the file and found a JPEG image header.

![Ghex-JPEG](ghex.png)

So I knew just what to do. I simply used `dd` to carve out the file from the offset.

`$ dd if=new.img of=flag.jpg skip=69476332`

![dd](dd.png)

Well, the offset I used had some extra bytes at the start so we can simply remove till we get the start of the valid JPEG file signature.

![Extrabytes](extrabytes.png)

## Flag

After deleting the extra bytes at the start and opening the new image in any image viewer gives us the flag

![Flag](flag.jpg)

**FLAG**: `HackTM{1bf965b6e23e5d2cb4bdfa67b6d8b0940b5a23e98b8593bb96a4261fb8a1f66a}`

For further queries, feel free to message me on Twitter: https://twitter.com/_abhiramkumar