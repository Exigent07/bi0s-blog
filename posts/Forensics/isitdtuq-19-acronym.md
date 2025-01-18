---
title: Acronym - ISITDTU Quals 2019
date: 2019-07-08 20:36:07
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
  - Forensics
  - Steganography
tags:
  - Steganography
---

Full solution of Acronym challenge from ISITDTU Quals 2019.
tl;dr - Steganography
<!--more-->

**Challenge Points**: 826  
**Challenge Solves**: 23  
**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar) & [Nihith](https://twitter.com/NihithNihi)  

**Challenge Description**:  
<img src = "Acronym.png" align = "left">

We got a first blood in this challenge.

**Note**: As we understood later, the description does have a big role to play in solving the challenge.

We first download the following file Output.png but the file size is 9.2MB which was a little suspicious to me.  
So I went through the hex dump of the file and saw the header of another PNG.  

![Ghex](ghex.png)

After **IEND** of the 1st PNG, The header of the next PNG starts. You can extract that using “dd”  

So I extracted it out and got the following image (Also note that the Image you get after extracting is  
corrupted. Change the header from “82” to “89”).  

![pikachu](pikachu.png)  

There is a big clue in the image: **BLUE STEGO**.  So I instantly googled for any GitHub repo or tool with the  
name bluestego. And I found this link: <u>https://github.com/BinhHuynh2727/BlueStego</u>  

This tool was needed to get the flag but it also requires a key. Where do we find a key??  

So I tried some more tools on the same image and when using stegsolve(RED plane 0), I found a QR code  
hidden in the image.  

![stegsolve](stegsolve.png)

So after visiting the website, I searched around for a lot of time but I didn’t know what I was looking for.  
Finally, the word “DIFF“(Danang International Fireworks Festival) looked like a suitable acronym to be used as  
the key for the bluestego tool. Yes, I was right! DIFF is the key.  

Yes, then we got the flag.  

![flag](flag.png)

Yay!! The flag is **ISITDTU{D4N4NG_1S_MY_L0V3}**  
