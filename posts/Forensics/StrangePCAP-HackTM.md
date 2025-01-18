---
title: Strange PCAP - HackTM CTF Quals 2020
date: 2020-02-10 21:42:34
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
  - Forensics
  - Network
tags:
  - HackTM
  - Wireshark
---

**tl;dr**
+ Disk Dump extraction.
+ USB leftover Capture data extraction.
+ Zip file cracking.

<!--more-->
**Challenge points**: 144
**No. of solves**: 89
**Solved by**: [g4rud4](https://twitter.com/NihithNihi) & [f4lc0n](https://twitter.com/theevilsyn)

## Challenge Description

![Challenge Description](description.png)

## Initial Analysis

We found that the given network capture contains the USB traffic. Their communications captured are between a few USB devices to the HOST. One of them is a Mass Storage Device and the other is a Keyboard.

## Further Proceeding

The Mass Storage Device is actually carrying a FAT32 Disk Dump. We extracted the data transfered using scapy
```python
#!/usr/bin/env python
from scapy.all import *
r=rdpcap("Strange.pcapng")
x=""
for i in range(254, len(r)):
    if(len(str(r[i].load))> 530):
        x+=r[i].load
f=open("disk.img",'w').write(x)
```
As the extracted file seems to be a disk dump, we can extract the contents using binwalk.
```
$ binwalk -e disk.img
```

We have found a zip file in the binwalk output. So after extracting it and opening it, it asked for a password.

![binwalk output](binwalk.png)

As said earlier, there is some USB Keyboard data is being transferred. So kept a filter **usb.capdata** for getting the leftover capture data and storing those into another pcap and running the code given below, will get the password for the zip file.

Here is the code for extracting the USB Hid Keys,

```python
import os

os.system('tshark -r capdata.pcapng -T fields -e usb.capdata > data.txt')

f=open('data.txt','r').readlines()

a=[]

for i in range(len(f)):
    if(len(f[i])==24):
        a.append(f[i])

a=''.join(a)

g=open('capdata.txt','w').write(a)

usb_codes = {
   0x04:"aA", 0x05:"bB", 0x06:"cC", 0x07:"dD", 0x08:"eE", 0x09:"fF",
   0x0A:"gG", 0x0B:"hH", 0x0C:"iI", 0x0D:"jJ", 0x0E:"kK", 0x0F:"lL",
   0x10:"mM", 0x11:"nN", 0x12:"oO", 0x13:"pP", 0x14:"qQ", 0x15:"rR",
   0x16:"sS", 0x17:"tT", 0x18:"uU", 0x19:"vV", 0x1A:"wW", 0x1B:"xX",
   0x1C:"yY", 0x1D:"zZ", 0x1E:"1!", 0x1F:"2@", 0x20:"3#", 0x21:"4$",
   0x22:"5%", 0x23:"6^", 0x24:"7&", 0x25:"8*", 0x26:"9(", 0x27:"0)",
   0x2C:"  ", 0x2D:"-_", 0x2E:"=+", 0x2F:"[{", 0x30:"]}",  0x32:"#~",
   0x33:";:", 0x34:"'\"",  0x36:",<",  0x37:".>", 0x4f:">", 0x50:"<"
   }
l = ["","","","",""]
 
pos = 0

for x in open("capdata.txt","r").readlines():
   c = int(x[6:8],16)

   if c == 0:
       continue
   # newline or down arrow - move down
   if c == 0x51 or c == 0x28:
       pos += 1
       continue
   # up arrow - move up
   if c == 0x52:
       pos -= 1
       continue
   # select the character based on the Shift key
   if int(x[0:2],16) == 2:
       l[pos] += usb_codes[c][1]
   else:
       l[pos] += usb_codes[c][0]

print l[0]
```
The zip file password is: **7vgj4SSL9NHVuK0D6d3F**

## Flag

Unarchiving the zip file using the above password, gives us the flag.

Flag: **HackTM{88f1005c6b308c2713993af1218d8ad2ffaf3eb927a3f73dad3654dc1d00d4ae}**