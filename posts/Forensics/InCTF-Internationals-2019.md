---
title: ' "...---..." - InCTF Internationals 2019 '
date: 2019-10-10 19:50:12
author: f4lc0n
author_url: https://twitter.com/_f41c0n
categories:
  - Forensics
  - Network
tags:
  - BLE
  - Wireshark
  - InCTFi
  - Morse Code
---
Write-Up for the "...---..." challenge from InCTF Internationals 2019

tl;dr
1. Alert signals encoded in morse transfered to the Mi-Band
2. Traverse through the packets and find the appropriate BLE handles of the encoded message
3. Decode the morse encoded message

<!--more-->
**Challenge Points**: 216 
**Challenge Author**: [f4lc0n](https://twitter.com/_f41c0n)


## Challenge Description

I recently bought a MiBand and started exploring what crazy stuff I can do with it. Maybe this capture helps you find it yourself.

Note: Please submit the flag as inctf{sha1(FLAG IN CAPITALS)}

## Write-Up

This challenge is pretty straight forward.

We are provided with a network capture when a MiBand is recieving an encoded message. 
So, if we go throught the packets, we see that the text "Sending Encoded Message" is being sent to the MiBand.
![SendingEncodedMSG](SendingEncodedMessage1.png)
![SendingEncodedMSG](SendingEncodedMessage2.png)


And after that message is sent, we observe a pattern in the packets being sent to the MiBand.
We see that packets contain handles which point to the Alert Level of the message they carry. In this challenge there are three handles which point to 

+ "High Alert"
+ "Mild Alert"
+ "SMS/MMS Arrives"

## Extracting the Encoded Message

So, after figuring out what handles point out to which character in the morse encoded message, we use scapy to solve the challenge. As of now, we have two handles 0x12, 0x52. In 0x52 handle, we have two sub-categories (High Alert, Mild Alert)

If we map the handles with the morse characters, 

**Handle 0x52** with 0x01 in the trailing data: Mild Alert - Corresponds to **'.'** in the morse code
**Handle 0x52** with 0x02 in the trailing data: High Alert - Corresponds to **'-'** in the more code
**Handle 0x12**: SMS/MMS Arrives- Corresponds to **' '** in the morse code
	

```python
#!/usr/bin/env python2

from scapy.all import *
r=rdpcap("Challenge.pcap")

flag = ''

for i in range(len(r)):
    try:
        if str(r[i])[12]==chr(0x52):     # The handle 0x52 indicates an alert message is being transfered
            if str(r[i])[-1]==chr(0x01): # 0x01 in the packet indicates mild alert
                flag+='.'
            elif str(r[i])[-1]==chr(0x02): # 0x02 indicates high alert 
                flag+='-'
        elif str(r[i])[12]==chr(0x12): # The handle 0x12 indicates an empty message being transfered
            flag+=' '
    except:
        pass

print flag
# The above script prints
.- - - .- -.-. -.- .- - -.. .- .-- -.
```
Translating the above morse code, we get 'ATTACKATDAWN'.

## Flag

As given in the description, flag is inctf{sha1(ATTACKATDAWN)}

So, the flag is **inctf{14c8cfaa269659f52dd76cce43469554cfd5aedc}**



