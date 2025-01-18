---
title: Fresh From The Oven - InCTF Internationals 2019
date: 2019-10-03 16:52:56
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
  - Forensics
  - Network
tags:
  - Wireshark
  - Stego
  - InCTFi
---

**tl;dr**

+ Decoding the strings found in TCP stream 0.
+ Analysing and extracting data sent via different ports of TCP.
+ Using character-wise caesar from the extracted data.
+ Zip cracking

<!--more-->

**Challenge points**: 879
**No. of solves**: 12
**Challenge Authors**: [Sh4d0w](https://twitter.com/__Sh4d0w__) & [g4rud4](https://twitter.com/NihithNihi)

## Challenge Description
![Description](description.png)

You can download the challenge file from [**Mega**](https://mega.nz/#!d6wEFICJ!u9XykRdIoJtloYDZQxFqXt1KvWR5aK3Ucisd2-a-qms) or [**G-Drive**](https://drive.google.com/file/d/1ZBLNYqFOA0dOx8e1GnNoO3qn2V0Elpcm/view?usp=sharing)

## Writeup

We are provided with a **pcap** file. Let's start our initial analysis.

We can see so many TCP packets in the capture file and the description says that it was a chat between two friends. So let's follow the TCP stream and see if anything is interesting in it.

![TCP Stream](tcp-stream-0.png)

We do see a chat between 2 people. Also, we can find some encoded strings. The secret code: **Remember remember the FIFTH of november :)** does hint out something. We can assume the encoded strings are **ROT5**. Decoding them, we get;

```
Rohith: This is a sample in that encoded way.

Shyam: Oh, It's good and it took a lot of time to understand for me.

Rohith: Sending you some interesting files, try to find the secret behind them and keep it confidential

Shyam: Okay, sure:)
```

As the chat between them says that some files have transferred. And we can see that from **TCP Stream 2**, extra data with **800 bytes** is transferred in two different destination ports(**444** & **81**). We can assume that the two files have been transferred.

Extracting the data sent to the above-mentioned ports and applying **Caesar cipher** on the two files, we get the file structure of a **PDF file** and a **ZIP file**.

![](file_pdf.png)

![](file_zip.png)

After opening the PDF and we find extra spaces in the last page of that file. It says "**NOTHING HERE :( DON’T WASTE YOUR TIME**".

So it's just a **rabbit hole**.

After a brief observation, we see that the ZIP is password protected. So, we use **fcrackzip** in dictionary mode to crack the password,

![zip cracking](zip_cracking.png)

The password is **johnjandroveclarkmichaelkent**.

Extracting the file from the zip gave a **PNG** image.

![flag](flag.png)

Simple LSB steg can be used to get the flag. We used the popular tool **zsteg** for this.

**FLAG**: inctf{3ach_4nd_3v3ry_s3cre7_inf0rm4t10n_w1ll_b3_kn0wn_by_wir3shark!!!!!_:)}
