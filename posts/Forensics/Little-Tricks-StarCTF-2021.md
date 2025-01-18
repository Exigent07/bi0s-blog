---
title: Little Tricks - StarCTF 2021
author: g4rud4
author_url: 'https://twitter.com/NihithNihi'
tags:
  - Disk Encryption
  - Bitlocker
  - StarCTF
categories:
  - Forensics
  - Disk
date: 2021-01-28 23:09:23
---

**tl;dr**
+ Decrypt the bitlocker encrypted drive
+ extracting the flag from deleted PDF

<!--more-->

**Challenge points**: 246
**No. of solves**: 62
**Solved by**: [g4rud4](https://twitter.com/NihithNihi), [stuxn3t](https://twitter.com/_abhiramkumar), [v1ru5](https://twitter.com/SrideviKrishn16), [d3liri0us](https://twitter.com/d3liri0us_)

## Initial Analysis

We are given a VHDX file, you can download the file from [here](https://drive.google.com/file/d/1V7TmLrCtFM6zdKwXHh77zW3NqsUWU6Wl/view?usp=sharing). The file signature of the given VHDX file is also in format. 

## Mounting VHDX file

We can mount the VHDX file by double-clicking the VHDX file. On mounting the file we got a pop-up asking for the bit-locker password.

Now we need to find the password of the BitLocker encrypted drive. 

![](load-vhdx.png)

## Cracking the password

On searching online found a tool [BitlockCracker](https://github.com/dev0p0/BitLockerCrack) for brute-forcing the BitLocker password. But brute-forcing `10^48` is not possible so the same Github user provided a link to [bitcracker](https://github.com/e-ago/bitcracker).

The bit cracker is made simple for cracking the password. As it resulted with the hash, which can be cracked with `John the Ripper`.

Here is what we got after building the bit cracker tool.

```bash
$ ./build/bitcracker_hash -i ../ll2.vhdx

---------> BitCracker Hash Extractor <---------
Encrypted device ../ll2.vhdx opened, size  132.00 MB

************ Signature #1 found at 0x1400003 ************
Version: 8
Invalid version, looking for a signature with valid version...

************ Signature #2 found at 0x5500000 ************
Version: 2 (Windows 7 or later)

=====> VMK entry found at 0x55000a7
Encrypted with User Password (0x55000c8)
VMK encrypted with AES-CCM
======== UP VMK ========
UP Salt: 212afe1afbb733f18b043338d85c4744
UP Nonce: 80ad0e8486ead60103000000
UP MAC: 01c1f4b616a85eecbd9d090ba2f0cbf5
UP VMK: 642f6591ff2abdf1df84e3fc33240b714e5fd280f03b7b4fbb8fe6f58dcea572f1258671c7d42748c76097ed

=====> VMK entry found at 0x5500187
Encrypted with Recovery Password (0x55001a8)
Searching for AES-CCM (0x55001c4)...
        Offset 0x5500257.... found! :)
======== RP VMK #0 ========
RP Salt: b044a4ad4fc868f736d0baf7ef47a9ea
RP Nonce: 80ad0e8486ead60106000000
RP MAC: 58fe021061ac9673d8925324f7a35304
RP VMK: 3381445679ab17420c05c408a728775c3fde50f1333b720a876dab4cc850e29078aa257dab9f4f690be0fb81

************ Signature #3 found at 0x64c8000 ************
Version: 2 (Windows 7 or later)

=====> VMK entry found at 0x64c80a7
Can't define a key protection method for values (0,20)... skipping!

=====> VMK entry found at 0x64c8187
Encrypted with Recovery Password (0x64c81a8)
Searching for AES-CCM (0x64c81c4)...
        Offset 0x64c8257.... found! :)

This VMK has been already stored...quitting to avoid infinite loop!

User Password hash:
$bitlocker$0$16$212afe1afbb733f18b043338d85c4744$1048576$12$80ad0e8486ead60103000000$60$01c1f4b616a85eecbd9d090ba2f0cbf5642f6591ff2abdf1df84e3fc33240b714e5fd280f03b7b4fbb8fe6f58dcea572f1258671c7d42748c76097ed

Recovery Key hash #0:
$bitlocker$2$16$b044a4ad4fc868f736d0baf7ef47a9ea$1048576$12$80ad0e8486ead60106000000$60$58fe021061ac9673d8925324f7a353043381445679ab17420c05c408a728775c3fde50f1333b720a876dab4cc850e29078aa257dab9f4f690be0fb81

Output file for user password attack: "hash_user_pass.txt"

Output file for recovery password attack: "hash_recv_pass.txt"
```

Using John to crack the `User Password hash` we got `12345678` as the password for the BitLocker encrypted drive.

## Further Analysis

On opening the BitLocker encrypted drive, we found only one text file named `password`. And it has the password used for encrypting the drive.

But the drive has 14 MB filled files, but we can only see a text. Stuxn3t suggested to open the unlocked drive-in `FTK Imager` and check out the deleted files.

![](unlock-vhdx-drive.png)

There a PDF file deleted on opening the PDF found a fake flag.

![](fake-flag.png)

But we see some text highlighed back on that fake flag.

![](original-flag.png)

## Flag

`*CTF{59ca21b54198345f0efa963195e}`