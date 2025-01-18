---
title: USB 2 - 2020 Defenit CTF
date: 2020-06-07 22:48:20
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
 - Forensics
 - Registry
tags:
 - Windows Registry Analysis
 - Defenit
---

**tl;dr**

+ Digging into windows registry to find process run counts.
+ Extracting and parsing AmCache to find the hash of process images

<!--more-->

**Challenge points**: 766
**No. of solves**: 6
**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar) & [g4rud4](https://twitter.com/NihithNihi)

## Challenge Description

![Challenge-Description](description.png)

The challenge file can be downloaded from [Google Drive](https://drive.google.com/drive/folders/1xWIDVxxr6gGL6w-7K2KNwDmanADfKMDW).

## Initial Analysis

We are provided with the file `usb.ad1`. From the extension, It was quite clear that the evidence was acquired via Access Data's FTK Imager. So let us go ahead and load the file in FTK Imager.

We observe that only very few directories are present and our objective is to find the answer to the following questions so that we can combine them to get the flag. So let us dig in.

## Answering Question 1

Question 1: `Among the exe files, there are several files executed on the same USB. Let's call the second executed file 'A'. What is the name of 'A'?`

So we have to find what processes were run when the USB was loaded. Well, we normally know that Sysmon records the events of process creation. However, Sysmon is not enabled in any system by default and when we analyzed the event logs, we did not find any trace of Sysmon as well. So this approach wouldn't work.

However, we found the presence of `NTUSER.DAT` in the system.

![NTUSER](ntuser.png)

**Path**: `[root]/Users/james`

There are a lot of tools to view registry files. Here I am using **Registry Explorer** from Eric Zimmerman.

**Path**:`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`

This sub-key gives us the list of processes that were run with timestamps and also how many times they were run.

![UserAssist](userassist.png)

To know which process was run on the USB, we first have to know when the USB was loaded. For this, we use the `SYSTEM` registry to determine the `Last Installed` time of the USB on the system.

**Path**:`ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C531001461206123040&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066`

We can see the last write time as `2020-05-17`. So from this small detail, we can easily eliminate a lot of processes. However, we also found out that the USB was plugged-in/used ~ 19:00 Hrs as well. We found this from the `.lnk` files created in the system.

![RecentApps](recentapps.png)

`.lnk` files are created whenever a file/folder is opened. In this case, we find a **USB (E).lnk** created on `2020-05-17 19:11:36 Hrs`

So we can now even accurately predict the process. We only want to locate the 2 processes closest to this timestamp and the second one in that is the answer. Observing closely, we see 2 processes pretty near the above timestamp.

|Program Name | Run Counter | Focus Count | Focus Time | Last Executed |
|:----:|:----:|:----:|:----:|:----:|
| E:\svchost.exe | 1  | 0 | 0d, 0h, 00m, 00s | 2020-05-17 19:11:00 |
| Microsoft.Windows.Explorer | 40 | 109 | 0d, 0h, 53m, 03s | 2020-05-17 19:10:13 |

Judging by the timestamp and my knowledge on the services given by processes, I chose `svchost.exe`

## Answering Question 2

**Question 2**: `How many times has 'A' been executed?`

Since we have determined the which process is 'A' (svchost.exe), from the above table, we can get the answer to this question from the value specified in the `Run Counter` column, we can see the svchost.exe was run `1` time.

## Answering Question 3

**Question 3**: `What is the sha-1 hash value of 'A'?`

We can get the process details from the `Amcache.hve` file. Luckily, this file was present in the system.

**Path**: `[root]/Windows/appcompat/Programs`

We can use Eric Zimmerman's tool [AmcacheParser](https://f001.backblazeb2.com/file/EricZimmermanTools/AmcacheParser.zip) to parse the files.

We extract the following files
+ Amcache.hve
+ Amcache.hve.LOG1
+ Amcache.hve.LOG2

Next, we use PowerShell to properly parse the files into `.CSV` format.

![amcache](amcache.png)

The excel file required in this case is the `Amcache_UnassociatedFileEntries.csv`.

![excel](excel.png)

So we now have the SHA-1 hash of the file as: `d68960b8ecb374dd98ef6a33fed45dddd9796402`

## Flag

Concatenating all the 3 answers gives us the flag.

**FLAG**: `Defenit{svchost.exe_1_d68960b8ecb374dd98ef6a33fed45dddd9796402}`