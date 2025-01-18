---
title: Mapping the Digits - Week 1 - Magnet Weekly CTF
date: 2020-10-12 22:52:10
author: g4rud4
author_url: https://twitter.com/NihithNihi
tags: 
 - Magnet Weekly CTF
 - Autopsy
 - Android Forensics
categories:
 - Forensics
 - Android
---

**tl;dr**

+ Finding the last modified timestamp of the file that maps names to IP's accessed.

<!--more-->

## Description

![](description.png)

As the description says, we need to find the last modified time of a file that maps DNS names to IP's recently accessed.

I don't have much knowledge on Mobile Forensics. It is time to sharen my skills on Mobile Forensics. Magnet Forensics has decided for a weekly CTF, new challenge every Monday for the last quarter of 2020. You can find more info in the [blog post](https://www.magnetforensics.com/blog/magnet-weekly-ctf-challenge/) released by Magnet Forensics.

## Initial Analysis

With my limited experience in Mobile Forensics, I started to look for **hosts** file as it is responsible for mapping IP's to DNS names(Similar to Windows and Linux).

Let's go a head and load the Android Image in Autopsy. You can download the image [here](https://drive.google.com/file/d/1tVTppe4-3Hykug7NrOJrBJT4OXuNOiDO/view?usp=sharing). 

If you don't know how to load an Android Image in autopsy, found this [blog post](https://www.digitalforensics.com/blog/forensic-analysis-of-an-android-logical-image-with-autopsy/) and followed that and loaded the image in Autopsy.

After loading the android image in autopsy, on checking the files present on the device, I found something intersting in Downloads folder(`/data/media/0/Download`).

![](autopsy_downloads.png)

This seems to the required hosts file, Normally it won't be stored in any local folder, So to confirm I searched for the hosts file location in android device.

## Retrieving hosts file

Upon seaching for the hosts file location, got hit, saying that it will be stored in `/device/system/etc/system`.

![](hosts_location_net.png)

When I checked it, etc folder is not there in the mentioned location.

![](system_etc_system.png)

Upon searching and got an another hit saying that it will be stored in `adb` folder of the image. 

> Location: /adb/modules/hosts/system/etc/hosts

![](adb.png)

In the same way I am not able to view the metadata on Autopsy for that file.

As I have extracted the tar file, I went to that location and viewed the metadata of that file.

![](metadata_hosts.png)

Upon converting the timestamp `‎05 ‎March ‎2020, ‏‎11.20.18 AM` from IST to UTC, we get `‎05 ‎March ‎2020, ‏‎05.50.18 AM`

## Flag

> 03/05/2020 05:58:18