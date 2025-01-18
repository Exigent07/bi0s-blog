---
title: Heist Continues - InCTF Internationals 2021
author: g4rud4
author_url: 'https://twitter.com/_Nihith'
date: 2021-08-16 19:00:10
tags:
 - USB
 - Slack
 - Windows Activity timeline
 - Anydesk
 - InCTFi
categories:
 - Forensics
 - Windows
---

**tl;dr**

+ Extract User ID and Workspace ID of the Slack workspace participating.
+ Extract the first & last 3 characters of text from the Anydesk Remote connected PC's thumbnail wallpaper.
+ Extract the type of filesystem of the USBs connected to the system.
+ Extracting active duration of Voice Modulator application used by parsing Windows Activity timeline.

<!--more-->

**Challenge Points**: 984
**Challenge Solves**: 7
**Challenge Author**: [g4rud4](https://twitter.com/_Nihith)

## Challenge Description

![description](description.png)

Challenge file is same as **Heist** Challenge. If you haven't downloaded it, you can download it from [here](https://drive.google.com/drive/folders/1H3Ly8hnAW7eh7dxvf_bTA7_JYk8zMP3-?usp=sharing)

## Answering 1st Question

> 1. What is the workspace ID and USER ID of the Slack workspace that is the user participating in?

As Slack is installed on the system. Slack stores it user logs at `Users\Danial Benjamin\AppData\Roaming\Slack`.

Main files of interest would be `000004.log` & `root-state.json` present in `Local Storage\leveldb` & `\storage\`.

+ **root-state.json** - It contains details about files download from a Slack Workspace and some metadata about the Workspace.
+ **000004.log** - Contains metadata details about the workspace, like Workspace name, User ID, Workspace ID, Icons etc.

Some of the usefull infomation that we can retrieve from **000004.log** are:

+ Workspace Name - Heist Planning
+ Workspace URL - heistplanning.slack.com
+ User ID - U027XK55WCT
+ Workspace ID - T027GM97WJ3

With the help of **root-state.json**, we can confirm the about details we retrieved.

![root-state.json](root-state.png)

As highlighed and confirmed with **000004.log**, We got the Workspace ID and the USER ID. Converting them to the format given in description, we get `T027GM97WJ3_U027XK55WCT`.

## Answering 2nd Question

> 2. There was a remote connection and we think there is a secret text on the remote connected PC's wallpaper. What are the first and last 3 characters of the secret text?

During the initial analysis of Heist challenges. We found out there are 2 Remote access application, TeamViewer & AnyDesk. Both of the these applications have their capabilities, but AnyDesk has something more.

AnyDesk stores the wallpaper of the Remote Desktop's as a thumbnail. We can find these thumbnails at `Users\Danial Benjamin\AppData\Roaming\AnyDesk\thumbnails`.

![AnyDesk Remote PC Wallpaper thumbnail](thumbnail.png)

We can find a string on the thumbnail. We are asked to provide the first & last 3 characters of the string found. Which will be `a27da2`.

## Answering 3rd Question

> 3. Team restored 2 USB devices (Sandisk 3.2Gen1 & Toshiba External USB 3.0) at the leader's place. What is the file system of these 2 USB devices?

We were asked to find the FileSystem of the USB devices connected to the system. 

### USB connection

**System** registry contains the details about USB devices connected to the system. From USBStor registry key we can find the list of USB devices connected to the system.

![USBs Connected](USB_connected.png)

As we highlighted, we have the 2 USB drives connected to system. Now we need to find the filesystem of these 2 USB devices.

### Finding FileSystem of USBs

Event logs are an another place where these details(USB connection/removal) are stored. The **Event ID 1006** is generated during USB insertion or removal, we can find this event ID in `Microsoft-Windows-Partition%4Diagnostic.evtx`, where this event log stores metadata information about both removal devices and internal hard disk of the computer. This event log contains information if someone plugs in or out one of these devices, after booting the computer.

Event logs is located at `C:\Windows\System32\winevt\Logs`. We can use Eric Zimmerman's [**EvtxExplorer**](https://ericzimmerman.github.io/#!index.md), to parse this event log to a CSV file.

Once the CSV is generated, we can filter out the CSV based on the model name of these 2 USB drives.

This is one of the [research paper](https://dfir.pubpub.org/pub/h78di10n/release/2) by *Alexandros Vasilaras, Evangelos Dragonas, and Dimitrios Katsoulis*, they have explained clearly what all artifacts can be extracted from `Microsoft-Windows-Partition%4Diagnostic.evtx`, that also contains how we can get the FileSystem that a particular USB drive uses.

![vbr0](vbr0.png)

Basically what we have to do is we need to decode the hexadecimal data present at `Vbr0`, that gives us the file system of the connected USB drives.

By decoding the hexadecimal bytes present at `vbr0` for both the USB drive, we got:

1. Sandisk 3.2Gen1 - **FAT32**
2. Toshiba External USB 3.0 - **NTFS**

No we can convert them in the format given in description, which results in `FAT32_NTFS`.

## Answering 4th Question

> 4. Team found some traces of Voice Modulator, How much time did the user actively used this Voice Modulator?

From Windows Version 1803, Windows introduced **Windows 10 Timeline**, which help forensics analysis to reconstruct user activities.

For Digital Forensics analysts, Windows Timeline provides information about applications that were executed on the computer such as application name, time when application launched, and application usage duration.

User activities are displayed in the timeline are stored in `ActivityCache.db` which is located at `C:\Users\<user>\AppData\Local\ConnectedDevicePlatform\L.<profile>\ActivitiesCache.db`.

### Finding USER Profile cid

Users profile cid can be found in NTUSER.dat: `/software/Microsoft/IdentityCRL/UserExtendedProperties`

![Profile cid](profile_cid.png)

### Finding application usage duration

We got the profile cid, we can head over to `Users/Danial Benjamin/AppData/Local/ConnectedDevicesPlatform/f648d51b99a9ba12/ActivitiesCache.db`.

There 7 tables to be specific in `ActivityCache.db`. For answering this question we need to look at `ActivityOperation` table.

Filtering out `Voicemod Desktop`, we can find some ActivityType 6 entries which indicates **"App in focus"**. By checking `activeDurationSeconds` from payload, we can get the user's application usage duration.

![Active Duration Seconds](activitycache_db.png)

As highlighted, we can see various instances of usage activity of the application VoiceMod with different activeDurationSeconds as `32, 25, 736, 7`. Which sums to `800 seconds`.

## Flag

Concatinating all answers, we can get the flag.

**inctf{T027GM97WJ3_U027XK55WCT_a27da2_FAT32_NTFS_800}**



For further queries, please DM on Twitter: https://twitter.com/_Nihith
