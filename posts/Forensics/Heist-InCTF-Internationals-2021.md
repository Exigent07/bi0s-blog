---
title: Heist - InCTF Internationals 2021
author: g4rud4
author_url: 'https://twitter.com/_Nihith'
date: 2021-08-16 19:00:05
tags:
 - InCTFi
 - Browser Forensics
 - TeamViewer
categories:
 - Forensics
 - Windows
---

**tl;dr**

+ Finding default browser and the top visited website.
+ Extract timestamp, ID, Hostname of the TeamViewer FileTransfer session.

<!--more-->

**Challenge Points**: 913
**Challenge Solves**: 15
**Challenge Author**: [g4rud4](https://twitter.com/_Nihith)

## Challenge Description

![Description](description.png)

Download the challenge file from [here](https://drive.google.com/drive/folders/1H3Ly8hnAW7eh7dxvf_bTA7_JYk8zMP3-?usp=sharing)

**MD5 Hashes:**

+ `A916E26016180D2C5189061D652DC9E1 Heist.7z`
+ `31f23c78ff99142bad2a778db6a64163 Heist.E01`

## Initial Analysis

We are given with a disk dump, lets use add the data source to Autopsy. We can see that, the given dump is from Windows 10 Home system, and Owner of the system is `Danial Benjamin`.

By checking all installed applications, we can see there are 3 web browsers(Google Chrome, Mozilla Firefox, Brave), Slack, Voice Modulator, TeamViewer, AnyDesk etc.

## Answering 1st Question

> 1. What is the default browser that the Heist leader is using on the device?

As there were 3 browsers being installed on the system. Let us check which is the default browser that user is using.

We can find that by checking the following registry key.

```text
NTUSER.DAT: Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{http|https}\UserChoice
```

![Default browser](default_browser.png)

From the above highlighting, We get it as `ChromeHTML`, which means user is using `Chrome` as his default browser.

So the answer will be `Chrome` or `Google_Chrome`.

## Answering 2nd Question

> 2. What is the top-visited website in the leader's system on the default browser?

Now we know `Chrome` is the default browser. Chrome stores it user data in the following folder `Users/Danial Benjamin/AppData/Local/Google/Chrome/User Data/Default/`.

In that directory we can find a SQlite database named `Top Sites`. This database provides us a list of top-visited websites by the user and gives a `url_rank` for each site. Sorting the table(`top_sites`) according to `url_rank`. We can get the top visited website user visited.

![top-sites](top-sites.png)

As highlighted above, we can see for url_rank - 0, we have `https://www.ebay.com/`. Converting it to the given format, we get `ebay.com`

## Answering 3rd Question

> 3. When was the latest file transfer session initiated in TeamViewer?

We need to find when the file transfer session initiated in TeamViewer.

TeamViewer stores its user data, in these following locations:

1. `C:\Program Files\TeamViewer\`
2. `C:\Users\<User Profile>\AppData\Roaming\TeamViewer\`

Main files of interest would be `Connection_incoming.txt` & `Connections.txt`. These files store the incoming and outgoing connections from TeamViewer.

Here is an example representation for data found in `Connection_incoming.txt`.

![](connections_incoming_example.png)

Img src: [mii-cybersec](https://medium.com/mii-cybersec/digital-forensic-artifact-of-teamviewer-application-cfd6290dc0a7)

On comparing both files, we can have only **one** file transfer session in `Connection_incoming.txt`. From that we can get the time initiated, TeamViewer ID, and the Hostname of the remote PC.

![](connections_incoming.png)

As highlighted above, we can see that TeamViewer ID is `920981533`, Remote PC's Hostname is `DESKTOP-S34NLCJ`, and time file transfer session initiated is `20-07-2021 07:48:50` in UTC.

But for this we need only the time initiated for this question. Which is `20-07-2021_07:48:50`.

## Answering 4th Question

> 4. What is the ID, Hostname of that file-transfer session?

We found the TeamViewer ID and hostname of the Remote PC from the previous question.

So the TeamViewer ID and Hostname are `920981533` & `DESKTOP-S34NLCJ`.

Converting the answer in the given format we get, `920981533_DESKTOP-S34NLCJ`.

## Flag

Combining all answers we can get the flag.

**inctf{Google_Chrome_ebay.com_20-07-2021_07:48:50_920981533_DESKTOP-S34NLCJ}**

For further queries, please DM on Twitter: https://twitter.com/_Nihith
