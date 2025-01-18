---
title: Heist Ends - InCTF Internationals 2021
author: g4rud4
author_url: 'https://twitter.com/_Nihith'
date: 2021-08-16 19:00:20
tags:
 - ALEAPP
 - Android
 - InCTFi
categories:
 - Forensics
 - Android
---

**tl;dr**

+ Extract creation timestamp of a note from Google Keep Notes.
+ Finding location, date & time from Slack Messages.
+ Extract no. of tasks completed and created from Google Tasks.
+ Finding secret code from Google Docs cache.
+ Extract first opened timestamp of a Game.

<!--more-->

**Challenge Points**: 989
**Challenge Solves**: 6
**Challenge Author**: [g4rud4](https://twitter.com/_Nihith)

## Challenge Description

![Description](description.png)

Download the challenge file from [here](https://drive.google.com/file/d/1hLgFoXYQA-brR8ucAKJa3lCRx94XXXRD/view?usp=sharing)

**MD5 Hash**: `Heist_ends.zip 28EB446FB1A2D3B408CBCCAFBBFBA86D`

## Initial Analysis

We are given a with an Android Device dump, I will be using [Alexis Brignoni](https://twitter.com/AlexisBrignoni)'s [ALEAPP](https://github.com/abrignoni/ALEAPP) to parse the given android dump. ALEAPP generated a HTML report of all artifacts that can be parse by it.

Android stores its application data in `/data/data` directory and all the installed applications in `/data/app` directory.

We can see a lot of apps being installed, some of which are Google apps, Slack, Dr. Driving, etc.

![Android Version](android_version.png)

From the ALEAPP report, we can see that the given Android device is running **Android 10.**

## Answering 1st Question

> 1. When did the Professor create the note for Rio?

We can only find one note taking app installed, i.e: **Google Keep - Notes and Lists**. Keep stores user data in the following directory: `/data/data/com.google.android.keep/`. Only file of interest for this question is `keep.db` present in `databases` directory. We can go through the database and extract the creation time of the Note. 

As we already ran ALEAPP, we can go check the Google Keep - Notes report.

![Google Keep](keep.png)

As highlighted above, We can get the note creation time as `2021-07-19 12:28:39`. Converting that to the format mentioned in the description would result in `19-07-2021_12:28:39`.

If you want to learn more about the artifacts of Google Keep, checkout my blog post [here](https://g4rud4.gitlab.io/2021/Google-Keep-Notes-and-Lists-Mobile-Artifacts/).

## Answering 2nd Question

> 2. Where did Professor and Rio, Plan to meet to plan the heist?

As Slack is installed on the device, they might have used it for communication.

This [blog post](https://abrignoni.blogspot.com/2018/09/finding-slack-messages-in-android-and.html) from Alexis Brignoni, gives us a detailed info on how we can extract messages from Slack Workspace. And [here](https://github.com/abrignoni/DFIR-SQL-Query-Repo/tree/master/Android/SLACK) you can find the SQL queries required for extracting chats and files shared in a slack workspace.

Slack stores user data in the following directory, `\data\data\com.Slack`.

Main files of interest are the database files named with the workspace ID found in **databases** directory.

We can see 2 files: `org_T027GM97WJ3` and `T027GM97WJ3`.

### Extracting messages from Slack

Extracting the useful data from `org_T027GM97WJ3`, we can get all the messages between Professor and Rio.

```sql
SELECT datetime(ts , 'unixepoch') AS 'Time Sent', channel_id, user_id, json_extract(message_json, '$.text') AS 'Messages' FROM messages ORDER BY ts;
```

![Message](slack_message.png)

As highlighted, we can see a message from user with user ID `U027H1QN8MD`, saying that they were planning to meet exactly at 9 PM on July 20, 2021 at [this](https://goo.gl/maps/iDmTQoZgrZae95JL6) location.

We can get the Latitude and Longitude from the url shared.

Hence, we got the answer. Latitude and Longitude as `13.106_80.225`

## Answering 3rd Question

> 3. When did Rio plan to meet Professor?

We got the answer for this question in the previous question.

We need to answer in original timezone, so irrespective of timezone that the user using on slack, we don't need to convert it to different timezone.

So, We got our answer. Converting it to the format given in description, results in `20-07-2021_21:00:00`.

## Answering 4th Question

> 4. How many members did Rio gathered for the heist?

From the Slack messages that we extracted previously. We can see a conversation regarding how many members for heist. Where Rio says, he is having a team of 11 members.

![Members for the heist](members_slack.png)

We got the answer. Members for the heist are `11`.

## Answering 5th Question

> 5. How many tasks did Rio created in planning the heist, and how many did he complete?

As there are a lot of Google apps installed, we found an installation of Google Tasks.

Google Tasks stores user data at `\data\data\com.google.android.apps.tasks\`.

Main files of interest is `data.db` present in `files\tasks-109039317116448576167\`.

This database contains a lot of tables, but the table of interest is `Tasks`. Where we can find Task ID, Task list ID, completion status, Effective task(A blob data contains infomation about task, task details, creation, modification, & completion timestamps) etc.

![Tasks](tasks.png)

AS highlighted, we can see that 4 tasks were created and 3 were completed. Converting to the format mentioned in description, results in `4_3`.

## Answering 6th Question

> 6. There is a secret code present in a document shared between Rio & Professor, can you find out what it is?

From the Slack messages, we saw some conversion, where Rio sharing a link to the document. And also Google Docs is installed in the android device.

We can find the 1st page cache of the document opened via Google docs from the mobile device.

### Finding docs cache

Location for the documents cache is `data\data\com.google.android.apps.docs\cache\docs_glide\data`. We will find some images where they contain the 1st page cache.

![cached image](cache.png)

From the image you can find the secret code used by Rio & Professor.

Secret code is `MintMMCT15AUG`.

## Answering 7th Question

> 7. We found a game installed on the device. When did Rio first open this game?

We only found one game installed on the device. Which is `Dr. Driving`. We are asked to find the first open time of this game.

Dr. Driving stores user data at `data\data\com.ansangha.drdriving`.

### Finding First Time app opened

Main files for interest is `com.google.android.gms.measurement.prefs.xml` present in **shared_prefs**.

```xml
<long value="1626782632701" name="last_upload"/>
<long value="1626782629126" name="first_open_time"/>
<long value="1628089054881" name="health_monitor:start"/>
...
<snip>
...
<string name="previous_os_version">10</string>
<boolean value="true" name="has_been_opened"/>
<boolean value="false" name="allow_remote_dynamite"/>
<long value="1628089934425" name="last_pause_time"/>
```

This file contains some metadata information about first time app opened, last upload, previous os version, etc.

Converting the epoch timestamp to UTC, we get `20-07-2021_12:03:49`.

## Flag

Combining all answers gives us the flag.

**inctf{19-07-2021_12:28:39_13.108_80.225_20-07-2021_21:00:00_11_4_3_MintMMCT15AUG_20-07-2021_12:03:49}**

For further queries, please DM on Twitter: https://twitter.com/_Nihith
