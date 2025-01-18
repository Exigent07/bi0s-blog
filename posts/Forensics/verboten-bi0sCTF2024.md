---
title: verboten - bi0sCTF 2024
date: 2024-03-08 13:54:08
author: sp3p3x
author_url: https://twitter.com/sp3p3x
author2: jl_24
author2_url: https://twitter.com/j0hith
author3: gh0stkn1ght
author3_url: https://twitter.com/mspr75
author4: hrippi.x_
author4_url: https://twitter.com/hrippix_
categories:
  - Forensics
tags:
  - bi0sCTFs
  - Incident Response
  - AnyDesk
  - prefetch
  - Slack
  - Chrome
  - USB
  - Windows Activity timeline
---

**tl;dr**

+ Registry Hives analysis
+ Analyse Chrome browser artifacts
+ Analyse Slack artifacts
+ Analyse AnyDesk artifacts
+ Analyse artifacts for evidence of execution
+ Analyse clipboard artifacts

<!--more-->

**Challenge Points**: 559
**No. of solves**: 29
**Challenge Author(s)**: [sp3p3x](https://twitter.com/sp3p3x), [jl_24](https://twitter.com/j0hith), [gh0stkn1ght](https://twitter.com/mspr75), [hrippi.x_](https://twitter.com/hrippix_)


## Challenge Description:

Randon, an IT employee finds a USB on his desk after recess. Unable to contain his curiosity he decides to plug it in. Suddenly the computer goes haywire and before he knows it, some windows pops open and closes on its own. With no clue of what just happened, he tries seeking help from a colleague. Even after Richard's effort to remove the malware, Randon noticed that the malware persisted after his system restarted.

*Note:*

+ For Q7: 12HR time format

+ All epoch times should be converted to IST (UTC + 5:30).

+ All other timestamps are to be taken as it is from artifacts.

## Writeup:

We are given an `.ad1` file which is a dump taken from a windows machine. We can use `FTK Imager` to open the dump file and start our analysis.

Answering the questions...

### Question 1

```
Q1) What is the serial number of the sandisk usb that he plugged into the system? And when did he plug it into the system?

Format: verboten{serial_number:YYYY-MM-DD-HH-MM-SS}
```

For getting the serial number of the sandisk usb, we can analyse the SYSTEM registry hive present in the dump. We can use `Registry Explorer` to view the hives and upon navigating to `SYSTEM/CurrentControlSet/Enum/USBSTOR`, we can see the that there is an entry of a SanDisk USB.

![usbstor reg](image.png)

From here, we can get the answer for the 1st question,

```
Answer Q1: verboten{4C530001090312109353&0:2024-02-16-12-01-57}
```

---

### Question 2

```
Q2) What is the hash of the url from which the executable in the usb downloaded the malware from?

Format: verboten{md5(url)}
```

By analysing and timelining all the relevant artifacts from where the malware could've been downloaded, we can see that the occurrence of a filebin link in the chrome history matches up with the events and the scenario.

Chrome artifacts can be found in,

`C:\Users\%username%\AppData\Local\Google\Chrome\User Data\%profilename%.default`

In the challenge file, we can see that there is only the Default profile,

![chrome artifacts](image-1.png)

Inside the folder, we can find the following contents,

![chrome folder content](image-2.png)

`History` file can be parsed using an SQLite viewer. I used an [online tool](https://inloop.github.io/sqlite-viewer/) to parse the SQLite database.

From the `downloads` table in the database, we can see there are two entries, one for winrar and another one which is a suspicious filebin link that has the following download link in the `tab_url` column,

`https://filebin.net/qde72esvln1cor0t/mal`

From the `target_path` column, we can see that it was downloaded to the following path,

`C:\Users\randon\Downloads\mal`

Taking the MD5 hash of this suspicious url gives us the answer.

```
Answer Q2: verboten{11ecc1766b893aa2835f5e185147d1d2}
```

---

### Question 3

```
Q3) What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware?

Format: verboten{md5{malware_executable)}
```

Since we know that the malware had existed in the system even after a basic cleanup, we can check for any persistence techniques the malware used. Among the evidences present in the dump, we can find the Startup Folder and since startup is a basic and easy persistence to setup, its necessary to check the contents of the startup folder.

Navigating to the user's startup folder we can see that there is a suspicious `mal.exe` file, which has the same name as endind of the filebin link.

![startup folder](image-3.png)

Extracting the file and calculating the MD5 hash gives us the answer.

```
Answer Q3: verboten{169cbd05b7095f4dc9530f35a6980a79}
```

---

### Question 4

```
Q4) What is the hash of the zip file and the invite address of the remote desktop that was sent through slack?

Format: verboten{md5(zip_file):invite_address}
```

For this question, we have to anaylse the slack artifacts present in,

`C:\Users\[username]\AppData\Roaming\Slack`

We can use [Slack-Parser](https://github.com/0xHasanM/Slack-Parser/) tool to parse the artifacts. We can find the database file in,

`%AppData%\Slack\IndexedDB\https_app.slack.com_0.indexeddb.blob*`

![database file](image-13.png)

Exporting the database and parsing it with the above tool gives us this,

![users slack](image-14.png)

![workspaces](image-15.png)

and parsing the messages gives us this,

```
always welcome {o
always welcome {o
$i couldn't have done it without you {o
$i couldn't have done it without you {o
 thank you so much for your help!{${${$
 thank you so much for your help!{${${$
*there we go.. all done with the shredding!{${${$
*there we go.. all done with the shredding!{${${$
cool!{${${$
cool!{${${$
+here is the address for anydesk: 1541069606{${${$
+here is the address for anydesk: 1541069606{${${$
>Hey i have backed up all my important files to my google drive{${${$
>Hey i have backed up all my important files to my google drive{${${$
sounds cool!{${${$
sounds cool!{${${$
Jokay, i'll backup my files and setup a remote desktop for you to join in..{${${$
Jokay, i'll backup my files and setup a remote desktop for you to join in..{${${$
mokay before we proceed with the shredder, I guess it would be wise to back up your important files to cloud..{${${$
mokay before we proceed with the shredder, I guess it would be wise to back up your important files to cloud..{${${$
-thank you so much! that would be very helpful{${${$
-thank you so much! that would be very helpful{${${$
]If you need more assistance, i could join you through a remote desktop and help you with it! {o
]If you need more assistance, i could join you through a remote desktop and help you with it! {o
4the password for the rar file is: 
4the password for the rar file is: 
JHey, i have compiled some of the good file shredders that I found online..{${${$
JHey, i have compiled some of the good file shredders that I found online..{${${$
Sure thing!{${${$
Sure thing!{${${$
HCould you help me out with that? I am not very familiar to all of this..{${${$
HCould you help me out with that? I am not very familiar to all of this..{${${$
:I guess try shredding the files and hope that it's deleted{${${$
:I guess try shredding the files and hope that it's deleted{${${$
%Oh no.. what do you suggest i do now?{${${$
%Oh no.. what do you suggest i do now?{${${$
+Hmm what it downloaded could be a malware!!{${${$
+Hmm what it downloaded could be a malware!!{${${$
I saw some black window pop open and then suddenly my browser opened and downloaded something.. after that the browser just closed itself..{${${$
I saw some black window pop open and then suddenly my browser opened and downloaded something.. after that the browser just closed itself..{${${$
Oh and then what happened?{${${$
Oh and then what happened?{${${$
I had found a usb near on my desk after i came back from my break, and out of curiosity i ran something that was there in the usb..{${${$
I had found a usb near on my desk after i came back from my break, and out of curiosity i ran something that was there in the usb..{${${$
Hi{${${$
Hi{${${$
Hey!{${${$
Hey!{${${$
```

Going through the above chats, we can find,

`+here is the address for anydesk: 1541069606{${${$`

So the anydesk invite address we need is `1541069606`. Now for the zip file attachment, manually going through the database file, we can find the following,

![attachment in db](image-17.png)

From the question, we know that a zip file was sent, and since the only instance of .zip we can find in the database is the above one (file_shredders.zip), we have a possible match.

By manually going through the cached data in the slack artifacts in the following path,

`C:\Users\[username]\AppData\Roaming\Slack\Cache\Cache_Data`

We can try to find the zip file which could have been cached.

After navigating to this folder, one easy way to find the zip file, which we know could be atleast a few mb's from the pool of other cached files, is by sorting with size. And by looking at the hex view of the first file in the list, we can see that it is a zip file and one of the files it contains inside it is `shredders.rar`.

![cache path](image-16.png)

Therefore we can confirm that this the attachment we are looking for. Exporting and taking the MD5 of the file and combing it with the anydesk address we found gives us the answer.

```
Answer Q4: verboten{b092eb225b07e17ba8a70b755ba97050:1541069606}
```

---

### Question 5

```
Q5) What is the hash of all the files that were synced to Google Drive before it was shredded?

Format: verboten{md5 of each file separated by ':'}
```

Google drive artifacts can be found in the following path,

`C:\Users\%user%\AppData\Local\Google\DriveFS`

We can find a folder for the user which has a unique id as the folder name, inside which we can see that there is a folder named `content_cache`.

![drivefs folder](image-4.png)

Looking inside this folder we can find 5 sub-folders

![sub-folders](image-5.png)

and upon navigating inside these folders, we can see each one of them have a file with no particular extension. But upon looking at the hex content of each file, we can see that three of them are possible word files (.docx, .doc etc.) and two are jpeg images, which FTK Imager automatically parses.

![doc hex](image-6.png)

![image ftk](image-7.png)

Taking the MD5 hash of files in order gives us the answer for this question.

```
Answer Q5: verboten{ae679ca994f131ea139d42b507ecf457:4a47ee64b8d91be37a279aa370753ec9:870643eec523b3f33f6f4b4758b3d14c:c143b7a7b67d488c9f9945d98c934ac6:e6e6a0a39a4b298c2034fde4b3df302a}
```

---

### Question 6

```
Q6) What is time of the incoming connection on AnyDesk? And what is the ID of user from which the connection is requested?
        
Format: verboten{YYYY-MM-DD-HH-MM-SS:user_id}
```

We can get the required information for this question by analysing the anydesk artifacts. AnyDesk artifacts can be found at,

```
%systempartititon%\%username%\AppData\Roaming\AnyDesk\
%systempartititon%\ProgramData\AnyDesk\
```

We can find the incoming connections log in `connection_trace.txt` file in the `ProgramData\AnyDesk` folder,

![connection_trace.txt](image-8.png)

`Incoming    2024-02-16, 20:29    User                              221436813    221436813`

This gives us everything to answer the question except the second of the incoming connection. For this, we will have to look into `ad.trace` file in the `AppData\Roaming\AnyDesk` folder which contains logs of events in the application.

![ad.trace](image-9.png)

By analysing this file and corroborating the evidence from `connection_trace.txt`, we can see there is entry of incoming request from Richard Beard and it contains the exact time of the incoming connection.

`info 2024-02-16 20:29:04.298       back   4668   6440                   app.backend_session - Incoming session request: Richard Beard (221436813)`

```
Answer Q6: verboten{2024-02-16-20-29-04:221436813}
```

---

### Question 7

```
Q7) When was the shredder executed?

Format: verboten{YYYY-MM-DD-HH-MM-SS}
```

We can get the time of execution of shredder from evidence of execution artifacts. In the given dump, we can see that prefetch is available. Looking through the prefetch entries, we can see there is an entry for `BLANKANDSECURE_X64.EXE`.

![prefetch](image-10.png)

With a bit of looking around, we can find out that this application is a shredder, and with no other entries of other shredder application in prefetch, we can confirm this is what we need. Taking the modified time and converting it to 12HR format as mentioned in the challenge description gives us the answer of this question.

```
Answer Q7: verboten{2024-02-16-08-31-06}
```

---

### Question 8

```
Q8) What are the answers of the backup questions for resetting the windows password?

Format: verboten{answer_1:answer_2:answer_3}
```

We can find the answer for this question in the SAM registry hive. Navigating to `ROOT\SAM\Domains\Account\Users`

![sam reg path](image-11.png)

![sam user entries](image-12.png)

And the backup questions and answers can be seen in the ResetData column.

```
{"version":1,"questions":[{"question":"What was your first pet’s name?","answer":"Stuart"},{"question":"What’s the name of the first school you attended?","answer":"FutureKidsSchool"},{"question":"What’s the first name of your oldest cousin?","answer":"Howard"}]}
```

```
Answer Q8: verboten{Stuart:FutureKidsSchool:Howard}
```

---

### Question 9

```
Q9) What is the single use code that he copied into the clipboard and when did he copy it?
        
Format: verboten{single_use_code:YYYY-MM-DD-HH-MM-SS}
```

For this question, we need to analyse `ActivitiesCache.db` which contains clipboard log along with a lot of other artifacts. The path where we can find this artifact is,

`%AppData%\Local\ConnectedDevicesPlatform\<UserProfile>\`

We can extract the `ActivitiesCache.db` file from our dump by navigating to this path.

We can load the db file into the same online parser we used before to view the contents. We can see the clipboard content in the `ClipboardPayload` column in the `SmartLookup` table. The `ClipboardPayload` column contains base64 encoded string of the clipboard content. Looking through the content, we can see entries of the following string:

`Your single-use code is: 830030`

`StartTime` column gives us the epoch time of when the data was first copied to the clipboard. Taking the StartTime timestamp first occurance of the above string and converting the epoch timestamp to IST as mentioned in the challenge description gives us the answer.

`1708106083 -> February 16, 2024 23:24:43`

```
Answer Q9: verboten{830030:2024-02-16-23-24-43}
```

---

Once we submit all the right answers for the questions, we are met with the final flag,

Flag: `bi0sctf{w3ll_th4t_w4s_4_v3ry_34sy_chall_b9s0w7}`

## Conclusion

This challenge was targeted towards beginners and people who are just getting started in DFIR, to get them familiar with finding and analysing artifacts as well as some common Windows artifacts. We were able to learn a lot while making this challenge and we really hope that you were also able to learn something new while solving this challenge.