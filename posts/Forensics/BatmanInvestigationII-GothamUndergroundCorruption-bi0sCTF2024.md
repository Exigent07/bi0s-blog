---
title: Batman Investigation II - Gotham Underground Corruption - bi0sCTF 2024 
date: 2024-02-27 17:51:58
author: Azr43lKn1ght
author_url: https://twitter.com/Azr43lKn1ght
categories:
  - Forensics
tags:
  - bi0sctf2024
  - Memory Forensics
  - Incident Response
  - Malware Analysis
  - Blockchain Forensics
  - Password Retrieval
  - WinDBG Dump Debugging
  - MAC Artefact Analysis
---

Full solution of Batman Investigation II - Gotham Underground Corruption from bi0sctf 2024

**tl;dr**

+ Challenge 2 of Batman Investigation series
+ Memory Forensics - WinDBG Dump Debugging - Malware Analysis - Blockchain Forensics - Password Retrieval - MAC Artefact Analysis

<!--more-->

**Challenge Points**: 1000
**No. of solves**: 0
**Challenge Author**: [Azr43lKn1ght](https://twitter.com/Azr43lKn1ght)

### Challenge Description
After getting in hold of Carmine Falcone's Laptop, Bruce Wayne has to investigate his laptop but unfortnatly he can't get the files nor the encrypted disk and its key, so he went ahead to get the memory dumped. After investigating and getting the data from the guy hired by Falcone for analysis, it seems corrupted!. Now He have to find and solve the things uncovering the Gotham's underground secrets, Help him solve the case of biggest Gotham corruption that is yet to happen!! They need to be stopped!

Password : **freIsEprOMPOLICkLERA**

**Challenge Files**:
+ [Primary Link](https://drive.google.com/file/d/1Z3TH8qo8SyEZO6UjteakHsekRKoZgE3C/view?usp=sharing)
+ [Mirror Link](https://mega.nz/file/NnEFCIaJ#hpPcwCBVfR_E_qN4cfHNNzwgCm-hA4vgcehxZ7YABy4)
+ nc link

### Solution

![alt text](image.png)

#### Question 1:

Q1) who asked Carmine falcon to contact someone and who is falcone disguised as?
Format: disguse-name_person-contacted (all lowercase)

We are given a Raw file which is a memory dump, so we can use volatility to analyze the memory dump. First, we need to find the profile of the memory dump. We can use the `imageinfo` plugin to find the profile of the memory dump if we are using vol2.


as it was Win10x64_19041, we can either use vol2 or vol3 to analyze the memory dump.

Looking into active process list using windows.pslist.PsList
```bash
 vol -f Carmine-Falcone.raw windows.pslist.PsList
```
```
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime       File output

[snip]
3668    748     svchost.exe     0xab0b10473080  2       -       0       False   2024-01-07 17:29:41.000000      N/A    Disabled
3660    748     MsMpEng.exe     0xab0b0e2b8080  44      -       0       False   2024-01-07 17:30:46.000000      N/A    Disabled
7748    896     ShellExperienc  0xab0b125892c0  15      -       1       False   2024-01-07 17:37:19.000000      N/A    Disabled
7824    896     RuntimeBroker.  0xab0b07662080  2       -       1       False   2024-01-07 17:37:19.000000      N/A    Disabled
6528    896     ApplicationFra  0xab0b108ab0c0  1       -       1       False   2024-01-07 17:37:24.000000      N/A    Disabled
1536    748     svchost.exe     0xab0b10d48080  2       -       0       False   2024-01-07 17:37:28.000000      N/A    Disabled
6424    748     NisSrv.exe      0xab0b10d83080  14      -       0       False   2024-01-07 17:41:46.000000      N/A    Disabled
6068    4640    Exodus.exe      0xab0b1259c080  0       -       1       False   2024-01-07 18:08:55.000000      2024-01-07 18:52:34.000000      Disabled
1232    896     Microsoft.Phot  0xab0b0e63f080  16      -       1       False   2024-01-07 18:16:04.000000      N/A    Disabled
5912    896     RuntimeBroker.  0xab0b0e809080  3       -       1       False   2024-01-07 18:16:07.000000      N/A    Disabled
5756    748     svchost.exe     0xab0b12c7d240  3       -       0       False   2024-01-07 18:20:53.000000      N/A    Disabled
5408    896     smartscreen.ex  0xab0b11a28340  9       -       1       False   2024-01-07 19:03:15.000000      N/A    Disabled
8596    2280    audiodg.exe     0xab0b0e63e080  4       -       0       False   2024-01-07 19:03:16.000000      N/A    Disabled
7284    4504    DumpItog.exe    0xab0b1259b080  1       -       1       True    2024-01-07 19:03:18.000000      N/A    Disabled
6576    7284    conhost.exe     0xab0b0e024080  4       -       1       False   2024-01-07 19:03:18.000000      N/A    Disabled
5372    4504    notepad.exe     0xab0b152e8080  4       -       1       False   2024-01-07 19:04:06.000000      N/A    Disabled
2352    8552    Exodus.exe      0xab0b0e2b9080  45      -       1       False   2024-01-07 19:04:23.000000      N/A    Disabled
7260    2352    Exodus.exe      0xab0b0feef080  22      -       1       False   2024-01-07 19:04:23.000000      N/A    Disabled
5616    2352    Exodus.exe      0xab0b117bb080  19      -       1       False   2024-01-07 19:04:23.000000      N/A    Disabled
3972    2352    Exodus.exe      0xab0b10479080  11      -       1       False   2024-01-07 19:04:23.000000      N/A    Disabled
2436    2352    Exodus.exe      0xab0b106b0080  22      -       1       False   2024-01-07 19:04:24.000000      N/A    Disabled
6700    2352    Exodus.exe      0xab0b0d257080  17      -       1       False   2024-01-07 19:04:24.000000      N/A    Disabled
1176    2352    Exodus.exe      0xab0b152ef080  29      -       1       False   2024-01-07 19:04:24.000000      N/A    Disabled
6048    2352    Exodus.exe      0xab0b104d1080  25      -       1       False   2024-01-07 19:04:24.000000      N/A    Disabled
3028    2352    Exodus.exe      0xab0b0773a080  17      -       1       False   2024-01-07 19:04:24.000000      N/A    Disabled
9892    2352    Exodus.exe      0xab0b10c57080  15      -       1       False   2024-01-07 19:04:29.000000      N/A    Disabled
8716    2352    Exodus.exe      0xab0b0f6f6080  17      -       1       False   2024-01-07 19:04:30.000000      N/A    Disabled
7828    2352    Exodus.exe      0xab0b0773f080  17      -       1       False   2024-01-07 19:04:30.000000      N/A    Disabled
3768    4504    KeePass.exe     0xab0b1047f080  8       -       1       False   2024-01-07 19:04:42.000000      N/A    Disabled
1576    4504    7zG.exe 0xab0b07767080  3       -       1       False   2024-01-07 19:05:17.000000      N/A     Disabled
6628    4504    7zFM.exe        0xab0b0e4c9080  4       -       1       False   2024-01-07 19:05:31.000000      N/A    Disabled
7644    4504    thunderbird.ex  0xab0b0765d080  68      -       1       False   2024-01-07 19:05:46.000000      N/A    Disabled
4872    7644    thunderbird.ex  0xab0b12f54080  28      -       1       False   2024-01-07 19:05:46.000000      N/A    Disabled
6248    7644    thunderbird.ex  0xab0b125062c0  30      -       1       False   2024-01-07 19:05:49.000000      N/A    Disabled
5848    2352    Exodus.exe      0xab0b1102e2c0  29      -       1       False   2024-01-07 19:06:13.000000      N/A    Disabled
3960    2352    Exodus.exe      0xab0b13c020c0  16      -       1       False   2024-01-07 19:06:13.000000      N/A    Disabled
6392    5432    SearchProtocol  0xab0b0d3c8080  11      -       0       False   2024-01-07 19:06:21.000000      N/A    Disabled
6172    5432    SearchFilterHo  0xab0b152c2080  7       -       0       False   2024-01-07 19:06:21.000000      N/A    Disabled
56      0               0xab0b108d9080  0       -       -       False   N/A     N/A     Disabled
```
For the messages sent we can see that Thunderbird.exe is an active process. So analysing Inbox file will give us all the conversation data. So lets scan and list all files in the system using

```bash
vol -f Carmine-Falcone.raw windows.filescan.FileScan
```
```
[snip]
0xab0b10cde210  \Users\Carmine Falcone\AppData\Roaming\Thunderbird\Profiles\ifbixagh.default-release\Mail\pop.gmail.com\Inbox   216
[snip]
 ```
Lets dump the files from memory using the following command
```bash
vol -f Carmine-Falcone.raw windows.dumpfiles.DumpFiles --virtaddr 0xab0b10cde210 
 ```
 let's analyze the file, on analysis on the contents of the file, the answer to the first question is found.
 ```
[snip]
X-Gm-Message-State: AOJu0Yyv8yhr8N0SSfAETgbGKlwAAXHBQ8dPe0iUUHmbk4oykMYSTuoR
    ErKG++vrWZ5uSwIcHfIukc3n4Q98KhcEOA==
X-Google-Smtp-Source: AGHT+IEaR13fr5QwtA2EVAeeqRlt5MHwDILGsc17qMCuDr64g/xiFSQi2/n9+TmXEoQztdSMzBFY3Q==
X-Received: by 2002:a17:902:e54a:b0:1d4:da6d:c121 with SMTP id n10-20020a170902e54a00b001d4da6dc121mr2644778plf.13.1704622743610;
        Sun, 07 Jan 2024 02:19:03 -0800 (PST)
Return-Path: <salvatoremaroni3376@gmail.com>
Received: from [10.0.2.15] ([59.89.233.32])
        by smtp.gmail.com with ESMTPSA id ji5-20020a170903324500b001d3ffb7c4c7sm4214767plb.40.2024.01.07.02.18.49
        for <hugostrange581@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Jan 2024 02:18:59 -0800 (PST)
Content-Type: multipart/mixed; boundary="------------I30YCObF3eWdYu0uKKgStigo"
Message-ID: <d3a63f93-a0ee-4718-a71a-d9646de2698b@gmail.com>
Date: Sun, 7 Jan 2024 10:17:39 +0000
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: hugostrange581@gmail.com
From: Salvatore Maroni <salvatoremaroni3376@gmail.com>
Subject: Confidential!!

This is a multi-part message in MIME format.
--------------I30YCObF3eWdYu0uKKgStigo
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

Contact the guy and the key for his reply is his private key!!


--------------I30YCObF3eWdYu0uKKgStigo
Content-Type: application/octet-stream; name="contact.rar"
Content-Disposition: attachment; filename="contact.rar"
Content-Transfer-Encoding: base64

UmFyIRoHAQC+0emJDQEFCQAIAQGb1umAgAAblo4KLwIDC+eEAASEwAAgz4NtOoA7ABFjb250
YWN0Ly5EU19TdG9yZQoDAp8i9ZMvP9oBzfZjAjB1QzNC9HBGxzabsqp/ESASvESqR1DS3aIR
UcaXdOB0Nog4aCpZbC2Gyx0sl2iVVSvY34OfBd6nxI+LnITbtzHJBWyyoR1OZu9clcxuvPZj
[snip]
```
`hugo-strange_salvatore-maroni` is the answer to the first question.
```
Answer1:hugo-strange_salvatore-maroni
```

but we also found an attachment that was sent with the email. Let's extract the file contact.rar which is the attachment and analyze it as well look into the second question.

but this can also be solved by taking a memory dump of the process and listing all the strings.

#### Question 2:
Q2) what is the hash of the file that he sent him to contact
Format: sha1sum

After decoding the base64 encoded attachment file as well removing all trailing white spaces, we get the attachment file, now we can extract and compute the sha1sum of the attachment.

```
Answer2: 61ca5520263677e648297e1aefd90343fdd0388f
```
#### Question 3:
Q3) what is the password of his password manager
Format: password_manager_name_with_version:md5(password)

As we can see KeePass was the only password manager that was running on the system, we can conclude it was the password manager. Now we have to find its version.

From filescan, we can see that KeePass 2.53.1 was present (version : 2.53.1)  

```
0xab0b10a0f1b0  \Users\Carmine Falcone\Downloads\KeePass-2.53.1-Setup.exe
```
this can also be found from the following config file

`0xab0b10a3b3f0         \Program Files\KeePass Password Safe 2\KeePass.exe.config	216`

So i went ahead and dumped `KeePass.exe.config` and its contents were:
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
	<startup useLegacyV2RuntimeActivationPolicy="true">
		<supportedRuntime version="v4.0" />
		<supportedRuntime version="v2.0.50727" />
	</startup>
	<runtime>
		<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
			<dependentAssembly>
				<assemblyIdentity name="KeePass"
					publicKeyToken="fed2ed7716aecf5c"
					culture="neutral" />
				<bindingRedirect oldVersion="2.0.9.0-2.53.1.0"
					newVersion="2.53.1.20815" />
			</dependentAssembly>
		</assemblyBinding>
		<enforceFIPSPolicy enabled="false" />
		<loadFromRemoteSources enabled="true" />
	</runtime>
	<appSettings>
		<add key="EnableWindowsFormsHighDpiAutoResizing" value="true" />
	</appSettings>
</configuration>
```
as well this can be done by printing the hive registry or dumping hives and analysing the registry.

now we want the password, searching for password recovery/retrieval of the database of KeePass which is .kdbx file, we come across a CVE dated 2023. That is CVE-2023-32784 as well we can find this [article](https://www.forensicxlab.com/posts/keepass/).

Now let's search for .kdbx files using filescan and dump the file from memory.
```
[snip]
0xab0b138c5bc0  \Users\Carmine Falcone\Downloads\bruce.kdbx     216
[snip]
```
```bash
vol -f Carmine-Falcone.raw windows.dumpfiles.DumpFiles --virtaddr 0xab0b138c5bc0
```
The plugin we found from the article above shows a missing character in the middle.
```
Possible password: ●i&Y●Q)8h<)1T2j
Possible password: ●+&Y●Q)8h<)1T2j
Possible password: ●`&Y●Q)8h<)1T2j
Possible password: ●"&Y●Q)8h<)1T2j
Possible password: ●j&Y●Q)8h<)1T2j
Possible password: ●r&Y●Q)8h<)1T2j
Possible password: ●1&Y●Q)8h<)1T2j
Possible password: ●R&Y●Q)8h<)1T2j
Possible password: ●B&Y●Q)8h<)1T2j
Possible password: ●Q&Y●Q)8h<)1T2j
Possible password: ● &Y●Q)8h<)1T2j
```
So it's better we go with the .net [tool](https://github.com/vdohney/keepass-password-dumper?tab=readme-ov-file) which is better.
```
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:	●
2.:	w, |, Q, B, }, j, , Ë, +, , s, ü, r, {, :, d, Ô, §,                                                                                    , ,  , ;, 8, Þ, , F, Á, 1, i, 0, c, u, Ç, , ç, q, Í,  Ö, Ø, !, 5, , è, £, ®, Ñ, `, , , X, 6, È, %, ), Ì, &, ", 	,  , Å, Û, ¨, ', -, @, û, R, , 
                                              , ð, ÷, ý, a, \, 3, t, H, A, Ú, y, ã, Ý, 7, , p, 
3.:	&, 
4.:	Y, 
5.:	é, 
6.:	Q, 
7.:	), 
8.:	8, 
9.:	h, T, 
10.:	<, 
11.:	), 
12.:	1, 
13.:	T, 
14.:	2, 
15.:	j, 
Combined: ●{w, |, Q, B, }, j, , Ë, +, , s, ü, r, {, :, d, Ô, §,                                                                                , ,  , ;, 8, Þ, , F, Á, 1, i, 0, c, u, Ç, , ç, q, Í,  Ö, Ø, !, 5, , è, £, ®, Ñ, `, , , X, 6, È, %, ), Ì, &, ", 	,  , Å, Û, ¨, ', -, @, û, R, , 
                                              , ð, ÷, ý, a, \, 3, t, H, A, Ú, y, ã, Ý, 7, , p}&YéQ)8{h, T}<)1T2j
```
lets write a easy script to bruteforce the password
```py
#!/usr/bin/python

from pykeepass import PyKeePass
import sys

f = 'bruce.kdbx'

charset = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+',
        '[', ']', '\\', '|', '{', '}', ';', ':', "'", '"', ',', '<', '.', '>', '/', '?',
        ' '
]

with open('dbpass.txt', 'r') as file:
    pwds = file.read().split("\n")

count = found = 0
total = len(pwds)
for p in pwds:
    for char in charset:
        password = char+p
        try:
            db = PyKeePass(f, password=password)
            print("Valid password found for %s : %s" % (f,password))
            found = 1
        except Exception as err:
            print(err)
            if found == 1:
                sys.exit(0)
        count += 1
        print(f"{count}/{total} : {password}")
```
before that we analyse the kdbx file for a structure check and remove the trailing null bytes added up during filedump.

After running the script on it, we get the correct password:
```
[snip]
29/11 : ci&YéQ)8h<)1T2j
Valid password found for bruce.kdbx : di&YéQ)8h<)1T2j
30/11 : di&YéQ)8h<)1T2j
[snip]
```
so the password is `di&YéQ)8h<)1T2j`
and now the answer will be
```
Answer3: keepass_2.53.1:4e896dbb5120c2c33e0965174c6036c2
```
#### Question 4:
Q4) what is the key he stored in his password manager that he deleted?
Format: (format: user_name:key)

now we can open the kdbx file using the password we retrieved.

![alt text](image-1.png)

now lets look for the key he stored in his password manager which was deleted.

![alt text](image-2.png)

let's view it

![alt text](image-3.png)

```
Answer4: Azr43lKn1ght:sw1zwJjvpqVvFNANws1v
```
#### Question 5:
Q5) what is the cryptocurrency wallet installed and when is it installed?
Format: wallet_name-date-time(in format YYYY:MM:DD:HH:MM)

We can see from the active processes that Exodus is running, so we can conclude that Exodus is the cryptocurrency wallet installed. Now we have to find the installation time.

From Uninstall reg entry of exodus, we can get the install date

```
vol.py -f Carmine-Falcone.raw --profile=Win10x64_19041 printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\exodus"   
Volatility Foundation Volatility Framework 2.6.1
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \??\C:\Users\Carmine Falcone\ntuser.dat
Key name: exodus (S)
Last updated: 2024-01-07 08:39:51 UTC+0000

Subkeys:

Values:
REG_SZ        DisplayIcon     : (S) C:\Users\Carmine Falcone\AppData\Local\exodus\app.ico
REG_SZ        DisplayName     : (S) Exodus
REG_SZ        DisplayVersion  : (S) 24.1.1
REG_SZ        InstallDate     : (S) 20240107
REG_SZ        InstallLocation : (S) C:\Users\Carmine Falcone\AppData\Local\exodus
REG_SZ        Publisher       : (S) Exodus Movement Inc
REG_SZ        QuietUninstallString : (S) "C:\Users\Carmine Falcone\AppData\Local\exodus\Update.exe" --uninstall -s
REG_SZ        UninstallString : (S) "C:\Users\Carmine Falcone\AppData\Local\exodus\Update.exe" --uninstall
REG_SZ        URLUpdateInfo   : (S) 
REG_DWORD     EstimatedSize   : (S) 193279
REG_DWORD     NoModify        : (S) 1
REG_DWORD     NoRepair        : (S) 1
REG_DWORD     Language        : (S) 1033
```
as well we can get it from exodus file installer's prefetch execution time or as well look into mft.
```
vol -f Carmine-Falcone.raw windows.mftscan.MFTScan
```

```
* 0xab0b0769c920    FILE    89142   2   File    Archive FILE_NAME   2024-01-07 08:39:03.000000  2024-01-07 08:39:03.000000  2024-01-07 08:39:03.000000  2024-01-07 08:39:03.000000  EXODUS-WINDOWS-X64-24.1.1.EXE-5FE34CD7.pf
```
```
2024-01-07 08:38:08 UTC+0000 2024-01-07 08:38:32 UTC+0000   2024-01-07 08:38:32 UTC+0000   2024-01-07 08:38:32 UTC+0000   Users\CARMIN~1\DOWNLO~1\exodus-windows-x64-24.1.1.exe
2024-01-07 08:39:03 UTC+0000 2024-01-07 08:39:03 UTC+0000   2024-01-07 08:39:03 UTC+0000   2024-01-07 08:39:03 UTC+0000   Windows\Prefetch\EXODUS-WINDOWS-X64-24.1.1.EXE-5FE34CD7.pf
```
And we can see there is a prefetch entry for the installer which has the time 08:39:03
```
Answer5: exodus-2024:01:07:08:39
```
#### Question 6:
Q6) what is the malware that wants to steal the cryptocurrency wallet and ip it's trying to send to with port number?
Format: malware_ip:port)
let's look through the contents of Downloads, Desktop etc. There didn't seem to be anything suspicious present in the downloads folder since all that there was the installers for the applications present in his system. But in desktop folder, there was a services.exe which looked suspicious which also has a execution/run in prefetch files as well as other Evidence of Executions.
```
0xab0b0d34fe90	\Users\Carmine Falcone\Desktop\services.exe	216

vol -f Carmine-Falcone.raw windows.dumpfiles.DumpFiles --virtaddr 0xab0b0d34fe90
```
So assuming the ip and port is present in the strings of the binary, I made a quick code snippet find all occurances of ip addresses in the strings.
```py
import re

strings = open('./stealerStrings.txt','r').read()
format = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
print(format.findall(strings))
```
which gives the output,

`['127.0.0.1', '172.30.145.189']`
First one is localhost, hence the second one should be the one we are after.
ding strings grep with the ip, we get the port too.

![alt text](image-4.png)

```
Answer6: services.exe_172.30.145.189:6969
```
#### Question 7:
Q7) Eventhough Falcone's Network Moniter blocked the file sent, falcone made sure to zip with a password and noted it down temporaily in his screen and sent it to a detective for analysis.what is the password of the zip file?

as he noted it down and only notepad.exe was running and as it not get saved as well it's mentioned temporarily, we have to retrieve it from notepad memory.
So let's dump the VAD structures using vaddump vol2 plugin.
```bash
 vol.py -f Carmine-Falcone.raw --profile=Win10x64_19041 vaddump -p 5372 -D vaddumps
 ```
 But unless we can pinpoint to the heap dumps in the VAD structures, its going to be hectic to go through the whole process's memory dump. So i used vadtree plugin in vol2 to look at the VAD (Virtual Address Descriptor) tree.
```bash
vol.py -f Carmine-Falcone.raw --profile=Win10x64_19041 vadtree -p 5372 --output-file=./vadtree.dot --output=dot

dot vadtree.dot -Tpng > vadtree.png
```
![alt text](vadtree.png)
![alt text](image-5.png)
here the colours represent
```
Red: Heaps
Gray: Dynamic Link Libraries
Green: Stacks
Yellow: Mapped Files
```
We can see there are 4 heaps within the process structure as denoted by the red blocks. We can also achieve the same with volshell.
```bash
vol.py -f Carmine-Falcone.raw --profile=Win10x64_19041 volshell -p 5372
Volatility Foundation Volatility Framework 2.6.1
Current context: notepad.exe @ 0xffffab0b152e8080, pid=5372, ppid=4504 DTB=0x261a7000
Python 2.7.18 (default, Jul  1 2022, 10:30:50) 
Type "copyright", "credits" or "license" for more information.

IPython 5.10.0 -- An enhanced Interactive Python.
?         -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help      -> Python's own help system.
object?   -> Details about 'object', use 'object??' for extra details.

In [1]: process_heaps_address_list = proc().Peb.ProcessHeaps.dereference()

In [2]: process_heaps_address_list
Out[2]: <Array 2106693189632,2106691747840,2106719469568,2106720911360>

In [3]: for i in [2106693189632,2106691747840,2106719469568,2106720911360]:
   ...:     print(hex(i))  
0x1ea80b30000
0x1ea809d0000
0x1ea82440000
0x1ea825a0000
```
Now that we have the addresses of the heaps, we narrow down our analysing to just the heap dumps.
```bash
strings -e l notepad.exe.4775c080.<address>.dmp
```
3 out of 4 dumps we got didn't contain much information. But while going through the strings of the dump of the address `0x000001ea80b30000-0x000001ea80c2ffff`, along with other interesting strings, we can find this.

![alt text](image-6.png)

And we can confirm its just a whitespace. So now that we have a possible candidate for a password `w&31D,%4> C6'nT`

We can also get this using MemProcFS by looking into the heaps of notepad.

![alt text](image-8.png)

![alt text](image-9.png)

and as well we can verify this by debugging the memory dump using windbg.

we can get the dmp file of the original raw memory file with mounting the device using memprocfs and then we can use windbg to debug the memory dump.

![alt text](image-7.png)

![alt text](image-10.png)

![alt text](image-11.png)

!process 0 0 notepad.exe command displays detailed information about the notepad.exe
.process /r /p ffffab0b152e8080 command sets the process context to the notepad.exe process with the specified address. The /r option reloads the user-mode symbols for the process, and the /p option specifies a physical address.
After running this command, the debugger’s process context is set to the notepad.exe process, and the user-mode symbols for the process are loaded.

now let's list all heaps using 
`!heap -s -v -a`

![alt text](image-12.png)

we have to look int heaps with extra user_flag

![alt text](image-13.png)

and lets display the heap content using
```
db 000001ea80b6ec80 L80
```
![alt text](image-14.png)

`w&31D,%4> C6'nT`
and we finally find the valid string that could be the noted down one.
```
Answer7: 63eeb3a466f8bab52b44e182e919b512
```
#### Question 8:
Q8) what is the hash of the original files in the zip file before the stealer modified them?
Format: sha1sum:sha1sum

now we can either dump the zip file from memory or get it from the handle of 7z.

![alt text](image-15.png)

but apparently when we look into the file's hex it is hollowed out eventhough it is a handle to a process, the middle is only null bytes, so we can't extract the file either. dumping it from memory also has the same effect.
```
vol.py -f Carmine-Falcone.raw --profile=Win10x64_19041 filescan | grep "Desktop" 
[snip]
0x0000ab0b10a27530  32758      1 R--r-- \Device\HarddiskVolume2\Users\Carmine Falcone\Desktop\Carmine Falcone_2.7z
[snip]
```
so looking into why the file unknown.data is given as well this zip file that is inside the 7z was dropped by the services.exe which is found using timelining, so from the previous question as well as description we can conclude that the unknown.data is the original file that was zipped and sent to the detective it's corrupted

now we can try and fix the file using the hollowed out 7z.

![alt text](image-16.png)

fixing both after comparing, we are able to fix the file and extract it using the above obtained password `w&31D,%4> C6'nT` and we get 2 .seco files.

but as mentioned by the question as well as looking into the timeline as the stealer modified the seco files, lets statically analyse the binary with IDA to fix it as the hash is also verified as wrong.

We can see that it's a PE32+ executable, pretty standard stuff.

![alt text](image-19.png)

We get to the start function from which we follow start_0

![alt text](image-20.png)

As it's windows go binary, the offset in line 47 in start_0 should point to the offset of runtime_main.

![alt text](image-21.png)

then looking into the runtime_main.

![alt text](image-22.png)

we can immediately see that it is loading the path of a file called `exodus.wallet`, by joining it with an environment variable `USERPROFILE`. 

Then, it's concatenating ".zip" to the filename which is stored in the environment variable. 

Then, it calls a function `getFilesInFolder` (which I renamed in IDA) after looking at it. 

`getFilesInFolder` is defined as follows 

![alt text](image-23.png)

Here we can see that it's just walking the entire directory and getting every file in it. 

![alt text](image-24.png)

After that, it enters a for loop, where first it enters a function (on the right branch of the jump) which first opens and reads the file (which is clear from the assembly)

![alt text](image-25.png)

(Note that the buffer of the file is stored as a pointer inside `rdx` after the function returns)

Then, once that is done, a function called `runtime_makeslice` (IDA's renaming convention) is called. This essentially allocates new memory on the heap for a fresh object and initialises its values to 0. 

After that, it enters this for loop 

![alt text](image-26.png)

Notice how the file's buffer is being stored in `esi`, then XORed with 0x33, then stored as a pointer inside `rax`. This is done for the entire length of the buffer (basically the whole file)

Then, again, from the assembly itself, it is pretty clear that this new "encrypted" buffer (which is just the original file XORed with 0x33), that is then written to a fresh file. This is done for every file in the directory (this is evident also from the fact that the entire directory was previously walked to get every file handle). 

After the for loop to encrypt every file, another function (on the left branch of the jump) is called, let's take a look at what it does. 

Again, like the previous function, it first opens the file (the encrypted files this time), stats them, creates a zip header, and copies the file content to the zip archive. 

After that, we enter this part of the binary 

![alt text](image-27.png)

It enters a for loop to remove every encrypted file that was created.

After that, it gets the current working directory of the zip file that was created (containing all the encrypted files). 

![alt text](image-28.png)

After that, it initiates a `tcp` connection to `172.30.145.189:6969`, to which it sends our zipped archive of the encrypted files. 

So the binary itself does something pretty simple overall. It reads every single file in the directory, "encrypts" it by XORing with 0x33, then zips it and sends it to that IP and port. 

Here we can see, the data is begin xored with 0x33, which is also evident when looking back to the .seco files in hex editor where there are a lot of 0x33 bytes present.

![alt text](image-29.png)

so wrote a quick script to fix up the .seco files by xoring them with 0x33,

```py
with open('enc/seed.seco','rb') as file:
    encdata = file.read()

decdata = bytearray()

for i in encdata:
    decdata.append(i^51)

with open('dec/seed.seco','wb') as out:
    out.write(decdata)
```
So now i have the fixed both seco files. So taking the sha1 of both the files.

```
Answer8: 3ba6011f5e1b6941f893df6579f87f1c823e7493:5e38ffd5e6d6115a6f4bb21b5216c37392eb544f 
```
#### Question 9:
Q9) what is the password that Carmine Falcone protected the wallet with
Format: md5(password)

After doing research, tests and analysis on exodus wallet, we are able to find that the password is stored in plaintext between `exodus.wallet%22%2C%22passphrase%22%3A%22` and `%22%7D` in memory. So we can extract the password from the memory dump.

![alt text](image-17.png)

so now we got the password as `yb%23uO7%26n%25%24%C2%A36%5BE310`, converting the url encoded characters to ascii we get `yb#uO7&n%$£6[E310`

![alt text](image-18.png)

password is `yb#uO7&n%$£6[E310`

![alt text](image-31.png)

```
Answer9: 93bbca2406298b9cb574ac06abf113e4
```
#### Question 10:
Q10) who did Carmine falcone recive money from?
Format: name_person:curreny_used(3 or 4 letter significance):amount(in dollars with precision of 2 decimal places):transaction_id

after transferring the wallet to exodus , we can use the password we found to open the wallet and look into the transactions.

![alt text](image-30.png)

let's check the received logs.

![alt text](image-34.png)

![alt text](image-35.png)

he have received money from Edward Nigma (Riddler) in USD 15.31 with a transaction id of 0xab42fc3fb81fca7bec9e49058d80dc928ed5de2e780a54de41d3c1a8587c4ab7.
```
Answer10 edward_nigma:eth:15.31:0xab42fc3fb81fca7bec9e49058d80dc928ed5de2e780a54de41d3c1a8587c4ab7
```
#### Question 11
Q11) who did Carmine falcone send money to?
Format: name_person:curreny_used(3 or 4 letter significance):amount(in dollars with precision of 2 decimal places):senderaddress

the same way we look into the sent log.

![alt text](image-36.png)

He sent the money to Oswald Cobblepot, which was USD 13.65 with a transaction id of 0xab42fc3fb81fca7bec9e49058d80dc928ed5de2e780a54de41d3c1a8587c4ab7 with a  wallet address of 0xcfb6b082B7296FaA5aD18695e1F554AFC23724eD 
```
Answer11: oswald_cobblepot:eth:13.65:0xcfb6b082B7296FaA5aD18695e1F554AFC23724eD
```
#### Question 12
Q12) what is the name and client private key that Salvatore asked for contact verification?
Format: infobreakage_dbkey:client_email

Now looking into the email attachment, we have few folders, on analysis we can find that it is dropbox files.

![alt text](image-37.png)

looking into info.json gives that an info from the path that it is either linux or mac .dropbox folder

looking into files, analysing as well after researching, we are able to come across these tools that can give us the required information.

for 
[mac](https://github.com/dnicolson/dbx-keygen-macos) and 
[linux](https://github.com/newsoft/dbx-keygen-linux)

but apparently we have to edit it so it can work in our case.

so I made a cpp script to do that.

```cpp
#include <iostream>
#include <vector>
#include <stdint.h>
#include <utility>
#include <algorithm>
#include <fstream>
#include <pthread.h>
#include <openssl/evp.h>

const std::string DROPBOX_PATH = "/mnt/d/bi0sctf/chall4/dropbox/instance1/";
std::vector<uint8_t> CLIENT_VEC = {'C', 'l', 'i', 'e', 'n', 't'};
const std::vector<uint8_t> IV = {108,7,56,1,52,36,115,88,3,255,114,105,51,19,97,81};
    
#define NUM_THREADS 10
typedef struct thread_data{
    uint64_t start;
    uint64_t end;
    uint8_t version;
    std::vector<uint8_t> raw_payload;
} tdata;

std::pair<uint8_t, std::vector<uint8_t>> unpack_payload(std::vector<uint8_t> data){
    uint8_t res1 = data[0];
    std::vector<uint8_t> res2;
    res2.assign(data.begin() + 1, data.end() - 16);
    return std::make_pair(res1, res2);
}

std::vector<uint8_t> read_file(std::string filename){
    std::vector<uint8_t> data;
    std::ifstream file(filename, std::ios::binary);
    file.seekg(0, std::ios::end);
    data.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read((char *)data.data(), data.size());
    file.close();
    return data;
}

unsigned char* calculate_md5(uint64_t inode_no){
    std::string str_inode = std::to_string(inode_no);
    std::string value = "ia9" + str_inode + "Xa|ui20";
    EVP_MD_CTX *mdctx;
    unsigned char *md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    
    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx);
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // MD5_Update
    EVP_DigestUpdate(mdctx, (unsigned char*)value.c_str(), value.length());

    // MD5_Final
    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);
    return md5_digest;
}

std::vector<uint8_t> decrypt_the_payload(std::vector<uint8_t> data, uint64_t inode_no){
    std::vector<uint8_t> output;
    output.resize(data.size());
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    unsigned char* enc_key = calculate_md5(inode_no);
    std::vector<uint8_t> target_message = data;
    int inlen = target_message.size();
    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), enc_key, IV.data());
    EVP_DecryptUpdate(ctx, output.data(), &outlen, target_message.data(), inlen);
    EVP_DecryptFinal(ctx, output.data()+outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return output;
}

// bool check(std::vector<uint8_t> first, std::vector<uint8_t> second){
//     std::sort(first.begin(), first.end());
//     std::cout << "\nRHA: contains:\n";
//     for(int i=0; i<first.size(); i++){
//         printf("%x ", first[i]);
//     }
//     printf("\n\n");
//     for(int i=0; i<second.size(); i++){
//         printf("%x ", second[i]);
//     }
//     printf("\n\n");
//     return std::includes(first.begin(), first.end(), second.begin(), second.end());
// }

bool check(std::vector<uint8_t> data) {
   for(int i=0; i<CLIENT_VEC.size();i++){
        if(data[i+2] != CLIENT_VEC[i])
            return false;
   }
   return true;
}


int get_versioned_key(tdata *td){
    std::vector<uint8_t> raw_payload = td->raw_payload; 
    uint64_t start = td->start;
    uint64_t end = td->end;
    
    std::vector<uint8_t> dec_payload;
    for(uint64_t inode_no=start; inode_no<=end; inode_no++){
        dec_payload = decrypt_the_payload(raw_payload, inode_no);
        bool result = check(dec_payload);
        if(result == true){
            std::cout << "\n ========================================== \n";
            std::cout << "[+] Key Found !\n";
            std::cout << "[*] Wanted Number: " << inode_no << "\n\n" << std::endl;
            // printf("result: %d\n", result);
            // for(int i=0;i <CLIENT_VEC.size(); i++){
            //     printf("%c", CLIENT_VEC[i]);
            // }
            exit(0);
        }
    }
    return 0;
}


int main(int argc, char *argv[]){

    if (argc < 3){
        std::cout << "[!] Usage: " << argv[0] << " <start> <end>" << std::endl;
        exit(0);
    }

    uint64_t start = atoll(argv[1]);
    uint64_t end = atoll(argv[2]);

    std::cout << "[*] Range Start: " << start << std::endl;
    std::cout << "[*] Range End: " << end << std::endl;
    
    std::string filename = DROPBOX_PATH + "hostkeys";
    
    std::cout << "[*] Reading file: " << filename << std::endl;
    std::vector<uint8_t> data = read_file(filename);
    std::pair<uint8_t, std::vector<uint8_t>> res = unpack_payload(data);

    tdata td;
    td.version = res.first;
    td.raw_payload = res.second;
    td.start = start;
    td.end = end;

    printf("[*] Version: %d\n", res.first);
    std::cout << "[*] Raw Payload len: " << res.second.size() << std::endl;


    // std::sort(CLIENT_VEC.begin(), CLIENT_VEC.end());
    int flag = get_versioned_key(&td);
    if(flag == 0){
        std::cout << "[!] Not Found\n\n" << std::endl;
    }
    return 0;
}
```
and we get the output as 

![alt text](image-38.png)

as well this can be made efficient by

```py
import sys
import subprocess

NO_OF_PROCESS = 10

def main():
    if(len(sys.argv) < 3):
        print(f"[!] Usage: {sys.argv[0]} <start> <end>")
        exit(0)
    start = int(sys.argv[1], 10)
    end = int(sys.argv[2], 10)
    interval = (end - start) // NO_OF_PROCESS

    for i in range(NO_OF_PROCESS):
        rstart = start + (interval * i)
        rend = rstart + interval
        print(f"[*] Py: Started Process {i} rstart: {rstart} rend: {rend}")
        subprocess.run(["./dbx-crack", str(rstart), str(rend)])

main()
```

now we can use this on the tool and get the details, here is what I edited in the tool.

```py
#!/usr/bin/env python

import hashlib
import ctypes
import ctypes.util
import os
import hmac
try:
    import simplejson
except ImportError:
    import json as simplejson
import struct
import base64
# requires pip install pbkdf2
from pbkdf2 import PBKDF2

import binascii
import glob

BUILD_KEY = "dropbox"
CLIENT_KEY_NAME = u'Client'

# --------------------------------------------------
# Taken from common_util/keystore/keystore_posix.py
#
# NOTE: original version is based on ncrypt
# http://pypi.python.org/pypi/ncrypt/

try:
    import Crypto
except ImportError:
    import crypto
    import sys
    sys.modules['Crypto'] = crypto

#CIPHER_TYPE = CipherType('AES-128', 'CBC')
from Crypto.Cipher import AES

class KeyStoreFileBacked(object):

    def __init__(self, appdata_path):
        self._appdata_path = appdata_path
        c=40370414 # bruteforced uid
        self._s = self.id2s(c)
        self._i = 'l\x078\x014$sX\x03\xffri3\x13aQ'
        self._h = '\x8f\xf4\xf2\xbb\xad\xe9G\xea\x1f\xdfim\x80[5>'
        self._f = os.path.join(self._appdata_path, u'hostkeys')
        self._dict = None
        # simplified version

    def id2s(self, _id):
        return hashlib.md5('ia9%sX' % _id + 'a|ui20').digest()

    def obfuscate(self, data):
        encryptor = AES.new(key=self._s, mode=AES.MODE_CBC, IV=self._i)
        return encryptor.encrypt(data)

    def _unobfuscate_low(self, data, key):
        decryptor = AES.new(key, mode=AES.MODE_CBC, IV=self._i)
        return decryptor.decrypt(data)

    def unobfuscate(self, data):
        return (self._unobfuscate_low(data, self._s), False)

    def unversionify_payload(self, data, hmac_keys):
        version = ord(data[0])
        if version not in hmac_keys:
            raise Exception('Parsing error, bad version')
        hm = hmac.new(hmac_keys[version])
        ds = hm.digest_size
        if len(data) <= ds:
            raise Exception('Bad digest size')
        stored_hm = data[-ds:]
        payload = data[:-ds]
        hm.update(payload)
        if hm.digest() != stored_hm:
            raise Exception('Bad digest')
        return (version, payload[1:])

    def _load_dict(self):
        if self._dict is not None:
            return

        data = open(self._f).read()

        # Overly simplified version
        version, raw_payload = self.unversionify_payload(data, {0: self._h})
        payload, needs_migrate = self.unobfuscate(raw_payload)
        # Manually remove AES-CBC padding ...
        pad = -(ord(payload[-1]))
        payload = payload[:pad]

        self._dict = simplejson.loads(payload)
        return

    def get_key(self, name):
        self._load_dict()
        return base64.decodestring(self._dict[name])

    def get_versioned_key(self, name, hmac_keys):
        data = self.get_key(name)
        if not data:
            raise Exception('No Data')
        return self.unversionify_payload(data, hmac_keys)

class KeyStore(KeyStoreFileBacked):

    def unique_id(self, path):
        inode = os.stat(path).st_ino
        print 'KEYSTORE: unique_id = %r %s'  % (path, '%d' % inode)
        return ('%d' % inode).encode('ascii')

# ---------------------------------------------
# ...

class Version0(object):
    USER_HMAC_KEY = '\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    APP_KEY = '\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    APP_IV = '\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    APP_ITER = 1066
    USER_KEYLEN = 16
    DB_KEYLEN = 16

    def new_user_key_and_hmac(self, ks):
        return (ks.get_random_bytes(self.USER_KEYLEN), self.USER_HMAC_KEY)

    def get_database_key(self, user_key):
        return PBKDF2(passphrase=user_key, salt=self.APP_KEY, iterations=self.APP_ITER).read(self.DB_KEYLEN)

# ---------------------------------------------
# ...

class DBKeyStore(object):

    def __init__(self, appdata_path):
        self.parsers = {0: Version0()}
        self.hmac_keys = dict(((v, self.parsers[v].USER_HMAC_KEY) for v in self.parsers))
        self.ks = KeyStore(appdata_path)
        # simplified version
        # ...
        return

    def get_user_key(self):
        version, user_key = self.ks.get_versioned_key(CLIENT_KEY_NAME, self.hmac_keys)
        # Original displays dropbox_hash() instead
        print 'KEYSTORE: got user key (%d, %s)' % (version, binascii.hexlify(user_key))
        return (version, user_key)


# ---------------------------------------------
appdata_path = ("/mnt/d/bi0sctf/chall4/dropbox/instance1/")
dbks = DBKeyStore(appdata_path)
user_key = dbks.get_user_key()
print "User key: ", binascii.hexlify( user_key[1] )

v0 = Version0()
db_key = v0.get_database_key(user_key[1])
print "Database key: ", binascii.hexlify( db_key )
```
![alt text](image-39.png)

```
KEYSTORE: got user key (0, e747b9c8cc2f80b88c6b511f26682b66)
User key:  e747b9c8cc2f80b88c6b511f26682b66
Database key:  89839f76862bd89b369d99f41ca51cd7
```

so `dbkey: 89839f76862bd89b369d99f41ca51cd7` 

now we can use this [tool](https://github.com/newsoft/sqlite3-dbx) to decrypt and view the dbx file.

```bash
sqlite -key b7b04158ee71df20a80d1a70113798c1 <path to config.dbx>
```

![alt text](image-40.png)

from which we can get the required information that is: 

```
client email :twoface2681988@gmail.com
client name  :Harvey Dent
private_key:MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJGmnt3gVtSX2iswJYf9S3I5X4vPaS1xKHAvFdN5A2tWhRANCAASO63HNoO6rpC9Gfpi5tR+F5kEiRoTzbV/xWscN9McLCTlj2gWtZ+LSrkQkuaO5/XYiHXxCF/1vRWuNspXwY/K9
```

```
Answer12: 89839f76862bd89b369d99f41ca51cd7:twoface2681988@gmail.com
```

#### Question 13
Q13) what is the information interpreted further from previous question
Format: name_client:private_key

so we can answer this from the above analysis

```
Answer13: harvey_dent:MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJGmnt3gVtSX2iswJYf9S3I5X4vPaS1xKHAvFdN5A2tWhRANCAASO63HNoO6rpC9Gfpi5tR+F5kEiRoTzbV/xWscN9McLCTlj2gWtZ+LSrkQkuaO5/XYiHXxCF/1vRWuNspXwY/K9
```

#### Question 14
Q14) what is the userkey of the encrypted dbx database?
Format: userkey
![alt text](image-41.png)

`userkey:e747b9c8cc2f80b88c6b511f26682b66`

```
Answer14 : e747b9c8cc2f80b88c6b511f26682b66
```

and after this, we finally finish the Adventure! and yeah we made Batman uncover the most underground corruption that was happening in Gotham.

### flag
```
bi0sctf{b4tm4n_und3rgr0und_inv3st1g4t10n_Succ3ssful_f98a12405d41746836bb4e7df69e44f6}
```
## Closing Note

Thank you to everyone who tried the challenge. We thank you for playing the CTF and would love to hear some feedback about the challenge. 
If you have any queries regarding the challenge, feel free to hit me up over twitter/discord.


**Contact**: Azr43lKn1ght | [twitter](https://twitter.com/Azr43lKn1ght) | [Linkedin](https://www.linkedin.com/in/azr43lkn1ght?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app) | [github](https://github.com/Azr43lKn1ght)