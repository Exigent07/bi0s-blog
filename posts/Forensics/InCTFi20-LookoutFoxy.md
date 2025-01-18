---
title: Lookout Foxy - InCTF Internationals 2020
date: 2020-08-03 16:52:56
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
  - Forensics
  - Disk
tags:
  - Autopsy
  - InCTFi
---

**tl;dr**

+ Decrypt the encrypted GPG file found in Outlook Express with the private key stored on the device.
+ Decrypt the firefox saved passwords and log in to the website that the terrorist used.

<!--more-->

**Challenge points**: 627
**No. of solves**: 30
**Challenge Author**: [g4rud4](https://twitter.com/NihithNihi)

## Challenge description

![Description](description.png)

You can download the challenge file from [**Mega**](https://mega.nz/folder/MgtBHIhL#ChC7QdsEESP6_O-aALDSvw) or [**Google Drive**](https://drive.google.com/drive/folders/1EICM8RCZB4jHm63M6Y2Dua2Ir8zOaj5B?usp=sharing).

## Initial analysis

We are provided with an E01 file(Expert  Witness format image). There are a lot of ways in analyzing these files, I choose to use Autopsy for analyzing this. Let's go ahead and load our E01 file in Autopsy. You can visit [Autopsy's documentation](https://sleuthkit.org/autopsy/docs/user-docs/4.3/ds_page.html) if you don't know how to add a data source to autopsy.

From the description, we have a clue that the terrorist is using a **genuine chat client**, lets see what all applications are installed in the device.

As we know, all the applications present on the device can be found in `Program Files`. Some of the applications we need to check are `GPG`, `Mozilla Firefox`, `NetMeeting`, `Outlook Express`. Let us dig more into it and check if they have identified and configured.

![applications](applications.png)

So by checking application data, we can say that `Outlook Express` and `Mozilla Firefox` are configured. Let us dig more into them.

## First part solution

As the Outlook Express is configured on the device, it leaves us useful forensics artefacts on the device.

![application data](application_data.png)

Some of them are the emails received and sent. Whenever we receive a mail or delete a mail or sent a mail it will be stored in a **.dbx files**. Ex: for Inbox Emails - `inbox.dbx`, Sent Emails - `outbox.dbx` etc.

These files are stored at `C:\Documents and Settings\Crimson\Local Settings\Application Data\Identities\{random characters}\Microsoft\Outlook Express\`

In our case, these are stored at `C:\Documents and Settings\Crimson\Local Settings\Application Data\Identities\{72F33BC6-0035-4FE0-AED1-5870C5CA389E}\Microsoft\Outlook Express\`

![Outlook Express files](outlook_files.png)

You can see .dbx files being listed there on right. We know that we can't view the messages stored in **DBX** files. So I have converted the DBX file into a PDF file using this [**link**](https://www.coolutils.com/online/DBX-to-PDF). There are other ways too, as this gives us something similar to the GUI, I used this. And one of the best things is to do `strings` on the DBX files.

Converting the `Inbox.dbx` to PDF, One will be able to see that there is a mail from `David Banjamin davin.banjamin@gmail.com` with a subject `Secret File`. And a file named `secret.gpg` has been attached.

![Outlook_Inbox](inbox.png)

We can get this file by a simple keyword search in Autopsy or check below.

So these attached files are stored in this location, unless the user saved it into a specified location `C:\Users\{username}\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\{random characters}`.

We have 4 directories listed there, so rather than traversing through all directories, I used Autopsy's `Web Downloads` Result. There we can see that there is a `secret.gpg.Zone.identifier` file. These **Zone identifier** files are generated automatically by applications/programs when files are downloaded to a Windows computer. So by checking the `Source file path` we can get the random characters. So going into that directory(`U0PDHEH3`), we can get the `secret.gpg` file easily.

![Web Downloads Autopsy](web_downloads.png)

![Temporory internet files - secret.gpg](temintfil.png)

We know that the gpg files can only be decrypted by the Owner's private key. As we have seen a directory named `GPG` while traversing through the program files. Going into this directory we can find the `secret.key`.

Importing the private key and decrypting the encrypted GPG file, we can get the first half of the flag.

![GPG Import](gpg_import.png)

```bash
$ gpg --decrypt secret.gpg
```

Snipping the output,

![First half flag](firsthalfflag.png)

First half: **inctf{!_h0p3_y0u_L1k3d_s0lv1ng_7h3_F1rs7_p4r7_**

## Second part solution

As we see that there are a lot of web searches listed out in `Web History` results in Autopsy and going through them we can see a suspicious link **http://35.209.205.103/** in the history. So going to that link there is a login page. And there is a note saying **Don't brutefore the Password**. So the password must be saved somewhere.

![login](login.png)

As the terrorist is using firefox. And an active firefox installation will have a profile(in our case - **5ztdm4br.default**) which consists of a lot of forensics artefacts and that can be found generally at `C:\Documents and Settings\{Username}\Application Data\Mozilla\Firefox\{random characters}.default\`. In our case, these are found at `C:\Documents and Settings\Crimson\Application Data\Mozilla\Firefox\5ztdm4br.default\`

By Checking the `Web Form Autofill` results in Autopsy or by looking at the **formhistory.sqlite** database present in the firefox profile, we were able to see that the username as **Danial_Banjamin** and we need to find out the password.

As the username and password are stored in formhistory, that means passwords are stored in firefox saved passwords. We need to decrypt the saved passwords to get the original password.

Here comes the interesting part of decrypting Firefox saved passwords. There are a lot of ways

1. By dumping the whole profile and passing the dumped folder location to [firepwd](https://github.com/lclevy/firepwd).
2. By dumping only the required files from the profile.

I am choosing the second way and here are those files:

1. **logins.json** - Place where all login information such as encrypted username and password are stored.

2. **cert8.db** and **key3.db**/**key4.db** - These are encrypted SQLite database files, and the entries `encryptedUsername` and `encryptedPassword` found in logins.json are encrypted with the keys found in both databases.

3. **Permissions.sqlite** - It contains permissions for installing add-ons, cookies, etc.

After dumping all these files from the firefox profile mentioned above, I used `pwdecrypt` to decrypt the password. It's a Debian package and can be installed by with apt.

```bash
$ sudo apt install libnss3-tools
```

Then, I used a JSON parser(`jq`) to parse the JSON file and redirected the output to pwdecrypt.

Here is the JSON parsed output of logins.json.

```bash
$ jq . < logins.json

{
  "nextId": 3,
  "logins": [
    {
      "id": 2,
      "hostname": "http://35.209.205.103",
      "httpRealm": null,
      "formSubmitURL": "http://35.209.205.103",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECOczOqq7/ZDYBBC7w84JwpxUfkx1Nw52VKlx",
      "encryptedPassword": "MFoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECCwD7aXJGN+hBDAmr4dSU/2vXn+H+TZDl+oTlLGPMbX4usiAkneTan114d6kB2GGUa2b6771U5YIU40=",
      "guid": "{3ff55df0-bbb8-4192-98df-a1f428964c31}",
      "encType": 1,
      "timeCreated": 1595695030340,
      "timeLastUsed": 1595858974764,
      "timePasswordChanged": 1595695030340,
      "timesUsed": 2
    }
  ],
  "disabledHosts": [],
  "version": 2
}
```

As we are having so many entries, and we only need the username, password and URL. So added those entries to JSON parser and redirected it to **pwdecrypt**.

```bash
$ jq -r -S '.logins[] | .hostname, .encryptedUsername, .encryptedPassword' logins.json | pwdecrypt -d .

http://35.209.205.103
Decrypted: "Danial_Banjamin"
Decrypted: "2!6BQ&e626g#YNWxsQWV9^knO8#85*E%6Zaxr@At42"
```

As the master password was not set by the terrorist we were able to get the decrypted password. So logging in using those credentials gives the second part of the flag.

![second part](second_part.png)

Second Part of the flag: **4nd_3njoy3d_7he_53c0nd_p4rt_0f_7h3_ch4ll3ng3}**

## Flag

By concatinating two parts, here is the final flag:
**inctf{!_h0p3_y0u_L1k3d_s0lv1ng_7h3_F1rs7_p4r7_4nd_3njoy3d_7he_53c0nd_p4rt_0f_7h3_ch4ll3ng3}**

If you have any queries, Feel free to ping me. I am available on Twitter [@NihithNihi](https://twitter.com/NihithNihi)

## References

Here are some of the resources I came up while making the challenge. Hope it will be useful.

+ https://blog.tajuma.com/?p=35
+ http://raidersec.blogspot.com/2013/06/how-browsers-store-your-passwords-and.html
+ http://media.blackhat.com/bh-us-11/Bursztein/BH_US_11_Bursztein_Owade_Slides.pdf
