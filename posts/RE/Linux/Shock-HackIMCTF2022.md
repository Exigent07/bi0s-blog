---
title: Shock - HackIM CTF 2022
date: 2022-08-16 12:36:15
author: k1n0r4
author_url: https://twitter.com/k1n0r4
categories:
  - RE
  - Linux
tags:
  - CTF
  - ltrace
---

**tl;dr**

+ This challenge comes under easy level challenge.
+ The binary has a script being executed using execvp.

<!--more-->

**Challenge Points**: 481 
**No. of solves**: 12 
**Solved by**: [AmunRha](https://twitter.com/amun_rha), [Ad0lphus](https://twitter.com/Ad0lphu5), [Barla Abhishek](https://twitter.com/barlabhi), [k1n0r4](https://twitter.com/k1n0r4)

## Description

Our new sys admin is shocked, because the old grumpy one left nothing but these weird binaries which he called 'shell scripts'.

Can you help?

Hint: We built this in a debian bullseye docker container.

## Solution

In this challenge we are provided with an elf binary and on executing we get the output as shown below. 

![](https://i.imgur.com/AHv6Mh7.png)

<hr>

### Analysis

On statically analysing the binary we see that the input statement and output statements are no where to be found in the strings section of the binary plus we have a execve instruction in our binary under a function inside main function, which surely means that we have an another script running within our main binary. 


### Anti-Debug check 

While analysing we could also see an anti-debugging test, that is, ptrace. First I went on to pass this debugging test by nopping out the function by adding a ret statemnet at the beginning of the function. Now we are free to debug it or trace it. 


### Final Step

Hereafter we simply use the ltrace command with the binary 

![](https://i.imgur.com/tyevg1c.png)

![](https://i.imgur.com/KErTq82.png)

We see that the script being executed is copied up using memcpy and then executed using execvp, thus the trace function gives away the content of the script being copied, including the flag that our input is getting compared with. 


### Flag

```Flag - ENO{SH3LL_SCr1Pts_N0t_S3cur3}```
