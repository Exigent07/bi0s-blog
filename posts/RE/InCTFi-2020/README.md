---
title: Reversing - InCTF Internationals 2020
tags: 
  - InCTFi
categories:
  - Reversing 
date: 2020-8-14
author: 4le31 
---

 A brief write-up detailing solutions of Reversing Challenges from InCTF Internationals 2020
<!--more-->


We are releasing the source code for all of the Reversing Challenges from InCTFi 2020, you can find them [here](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing).
In this blog post, you can find a short description on how you can solve each of these challenges

## [RE Warmup](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/RE_warmup)

Author: R3x

I added a command line flag into the code for GNU strings and generated a buffer from extracted strings. The strings were then compared in a destructor for the ELF. It was meant as a pun on most CTFs having to do strings on RE challenges as warmup.

## [ArchRide](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/ArchRide)

Authors: 4lex1, Mr_UnKnOwN

The challenge solution script has been added [here](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/ArchRide/Admin/Solution) which is the intended solution. The unintended approach is that the header of the bzip can be used to bruteforce the input to each level and the binaries can be emulated and run in the various archs to get the flag.

Total no of levels: 120

## [jazz](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/jazz)

Author: k4iz3n

The challenge implements a simple variant of Substitution Cipher where multiple tables are created using a seeded random function. The challenge can be solved in multiple ways, either by creating the tables using the same seed, by dumping the tables or by running a single byte brute force. To make it less obvious that a single byte brute force is possible, AES encryption with known key was added at the end.
The challenge was a Rust release binary. Making the reversing process more challenging than usual.
Some good write-ups for the above mentioned approaches: 
[https://daniao.ws/inctf-20/jazz](https://daniao.ws/inctf-20/jazz)
[https://sudhackar.github.io/blog/INCTF-reversing-writeups](https://sudhackar.github.io/blog/INCTF-reversing-writeups)



## [FuncAnalyzer](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/FuncAnalyzer)

Author: R3x

This was an LLVM analysis pass which did analysis on the bitcode file provided. Some of the checks were number of IF statements without ELSE statements, pointer arithmetic etc.

## [P1Ayground](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/Hooking-APIcalls)

Author: leArner

tl;dr 
- Challenge is based on function hooking at runtime.
- On reversing you will find 4 functions at same address but executing different code(basically hooked at runtime).
- Jump inside each fucntion, reverse the algorithms to pass the checks.
- Ignore the FAKE flag check.

Find full writeup [here](https://blog.bi0s.in/2020/08/14/RE/Windows/InCTFi20-P1ayground/)


## [Demoscene](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/demoscene)
Author: Freakston, silverf3lix

An encryptor that encrypts an exe using a simple xor function and some correction may be required for carriage return characters which gives out an exe containing the flag in a function that controls the FPS of the graphics displayed.


## [2^gubed](https://github.com/teambi0s/InCTFi/tree/master/2020/Reversing/2%5Egubed)

Author: R3x, Ayushi

A debugger implemented in Go. The players has to submit a C file which is then compiled and run under debugger. One should be able to hit certain breakpoints in a definite order. 
The file should have functions which would mmap a particular region of memory and execute a self mutating shellcode which helps to pass the conditions which include - checks for values stored in variables and registers, number of breakpoints. Additional checks include - seccomp filters to check for syscalls like printf. 
Link to the solution script - [test.c](https://github.com/ais2397/InCTF-rev/blob/master/InCTFi-2020/2%5Egubed/Admin/tester/test.c)