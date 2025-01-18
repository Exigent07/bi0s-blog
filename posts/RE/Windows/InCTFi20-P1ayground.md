---
title: P1ayground - InCTF Internationals 2020
tags: 
  - Reversing 
  - Windows
  - APIhooking
  - InCTFi
categories:
  - Reversing 
  - Windows
date: 2020-8-14
author: leArner 
author_url: https://twitter.com/Ashwathi_sasi
---

 A brief write-up of the intended solution of P1ayground challenge from InCTF Internationals 2020

tl;dr 
- Challenge is based on function hooking at runtime.
- On reversing you will find 4 functions at the same address but executing different code(basically hooked at runtime).
- Jump inside each function, reverse the algorithms to pass the checks.
- Ignore the FAKE flag check.

<!--more-->

**Challenge Points**: 979
**Challenge Solves**: 10
**Challenge Author**: [leArner](https://twitter.com/Ashwathi_sasi)

## Challenge description

![Description](description.png)

## Initial Analysis 

In this challenge, we are given a PE32+ executable for windows. Running the file at first looks like it does nothing.

![File](File.PNG)

- The first check is of flag format and length of the flag.

- On further reversing we will find 4 functions at the same address but executing different code.
    - The input is encoded using a square cipher of 8x8 matrix.
    - Then the string is xored and this string is converted to one hot encoding using the index value form [a-z] 
    - The one hot encoding of each character is considered as binary number and converted to integer then compared with a stored array.
    - Both the previous checks is validated using a `check` variable.
- If the `check` variable is correct then the input is correct.  


```python
in_array = [4194304 ,16384 ,2 ,262144 ,8192 ,1 ,2048 ,64 ,65536 ,256 ,524288 ,33554432 ,262144 ,32768 ,65536 ,33554432 ,4096 ,2048 ,512 ,16384 ,32 ,512 ,256 ,16384 ,65536 ,2097152 ,524288 ,262144 ,128 ,8388608 ,2048 ,32768 ,8 ,64 ,8192 ,262144 ,1024 ,512 ,8192 ,32 ,8192 ,65536 ,4194304 ,8 ,16 ,32 ,512 ,65536 ,1 ,33554432 ,16777216 ,32768 ,262144 ,8388608 ,8192 ,2097152]
x = [57, 39, 27, 25, 40, 23, 62, 63, 64, 48, 44, 61, 63, 65, 66, 75, 92, 9, 12, 5, 60, 4, 7, 9, 32, 41, 56, 24, 58, 1, 43, 9, 49, 16, 24, 71, 15, 18, 61, 20, 42, 34, 48, 29, 41, 23, 32, 23, 3, 18, 54, 19, 82, 29, 95, 19]
st_p1 = [ '9', 'i', 'b', 'P', 'w', 'R', '3', 'k', 'e', 'j', 'Z', 'O', 'p', 'd', '_', 'r', 'c', 'N', '!', 'n', 'K', '6', 'A', 'F', '7', '4', 'I', 'M', '2', 'B', 'H', '1', 'h', 'f', 'T', 'V', 'Q', 'L', 'a', 'q', 'z', '5', 'u', 'U', 'G', 'l', '8', 'm', 't', 'o', 'E', 'x', 'S', 'J', 'D', 'W', 'g', 'C', 's', 'Y', 'X', 'y', '0', 'v' ]
st_c1 = [ 'U', 'H', 'F', 'B', '6', 'l', 'g', '7', 'f', 'n', 'S', 'P', '_', 'J', 's', '!', 'k', 'r', 'Y', 'E', '3', 'i', '2', 'e', 'q', 'u', 'N', 'O', 'L', 'c', '4', 't', 'D', 'x', 'M', '5', 'b', 'w', 'W', 'K', 'X', 'm', 'd', 'h', 'T', 'o', 'C', '0', 'R', 'z', 'Z', 'p', 'Q', 'j', 'G', 'I', 'y', '8', '1', 'V', 'v', 'a', '9', 'A' ]
st_c2 = [ '8', 'W', 'm', 'L', 'b', 'z', 'F', 'q', 'e', 'k', '6', 'u', 'I', 'V', 'H', '5', 'l', 'O', 'E', '7', 'g', '9', 'd', 'C', 'y', 'S', 'G', 's', 'T', 'j', 'w', 'X', 'n', 'Q', 'o', 'Y', 'v', 'J', 'r', 'K', 'M', '4', '2', '_', 'i', 'R', 'N', '!', 'h', 'B', 'D', '1', 'A', '0', 'f', '3', 'p', 'U', 'x', 'a', 't', 'P', 'Z', 'c' ]
st_p2 = [ '4', '1', 'R', '5', 's', 'o', '7', 'z', '!', '9', '3', 'p', 'c', 'g', 'T', 'n', 'S', 'I', 'b', 'v', 'i', 'W', 'O', 'x', '_', 'e', 'G', 'u', 'f', 'D', 'h', 'Q', 'V', 'J', '0', 'd', '2', 'F', 'j', 'U', 'y', 'L', '8', 'M', 'r', 'q', 'A', 'Z', '6', 'E', 'B', 'Y', 'a', 'C', 'N', 'K', 'w', 'k', 'X', 'l', 'H', 'P', 't', 'm' ]
st = "abcdefghijklmnopqrstuvwxyz"
char_array = []

s1 = ""
for i in range(len(in_array)):
  s1 = s1 +chr(ord(st[len(str(bin(in_array[i])))-3])^x[i])
flag = ""
for j in range(0,len(s1),2):
  p = st_c1.index(s1[j])
  q = st_c2.index(s1[j+1])
  x1,y1 = int(p/8),q%8
  x2,y2 = int(q/8),p%8
  flag = flag+st_p1[x1*8+y1]+st_p2[8*x2+y2]

print("inctf{"+flag+"}")
```


### Flag

`inctf{H3y_w0W_Y0u_Manag3d_t0_Exr4ct_th3_CruX_0f_th1s_Cha1leng3}`