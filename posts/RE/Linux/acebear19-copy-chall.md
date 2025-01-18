---
title: Copychall - Acebear CTF 2019
date: 2019-04-25 13:51:00
author: R3x 
author_url: https://twitter.com/Tr3x__
tags:
  - Linux Reversing
categories:
  - Reversing 
  - Linux
---
tl;dr 

- You need to pass 999 levels to get the flag.
- Each of the levels involves multiple checks on input characters.
- Each check happens in seperate functions which are decrypted during runtime.
- Extract function order and arguments.
- Automate finding input for each check.

<!--more-->

**Challenge Points**: 951
**Challenge Solves**: 4
**Solved by**: [R3x](https://twitter.com/Tr3x__), [k4iz3n](https://twitter.com/akulpillai), [silverf3lix](https://twitter.com/__silv3r)
	
## Initial Analysis

Our initial approach was to manually reverse the first round and then find patterns
between each rounds since we thought they would be somehow similar. But we saw that
the order in which functions were called in each round was completely random.

Next step was to figure out the logic behind which all functions get executed and how
the arguments and return values are defined by the program. Some searching got us to
this really huge array(~2 Mb) which was being used to get function addresses and all.
Now we just need to figure out what each of the functions do.

## Analysis of the array dump

We did some diggging around the array to figure out what were the different parts of
the array and we noticed a pattern.

$ cat dump

 480d 4000  7200 0000 fd00 0000 0c00 0000 0300 0000 d120 0400 2ce7 0300 6714 0600 2b0e 4000

| fn addr | Don't care | index | size | results of each size inputs | next |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
|480d 4000|7200 0000 fd00 0000|0c00 0000|0300  0000|d120 0400 2ce7 0300 6714 0600|2b0e 4000|

We noticed the call to the function address in the array and the index of the input
in the array and size number of values were computed and compared with the
corresponding results given in the program.

Next step is to reverse the functions.

## Figuring out the different functions

There were a total of 7 functions in the code. We used the addresses to differentiate
each of them.

Most of them were very trivial to reverse. You can see the reverse implementation in
the python script below.

## Solving 999 rounds

We decided to perform the reverse opertations based on the dumped array. So I wrote
a script which would parse the function addresses and then return the corresponding
input.

```python
import struct

dic = {128: ']', 132: 'V', 133: 'y', 140: 'L', 144: 'w', 152: 'o', 280: 'l', 156: '}', 312: '~', 240: 'r', 162: 'j', 38: '%', 168: '{', 42: ')', 171: 'b', 44: '+', 48: '/', 180: 'v', 54: '5', 56: "'", 57: '1', 186: 'z', 60: ';', 62: '=', 63: ' ', 192: 'i', 224: '|', 195: 'H', 68: 'C', 182: 'u', 72: 'G', 74: 'I', 78: '-', 80: 'O', 248: 'p', 210: 't', 84: 'S', 216: 'n', 217: 'd', 90: 'Y', 91: '$', 93: '2', 96: 'M', 98: 'a', 102: 'e', 104: 'g', 252: '`', 234: 'Z', 108: 'k', 110: 'm', 112: '[', 360: 'x', 114: 'q', 120: '_', 121: 'Q', 124: 'K', 126: 'R', 127: '@'}

def reverse_1(val):
   inp = ""
   for i in val:
       inp += chr(i/0x1337)
   return inp

def reverse_2(val, size):
    inp = ""
    for i in range(size):
            inp += chr(val[i] ^ 4)
    return inp

def reverse_3(final, size):
    inp = ""
    for i in range(size):
        val = ((0xffffffff - final[i]) & 0xffffffff)
        for j in range(7, -1, -1):
            if (val >> 31) == 1:
                val = val ^ 0xedb88320
                val = ((val << 1) & 0xffffffff) | 1
            else:
                val = ((val << 1) & 0xffffffff) | 0
        char = val ^ 0xffffffff
        inp += chr(char)
    return inp

def reverse_4(final):
    inp = ""
    for i in final:
        inp += chr(i/2)
    return inp

def reverse_5(val):
    inp = ""
    for i in val:
        inp += dic[i]
    return inp

def reverse_6(val):
    inp = ""
    for i in val:
        di = ((0xcafebabe - i) / (0xaaaa + 0x1337)) * 2
        if (0xcafebabe - i) % (0xaaaa + 0x1337) != 0:
            di = di + 1
        inp += chr(di)
    return inp

def reverse_7(val):
    inp = ""
    for i in val:
        inp += chr(i ^ 0x1337)
    return inp

def round(op, ex_1, index_1, size_1):
    '''
    Switch based on the function address and modify the input accordingly
    '''
    if op == 0x400d48:
        chrs = reverse_1(ex_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400e2b:
        chrs = reverse_2(ex_1, size_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400f4e :
        chrs = reverse_3(ex_1, size_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400c0e:
        chrs = reverse_4(ex_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400eb5:
        chrs = reverse_5(ex_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400ca8:
        chrs = reverse_6(ex_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    elif op == 0x400dba:
        chrs = reverse_7(ex_1)
        for i in range(0, size_1):
            inp[i + index_1] = chrs[i]
    else:
        print "opcode not found : "+hex(op)
        exit()

def dump_parse():
    '''
    Parse the dump and pass it to be reversed
    '''
    op = int(struct.unpack("<I", f.read(4))[0])
    if op == 0:
        return -1
    f.read(8)
    index_1 = int(struct.unpack("<I", f.read(4))[0])
    size_1 = int(struct.unpack("<I", f.read(4))[0])
    ex_1 = []
    for i in range(size_1):
        ex_1.append(int(struct.unpack("<I", f.read(4))[0]))
    round(op, ex_1, index_1, size_1)

f = open('dump', 'r')
for j in range(999):
    inp = list("A"*64)
    print "starting level "+str(j)
    for i in range(40):
        if dump_parse() == -1:
            break
    '''
    Each of the opcode's are in a location (level_number << 9) * 4
    This is visible in the function which uses the array for checking password
    '''
    f.seek(((j + 1) << 9) * 4, 0)
    print "functions : " + str(i)
    print "password for level " + str(j) + "/999  :  " + "".join(inp)
```

The flag generation of the challenge was messed up due to some mistake by the admins - so they had asked us to send the output (Basically each of the 999 round passwords). We got the flag once we gave them the information. 

