---
title: dummyper - AeroCTF 2021
date: 2021-2-28 20:00:00
author:  fug1t1v3
author_url: https://twitter.com/fug1t1v31

categories:
  - Reversing
  - Linux

tags:
  - Reversing 
  - Linux
  - AeroCTF
  - AES_CBC

---

**tl;dr**

+ The dump has some encrypted functions
+ The encrypted bytes are being xorred with a 32 byte key 
+ Find the xor_key in the dump
+ Use xor_key offset to find the offset of AES_key and iv
+ AES_CBC decrypt to find flag 

<!--more-->

**Challenge Points**: 454
**Challenge Solves**: 18
**Solved by**: [silverf3lix](https://twitter.com/__silv3r), [Freakston](https://twitter.com/freakst0n), [fug1t1v3](https://twitter.com/fug1t1v31)

## Initial Analysis
We Opened the binary dump using ida and found that 2 functions(`sub_13a9`,`sub_1691`) were encrypted. 
```asm
loc_1691:                               ; CODE XREF: main+8↓p
LOAD:0000000000001691                 out     53h, al
LOAD:0000000000001693                 pop     rbp
LOAD:0000000000001694                 out     1, eax          ; DMA controller, 8237A-5.
LOAD:0000000000001694                                         ; channel 0 base address and word count
LOAD:0000000000001696                 std
LOAD:0000000000001697                 adc     [rdi+65h], cl
LOAD:000000000000169A                 movsb
LOAD:000000000000169B                 mov     ebx, 58D66E0Ah
LOAD:000000000000169B ; ---------------------------------------------------------------------------
LOAD:00000000000016A0                 dq 91870DBC4BC97160h, 1FEC1165698C4247h, 26B5D424EA599C8Ah
```
On further analysis we found that the function `sub_172A` was xorring the bytes from offset `13a9` to `0x13a9+895` with 32 bytes.
```c
{
  v3 = getpagesize();
  mprotect(sub_13A9 - sub_13A9 % v3, v3, 7);
  ptr = sub_13A9(0x20uLL);
  fread(ptr, 0x20uLL, 1uLL, stream);
  for ( i = 0; i <= 63; ++i )
  {
    v4 = rand() % 2047;
    v6 = sub_13A9(v4);
    fread(v6, v4, 1uLL, stream);
  }
  result = sub_13A9;
  for ( j = 0; j <= 895; ++j )
  {
    result = (sub_13A9 + j);
    *result ^= ptr[j % 32];
  }
  return result;
}
```
Also, the function `sub_188B` was dumping all sections of ELF and HEAP which means that the 32 bytes are there in the dump.
```c
  stream = fopen("/proc/self/maps", &off_3000 + 4);
  v3 = 0LL;
  fread(&ptr, 0xCuLL, 1uLL, stream);
  v12 = 0;
  off = strtoll(&ptr, 0LL, 16);
  lineptr = 0LL;
  do
    getline(&lineptr, &n, stream);
  while ( !strstr(lineptr, "[heap]") );
  src = strchr(lineptr, 45);
  if ( src )
  {
    strncpy(&dest, ++src, 0xCuLL);
    LOBYTE(v14) = 0;
    v3 = strtoll(&dest, 0LL, 16);
  }
  size = v3 - off;
  v8 = fopen("/proc/self/mem", &off_3000 + 4);
  if ( !v8 )
  {
    puts("NULL!");
    exit(1);
  }
  fseek(v8, off, 0);
  v9 = malloc(size);
  fread(v9, size, 1uLL, v8);
  fclose(v8);
  s = fopen("dump", "w");
  fwrite(v9, size, 1uLL, s);
  fclose(s);
```

## Recovering the original bytes
Since, Function prologue starts with `endbr64; push rbp; mov rbp, rsp` so we have the 8 bytes of the key.We then took the next 24 bytes in dump and xorred the encrypted bytes using IDAPython.

```python
ea = 0x13A9
a = [0x42,0x8C,0x81,0xC5,0xEA,0x13,0xE0,0xC2,0x15,0x5C,0x43,0x1D,0x54,0xB5,0x99,0xAA,0x2D,0x27,0x57,0x1A,0x26,0x5B,0x6D,0x00,0x68,0xC9,0x4B,0xF4,0x80,0xBA,0xCA,0x5E]

for i in range(896):
    tmp = get_wide_byte(ea + i)
    patch_loc = ea + i
    patch_byte(patch_loc,tmp ^ a[i%32])
```
After this we defined the functions and got the binary.

## Analysing the recovered bytes
We see that in one of the recovered functions our flag is being read and also srand() is being called and the seed is the timestamp which should be there in the dump.
```c
  stream = fopen(&off_3000 + 6, &off_3000 + 4);
  v0 = time(0LL);
  srand(v0);
  v2 = fopen("./flag.txt", &off_3000 + 4);
  v3 = sub_13A9(0x80uLL);
  fread(v3, 0x80uLL, 1uLL, v2);
  fclose(v2);
  return sub_13FE(v3);
```
It was also encrypting our flag using AES and the key and IV used to encrypt and the function doing this had one extra function which was calling memset() being called multiple times that was done to fill the heap with random bytes and all of this info is stored in the heap dump.
```c
{
  for ( i = 0; i <= 63; ++i )
  {
    v9 = rand() % 2047;
    v16 = sub_13A9(v9);
    fread(v16, v9, 1uLL, stream);
  }
  key = sub_13A9(0x20uLL);
  for ( j = 0; j <= 63; ++j )
  {
    v8 = rand() % 2047;
    v15 = sub_13A9(v8);
    fread(v15, v8, 1uLL, stream);
  }
  iv = sub_13A9(0x10uLL);
  for ( k = 0; k <= 63; ++k )
  {
    v7 = rand() % 2047;
    v14 = sub_13A9(v7);
    fread(v14, v7, 1uLL, stream);
  }
  fread(key, 1uLL, 0x20uLL, stream);
  fread(iv, 1uLL, 0x10uLL, stream);
  aes = sub_13A9(0xC0uLL);
  for ( l = 0; l <= 63; ++l )
  {
    v6 = rand() % 2047;
    v13 = sub_13A9(v6);
    fread(v13, v6, 1uLL, stream);
  }
  set_AES_key(aes, key);
  set_AES_IV(aes, iv);
  return AES_ENCRYPT(aes, a1, 0x80uLL);
}
```
As you can see First some random bytes are stored then the space for `key` is set then random bytes again then `iv` and random bytes again and then aes and `key` and `iv` is read and then the random bytes after all this the next memset called is for `xor_key`.Also, before all this memset our memset(flag,128) is also done and the starting point where it start writing this is 0x5060.

## Final Steps
So, using the offset of `xor_key` we can bruteforce the offset of timestamp.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
int main()
{
    void *v1;
    int ran;
    int sum;

    sum = 0x5060 + 128;

    long int c=1614211200;
    long int chae = 0;
    for (long int l = 0; l <=24*3600 ; l++)
    {
        chae = c+l;
        srand(chae);
        sum = 0x5060 + 128;
        printf("seed = %x\n", chae);
        for (int i = 0; i <= 63; ++i)
        {
            ran = rand() % 2047;
            //printf("%d\n",ran);
            sum = sum + ran;
        }
        printf("key at %x\n", sum);
        sum = sum + 32;
        for (int i = 0; i <= 63; ++i)
        {
            ran = rand() % 2047;
            //printf("%d\n",ran);
            sum = sum + ran;
        }
        printf("IV at %x\n", sum);
        sum = sum + 16;
        for (int i = 0; i <= 63; ++i)
        {
            ran = rand() % 2047;
            //printf("%d\n",ran);
            sum = sum + ran;
        }
        printf("aes object at %x\n", sum);
        sum = sum + 192;
        for (int i = 0; i <= 63; ++i)
        {
            ran = rand() % 2047;
            //printf("%d\n",ran);
            sum = sum + ran;
        }
        printf("xor key at %x\n", sum);
        printf("---------snip-----------\n");
        if (sum == 0x4ba74)
        {
            printf("%d found the seed\n", l, sum);
            exit(0);
        }
    }
}
```
In this script we are bruteforcing the timestamp until the last sum is 0x4ba74 and that is the offset for `xor_key`.We are also finding the respective `AES_key` and `iv`.And `CT` is from `0x5060` to `0x5060+0x80`.We then using ghex extracted the `AES_key` ,`iv` and the `CT`.
Now, the only thing left to do AES_CBC decrypt.
```python
from Crypto.Cipher import AES

key=b'8\x88.\xab\xe1\x0e\xf8\xfe\xb8\xd4\x96o \x16\xb7\xee'

iv=b'\x5A\x1E\xCC\x48\x93\x15\x93\x0F\x17\x6A\x76\xE6\x7A\xFA\xC4\xEF'

ct=b'\xa5\x8e\x82_\xc5f \x0cS\xfdr\x18\x13\xbd\x98\xb7aVp\x9d\xc3\'\xd2N_\xf0\xeb\xb4\x90\xba\xf5R*.\x9c^\xd3i\n\xbcd\xdb\x1e`1~\xedO\xc4\xb8\xa4\xfe>K\xcc\x90f*\x90D\x84\x1e\xbd\xd6\xf1W\x9a\xb3\xe0\x97\xb0\xdbP^\x8f\xa5 \n\xf3rU\x96\x07sE\x12\xb6\xca\xbd\xe0v\t\x89\xc0\x1cC\xb9\xbd%-\x0e\xa21<n0;f\x92\xbc\x1f\xbc\n\xce"\xb2%\xd7\x0b\xcb\xd0\xbeyh\xdc\xe4+\xc8'

def dec(data,key,iv): return AES.new(key, AES.MODE_CBC,iv).decrypt(data)

print(dec(ct,key,iv))
```
`Flag:Aero{d37fd6db2f8d562422aaf2a83dc62043}`
