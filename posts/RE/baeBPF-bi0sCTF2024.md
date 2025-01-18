---
title: baeBPF - bi0sCTF 2024
date: 2024-03-03 18:37:08
author: Chee-tzu
categories:
  - RE
tags:
  - bi0sCTF
  - eBPF
---

**tl;dr**

+ Analysis of eBPF assembly 
+ Simple optimization

<!--more-->

**Challenge points** : 230
**No. of solves**: 37
**Challenge Author** : Chee-tzu

## Challenge description:
eBPF?? What is that??? wrap flag with bi0sctf{}


## Solution

## Level 1:

![alt text](img_1.png)

All the r1 ≠ <some_val> is for the filename, getting the values convert them to ascii, you will get `flag.txt`

You will find similar repeating elements inside the dump, of which another one being

![alt text](img_2.png)

That along with the map dump will get us the password for level_1

## Level 2:

After getting the dump , you can understand that its classic `TEA` encryption 
And the keys being {0x12341234,0x12341234,0x12341234,0x12341234}

Decrypting the dump given with the keys using classic `TEA` decryption will give you the 3rd part of the challenge

```cpp
#include <stdio.h>
#include <stdint.h>

void decrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

int main() {
    long long int vals[] = {<data_arr_dump>};
    for(int i = 0; i < sizeof(vals)/sizeof(vals[0]); i+=2) {
        uint32_t v[2] = {vals[i], vals[i+1]};
        uint32_t k[4] = {0x12341234, 0x12341234, 0x12341234, 0x12341234};
        decrypt(v, k);
        
        printf("%llx", v[0]);
        printf("%llx", v[1]);
    }
    return 0;
}
```

```python
 val = bytes.fromhex('646566207265636375722869293a200a20202020206966286e6f742069293a0a20202020202020202072657475726e20310a202020202069662869203d3d203
 1293a0a20202020202020202072657475726e2020330a202020202076616c5f32203d2032202a72656363757228692d31290a202020202072657475726e2076616c5f32202b20332a207
 2656363757228692d3229200a2020202020657869742829200a656e635f666c6167203d205b3130322c37352c3136332c3233392c3135362c3135382c372c3134332c39322c3132302c3
 02c35342c3138332c36352c3139392c3235332c36302c3138322c3230345d200a666f72206920696e2072616e6765283230293a0a20202020666c61675f76616c203d20656e635f666c6
 1675b695d0a202020206374725f76616c203d20726563637572282869202a2069292b312925203235360a2020202076616c203d20666c61675f76616c205e206374725f76616c200a202
 020207072696e742820290a202020207072696e74286368722876616c292c656e643d222229202020875a6ff8d42f51b0')
 with open('fin_file.py', "wb") as f:
     f.write(val)
```

This the resulting python file(ignore the redundant random bytes at the end)

```python
def reccur(i): 
     if(not i):
         return 1
     if(i == 1):
         return  3
     val_2 = 2 *reccur(i-1)
     return val_2 + 3* reccur(i-2) 
     exit() 
enc_flag = [102,75,163,239,156,158,7,143,92,120,0,54,183,65,199,253,60,182,204] 
for i in range(20):
    flag_val = enc_flag[i]
    print(reccur((i * i)+1)% 256)
    ctr_val = reccur((i * i)+1)% 256
    val = flag_val ^ ctr_val 
    print( )
    print(chr(val),end="")
```

Now what is left is to optimize it, and the simplefied optimization is :-

```python
enc_flag = [102,75,163,239,156,158,7,143,92,120,0,54,183,65,199,253,60,182,204]
for i in range(len(enc_flag)):
     val = (3 ** ((i ** 2)+1)) % 256
     print(chr(enc_flag[i] ^ val),end="")
```

And there you go, you got the flag!!!.

`bi0sctf{eBPF_wtF_1s_th4t???}`