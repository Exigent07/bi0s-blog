---
title: MIX & MASH - InCTF Internationals 2020
date: 2020-08-14 06:41:04
author: v3ct0r
author_url: https://twitter.com/__v3ct0r__
categories:
  - Crypto
tags:
  - InCTFi
---

**tl;dr**

+ Extract higher bits of secret using input manipulation
+ Extract lower bits of secret using the highers bits and input manipulation

<!--more-->

**Challenge points**: 925 
**No. of solves**: 14 
**Challenge Author**: [v3ct0r](https://twitter.com/__v3ct0r__)

## Challenge description

 	Keep this off the record, cause it is pro stuff

## Initial analysis

Challenge is based on Permutation Based Crypto Algorithm called Proest-OTR, with a custom 64-bit permutation instead of Proest. In the service you could either encrypt any 64 bit message or get the flag if you give the correct secret. 

Here is the challenge script :

```python
#!/usr/bin/env python2
import random
import sys
from stuff import flag


def ROL32(x, y):
    return (((x) << (y)) ^ ((x) >> (32 - (y)))) & 0xFFFFFFFF


def LSB(x):
    return x & 0x00000000FFFFFFFF


def TIMES2(x):
    if (x & 0x8000000000000000):
        return ((x << 1) ^ 0x000000000000001B) & 0xFFFFFFFFFFFFFFFF
    else:
        return (x << 1) & 0xFFFFFFFFFFFFFFFF


def TIMES4(x):
    return TIMES2(TIMES2(x)) & 0xFFFFFFFFFFFFFFFF


def MIX(hi, lo, r):
    hi += (lo & 0xFFFFFFFF)
    lo = ROL32(lo, r)
    lo ^= (hi & 0xFFFFFFFF)
    return hi & 0xFFFFFFFF, lo & 0xFFFFFFFF


def PERM64(x):

    rcon = [1, 29, 4, 8, 17, 12, 3, 14]
    hi = x >> 32
    lo = LSB(x)

    for i in range(32):
        hi, lo = MIX(hi, lo, rcon[i % 8])
        lo += i
    return ((hi & 0xFFFFFFFFFFFFFFFF) << 32) ^ lo


def EMR64(k, p):
    return PERM64(k ^ p) ^ k


def encrypt(key, n, m, x):

    l = TIMES4(EMR64(key, n))
    c = EMR64(key, l ^ m) ^ x
    return c


if __name__ == "__main__":

    secret_key = random.getrandbits(64)
    x = random.getrandbits(64)


    for _ in range(140):
        
        print "[1] Encrypt"
        print "[2] Get Flag"
        print "[3] Exit"

        try:
            ch = int(raw_input('\nEnter option > '))
        except:
            print "Error!"
            sys.exit()
        if ch == 1:
            try:
                off = int(raw_input('\nEnter offset for key > '))
                n = int(raw_input('\nEnter Parameter n > '))
                m = int(raw_input('\nEnter Message > '))
               
                m = m & 0xFFFFFFFFFFFFFFFF
                c = encrypt(secret_key + off, n, m, x)
                print "\nCiphertext: ", hex(c).strip('L'), "\n"
            except:
                print "Something went wrong!"
                sys.exit()

        elif ch == 2:
            try:
                secret = int(raw_input('Enter Secret Key > '))
            except:
                print "Error!"
                sys.exit()
            if secret == secret_key:
                print "Here is your Flag [+] ", flag

            else:
                print "Wrong Secret!"
                sys.exit()


        elif ch == 3:
            print "Bye!"
            sys.exit()
        else:
            print "Error!"
            sys.exit()


```

 
## Solution :

Step 1: Recovering the most significant half of the key

It is straightforward to see that one can recover the value of the bit `k[i]` by performing only two queries with related-keys and different nonces and messages. One just has to compare `c1 = F(k, n, m, x)` and `c1 = F(k + ∆i, n ⊕ ∆i, m ⊕ ∆i ⊕ π(∆i) ,x)` .

Indeed, if `k[i] = 0`, then the value `l` obtained in the computation of `c1_` is equal to `l ⊕ ∆i` and `l1 = l ⊕ π(∆i)` , hence `c1_ = c1 ⊕ ∆i`. If `k[i] = 1`, the latter equality does not hold with overwhelming probability.

Hence you can recover it bit by bit.


Step 2: Recovering the least significant half of the key. 
	

Similarly extract the most signigicant part of the least significant half.

	
For more details refer this [paper](https://eprint.iacr.org/2015/134.pdf)	

Here is the exploit script:

```python

from pwn import *
from hashlib import *
import random, string
from pwnlib.util.iters import mbruteforce
import re, codecs

def TIMES2(x):
    if (x & 0x8000000000000000):
          return ((x << 1) ^ 0x000000000000001B) & 0xFFFFFFFFFFFFFFFF
    else:
        return (x << 1) & 0xFFFFFFFFFFFFFFFF


def TIMES4(x):
    return TIMES2(TIMES2(x)) & 0xFFFFFFFFFFFFFFFF


def ROL32(x, y):
    return (((x) << (y)) ^ ((x) >> (32 - (y)))) & 0xFFFFFFFF


def MSB(x):
    return x & 0xFFFFFFFF00000000


def LSB(x):
    return x & 0x00000000FFFFFFFF


def DELTA(x):

    return 1 << x


def MIX(hi, lo, r):
    hi += (lo & 0xFFFFFFFF)
    lo = ROL32(lo, r)
    lo ^= (hi & 0xFFFFFFFF)
    return hi & 0xFFFFFFFF, lo & 0xFFFFFFFF


def p64(x):

    rcon = [1, 29, 4, 8, 17, 12, 3, 14]
    hi = x >> 32
    lo = LSB(x)

    for i in range(32):
        hi, lo = MIX(hi, lo, rcon[i % 8])
        lo += i

    return ((hi & 0xFFFFFFFFFFFFFFFF) << 32) ^ lo


def em64(k, p):

    return p64(k ^ p) ^ k


def encrypt1(key, n, m, x):

    l = TIMES4(em64(key, n))
    c = em64(key, l ^ m) ^ x

    return c


def recover_high():
    kk = 0

    for i in range(62, 31, -1):
        m1 = random.getrandbits(64)
        m2 = random.getrandbits(64)
        n = (random.getrandbits(32) << 32) ^ 0x80000000

        c11 = encrypt(0, n, m1)

        c12 = encrypt(+ DELTA(i), n ^ DELTA(i), m1 ^ DELTA(i) ^ TIMES4(DELTA(i)))
        if (c11 != (c12 ^ DELTA(i))):
            kk |= DELTA(i)

    return kk


def recover_low(hi_key):
    kk = hi_key
    for i in range(31,-1,-1):
        m1 = random.getrandbits(64)
        m2 = random.getrandbits(64)
        n = random.getrandbits(64)

        delta_p = DELTA(i) - MSB(kk) + (((LSB((~kk)) >> (i + 1)) << (i + 1)))
	delta_m = DELTA(i) + MSB(kk) + LSB(kk)

	c11 = encrypt( + delta_p, n ^ DELTA(32), m1 ^ DELTA(32))
	c12 = encrypt( - delta_m, n, m1 ^ TIMES4(DELTA(32)))

        if (c11 == (c12 ^ DELTA(32))):
            kk |= DELTA(i)

    return kk

    


def potr_1(n, message, x):
    return encrypt(secret_key, n, message, x)


def encrypt(off, n, m):
    io.sendline('1')
    io.recvuntil('Enter offset for key > ')
    io.sendline(str(off))
    io.recvuntil('Enter Parameter n > ')
    io.sendline(str(n))
    io.recvuntil('Enter Message > ')
    io.sendline(str(m))
    io.recvuntil('Ciphertext: ')
    c = io.recv()
    c = c.split()[0]
    
    c = int(c,16)
    if io.can_recv(): io.recv()
    return c


def bruteforce(suffix, digest):
    """
    Multithreaded POW solver for custom challenge designs
    INPUT:
    @partial: bytes
    @digest: str

    OUTPUT:
    X: sha256(X + suffix).hexdigest() == digest
    """
    return mbruteforce(
        lambda x: hashlib.sha256(x.encode() + suffix).hexdigest() == digest,
        string.ascii_letters + string.digits,
        length = 4,
        method = "fixed"
    )


def pow_handler():
    """
    Handler function to parse, and solve POW challenges
    """
    global io

    data = str(io.recv())
    suffix = re.search(r"[\w]{16}", data).group().encode()
    digest = re.search(r"[\w]{64}", data).group()
    prefix = bruteforce(suffix, digest)
    if io.can_recv(): io.recv()
    io.sendline(prefix)




if __name__=="__main__":
   
    #io = process('./encrypt.py')
    io = remote('34.74.30.191', 6666)
    pow_handler()
    if io.can_recv(): print io.recv()
    
    secret = recover_low(recover_high())
    if io.can_recv(): io.recv()
    io.sendline('2')
    io.recv()
    io.sendline(str(secret))
    print io.recv()
    io.interactive()
    if io.can_recv():
        print io.recv()
    print "secret is ", hex(secret) ,"or" , hex(secret^0x8000000000000000)

``` 
Here is the Flag: `inctf{Wow_U_R_r34lly_g00d_4t_7h1s}`


 
	
