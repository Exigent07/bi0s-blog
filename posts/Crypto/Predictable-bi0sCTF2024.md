---
title: Predictable - bi0sCTF 2024
date: 2024-03-28 17:29:38
author: LS
author_url: https://twitter.com/mohithls
categories:
  - Crypto
tags:
  - bi0sCTF
  - Dual_EC_DRBG
  - NSA Backdoor
  - PRNG Prediction
---

**tl;dr**

+ Timing-based attack on the double-and-add algorithm to recover secret value `d`
+ Predict pseudo-random value using the NSA backdoor on Dual_EC_DRBG

<!--more-->

**Challenge Points**: 964
**No. of solves**: 9
**Solved by**: [LS](https://twitter.com/mohithls)

## Challenge Description

Can you help me test out this PRNG I implemented? I'm inserting a backdoor, but I'm sure you can't find it. Oh btw, I did some optimizing, so version 2 is faster. You can still try out version 1 though. They're the same anyway.

## Overview  

Source isn't provided for this challenge, and the only thing given to us is an nc connection.  
The description tells us that the service is a PRNG implementation, that has a backdoor inserted into it.  
It also tells us that there are two versions, that are essentially the same except for their speeds. 
```
Choose your version [1/2]
>
```
After we choose either version, it starts "computing parameters". It gives us a percentage of the progress. 
With multiple trials, it's also noted that the first version takes significantly longer than the second version, as implied by the challenge description. 
After the parameter computation, we're given a curve and two points on the curve.  
We're also given a menu following the two parameters, that looks like this: 
```
Curve: secp192r1
(2064958031430532587081997041839235219283658616799308490452, 3436621656979873912486085881613888167975620686870961904549)
(691481184530199221956209859923580998768043904110332072306, 614926827963334006071816178609509255009988990597010907912)
1. Get a random number
2. Predict
3. Exit
```
Seemingly, our goal is to predict the next random number. 
If we get a random number from the service, we get a number that's `240` bits long. 

## Approach

We have limited information about this service, but we know that it's a PRNG, and that it uses a curve and two points on the curve in some way. 
With some googling, we come across the PRNG called Dual_EC_DRBG, which is a PRNG that was standardized by NIST, and was later found to have a backdoor inserted into it by the NSA.

### How the PRNG works

The PRNG has an internal state `s` that's updated every time a new pseudo-random value is requested. 
There are two internal parameters `P` and `Q` which are elliptic curve points. 
The value that's returned by the PRNG is the x-coordinate of `r`. The computation is as follows: 

![alt text](image.png)  
![alt text](image-1.png)


Here's the implementation that was used in the challenge: 
```python
class PRNG:
    def __init__(self, curve, seed=None):
        self.curve = curve
        if seed is None:
            self.seed = random.randint(1, self.curve.n - 1)
        else:
            self.seed = seed % self.curve.n
        self.P = self.curve.random_point()
        self.Q = random.randint(1, self.curve.n - 1) * self.P

    def next(self):
        self.seed = (self.P * self.seed).x
        r = (self.Q * self.seed).x
        return r & (2**(8 * 30) - 1)
```

### The backdoor

The backdoor in Dual_EC_DRBG is present when the `Q` parameter is directly related to the parameter `P`. In a safe implementation of the PRNG, `Q` is supposed to be a random point on the curve. However, in the backdoored implementation, `Q` is related to `P` in a way that allows the attacker to predict the next value.
The relation is as follows:

![alt text](image-2.png)

Where `d` is the secret value that's known to entity that inserted the backdoor.
Knowing this value allows for calculating the internal state of the PRNG, given any two consecutive output values. 

## Solution

Since we're told that the backdoor is inserted, we can assume that the `Q` parameter is going to be a scalar multiple of `P`. However, discrete log would be infeasible here. It should be noted that the "Computing parameters..." stage of the service implies the insertion of the backdoor, that is, the calculation of `P * d`. 
One of the most common methods of elliptic curve point multiplication is the Double and Add algorithm, and it's been intentionally made vulnerable to a timing attack in this challenge. 
The percentages can be timed to determine the bits of the secret `d`.
After recovering the bits and verifying that they're correct by multiplying `P` with the recovered `d`, we can predict the next value of the PRNG using the backdoor.

## Exploit

```python
from pwn import remote
import time
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from Crypto.Util.number import inverse

io = remote('localhost', 1337)
print(io.recvline())
io.sendlineafter(b'> ', b'2')
print(io.recvline())
dbits = []
while True:
    start = time.time()
    dat = io.recvuntil(b'\r', drop=True, timeout=5)
    end = time.time()
    if dat == b'':
        break
    dbits.append(end-start)
    print(end-start)
avg_time = sum(dbits) / len(dbits)
print("Average:", avg_time)
dbits = ['1' if i > avg_time else '0' for i in dbits]
d = int(''.join(dbits)[::-1], 2)
print(d)
curve = io.recvline().decode().split()[1]
if curve == 'secp256k1':
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    a = 0
    b = 7
    Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
else:
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    Gx, Gy = (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
    n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

E = Curve(curve, p, a, b, n, Gx, Gy)
P = Point(*(eval(io.recvline().decode())), E)
Q = Point(*(eval(io.recvline().decode())), E)
print(P)
print(Q)
R = P * d
print(R)

def lift_x(x, all=False):
    try:
        point_a = Point(x, pow(x**3 + a*x + b, (p+1)//4, p), E)
        if all:
            return [point_a, Point(x, p - pow(x**3 + a*x + b, (p+1)//4, p), E)]
        else:
            return point_a
    except:
        return []
    
class RNG:
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def next(self): 
        self.seed = (self.seed * self.P).x
        return (self.seed * self.Q).x & (2**(8 * 30) - 1)

def predict_seed(r1, r2, e=inverse(d, n)):
    print("Starting prediction")
    print(r1, r2, e)
    for i in range(2**16):
        r_ = (i<<240) ^ r1
        for point in lift_x(r_, all=True):
            if (((e*point).x*Q).x & (2**240 - 1)) == r2:
                return (e*point).x
    print("Prediction failed :(")

io.sendlineafter('➤ '.encode(), b'1')
r1 = int(io.recvline().decode())
print(r1)
io.sendlineafter('➤ '.encode(), b'1')
r2 = int(io.recvline().decode())
print(r2)
seed = predict_seed(r1, r2)
print(seed)
prng = RNG(seed, P, Q)
io.sendlineafter('➤ '.encode(), b'2')
io.sendlineafter(b'prediction: ', str(prng.next()).encode())
io.interactive()
```

## Conclusion
I thought it was an interesting idea to make a challenge out of, but the execution may have not been the best. I hope you enjoyed the challenge regardless. 