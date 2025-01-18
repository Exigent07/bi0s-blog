---
title: Bro do you even Lift - Teaser CONFidence CTF 2019
date: 2019-03-18 13:45:38
author: v4d3r
author_url: https://twitter.com/sayoojsamuel
tags:
  - PolynomialRing
  - HenselLifting
categories:
  - Crypto
mathjax: true
---

tl;dr
1. Find roots in a polynomial ring over $ mod\;p $
2. Use Hensel's Lifting lemma to find roots over $ mod\;p^k $

<!--more-->

**Challenge Points**: 85
**Challenge Solves**:
**Solved by**: [v4d3r](https://twitter.com/sayoojsamuel), [s0rc3r3r](https://twitter.com/ashutosha_), [v3ct0r](https://twitter.com/__v3ct0r__), [4lph4](https://twitter.com/__4lph4__)

## Preliminary Analysis

This challenge was based on a 4th degree Univariate Polynomial Ring. We are provided with `lift.sage` and
`outputs.txt`. In `lift.sage` we have:

```python
flag = int(open('flag.txt','r').read().encode("hex"),16)
ranges = int(log(flag,2))
p = next_prime(ZZ.random_element(2^15, 2^16))
k = 100
N = p^k
d = 5
P. = PolynomialRing(Zmod(N), implementation='NTL')
pol = 0
for c in range(d):
    pol += ZZ.random_element(2^ranges, 2^(ranges+1))*x^c
remainder = pol(flag)
pol = pol - remainder
assert pol(flag) == 0

print(p)
print(pol)
```

Contents of `outputs.txt` are:
>35671

>12172655049735206766902704703038559858384636896299329359049381021748\*x^4 + 11349632906292428218038992315252727065628405382223597973250830870345\*x^3 + 9188725924715231519926481580171897766710554662167067944757835186451\*x^2 + 8640134917502441100824547249422817926745071806483482930174015978801\*x + 170423096151399242531943631075016082117474571389010646663163733960337669863762406085472678450206495375341400002076986312777537466715254543510453341546006440265217992449199424909061809647640636052570307868161063402607743165324091856116789213643943407874991700761651741114881108492638404942954408505222152223605412516092742190317989684590782541294253512675164049148557663016927886803673382663921583479090048005883115303905133335418178354255826423404513286728

It is clear from the above snippet that the flag is a root of the following polynomial:
$ ax^4 + bx^3 + cx^2 + dx + e = 0\;(mod\;N) $  
where $ N = p^{100} $; $ p = 35671 $

Thus, the challenge was to find the root of this polynomial!

To solve this challenge, we can first find a solution for the given polynomial over $ mod\;p $ and then use
Hensel’s lifting lemma to find a solution for the given polynomial over $ mod\;p^k = mod\; N $. Hensel’s lifting
lemma states that:
> If a polynomial equation has a simple root modulo a prime number p, then this root corresponds to a unique root of the same equation modulo any higher power of p, which can be found by iteratively “lifting” the solution modulo successive powers of p.

## Step-1: Finding roots over $ mod\;p $
```python
p = 35671
k = 100
P. = PolynomialRing(Zmod(p), implementation='NTL')
f = 12172655049735206766902704703038559858384636896299329359049381021748*x^4 + 11349632906292428218038992315252727065628405382223597973250830870345*x^3 + 9188725924715231519926481580171897766710554662167067944757835186451*x^2 + 8640134917502441100824547249422817926745071806483482930174015978801*x + 170423096151399242531943631075016082117474571389010646663163733960337669863762406085472678450206495375341400002076986312777537466715254543510453341546006440265217992449199424909061809647640636052570307868161063402607743165324091856116789213643943407874991700761651741114881108492638404942954408505222152223605412516092742190317989684590782541294253512675164049148557663016927886803673382663921583479090048005883115303905133335418178354255826423404513286728
print f.monic().roots()
```
Cool! This python/sagemath script returned the base solutions as `[27020, 25020]`

## Step-2: Use Hensel's lifting to find roots over $ mod\;N $
We primarily used p4’s Hensel’s lifting implementation in their library [crypto-commons](https://github.com/p4-team/crypto-commons). [v4d3r](https://twitter.com/sayoojsamuel) tweaked it to
make it compatible with sagemath.

```python
from sage.all import *
from Crypto.Util.number import *

def lift(f, p, k, previous):
    result = []
    df = diff(f)
    for lower_solution in previous:
        dfr = Integer(df(lower_solution))
        fr = Integer(f(lower_solution))
        if dfr % p != 0:
            t = (-(xgcd(dfr, p)[1]) * int(fr / p ** (k - 1))) % p
            result.append(lower_solution + t * p ** (k - 1))
        if dfr % p == 0:
            if fr % p ** k == 0:
                for t in range(0, p):
                    result.append(lower_solution + t * p ** (k - 1))
    return result

def hensel_lifting(f, p, k, base_solution):
    solution = base_solution
    for i in range(2, k + 1):
        solution = lift(f, p, i, solution)
    return solution

if __name__=="__main__":
    #base = [27020,25020]
    base = [27020]
    p = 35671
    k = 100
    N = p^k
    P. = PolynomialRing(Zmod(N), implementation='NTL')
    f = 12172655049735206766902704703038559858384636896299329359049381021748*x^4 + 11349632906292428218038992315252727065628405382223597973250830870345*x^3 + 9188725924715231519926481580171897766710554662167067944757835186451*x^2 + 8640134917502441100824547249422817926745071806483482930174015978801*x + 170423096151399242531943631075016082117474571389010646663163733960337669863762406085472678450206495375341400002076986312777537466715254543510453341546006440265217992449199424909061809647640636052570307868161063402607743165324091856116789213643943407874991700761651741114881108492638404942954408505222152223605412516092742190317989684590782541294253512675164049148557663016927886803673382663921583479090048005883115303905133335418178354255826423404513286728
    solutions = hensel_lifting(f,p,k,base)
    for solution in solutions:
        print long_to_bytes(solution)
```

Running the above script gave the flag as:
**p4{Th4t5_50m3_h34vy_l1ft1n9}**
