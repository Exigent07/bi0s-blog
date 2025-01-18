---
title: Faulty LFSR - InCTF Internationals 2020
date: 2020-08-02 06:09:19
author: ph03n1x
author_url: https://twitter.com/MeenakshiSL1
tags:
  - InCTFi
  - LFSR
  - Correlation attack
categories:
  - Crypto
  - LFSR
mathjax: true

---
**tl;dr**

1. Find the co-relation between variables in the LFSR equation
    1. d == out (75%)
    2. a == b (75%)
    3. c^d == out (75%)
    4. (d!= out) => (c==1) always
2. Solve for the seed using 2000 output bits
3. Try out which among the four possible combinations decrypt the flag

<!--more-->

**Challenge Points**: 804
**Challenge Solves**: 22
**Challenge Author**: [ph03n1x](https://twitter.com/MeenakshiSL1)



## Challenge description

My friend who claims to be someone who is good in statistics, had my new encryption scheme analysed. He claims that there are some problems with my encryption scheme and challenged me to find it out myself. I tried checking the seeds and found that two of them were in the inital parts of their range. But that couldnt be the problem right? Can you try to prove that this scheme is faulty by trying to find out the flag?

### Attachment 
```
- [keygen2.py](../InCTFi-20-FaultyLFSR/keygen2.py)
- [rem_data](../InCTFi-20-FaultyLFSR/rem_data)
- [flag.enc](../InCTFi-20-FaultyLFSR/flag.enc)
```

## Keygen file

The `generate()` function generates seeds from the using 

The masks for the seeds of the LFSR are provided. Bitlength of the masks are same as those of its corresponding seed.

```python
def generate() :
    masks = [43, 578, 22079, 142962]
    for i in range(4) :
        assert (masks[i].bit_length() == seeds[i].bit_length()) == True
```

We know the value of SECRET and the fact that the 2nd seed divides the fourth.

```python
	SECRET = 14810031
	#assert seeds[3]%seeds[1] == 0
```

## Finding correlation

The challenge description speaks about the lfsr equation being statistically unsafe.
``` (a^b)^(a|c)^(b|c)^(c|d) ```

**Truth Table**
```
| a | b | c | d ||out|
-----------------------
| 0 | 0 | 0 | 0 || 0 |
| 0 | 0 | 0 | 1 || 1 |
| 0 | 0 | 1 | 0 || 1 |
| 0 | 0 | 1 | 1 || 1 |
| 0 | 1 | 0 | 0 || 0 |
| 0 | 1 | 0 | 1 || 1 |
| 0 | 1 | 1 | 0 || 0 |
| 0 | 1 | 1 | 1 || 0 |
| 1 | 0 | 0 | 0 || 0 |
| 1 | 0 | 0 | 1 || 1 |
| 1 | 0 | 1 | 0 || 0 |
| 1 | 0 | 1 | 1 || 0 |
| 1 | 1 | 0 | 0 || 0 |
| 1 | 1 | 0 | 1 || 1 |
| 1 | 1 | 1 | 0 || 1 |
| 1 | 1 | 1 | 1 || 1 |

```

From the truth table we find out the following :

 1. Probability distributions of [a,b,c,d] = [50%,50%,50%,75%]
 2. a == b (75%)
 3. d == out (75%)
 4. (d!= out) => (c==1) always


## Finding seed-d (& seed-b)

Bitlength of d = 18
Thus range is `[2**17,2**18 - 1]`
We know two of the seeds are in the initial part of their range. Assuming this is the one :
We also know that the second seed divides this one. We shall also incorporate this fact into the script.
```python

def solve_d() :
    poss = []
    for i in tqdm(range(2**17 ,2**17 + 2**16)) :
        d = lfsr(i,masks[3],masks[3].bit_length())
        ct = 0
        for k in range(160) :
            d.next()
        for j in remdata[:2000] :
            if d.next() == j :
                ct+=1.0
        if ct/2000 >= 0.74 :
            poss.append(i)
            print ((i,ct/2000))
    bd = []
    for i in poss :
        for j in factorint(i).keys() :
            if j.bit_length() == 10 :
                bd.append((j,i))
    return bd

```
We end up with the pair bd = `[(839, 136757)]`

## Finding seed-c
For this we use the relations :
 1. c^d == out (75%)
 2. (d!= out) => (c==1) always
 3. Probability of c is 50%
```python
def solve_c() :
    pair = []
    poss_d = solve_d()
    for b,d in tqdm(poss_d) :
        for i in tqdm(range(2**14,2**15)) :
            dt = lfsr(d,masks[3],masks[3].bit_length())
            ct = lfsr(i,masks[2],masks[2].bit_length())
            ct1 = ct2 = 0
            for j in range(160) :
                dt.next()
                ct.next()
            for j in remdata[:2000] :
                dtmp = dt.next()
                ctmp = ct.next()
                if dtmp!=j and ctmp!=1 :
                    break
                if ctmp == j :
                    ct1+=1.0
                if ctmp^dtmp == j :
                    ct2+=1.0
            if ct1/2000 > 0.45 and ct1/2000<0.6 and ct2/2000>0.74 :
                pair.append((b,i,d))
                print (i,ct1/2000,ct2/2000)
    return pair
```

## Finding seed-a
The bitlength of a is 6 thus fairly easy to brute force :

```python

def decrypt(seeds) :
    f = open('flag.enc').read()
    key = sha256(generate(seeds)).digest()
    flag = AES.new(key,AES.MODE_ECB).decrypt(f)
    if "inctf" in flag :
        return flag
    return ""
    
def solve_rest() : 
    res = []
    pair = p
    for b,c,d in tqdm(pair) :
        for a in range(2**5,2**6) :
            l = [lfsr(i,j,j.bit_length()) for i,j in zip((a,b,c,d),masks)]
            for i in range(160) :
                l[0].next()
                l[1].next()
                l[2].next()
                l[3].next()
            ct = 0
            for i in remdata[:2000] :
                if combine(l[0].next(),l[1].next(),l[2].next(),l[3].next()) == i :
                    ct+=1
                    continue
                else :
                    break
            if ct == 2000 :
                flag =  decrypt([a,b,c,d]) 
                if "inctf" in flag :
                    return flag
```
## Flag 

**FLAG**: inctf{l00k5_l1k3_y0u_r_a_pr0_1n_LFSR}

## Conclusion

Never use a pseudo random sequence which violates [Golomb's principles](http://www-math.ucdenver.edu/~wcherowi/courses/m5410/m5410fsr.html) to generate a key.
Hope you enjoyed the challenge!