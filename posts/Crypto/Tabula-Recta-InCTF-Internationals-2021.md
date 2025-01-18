---
title: Tabula Recta - InCTF Internationals 2021
date: 2021-08-20 10:00:00
author: ph03n1x
author_url: https://twitter.com/MeenakshiSl1
author2: 4l3x1
author2_url: https://twitter.com/SandhraBino
categories:
  - Crypto
  - RC4 cipher
  - InCTFi
tags:
  - Elliptic Curve
  - RC4
  - Password Manager
mathjax: true
---

Official writeup of Crypto challenge "Tabula Recta" from InCTFi 2021

**tl;dr** 

+ Retrive first few bytes of table through Matrix calculations, then find which special b-exact key is used.

<!--more-->

## Working

The script is that of a stateless password manager build using a combination of RC4  cipher and Matrix calculations based on Elliptic Curves.

`crypto.py` is used to generate entries to a tabula-recta. The table is unique for a given master password. The row number is calculated as the sum of ASCII of websites % 37 and the intermediate password is generated as follows :-

<img src="https://docs.google.com/drawings/d/e/2PACX-1vSc0yCQZk7QjMGfgMPZVQLMeY-fabQwdIy54xTekNBcCa-VexjYZ8jBdz2cRj5GqAJyHCRV1QQ_k33U/pub?w=960&amp;h=720">

<img src="https://docs.google.com/drawings/d/e/2PACX-1vSTQwZajRqiRlNUdNYbICQTFi9olifZuXVW1NV5CoJ9o0Di-tpNeDUuNEn_2jmJqYuxyF1mUs3FwpSi/pub?w=960&amp;h=720">

`gen.sage` uses matrix calculations to map it into different values within the table.

## Weakness

- The implementation of RC4 cipher is as per the weakened version as described by the paper [Weakness in Key Scheduling Algorithm of RC4](https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_1.pdf) , specifically section 3.1
- Mapping of points is reversible

## Exploit

### Reverse Mapping 

The passwords and mapping are for website whose sum is zero is given. Essentially inversing it would give the first row of the table.

Mapping involves the following states :
1. Alphabetical points are mapped on to points on the Ellipitic Curve
2. A matrix of dimensions 3xr is created with entries as points on the Elliptic Curve(call it M)
3. We define a matrix Q as Q = A.M
4. C1, C2 = (13*P , Q + 13 * 25 * P)

our mapped point is the x-coordinate of C1 and y-coordinate of C2


With the original points, Q and thus the original points can be calculated as follows :

```python
from crypto import *
from matrix import *
load("gen.sage")

E = EllipticCurve(GF(37),[1,5])  
G = E.gen(0) 
allowed = "abcdefghijKLMNOPQRSTUV0123467!#$%&*+,"
d = {} 
for i in range(37) :  
    d[allowed[i]] = E.points()[i+1]  
A = [[-1,5,-1],[-2,11,7],[1,-5,2]]


l = [('O', ((25, 35), (15, 18))), ('d', ((9, 22), (18, 34))), ('U', ((19, 36), (15, 19))), ('N', ((9, 22), (19, 1))), ('Q', ((14, 32), (1, 28))), ('P', ((14, 5), (30, 32))), ('+', ((30, 32), (19, 36))), (',', ((1, 28), (18, 34))), ('V', ((8, 28), (8, 9))), ('1', ((30, 5), (10, 33))), ('!', ((16, 11), (30, 32))), ('V', ((14, 5), (19, 36)))]
points_c1 = [E.point(tup[1][0]) for tup in l]
points_c2 = [E.point(tup[1][1]) for tup in l]
C1 = [points_c1[i:i+4] for i in range(0,12,4)]
C2 = [points_c2[i:i+4] for i in range(0,12,4)]
C1_M = Matrix((3,4),C1)
C2_M = Matrix((3,4),C2)
A_M = Matrix((3,3),A)
A_inv = [[-57,5,-46],[-11,1,-9],[1,0,1]]
A_inv_M = Matrix((3,3),A_inv)
Q = C2_M.__sub__(C1_M.__mul__(13))
inv_d = dict(zip(d.values(),d.keys()))  

E_arr = A_inv_M.__mul__(Q)
pt_E = [] 
for i in range(E_arr.rows) :
    for j in range(E_arr.cols) :
        pt_E.append(inv_d[E_arr.M[i][j]])
first_row = ''.join(pt_E)

```

We would get the first row of the table as `$3e3ijhNag&j`.

## Some definitions

**b-conserve** :  Let S be a permutation of {0,...,N −1}, t be an index in S and
b be some integer. Then if S[t] mod b ≡ t, the permutation S is said to b-conserve
the index t. Otherwise, the permutation S is said to b-unconserve the index t.

**special b-exact key** : Let b, l be integers, and let K be an l word key. Then K is called
a b-exact key if for any index r, K[r mod l] ≡ (1−r) (mod b). In case K[0] = 1
and MSB(K[1]) = 1, K is called a special b-exact key.

## Weakness

For the conditions ,
1. q <= n and b = 2 ** q
2. b | l
3. K be a b-exact key of l-words

a maximum number of state bits remain preserved for the weakened version of KSA.

Here we know that conditions 1 and 2 are satsifed , however we do not know the length of the key. If we assume a special b-exact key there are the following possibilities :
```python
poss_K = []
for i in range(7) :
    tmp = [(1-r)%64 for r in range(2**i)]
    poss_K.append(tmp)
```

Now, we check if any of these keys correspnd to the password produced :

```python
master_key = ""
for K in poss_K : 
    key = ''.join(chr(i) for i in K) 
    S = get_entries(key) 
    tmp = ''.join(S[:12])
    if tmp == first_row :
      print("Success")
	    break
master_key = key
```

We get the master key as `?>=<;:98765432`.

Now we use this key to generate passwords for the websites printed in the service `nc 34.106.211.122 1222`. The percentage of the passwords which you need to get the flag is not sufficient to get the flag via table recovery.


### Bug

Due to an unintended bug in the server file, you would get the flag if the fraction of correct passwords by the total number of passwords asked was greater than 0.0075. So the flag would be printed with 1 or 3 passwords given. Thus it was possible to get the flag via table recovery. 

## Flag

**inctf{Always_h4v3_a_statistic4l_3y3_wh3n_it_com3s_to_weakn3ss3s}**




