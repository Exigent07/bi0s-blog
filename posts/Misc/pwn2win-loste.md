---
title: Lost Exponent - Pwn2Win 2021
tags:
  - Pwn2Win
  - Writeup
  - Misc
  - Matrix
author: xxMajinxx
author_url: 'https://github.com/AlekhAvinash/'
mathjax: true
categories:
  - Misc
date: 2021-06-05 00:00:00
---


**tl;dr**
+ Reverse bytearray to recover matrix `cflag`.
+ Use first element of matrix to recover e (bruteforce &iroot)
+ Reduce the flag to finite field of a 32-bit prime, solve for each character.

<!--more-->

**Challenge Points:** 249
**Solves:** 31
**Solved By**: [xxMajinxx](https://github.com/AlekhAvinash/), [v4d3r](https://twitter.com/sayoojsamuel)

## Challenge Description

>While Laura was looking for her brother, she found a program that seems to scramble a password and save the result. Could you help her find the original password so that she can find and save her brother before it's too late?

*Challenge Files:-*
| -> [encode.py](encode.py)
| -> [enc](enc)

## First Impressions

- The challenge description suggests that the challenge involves unscrambling the flag text.
- The starting bytes of the flag and the seed are revealed. This implies randomization is reversible.
- There are 2 unknown variables e (int - most likely), flag (string).
- The scrambled flag is stored as bytes in `enc`.
- The enc file is `17.5 Mb`, implying that either the length of the flag is really large or each element in the flag matrix is really large.

## The Challenge

The challenge can be mainly explained in 3 parts:

### Order

```python
n = int(sqrt(len(flag))) + 2
order = list(product(range(n), repeat=2))
shuffle(order)
order.sort(key=(lambda x: sign(diff(x))))
```
- Initially, the challenge uses the $n = \sqrt{l}+2$ (l is the length of the flag), to create a list of tuples (order) with each tuple containing 2 elements (each element range from 0 to n).
- This list is shuffled and then sorted based on the sign of the difference between the variables in each element.
>**Note**:- After some testing, we can conclude that this was done so that for any flag of length l, the $n*n$ matrix will contain the scrambled flag in its lower triangle.
### Matrix class
```python
class Matrix:
    def __init__(self):
        self.n = n
        self.m = [[0]*n for _ in range(n)]

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix()
        for i in range(n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix()
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k]*other[k, j] for k in range(n))
        return r

    def __pow__(self, power):
        r = self.I()
        for _ in range(power):
            r = r * self
        return r

    def __str__(self):
        return str(self.m)
```
- The class maintains a matrix and allows a few operations on the matrix.
- The Matrix class uses a tuple with 2 variables to get and set values in their (X, Y) positions.
- Matrix is capable of matrix multiplication & exponentiation.

### Main

```python
m = Matrix()
for i, f in zip(order, flag):
    m[i] = ord(f)
cflag = list(map(str, m ** e))
mn = max(map(len, cflag))
mn += mn % 2
cflag = ''.join(b.zfill(mn) for b in cflag)
cflag = bytes([int(cflag[i:i+2]) for i in range(0, len(cflag), 2)])
with open('enc', 'wb') as out:
    out.write(cflag)
```
- Based on `order` the flag bytes is mapped to a matrix `cflag` and exponentiated w\ the variable `e`.
- The integers are converted to a string and padded to the size of the largest integer in the matrix.
- The padded strings are joined together and converted to bytes & are stored in the `enc` file.

## Solution

The solution was a 4 step process. It is possible to recover the flag from the cflag matrix if reduced to `e = 1`, but for this, we need two objects.
1) The cflag matrix.
2) The e value

### Step 1 - Retrieve cflag

This is the easy step. Since we know how the bytes are stored in the `enc` file we can easily undo the step to get the cflag as a string.
```python
cip = ''.join([str(i).zfill(2) for i in open('enc','rb').read()])
```
Since we don't know the length of the flag, we don't know the `n` value (ie the order of the matrix). Thus it might be difficult to decide how the string is to be split.
>*Hint*: All elements are of equal length.
But if we look at the factors of length of the flag, it becomes more obvious.
```python
sage: ecm.factor(len(cip))
[2, 2, 3, 3, 3, 7, 7, 19, 349]
```
Since 2 and 3 matrices are too small to contain atleast 7 bytes, The most likely matrix would be 7.
This was the correct choice when the string was split based on the word length $wrdln = cipln/7^2$, the paddings aligned correctly to each element.
```python
a = [int(cip[i:i+wrdln]) for i in range(0, ln, wrdln)]
```

### Step 2 - Get e

The first character of the matrix $a[0,0]$ when exponentiated will be just $a^e$. Therefore this value can be reduced to find the e (lost e) value. We checked with all possible primes to reduce the value to 20-128 range. We got a return $48, [2, 2, 85381]$ after a long bruteforce. Implying that the first character code 48, and the exponent is 341524.
```python
def get_e(val, k= 2, ret = []):
    from gmpy2 import iroot, next_prime, is_prime
    while val>128 and not is_prime(val):
        tmp, flag = iroot(val, k)
        if flag:
            val = tmp
            ret += [int(k)]
        else:
            k = next_prime(k)
    return int(k), ret
```

### Step 3 - Recover the Matrix Values

Each element in the Matrix was at least 1907399 bits, we couldn't do any operations on the matrix(much less reduce it). So one idea was to reduce the size of the matrix with modular arithmetics.
```python
ct = Matrix(GF(p), 7, 7, a)
```
Now that we have a simple matrix and the exponent `e`, we can start finding which values will result in the `ct` matrix.
>Note:- In exponentiation of matrices that only occupy the lower triangle, each element is only affected by the elements that are above it or to its right.
Since the elements in the diagonal are not effected by any other value those are bruteforced first $(mat^e)[i,i] = x^e$
Next the elements that are below the diagonal elements are bruteforced $(mat^e)[i+1,i] = x^e + c$
This process is repeated until all elements are recovered.
```python
def brute(pt, ct, loc):
    for i in printable:
        pt[loc] = ord(i)
        if (pt^e)[loc]==ct[loc]:
            return i, True
    pt[loc] = 0
    return -1, False

def crack(pt, ct):
    print('cracking..')
    for depth in range(6):
        for i in range(7-depth):
            loc = (i+depth,i)
            if not pt[loc]:
                brute(pt, ct, loc)
        print(f'pass: {depth}\n{pt}')

if __name__ == '__main__':
    ct = Matrix(p, 7, 7, a)
    known = b'CTF-BR{'+b'\x00'*18+b'}'
    mat = Matrix(p, 7, 7)
    for i,j in zip(known, order):
        mat[j] = i
    crack(mat, ct)
```

### Step 4 - Unscamble

Now that we have recovered all bytes we can unscamble the matrix with the known order to get the flag.
```python
flag = ''.join([chr(mat[loc]) for loc in order if mat[loc]])
```

## Conclusion

Large numbers are hard to work with, therefore most CPU heavy tasks can be reduced to a few bytes with modular arithematics. And never reveal the seed.
`Exploit Code`: [sol.sage](sol.sage)
`Flag`: **CTF-BR{s0M3_0F_m47r1X_106}**