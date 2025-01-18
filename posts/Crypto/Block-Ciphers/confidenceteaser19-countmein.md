---
title: Count me in - Teaser CONFidence CTF 2019
date: 2019-03-18 10:34:56
author: v3ct0r
author_url: https://twitter.com/__v3ct0r__
tags:
  - AES-CTR
categories:
  - Crypto
  - Block-Ciphers
mathjax: true
---
tl;dr Known plaintext attack on a multithreaded AES-CTR

<!--more-->

**Challenge Points**: 59
**Challenge Solves**:
**Solved by**: [v3ct0r](https://twitter.com/__v3ct0r__)

This challenge is a customised version of AES-CTR. Here is the challenge script:
```python
import multiprocessing

from Crypto.Cipher import AES

from secret import key, flag

counter = 0
aes = AES.new(key, AES.MODE_ECB)

def chunk(input_data, size):
    return [input_data[i:i + size] for i in range(0, len(input_data), size)]

def xor(*t):
    from functools import reduce
    from operator import xor
    return [reduce(xor, x, 0) for x in zip(*t)]

def xor_string(t1, t2):
    t1 = map(ord, t1)
    t2 = map(ord, t2)
    return "".join(map(chr, xor(t1, t2)))

def pad(data):
    pad_byte = 16 - len(data) % 16
    return data + (chr(pad_byte) * pad_byte)

def worker_function(block):
    global counter
    key_stream = aes.encrypt(pad(str(counter)))
    result = xor_string(block, key_stream)
    counter += 1
    return result

def distribute_work(worker, data_list, processes=8):
    pool = multiprocessing.Pool(processes=processes)
    result = pool.map(worker, data_list)
    pool.close()
    return result

def encrypt_parallel(plaintext, workers_number):
    chunks = chunk(pad(plaintext), 16)
    results = distribute_work(worker_function, chunks, workers_number)
    return "".join(results)

def main():
    plaintext = """The Song of the Count

You know that I am called the Count
Because I really love to count
I could sit and count all day
Sometimes I get carried away
I count slowly, slowly, slowly getting faster
Once I've started counting it's really hard to stop
Faster, faster. It is so exciting!
I could count forever, count until I drop
1! 2! 3! 4!
1-2-3-4, 1-2-3-4,
1-2, i love couning whatever the ammount haha!
1-2-3-4, heyyayayay heyayayay that's the sound of the count
I count the spiders on the wall...
I count the cobwebs in the hall...
I count the candles on the shelf...
When I'm alone, I count myself!
I count slowly, slowly, slowly getting faster
Once I've started counting it's really hard to stop
Faster, faster. It is so exciting!
I could count forever, count until I drop
1! 2! 3! 4
1-2-3-4, 1-2-3-4, 1,
2 I love counting whatever the
ammount! 1-2-3-4 heyayayay heayayay 1-2-3-4
That's the song of the Count!
""" + flag
    encrypted = encrypt_parallel(plaintext, 32)
    print(encrypted.encode("hex"))

if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
```
After observing the script carefully, we can see that the each block has been parallelly encrypted using multithreading , but here lies the vulnerability!

Since multithreading is used, a few set of blocks are encrypted with the same nonce. Here comes the use of
the given plaintext, since we have many plaintext and ciphertext block pairs we can recover the encrypted
nonce.

It is basically a xor challenge where the encrypted nonces are the keys which when XORed with the plaintext
gives us the ciphertext. So basically the part of the flag maybe XORed with the same key block with which
some of the previous blocks have been XORed. But we don’t which of these is used so we try all of them.

There are two steps involved in solving this challenge:
1. **Recovering the key sets from the known plaintext-ciphertext pairs**
We can get that by XORing the pt-ct pairs and dividing it into chunks of 16 since each block is 16.
2. **Getting the flag**
Find which key set used to XOR with the flag. Just try all of them and there is nothing else to do but getting
the flag.

Here is the exploit script:
```python
from Crypto.Cipher import AES
import string

from count import plaintext as pt
ct = open("output.txt").read().decode('hex')

chars = string.ascii_lowercase+string.digits+"{}_"

def chunk(input_data, size):
    return [input_data[i:i + size] for i in range(0, len(input_data), size)]

def xor(a,b):
    from itertools import cycle
    return ''.join(chr(ord(i)^ord(j)) for i,j in zip(a,cycle(b)))

# Possible Keys
k = xor(ct,pt)[:len(pt)]
keys = chunk(k,16)

ctflag = ct[-64:]
flag = ''
for key in set(keys):
    out = chunk(xor(ctflag,key),16)
    for i in out:
        if all(char in chars for char in i[:8]):
            flag+=i
print flag
```

Running the above script gives out the flag as:
**p4{at_the_end_of_the_day_you_can_only_count_on_yourself}**!
