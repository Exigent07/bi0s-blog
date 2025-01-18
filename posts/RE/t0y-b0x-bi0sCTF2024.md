---
title: t0y-b0x - bi0sCTF 2024
date: 2024-03-03 17:39:56
author: the.m3chanic
author_url: https://twitter.com/the_m3chanic_
author2: Sans
author2-url: https://twitter.com/SarinKrishnanR
categories:
  - RE, Crypto
tags:
  - bi0sCTF
  - Anti-debug
  - AES
mathjax: true
---

**tl;dr**

+ Binary obfuscation with hidden anti-debug checks
+ Linear Cryptanalysis (AES with linearly dependent SBOX)

<!--more-->

**Challenge points**: 758
**No. of solves**: 21
**Challenge Author(s)** : [Sans](https://twitter.com/SarinKrishnanR), [the.m3chanic](https://twitter.com/the_m3chanic_)


## Challenge description: 
All my toys are shuffled :(


## Initial Analysis 

We're given a stripped C binary along with a `ciphertext.txt`. 

![alt text](image.png)

We see that the binary is asking for up to 16 bytes of input followed by upto 1024 bytes in the next line - already kind of suspicious, hints AES, but let's see. 

Now right off the bat, there's a conditional check to set an array to one or the other value based on a global variable, let's check that out. 


![alt text](image-1.png)

There are only 2 xrefs to this global symbol, one of them which we are currently checking out - whereas the other one seems to be in another function. 

IDA is unable to decompile it properly, but it says that the function has inline assembly present in it - let's look at that. 

![alt text](image-2.png)

This looks like a fancy way of setting up a syscall, specifically `ptrace`, so it's an anti-debug check. 
We can simply patch the jump condition, or nop out this entire function itself - up to whoever is reversing it. 

The output of this function seems to change the values that a specific array is set to, which we'll find to be important later. 
Additionally, the array that is being set is of length 256, another AES hint. 

The array that is copied into this is initialised from another function, which you can analyse by debugging and see that all it does is initialise an array with values from 0-255.

![alt text](image-3.png)

This looks like the mix columns function from AES, it also calls the `coef_mult` that is implemented in AES. 

At this point we can conclude that this binary is implementing AES, but with some modifications to it. The only modification being that the SBOX being used in it is linear (0, 1, 2...255). We can find this out by inspecting the arguments being passed to the `aes_encrypt` function in main. 


## Solving linear AES
Looking at the implementation of the `sub_bytes` function in the binary, we can see this 
```c
void sub_bytes(uint8_t *state) {

	uint8_t i, j;
	
	for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			state[Nb*i+j] = s_box[state[Nb*i+j]];
		}
	}
}
```

This is the only non-linear part of AES, and it's what makes AES resistant to linear attacks. The standard SBOX was designed with this in mind. In this binary, however, we use a linear SBOX. 

$SBOX[i \oplus j \oplus 0] = SBOX[i] \oplus SBOX[j] \oplus SBOX[0]$

The new substitution box can be represented as a linear operation on bits, with just XORs and shuffling bits. Because of this - the AES encryption operation is now affine. Since the first block of plaintext and ciphertext, you can construct a matrix and recover the key this way, using it to decrypt the rest of the ciphertext. 

You can refer to [this](https://hackmd.io/@vishiswoz/r10P7knwj) and [this](https://kevinliu.me/posts/linear-cryptanalysis/) article for more information on this vulnerability. 

Overall, this was an easy to medium challenge, with just some obfuscation to hide some things being generated in the binary and a vulnerable implementation of AES being implemented. I hope you guys had fun solving the challenge and learnt something new from it as well! :)



