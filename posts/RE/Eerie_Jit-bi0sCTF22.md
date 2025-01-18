---
title: Eerie_Jit - bi0sCTF 2022 
date: 2023-01-25 10:54:26
author: Abhishek Barla
author_url: https://twitter.com/barlabhi
author2: Abhishek Bharadwaj
author2_url: https://twitter.com/medicherlaabhi2
categories:
  - RE
tags:
  - bi0sCTF2022
  - VM
  - JIT
---

**tl;dr**

+ This challenge is a JIT VM
+ The VM logic implements modular equations

<!--more-->

**Challenge Points**: 996
**No. of solves**: 4
**Challenge Author**: [Abhishek Barla](https://twitter.com/barlabhi), [Abhishek Bharadwaj](https://twitter.com/medicherlaabhi2)

## Challenge Description

We made a challenge assuming it would turn out good. But Oh No! The challenge turned out eerie, yes, eerie, not weird but eerie. We are currently on process of figuring out what changed overnight. It is true when people say your code can change overnight. Here is the challenge that we made, let's work together to figure out why the challenge turned out the way it is.

*sobing, in a corner* 

Oh my poor chall, what have you become ?

## Solution

### Initial Analysis

We are given a 64-bit stripped ELF. Running the program it prints a prompt after the user input is given. We open the file in IDA and get to main function, we see a flag format check, After the check, we have two functions

The first function takes the user input and converts it into four DWORD's (excluding flag format) and assigns them globally along with few other constants.
The second function has an array initialized with constants and a switch case inside a while loop, which iterates over a global dump and the last case (`case 0x40`) prints the win/fail prompt.

### The second function

After initializing the values, each case inside the switch has a function call, if we look at the definition of these functions we can see that a region is mmaped and few bytes are copied to that region and in the end this function is executed (jit).
To find out what each function does we can set a breakpoint at mmap's function call and look at the jit code and relate them with function arguments. 
The functions in cases 0x35,0x36 work in a different way compared to the rest as these functions take in the previous return value as an argument, the vm also has a reset case (case 0x3E) where these return values are stored into memory and the varibale is re-assigned to another value.
The switch cases performs ADD,SUB,MUL,XOR,AND,OR,DIV operations out of which only ADD,SUB,XOR,DIV are used and each function in the respective case would jit the corresponding x86 code, execute it and get the return value.  

Now that we have an idea of what's happening inside the switch case, we can continue with replicating the same in python along with debug statements i.e writing a disassembler, we'll use Z3's Bitvectors for flag variables to trace our input

### Disassembler

```python
# Z3's BitVec to compute and see the whole equation as it is.
from z3 import *

p1, p2, p3, p4 = [BitVec(f"flag_{i}", 32) for i in range(4)]

prime, eq1, eq2, eq3, eq4 = [0x7EFF4B91, 0x1EF6E9EB, 0x34CC1889, 0x68E54823, 0x11226D6A]

dump = [0x35, 0x0, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x35, 0x0, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x35, 0x3, 0x3e, 0x35, 0x0, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x35, 0x3, 0x3e, 0x35, 0x0, 0x35, 0x3, 0x3e, 0x35, 0x3, 0x3e, 0x30, 0x0, 0x3, 0x31, 0x0, 0x3, 0x3d, 0x3, 0x30, 0x0, 0x3, 0x31, 0x0, 0x3, 0x3d, 0x3, 0x30, 0x0, 0x3, 0x30, 0x0, 0x3, 0x3d, 0x3, 0x30, 0x0, 0x3, 0x30, 0x0, 0x3, 0x31, 0x0, 0x3, 0x3d, 0x3, 0x3e, 0x36, 0x0, 0x3, 0x36, 0x0, 0x3, 0x36, 0x0, 0x3, 0x36, 0x0, 0x3, 0x40]

values = iter([p1, p1, p1, p2, p1, p2, p1, p2, p2, p3, p4, p3, p4, 0, 0])
mul_const = iter([4, p2, 5, 0x69, 6, 2, 13, 17, p3, 5, 5, 0x69, p3, 4, 5, 303])
xor_const = iter([eq1, eq2, eq3, eq4])

ret_val = next(values)

i, j, ind = 0, 0, 0

stack = [0] * 20
rem = []

while 1:

    match dump[ind]:

        case 0x30:

            i -= 1; arg1 = stack[i]
            i -= 1; arg2 = stack[i]

            print(f"[*] ADD  {arg2}, {arg1}")
            stack[i] = arg1 + arg2
            i += 1; ind += 3

        case 0x31:

            i -= 1; arg1 = stack[i]
            i -= 1; arg2 = stack[i]

            print(f"[*] SUB  {arg2}, {arg1}")
            stack[i] = arg1 - arg2
            i += 1; ind += 3

        case 0x35:

            if dump[ind + 1]:

                arg = next(mul_const)
                print(f"[*] MUL  {ret_val}, {arg}")
                ret_val = ret_val * arg

            else:

                print(f"[*] MUL  {ret_val}, {ret_val}")
                ret_val = ret_val * ret_val

            ind += 2

        case 0x36:

            arg1 = rem.pop()
            arg2 = next(xor_const)
            print(f"------")
            print(f"[*] Xor  {arg1}, {arg2}")
            ret_val = arg1 ^ arg2 ^ ret_val

            ind += 3

        case 0x3D:

            i -= 1; arg = stack[i]

            print(f"[*] MOD  {arg}, {prime}")
            rem.append(arg % prime)
            ind += 2

        case 0x3E:

            print(f"[*] PUSH {ret_val}")
            stack[i] = ret_val
            ret_val = next(values)
            ind += 1; i += 1

        case 0x40:
            print("[*] Done")
            # if ret_val:
            #     print("Fail")
            # else:
            #     print("Done")
            exit(0)
```

The above disassembly yeilds 

```txt
[*] Xor  (flag_1*6 + flag_0*105 + flag_0*flag_1*5 - flag_0*flag_0*4) % 2130660241, 519498219

[*] Xor  (flag_0*17 + flag_1*13 + flag_0*flag_0*2) % 2130660241, 885790857

[*] Xor  (flag_2*105 + flag_1*flag_1*5 - flag_1*flag_2*5) % 2130660241, 1759856675

[*] Xor  (flag_3*303 + flag_2*flag_2*5 - flag_3*flag_2*4) % 2130660241, 287468906
```

If we take a look at the opcodes in the dump the last opcode is 0x40 (responsible to print the prompt) and the ones before that are 0x36 which performs XOR, 
Inorder for the program to print `noICE`, the return value of the xor case (case 0x36) should be zero in every iteration as the inside the case(case 0x36) takes the previous return value as an argument which takes us to,

```python
(flag_1*6 + flag_0*105 + flag_0*flag_1*5 - flag_0*flag_0*4) mod 2130660241=519498219
(flag_0*17 + flag_1*13 + flag_0*flag_0*2) mod 2130660241=885790857
(flag_2*105 + flag_1*flag_1*5 - flag_1*flag_2*5) mod 2130660241=1759856675
(flag_3*303 + flag_2*flag_2*5 - flag_3*flag_2*4) mod 2130660241=287468906
```



### Solving modular equations

Let A,B,C,D be the flag variables and `p` be the prime number and eq1,eq2,eq3,eq4 be the values that are being compared to



```py
eq1⇒(5*A*B-4*A^2+105*A + 6*B) mod p 
eq2⇒(2*A^2 + 13 * B+ 17 * A) mod p 
eq3⇒(5*B^2 + 105*C - 5*B*C) mod p 
eq4⇒(5*C^2 - 4*C*D + 303*D) mod p 
```

Now we have 4 modular equations with 4 unknowns, consider `eq1` and `eq2` and subjecting `b` from eq2 we get,

```python
b=((eq2-2*A^2-17*A)÷13)
```

Since these equations are under `mod p` it would become `inverse(13,p)`, Substituting `b` in `eq1` gives us a polynomial in `a`, upon solving yields `a`, we can  proceed with the other unknowns in a similar way to get the remaining flag variables.

Below is the sage script to solve the equations

```python
# constants
eq1, eq2, eq3, eq4 = [0x1EF6E9EB, 0x34CC1889, 0x68E54823, 0x11226D6A] 
prime = 0x7EFF4B91 

# x,y,c are vairables under a prime field `P`
P.<x,y,c> = GF(prime)[]

d = (eq2 - 2 * c ^ 2 - 17 * c) * inverse_mod(13, prime)
X = (-4 * c ^ 2 + 5 * c * d + 105 * c + 6 * d) - eq1
X = X.univariate_polynomial()
flag_0 = X.roots()[0][0]

flag_1 = (eq2 - 2 * flag_0 ^ 2 - 17 * flag_0) * inverse_mod(13, prime)

l = eq3 - 5 * flag_1 ^ 2 - 105 * x + 5 * flag_1 * x
l = l.univariate_polynomial()
flag_2 = l.roots()[0][0]

h = eq4 - 5 * flag_2 ^ 2 + 4 * flag_2 * y - 303 * y
h = h.univariate_polynomial()
flag_3 = h.roots()[0][0]

flag = b"".join(bytes.fromhex(hex(i)[2:]) for i in [flag_0, flag_1, flag_2, flag_3])
print(b"bi0sCTF{" + flag)
```

### Flag

`bi0sCTF{timelapsing_jit}`
