---
title: kawaii_vm - bi0sCTF 2022
date: 2023-01-25 19:01:39
author: k1R4
author_url: https://twitter.com/justk1R4
categories:
  - Pwn
tags:
  - Exploitation
  - bi0sCTF
  - VM
---

**tl;dr**

+ Giving custom array size of NaN, passes checks while allowing OOB r/w
+ Use OOB r/w to get libc, stack (environ) addresses
+ Craft fake chunk on array and overwrite fastbin fd
+ Reset machine to allocate register context on fake chunk
+ Overwrite VM sp with real stack
+ Push ropchain onto stack and halt VM to execute ropchain

<!--more-->

**Challenge Points**: 996
**No. of solves**: 4
**Challenge Author**: [k1R4](https://twitter.com/justk1R4)


## Challenge Description

`The VM is only kawaii from the outside T_T`

Handout has the kawaii_vm binary & ld, libc and libseccomp inside the lib folder

## Initial Analysis

The binary is stripped when checked with `file` command. Typical for a VM challenge.

Here is the checksec output:
```bash
[k1r4@zg15 handout]$ checksec kawaii_vm
[*] '/home/k1r4/Shared/projects/kawaii_vm/handout/kawaii_vm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./lib/'
```

All mitigations are enabled. Since libseccomp is included checking the binary with seccomp-tools reveals:
```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0011
 0009: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0011
 0010: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```
Only syscalls allowed that are relevant are open,read,write. So the goal would be to perform orw on flag file.

Running the binary it is seen that it intially checks if a custom array size is needed, if so it takes input in unit pages. Then it reads bytecode to be executed.

## Source Code

Full src can be found [here](https://github.com/teambi0s/bi0sCTF/tree/master/2022/Pwn/kawaii_vm)

I will be including only the important parts here. It is recommended to have the full src open while going through this writeup.


This VM has:
+ Some general purpose registers
+ A program counter
+ A stack pointer
+ An array pointer

Bytecode, stack are allocated a fixed size of 0x10000 bytes, whereas array can have maximum size of 0x10000 bytes.
```c
#define BYTECODE_SZ       0x10000
#define MAX_ARRAY_SZ      0x10000
#define STACK_SZ          0x10000
#define MAX_REGS          0x4

typedef struct
{
    unsigned long x[MAX_REGS];
    unsigned char *pc;
    unsigned long *sp;
    unsigned int  *ar;
}kawaii_registers;

kawaii_registers *regs;
```
The register context contains 4 general purpose registers, PC, SP and an AR (array pointer), and is allocated on the heap.
The instruction set can be found in full src. It doesn't have any useful bugs, nor does the bytecode sanity checker.\
The general instruction format for this VM goes something like:
```
<INSTRUCTION>  <DEST_REG>  <SRC_REG1>  <SRC_REG2>  (for arithmetic instructions)
<INSTRUCTION>  <REG>       <VAL>                   (for set,get,mov)
<INSTRUCTION>  <REG>                               (for push,pop,shr,shl)
```

## Bug

The bug here is hidden in plain sight since its a niche one. My goal with this challenge was to demonstrate this cool trick.
```c
void get_kawaii_map()
{
    char ans;

    prompt("Do you want a custom array size? (y/n)");

    scanf("%c", &ans);
    getchar();

    if(ans == 0x79) 
    {
        prompt("Enter no of pages (1 page = 4096 bytes)");
        scanf("%f", &units);
        if(units < 0 || units > MAX_ARRAY_SZ/0x1000) error("Array size isn't kawaii :/");
        array_size = 0x1000*units;
    }

    kawaii_map = mmap(NULL, (unsigned long)(BYTECODE_SZ + STACK_SZ + MAX_ARRAY_SZ),  PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);
    if(kawaii_map == (void *)-1) error("mmap failed :-(");
}
```
The scanf is taking in a float and the bounds are checked, however passing in `NaN` as input bypasses these checks. I learnt this cool trick from [Histogram - ACSC 2021](https://github.com/acsc-org/acsc-challenges-2021-public/tree/main/pwn/histogram) authored by [ptr-yudai](https://twitter.com/ptrYudai). The value of `NaN` in memory is `0x8000000000000`. So when multiplied with 0x1000, `array_size` would be `0x8000000000000000` which is clearly out of bounds.

## Exploit Strategy

Now the `get` and `set` instructions can be used to achieve OOB read/write on the mmapped region which is meant to hold the bytecode, stack and array of the VM. Since mmapped regions are adjacent to libc, the primary attack vector is libc rw region which holds `main_arena`, file structures and critical function pointers.
Only open,read,write is viable in this challenge, so overwriting function pointers or hijacking file structures wouldn't be useful. This is where the `reset` instruction comes into play. It updates the register context allocation without freeing the current one. So messing with the `main_arena` could potentially let us control the register context after which we would have arbitrary r/w.

Strategy:
+ Read libc base from ld rw using `get`
+ Read stack address from `environ` in libc rw using `get`
+ Store both values in array for later use, with `set`
+ Craft fake fastbin chunk on array by setting `size` and `fd`
+ Since this challenge  uses libc 2.36, `fd` has to be set to mangled ptr to the fake chunk
+ Use `reset` to allocate register context on array
+ Overwrite `sp` to point to the real stack
+ Craft orw ropchain with libc gadgets using previously saved libc base in array
+ Use `push` instructions to put ropchain on the stack
+ Use `halt` to execute ropchain


## Conclusion

Since this was my first time writing a VM challenge, I learnt a lot. Hope it was fun to solve this :D

You can find the full exploit [here](https://gist.github.com/k1R4/47156c3cf6089e8829475c849ea05e44)

Flag: `bi0sctf{kawaii_vm_n0t_s0_k4wa1i_4ft3r_4ll_f97cf315ea3a}`