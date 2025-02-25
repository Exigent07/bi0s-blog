---
title: cs2100 - HackTM CTF Quals 2023
date: 2023-02-23 12:26:14
author: k1R4
author_url: https://twitter.com/justk1R4
categories:
  - Pwn
tags:
  - Exploitation
  - VM
---

**tl;dr**

+ `LOAD` and `S_TYPE` opcodes lead to OOB when addr > `DRAM_BASE+DRAM_SIZE`
+ Get libc and stack pointers and offset to obtain RIP offset and base
+ Write ropchain on stack using libc gadgets
+ Perform ORW on flag file

<!--more-->

**Challenge Points**: 462
**No. of solves**: 29
**Solved by**: [k1R4](https://twitter.com/justk1R4)


## Challenge Description

```
To all my CS2100 Computer Organisation students, I hope you've enjoyed the lectures thus far on RISC-V assembly.

I have set-up an online service for you to test your own RISC-V code!
Simply connect to the service through tcp:

nc 34.141.16.87 10000

Credit: Thanks to `@fmash16` for his emulator! I didn't even have to compile the emulator binary myself :O https://github.com/fmash16/riscv_emulator/blob/main/main
```

Handout has the challenge binary, libc, server.py and Dockerfile

## Initial Analysis

The binary is not stripped and has most mitigations turned on, typical for a binary compiled without explicit GCC flags.

Here is the checksec output:
```bash
[k1r4@zg15 chal]$ checksec main
[*] '/home/k1r4/Shared/ctfs/hacktm-quals-23/cs2100/chal/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This challenge seems to be a VM which implements the RISC-V architecture. There is a github repo provided from which the challenge seems to be based on. The next obvious step is to look at the src for bugs.

## Source Code

The source code can be found [here](https://github.com/fmash16/riscv_emulator/tree/bb04b265600d127d8b056fd470f7e21b810f630b)

Before this challenge, I had never tried and RISC based challenges. I went ahead with solving this challenge, without understanding the architecture. I solved it by reversing the instruction opcodes. In hindsight it would've been much easier if I went through the register and instruction structure first. Wikipedia has a decent explanation of the architecture design, which you can find [here](https://en.wikipedia.org/wiki/RISC-V#Design).

Moving on to the src, the `src/cpu.c` file contains majority of the code that drives the VM. However there doesn't appear to be any useful bugs on the surface. Since it is a VM challenge, the bug is probably OOB. In that case, the first instructions to look at are ones which involve memory derefences. The `LOAD` and `S_TYPE` opcodes seem to have the most potential in that case. Here is the implementation of the `LD` instruction:
```c
void exec_LD(CPU* cpu, uint32_t inst) {
    // load 8 byte to rd from address in rs1
    uint64_t imm = imm_I(inst);
    uint64_t addr = cpu->regs[rs1(inst)] + (int64_t) imm;
    cpu->regs[rd(inst)] = (int64_t) cpu_load(cpu, addr, 64);
    print_op("ld\n");
}
```
Seems like memory is accessed through addresses which are passed to `cpu_load()` which calls `bus_load()` which again calls `dram_load()`.

## Bug

`dram_load()` calls `dram_load_x()` where `x` is the number of bits. In the case of `LD`, `dram_load_64()` is called. It is implemented as follows:
```c
uint64_t dram_load_64(DRAM* dram, uint64_t addr){
    return (uint64_t) dram->mem[addr-DRAM_BASE]
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 1] << 8
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 2] << 16
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 3] << 24
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 4] << 32
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 5] << 40 
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 6] << 48
        |  (uint64_t) dram->mem[addr-DRAM_BASE + 7] << 56;
}
```

The following code is from `include/dram.h`:
```c
#define DRAM_SIZE 1024*1024*1
#define DRAM_BASE 0x80000000

typedef struct DRAM {
	uint8_t mem[DRAM_SIZE];     // Dram memory of DRAM_SIZE
} DRAM;
```

In the end `dram->mem` array is accessed, which is part of the `CPU` struct located on the stack. Since `addr` can be controlled, giving an `addr` larger than `DRAM_BASE+DRAM_SIZE` will lead to OOB on the stack.


## Exploit Strategy

The `LOAD` and `S_TYPE` opcodes can be used to achieve OOB read and write respectively. Stack and libc pointers that are down the stack, can be copied and performed arithmetic on to obtain address of saved RIP and libc base. The `LUI` instruction can be used to move immutables to upper 20 bytes of registers and `ADDIW` can be used to add immutables to the lower 12 bits of registers. `ADD` can be used to offset from libc base to get gadgets. This seems pretty straightforward but I ran into some trouble. The `ADD` or `LUI` instructions were causing the value to be off by 0x1000 sometimes, so I had to manually increase the offset in those cases.

Finally a ropchain is written at saved RIP of main, using `SW` and `SD` instructions. `execve` isn't feasible here since server.py is what we interact with and not the binary directly. So open,read,write is used instead.


## Conclusion

I learnt a lot about the RISC-V architecture from this challenge and had a lot of fun solving this. 

You can find the full exploit [here](https://gist.github.com/k1R4/7b02827e9291fb43635ce8ef659c5bbd)

Flag: `HackTM{Now_get_an_A_for_the_class!}`