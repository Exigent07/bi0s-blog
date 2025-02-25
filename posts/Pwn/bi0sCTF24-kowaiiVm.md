---
title: kowaiiVm - bi0sCTF 2024
date: 2024-02-28 20:33:00
author: k1R4
author_url: https://twitter.com/justk1R4
categories:
  - Pwn
tags:
  - Exploitation
  - bi0sCTF
  - JIT
  - VM
---

**tl;dr**

+ The VM takes a custom binary as input
+ Binary contains function table, code and bss sections
+ Code can overlap with bss and be modified at runtime
+ The JIT compiler assumes that a function is safe since it ran many times
+ Functions modified right before JIT bypass security checks

<!--more-->

**Challenge Points**: 919
**No. of solves**: 13
**Challenge Author**: [k1R4](https://twitter.com/justk1R4)


## Challenge Description

`I fear no man, but that thing..., JIT, it scares me`

Handout has the binary, dynamic libraries and the source code. The source code includes:
 - `kowaiiVm.h` - The main header file
 - `kowaiiVm.cpp` - Implementation of the VM without JIT
 - `kowaiiJitVm.cpp` - JIT Implementation of the VM inherited from the previous file

## Initial Analysis

### Mitigations
The binary has all mitigations that are expected:
```bash
[k1r4@enderman handout]$ pwn checksec kowaiiVm
[*] '/home/k1r4/work/projects/2024/Pwn/kowaiiVm/handout/kowaiiVm'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Furthermore it uses seccomp to enable only certain syscalls
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x09 0xffffffff  if (A != 0xffffffff) goto 0014
 0005: 0x15 0x07 0x00 0x00000000  if (A == read) goto 0013
 0006: 0x15 0x06 0x00 0x00000001  if (A == write) goto 0013
 0007: 0x15 0x05 0x00 0x00000002  if (A == open) goto 0013
 0008: 0x15 0x04 0x00 0x00000008  if (A == lseek) goto 0013
 0009: 0x15 0x03 0x00 0x0000000a  if (A == mprotect) goto 0013
 0010: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0013
 0011: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0013
 0012: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```
The flag will have to be obtained through open, read, write.

## Implementation
The VM is implemented as a class `kowaiiJitVm` which inherits `kowaiiVm`, which itself contains a child class `kowaiiCtx` as member. `kowaiiCtx` has members `struct kowaiiBin` and `struct kowaiiRegisters`. The [source code](https://github.com/teambi0s/bi0sCTF/tree/main/2024/Pwn/kowaiiVm/admin/src) is quite lengthy, so only the necessary parts will be covered here.

## Opcodes
List of opcodes present in the VM:
- `ADD`, `SUB`, `MUL` - Perform arithmetic on 2 registers and store result in third
- `SHR`, `SHL` - Shift a register based on 1 byte immidiate and store result in other register
- `PUSH`, `POP` - push/pop register onto/from stack
- `GET`, `SET` - read/write register from/to `bss` offset by 4 byte immidiate
- `MOV` - move 4 byte immidiate into register, clearing upper 4 bytes
- `CALL` - call a function based on 2 byte hash
- `RET` - return from function
- `NOP` - no operation

### Structs
```cpp
typedef struct __attribute__((__packed__)) kowaiiFuncEntry
{
    u16 hash;
    u64 addr;
    u8 size;
    u8 callCount;
} kowaiiFuncEntry;
```
- Multiple counts of this struct make up the function table present in `kowaiiBin`
- During function calls, `hash` of the callee is looked up in the table and `addr` is put in pc
- `size` is used to know the end of a function
- `callCount` is kept track of to know how hot a function is, in order to JIT it<br>

```cpp
typedef struct __attribute__((__packed__)) kowaiiBin
{
    u8 kowaii[6];
    u16 entry;
    u32 magic;
    u16 bss;
    u8 no_funcs;
    kowaiiFuncEntry funct[];
} kowaiiBin;
```
- Binary is supposed to have the header "KOWAII"
- `entry` contains the entrypoint for the binary
- `magic` is supposed to be `0xdeadc0de` to pass verification
- `bss` contains the start of bss
- `no_funcs` contains no of functions present in the function table
- `funct` is an arrray of function entries of size `no_funcs`<br>

```cpp
typedef struct __attribute__((__packed__)) kowaiiRegisters
{
    u64 x[MAX_REGS];
    u8 *pc;
    u64 *sp; 
    u64 *bp;
} kowaiiRegisters;
```
- The VM has 5 registers, [x0-x5] which in JITed code translate to [r10-r15]
- Furthermore it has a program counter, stack pointer and base pointer<br>

```cpp
public:
    kowaiiBin *bin;
    kowaiiRegisters *regs;
    kowaiiFuncEntry **callStack;
    kowaiiFuncEntry **callStackBase;
    u8 *bss;
    u8 *jitBase;
    u8 *jitEnd;
```
- `callStack` and `callStackBase` are used to keep track of function calls for JIT-ing
- `jitBase` and `jitEnd` are used to keep track of mapping created for JIT-ed code<br>

### Important Functions
```cpp
void *genAddr()
{
    u64 r = 0;
    do r = (u64)rand();
    while((int)r < 0);

    return (void *)(r << 12);
}
```
This private method of `kowaiiCtx` is used to generate address for mappings of `kowaiiBin`. The seed is initialized properly, so the addresses aren't guessable. All these addresses are low in memory, so there is no chance of OOB access to other memory regions.

During the initialization of `kowaiiBin`, the function table addresses, `entry` and `bss` are patched so that they are offset from the base of the memory map of `kowaiiBin`. This is done in `prepareFuncTable()` and `prepareCtx()`.<br>


```cpp
void runVm()
{
    while(*this->ctx.regs->pc != HLT)
    {
        this->checkState();
        this->executeIns();

        this->ctx.regs->pc += this->stepSize;
    }
    cout << "[*] Execution complete!" << endl;
}

```
During execution of the interpreter, there are plenty of checks in `checkState()` and then only it proceeds to `executeIns()`, where the execution actually occurs. No obvious bugs here<br>

```cpp
void virtual retFunc()
{
    this->ctx.regs->pc = (u8 *)(*this->ctx.regs->sp++);
    (*this->ctx.callStack)->callCount++;
    if((*this->ctx.callStack)->callCount >= JIT_CC && (*this->ctx.callStack)->size >= JIT_MS ) this->jitGen(*this->ctx.callStack);
    *(this->ctx.callStack--) = NULL; 
    return;
}
```
`kowaiiJitVm` overrides `retFunc()` to catch hot functions as they return and JIT them. The condition for JIT-ing is:
- The function has to be called atleast `JIT_CC` times (10 by default)
- The function has to be atleast of size `JIT_MS` (10 by default)<br>

After a function is JIT-ed using `jitGen()`, the address is updated with the respective JIT region address.
When its called next time through `callFunc()`, the constraints for JIT-ing a function is checked again to see if it would've been JIT-ed. If so, the function is called using `jitCall()`. `jitCall()` seems complicated but its essentially doing the following
- Saves [r8-r15], `rbp`, `rsp`, `rcx`, `rdi`, `rdx`
- Moves [x0-x5] from the register context into [r10-r15]
- Sets `rsp` to the stack from register context
- Sets `rdx` to start `bss` (used in `SET` and `GET`)
- Calls `fe->addr`
- Moves [r10-r15] into [x0-x5] in the register context
- Restores saved registers

## Bug

The intended bug here is very subtle. There is no bounds check on `pc` anywhere in the interpreter. This allows a function to start in `code` section but overlap onto `bss`. So the function can modify itself at runtime using `GET` opcode.

There were some interesting unintended solutions that leveraged these bugs:
- `stackBalance` doesn't work as intended with nested calls and overlapping functions
- After JIT-ing `MUL` instruction could clobber `rdx`, which was used as start of `bss`

## Exploit Strategy
- Create the target function at the end of `code` such that most of it overlaps with `bss`
  - The function modifies itself at runtime using `SET`
  - Modification results in the `RET` at the end, considered as part of immidiate of previous instruction
  - Place unsafe instructions below the ret which will JIT-ed later, bypassing the checks of interpreter
- Create an entry function
  - This function calls the target function `JIT_CC`+1 times
  - Restores the opcodes that were changed at runtime
  - This is done to pass checks everytime the function runs until it is JIT-ed
- Place "flag.txt" somewhere in bss
- The unsafe instructions at the end of target function do the following
  - Use OOB `GET` to read function table (`this->ctx.bin->funct`) to leak `kowaiiBin` and JIT region addresses
  - Include ropgadgets as immidiate values in `MOV` instruction
  - Use leaks and offset to ropgadgets and "flag.txt"
  - Construct ropchain in reverse using `PUSH` instructions
  - Add a `ret` finally to execute ropchain
- The ropchain performs open, read, write to leak flag

## Conclusion

I spent a lot of time making this challenge and it was a lot of fun. There were a few unintended bugs as mentioned earlier which have arguably cooler solutions that the one I envisioned. The bugs are actual errors I made when writing the code. I noticed the intended bug and decided to keep that and built my exploit around it. After this experience, I really understood how hard it is to write a safe JIT compiler. I find JIT really fascinating now :D

You can find the exploit [here](https://gist.github.com/k1R4/896eb049d42c06a5922d1c8b8d0707b4)

Flag: `bi0sctf{4ssump7i0ns_4r3nt_4lw4y5_tru3_811f079e}`