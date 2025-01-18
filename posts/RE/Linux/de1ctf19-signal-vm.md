---
title: Signal VM (Part 1) - de1CTF 2019 
tags:
  - VM 
  - Reversing 
  - Linux
  - Automation
categories:
  - Reversing 
  - Linux
date: 2019-8-8 16:00:00 
author: R3x 
author_url: https://twitter.com/Tr3x__
---

tl;dr

- Challenge is a VM implemented over signals and ptrace
- Reverse Instruction types and implementation
- Use gdb scripting to find the executed code and get the pseudo VM code
- Reverse the VM functionality (Hill cipher) for flag and profit

<!---more--->

**Challenge Points**: 500
**Challenge Solves**: 21
**Solved by**: [R3x](https://twitter.com/Tr3x__), [silverf3lix](https://twitter.com/__silv3r), [Ayushi](https://twitter.com/Ais2397Ayushi)

## Initial Analysis

Challenge takes an input - and running strace we see that it forks a child and then does some ptrace calls. 

```sh
~> strace ./signal_vm

clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1
e69b50) = 1763
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 1763
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1763, si_uid=1000, si_status=SIGILL,
 si_utime=0, si_stime=0} ---
ptrace(PTRACE_GETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_PEEKTEXT, 1763, 0x4014ec, [0x600000000060106]) = 0
ptrace(PTRACE_SETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_CONT, 1763, NULL, SIG_0)  = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1763, si_uid=1000, si_status=SIGILL,
 si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 1763
ptrace(PTRACE_GETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_PEEKTEXT, 1763, 0x4014f3, [0x30106]) = 0
ptrace(PTRACE_SETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_CONT, 1763, NULL, SIG_0)  = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1763, si_uid=1000, si_status=SIGSEGV
, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGSEGV}], 0, NULL) = 1763
ptrace(PTRACE_GETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_PEEKTEXT, 1763, 0x4014fa, [0xcc0000000f000000]) = 0
ptrace(PTRACE_SETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_CONT, 1763, NULL, SIG_0)  = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=1763, si_uid=1000, si_status=SIGILL,
 si_utime=0, si_stime=0} ---
.
.
.
```

Taking a look into the binary for a better understanding we come across the main function.

```c
signed __int64 sub_40172D()
{
  signed int v1; // [rsp+Ch] [rbp-4h]

  print("Check up: ");
  print_0("%s", &unk_6D5132);
  v1 = fork_("%s", &unk_6D5132);
  if ( v1 < 0 )
    return 0xFFFFFFFFLL;
  if ( !v1 )
  {
    (vm_part)();
    sub_40F690(0LL);
  }
  handler(v1);
  if ( dword_6D74E0[0] )
    sub_411110("Ture.");
  else
    sub_411110("False.");
  return 0LL;
}
```

This leads us to understand that the code is basically forking and trying to establish some communication between the child and parent using ptrace.

## Analysis of the Child

Run the binary on gdb with `set follow-fork-mode child` to observe the behaviour of the child. We get `SIGILL`.

Let take a close look at the disassembly of the child.

```as
push    rbp
mov     rbp, rsp
mov     ecx, 0
mov     edx, 0
mov     esi, 0
mov     edi, 0
mov     eax, 0
call    sub_44B410
db    6  //This is where SIGILL is triggered
add     [rsi], eax      
```

This is strange - looks like the child is made to trigger the signal. This leads us to the conclusion that the parent is responsible for handling the signal and continuing the execution of the child somehow.

## Initial analysis of the Parent

Now lets take a look at what is happening in the parent. On reversing the function `handler` we come to the following conclusions.

{% asset_img signal_vm.png Signal VM structure %}

- Parent is the VM handler and the child is basically the VM code.
- Every time the child sends a signal the parent basically handles it like a opcode and performs actions. This is done with the help of ptrace.
- The VM has a set of registers in the parent which are modified based on the opcode and one of these have to be set to 0 for us to get the flag. 

## Digging deeper into the parent VM 

First thing to understand the role ptrace actually plays. Strace gives us - 

```c
ptrace(PTRACE_GETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_PEEKTEXT, 1763, 0x4014ec, [0x600000000060106]) = 0
ptrace(PTRACE_SETREGS, 1763, NULL, 0x7ffc4cb9c0e0) = 0
ptrace(PTRACE_CONT, 1763, NULL, SIG_0)  = 0
```

Having not seen anything other than PTRACE_TRACEME - we start digging into the man page.

> The `ptrace()` system call provides a means  by which one process (the "tracer") may observe and control the execution of another process (the     "tracee"), and examine and change the tracee's memory and registers.
> **PTRACE_PEEKTEXT/POKETEXT** - Read/Write a word at the address addr in the tracee's memory.
> **PTRACE_GETREGS/SETREGS** - Read/Write into the registers of the tracee. 

The parent has handlers for the following signals and each of them define a certain class of instructions:
* SIGILL (signal no 4) - `move` class
* SIGTRAP (signal no 5) - `logical` class
* SIGFPE (signal no 8) - `compare` class
* SIGSEGV (signal no 11) - `jump` class

Now the following script skims through the signals triggered and parses them to give a set of readable instructions which decreased our work.

```python
import gdb
import struct

class Opcode:
    opcode = ""
    val1 = 0
    const = 0
    src = 0
    dest = 0
    final = 0
    final2 = 0
    
    def __init__(self, opcode):
        self.opcode = opcode
        test = struct.unpack("<Q", int(opcode, 16).to_bytes(8, byteorder='big'))[0]
        self.val1 = test >> 56
        self.const = (test >> 48) & 0xff
        self.src = (test >> 40) & 0xff
        self.dest = (test >> 32) & 0xff
        self.final = struct.unpack("<I", ((test & 0xffffffff00) >> 8).to_bytes(4, byteorder='big'))[0]      
        self.final2 = struct.unpack("<I", (test & 0xffffffff).to_bytes(4, byteorder='big'))[0]

    def __repr__(self):
        str_out = "-------------------\n"
        str_out += "OPCODE : %s  |  %d\n" % (self.opcode, int(self.opcode, 16) ) 
        str_out += "val1 = %d | const = %d | src = %d | dest = %d\n" % (self.val1, self.const, self.src, self.dest)
        str_out += "val1 = %s | const = %s | src = %s | dest = %s\n" % (hex(self.val1), hex(self.const), hex(self.src), hex(self.dest))
        str_out += "final = %d    |   final2 =  %d \n" % (self.final, self.final2)
        str_out += "-------------------\n"
        return str_out
        

sign = {4: "SIGILL", 5 : "SIGTRAP", 8: "SIGFPE", 0xb: "SIGSEGV" }
mov_ins = {0: "%d: mov r%d r%d\n",1: "%d: mov r%d 0x%x\n" ,2: "%d: mov r%d [r%d]\n", 32: "%d: mov [r%d] r%d\n"}
ops = ["add" , "sub" ,  "mul" , "div" , "mod" , "or" , "and" , "xor" , "lsh" , "rsh"]
op_sym = ["+", "-", "*", "/", "%", "|", "&", "^", "<<", ">>"]
str_ops = ["%d: %s r%d r%d\n", "%d: %s r%d 0x%x\n"]
jmp = ["", "eq", "neq", "le", "lt", "ge", "gt"]

f = open('ins.out', 'w')

gdb.execute("file signal_vm")
gdb.execute("set pagination off")
gdb.execute("set follow-fork-mode parent")
gdb.execute("b * 0x400C5B")
gdb.execute("b * 0x400C67")
gdb.execute("b * 0x0401448")

gdb.execute("r < input")

i = 0
while True:
    gdb.execute("ni")
    opcode = gdb.execute("p/x $rax", to_string=True).split("=")[1].strip()
    gdb.execute("c")

    sig = gdb.execute("p/x $al", to_string=True).split("=")[1].strip()
    gdb.execute("c")

    print(sign[int(sig, 16)])
    op = Opcode(opcode)    
    print(op)

    if int(sig, 16) == 4:
        if op.const == 1:
            f.write(mov_ins[op.const] % (i, op.src, op.final))
        else:
            f.write(mov_ins[op.const] % (i, op.src, op.dest))

    elif int(sig, 16) == 5:
        
        if op.const == 1:
            f.write(str_ops[1] % (i, ops[op.val1], op.src, op.final))      
        else:
            f.write(str_ops[0] % (i, ops[op.val1], op.src, op.dest))      

    elif int(sig, 16) == 8: 
        if op.src == 1:
            f.write("%d: cmp r%d 0x%x\n" % (i, op.dest, op.final2))
        else:
            f.write("%d: cmp r%d r%d\n" % (i, op.dest, op.final2 & 0xff))
    
    elif int(sig, 16) == 0xb:
        f.write("%d: jmp %s 0x%x\n" % (i, jmp[op.src], op.dest))
      
    else:
        print("Error")

    gdb.execute("c")
    i = i + 1
```

## Final Steps

From the instructions given out by the above script we were able to deduce that it is basically [Hill cipher](https://en.wikipedia.org/wiki/Hill_cipher).

The key Matrix is a 7x7 one generated from the string below

```as 
.data:00000000006D5100 aAlmostHeavenWe db 'Almost heaven west virginia, blue ridge mountains',0
```

The ciphertext matrix can be found from the instructions generated by the above script.Then we used sagemath to do the math for us.

```python
from sage.all import *
s=[[65, 108, 109, 111, 115, 116, 32],
 [104, 101, 97, 118, 101, 110, 32],
 [119, 101, 115, 116, 32, 118, 105],
 [114, 103, 105, 110, 105, 97, 44],
 [32, 98, 108, 117, 101, 32, 114],
 [105, 100, 103, 101, 32, 109, 111],
 [117, 110, 116, 97, 105, 110, 115]]
s = Matrix(IntegerModRing(256),s)
s = s.transpose()
c = [214, 77, 45, 133, 119, 151, 96, 98, 43, 136, 134, 202, 114, 151, 235, 137, 152, 243, 120, 38, 131, 41, 94, 39, 67, 251, 184, 23, 124, 206, 58, 115, 207, 251, 199, 156, 96, 175, 156, 200, 117, 205, 55, 123, 59, 155, 78, 195, 218, 216, 206, 113, 43, 48, 104, 70, 11, 255, 60, 241, 241, 69, 196, 208, 196, 255, 81, 241, 136, 81]
l = []
for i in range(0,len(c),7):
    l.append(c[i:i+7])
l = Matrix(IntegerModRing(256),l)
flag = "".join("".join(map(chr,s.inverse()*l[i])) for i in range(10))
print flag

```

> Running the above script gave us the flag => `de1ctf{7h3n_f4r3_u_w3ll_5w337_cr4g13_HILL_wh3r3_0f3n_71m35_1_v3_r0v3d}`