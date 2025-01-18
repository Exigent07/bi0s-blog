---
title: beehive - bi0sCTF 2024
date: 2024-03-02 18:38:44
author: the.m3chanic
author_url: https://twitter.com/the_m3chanic_
categories:
  - RE
tags:
  - bi0sCTF
  - eBPF
---

**tl;dr**

+ Custom hook to syscall 0x31337 using eBPF 
+ Check on the argument passed to syscall to verify correct/incorrect key

<!--more-->

**Challenge Points**: 100
**No. of solves**: 61
**Challenge Author**: [the.m3chanic](https://twitter.com/the_m3chanic_)


In this writeup I'll be covering the challenge I authored for bi0s CTF, 2024. 
I intended for this to be an easy warmup challenge for the players, and hopefully some people learned some new stuff from it as well :)


## Challenge description: 
according to all known laws of aviation, there is no way a bee should be able to fly


## Initial Analysis 
In the handout, there is a single file, `beehive.o`, let's take a look at what kind of file it is

![file type](image.png)

So it's an ELF file, but of type eBPF. What is eBPF? 

(I'm going to dive a little deep into eBPF and things surrounding it. If you're only here for the solution to the challenge, you can skip to the solution)


## Understanding eBPF
eBPF is a technology that can be used in the Linux kernel that is like running a very tightly bound (ability-wise) program directly in the kernel space. It is an event-driven language that can be used to hook kernel actions and perform specific tasks. 

It runs natively in the kernel space with the help of a JIT compiler. 

It’s basically a kernel level virtual machine that allows for programming of certain kernel level tasks, such as packet filtering, tracing, etc. Essentially a small computer inside the kernel that can run custom programs with restricted access. 

Basically, think of it as a Kernel level javascript running inside a restrictive VM. 

The obvious question that might come in your mind is - **How is eBPF different from normal kernel drivers or kernel modules**? 

Well, the answer to that is simple:
eBPF programs don’t have nearly the amount of permissions as a regular kernel module, so you could say that they run in a much more constrained environment. They can’t make any drastic changes to the behaviour of the kernel, so this adds to their security and can help in reducing crashes. It’s  perfectly in between a user program and a kernel program, in the sense that it runs in the kernel space, but with restrictions that differentiate it from an actual kernel module. 


Now that we've got the basics out of the way, let's get back to solving the challenge. 

## Our Approach 
Some google searches tell us that eBPF can be disassembled using `llvm`, so let's give that a try 

![llvm output](image-1.png)

Sure enough, we get the output, and in that we see a function called `weird_function`, now let's take a look at what it does

One thing to keep in mind is: eBPF has its own instruction set architecture, so everything from registers to calling convention will be different

Quick overview of eBPF architecture:
```
eBPF is a RISC register machine with 11 registers in total. Each 64-bits in size. 

9 of these registers are general purpose, with arbitrary read-write over each of them. One register is a read-only stack pointer, and one implicit program counter (in the sense, we can only jump to a particular offset with it). 

The VM registers are always 64-bits wide, even if it’s running on a 32-bit processor, the rest of the bits are just zeroed out in that case. 

r0 register holds the return value of helper function calls

r1-r5 hold the function arguments for kernel function calls, r6-r9 are callee saved registers 

r0 also stores the exit value when the eBPF program exits from the kernel.
```



## Understanding the challenge 
Now, the first few instructions from the dump kind of give us an idea of what's going on here. 

A bunch of stuff is loaded on the stack first, following which the last value loaded on top is later compared to 0x31337. 

In eBPF, whenever a syscall is made, arguments passed to the syscall are pushed on the stack in reverse order, and the syscall number is pushed last (i.e, at the top). We can see that our program is doing something similar here. 

We know that eBPF harbours the capability to hook onto syscalls on the kernel, so could it be possible that it is trying to hook onto syscall 0x31337? 
Let's confirm that hunch. 

A failed comparison of the syscall number with 0x31337 leads us to label-18, which is

![exit label](image-2.png)

So I think we would need to make the syscall number 0x31337 to interact with this program. But what do we pass to it? 

![strings output](image-3.png)

Seems like the program is asking for a key, and verifies that key for us.

Obviously the entire program can't be efficiently analysed using just the object dump, so I will switch to IDA PRO for the remainder of this writeup. 
By default, IDA is not capable of recognising this machine type, but there is a handy [processor](https://github.com/cylance/eBPF_processor) plugin that supports eBPF. 

The output still doesn't look too clean on IDA, so we can run the scripts on the processor repo to relocate maps and clean up eBPF helper calls for us. 

(To run script files on IDA: File -> Script file -> filename.py)

The first few blocks of the disassembly seem to be telling us some pretty obvious things, it takes input, copies it to a kernel land string, then stores it. 

How does it reference it though? 
Let's look at this logically - we know the binary has a print statement somewhere, and it prints 1 of 2 things

![correct incorrect print](image-5.png)

How is it referencing the correct and incorrect strings? 

We can see some constants being loaded into `r1` in each block, and that constant just happens to be the offset of the strings "Key is correct!" and "Key is incorrect!", from the .rodata section. `r2` just holds the length of the string to be printed. 

I don't want to get into too much detail about assembly level reversing here, so I will mention the required details, while trying to retain as much information as possible 
```
r1 --> loop counter for byte by byte encryption
r2 --> contains the pointer to current encrypted byte 
r3 --> is_correct flag 
```

And, a python (almost line-by-line) representation of the encryption is as follows: 
```py
def check(r5):
    r7 = r5
    print(f"[*] Initial state of r5: {'{:08b}'.format(r5)}")
    r7 &= 15
    r7 <<= 4
    r5 &= 240
    r5 >>= 4
    r5 |= r7
    r7 = r5
    r7 &= 51
    r7 <<= 2
    r5 >>= 2
    r5 &= 51
    r5 |= r7
    r7 = r5
    r7 &= 85
    r7 <<= 1
    r5 >>= 1
    r5 &= 85
    r5 |= r7
    print(f"\n\n[*] Final state of r5: {'{:08b}'.format(r5)}")
```


## Interacting with the program? 

This is all very nice, but what's a program that you cannot interact with? 

Well, since this is an eBPF program, it'll have to be loaded on the kernel and get past the verifier first, before we can actually make the syscall `0x31337` to trigger it. 

How do we do that?

You can use this loader file to load the program and simultaneously read `trace_pipe` (where the outputs of `bpf_trace_printk`) are logged. 

(Run this shell script first)

```sh
sudo clang -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c "$1"_challenge.c -o $1.o
sudo bpftool gen skeleton $1.o > $1.skel.h
sudo clang -g -O2 -Wall -I . -c loader.c -o loader.o
sudo clang -Wall -O2 -g loader.o libbpf/build/libbpf/libbpf.a -lelf -lz -o loader
sudo ./loader
```

(Then, run this file to load the program)
```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "final.skel.h"

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(void)
{
	struct final *obj;
	int err = 0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}


	obj = final__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = final__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = final__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	read_trace_pipe();

cleanup:
	final__destroy(obj);
	return err != 0;
}
```

Once loaded, you can write a python program to trigger the syscall with the arguments that you want to test it out (I used the  `ctypes` module for this)

<br>  


## The Solution

Once you understand how the program manipulates your input, reversing it becomes quite trivial. The program simply takes each byte of your input, flips the bits (8 padded), then compares it with a preexisting array. 

```py 
compArray = [86, 174, 206, 236, 250, 44, 118, 246, 46, 22, 204, 78, 250, 174, 206, 204, 78, 118, 44, 182, 166, 2, 70, 150, 12, 206, 116, 150, 118]

for i in compArray: 
    i = '{:08b}'.format(i) 
    i = i[::-1]
    i = int(i, 2)
    print(chr(i), end = "")
```


And that was my challenge! I hope you had fun solving it and (hopefully) also learned something new while doing it. :)
