---
title: golf.so - PlaidCTF 2020
date: 2020-04-29 13:37:44
author: d4rk_kn1gh7
author_url: https://twitter.com/_d4rkkn1gh7
categories:
  - Misc
  - Linux
  - ELF
tags:
  - Plaid
---

**tl;dr**

+ Hand-crafting a linux shared object file with a size of less than 194 bytes

<!--more-->
**Challenge points**: 500
**No. of solves**: 104
**Solved by** : [d4rk_kn1gh7](https://twitter.com/_d4rkkn1gh7), [k4iz3n](https://twitter.com/akulpillai)

## Challenge Description

The challenge description gave us a link to http://golf.so.pwni.ng/upload, which contained the following instructions:
```
Upload a 64-bit ELF shared object of size at most 1024 bytes. It should spawn a shell (execute execve("/bin/sh", ["/bin/sh"], ...)) when used like

LD_PRELOAD=<upload> /bin/true
```

## Initial approaches

Our first approach was to create a minimalistic C program containing just a simple `execve` system call. However it soon became apparent that however much you tried, even with all of gcc's optimization flags, there was no way to compile a shared object of size < 1 kb.

Then, our next approach was simply creating an assembly file as follows:
```asm
[BITS 64]
      global _init:function
      section .text
_init:
      xor rax,rax
      xor rdx,rdx
      mov rbx,'/bin/sh'
      push rbx
      mov rdi,rsp
      push rax
      push rdi
      mov rsi,rsp
      mov al, 59
      syscall
```
Eventually, compiling this into an elf with nasm, and then into a shared object file with gcc, followed by a lot of manual stripping at the end of the file, we were able to get a working file of size 673 bytes.

We used the following flags to compile.

```sh
nasm -f elf64 code.asm -o test.o && gcc -Os -fno-asynchronous-unwind-tables -Qn
-fPIC -shared -Wl,-z,norelro -nostartfiles test.o -o libtest.so
```

Using the above flags significantly reduced the number of needless Physical Headers and supporting data, few of them were still there though such as a NOTE header and some data that went along with it. We figured out how to get rid of this later.

By manually cutting off the file near the end, we were getting rid of the section headers and sections, which are apparently not required for an ELF to run.

However, uploading this onto the server gave us the following:

```
You made it to level 0: non-trivial! You have 173 bytes left to be considerable. This effort is worthy of 0/2 flags.
```


At this point there were several things we knew we could strip off such as the NOTE section and header, so our priority was to get rid of this. Since we were taking the trial and error approach, manually modifying the binary with a hex-editor would have become tiresome after a while.
It became pretty apparent that in order to get the file under 500 bytes, we had to hand-craft the asm file.

## Hand-crafting the assembly file

Referencing links such as https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html, we were able to create an elf file that executed the required commands, at a size of less than 170 bytes.


```asm
; nasm -f bin -o tiny64 tiny64.asm
BITS 64
  org 0x400000
ehdr:           ; Elf64_Ehdr
  db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
  times 8 db 0
  dw  2         ; e_type
  dw  0x3e      ; e_machine
  dd  1         ; e_version
  dq  _start    ; e_entry
  dq  phdr - $$ ; e_phoff
  dq  0         ; e_shoff
  dd  0         ; e_flags
  dw  ehdrsize  ; e_ehsize
  dw  phdrsize  ; e_phentsize
  dw  1         ; e_phnum
  dw  0         ; e_shentsize
  dw  0         ; e_shnum
  dw  0         ; e_shstrndx
  ehdrsize  equ  $ - ehdr
phdr:           ; Elf64_Phdr
  dd  1         ; p_type
  dd  5         ; p_flags
  dq  0         ; p_offset
  dq  $$        ; p_vaddr
  dq  $$        ; p_paddr
  dq  filesize  ; p_filesz
  dq  filesize  ; p_memsz
  dq  0x1000    ; p_align
  phdrsize  equ  $ - phdr
_start:
  xor rax,rax
  mov rdx, rax
  mov rbx,'/bin/sh'
  push rbx
  mov rdi,rsp
  push rax
  push rdi
  mov rsi,rsp
  mov al, 59
  syscall
  mov rax, 231 ; sys_exit_group
  mov rdi, 42  ; int status
  syscall
filesize  equ  $ - $$
```


Then, in order to convert this into a shared object file, we cross-referenced the smallest working `.so` file we had in IDA, and copied the required program headers and dynamic section. We didn't include the section headers as they weren't required for the program to run.
 
This gave us the following minimalistic 485 byte shared object file:


```asm
; nasm -f bin -o libcopy.so libcopy.asm
BITS 64
  org 0x0
ehdr:           ; Elf64_Ehdr
  db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
  times 8 db 0
  dw  3         ; e_type
  dw  0x3e      ; e_machine
  dd  1         ; e_version
  dq  _init; e_entry
  dq  phdr - $$ ; e_phoff
  dq  0x358; e_shoff
  dd  0         ; e_flags
  dw  ehdrsize  ; e_ehsize
  dw  phdrsize  ; e_phentsize
  dw  3         ; e_phnum
  dw  0x40         ; e_shentsize
  dw  0x9         ; e_shnum
  dw  0x8         ; e_shstrndx
  ehdrsize  equ  $ - ehdr
phdr:           ; Elf64_Phdr
  dd  1         ; p_type
  dd  5         ; p_flags
  dq  0         ; p_offset
  dq  $$  ; p_vaddr
  dq  $$         ; p_paddr
  dq  filesize  ; p_filesz
  dq  filesize  ; p_memsz
  dq  0x200000    ; p_align
  phdrsize  equ  $ - phdr
lhdr:
  dd 1
  dd 6
  dq filesize
  dq 0x200000 + filesize
  dq 0x200000 + filesize
  dq 0xc0
  dq 0xc0
  dq 0x200000  
dhdr:
  dd 2  ; p_type
  dd 6  ; p-flags
  dq filesize ; p-offset
  dq 0x200000 + filesize
  dq 0x200000 + filesize
  dq 0xc0
  dq 0xc0
  dq 0x8
  dq 0xB2719A12
dt_hash:
  dd 3
  dd 1
  dd 1
  dd 6
dt_symtab:
  dd 0
  db 0
  db 0
  dw 0
  dq 0
  dq 0
  dd 7
  db 0x10
  db 0
  dw 7
  dq 0x200300
  dq 0
  dd 0x1a
  db 0x10
  db 0
  dw 7
  dq 0x200300
  dq 0
  dd 1
  db 0x12
  db 0
  dw 5 
  dq _init
  dq 0
dt_strtab:
  db 0
  db "_init", 0
  db "_edata", 0
  db "__bss_start", 0
  db "_end", 0
  db 0
  dq 0
_init:
  xor rax,rax
  mov rdx, rax
  mov rbx,'/bin/sh'
  push rbx
  mov rdi,rsp
  push rax
  push rdi
  mov rsi,rsp
  mov al, 59
  syscall
filesize  equ  $ - $$
dynamic:
  dq 0x0c
  dq _init
  dq 0x6FFFFEF5 ; dummy dt_hash
  dq dt_hash
  dq 0x5
  dq dt_strtab
  dq 0x6
  dq dt_symtab
```

This was basically a handcrafted copy of the binary we were able to create with gcc excluding the NOTE section. Note for example the `dt_symtab` section which contains bytes stripped out from the working `.so` and laid out like this using a python script. We were not concerned with it at this point as we were aiming for the 500 byte mark.

However, this still wasn't worthy of a flag:

```
You made it to level 1: considerable! You have 185 bytes left to be thoughtful. This effort is worthy of 0/2 flags.
```


We eventually found out that this file still contained many unnecessary sections like `dt_hash` and `dt_symtab`, also the last few entries of the `ehdr` contained offsets of the section headers, which weren't in use. So we could override this with junk values, i.e the first few entries of the program header, thereby overlapping the headers and saving even more space. Doing this, we obtain the following file:

```asm
; nasm -f bin -o libcopy.so libcopy.asm
BITS 64
  org 0x0
ehdr:           ; Elf64_Ehdr
  db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
  times 8 db 0
  dw  3         ; e_type
  dw  0x3e      ; e_machine
  dd  1         ; e_version
  dq  _init; e_entry
  dq  phdr - $$ ; e_phoff
  dq  0x358; e_shoff
  dd  0         ; e_flags
  dw  ehdrsize  ; e_ehsize
  dw  phdrsize  ; e_phentsize
  dw  3         ; e_phnum
  ehdrsize  equ  $ - ehdr
phdr:           ; Elf64_Phdr
  dd  1         ; p_type
  dd  5         ; p_flags
  dq  0         ; p_offset
  dq  $$  ; p_vaddr
  dq  $$         ; p_paddr
  dq  filesize  ; p_filesz
  dq  filesize  ; p_memsz
  dq  0x200000    ; p_align
phdrsize  equ  $ - phdr
lhdr:
  dd 1
  dd 6
  dq filesize
  dq 0x200000  +filesize
  dq 0x200000  +filesize
  dq 0xc0
  dq 0xc0
  dq 0x200000
dhdr:
  dd 2  ; p_type
  dd 6  ; p-flags
  dq filesize ; p-offset
  dq 0x200000 + filesize
  dq 0x200000 + filesize
  dq 0xc0
  dq 0xc0
  dq 0x8
dt_strtab:
  db "_init", 0
_init:
  xor rax,rax
  mov rdx,rax
  mov rbx,'/bin/sh'
  push rbx
  mov rdi,rsp
  push rax
  push rdi
  mov rsi,rsp
  mov al, 59
  syscall
filesize  equ  $ - $$
dynamic:
  dq 0x0c
  dq _init
  dq 0x5
  dq dt_strtab
  db 0x6
```

This file is 294 bytes, and on uploading it we get our first flag:

```
You made it to level 2: thoughtful! You have 70 bytes left to be hand-crafted. This effort is worthy of 1/2 flags. PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward}
```


So we evidently needed to get it to 224 bytes to obtain our next flag. However, after overlapping a few `QWORDs` from the `dhdr` section with junk values, we were only able to get the file to 268 bytes. Then on reading more about the structure of shared object files, we found out that we could reduce the number of program headers present from 3 to 2, as there were 2 headers present with the LOAD(1) flag.

One LOAD header was for loading the `_DYNAMIC` section, while the other was for loading the code. We combined these by making it so that both of them are loaded into memory together, this was done by modifying the offsets and with a bit of trial and error. Note that a lot of the values here make little sense and are far from what they are supposed to be as defined by the ELF file format. But it works, so we don't care!

On combining these two headers, creating a couple more header overlaps, and moving the `dt_strtab` entry, we get this:

```asm
; nasm -f bin -o libcopy.so libcopy.asm
BITS 64
  org 0x0
ehdr:           ; Elf64_Ehdr
  db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
  times 8 db 0
  dw  3         ; e_type
  dw  0x3e      ; e_machine
  dd  1         ; e_version
  dq  _init; e_entry
  dq  lhdr - $$ ; e_phoff
  dq  0x358; e_shoff
  dd  0         ; e_flags
  dw  ehdrsize  ; e_ehsize
  dw  phdrsize  ; e_phentsize
  dw  2         ; e_phnum
  ehdrsize  equ  $ - ehdr
lhdr:
  dd 1
  dd 7
  dq 0
  dq $$
  dq $$
  dq filesize + 40
  dq filesize + 40
  dq 0
phdrsize  equ  $ - lhdr
dhdr:
  dd 2  ; p_type
  dd 6  ; p-flags
  dq 0 ; p-offset
  dq filesize
_init:
  xor eax,eax
  xor edx,edx
  mov rbx,'/bin/sh'
  push rbx
  mov rdi,rsp
  push rax
  push rdi
  mov rsi,rsp
  mov al, 59
  syscall
filesize  equ  $ - $$
dynamic:
  dq 0x0c
  dq _init
  dq 0x5
  dq dt_strtab
dt_strtab:
  db 0x6
```

Uploading this 198-byte file gave us:

```
You made it to level 3: hand-crafted! You have 4 bytes left to be flag-worthy. This effort is worthy of 1/2 flags. PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward}
```


So we needed to reduce the file by 4 more bytes to get it to 194 and hopefully obtain our flag!
So finally on removing the `xor edx,edx` instruction (as the program apparently didn't mind a non-null rdx value), and replacing the `mov` instructions with `push` and `pop` instructions to reduce bytes, we get this incredibly small, but somehow working file:

```asm
; nasm -f bin -o libcopy.so libcopy.asm
BITS 64
  org 0x0
ehdr:           ; Elf64_Ehdr
  db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
  times 8 db 0
  dw  3         ; e_type
  dw  0x3e      ; e_machine
  dd  1         ; e_version
  dq  i; e_entry
  dq  lhdr - $$ ; e_phoff
  dq  0x358; e_shoff
  dd  0         ; e_flags
  dw  ehdrsize  ; e_ehsize
  dw  phdrsize  ; e_phentsize
  dw  2         ; e_phnum
  ehdrsize  equ  $ - ehdr
lhdr:
  dd 1
  dd 7
  dq 0
  dq $$
  dq $$
  dq filesize + 40
  dq filesize + 40
  dq 0
phdrsize  equ  $ - lhdr
dhdr:
  dd 2  ; p_type
  dd 6  ; p-flags
  dq 0 ; p-offset
  dq filesize
i:
  xor eax,eax
  mov rbx,'/bin/sh'
  push rbx
  push rsp
  pop rdi
  push rax
  push rdi
  push rsp
  pop rsi
  mov al, 59
  syscall
filesize  equ  $ - $$
dynamic:
  dq 0x0c
  dq i
  dq 0x5
  dq dt_strtab
dt_strtab:
  db 0x6
```

And finally, the server gives us the response we want:

```
You made it to level 4: flag-worthy! You have 1 byte left to be record-breaking. This effort is worthy of 2/2 flags. 
PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward} 
PCTF{t0_get_a_t1ny_elf_we_5tick_1ts_hand5_in_its_ears_rtmlpntyea}
```


It seems that there are still things that you can get rid of and very creative ways in which you can embed the code within the ELF header itself. The challenge is a great task that teaches you a lot about the ELF file format and how one can bend its rules.


## Flags

**golf.so-putter**: `PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward}`
**golf.so-driver**: `PCTF{t0_get_a_t1ny_elf_we_5tick_1ts_hand5_in_its_ears_rtmlpntyea}`