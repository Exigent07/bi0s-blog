---
title: k32 - bi0sCTF 2022
date: 2023-01-23 14:10:39
author: k1R4
author_url: https://twitter.com/justk1R4
categories:
  - Pwn
tags:
  - Exploitation
  - bi0sCTF
  - Kernel
  - Heap
---

**tl;dr**

+ Giving size > 48 causes heap OOB r/w of 16 bytes
+ Use OOB r/w get leaks and overwrite objects for rip control

<!--more-->

**Challenge Points**: 1000
**No. of solves**: 1
**Challenge Author**: [k1R4](https://twitter.com/justk1R4)


## Challenge Description

`32 bytes is all you get, or is it? :-O`

Handout has the files bzImage, rootfs.cpio, run.sh and pow.py(for PoW). Typical for a kernel challenge.

## Initial Analysis

SMEP, SMAP, KPTI and KASLR are all enabled. `CONFIG_STATIC_USERMODEHELPER=y` is set, so `modprobe_path` is readonly.

### Structs

```c
typedef struct{
    struct k32_t *next;
    char *buf;
    uint8_t size;
}k32_t;
```
Each node has a pointer to next node, pointer to chunk that holds data and size

```c
typedef struct{
    char *buf;
    uint8_t size;
    uint32_t idx;
}req_t;
```
The request struct passed to ioctl is self-explanatory

### Functionality

We have 4 commands in accessible through ioctl
+ k32_create - create a node
+ k32_delete - delete a node
+ k32_read   - read data from a node
+ k32_write  - write data to a node

## Bug

The bug is in k32_create:
```c
static noinline uint8_t k32_fix_size(uint8_t size)
{
   if(size > 0x30) return 0x30;
   else return 0x20;
}

static noinline long k32_create(req_t *req)
{
    k32_t *k32 = k32_head;
    k32_t *prev = NULL;

    req->size = k32_fix_size(req->size);

    while(k32 != NULL && k32->buf != NULL)
    {
        prev = k32;
        k32 = k32->next;
    }

    if(k32 == NULL)
    {
        k32 = kmem_cache_zalloc(k32_cachep, GFP_KERNEL_ACCOUNT);
        if(k32 == NULL) return error("[-] Unable to kmem_cache_zalloc() in k32_create");
        if(k32_head != NULL) prev->next = k32;
        else k32_head = k32;
    }

    k32->buf = kmalloc(k32_fix_size(req->size), GFP_KERNEL);
    if(k32->buf == NULL) return error("[-] Unable to kmalloc() in k32_create");

    k32->next = NULL;
    k32->size = req->size;

    return 0;
}
```

req->size is updated with the fixed size. However when its passed to kmalloc, its fixed again with k32_fix_size.
Finally node->size is set to req->size. So giving size > 48 will cause node->size = 48 but will kmalloc a chunk of size 32 (kmalloc-32), hence the challenge name k32 :)

## Exploit Strategy

+ Allocate a bunch of nodes with `k32_create` and use OOB read in `k32_read`, to leak heap by reading a freelist pointer
+ Spray `seq_operations` structs and leak code address
+ Create ropchain that performs `commit_creds(prepare_kernel_cred(0))`
+ Spray `msg_msg` structs having said ropchain in msg buffer
+ Overwrite `.start` and `.next` fn pointers in `seq_operations` using `k32_write`
+ Call `read()` to trigger `seq_read_iter`, which executes code form the `.start` and `.next` fn pointers
+ `.start` and `.next` fn pointers are set to ret gadgets so as to misalign the stack
+ When `seq_read_iter` returns, RIP is popped from userspace saved registers down the stack
+ This allows us to pivot to heap where our ropchain is saved
+ Ropchain is executed and finally returns to userland where root shell is popped.


## Conclusion

It was fun making this challenge. Hope it was fun to solve it as well :D

You can find the full exploit [here](https://gist.github.com/k1R4/16cc79d157bd346e4155087540fa03ec)

Flag: `bi0sctf{km4ll0c-32_1sn't_3xpl01tabl3_r1gh7_guy5?_3feb178d2a9c}`