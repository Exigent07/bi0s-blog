---
title: MultiStorage - InCTF Internationals 2021
date: 2021-08-18 12:00:00
author: 3agl3
author_url: https://twitter.com/3agl31
categories:
  - Pwn
tags:
  - Exploitation
  - Heap
  - Kernel
  - InCTFi
---

**tl;dr**

+ Race condition to change the `type`.
+ Leak using uninitialized memory and get rip with overflow.

<!--more-->

**Challenge Points:** 1000
**No of Solves:** 1
**Challenge Author:** [3agl3](https://twitter.com/3agl31)


## Challenge Description

`You can now store two types of data in kernel.`

Handout have the files bzImage, rootfs.cpio, start.sh and src files. Typical for a kernel challenge.

## Initial Analysis

If we check the src files, we can see there are 3 options avaiable:

- Add: Takes a user memory, count number of `type1` and `type2` elements, allocate memory and copy it.
- Delete: Free the allocated memory and nulls out global variables.
- View: Copy data to user depending on which `type` is specified in input.

## Structures

These are some of structures that we can see in `MultiStorage.h`

### Used for TYPE1

```c
typedef struct{
    char data[28];
    unsigned int id;
}Type1;
```

### Used for TYPE2

```c
typedef struct{
    unsigned int arr[7];
    unsigned int id;
}Type2;
```

As we can see, both Type1 and Type2 are of the same size.

The program is pretty straghtforward in implementing the above mentioned functionalities.

## Bug

If we look at the `Add` function, we can see a problem. It is directly using userspace memory without copying it to kernel. This means that user can modify the memory while kernel is processing it and there is nothing to prevent this. Ideally, Add should have copied the entire memory to kernel space and then process it.

So what can we do here?
If we look at the Add, it first finds the count of Type1 and Type2 elements. Then it allocates the space using kmalloc and then copy the data. But the second copy again uses the userspace memory. So consider the case where we gave 5 Type1 and 5 Type2 and then somehow change this number after the first for loop, before the second for loop, we can get an overflow.

Another thing that we can see is the call to `Info` in between these loops.

```c
static noinline void Info(char* s){
    msleep(10);
    printk(KERN_INFO "%s", s);
    return;
}```

Info calls `msleep` which makes the race condition reliable.

## Exploitation

So the idea is to first create 5 of Type1 and 1 of Type2. Once we call ioctl, in another thread, we change the 1 Type2 to 0. So now we will have 6 of Type1 and 0 of Type2. Meaning nothing will be copied to the space allocated for Type1. So if that chunk was used before for something else, we can leak the data inside it. We will use `seq_operations` to leak a kernel address.

After getting leak, we can use the similar method to get rip control. We again create 5 Type1 and 1 Type2. But instead of changing Type2 to 0, we change it to 2. So when `Add` tries to copy the 2nd Type2, it will overwrite whatever is there below the allocated chunk since `Add` only allocated for 1 Type2. We can again use `seq_operation` and overwrite the pointer inside it to get RIP control.

Since there is no `SMAP` enabled, we can just stack pivot to userspace and execute a rop chain which does `commit_creds(prepare_kernel_cred(0))` giving us root.


## Conclusion

Hope everyone enjoyed the challenge.

You can find the full exploit [here](https://gist.github.com/souragc/7a8024792759a7795244cbc8ced66fae).

Flag - inctf{m1ssed_copy_from_user_T_T3605493d60}
