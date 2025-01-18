---
title: Baby Glob - InCTF Internationals 2021
date: 2021-08-17 12:00:00
author: Cyb0rG
author_url: https://twitter.com/_Cyb0rG
categories:
  - Pwn
tags:
  - Exploitation
  - Heap
  - CVE-2017-15804
  - InCTFi
---

**tl;dr**

+ Heap Overflow in glob function while handling `Tilde` operator.
+ Abuse null byte overflow to gain RCE.

<!--more-->

**Challenge Points:** 983
**No of Solves:** 9
**Challenge Author:** [Cyb0rG](https://twitter.com/_Cyb0rG)

## Challenge Description

`A Super secure path finder from your own 2017.`

To start with , the challenge handout folder contains the binary , `chall.c` and `glob.c`.

The binary is a standard CTF-style executable. According to the description , the challenge is running on standard `ubuntu 20.04` docker container so the libc naturally is `2.31`.

## Initial Analysis

There are 4 straightforward functions 

1. **Add Path** - Takes a pattern of user supplied size (limited to 0x1000) , mallocs it and stores it in a global array of patterns.
2. **Check Path** - Takes an index , and uses the `glob` function to check if there exists a pathname matching the pattern.
3. **View Path** - Takes an index and prints the pattern.
4. **Remove Path** - Frees the memory containing the pattern at a user specified index , and nulls out the global array.

It is fairly trivial to get a libc leak , since malloc is used and size limit is 0x1000 , we can easily leak a libc main arena pointer to start with.

But where is the actual exploitable bug? The answer partly lies in the description as well as the `glob.c` provided. A quick internet search on `glob cve 2017` quickly reveals the presence of an overflow while mishandling the `Tilde` operator. A little more research reveals a public [poc](https://sourceware.org/bugzilla/attachment.cgi?id=10549&action=edit) available too. 

Using the poc , we can see that we immediately trigger crash with `malloc() corrupted top chunk`.

## Analysis of CVE-2017-15804

The code path which triggers the heap overflow is as follows -

In `glob.c line: 523` , the first call to malloc happens and the data string is stored on heap.

```c
    else
      {
        newp = malloc (dirlen + 1);
        if (newp == NULL)
          return GLOB_NOSPACE;
        malloc_dirname = 1;
      }
    *((char *) mempcpy (newp, pattern, dirlen)) = '\0';
    dirname = newp;
    ++filename;
```

We are interested in the part of code from `line: 575 of glob.c`

```c
  if ((flags & (GLOB_TILDE|GLOB_TILDE_CHECK)) && dirname[0] == '~')
```

+ The very first character should be `~` and the flags should have the GLOB_TILDE to get into the if condition.

Now , from `line: 709 of glob.c` , we see -

```c
         char *end_name = strchr (dirname, '/');
         char *user_name;
         int malloc_user_name = 0;
         char *unescape = NULL;

         if (!(flags & GLOB_NOESCAPE))
           {
             if (end_name == NULL)
               {
                 unescape = strchr (dirname, '\\');
                 if (unescape)
                   end_name = strchr (unescape, '\0');
               }
             else
               unescape = memchr (dirname, '\\', end_name - dirname);
           }
         if (end_name == NULL)
           user_name = dirname + 1;
```

+ Input must contain a `/` so that the `end_name` is not null and we reach the else condition where `unescape` is initialized.
+ Input should also contain `\\` as unescape should not be null for triggering the heap overflow.

If all this is well , another malloc is called to store the string of size `end_name - dir_name`.

We have a lot of variables on out plate , so let's just list them all together at once.

1. newp = malloc(endname - dirname)
2. dirname = input pointer
3. endname = address of first occurence of `/`
4. unescape = address of first occurence of `\\`

The following `if` condition is the actual cause of heap overflow.

```c
if (unescape != NULL)
  {
    char *p = mempcpy (newp, dirname + 1,
                       unescape - dirname - 1);
    char *q = unescape;
    while (*q != '\0')
      {
        if (*q == '\\')
          {
            if (q[1] == '\0')
              {
                /* "~fo\\o\\" unescape to user_name "foo\\",
                   but "~fo\\o\\/" unescape to user_name
                   "foo".  */
                if (filename == NULL)
                  *p++ = '\\';
                break;
              }
            ++q;
          }
        *p++ = *q++;
      }
    *p = '\0';
  }
```

+ The call to `mempcpy` copies into the `newp` pointer , input of size `unescape - dirname - 1`.
+ In a while loop , it is checked if the unescape string is `\\` , if not , the character at `unescape` is copied into the region after mempcpy.

**Observation** : It keeps copying the entire string without any out of bounds check and thus causes the heap overflow.

## Exploit Idea

Using the public poc , we can check in gdb how things look and do some basic crash analysis.

In one iteration

```sh
0x55555555b390:	0x0000000000000000	0x0000000000000061
0x55555555b3a0:	0x6161616161616161	0x6161616161616161
0x55555555b3b0:	0x6161616161616161	0x6161616161616161
0x55555555b3c0:	0x6161616161616161	0x6161616161616477
0x55555555b3d0:	0x6161616161616161	0x6161616161616161
0x55555555b3e0:	0x6161616161616161	0x6161616161616161
0x55555555b3f0:	0x2f2f2f2f2f2f6161	0x0000000000020c11 <- top chunk
```

In next iteration

```sh
0x55555555b390:	0x0000000000000000	0x0000000000000061
0x55555555b3a0:	0x6161616161616161	0x6161616161616161
0x55555555b3b0:	0x6161616161616161	0x6161616161616161
0x55555555b3c0:	0x6161616161616161	0x6161616161616477
0x55555555b3d0:	0x6161616161616161	0x6161616161616161
0x55555555b3e0:	0x6161616161616161	0x6161616161616161
0x55555555b3f0:	0x2f2f2f2f2f2f6161	0x0000000000020c2f <- top chunk corrupted with input
```

This is what causes the `malloc() corrupted top`.

For the sake of ease of debugging , I have provided the challenge binary with debug symbols and source code stepping within gdb.

### Null byte to the rescue

After playing around with the poc and tweaking it a bit , we realize that overflow is happening only with `0x2f` byte which really isnt very interesting in terms of overwriting a tcache pointer fd or unsorted bin since it's not aligned. But with some effort and tweaking the poc , we can actually get a null byte overflow which is very powerful primitive as we all know.

With the null byte overflow , we can easily point tcache fd of a chunk to point to a fake chunk which resides at the memory ending with `\x00`. With this , we can successfully construct a fake chunk containing `free_hook` as fd.

## Conclusion

I had randomly come across this CVE and found it very interesting, I hope you enjoyed solving the challenge.

[Here](https://gist.github.com/PwnVerse/d4d73d38c06b6cc20be4de9e98f16bbe) is the complete exploit.

Flag - `inctf{CVE-2017-15804_Subtl3_H3ap_Overfl0w}`












