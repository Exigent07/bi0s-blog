---
title: "Login - Fword CTF 2021"
date:  2021-08-31 12:30:06
author: Vishvesh
author_url: https://twitter.com/The_Str1d3r
mathjax: true
categories:
  - Crypto
tags:
  - FwordCTF
  - Hash-extension
  - RSA-Signature
---

**tl;dr**

+ use hash extension to bypass password check on login.
+ use RSA properties to recover $q$ and get $p$ and therefore $N= p*q$.
+ sign the message given, and get the flag.

<!--more-->

**Challenge Points**: 900

**Challenge Solves**: ~20


## Challenge Description

try to login to this service.

## Initial Analysis
 We are provided with an nc service with the following three options
1. **Sign up**
2. **Login**
3. **Leave**

a) ***Sign up***

This asked us for a username following which a password would be generated 
password consisted of three parts each seperated by a `;` whose sha256 hash was taken

```python
passwd = H(server_token + b';' + user + b';' + proof)
```

- `server_token`: random 16 byte string
- `user`: username over which the user had control over
- `proof`: value of this was initially set to *`is_admin=false`*

after sign up user would get $username$ , $password$ and $proof$ values

b) ***Login***

on Login user would have to input the values of $username$,$password$ and $proof$.
the password value is checked with the hash of secret token and $user$ and $proof$ values which you entered.
if it is correct u move on to next stage

## Login check
the 3 values which you enter on login: $username$, $password$ and $proof$
are used for the first check

```python
    if password == H(server_token + b';' + username + b';' + proof):
        if b'is_admin=true' in proof:
            return True
```
here the hash is calulated by using sha256.
And we need `is_admin=true` in $proof$ but on signup $proof$ is initialised with `is_admin=false` 

a) ***Intended solution***

the intended way here is to append the data `is_admin=true` to $proof$ and generate a hash which satisfies this new data. This can be achived by hash extension attack using [this](https://github.com/iagox86/hash_extender) tool.

b) ***Unintended solution***

Instead of going though with implementation of hash extension there is way more simpler solution to this. If we look at the login part where the 2 if conditions are present we see the second if condition only checks for if the string `is_admin=true` is present in $proof$. But we see that $proof$ is initialised with `is_admin=false` in the begining itself.
Also we notice we have control over username and the value assigned to proof in the login function. So the idea here is to initially generate a password that will pass the first if condition and contain the desired proof value.

Since on sign up we do not have acess to proof we use username itself to assign the value of $proof$.

*confusing.......*

well the idea is to match the password hash and that proof should contain the desired value. For this to work we use the fact that the hash is calculated by adding the strings together it doesnt matter wherse a string is placed as long as on adding all the strings we get the same final string and hence the same hash.

So in sign up we fill in the desired value of proof in username field itself like so

`
username = 'a;is_admin=true'
`
    
so now password hash is:

```python
passwd = H(server_token + b';' + b'a;is_admin=true' + b';' + b'is_admin=false')
```
Now on sign up we have control over bothe username and proof fields
So we give **username** as `a` and **proof** as `is_admin=true;is_admin=false`

```python
passwd = H(server_token + b';' + b'a' + b';' + b'is_admin=true;is_admin=false')
```

so the password hash is same as what we get after sign up but this time the desired vaue is there in proof instead of username hence we pass the check

## Signing

to pass this we need to correctly sign this 
```python
    message_to_sign = b"https://twitter.com/CTFCreators"
```
since the server gives us $e$ and $d$ we can easily get the correct signature only problem is we dont have modulus instea we have $pinv \equiv p^{-1} \bmod\ q$

we know this rsa formula $ed = 1 + k*(p-1)(q-1)$ from this we see $k$ will have same bit size as e and so it can be bruteforced hence we can assume we have $\phi(n) = (p-1)(q-1)$

also we have $p^{-1}p \equiv 1\bmod\ q$
writing $\phi(n)$ in terms of $ \bmod\ q$  we get $\phi(n) \equiv -(p-1) \bmod\ q$

from these 2 observatoins we get $1 + pinv*\phi(n) - pinv \equiv 0 \bmod\ q$ ,
after substituting $p$ in the equation.
$i.e$ LHS of the above equation is a multiple of $q$

from ***fermats little theorem*** for some $a$ we get $a^{\phi(n)} - 1 \equiv 0 \bmod\ p*q$

so we have another multiple. Taking the gcd of these two will get us the value of $q$ after which we get $p$ and so we have $N = p*q$ and we can easily generate a valid sign for the given message!!


----
