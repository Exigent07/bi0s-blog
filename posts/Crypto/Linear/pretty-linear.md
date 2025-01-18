---
title: pretty-linear
tags: 
  - 35c3
  - Matrix
  - Gauss
categories:
  - Crypto
  - Linear
date: 2018-12-30 16:45:33
slidehtml: true
author: v4d3r
author_url: https://twitter.com/sayoojsamuel
popular_posts: true
---
Writeup from Junior 35c3CTF'18
# Junior 35c3CTF 2018: pretty-linear

**Category:** Crypto
**Challenge Points:** 158 
**Solves:** 28

**Description:**
```
The NSA gave us these packets, they said it should be just enough to break this crypto.

surveillance.pcap server.py

Difficulty estimate: Medium-Hard
```
<!--more-->

This challenge objective was pretty clear - **Solve Linear Equation with 40 unknowns**

Now starting with  `*server.py*`, we have three sets of variables, 
```python
if __name__ == '__main__':
     # key = keygen()   # generated once & stored in secrets.py
     challenge = keygen()
     print(' '.join(map(str, challenge)))
     response = int(input())
     if response != sum(x*y%p for x, y in zip(challenge, key)):
         print('ACCESS DENIED')
         exit(1)
```

>1. key
>- unknown, find 40 of them to get flag
>2. challenge
>- 40 integers per stream, we have 40 of them
>3. response
>- 1 response per stream, again 40 of them

----------
## Analysing *surveilance.pcap* with Wireshark
Open the `packet capture` file with Wireshark. We see mostly TCP packets, and to analyse the TCP packets, click 
>Analyse > Follow > TCP stream
{% asset_img TCP-stream-eq-0.png Wireshark %}

We have 40 such streams of which, the *blue* ones are the `challenge`, and the *red* ones are `response`.

### Extracting data using tshark
The following bash script will extract the data from **surveilance.pcap**
>extract.sh
```bash
infile=surveilance.pcap
outfile=out
ext=txt
for stream in $(tshark -nlr $infile -Y tcp.flags.syn==1 -T fields -e tcp.stream | sort -n | uniq | sed 's/\r//')
do
        echo "Processing stream $stream: ${outfile}_${stream}.${ext}"
            tshark -nlr $infile -qz "follow,tcp,raw,$stream" | tail -n +7 | sed 's/^\s\+//g' | xxd -r -p > ${outfile}_${stream}.${ext}
        done
```

## Solving Linear Equations using Matrices 
Again, from `*server.py*`, we get
> response = sum(x*y%p for x, y in zip(challenge, key))

So, finally with all the 40 files, we get 40 such equations (where i=range(40) )
> response[i] = sum(x*y%p for x, y in zip(challenge[i], key))

Solving linear equation of 40 unknowns can be done easily with Matrices.
[,reference](https://www.mathsisfun.com/algebra/systems-linear-equations-matrices.html)

Thus, the key will be 
```sage
challenge * key = response
key = challenge_inv * response 
```

## Solving for key using Sage
To calculate the InverseMod(p) of the Matrix `challenge`, **sage** provides an easy way to this:
>challenge_inv = Matrix(IntegerModRing(p),challenge).inverse()

Matrix multiplication of `challenge_inv` and `response` yeilds the `key`
> key = challenge_inv * response

```python
key = [151166356399959194245460055888166966126L,
 23349654305343746371904146512921179610L,
 303231127335861985008837572586617401477L,
 52564325979162295713031020943288299431L,
 318561098467762156502271721157519784045L,
 263049694618319332492436935081367988962L,
 151925705582116739255625584197651639678L,
 46319333286788790879399387215584902926L,
 144250191566113115015826218788418570765L,
 95097625879948609497612754022619234195L,
 40890527924981050968775993543458295905L,
 73015657936779070795829412187806965634L,
 17764129701686300306686689106838999642L,
 325835500394544926294581718484613749556L,
 71443020776832402486826429105359001130L,
 328905290970722092344104084599942510400L,
 246319993494260311894585740502008352891L,
 339251916682414225894494357646852524504L,
 270753355547506496805860877660621175158L,
 266604583518913012106937436764867155955L,
 132952188910249324219774647464400732439L,
 229485064954594431373138165566214808548L,
 273124499649767430591820642695664426994L,
 161206428662237066098654588615704724656L,
 191676246712534509807283243359699775780L,
 110791878778380133926865862999743362183L,
 121869512181659437298676494294916884080L,
 81324902884339942138294016318959955113L,
 219404824444265280645688236691554688702L,
 169041597038940530794876375975659802012L,
 131851490945732599957487956170326572223L,
 337190018815691236060142455413012785269L,
 215436829468576180414177636304832181536L,
 174614268507338543165725749934608091983L,
 316523955444804263394840392424504742312L,
 215434679427738924369625297037020081680L,
 103769840624100781721896803697739863413L,
 302813910848119681638497129402557822574L,
 104414047167186149419822776294661649936L,
 124689157029586638342169541932443340723L]
 ```

All we have to do next is, create the AES instance using the AES_key = **sha256(key)** 
```python
cipher = AES.new(
            sha256(' '.join(map(str, key)).encode('utf-8')).digest(),
            AES.MODE_CFB,
            b'\0'*16
        )
print cipher.decrypt(ct.decode('hex'))
```

## FLAG
>**35C3_G4uss_w0uld_b3_so_pr0ud_of_y0u_r1ght_n0w** 

## Complete Script
P.S you need to install sage to run the script 
>$sage exploit.sage

```python
from hashlib import sha256
from Crypto.Cipher import AES
import os

p = 340282366920938463463374607431768211297
challenge=[]    # the x values
response=[]     # the sum of s values
key=[]          # the y values
ct = "923fa1835d8dbdcd9f9b0e6658b24fce54512fbba71d7a0012c37d2c9dd094a6278593d8d9f7a4aa9fecb66042"

# to parse the values from pcap
os.system("./extract.sh") 
for i in range(40):
    f = open("out/out_"+str(i)+".txt").read().split('\n')
    challenge+=[map(int,f[0].split(' '))]
    response+=[int(f[1])]

#Calculate the modularInverse the Matrix challenge
challenge_inv = Matrix(IntegerModRing(p),challenge).inverse()

#Create the 40x1 Matrix for response
rl=[]
for i in response: rl+=[[i]]
response_mat = Matrix(rl)

#multiply  challenge_inv with response_mat to get a 40x1 matrix for y (key)
## Ay=B  implies  y= invA*B
y = challenge_inv*response_mat

key = eval(y.str().strip().replace("]\n[",","))
print key
cipher = AES.new(
            sha256(' '.join(map(str, key)).encode('utf-8')).digest(),
            AES.MODE_CFB,
            b'\0'*16
        )
print cipher.decrypt(ct.decode('hex'))
```
