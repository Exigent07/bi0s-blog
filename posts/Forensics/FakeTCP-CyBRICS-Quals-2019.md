---
title: FakeTCP - CyBRICS Quals 2019
date: 2019-07-25 23:12:11
author: f4lc0n
author_url: https://twitter.com/theevilsyn
categories:
  - Forensics
  - Network
tags:
  - CustomTCP
---
tl;dr
1. Open a raw socket.
2. Craft the outgoing packets with the byte order of S-PORT, D-PORT, SEQ, ACK reversed.
3. Establish the three way handshake in this fashion.
4. Send "GET_FLAG" to the server.

<!--more-->

**Challenge Points**: 277
**Challenge Solves**: 13
**Solved by**: [f4lc0n](https://twitter.com/theevilsyn)

[f4lc0n](https://twitter.com/theevilsyn) solved this challenge after the CTF ended.

## Challenge Description
Seems like this server doesn't respect network byte order.

It swaps byte order in some tcp header fields (sport, dport, ack, seq). Could you get the flag from it?

**209.250.241.50:51966**

## Initial Analysis
On trying to connect to the given service we receive the RST flags in incoming packets indicating the connection being reset.

![Wire1](conn-reset.png)
So, as told in the description we need to connect to the server by reversing the byte order of the sport, dport, ack, seq fields.

Now let's look into the ports section,
```python
import struct
struct.pack("<H",51966)  #returns '\xfe\xca'
int(0xfeca) #returns 65226
```
Given port is 51966. So reversing the byte-order for this number gives 65226
So, we need to send the packets to the port 65226.

## Crafting The Packets

### IP Headers for all the packets
![ip-info](ip-info.png)

Now let's craft the IP Headers for the packets

```python
 ip-header = '\x45\x00\x00\x28' # Version, IHL, Type of Service | Total Length
 ip-header += '\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
 ip-header += '\x40\x06\x00\x00'  # TTL, Protocol | Header Checksum (Here, we can take the checksum as null)
 ip-header += Source-IP-Address   # for example 127.0.0.1 becomes '\x7f\x00\x00\x01'
 ip-header += Destination-IP-Address
```
Now we have our ip-header for all the packets ready and let's craft the packets for the TCP three-way handshake.

### TCP Headers for the SYN packet

![handshake](tcp-headers.png)
![handshake](tcp-3-way.png)

So for the SYN packet we can take the SEQ number anything, for instance let's take '0'  
#### Crafting the SYN packet
```python
tcp-header  = '\x39\x30\xfe\xca' # Source Port | Destination Port
tcp-header += '\x00\x00\x00\x00' # Sequence Number
tcp-header += '\x00\x00\x00\x00' # Acknowledgement Number
tcp-header += '\x50\x02\x71\x10' # Data Offset, Reserved, SYN-Flag-Set(0x02) | Window Size
tcp-header += '\x00\x00\x00\x00' # Checksum | Urgent Pointer
```
Now let's send the syn packet to the server and check the response,

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

packet = ip-header + tcp-header

s.sendto(packet, ('209.250.241.50', 65226))
```
Let's look at this process in wireshark,
![syn-ack](syn-ack.png)
Yayy!! now we've received the ACK packet back with the details of the next packets SEQ & ACK numbers.


#### Crafting the ACK packet
Now let's craft the tcp header for ACK packet
The SEQ and ACK numbers are based on the SYN-ACK packet from the server.

```python
ack-header  = '\x39\x30\xfe\xca' # Source Port | Destination Port
ack-header += '\x01\x00\x00\x00' # Sequence Number
ack-header += '\x01\x00\x00\x00' # Acknowledgement Number
ack-header += '\x50\x10\x71\x10' # Data Offset, Reserved, ACK-Flag-Set(0x10) | Window Size
ack-header += '\x00\x00\x00\x00' # Checksum | Urgent Pointer
```
The SEQ and ACK numbers in this packet are dependent on the [SYN, ACK] packet from the server.
Now lets send the ACK packet and check the response
![final-ack](final-ack.png)
We've received a response saying "Send me 'GET_FLAG' and I give your flag"

#### Crafting the PSH-ACK packet

In the last [PSH, ACK] form the server, the length of the data is 39. So we need to add byte-reversed 39 to the last packets SEQ number. Now this number is the ACK number for the next [PSH, ACK] packet to the server.

```python
tcp-header  = '\x39\x30\xfe\xca' # Source Port | Destination Port
tcp-header += '\x01\x00\x00\x00' # Sequence Number
tcp-header += '\x28\x00\x00\x00' # Acknowledgement Number
tcp-header += '\x50\x18\x71\x10' # Data Offset, Reserved, PSH,ACK-Flags-Set | Window Size
tcp-header += '\x09\x32\x00\x00' # Checksum | Urgent Pointer
tcp-header += 'GET_FLAG'         # TCP Payload
```
After sending this packet we will get the flag in the incoming [PSH, ACK] packet.
![flag](flag.png)

## Summing Up
Here's the final exploit script,
```python
import time
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


class syn:
    ip_hdr = "\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06\x00\x00\xac\x1f\x23\x13\xd1\xfa\xf1\x32"
    tcp_hdr = "\x39\x30\xfe\xca\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x00\x00\x00\x00\x00\x00"

class ack:
    ip_hdr = "\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06\x00\x00\xac\x1f\x23\x13\xd1\xfa\xf1\x32"
    tcp_hdr = "\x39\x30\xfe\xca\x01\x00\x00\x00\x01\x00\x00\x00\x50\x10\x00\x00\x00\x00\x00\x00"

class pshack:
    ip_hdr = "\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06\x00\x00\xac\x1f\x23\x13\xd1\xfa\xf1\x32"
    tcp_hdr = "\x39\x30\xfe\xca\x01\x00\x00\x00\x28\x00\x00\x00\x50\x18\x00\x00\x00\x00\x00\x00"

syn_packet = syn.ip_hdr + syn.tcp_hdr
ack_packet = ack.ip_hdr + ack.tcp_hdr
psh_packet = pshack.ip_hdr + pshack.tcp_hdr + 'GET_FLAG'


s.sendto(syn_packet, ('209.250.241.50', 65226))
time.sleep(2)
s.sendto(ack_packet, ('209.250.241.50', 65226))
time.sleep(2)
s.sendto(psh_packet, ('209.250.241.50', 65226))
```
Run this script and we'll get the flag in the incoming [PSH, ACK] packet.

**Flag**: `cybrics{n0w_I_kn0w_how_cr@ft_tcp}`

## References
1. https://en.wikipedia.org/wiki/IPv4
2. https://en.wikipedia.org/wiki/Transmission_Control_Protocol
3. https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
