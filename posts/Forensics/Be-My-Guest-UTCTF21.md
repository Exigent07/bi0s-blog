---
title: Be My Guest - UTCTF21
date: 2021-03-15 10:24:47
author: g4rud4
author_url: https://twitter.com/NihithNihi
categories:
 - Forensics
 - Network
tags:
 - UTCTF
 - SMB
---

**tl;dr**

+ Retrieving the flag from Samba SMB workgroup guest.
 

<!--more-->

**Challenge Points**: 861
**No. of solves**: 119
**Solved by**: [g4rud4](https://twitter.com/NihithNihi)

## Description

Can you share some secrets about this box?

nmap is allowed for this problem. However, you may only target `misc.utctf.live ports 8881 & 8882`. Thank you.

## Initial Analysis

Let us do a quick nmap and see what are the services open on the given ports.

```bash
$ nmap -sC -sV -p 8881-8882 misc.utctf.live
Starting Nmap 7.70 ( https://nmap.org ) at 2021-03-15 06:27 UTC
Nmap scan report for misc.utctf.live (3.236.87.2)
Host is up (0.030s latency).
rDNS record for 3.236.87.2: ec2-3-236-87-2.compute-1.amazonaws.com

PORT     STATE SERVICE     VERSION
8881/tcp open  netbios-ssn Samba smbd 4.6.2
8882/tcp open  netbios-ssn Samba smbd 4.6.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.70 seconds
```

So we can see that both the ports are open and running on `Samba SMB`. As it is running on SMB lets retrieve the workgroup for the SMB server.

## Retrieving the SMB Workgroup

We can use the tool `smbclient` for intracting with this given SMB(Server Message Block) server, and its is somewhat similar to FTP. SMB servers will be having a workgroup let us retrieve it.

```bash
$ smbclient -L misc.utctf.live -p 8881
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\g4rud4's password:

        Sharename       Type      Comment
        ---------       ----      -------
        guest           Disk      Look, but don't touch please.
        IPC$            IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
```

We can see a workgroup/sharename guest. So lets connect to that and see what all files present in the guest.

## Retrieving the Flag

As we already got the workgroup, we can connect to `guest` workgroup using smbclient. Here is an example on how to connect to the smb server using smbclient.

```bash
$ smbclient \\\\<IP>\\<Workgroup>
```

As we know the IP as `misc.utctf.live` and workgroup as `guest`, let us connect to it and see what all files present in it.

```bash
smbclient \\\\misc.utctf.live\\guest -p 8881
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\g4rud4's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 12 12:15:26 2021
  ..                                  D        0  Sat Mar 13 04:14:53 2021
  flag.txt                            N       30  Fri Mar 12 12:15:26 2021

                8065444 blocks of size 1024. 3349624 blocks available
```

As we can see `flag.txt` is present on the guest workgroup, we can do `more flag.txt` and retrieve the flag.

## Flag

utflag{gu3st_p4ss_4_3v3ry0n3}