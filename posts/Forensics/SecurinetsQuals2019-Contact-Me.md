---
title: SecurinetsQuals2019-Contact_Me
date: 2019-08-24 15:39:20
author: stuxn3t
author_url: https://twitter.com/_abhiramkumar
categories:
  - Forensics
  - Memory
tags:
  - MacOS Memory Analysis
---

tl;dr

1. Analysis of memory dump using Volatility framework.
2. Using mac_contacts plugin to get relevant data.
3. Base64 decode to get flag.

**Solved by**: [stuxn3t](https://twitter.com/_abhiramkumar)

<!--more-->

## Challege description

People think it's hard to stay without a phone, but I don't! My computer has everything a smartphone has like browsers, notes, calendars, and a lot more.

You can download the challenge file here: [Mega Link](https://mega.nz/#!L6QVyA5T!GYhexxkkraKvcV6Q6jhf08-xw0x_1X9Nzz9hAF8PuwE)

## Challenge solution

So the first question that comes to mind is how did I find out that it was a MAC image?
Simple. the **imageinfo** plugin did not work.

Now let us get the profile of the memory dump.

```sh
$ python vol.py -f ../contact_me mac_get_profile
```

![profile](profile.png)

Okay, so the profile is MacSierra_10_12_6_16G23ax64.

The reason I call this challenge very easy since the name of the challenge hints out the plugin that I must be using to probably get the flag & one such relevant plugin that I found was the mac_contacts plugin.

Let us use that plugin.

```
$ python vol.py --profile=MacSierra_10_12_6_16G23ax64 -f ../contact_me mac_contacts
```
![mac_contacts](mac_contacts.png)

If you are able to see, I have highlighted a certain text which looks like a base64 string.

![flag](flag.png)

Voila! We got the flag.

**FLAG**: `securinets{31012e16c3e5dfa7e673612d7d075715}`

### References

1. https://github.com/volatilityfoundation/volatility/wiki/Mac-Command-Reference
