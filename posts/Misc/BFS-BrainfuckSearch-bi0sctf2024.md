---
title: BFS - Brainf*ck Search - bi0sCTF 2024
date: 2024-02-26 18:28:42
author: R0R1
author_url: https://twitter.com/adudewhodr23891
categories:
  - Misc
tags:
  - bi0sctf
---

**tl;dr**
+ Using brainf*ck to search for flag bytes within a huge tape
+ 3 levels with varying constraints to leak flag
+ Intended as a code golfing challenge

<!--more-->

**Challenge points**: 818  
**No. of solves**: 19  
**Author**: [R0R1](https://twitter.com/doesntexist) <!--Change user-->

## Challenge in Brief

The challenge has a python brainf\*ck interpreter which runs brainf*ck code which you give.

I shall briefly explain the premise of the following levels - 

- LEVEL 1
> Somehow bring the flag byte to the position where you are initially placed at to view that byte

- LEVEL 2
> Mark the bytes at the displayed indexes within the tape, in the order that is specified

- LEVEL 3
> You don't have anything within the tape visible other than the data pointer, so use that to leak the flag by moving it within the initial 10 byte frame.Where the dp location is controlled the byte of the flag.

This is the general setup for the challenge.

## Writeup
The challenge was a completely remote nc-style challenge, thus I shall be exploring the different solutions for each levels which were present in the remote instance of the challenge.

### Unintended
> code-golfing without an actual length check

The following challenge was supposed to be a code golfing challenge where you write optimised brainf\*ck code to solve the following challenges. 

But the code I had used in remote was not having a length check. Which was kind of a disappointment.
This made the challenge extremely easy to solve, especially the first two levels within the challenge. 

The `first level` ended up being pretty easy to solve for most contestants as it required only spamming the '>' instruction as much number of times as the index where the flag byte is dropped at.

The `second level` similarly had a solution where you could end up spamming '>' and '<' to go as far as you wanted and mark the bytes thus gaining you that part of the flag too.

The `Third level` for the challenge was basically doing the same thing again to bring the flag byte to the initial dp position after which you can subtract from it a fixed number making it possible for you to bruteforce the ascii lowercase, special characters, ascii uppercase separate to each other and finally make the flag. 

### Intended Solve 

This is the solve script that I had initially come up with for the challenge. I was planning on a revenge challenge with the fixed source but the bulk of challenges made it quite impossible to do so. Thus I shall be discussing the intended solve for the challenge.

The approach for all the challenges involved finding the first non-zero byte. This would essentially be the flag byte if you are moving the right direction. Using this you are able to get to the flag despite where it is currently at in the tape. All of these codes can be easily understood by experimenting it with the test brainf*ck driver programme that was given alongside it.

The final solve for level 3 of the challenge relies on using a division operator to do a division by 10 on the flag byte due to restriction in the size to get the dp to land within the frame. 

```bf
----------------------------------------------------------------
    LEVEL - 1
----------------------------------------------------------------
PART 1 
TRAVELLING TO NON-ZERO BYTE 

The following algorithm can be applied to travel to the first non-zero byte.   
Which is what I used to get to the flag byte in a zeroed out tape

1 -[+[<+<]>-]>             [OPTIMIZED TO 12 BYTES]

PART 2
TRANSPORTING A BYTE CONSIDERING ANCHOR POINTS

I place an anchor of 0xff to return to so that I can get back to the  
initial dp to fetch the flag byte back

2 [<[<<]>[<+>-]<]          [OPTIMIZED TO 15 BYTES]

The only change in the code is for the directions that have to be 
flipped sometimes as the byte can be in the left or right

COMPLETE SOLUTION --
<->-[+[<+<]>-]>[<[<<]>[<+>-]<]

Alt-approach to solving the same challenge through lvl3's method 

ATTEMPT 3 - LEAK USING DP POSITION
<->-[+[<+<]>-]>-[[<+>-]<-]<

COMBINING THESE TWO YOU CAN GET THE SOLUTION FOR LEVEL 1

----------------------------------------------------------------
    LEVEL - 2
----------------------------------------------------------------
TRAVEL TO FIRST NON-ZERO BYTE
1 -[+[<+<]>-]>
MARK THE BYTE AND DECREMENT IT UNTIL ZERO
2 .[-]

Using the following logic and mapping out a sorted list of entries 
you can do a sled-to-next-byte approach to get a solve.

----------------------------------------------------------------
    LEVEL - 3
----------------------------------------------------------------
TRAVEL TO THE FIRST NON ZERO BYTE
1 -[+[<+<]>-]>
BRING THE BYTE BACK TO DP -5
2 [<[<<]>[<+>-]<]

DIVIDE IT BY N 
3 >[<[<+>-]<[->>[<+>>-<-]>[<+<<<]>]>>>>+<<]>>-<<<<<<<[-]<+ 

The following code gets you the dividend and remainder which you can use to move the dp.
The input and output states of the code are of the following format : 
_____________________________________________________________
INITIAL STATES
=============================================================
|  0  | DATA/BYTE     |  DIVIDEND  | FLAG |  DIV  |    0
-------------------------------------------------------------

Runs the division code --
_____________________________________________________________
FINAL STATE
=============================================================
|  0  |(BYTE-REMANDER)|  DIVIDEND  | FLAG |   0   | QUOTIENT
-------------------------------------------------------------

MOVE THE DP AS MUCH AS THE RESULT 
4 [[->+<]>-]

This would be the logic for the third level : 
bring the flag byte to just before index and do a division operation to get both  
the remainder and the divisor which you can use to move the dp and   
leak the whole flag within 2 runs of the code.  

```

And this would be the final solution to the challenge. Where the only other thing to do would be scripting it. A cool thing is how the following way of solving takes much lesser operation time than the other linear '>' instruction approaches. I think the following is due to the reduction in the time taken to send our code to the programme.

## Conclusion
I hope everyone who solved this challenge had some amount of fun from the challenge. The following challenge took me a while to develop. I strongly feel that brainf*ck is a nice programming exercise and I had a lot of fun making the challenge, **despite the unintends**. Hope everyone had fun solving it too.    
We shall meet again in bi0sctf 2025 
> ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>+++++++++.------------.++++++++++++++++++++++++.-----------------------.+++.<<++.>>++++++++++++++++++.--------------.+++++++++++.------------.<<.>>-------.+++++++++++++.+.+++++.------------.---.+++++++++++++.<<.>>----------------.++++++++++++++++.-----------------.++++++++.+++++.--------.<<++++++++++.>>---.++++++++.<<----------.>>--------.+++++.-------.+++++++++++..-------.+++++++++.-------.--.<<.

## Solve
- You can find the whole script [here](https://gist.github.com/Rogitt/47a6d009e02421b7ad6b11773b3b51a6)
- You can find the source for the challenge [here](https://gist.github.com/Rogitt/c59a768bb4c7fcfb1a3dfd9a0daab530)

## Background
- This is where I got the inspiration to start this challenge from [mixtela](https://www.youtube.com/watch?v=Cg98wh2-lOw) and [Truttle1](https://www.youtube.com/watch?v=qK0vmuQib8Y)
