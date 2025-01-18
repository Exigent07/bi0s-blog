---
title: Miz - InCTF Internationals 2021
tags:
  - Maze
  - Reversing 
  - Linux
  - Rust
  - InCTFi
categories:
  - Reversing 
  - Linux
date: 2021-8-19 00:00:00 
author: AmunRha 
author_url: https://twitter.com/AmunRha
author2: Freakston
author2_url: https://twitter.com/Freakst0n
---

tl;dr

- This is a fairly simple Maze challenge
- Challenge is written in rust

<!---more--->    

**Challenge author**: [Freakston](https://twitter.com/freakst0n), [silverf3lix](https://twitter.com/silverf3lix)  

## Descrption

> Senpai plis find me a way.

## Solution

This is a fairly simple maze challenge implemented in rust.

At the start of the main function of the challenge miz we can see there is a some sort of a initialization going on at a function named `miz::bacharu::Kikai::new::h3a113b790cc2bb5c`

{% asset_img Untitled.png Untitled.png %}    

{% asset_img Untitled1.png Untitled1.png %}    

We can see from here than this function takes care of initializing the maze. We can extract the maze bytes either directly from here or during runtime, which ever is preferred.

Moving forward we can see that the function is also getting our input, and sending it over to another function `miz::bacharu::Kikai::run::h14398f1fc265e61e`

{% asset_img Untitled2.png Untitled2.png %}    

The function `miz::bacharu::Kikai::run` takes care of the maze logic, the up, left, down and right.

- Case "h"

{% asset_img Untitled3.png Untitled3.png %}    

We can see that the case "h" takes care of going left, which is by subtracting 1 from the y coordinate

- Case "j"

{% asset_img Untitled4.png Untitled4.png %}    

Similarly, case "j" is to go up, it does this by subtracting 1 from the x coordinate.

- Case "k"

{% asset_img Untitled5.png Untitled5.png %}    

Case "k" takes care of going down the maze, it adds 1 to the x coordinate

- Case "l"

{% asset_img Untitled6.png Untitled6.png %}    

This case takes care of going right in the maze, it does so by adding 1 to the y coordinate

From this function we can also get the bounds of the maze which is 24 x 25, where there are 25 rows and 24 columns.

And the properties of the maze are,

- "0" ⇒ Path to traverse
- "1" ⇒ Walls
- "2" ⇒ Final win position

We can also see that this is the function `miz::bacharu::Kikai::Furagu_o_toru::hd3e3c2fb2ccf3552` is the win function, and this is called when we traverse till we reach the number 2 in the maze.

{% asset_img Untitled7.png Untitled7.png %}    

Constructing the maze should be easy since we have its bounds,

```python
miz =       [[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
            ,[1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1]
            ,[1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1,0,1]
            ,[1,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,0,1,1,1,1,1]
            ,[1,0,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,1]
            ,[1,0,1,1,1,1,1,0,1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1]
            ,[1,0,0,0,1,0,1,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,1,1,0,1,0,1,0,1,1,1,1,1,1,1,0,1,1,1,0,1,0,1,1,1]
            ,[1,0,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1]
            ,[1,0,1,0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1]
            ,[1,0,1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,0,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1]
            ,[1,0,0,0,1,0,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1]
            ,[1,0,1,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,0,1]
            ,[1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,1,0,1,0,1]
            ,[1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1]
            ,[1,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,1,0,1,0,1]
            ,[1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1]]
```

The start position can be retrieved while debugging and it is (0, 13). The end position is 

(24, 19)

## Final script

To solve this maze we can make use of the python library `mazelib` 

Here is the script,

```python
from mazelib import Maze
from mazelib.solve.BacktrackingSolver import BacktrackingSolver
import numpy as np
m = Maze()
m.solver = BacktrackingSolver()
miz =       [[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
            ,[1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1]
            ,[1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1,0,1]
            ,[1,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,0,1,1,1,1,1]
            ,[1,0,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,1]
            ,[1,0,1,1,1,1,1,0,1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1]
            ,[1,0,0,0,1,0,1,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,1,1,0,1,0,1,0,1,1,1,1,1,1,1,0,1,1,1,0,1,0,1,1,1]
            ,[1,0,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1]
            ,[1,0,1,0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1]
            ,[1,0,1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1]
            ,[1,0,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1]
            ,[1,0,0,0,1,0,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1]
            ,[1,0,1,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,0,1]
            ,[1,0,1,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,1,0,1,0,1]
            ,[1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1]
            ,[1,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,1,0,1,0,1]
            ,[1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1]
            ,[1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,1]
            ,[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]]
m.grid = np.array(miz)
m.start = (0,13)
m.end = (24,19)
m.solve()
sol = m.solutions[0]

for i in range(len(sol)-1):
    x = sol[i][0]
    y = sol[i][1]
    xn = sol[i+1][0]
    yn = sol[i+1][1]
    #print(f"x -> {x} y- >{y}  xn -> {xn} yn -> {yn}")
    if (x - xn) > 0:
        print("j",end="")
    elif (y - yn) > 0:
        print("h",end="")
    elif (yn - y) > 0:
        print("l",end="")
    elif (xn - x) > 0:
        print("k",end="")
```

The final moves to be sent as input comes out to be,

`llkkhhhhkkkkhhhhjjhhhhhhkkllkkkkkkhhkkllkklljjlllllljjhhjjllllllkklljjllkklljjllkkkkhhhhkkkkllkkkkhh`

Flag: `inctf{mizes_are_fun_or_get}`