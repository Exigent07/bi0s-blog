---
title: EV3 Arm - HITCON Quals 2019
date: 2019-10-16 14:11:07
author: f4lc0n
author_url: https://twitter.com/_f41c0n
categories:
  - Reversing
  - Automation

tags:
  - EV3 Robot
  - HITCON
  - PIL
  - RBF
---
tl;dr
1. Decompile the given RBF file
2. Extract the low level instructions.
3. Write a script to plot the lines.

<!--more-->
**Challenge Points**: 221
**Challenge Solves**: 44
**Solved by**: [f4lc0n](https://twitter.com/_f41c0n), [g4rud4](twitter.com/NihithNihi),[stuxn3t](twitter.com/_abhiramkumar)

## Initial Analysis

This challenge looks similar to last year's EV3 challenge. But this time a compiled project was given instead of network logs.
So, after a couple of minutes surfing the internet about decompiling ev3 project files, I found this website which actually retrieves the low level instructions sent to the MindStorm Robot. After uploading the given rbf file to the website it listed out all the decompiled instructions in the file.

Some of the instructions looked like this
```bash
[f4lc0n@arch-linux ~]$ cat operations.txt | head

port_motor: B | rotations: 35 | speed: 15
port_motor: A | rotations: 720 | speed: 75
port_motor: C | rotations: 2.5 | speed: 70
port_motor: A | rotations: 540 | speed: -75
port_motor: B | rotations: 35 | speed: -15
port_motor: C | rotations: 2 | speed: 70
port_motor: A | rotations: 240 | speed: 75
port_motor: C | rotations: 2 | speed: -70
```   


## Analyzing the instructions

So, basically after sometime of struggling with the instructions we understood that,

 1. Port Motor B is responsible for the robot's arm. It basically determines whether the marker should be touching the paper while moving.
     - **Example**: ```port_motor: B | rotations: 35 | speed: -15```
     - This instruction is responsible for the robot's arm to move towards the ground, making the pen touch the ground.
 2. Port Motor A is responsible for the horizontal movement of the robot's arm.
     - **Example**: ```port_motor: A | rotations: 720 | speed: 75```
     - With this instruction the robot's arm moves for 720 units in the right direction.
 3. Port Motor C is responsible for moving the robot forward and backward.
     - **Example**: ```port_motor: C | rotations: 2.5 | speed: 70```
     - This instruction moves the robot backward for 2.5 units(The measurement here is cycles corresponding to Motor C)

## Scripting Part
Initially I thought of printing the characters to STDOUT. But that would make things more complex. So, I decided to use PIL to plot the lines.

Now, let's write a function that will draw a line on image.

```python
def drawLine(x1,y1,x2,y2):
    global im
    draw = ImageDraw.Draw(im)
    draw.line((x1,y1, x2,y2), fill=255)
    draw.line((x1+1,y1+1, x2+1,y2+1), fill=255)
    draw.line((x1-1,y1-1, x2-1,y2-1), fill=255)
```

So, now we will write a check function for drawing the lines according to the instructions.

```python
def check(arg):
    motor = f[arg].split('motor: ')[1][:1]
    if motor == 'A':
        direction = f[arg].split('speed: ')[1]
        length = int(f[arg].split('rotations: ')[1].split(' | ')[0])/10
        if int(direction) > 0:
            newCoord = (coords[0]+length,coords[1])
        else:
            newCoord = (coords[0]-length,coords[1])
        if OnPaper is True:
            drawLine(coords[0],coords[1],newCoord[0],newCoord[1])
            coords = newCoord
        else:
            coords = newCoord
    elif motor == 'B':
        if int(f[arg].split('speed: ')[1]) < 0:
            OnPaper = True
        else:
            OnPaper = False
    else:
        if int(f[arg].split('speed: ')[1]) < 0:
            direction = -1
        else:
            direction = +1
        length = 24*float((f[arg].split('rotations: ')[1].split(' | ')[0]))
        if direction > 0:
            newCoord = (coords[0],coords[1]+length)
        else:
            newCoord = (coords[0],coords[1]-length)
        if OnPaper is True:
            drawLine(coords[0],coords[1],newCoord[0],newCoord[1])
            coords = newCoord
        else:
            coords = newCoord
```

Summing up with the two functions, the final script is,

```python
#!/usr/bin/env python2
from PIL import Image, ImageDraw

def check(arg):
    global OnPaper, f, im, coords
    motor = f[arg].split('motor: ')[1][:1]
    if motor == 'A':
        direction = f[arg].split('speed: ')[1]
        length = int(f[arg].split('rotations: ')[1].split(' | ')[0])/10
        if int(direction) > 0:
            newCoord = (coords[0]+length,coords[1])
        else:
            newCoord = (coords[0]-length,coords[1])
        if OnPaper is True:
            drawLine(coords[0],coords[1],newCoord[0],newCoord[1])
            coords = newCoord
        else:
            coords = newCoord
    elif motor == 'B':
        if int(f[arg].split('speed: ')[1]) < 0:
            OnPaper = True
        else:
            OnPaper = False
    else:
        if int(f[arg].split('speed: ')[1]) < 0:
            direction = -1
        else:
            direction = +1
        length = 24*float((f[arg].split('rotations: ')[1].split(' | ')[0]))
        if direction > 0:
            newCoord = (coords[0],coords[1]+length)
        else:
            newCoord = (coords[0],coords[1]-length)
        if OnPaper is True:
            drawLine(coords[0],coords[1],newCoord[0],newCoord[1])
            coords = newCoord
        else:
            coords = newCoord

def drawLine(x1,y1,x2,y2):
    global im
    draw = ImageDraw.Draw(im)
    draw.line((x1,y1, x2,y2), fill=255)
    draw.line((x1+1,y1+1, x2+1,y2+1), fill=255)
    draw.line((x1-1,y1-1, x2-1,y2-1), fill=255)

def main():
    global f,coords, OnPaper,im
    f=open('ops.txt').read().split('\n')
    coords = (130,10)
    OnPaper=False
    im = Image.new('RGBA', (260, 3000), (255,255,255))
    for i in range(len(f)):
        check(i)
    im.save('flag.png','PNG')

if __name__=='__main__':
    main()
```


## Flag

![flag](flag.jpg)
After correcting a few characters, we get the flag
**Flag**: `hitcon{why_not_just_use_the_printer}`

## References
1. http://ev3treevis.azurewebsites.net/
2. https://pillow.readthedocs.io/en/3.1.x/reference/ImageDraw.html
