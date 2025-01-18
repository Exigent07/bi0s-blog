---
title: Falcon Badge 
date: 2020-01-21 13:45:38
author: securehardware
author_url: https://securehardware.in
tags:
  - Badge Life
  - IoT
  - Hardware Badge
categories:
  - Hardware
---
In this blog, we are going to share the experience of creating our first electronic badge.
<!--more-->
## InCTF 10th Edition
![](https://i.ibb.co/VgTRQHB/photo-2020-01-21-10-44-10.jpg)

This year's [InCTF](https://inctf.in/) was very special for the [hardware team](https://securehardware.in/) @[bi0s](https://bi0s.in/) as we released an electronic badge similar to conferences internationally. 

This year's theme was inspired by Star Wars, and being huge fans of Han Solo and Chewbacca, the badge design inspiration came from the famous Millenium Falcon.

We wanted more students to get started with hardware. Thus we created the badge with a small quest on it. The quest focused on IoT Security so that students would get a taste of security as well. 

We wanted the badge to be a fun and engaging activity, so we ported some games into it, not just to be played on the badge, but physically as well. 

The games we ported into the badge were the:
* **Conway's [Game of Life](https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life)** [0]
    * *The game gets the input from the LDR connected, hence spawns a new generation every time*
* **Asteroids** arcade game [1]
    * *Similar to the original game with dodging the asteroids, and firing lasers.*
* **Millenium Canon**
    * *If you were able to unlock the lasers, you can shoot other badge's LDR, to *attack* thrice, that would put the badge in a *damaged* mode. Of course, you'd have to wait to recover from that for a couple of minutes.* 
i
### Hardware
![](https://i.ibb.co/48Vmntg/photo-2020-01-21-10-39-36.jpg)

* NodeMCU Development Board
* 74HC595 Shift Register
* LDR Sensor
* Laser Pointer (LED with a lens)
* OLED 128x32 Display
* 2 Pushbuttons
* 16 LEDs 
* 4 AA batteries 

### Design 
![](https://i.ibb.co/2cJNDyW/photo-2020-01-21-10-42-35.jpg)

With IoT in mind, we decided to select one of the most commonly used microcontrollers, the [ESP8266](https://www.espressif.com/en/products/hardware/esp8266ex/overview). It is one of the best microcontrollers to get started with development and testing in the IoT field. 
What's a hardware badge without a display? So, we went for an OLED display, just because it upgrades its coolness, and is less costly than expected ;) 
And just to make the badge worth hacking and eye-catching, we arranged the LEDs in an array and used the shift register to control. The ESP8266 is a bit less on pins.
We added the LDR sensor and the Laser pin to support the physical game that we had designed.
To make game controls comfortable we used 2 push buttons [fewer pins :(]. Next year hopefully we'll have more of those buttons ;).
Finally, to power this board up, we selected the commonly available AA batteries which can be easily replaced when dead. 

### Firmware
The firmware for the board was written using the Arduino SDK, due to open-source libraries for various components and ease of configuration. The badge had featured different firmwares for different purposes. 
There were 5 firmwares in total:
* **Initial**
    * The basic initial firmware everyone's badge was loaded with.
* **Serial-Exploitation**
    * Firmware that was designed to teach you serial exploitation.
* **Falcon-Fire**
    * A version of the 80s *Asteroid* Game.
* **Game-of-Life**
    * A version of *Conway's Game of Life* on Falcon.
* **Final-Unlocked**
    * Firmware with unlocked LED control and defense against laser attacks.

As mentioned before, as we wanted the badge to be an IoT device. We connected the badge to an open WiFi network in our campus, which was available anywhere within the campus. To make the firmware flashing as easy as possible, we had designed a custom OTA page for the users to update their badges. The badges were assigned static IPs and were secured by a username and password. 
The badge displayed the name, ID and the username. The password and other details were stored on the SPIFFS to avoid hard coding credentials in the firmware. Imagine creating 70x5=350 firmwares! EEPROM/SPIFFS is the better way. :)

The source code and the files will be available on [Github](https://github.com/securehardware-bi0s/Falcon-Badge)

### Production
![](https://i.ibb.co/Mgw6ZR2/photo-2020-01-21-10-41-33.jpg)

We designed the board to be through-hole, were we hand-assembled all the boards. We had ordered the components through various wholesale-dealers. The PCB was printed at [PCBPower](https://www.pcbpower.com/) based in Gujarat. 
The experience of creating badges turned out to be an internal workshop for everyone to learn soldering at bi0s. 

#### Sources:

[0]-https://raw.githubusercontent.com/DrMikeG/Conway/master/GameOfLife/GameOfLife.ino

[1]-https://github.com/pauls-3d-things/arduino-space-hopper

