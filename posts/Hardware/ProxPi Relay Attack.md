---
title: ProxPi Relay Attack 
date: 2021-02-07 
author: bi0sHardware
author_url: https://bi0s.in/hardware.html
tags:
  - Relay Attacks
  - PKES systems
  - Smart Cars 
categories:
  - Hardware
---

**tl;dr**

In this post, we are going to share our research into PKES systems and the possibility of Relay attacks on such systems. 

<!--more-->

**Relay attack** also called the **Wormhole Attack** or the **Two Thief Attack** is one of the most robust attack vectors when it comes to RF communication systems. 

> A relay attack against two legitimate parties A and B is one whereby a man-in-the-middle C forwards A’s messages to B and/or B’s messages to A, unbeknown to them. In doing so, C wishes to obtain a facility meant for A and granted by B or vice-versa. 

We here consider the case of a PKES (Passive Keyless Entry & Start) system in today's "Smart Cars". 

### PKES systems

PKES systems are interrogator first systems - which means First the Car sends a **challenge** and asks the Key fob for the **solution**. The Key fob replys to the car's message with the challenge solution if it is in the coverage area of the signal and it notices a particular pattern in the message. The Car sends the challenge in the LF (Low Frequency- 125KHz) channel so the range where it can be received is only a few feet from the car. 

![PKES_system](PKES_system.png) 

There could be 2 configurations **a)** and **b)** as shown above. **a)** has a separate set of Wake up and ACK messages being sent and received between the car and Key fob. Only after receiving the ACK messages the car sends a challenge looking for a solution. 

![Message_order](message_order.png)

### Relay Attacks

The objective of a Relay attack is to be able to operate the car even when the Key fob is not in the LF Signal's coverage area. We achieve this objective by setting up a relay in between the Car and the Key fob. A general overview of the attack could look somewhat like this :

![PKES_relay_attack](PKES_Relay_attack.png)

Here the relay consists of 2 thieves with their RF hacking gear capable of receiving and transmitting both LF and HF signals. Thief 1 receives the challenge from the Car, which it forwards to Thief 2. Thief 2 plays the signal to the Key fob. The Key fob checks for the pattern and replies with the solution to the challenge . Thief 2 captures this solution and passes it on to Thief 1. Thief 1 then plays the signal to Car.  And Hurrah !! the car unlocks. 

> Relay attacks are hard to detect and deter, as they subvert all conventional cryptographic mechanisms potentially employed in the protocols: C only forwards the messages, and does not need to break the cryptography that is used. This is even more acute in the case of contact less applications: user A simply brings a token (e.g. a card or phone) within range of a reader B, and the protocol starts automatically, with no consent or input by the person who is getting the privilege. Thus, a relay attack can be mounted without hindrance.

### The ProxPi Relay Attack

![ProxPi](ProxPi_relay_attack.png)

The thief's system is connected to a Proxmark which is used to receive and transmit signals from the Car. The Proxmark can save captured signals as `.pm3` files. As the laptop is synced with the Raspberry Pi, the captured files will also be available on the Pi. The Raspberry Pi is connected to another Proxmark which is used to send and receive signals from the Key fob .  

### Implementing the ProxPi on a Toyota Innova Crysta

Researchers at our lab were successful in implementing the attack on a Toyota Innova Crysta (obviously with the consent of the user). In this case the car sends the signal once a button is pressed on the Car Handle. Rest of the attack is exactly the same as described above. We first tried the Relay attack with the help of a HackRF, but were unable to implement the attack. However the Proxmark came to our rescue because of its amazing feature that enables us to save captured signals in the `.pm3` format. 

We keep this short and precise so as not to cause damage to the vendor and at the same time clearly articulate our research. 

### References:

1. Rodriguez, J., 2016. Long-range RFID emitter antennas for passive keyless entry systems. [online] eeNews Automotive. Available at: [https://www.eenewsautomotive.com/news/long-range-rfid-emitter-antennas-passive-keyless-entry-systems](https://www.eenewsautomotive.com/news/long-range-rfid-emitter-antennas-passive-keyless-entry-systems) [Accessed 2 February 2021].
2. [Nxp.com](http://nxp.com/). 2012. [online] Available at: [https://www.nxp.com/docs/en/brochure/75017275.pdf](https://www.nxp.com/docs/en/brochure/75017275.pdf) [Accessed 2 February 2021].
3. Francillon, A., Danev, B. and Capkun, S., 2010. [online] [eprint.iacr.org](http://eprint.iacr.org/). Available at: [https://eprint.iacr.org/2010/332.pdf](https://eprint.iacr.org/2010/332.pdf) [Accessed 2 February 2021]. 
4. Avoine G., Boureanu I., Gérault D., Hancke G.P., Lafourcade P., Onete C. (2021) From Relay Attacks to Distance-Bounding Protocols. In: Avoine G., Hernandez-Castro J. (eds) Security of Ubiquitous Computing Systems. Springer, Cham. [https://doi.org/10.1007/978-3-030-10591-4_7](https://doi.org/10.1007/978-3-030-10591-4_7)