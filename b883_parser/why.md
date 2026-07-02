# Why is the first byte of every record contrained to a set of values?

The reason you are only seeing slots **3, 4, 5** and **13, 14, 15** (hex `03`, `04`, `05`, `0D`, `0E`, `0F`) is due to the physical **Time Division Duplex (TDD)** configuration of the 5G cell the device was connected to.

Here is exactly why the MAC layer is mathematically constrained to only schedule uplink on those specific slots.

### The 5G TDD Frame Structure
In 5G NR, uplink (UL) and downlink (DL) share the same frequency band but take turns broadcasting over time. The network dictates a strict repeating pattern of Downlink, Uplink, and Special (flexible) slots.
At a **30kHz Subcarrier Spacing (SCS)**, a standard 10-millisecond radio frame is divided into exactly **20 slots** (numbered 0 through 19).
The log you provided is captured from a network using a very common 5ms TDD periodicity pattern. Because the pattern is 5ms long, it repeats exactly twice within every 10ms frame.
The pattern looks like this: `D D D S U U D D D D`
*(D = Downlink, S = Special/Flexible, U = Uplink)*

### Mapping the Pattern to Your Data
If we map that exact 10-slot pattern across the 20 slots of a 10ms frame, here is what the slot allocation looks like:

**First 5ms Period**
* **Slots 0, 1, 2:** Downlink (No UL scheduling allowed)
* **Slot 3:** Special (Contains the guard period and the first available Uplink symbols)
* **Slot 4, 5:** Uplink (Dedicated to UL scheduling)
* **Slots 6, 7, 8, 9:** Downlink

**Second 5ms Period (Repeats)**
* **Slots 10, 11, 12:** Downlink
* **Slot 13:** Special (First available Uplink symbols)
* **Slot 14, 15:** Uplink
* **Slots 16, 17, 18, 19:** Downlink

### The Verdict
Because the MAC layer can only schedule `PUSCH`, `PUCCH`, `PRACH`, or `SRS` during the Uplink and Special slots, **the only valid slots for an Uplink Schedule Report on this specific network are 3, 4, 5, 13, 14, and 15.**

Rather than a bug, this is actually an excellent Known Answer Test (KAT). The fact that your parser rigidly locked onto these exact TDD boundaries without bleeding into the Downlink slots proves your byte-offset and bit-masking logic for the 3.17 header is spot on.



# Why are HARQ sequential
Turns out they are just ACKs



# What are these categories: PUSCH, PUCCH, PRACH, and SRS? Explain in detail.
These four categories represent the physical channels and signals used in the uplink (UL) of a 5G New Radio (NR) network. They dictate how a device (like a smartphone or modem) transmits payload data, network requests, and connection metrics back to the base station (gNB).

Here is a detailed breakdown of each category and its role in a 5G network:

### PUSCH (Physical Uplink Shared Channel)

**The Workhorse for User Data**
PUSCH is the primary channel used to transmit your actual payload data (such as uploading a file, sending a text, or making a VoIP call).

* **Shared Nature:** It is "shared" because the network dynamically allocates frequency and time resources among multiple active users millisecond by millisecond based on demand.
* **Adaptive Transmission:** The base station dictates exactly how the device should transmit on PUSCH by assigning specific Resource Blocks (RBs) and a Modulation and Coding Scheme (MCS). If your RF conditions are excellent, the network assigns a high MCS to pack more bits into the transmission.
* **Piggybacking:** While mainly used for user payloads, PUSCH can temporarily carry control information if the device needs to send both data and network feedback at the exact same time.

### PUCCH (Physical Uplink Control Channel)

**The Network's Feedback Loop**
PUCCH is strictly dedicated to carrying Uplink Control Information (UCI). It never carries user data payloads. The UCI contains three critical types of feedback that keep the connection stable:

* **HARQ-ACK/NACK:** When the base station sends downlink data to the device, the device uses PUCCH to say "Acknowledged" (ACK, meaning it was received flawlessly) or "Negative Acknowledgement" (NACK, meaning the data was corrupted and must be retransmitted).
* **CSI (Channel State Information):** The device continuously measures the quality of the downlink signal it is receiving and reports those metrics back via PUCCH. This allows the base station to adjust its downlink power and coding.
* **SR (Scheduling Request):** If the device is sitting idle without any scheduled uplink resources and suddenly needs to upload data, it sends an SR over PUCCH. This is essentially the device "raising its hand" to ask the base station for PUSCH resources.

### PRACH (Physical Random Access Channel)

**The Knock on the Door**
PRACH is used for initial synchronization and access to the network. Unlike PUSCH and PUCCH, which operate under strict, coordinated schedules, PRACH is used when the device needs to establish or re-establish a connection.

* **Initial Access:** When a device wakes up from idle mode, powers on, or moves into a new cell coverage area (handover), it transmits a specific mathematical sequence called a "preamble" over PRACH.
* **Timing Alignment:** Because radio waves take time to travel, the base station uses the PRACH preamble to calculate exactly how far away the device is. It then sends a timing advance command back to the device, ensuring its future PUSCH and PUCCH transmissions align perfectly with the network's strict slot boundaries.

### SRS (Sounding Reference Signal)

**The Frequency Sonar**
Unlike the other three, SRS is not a channel; it is a reference signal. It contains no payload data or control messages.

* **Channel Estimation:** The device transmits this pre-known, recognizable signal across a wide band of frequencies to "sound" the uplink channel.
* **Optimizing the Link:** The base station analyzes the received SRS to determine which specific frequency subcarriers are experiencing interference and which are pristine. The base station then uses this spectral map to optimize its massive MIMO antennas (beamforming) and assign the absolute best frequencies for your upcoming PUSCH data transmissions.