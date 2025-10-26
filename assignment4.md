# Assignment4

## Overview

In this assignment, you will be tasked with creating a client-server application where the client downloads a pre-specified file from the server using **UDP**. Since UDP (User Datagram Protocol) is unreliable and does not provide congestion control, you will design and implement mechanisms to ensure **reliability** and **congestion control** at the application layer. In particular, you should implement:

- **Reliability:** Ensure that all packets are delivered to the client in the correct order and without loss.
- **Congestion Control:** Implement a congestion control algorithm to prevent overwhelming the network. 

---

## Part 1: Reliability (40%)

Since UDP does not provide reliability, your task is to build a reliable data transfer protocol on top of it. You’ll implement a sliding window protocol that ensures reliable and in-order delivery. While we won’t fix the exact design for you — you’ll have some flexibility — your protocol should include the following key ideas:

- **Packet Numbering:**  
  Each packet should carry a sequence number in its header. The client will use these sequence numbers to put the received data in order and detect missing packets.

- **Acknowledgments (ACKs):**  
  The client should send ACKs to let the server know which packets have arrived successfully. You can use cumulative ACKs (like TCP does), which generally perform well. You can also add Selective ACKs (SACKs) for better efficiency — see [RFC 2018](https://datatracker.ietf.org/doc/html/rfc2018) if you want to learn how TCP implements SACK. Of course, you can have your own implementation of the SACKs. 

- **Timeouts:**  
  If the server doesn’t receive an ACK within a certain time (called the *Retransmission Timeout*, or RTO), it should retransmit the packet. The RTO value could be estimated using a method similar to what we discussed in class.

- **Fast Retransmit:**  
  Waiting for timeouts can be slow. To speed things up, you should also implement a fast retransmit mechanism — for example, resend a packet after receiving three duplicate ACKs. If you use SACKs, you can design an even smarter mechanism.

---

### Connection Setup

Implement reliability only for the server-to-client transfer. For the initial client-to-server message (the file request), you can simply retry up to five times until the request succeeds. Use a 2-second timeout between retries. You can assume that the server handles only one client at a time.

### Sender Window Size

Recall that the sender window size (SWS) limits the number of bytes that can be “in flight” at once. Since we’re not implementing congestion control in this part, just use a fixed SWS value, provided as a command-line argument when starting the server.

---

### Packet Format

Assume UDP packets with a maximum payload size of **1200 bytes**. You shouldn’t send payloads larger than this number. The first 20 bytes of this payload will be the headers for the reliability protocols, while the remaining bytes will carry the data.

**Structure:**
- The first **4 bytes (32 bits)** are the **sequence number**.  
  - For data packets (server → client), it represents the data sequence number.  
  - For ACK packets (client → server), it represents the next expected sequence number (like in TCP).
- The next **16 bytes** are **reserved for optional features** (e.g., SACK or timestamps). You can use them or leave them unused. The server should not send data in these bytes.
- The rest of the bytes (up to **1180 bytes**) carry the actual data.

```
| Sequence Number (4 bytes) | Reserved / Optional (16 bytes) | Data (up to 1180 bytes) |
```

---

### File Transfer Process

The server will have a file called `data.txt` that the client wants to download. To keep things simple, the client can just send a one-byte message indicating that it wants to download the file (no need to send the filename). When the server receives this message, it starts sending the file. The client should write the data into a file named `received_data.txt`.  

Once the entire file is sent, the server should send a special segment with `"EOF"` (assume the file does not end with EOF characters) in the payload to signal the end of transfer. After that, both the client and server can terminate. We don’t care about the specifics of the termination logic as long as you correctly terminate the client and server processes.

---

### Analysis

You’ll now test your protocol in Mininet to see how well it performs.

- **Setup:**  
  Use the provided simple two-host topology (h1 and h2 connected via a switch s1) and a Ryu controller running a basic learning switch. Use your reliable transfer implementation (without congestion control) to transfer the file between the server and client.

- **Experiments:**  
  Use the provided `data.txt` file and run two sets of experiments:
  - Measure download time for different packet loss rates (1% to 5%) while keeping delay fixed.
  - Measure download time for different delay jitter values (20 ms to 100 ms) while keeping loss fixed.  
  You can introduce loss and delay on the Mininet link using `tc qdisc` commands.

- **Plotting Results:**  
  Repeat each experiment five times to smooth out random noise. For each set, make a line plot showing **download time vs. loss (or delay)** and include **90% confidence intervals**. Add these plots and a short explanation of your observations in your report.

---

### What to Submit

Submit your client and server files named:

```
p1_client.py
p1_server.py
```

We should be able to run your code as:

```bash
# Running server
python3 p1_server.py <SERVER_IP> <SERVER_PORT> <SWS>

# Running client
python3 p1_client.py <SERVER_IP> <SERVER_PORT>
```

Here:
- `<SERVER_IP>` and `<SERVER_PORT>` are the server’s IP address and port.
- `<SWS>` is the fixed sender window size for the experiment.

Also submit a **short report (max 2 pages)** that includes:
- A short description of your header structure, enhancements (if any), and design choices. If something is similar to TCP, you can simply say so.
- The analysis results: plots and a brief explanation of what you observed. Make sure all text and legends in the plots are readable.

---

### Grading

Your score for this part will depend on both **correctness** and **performance**:

- 50% — correctness and completion of all parts  
- 25% — meeting performance targets (we’ll share these limits later)  
- 25% — efficiency of your protocol compared to others (we’ll test all submissions, rank them by file download time for each test case, take the average rank, and assign marks based on decile rank, rounded up). For example, if your performance is at the 51st percentile, you’ll get 15 marks.

---

## Part 2: Congestion Control (60%)

You will implement a congestion control algorithm based on a sliding window approach. However, the number of unacknowledged bytes should be controlled to avoid overwhelming the network. You should take care of the following implementation details:

- Your CCA should start with an initial window of 1 MSS.  
- You should implement the congestion control mechanisms on top of the code that implements reliability in Part 1.  
- Assume the same format of the packet as specified in Part 1.  
- No need to implement flow control.  

While you can implement your own congestion control algorithm and we will grade mostly relatively, it is prudent to start with something that is known to work. For instance, you could start with **TCP Reno** or **CUBIC**. In particular, implementing the following mechanisms would be useful:

- Increase the congestion window (**cwnd**) size exponentially in the beginning, for instance, doubling it every RTT until it reaches a threshold or congestion is detected.  
- When cwnd exceeds some threshold, increase the window size slowly so as to avoid congestion.  
- Respond to congestion events by reducing the congestion window. Ideally, your response should differ based on the severity of congestion (e.g., timeouts vs duplicate ACKs).  

---

## Analysis

You will perform a series of experiments to analyze the performance of your congestion control algorithm (CCA). Each experiment will use a **dumbbell topology** as shown in *Figure 1*, with two client–server pairs unless specified otherwise.  

### Experiments

#### 1. Fixed Bandwidth
Vary the bandwidth of the bottleneck link from **100 Mbps** to **1 Gbps** in steps of **100 Mbps**.  
For each bandwidth setting:
- Each client–server pair will download a file.  
- Compute the **average link utilization** and the **Jain Fairness Index (JFI)**.  
  - Average link utilization = (Sum of observed throughputs of both pairs) / (Link capacity).  
  - Use the observed throughputs to compute JFI.  
- Plot both **JFI** and **link utilization (y-axis)** against **link capacity (x-axis)** on the same graph.  

#### 2. Varying Loss
Study the impact of random packet losses on the bottleneck link.  
- Vary the packet loss rate from **0% to 2%** in intervals of **0.5%**.  
- For each setting, compute the **link utilization** and plot a graph with:
  - **Loss rate (x-axis)** vs **Link utilization (y-axis)**.  

#### 3. Asymmetric Flows
Examine the impact of unequal RTTs on fairness.  
- Vary the delay on the `Client2–switch1` link from **5 ms to 25 ms** in steps of **5 ms**, while keeping `Client1–switch1` delay fixed at **5 ms**.  
- Compute **JFI** and plot **RTT (x-axis)** vs **JFI (y-axis)**.  

#### 4. Background UDP Flow
Evaluate how bursty background traffic affects efficiency and fairness.  
- The setup consists of the dumbbell topology with two TCP client–server pairs sharing the bottleneck link, plus an additional **UDP flow** generating short, bursty traffic to mimic web-like flows.  
- The UDP source alternates between **ON** and **OFF** periods:
  - During ON: transmits a fixed number of packets at a high rate.  
  - During OFF: remains silent for a random duration drawn from an exponential distribution.  
- Vary average UDP load by adjusting the **mean OFF duration** to represent **light**, **medium**, and **heavy** background traffic conditions.  
- For each case:
  - Log link utilization and fairness.  
  - Plot a **bar chart** showing average link utilization and fairness for all three conditions.  
  - Briefly explain your observations.  

---

### Why So Many Experiments?
These experiments are designed to help you appreciate the diversity of network conditions that real-world CCAs encounter.You should recognize that designing a congestion control algorithm that performs well across all scenarios is challenging.

---

### Topology Diagram

![Network Topology](topology.jpeg)

Figure : Dumbbell topology for Part 2.

---

### What to Submit

Submit your client and server files named:

```
p2_client.py
p2_server.py
```

We should be able to run your code as:

```bash
# Running server
python3 p2_server.py <SERVER_IP> <SERVER_PORT>

# Running client
python3 p2_client.py <SERVER_IP> <SERVER_PORT> <PREF_FILENAME>
```

Here:
- `<SERVER_IP>` and `<SERVER_PORT>` represent the IP address and port that the server is listening on.  
- `<PREF_FILENAME>` is the prefix the client appends to the received file name.  

**Assume:**
- The server transmits `data.txt`.  
- The client saves it as `<PREF_FILENAME>received_data.txt`.  
- This helps avoid file conflicts when multiple clients write into the same folder during fairness experiments.

Also submit a **report (max 2 pages)** that includes:
The required plots and briefly discuss your observations for each experiment.

---

### Grading

Your score for this part will mainly depend on the performance of your congestion control algorithm:

- **70%** — meeting performance targets (to be shared later) and completing the report.  
- **30%** — efficiency of your protocol compared to others.  

For each experiment, a performance score will be calculated as the product of **JFI** and **Link Utilization**.  
The scores will be ranked across submissions and average of the rank across all experiments will be calculated.You will be awarded a score based on the **decile rank**. Example: A performance at the **51st percentile** earns **15 marks**.

---

### How to debug

Debugging congestion control code is inherently challenging — the behavior often depends on complex timing interactions, queuing etc. Below are some general debugging tips that can help you identify issues systematically.

* **Start with controlled conditions:**
  Begin by running a single flow over a simple topology (e.g., one sender–receiver pair without cross-traffic). Verify that the flow starts, sends, and terminates as you expect before adding complexity.

* **Plot congestion window evolution:**
  Always record and plot the congestion window (`cwnd`) over time. This will help you see whether the window grows as expected (e.g., additive increase), reacts to loss, and stabilizes in steady state. If `cwnd` oscillates too much or collapses, it could indicate overreaction or incorrect state updates. If `cwnd` grows indefinitely, your decrease logic may not be triggered.

* **Compare sending rate vs. throughput:**
  Log both the sending rate (bytes sent per interval) and the received throughput. If the sending rate exceeds link capacity but throughput does not increase, you are likely filling queues unnecessarily. You can also run tcpdump on the switch to log the queue length.

* **Instrument and log key variables:**
  Log state variables such as `ssthresh`, `acked_bytes`, and mode transitions (e.g., slow start → congestion avoidance). Use structured logs (CSV or JSON) so that they can be easily plotted later.

* **Check for synchronization bugs:**
  If multiple flows behave identically (oscillating together), you may be facing synchronization effects — test with small perturbations (e.g., slight delay offset between flows).

---