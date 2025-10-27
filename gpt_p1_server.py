#!/usr/bin/env python3
"""
p1_server.py
Usage:
    python3 p1_server.py <SERVER_IP> <SERVER_PORT> <SWS>

Implements a UDP server that sends data.txt reliably using a byte-oriented sliding window.
Features:
- Header: 20 bytes: seq (4), ts (4), sack1 (4), sack2 (4), reserved (4)
- Adaptive RTO (Jacobson/Karels), Karn's rule, exponential backoff (cap 60s)
- Fast retransmit on triple duplicate ACKs
- SACK parsing (2 compact SACK blocks)
- EOF packet with payload "EOF"
Logs transfer statistics at the end.
"""

import socket
import struct
import sys
import time
import select
import threading
from collections import OrderedDict, defaultdict

# Constants
MAX_PAYLOAD = 1200  # entire UDP payload for our use
HEADER_FMT = "!IIIII"  # seq, ts, sack1, sack2, reserved
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # should be 20
DATA_SIZE = MAX_PAYLOAD - HEADER_SIZE  # up to 1180

MAX_RETRIES_CONN = 5
CONN_RETRY_INTERVAL = 2.0

# RTO defaults
DEFAULT_RTO = 1.0  # 1s
MAX_RTO = 60.0

# Helper: millisecond timestamp mod 2^32
def now_ms():
    return int((time.time() * 1000)) & 0xffffffff

# Compact pack/unpack for SACK block into 32-bit:
# pack (left, right) into uint32 as (left & 0xFFFF) << 16 | (right & 0xFFFF)
def pack_sack(left, right):
    return ((left & 0xFFFF) << 16) | (right & 0xFFFF)

def unpack_sack(v):
    left = (v >> 16) & 0xFFFF
    right = v & 0xFFFF
    if left == 0 and right == 0:
        return None
    return (left, right)

# Logging
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

class ReliableUDPSender:
    def __init__(self, sock, addr, data_bytes, sws_packets):
        self.sock = sock
        self.client_addr = addr
        self.data = data_bytes
        self.filelen = len(self.data)
        self.SWS = sws_packets

        # Sender state
        self.base = 0  # next byte expected acked
        self.next_seq = 0  # next byte to send
        self.pkt_map = OrderedDict()  # key=seq (byte offset) -> (data, last_send_ts, retrans_count)
        # Maintain packet sizes mapping to ease retransmit
        self.sent_packets = 0
        self.retransmitted = 0
        self.fast_retrans = 0
        self.ack_count = 0
        self.sack_used = 0

        # RTT estimation (Jacobson/Karels)
        self.SRTT = None
        self.RTTVAR = None
        self.RTO = DEFAULT_RTO

        # Duplicate ACK tracking
        self.last_ack = None
        self.dup_ack_count = 0

        # threading variables
        self.running = True

    def make_packet(self, seq, payload=b"", sack_blocks=None):
        """
        Build packet with header:
        seq (4), ts (4), sack1 (4), sack2 (4), reserved (4)
        sack_blocks: list of (l,r) max 2 blocks
        """
        ts = now_ms()
        sack1 = 0
        sack2 = 0
        if sack_blocks:
            if len(sack_blocks) > 0:
                sack1 = pack_sack(sack_blocks[0][0] & 0xFFFF, sack_blocks[0][1] & 0xFFFF)
            if len(sack_blocks) > 1:
                sack2 = pack_sack(sack_blocks[1][0] & 0xFFFF, sack_blocks[1][1] & 0xFFFF)
        reserved = 0
        header = struct.pack(HEADER_FMT, seq & 0xffffffff, ts, sack1, sack2, reserved)
        return header + payload

    def send_segment(self, seq):
        """Send the packet at byte-offset seq (must exist in pkt_map)."""
        entry = self.pkt_map.get(seq)
        if not entry:
            return
        payload, _, retrans = entry
        packet = self.make_packet(seq, payload)
        self.sock.sendto(packet, self.client_addr)
        self.pkt_map[seq] = (payload, time.time(), retrans)  # update send ts (in seconds)
        self.sent_packets += 1

    def send_new_data_if_allowed(self):
        """Send new segments up to SWS"""
        while len(self.pkt_map) < self.SWS and self.next_seq < self.filelen:
            # Determine payload length
            remain = self.filelen - self.next_seq
            send_len = min(DATA_SIZE, remain)
            payload = self.data[self.next_seq:self.next_seq + send_len]
            seq = self.next_seq
            # store with send ts = 0 initially
            self.pkt_map[seq] = (payload, 0.0, 0)  # retrans count 0
            self.send_segment(seq)
            self.next_seq += send_len

    def process_ack_packet(self, packet):
        """
        Expect incoming ACK packet format: same header. seq field = cumulative ACK (next expected byte).
        SACK blocks encoded in header positions (2 blocks).
        """
        if len(packet) < HEADER_SIZE:
            return
        seq_ack, ts, sack1_raw, sack2_raw, _ = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
        cum_ack = seq_ack  # next expected byte
        self.ack_count += 1

        # RTT sample: if ts (sender's timestamp) != 0, we can measure RTT from our send record
        sample_rtt = None
        # We attempt to find which packet this ack acknowledges: cum_ack - 1 is last received byte
        # Find largest seq <= cum_ack - 1 in pkt_map or in history (we have pkt_map only).
        # For simplicity, iterate pkt_map keys and find the one whose seq+len(payload) == cum_ack
        matched_seq = None
        for seq_k, (payload, send_ts, retrans) in list(self.pkt_map.items()):
            if seq_k + len(payload) == cum_ack and send_ts != 0:
                matched_seq = seq_k
                # Calculate sample RTT only if retrans == 0 (Karn's rule)
                if retrans == 0:
                    sample_rtt = time.time() - send_ts
                break

        # Update RTO estimates if we have a sample and Karn's rule allows
        if sample_rtt is not None:
            self.update_rto(sample_rtt)

        # Check duplicate ACKs
        if self.last_ack == cum_ack:
            self.dup_ack_count += 1
        else:
            self.dup_ack_count = 0
            self.last_ack = cum_ack

        if self.dup_ack_count >= 3:
            # fast retransmit: retransmit earliest unacked packet (base)
            self.fast_retrans += 1
            # find smallest seq in pkt_map (earliest outstanding)
            if self.pkt_map:
                seq0 = next(iter(self.pkt_map))
                payload, send_ts, retrans = self.pkt_map[seq0]
                self.pkt_map[seq0] = (payload, time.time(), retrans + 1)
                # retransmit immediately
                packet = self.make_packet(seq0, payload)
                self.sock.sendto(packet, self.client_addr)
                self.retransmitted += 1
            self.dup_ack_count = 0  # reset

        # Use SACK blocks to remove specifically acknowledged pieces
        sack_blocks = []
        s1 = unpack_sack(sack1_raw)
        s2 = unpack_sack(sack2_raw)
        if s1:
            sack_blocks.append(s1)
            self.sack_used += 1
        if s2:
            sack_blocks.append(s2)
            self.sack_used += 1

        # Remove all fully acknowledged packets with seq + len <= cum_ack
        removed = []
        for seq_k in list(self.pkt_map.keys()):
            payload, send_ts, retrans = self.pkt_map[seq_k]
            end = seq_k + len(payload)
            fully_acked = (end <= cum_ack)
            # also if covered by any SACK block (end <= sack_right)
            for left, right in sack_blocks:
                # left/right here are small (16-bit), so interpret cautiously — treat as relative to cum_ack when possible
                # We'll accept sack blocks only if they map to absolute offsets <= filelen
                if left <= seq_k <= right and end <= right:
                    fully_acked = True
            if fully_acked:
                removed.append(seq_k)
                # If this packet was not retransmitted (retrans==0) and we have send_ts, sample RTT
                # (already handled above for the packet ending at cum_ack)
        for r in removed:
            del self.pkt_map[r]

        # Advance base if possible: base is smallest seq in pkt_map or next_seq if none
        if self.pkt_map:
            self.base = next(iter(self.pkt_map))
        else:
            self.base = self.next_seq

    def update_rto(self, sample_rtt):
        # Jacobson/Karels:
        if self.SRTT is None:
            self.SRTT = sample_rtt
            self.RTTVAR = sample_rtt / 2.0
        else:
            alpha = 1/8.0
            beta = 1/4.0
            self.RTTVAR = (1 - beta) * self.RTTVAR + beta * abs(self.SRTT - sample_rtt)
            self.SRTT = (1 - alpha) * self.SRTT + alpha * sample_rtt
        self.RTO = self.SRTT + 4 * max(self.RTTVAR, 0.001)
        # Bound RTO
        if self.RTO < 0.1:
            self.RTO = 0.1
        if self.RTO > MAX_RTO:
            self.RTO = MAX_RTO

    def handle_timeouts(self):
        """Retransmit packets whose send_ts + RTO < now"""
        now = time.time()
        for seq_k in list(self.pkt_map.keys()):
            payload, send_ts, retrans = self.pkt_map[seq_k]
            # If never sent? send_ts will be 0 only before first send; we sent when added normally.
            if send_ts == 0:
                continue
            if now - send_ts >= self.RTO:
                # retransmit and exponential backoff
                self.pkt_map[seq_k] = (payload, time.time(), retrans + 1)
                packet = self.make_packet(seq_k, payload)
                self.sock.sendto(packet, self.client_addr)
                self.retransmitted += 1
                # exponential backoff
                self.RTO = min(self.RTO * 2, MAX_RTO)
                log(f"Timeout retransmit seq={seq_k} len={len(payload)} new RTO={self.RTO:.2f}s")

    def run(self):
        log("Sender started.")
        last_stats_ts = time.time()
        # Main loop: send new data when window allows, recv ACKs, handle timeouts
        self.send_new_data_if_allowed()
        while True:
            # Socket readiness: short timeout to remain responsive
            rlist, _, _ = select.select([self.sock], [], [], 0.05)
            if rlist:
                try:
                    packet, addr = self.sock.recvfrom(4096)
                except BlockingIOError:
                    packet = None
                if packet:
                    # Process ACK
                    self.process_ack_packet(packet)
            # Send more if allowed
            if self.next_seq < self.filelen:
                self.send_new_data_if_allowed()
            # Handle timeouts for outstanding packets
            if self.pkt_map:
                self.handle_timeouts()
            # Check done: all data sent and no outstanding packets
            if self.next_seq >= self.filelen and not self.pkt_map:
                break
            # small sleep to avoid busy loop
        # Send EOF packet 5 times
        log("All data acked. Sending EOF packets.")
        eof_payload = b"EOF"
        for i in range(5):
            packet = self.make_packet(self.filelen, eof_payload)
            self.sock.sendto(packet, self.client_addr)
            time.sleep(0.05)

        # Summarize stats
        log("Transfer complete.")
        log(f"File bytes: {self.filelen}")
        log(f"Packets sent (including retransmits): {self.sent_packets}")
        log(f"Retransmitted: {self.retransmitted}")
        log(f"Fast retransmits: {self.fast_retrans}")
        log(f"ACKs received: {self.ack_count}")
        log(f"SACK blocks seen (approx): {self.sack_used}")
        log(f"Final RTO: {self.RTO:.3f}s")

def run_server(bind_ip, bind_port, sws):
    # Prepare UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, bind_port))
    sock.setblocking(False)
    log(f"Server listening on {bind_ip}:{bind_port}, SWS={sws}")

    # Wait for a one-byte request with up to 5 retries (handled by client)
    client_addr = None
    start_wait = time.time()
    log("Waiting for client request (one-byte).")
    while client_addr is None:
        rlist, _, _ = select.select([sock], [], [], 2.0)
        if rlist:
            data, addr = sock.recvfrom(1024)
            if data and len(data) >= 1:
                client_addr = addr
                log(f"Received connection request from {client_addr}")
                # send an ACK for request (simple), not part of reliable protocol
                sock.sendto(b"OK", client_addr)
                break
        # else timeout; loop until client handles retries
    if client_addr is None:
        log("No client connected. Exiting.")
        return

    # Read file
    try:
        with open("data.txt", "rb") as f:
            data_bytes = f.read()
    except FileNotFoundError:
        log("data.txt not found. Exiting.")
        return

    sender = ReliableUDPSender(sock, client_addr, data_bytes, sws)
    try:
        sender.run()
    except KeyboardInterrupt:
        log("Interrupted.")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 p1_server.py <SERVER_IP> <SERVER_PORT> <SWS>")
        sys.exit(1)
    IP = sys.argv[1]
    PORT = int(sys.argv[2])
    SWS = int(sys.argv[3])
    run_server(IP, PORT, SWS)
