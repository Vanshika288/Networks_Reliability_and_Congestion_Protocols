#!/usr/bin/env python3
"""
Optimized Reliable UDP Server with SACK, Fast Retransmit, and Adaptive RTO
Implements TCP-like sliding window protocol for efficient file transfer
"""

import socket
import struct
import time
import sys
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RTOEstimator:
    """
    Jacobson/Karels RTO estimation algorithm
    Reference: "Congestion Avoidance and Control" (Jacobson & Karels, 1988)
    """
    def __init__(self):
        self.srtt = None      # Smoothed Round Trip Time
        self.rttvar = None    # RTT variance
        self.rto = 1.0        # Retransmission Timeout
        self.alpha = 0.125    # SRTT gain (1/8)
        self.beta = 0.25      # RTTVAR gain (1/4)
        self.K = 4            # Variance multiplier
        self.G = 0.001        # Clock granularity (1ms)
        
    def update_rtt(self, measured_rtt):
        """Update RTO based on new RTT measurement (Karn's algorithm)"""
        if self.srtt is None:  # First measurement
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2
        else:
            # Jacobson/Karels algorithm
            err = measured_rtt - self.srtt
            self.srtt = self.srtt + self.alpha * err
            self.rttvar = self.rttvar + self.beta * (abs(err) - self.rttvar)
        
        # Calculate RTO with variance component
        self.rto = self.srtt + max(self.G, self.K * self.rttvar)
        
        # Clamp RTO between 200ms and 60s
        self.rto = max(0.2, min(60.0, self.rto))
        logger.debug(f"RTO updated: {self.rto:.3f}s (SRTT: {self.srtt:.3f}s, RTTVAR: {self.rttvar:.3f}s)")
        
    def on_timeout(self):
        """Exponential backoff on timeout"""
        old_rto = self.rto
        self.rto = min(self.rto * 2, 60.0)
        logger.debug(f"Timeout detected: RTO backed off {old_rto:.3f}s -> {self.rto:.3f}s")


class SenderWindow:
    """
    Byte-oriented sliding window with SACK support
    Implements selective acknowledgment for efficient retransmission
    """
    def __init__(self, sws_packets):
        self.sws = sws_packets * 1180  # Convert packets to bytes
        self.send_base = 0              # Oldest unacknowledged byte
        self.next_seq = 0               # Next byte to send
        self.packets_in_flight = {}     # {seq_num: (data, send_time, retx_count)}
        self.rto_estimator = RTOEstimator()
        self.stats = {
            'packets_sent': 0,
            'packets_retransmitted': 0,
            'bytes_sent': 0,
            'acks_received': 0,
            'sacks_used': 0
        }
        
    def can_send(self):
        """Check if we can send more data (sliding window check)"""
        return (self.next_seq - self.send_base) < self.sws
    
    def send_packet(self, data, sock, addr):
        """Send a new data packet"""
        if not self.can_send():
            return False
        
        seq = self.next_seq
        timestamp_ms = int((time.time() * 1000)) % (2**32)
        
        # Build packet header (20 bytes)
        header = struct.pack('!II', seq, timestamp_ms)
        header += b'\x00' * 12  # Reserved/SACK blocks (empty for data packets)
        packet = header + data
        
        if len(packet) > 1200:
            logger.error(f"Packet too large: {len(packet)} > 1200")
            return False
        
        sock.sendto(packet, addr)
        self.packets_in_flight[seq] = (data, time.time(), 0)
        self.next_seq += len(data)
        self.stats['packets_sent'] += 1
        self.stats['bytes_sent'] += len(data)
        
        return True
    
    def process_ack(self, ack_seq, sack_blocks, recv_timestamp):
        """Process cumulative ACK and SACK blocks"""
        # Update RTT measurement (only for non-retransmitted packets - Karn's algorithm)
        if self.send_base in self.packets_in_flight:
            _, send_time, retx_count = self.packets_in_flight[self.send_base]
            if retx_count == 0:  # Only measure RTT from original transmissions
                rtt = time.time() - send_time
                if 0.001 <= rtt <= 60:  # Sanity check
                    self.rto_estimator.update_rtt(rtt)
        
        # Process cumulative ACK - remove all acknowledged packets
        if ack_seq > self.send_base:
            packets_acked = []
            for seq in list(self.packets_in_flight.keys()):
                if seq < ack_seq:
                    packets_acked.append(seq)
                    del self.packets_in_flight[seq]
            self.send_base = ack_seq
            self.stats['acks_received'] += 1
            logger.debug(f"Cumulative ACK: {ack_seq}, removed {len(packets_acked)} packets")
        
        # Process SACK blocks - mark additional packets as received
        if sack_blocks:
            self.stats['sacks_used'] += 1
            sack_removed = 0
            for left_edge, right_edge in sack_blocks:
                if left_edge >= self.send_base and right_edge <= self.next_seq:
                    for seq in list(self.packets_in_flight.keys()):
                        if left_edge <= seq < right_edge:
                            del self.packets_in_flight[seq]
                            sack_removed += 1
            logger.debug(f"SACK processed: removed {sack_removed} packets from blocks {sack_blocks}")
    
    def check_timeouts_and_retransmit(self, sock, addr):
        """Check for timeouts and retransmit intelligently"""
        current_time = time.time()
        rto = self.rto_estimator.rto
        
        # Find packets that need retransmission
        to_retransmit = []
        for seq, (data, send_time, retx_count) in self.packets_in_flight.items():
            if current_time - send_time > rto:
                to_retransmit.append((seq, data, retx_count))
        
        # Retransmit timed-out packets
        for seq, data, retx_count in sorted(to_retransmit):
            timestamp_ms = int((time.time() * 1000)) % (2**32)
            header = struct.pack('!II', seq, timestamp_ms)
            header += b'\x00' * 12
            packet = header + data
            
            sock.sendto(packet, addr)
            self.packets_in_flight[seq] = (data, time.time(), retx_count + 1)
            self.stats['packets_retransmitted'] += 1
            logger.debug(f"Timeout retransmission: seq={seq}, retx_count={retx_count + 1}")
            
        if to_retransmit:
            self.rto_estimator.on_timeout()


class FastRetransmit:
    """
    Fast retransmit mechanism - retransmit on 3 duplicate ACKs
    Reference: "TCP Fast Retransmit" (RFC 5827)
    """
    def __init__(self):
        self.last_ack = 0
        self.dup_ack_count = 0
        self.DUP_ACK_THRESHOLD = 3  # Standard TCP threshold
        self.stats = {'fast_retransmits': 0}
        
    def process_ack(self, ack_seq, sender_window, sock, addr):
        """Detect duplicate ACKs and trigger fast retransmit"""
        if ack_seq == self.last_ack and ack_seq < sender_window.next_seq:
            self.dup_ack_count += 1
            logger.debug(f"Duplicate ACK received: {ack_seq}, count={self.dup_ack_count}")
            
            # Fast retransmit after 3 duplicate ACKs
            if self.dup_ack_count == self.DUP_ACK_THRESHOLD:
                if ack_seq in sender_window.packets_in_flight:
                    data, send_time, retx_count = sender_window.packets_in_flight[ack_seq]
                    timestamp_ms = int((time.time() * 1000)) % (2**32)
                    header = struct.pack('!II', ack_seq, timestamp_ms)
                    header += b'\x00' * 12
                    packet = header + data
                    
                    sock.sendto(packet, addr)
                    sender_window.packets_in_flight[ack_seq] = (data, time.time(), retx_count + 1)
                    self.stats['fast_retransmits'] += 1
                    logger.info(f"Fast retransmit triggered for seq={ack_seq}")
        else:
            self.last_ack = ack_seq
            self.dup_ack_count = 0


def server(server_ip, server_port, sws_packets):
    """
    Reliable UDP server with sliding window and SACK support
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    sock.settimeout(0.01)  # 10ms timeout for responsive ACK processing
    
    logger.info(f"Server listening on {server_ip}:{server_port}, SWS={sws_packets} packets")
    
    # Wait for client request
    try:
        data, client_addr = sock.recvfrom(1)
        logger.info(f"Client connected from {client_addr}")
    except socket.timeout:
        logger.error("Timeout waiting for client request")
        sock.close()
        return
    
    # Read file to transfer
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        logger.info(f"File loaded: {len(file_data)} bytes")
    except FileNotFoundError:
        logger.error("data.txt not found")
        sock.close()
        return
    
    # Initialize protocols
    sender_window = SenderWindow(sws_packets)
    fast_retx = FastRetransmit()
    start_time = time.time()
    
    # Transmission loop
    offset = 0
    last_ack_time = time.time()
    ack_timeout_ms = 50  # Max time to wait for ACKs before checking timeouts
    
    logger.info("Starting file transfer...")
    
    while sender_window.send_base < len(file_data) or sender_window.packets_in_flight:
        # Send new packets while window allows
        while sender_window.can_send() and offset < len(file_data):
            chunk_size = min(1180, len(file_data) - offset)
            chunk = file_data[offset:offset + chunk_size]
            sender_window.send_packet(chunk, sock, client_addr)
            offset += chunk_size
        
        # Receive ACKs with timeout
        current_time = time.time()
        try:
            ack_data, _ = sock.recvfrom(1200)
            if len(ack_data) >= 4:
                ack_seq = struct.unpack('!I', ack_data[:4])[0]
                
                # Parse SACK blocks
                sack_blocks = []
                if len(ack_data) >= 20:
                    for i in range(3):
                        offset_bytes = 8 + i * 8
                        if len(ack_data) >= offset_bytes + 8:
                            left, right = struct.unpack('!II', ack_data[offset_bytes:offset_bytes + 8])
                            if left > 0 and right > left and left >= sender_window.send_base:
                                sack_blocks.append((left, right))
                
                sender_window.process_ack(ack_seq, sack_blocks, current_time)
                fast_retx.process_ack(ack_seq, sender_window, sock, client_addr)
                last_ack_time = current_time
        except socket.timeout:
            pass
        
        # Check for timeouts periodically
        if (current_time - last_ack_time) * 1000 > ack_timeout_ms:
            sender_window.check_timeouts_and_retransmit(sock, client_addr)
            last_ack_time = current_time
    
    # Send EOF marker multiple times for reliability
    eof_seq = len(file_data)
    eof_packet = struct.pack('!II', eof_seq, 0) + b'\x00' * 12 + b'EOF'
    
    logger.info("Sending EOF marker...")
    for i in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.05)
    
    elapsed_time = time.time() - start_time
    
    # Log statistics
    logger.info(f"\n{'='*60}")
    logger.info(f"Transfer Complete!")
    logger.info(f"{'='*60}")
    logger.info(f"File size: {len(file_data)} bytes")
    logger.info(f"Transfer time: {elapsed_time:.2f}s")
    logger.info(f"Throughput: {len(file_data) / elapsed_time / 1000:.2f} Kbps")
    logger.info(f"Packets sent: {sender_window.stats['packets_sent']}")
    logger.info(f"Packets retransmitted: {sender_window.stats['packets_retransmitted']}")
    logger.info(f"Retransmission rate: {sender_window.stats['packets_retransmitted'] / sender_window.stats['packets_sent'] * 100:.1f}%")
    logger.info(f"ACKs received: {sender_window.stats['acks_received']}")
    logger.info(f"SACK blocks used: {sender_window.stats['sacks_used']}")
    logger.info(f"Fast retransmits: {fast_retx.stats['fast_retransmits']}")
    logger.info(f"Final RTO: {sender_window.rto_estimator.rto:.3f}s")
    logger.info(f"{'='*60}\n")
    
    sock.close()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <SERVER_IP> <SERVER_PORT> <SWS>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    sws = int(sys.argv[3])
    
    server(server_ip, server_port, sws)
