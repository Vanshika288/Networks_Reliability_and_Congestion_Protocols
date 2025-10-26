#!/usr/bin/env python3
"""
Optimized Reliable UDP Client with SACK support
Implements receiver buffer and in-order delivery
"""

import socket
import struct
import time
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReceiverBuffer:
    """
    Receiver-side buffer with selective acknowledgment support
    Maintains received ranges and generates SACK blocks
    """
    def __init__(self):
        self.expected_seq = 0      # Expected sequence number for in-order delivery
        self.buffer = {}           # {seq_num: data}
        self.received_ranges = []  # [(left, right), ...] sorted, merged ranges
        self.stats = {
            'packets_received': 0,
            'packets_out_of_order': 0,
            'duplicate_packets': 0,
            'bytes_received': 0
        }
        
    def receive_packet(self, seq, data):
        """
        Process received packet and generate SACK blocks
        Returns (data_to_write, sack_blocks)
        """
        # Ignore packets before expected sequence
        if seq < self.expected_seq:
            self.stats['duplicate_packets'] += 1
            logger.debug(f"Ignoring duplicate/old packet: seq={seq}, expected={self.expected_seq}")
            return b'', []
        
        # Store packet
        end_seq = seq + len(data)
        if seq not in self.buffer:  # Avoid duplicate buffering
            self.buffer[seq] = data
            self.stats['packets_received'] += 1
            self.stats['bytes_received'] += len(data)
        
        # Track out-of-order packets
        if seq > self.expected_seq:
            self.stats['packets_out_of_order'] += 1
            logger.debug(f"Out-of-order packet: seq={seq}, expected={self.expected_seq}")
        
        # Update received ranges
        self._update_ranges(seq, end_seq)
        
        # Deliver in-order data
        delivered_data = self._deliver_in_order_data()
        
        # Generate SACK blocks (up to 3 non-contiguous blocks after cumulative ACK)
        sack_blocks = self._generate_sack_blocks()
        
        return delivered_data, sack_blocks
    
    def _update_ranges(self, seq, end_seq):
        """Merge overlapping ranges efficiently"""
        new_range = (seq, end_seq)
        self.received_ranges.append(new_range)
        self.received_ranges.sort()
        
        # Merge overlapping ranges
        merged = []
        for left, right in self.received_ranges:
            if merged and left <= merged[-1][1]:
                # Overlapping ranges - merge them
                merged[-1] = (merged[-1][0], max(merged[-1][1], right))
            else:
                merged.append((left, right))
        self.received_ranges = merged
        logger.debug(f"Received ranges: {self.received_ranges}")
    
    def _deliver_in_order_data(self):
        """Deliver all contiguous data starting from expected_seq"""
        result = b''
        
        while self.expected_seq in self.buffer:
            data = self.buffer.pop(self.expected_seq)
            result += data
            self.expected_seq += len(data)
        
        return result
    
    def _generate_sack_blocks(self):
        """Generate up to 3 SACK blocks for non-contiguous received data"""
        sack_blocks = []
        
        # SACK only covers data beyond the cumulative ACK point
        for left, right in self.received_ranges:
            if left >= self.expected_seq:  # Only SACK future data
                sack_blocks.append((left, right))
        
        # Limit to 3 blocks
        return sack_blocks[:3]
    
    def has_received_eof(self):
        """Check if EOF marker was received"""
        # EOF is a packet with payload 'EOF', detected on packet reception
        return False


def client(server_ip, server_port):
    """
    Reliable UDP client with SACK support
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # 1 second timeout for receiving data
    
    server_addr = (server_ip, server_port)
    
    logger.info(f"Client connecting to {server_ip}:{server_port}")
    
    # Send initial request (retry up to 5 times with 2-second timeout)
    request_data = b'\x01'  # Single byte request
    max_retries = 5
    retry_interval = 2.0
    
    for attempt in range(max_retries):
        try:
            sock.sendto(request_data, server_addr)
            logger.info(f"File request sent (attempt {attempt + 1}/{max_retries})")
            
            # Try to receive first packet to confirm connection
            sock.settimeout(retry_interval)
            data, _ = sock.recvfrom(1200)
            if data:
                logger.info("Connected to server")
                # Process first packet
                break
        except socket.timeout:
            if attempt < max_retries - 1:
                logger.warning(f"Timeout on attempt {attempt + 1}, retrying...")
            continue
    else:
        logger.error("Failed to connect after 5 attempts")
        sock.close()
        return
    
    # Initialize receiver
    receiver = ReceiverBuffer()
    sock.settimeout(0.05)  # 50ms timeout for ongoing reception
    
    # Process first packet
    output_file_data = b''
    eof_received = False
    start_time = time.time()
    last_ack_time = time.time()
    ack_interval = 0.05  # Send ACK every 50ms or on packet reception
    
    if data:
        seq = struct.unpack('!I', data[:4])[0]
        payload = data[20:]  # Skip 20-byte header
        if payload == b'EOF':
            logger.info(f"EOF received at seq={seq}")
            eof_received = True
        else:
            received_data, sack_blocks = receiver.receive_packet(seq, payload)
            output_file_data += received_data
    
    logger.info("Receiving file...")
    
    while not eof_received:
        try:
            packet_data, _ = sock.recvfrom(1200)
            
            if len(packet_data) < 20:
                logger.warning(f"Received short packet: {len(packet_data)} bytes")
                continue
            
            # Parse packet header
            seq = struct.unpack('!I', packet_data[:4])[0]
            payload = packet_data[20:]
            
            # Check for EOF marker
            if payload == b'EOF':
                logger.info(f"EOF received at seq={seq}")
                eof_received = True
                break
            
            # Process packet
            received_data, sack_blocks = receiver.receive_packet(seq, payload)
            output_file_data += received_data
            
            # Send ACK immediately on each packet (no delayed ACK)
            send_ack(sock, server_addr, receiver.expected_seq, sack_blocks)
            last_ack_time = time.time()
            
            logger.debug(f"Packet seq={seq}, len={len(payload)}, expected_seq={receiver.expected_seq}, sack_blocks={sack_blocks}")
            
        except socket.timeout:
            # Timeout - send an ACK if enough time elapsed
            current_time = time.time()
            if (current_time - last_ack_time) > ack_interval:
                sack_blocks = receiver._generate_sack_blocks()
                send_ack(sock, server_addr, receiver.expected_seq, sack_blocks)
                last_ack_time = current_time
            continue
    
    elapsed_time = time.time() - start_time
    
    # Write received data to file
    try:
        with open('received_data.txt', 'wb') as f:
            f.write(output_file_data)
        logger.info(f"File written to received_data.txt: {len(output_file_data)} bytes")
    except IOError as e:
        logger.error(f"Failed to write file: {e}")
    
    # Log statistics
    logger.info(f"\n{'='*60}")
    logger.info("Reception Complete!")
    logger.info(f"{'='*60}")
    logger.info(f"Total bytes received: {receiver.stats['bytes_received']}")
    logger.info(f"Packets received: {receiver.stats['packets_received']}")
    logger.info(f"Out-of-order packets: {receiver.stats['packets_out_of_order']}")
    logger.info(f"Duplicate packets: {receiver.stats['duplicate_packets']}")
    logger.info(f"Reception time: {elapsed_time:.2f}s")
    if elapsed_time > 0:
        logger.info(f"Throughput: {len(output_file_data) / elapsed_time / 1000:.2f} Kbps")
    logger.info(f"{'='*60}\n")
    
    sock.close()


def send_ack(sock, server_addr, cumulative_ack, sack_blocks):
    """
    Send ACK packet with cumulative ACK and SACK blocks
    
    Packet format:
    - 4 bytes: cumulative ACK (next expected sequence number)
    - 12 bytes: SACK blocks (3 × 8 bytes)
    """
    # Build ACK packet
    ack_packet = struct.pack('!I', cumulative_ack)
    
    # Add SACK blocks (pad with zeros if less than 3)
    sack_data = b''
    for i in range(3):
        if i < len(sack_blocks):
            left, right = sack_blocks[i]
            sack_data += struct.pack('!II', left, right)
        else:
            sack_data += struct.pack('!II', 0, 0)
    
    ack_packet += sack_data
    
    try:
        sock.sendto(ack_packet, server_addr)
        logger.debug(f"ACK sent: cumulative_ack={cumulative_ack}, sack_blocks={sack_blocks}")
    except Exception as e:
        logger.error(f"Failed to send ACK: {e}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    
    client(server_ip, server_port)
