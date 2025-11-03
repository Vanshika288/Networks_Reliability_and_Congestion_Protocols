import socket
import sys
import time
import struct

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'  # Seq(4) + TS(4) + SACK_Start(4) + SACK_End(4) + Padding(4)
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN  # 1180 bytes
EOF_MSG = b'EOF'

# --- Client State ---
receiver_buffer = {}  # {seq: data_chunk}
expected_seq = 0      # Next byte expected in-order

# --- Statistics ---
stats = {
    "packets_received": 0,
    "duplicates_received": 0,
    "out_of_order_packets": 0,
    "total_bytes_written": 0,
    "acks_sent": 0
}


def make_ack_packet(cum_ack, ts_echo, sack_block):
    """
    Create ACK packet.
    cum_ack: Next expected sequence number
    ts_echo: Timestamp to echo back
    sack_block: Tuple (start, end) for SACK, or (0, 0) if none
    """
    sack_start, sack_end = sack_block if sack_block else (0, 0)
    return struct.pack(PACKET_FORMAT, cum_ack, ts_echo, sack_start, sack_end, b'\x00'*4)


def get_sack_range(buffer, base_seq):
    """
    Find the largest contiguous block of received data above base_seq.
    Returns (start, end) for SACK block.
    """
    if not buffer:
        return (0, 0)
    
    received_seqs = sorted(buffer.keys())
    sack_start, sack_end = None, None
    
    for seq in received_seqs:
        if seq > base_seq:
            if sack_start is None:
                # Start of first block
                sack_start = seq
                sack_end = seq + len(buffer[seq])
            elif seq == sack_end:
                # Contiguous with current block
                sack_end += len(buffer[seq])
            else:
                # Gap detected, stop
                break
    
    if sack_start is None:
        return (0, 0)
    return (sack_start, sack_end)


def process_data_packet(packet, f_out):
    """
    Process incoming data packet and return ACK to send.
    Returns: ACK packet or "EOF" string if transfer complete
    """
    global expected_seq
    
    try:
        # Unpack header
        seq, ts, _, _, _ = struct.unpack(PACKET_FORMAT, packet[:HEADER_LEN])
        data = packet[HEADER_LEN:]
    except struct.error:
        print("Malformed packet received")
        return None
    
    stats["packets_received"] += 1
    data_len = len(data)
    
    # --- Check for EOF ---
    if data == EOF_MSG:
        print("EOF received. Transfer complete.")
        return "EOF"
    
    # --- Process packet ---
    if seq < expected_seq:
        # Duplicate - already processed
        stats["duplicates_received"] += 1
    
    elif seq == expected_seq:
        # In-order packet
        f_out.write(data)
        stats["total_bytes_written"] += data_len
        expected_seq += data_len
        
        # Deliver any buffered contiguous data
        while expected_seq in receiver_buffer:
            buffered_data = receiver_buffer.pop(expected_seq)
            f_out.write(buffered_data)
            stats["total_bytes_written"] += len(buffered_data)
            expected_seq += len(buffered_data)
    
    elif seq > expected_seq:
        # Out-of-order packet
        if seq not in receiver_buffer:
            stats["out_of_order_packets"] += 1
            receiver_buffer[seq] = data
    
    # --- Generate ACK with SACK ---
    sack_block = get_sack_range(receiver_buffer, expected_seq)
    ack_packet = make_ack_packet(expected_seq, ts, sack_block)
    stats["acks_sent"] += 1
    
    return ack_packet


def run_client(server_ip, server_port, pref_filename):
    """Main client logic"""
    global expected_seq
    
    # Output file with prefix
    outfile = f"{pref_filename}received_data.txt"
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_ip, server_port)
    
    # --- 1. Send connection request ---
    request = b'\x01'
    first_packet = None
    
    for i in range(5):
        print(f"Sending connection request (attempt {i+1}/5)...")
        sock.sendto(request, server_addr)
        
        sock.settimeout(2.0)
        try:
            first_packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            if first_packet:
                print("Connection established. Receiving data...")
                break
        except socket.timeout:
            continue
    
    if not first_packet:
        print("Server not responding. Exiting.")
        sock.close()
        return
    
    # --- 2. Main receiver loop ---
    start_time = time.time()
    last_print_time = start_time
    
    try:
        with open(outfile, 'wb') as f_out:
            # Process first packet
            ack_to_send = process_data_packet(first_packet, f_out)
            if ack_to_send and ack_to_send != "EOF":
                sock.sendto(ack_to_send, server_addr)
            
            # Loop for subsequent packets
            while True:
                sock.settimeout(10.0)
                
                try:
                    packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
                    ack_to_send = process_data_packet(packet, f_out)
                    
                    if ack_to_send == "EOF":
                        break
                    elif ack_to_send:
                        sock.sendto(ack_to_send, server_addr)
                    
                    # Print progress every 5 seconds
                    current_time = time.time()
                    if current_time - last_print_time >= 5.0:
                        elapsed = current_time - start_time
                        throughput = (stats["total_bytes_written"] * 8) / (elapsed * 1e6)
                        print(f"[{elapsed:.1f}s] Received: {stats['total_bytes_written']} bytes | "
                              f"Throughput: {throughput:.2f} Mbps | "
                              f"Buffered: {len(receiver_buffer)} packets")
                        last_print_time = current_time
                
                except socket.timeout:
                    print("Transfer stalled (timeout)")
                    break
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput = (stats["total_bytes_written"] * 8) / (total_time * 1e6) if total_time > 0 else 0
    
    print("\n" + "="*60)
    print("FILE RECEPTION COMPLETE")
    print("="*60)
    print(f"Saved to: {outfile}")
    print(f"Total Time: {total_time:.2f}s")
    print(f"Total Bytes: {stats['total_bytes_written']}")
    print(f"Throughput: {throughput:.2f} Mbps")
    print(f"\nPacket Statistics:")
    print(f"  Received: {stats['packets_received']}")
    print(f"  Out-of-Order: {stats['out_of_order_packets']}")
    print(f"  Duplicates: {stats['duplicates_received']}")
    print(f"  ACKs Sent: {stats['acks_sent']}")
    print("="*60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 p2_client.py <SERVER_IP> <SERVER_PORT> <PREF_FILENAME>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    PREF_FILENAME = sys.argv[3]
    
    run_client(SERVER_IP, SERVER_PORT, PREF_FILENAME)