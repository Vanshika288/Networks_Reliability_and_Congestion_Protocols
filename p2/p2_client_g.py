import socket
import sys
import time
import struct

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
# OUTFILE = 'received_data.txt' # No longer hardcoded

# --- Client State ---
receiver_buffer = {}  # {seq: data_chunk}
expected_seq = 0      # Next byte expected in-order

# --- Statistics ---
stats = {
    "packets_received": 0,
    "duplicates_received": 0,
    "out_of_order_packets": 0,
    "total_bytes_written": 0
}

def make_ack_packet(cum_ack, ts_echo, sack_block):
    """
    Creates an ACK packet.
    cum_ack: The next sequence number expected (cumulative ACK).
    ts_echo: The timestamp from the packet that triggered this ACK.
    sack_block: A tuple (start, end) for the first SACK block, or None.
    """
    sack_start, sack_end = 0, 0
    if sack_block:
        sack_start, sack_end = sack_block
        
    return struct.pack(PACKET_FORMAT, cum_ack, ts_echo, sack_start, sack_end, b'\x00'*4)

def get_sack_range(buffer, base_seq):
    """Return (start, end) of the largest contiguous received block above base_seq."""
    received = sorted(buffer.keys())
    sack_start, sack_end = None, None

    for seq in received:
        if seq > base_seq:
            if sack_start is None:
                sack_start = seq
                sack_end = seq + len(buffer[seq])
            elif seq == sack_end:
                # This packet starts exactly where the last one ended
                sack_end += len(buffer[seq])
            else:
                break  # non-contiguous gap

    if sack_start is None:
        sack_start, sack_end = 0, 0
    return sack_start, sack_end


def process_data_packet(packet, f_out):
    """Processes an incoming data packet and returns an ACK packet to send."""
    global expected_seq
    
    try:
        # Unpack Data: Seq (I), TS (I), SACK_Start (I), SACK_End (I)
        seq, ts, s1, s2, _ = struct.unpack(PACKET_FORMAT, packet[:HEADER_LEN])
        data = packet[HEADER_LEN:]
    except struct.error:
        print("Received malformed data packet.")
        return None

    stats["packets_received"] += 1
    data_len = len(data)

    # --- 1. Check for EOF ---
    if data == EOF_MSG:
        print("EOF received. Transfer complete.")
        return "EOF"

    # --- 2. Process Packet ---
    if seq < expected_seq:
        # Duplicate of an already-processed packet
        stats["duplicates_received"] += 1
        pass # Just re-ACK
    
    elif seq == expected_seq:
        # In-order packet
        f_out.write(data)
        stats["total_bytes_written"] += data_len
        expected_seq += data_len
        
        # Check buffer for contiguous packets
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
            
    # --- 3. Generate ACK with SACK ---
    sack_block = get_sack_range(receiver_buffer, expected_seq)
    ack_packet = make_ack_packet(expected_seq, ts, sack_block)
    return ack_packet


def run_client(server_ip, server_port, outfile_name):
    """Main client logic."""
    global expected_seq
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_ip, server_port)

    # --- 1. Send Connection Request ---
    request = b'\x01'
    first_packet = None
    for i in range(5): # Retry up to 5 times
        print(f"Sending connection request (attempt {i+1}/5)...")
        sock.sendto(request, server_addr)
        
        # Wait 2 seconds for the first data packet
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

    # --- 2. Main Receiver Loop ---
    start_time = time.time()
    try:
        with open(outfile_name, 'wb') as f_out:
            # Process the first packet we already received
            ack_to_send = process_data_packet(first_packet, f_out)
            if ack_to_send:
                sock.sendto(ack_to_send, server_addr)

            # Loop for subsequent packets
            while True:
                # Set a longer timeout for the transfer (e.g., 20s)
                sock.settimeout(20.0) 
                
                packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
                ack_to_send = process_data_packet(packet, f_out)
                
                if ack_to_send == "EOF":
                    break # Transfer complete
                elif ack_to_send:
                    sock.sendto(ack_to_send, server_addr)

    except socket.timeout:
        print("Transfer stalled. Server stopped responding.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

    end_time = time.time()
    total_time = max(end_time - start_time, 1e-9)
    throughput_mbps = (stats["total_bytes_written"] * 8) / (total_time * 1_000_000)

    print("\n--- File Reception Complete ---")
    print(f"Saved to {outfile_name}")
    print(f"Total time: {total_time:.2f} seconds")
    print("Statistics:")
    print(f"  Total Bytes Written: {stats['total_bytes_written']}")
    print(f"  Packets Received: {stats['packets_received']}")
    print(f"  Out-of-Order Packets: {stats['out_of_order_packets']}")
    print(f"  Duplicate Packets: {stats['duplicates_received']}")
    print(f"  Throughput: {throughput_mbps:.2f} Mbps")
    print("-------------------------------\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 p2_client.py <SERVER_IP> <SERVER_PORT> <PREF_FILENAME>")
        sys.exit(1)
        
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    PREF_FILENAME = sys.argv[3]
    
    # Construct the output filename as expected by p2_exp.py
    OUTFILE = f"{PREF_FILENAME}received_data.txt"
    
    run_client(SERVER_IP, SERVER_PORT, OUTFILE)