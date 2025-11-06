import socket
import sys
import time
import struct
import zlib

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
OUTFILE = 'received_data.txt'

# --- Client State ---
receiver_buffer = {}  # {seq: data_chunk}
expected_seq = 0      # Next byte expected in-order
data_buffer = bytearray()  # Will accumulate all received data

stats = {
    "packets_received": 0,
    "duplicates_received": 0,
    "out_of_order_packets": 0,
    "total_bytes_written": 0,
    "bytes_received": 0
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
    sack_start = None
    # an int representing using 0 and 1 which sequences have been received -> 4bytes -> 32 sequences checked
    ooo_acks = 0
    for seq in received:
        if seq > base_seq:
            if sack_start is None:
                sack_start = seq
                ooo_acks = 1
            else:
                diff = (seq - sack_start)/(1180)
                if diff < 32:
                    ooo_acks |= (1 << int(diff))

    if sack_start is None:
        return 0, 0
    return sack_start, ooo_acks

def process_data_packet(packet):
    """
    Processes an incoming data packet and returns an ACK packet to send.
    """
    global expected_seq, data_buffer
    
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
        data_buffer.extend(data)
        stats["bytes_received"] += data_len
        expected_seq += data_len
        
        # Check buffer for contiguous packets
        while expected_seq in receiver_buffer:
            buffered_data = receiver_buffer.pop(expected_seq)
            data_buffer.extend(buffered_data)
            stats["bytes_received"] += len(buffered_data)
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


def run_client(server_ip, server_port):
    """Main client logic."""
    global expected_seq, data_buffer
    
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

    start_time = time.time()
    try:
        ack_to_send = process_data_packet(first_packet)
        if ack_to_send and ack_to_send != "EOF":
            sock.sendto(ack_to_send, server_addr)

        # Loop for subsequent packets
        while True:
            # Set a longer timeout for the transfer
            sock.settimeout(10.0) 
            
            packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            ack_to_send = process_data_packet(packet)
            
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
    total_time = end_time - start_time

    received_bytes = len(data_buffer)
    
    if len(data_buffer) < 4:
        raise Exception("Received data too small to contain header")
    
    recieved_size = struct.unpack('!I', data_buffer[:4])[0]
    recieved_data = bytes(data_buffer[4:4+recieved_size])
    
    final_data = zlib.decompress(recieved_data)
    derecieved_size = len(final_data)
    
    with open(OUTFILE, 'wb') as f_out:
        f_out.write(final_data)
    
    stats["total_bytes_written"] = derecieved_size
        
    # Calculate throughputs
    throughput_mbps = (stats["total_bytes_written"] * 8) / (total_time * 1_000_000) if total_time > 0 else 0
    network_throughput_mbps = (stats["bytes_received"] * 8) / (total_time * 1_000_000) if total_time > 0 else 0

    print("\n--- File Reception Complete ---")
    print(f"Saved to {OUTFILE}")
    print(f"Total time: {total_time:.2f} seconds")
    print("Statistics:")
    print(f"  Packets Received: {stats['packets_received']}")
    print(f"  Out-of-Order Packets: {stats['out_of_order_packets']}")
    print(f"  Duplicate Packets: {stats['duplicates_received']}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p1_client.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
        
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_client(SERVER_IP, SERVER_PORT)
