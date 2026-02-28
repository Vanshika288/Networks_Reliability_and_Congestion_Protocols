import socket
import sys
import time
import struct

MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN
EOF_MSG = b'EOF'

receiver_buffer = {}
expected_seq = 0

stats = {
    "packets_received": 0,
    "duplicates_received": 0,
    "out_of_order_packets": 0,
    "total_bytes_written": 0
}

def make_ack_packet(cum_ack, ts_echo, sack_block):
    sack_start, sack_end = 0, 0
    if sack_block:
        sack_start, sack_end = sack_block
        
    return struct.pack(PACKET_FORMAT, cum_ack, ts_echo, sack_start, sack_end, b'\x00'*4)

def get_sack_range(buffer, base_seq):
    received = sorted(buffer.keys())
    sack_start = None
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


def process_data_packet(packet, f_out):
    global expected_seq
    
    try:
        seq, ts, s1, s2, _ = struct.unpack(PACKET_FORMAT, packet[:HEADER_LEN])
        data = packet[HEADER_LEN:]
    except struct.error:
        return None

    stats["packets_received"] += 1
    data_len = len(data)

    if data == EOF_MSG:
        return "EOF"

    if seq < expected_seq:
        stats["duplicates_received"] += 1
        pass
    
    elif seq == expected_seq:
        # In-order packet
        f_out.write(data)
        stats["total_bytes_written"] += data_len
        expected_seq += data_len
        
        while expected_seq in receiver_buffer:
            buffered_data = receiver_buffer.pop(expected_seq)
            f_out.write(buffered_data)
            stats["total_bytes_written"] += len(buffered_data)
            expected_seq += len(buffered_data)
            
    elif seq > expected_seq:
        if seq not in receiver_buffer:
            stats["out_of_order_packets"] += 1
            receiver_buffer[seq] = data
            
    sack_block = get_sack_range(receiver_buffer, expected_seq)
    ack_packet = make_ack_packet(expected_seq, ts, sack_block)
    return ack_packet


def run_client(server_ip, server_port, pref_filename):
    global expected_seq
    
    outfile = f"{pref_filename}received_data.txt"
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_ip, server_port)

    request = b'\x01'
    first_packet = None
    for i in range(5):
        sock.sendto(request, server_addr)
        
        sock.settimeout(2.0)
        try:
            first_packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            if first_packet:
                break
        except socket.timeout:
            continue
    
    if not first_packet:
        sock.close()
        return

    start_time = time.time()
    try:
        with open(outfile, 'wb') as f_out:
            ack_to_send = process_data_packet(first_packet, f_out)
            if ack_to_send:
                sock.sendto(ack_to_send, server_addr)

            while True:
                sock.settimeout(10.0) 
                
                packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
                ack_to_send = process_data_packet(packet, f_out)
                
                if ack_to_send == "EOF":
                    break
                elif ack_to_send:
                    sock.sendto(ack_to_send, server_addr)

    except socket.timeout:
        pass
    except Exception as e:
        pass
    finally:
        sock.close()

    end_time = time.time()
    total_time = end_time - start_time
    throughput_mbps = (stats["total_bytes_written"] * 8) / (total_time * 1_000_000) if total_time > 0 else 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(1)
        
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    PREF_FILENAME = sys.argv[3]
    
    run_client(SERVER_IP, SERVER_PORT, PREF_FILENAME)