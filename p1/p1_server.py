import socket
import sys
import time
import struct
import threading
import random
import zlib


# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + offset (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2

# --- RTO Estimator (Jacobson/Karels Algorithm) ---
class RTOEstimator:
    def __init__(self, alpha=0.125, beta=0.25, initial_rto=1.0, min_rto=0.04, max_rto=60.0):
        self.alpha = alpha
        self.beta = beta
        self.srtt = 0.0
        self.rttvar = 0.0
        self.rto = initial_rto
        self.min_rto = min_rto
        self.max_rto = max_rto

    def update(self, sample_rtt):
        """Update RTO based on a new RTT sample (in seconds)"""
        if self.srtt == 0.0:
            # First sample
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            # Subsequent samples
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        # TCP-style RTO with clock granularity
        G = 0.005  # 100ms clock granularity
        self.rto = self.srtt + max(G, 4 * self.rttvar)
        self.rto = max(self.min_rto, min(self.rto, self.max_rto))
        
        print("Updated RTO: {:.3f}s, SRTT: {:.3f}s, RTTVAR: {:.3f}s".format(self.rto, self.srtt, self.rttvar))

    def get_rto(self):
        return self.rto

# --- Global Server State ---
rtt_estimator = RTOEstimator()
in_flight_packets = {}  # {seq: (packet, send_time_sec, retransmit_count)}
dup_ack_counts = {}   # {seq: count}
base_seq = 0            # Cumulative ACK (lowest byte in window)
next_seq = 0            # Next byte to be sent
file_data = b''
file_size = 0
SWS = 0                 # Sender Window Size (in packets)
client_addr = None
transfer_complete = False
state_lock = threading.RLock()

# --- Statistics ---
stats = {
    "packets_sent": 0,
    "packets_retransmitted": 0,
    "acks_received": 0,
    "sacks_processed": 0,
    "fast_retransmits": 0
}

def make_packet(seq, data, timestamp_ms):
    """Creates a data packet with the 20-byte header."""
    # SACK fields (sack_start, sack_end) are 0 for data packets
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

def try_send_next_packets(sock):
    """
    Fill the sender window as long as space is available.
    Called from both the main loop and the ACK handler to make sending ACK-driven.
    """
    global next_seq, file_size, stats, in_flight_packets, SWS

    # We hold state_lock inside caller; but double-checking here to be safe:
    with state_lock:
        while len(in_flight_packets) < SWS and next_seq < file_size:
            data_chunk_size = min(DATA_LEN, file_size - next_seq)
            data_chunk = file_data[next_seq : next_seq + data_chunk_size]
            timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF

            packet = make_packet(next_seq, data_chunk, timestamp_ms)
            sock.sendto(packet, client_addr)

            in_flight_packets[next_seq] = (packet, time.time(), 0)
            stats["packets_sent"] += 1
            next_seq += data_chunk_size

def process_ack(ack_packet):
    """Processes an incoming ACK packet."""
    global base_seq
    try:
        # Unpack ACK: Cum_ACK (I), TS_Echo (I), SACK_Start (I), SACK_End (I)
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_packet)
    except struct.error:
        print("Received malformed ACK.")
        return

    with state_lock:
        stats["acks_received"] += 1
        
        was_base_retransmitted = False
        if base_seq in in_flight_packets:
            _packet, _send_time, retrans_count = in_flight_packets[base_seq]
            if retrans_count > 0:
                was_base_retransmitted = True
        
        # --- 1. Process SACKs (Karn's Rule applied here) ---
        if sack_end != 0:
            stats["sacks_processed"] += 1
            # sack_end is actually ooo_ack
            sacked_packets = []
            offset = sack_start
            # vary i from 0 to 31
            for i in range(32):
                if (sack_end >> i) & 1:
                    sacked_seq = sack_start + (i) * DATA_LEN
                    sacked_packets.append(sacked_seq)
            # Find all packets fully covered by SACK range
            sack_keys = [seq for seq in list(in_flight_packets.keys())
                        if seq in sacked_packets]
            print(f"--- SACK received for seqs {sack_keys} ---")

            for seq in sack_keys:
                packet, send_time, retrans_count = in_flight_packets.pop(seq)
                
                # Karn's Rule: Only update RTT for original transmissions
                if retrans_count == 0:
                    current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    packet_ts = struct.unpack(PACKET_FORMAT, packet[:HEADER_LEN])[1]
                    sample_rtt_ms = (current_time_ms - packet_ts) & 0xFFFFFFFF
                    sample_rtt = sample_rtt_ms / 1000.0
                    print(f"Sample RTT: {sample_rtt:.3f}s")
                    rtt_estimator.update(sample_rtt)


        # --- 2. Process Cumulative ACK (Karn's Rule applied here) ---
        if cum_ack > base_seq:
            if not was_base_retransmitted:
                current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                sample_rtt = sample_rtt_ms / 1000.0
                print(f"Sample RTT: {sample_rtt:.3f}s")
                rtt_estimator.update(sample_rtt)
            # New data has been cumulatively acknowledged
            base_seq = cum_ack
            dup_ack_counts.clear() # Reset duplicate ACK counter
            
            # Remove all acknowledged packets from in-flight window
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                _packet, _send_time, retrans_count = in_flight_packets.pop(seq)
                
        elif cum_ack == base_seq:
            # --- 3. Process Duplicate ACK ---
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            # Fast Retransmit Trigger
            if base_seq in in_flight_packets:
                old_packet,_,retrans_count = in_flight_packets[base_seq]
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    print(f"--- FAST RETRANSMIT for seq {base_seq} ---")
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    # old_packet, _st, retrans_count = in_flight_packets[base_seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    # Update send time and retransmit count
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[cum_ack] = 0 # Reset after retransmit
        try_send_next_packets(sock)

def ack_receiver_thread(sock):
    """Thread to continuously listen for ACK packets."""
    while not transfer_complete:
        try:
            # Set a timeout so the thread can check transfer_complete flag
            sock.settimeout(1.0)
            ack_packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            if ack_packet:
                process_ack(ack_packet)
        except socket.timeout:
            continue
        except Exception as e:
            if not transfer_complete:
                print(f"ACK receiver error: {e}")
            break
    print("ACK receiver thread stopping.")

def run_server(server_ip, server_port, sws):
    """Main server logic."""
    global SWS, file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock
    SWS = sws
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port} with SWS={SWS}")

    # --- 1. Wait for Connection Request ---
    while True:
        try:
            # Wait for the 1-byte request
            request, client_addr = sock.recvfrom(1)
            if request == b'\x01':
                print(f"Connection request from {client_addr}. Starting transfer.")
                break
        except Exception as e:
            print(f"Error waiting for client: {e}")
            return

    try:
        # Read the original file
        with open('data.txt', 'rb') as f:
            o_file_data = f.read()
        osize = len(o_file_data)
        cdata = zlib.compress(o_file_data, level=1)
        csize = len(cdata)
        
        size = int(osize * 0.8)
        
        if csize < size:
            offset_needed = size - csize
            header = struct.pack('!I', csize)
            offset = bytes(random.getrandbits(8) for _ in range(offset_needed - 4))
            file_data = header + cdata + offset
            
        elif csize > size:
            header = struct.pack('!I', csize)
            file_data = header + cdata
            
        else:
            header = struct.pack('!I', csize)
            file_data = header + cdata
        
        file_size = len(file_data)
        
    except FileNotFoundError:
        print("Error: data.txt not found.")
        sock.close()
        return

    # --- 3. Start ACK Receiver Thread ---
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()

    # --- 4. Main Sender Loop ---
    start_time = time.time()
    while base_seq < file_size:
        with state_lock:
            # --- 4a. Check for Timeouts (RTO) ---
            current_time = time.time()
            packets_to_retransmit = []
            
            for seq, (packet, send_time, retrans_count) in in_flight_packets.items():
                # Apply exponential backoff, capped at max_rto
                current_packet_rto = min(rtt_estimator.get_rto() * (2 ** retrans_count), rtt_estimator.max_rto)
                
                if current_time - send_time > current_packet_rto:
                    packets_to_retransmit.append(seq)
            
            for seq in packets_to_retransmit:
                if seq in in_flight_packets: # Check if not SACKed in the meantime
                    print(f"--- TIMEOUT for seq {seq} (RTO: {current_packet_rto:.2f}s) ---")
                    stats["packets_retransmitted"] += 1
                    old_packet, _st, retrans_count = in_flight_packets[seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[seq] =  0# Reset duplicate ACK count after timeout retransmit

            # --- 4b. Send New Packets ---
            while len(in_flight_packets) < SWS and next_seq < file_size:
                data_chunk_size = min(DATA_LEN, file_size - next_seq)
                data_chunk = file_data[next_seq : next_seq + data_chunk_size]
                timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                
                packet = make_packet(next_seq, data_chunk, timestamp_ms)
                sock.sendto(packet, client_addr)
                
                in_flight_packets[next_seq] = (packet, time.time(), 0)
                stats["packets_sent"] += 1
                next_seq += data_chunk_size
        
        # Sleep briefly to prevent busy-looping
        time.sleep(0.001) 

    # --- 5. Send EOF ---
    print("All file data acknowledged. Sending EOF.")
    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5): # Send EOF 5 times for reliability
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)

    # --- 6. Cleanup ---
    transfer_complete = True
    receiver_thread.join()
    sock.close()
    
    end_time = time.time()
    print("\n--- Transfer Complete ---")
    print(f"Total time: {end_time - start_time:.2f} seconds")
    print("Statistics:")
    print(f"  Packets Sent: {stats['packets_sent']}")
    print(f"  Packets Retransmitted: {stats['packets_retransmitted']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs Processed: {stats['sacks_processed']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  Final RTO: {rtt_estimator.get_rto():.3f}s")
    print(f"  Final SRTT: {rtt_estimator.srtt:.3f}s")
    print("-------------------------\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 p1_server.py <SERVER_IP> <SERVER_PORT> <SWS>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    SWS_ARG = int(sys.argv[3])
    
    run_server(SERVER_IP, SERVER_PORT, SWS_ARG/1180)