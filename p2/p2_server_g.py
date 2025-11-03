import socket
import sys
import time
import struct
import threading
import random
import enum

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4+4 = 20 bytes
MSS = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'

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
        self.min_rtt = float('inf') # For CUBIC

    def update(self, sample_rtt):
        """Update RTO based on a new RTT sample (in seconds)"""
        if sample_rtt < self.min_rtt:
            self.min_rtt = sample_rtt
            
        if self.srtt == 0.0:
            # First sample
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            # Subsequent samples
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        self.rto = max(self.min_rto, min(self.srtt + 4 * self.rttvar, self.max_rto))
        # print("Updated RTO: {:.3f}s, SRTT: {:.3f}s, RTTVAR: {:.3f}s, MinRTT: {:.3f}s".format(self.rto, self.srtt, self.rttvar, self.min_rtt))

    def get_rto(self):
        return self.rto
    
    def get_min_rtt(self):
        # Return a reasonable default if no samples yet
        return self.min_rtt if self.min_rtt != float('inf') else 0.04 

# --- Congestion Control ---
class CCAState(enum.Enum):
    SLOW_START = 1
    CONGESTION_AVOIDANCE = 2
    FAST_RECOVERY = 3

# --- Global Server State ---
rtt_estimator = RTOEstimator()
in_flight_packets = {}  # {seq: (packet, send_time_sec, retransmit_count)}
dup_ack_counts = {}   # {seq: count}
base_seq = 0            # Cumulative ACK (lowest byte in window)
next_seq = 0            # Next byte to be sent
file_data = b''
file_size = 0
client_addr = None
transfer_complete = False
state_lock = threading.Lock()

# --- CCA State Variables ---
cwnd = 1 * MSS                  # Congestion Window (bytes)
ssthresh = 1000 * MSS             # Slow Start Threshold (bytes), init to large value
cca_state = CCAState.SLOW_START
# CUBIC specific
W_max = 0.0                       # Window max before last congestion
t_K = 0.0                         # Time of last congestion event
C_const = 0.4                     # CUBIC C constant
beta_cubic = 0.7                  # CUBIC multiplicative decrease factor

# --- Statistics ---
stats = {
    "packets_sent": 0,
    "packets_retransmitted": 0,
    "acks_received": 0,
    "sacks_processed": 0,
    "fast_retransmits": 0,
    "timeouts": 0
}

def make_packet(seq, data, timestamp_ms):
    """Creates a data packet with the 20-byte header."""
    # SACK fields (sack_start, sack_end) are 0 for data packets
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

def handle_congestion_event(is_timeout=False):
    """Update CCA variables on a congestion event (timeout or 3 dup acks)."""
    global W_max, t_K, ssthresh, cwnd, cca_state
    
    t_K = time.time() # Set time of congestion event
    
    if is_timeout:
        print(f"--- TIMEOUT Event at t={t_K:.2f} ---")
        stats["timeouts"] += 1
        W_max = cwnd # Store window before drop
        ssthresh = max(cwnd * beta_cubic, 2 * MSS)
        cwnd = 1 * MSS # Reset cwnd
        cca_state = CCAState.SLOW_START
        dup_ack_counts.clear() # Clear dup acks after timeout
    else: # Fast Retransmit (3 Dup ACKs)
        print(f"--- FAST RETRANSMIT Event at t={t_K:.2f} ---")
        stats["fast_retransmits"] += 1
        W_max = cwnd # Store window before drop
        ssthresh = max(cwnd * beta_cubic, 2 * MSS)
        cwnd = ssthresh # Set cwnd to ssthresh
        cca_state = CCAState.FAST_RECOVERY
        
    print(f"  New ssthresh={ssthresh:.0f}, New cwnd={cwnd:.0f}, New state={cca_state.name}")


def process_ack(ack_packet):
    """Processes an incoming ACK packet."""
    global base_seq, cca_state, cwnd, ssthresh, W_max, t_K
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

        # --- 1. Process SACKs ---
        if sack_start < sack_end:
            stats["sacks_processed"] += 1
            sack_keys = [seq for seq in list(in_flight_packets.keys())
                        if sack_start <= seq < sack_end]
            # print(f"--- SACK received for seqs {sack_keys} ---")
            for seq in sack_keys:
                packet, send_time, retrans_count = in_flight_packets.pop(seq)


        # --- 2. Process Cumulative ACK ---
        if cum_ack > base_seq:
            # --- 2a. Update RTT (Karn's Rule) ---
            if not was_base_retransmitted:
                current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                # Handle timestamp wrap-around
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                rtt_estimator.update(sample_rtt_ms / 1000.0)

            # New data is acknowledged
            base_seq = cum_ack
            dup_ack_counts.clear() # Reset duplicate ACK counter
            
            # Remove all acknowledged packets from in-flight window
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                _packet, _send_time, retrans_count = in_flight_packets.pop(seq)

            # --- 2b. Update Congestion Window ---
            if cca_state == CCAState.SLOW_START:
                cwnd += MSS
                # print(f"SS: cwnd = {cwnd:.0f}")
                if cwnd >= ssthresh:
                    cca_state = CCAState.CONGESTION_AVOIDANCE
                    # print("--- SLOW START -> CONGESTION AVOIDANCE ---")
            
            elif cca_state == CCAState.CONGESTION_AVOIDANCE:
                # CUBIC Growth
                t_now = time.time()
                t_elapsed = t_now - t_K
                min_rtt = rtt_estimator.get_min_rtt()
                
                # CUBIC K (time to reach W_max)
                K = ((W_max * (1.0 - beta_cubic)) / C_const)**(1.0/3.0)
                
                # CUBIC target window
                W_cubic_t = C_const * (t_elapsed - K)**3 + W_max
                
                # TCP-friendly target (Reno growth)
                W_tcp_t = W_max * beta_cubic + (3 * (1-beta_cubic)/(1+beta_cubic)) * (t_elapsed / min_rtt) * MSS
                
                W_target = max(W_cubic_t, W_tcp_t)
                
                # Grow cwnd towards W_target
                # Increase is (W_target - cwnd) / (cwnd / MSS) per RTT
                # Per ACK, increase is ( (W_target - cwnd) / (cwnd / MSS) ) / (cwnd / MSS)
                # Simplified: scale the growth based on how far we are from target
                
                ack_ratio = MSS / cwnd
                increment = (W_target - cwnd) * ack_ratio
                cwnd += increment
                # print(f"CA: t={t_elapsed:.2f} W_cubic={W_cubic_t:.0f} W_tcp={W_tcp_t:.0f} -> W_target={W_target:.0f} cwnd={cwnd:.0f}")

            elif cca_state == CCAState.FAST_RECOVERY:
                # New ACK received, so we've recovered
                cca_state = CCAState.CONGESTION_AVOIDANCE
                # print("--- FAST RECOVERY -> CONGESTION AVOIDANCE ---")
                
        elif cum_ack == base_seq:
            # --- 3. Process Duplicate ACK ---
            if cca_state == CCAState.FAST_RECOVERY:
                # In Fast Recovery, inflate cwnd for each dup ACK
                # This is "Reno" behavior, CUBIC is simpler and just sets cwnd=ssthresh
                pass # CUBIC doesn't inflate window here
            else:
                dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
                
                # Fast Retransmit Trigger
                if dup_ack_counts[cum_ack] == 3:
                    if base_seq in in_flight_packets:
                        handle_congestion_event(is_timeout=False)
                        
                        stats["packets_retransmitted"] += 1
                        
                        old_packet, _st, retrans_count = in_flight_packets[base_seq]
                        data_chunk = old_packet[HEADER_LEN:]
                        new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                        new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                        sock.sendto(new_packet, client_addr)
                        # Update send time and retransmit count
                        in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                        dup_ack_counts[cum_ack] = 0 # Reset after retransmit

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
    # print("ACK receiver thread stopping.")

def run_server(server_ip, server_port):
    """Main server logic."""
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock, cwnd, ssthresh, W_max, t_K
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port} with CUBIC")
    print(f"Initial: cwnd={cwnd:.0f}, ssthresh={ssthresh:.0f}")

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

    # --- 2. Read File ---
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
        print(f"File data.txt read ({file_size} bytes).")
    except FileNotFoundError:
        print("Error: data.txt not found.")
        sock.close()
        return
        
    # Initialize CUBIC state at start of transfer
    W_max = cwnd
    t_K = time.time()

    # --- 3. Start ACK Receiver Thread ---
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()

    # --- 4. Main Sender Loop ---
    start_time = time.time()
    
    # Flag to ensure we only process one timeout per RTO period
    in_timeout_recovery = False
    
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
            
            # Process timeouts
            if packets_to_retransmit and not in_timeout_recovery:
                # Enter timeout recovery and trigger CCA event
                in_timeout_recovery = True
                handle_congestion_event(is_timeout=True)
                
                # Retransmit the *oldest* lost packet
                seq_to_retransmit = min(packets_to_retransmit)
                if seq_to_retransmit in in_flight_packets: # Check if not SACKed
                    print(f"--- RTO Retransmit for seq {seq_to_retransmit} (RTO: {current_packet_rto:.2f}s) ---")
                    stats["packets_retransmitted"] += 1
                    
                    old_packet, _st, retrans_count = in_flight_packets[seq_to_retransmit]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq_to_retransmit, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq_to_retransmit] = (new_packet, time.time(), retrans_count + 1)
            elif not packets_to_retransmit:
                in_timeout_recovery = False # Clear flag when no packets are timed out

            # --- 4b. Send New Packets ---
            # Send as long as bytes_in_flight < cwnd
            bytes_in_flight = next_seq - base_seq
            while bytes_in_flight < cwnd and next_seq < file_size:
                data_chunk_size = min(MSS, file_size - next_seq)
                data_chunk = file_data[next_seq : next_seq + data_chunk_size]
                timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                
                packet = make_packet(next_seq, data_chunk, timestamp_ms)
                sock.sendto(packet, client_addr)
                
                in_flight_packets[next_seq] = (packet, time.time(), 0)
                stats["packets_sent"] += 1
                next_seq += data_chunk_size
                bytes_in_flight = next_seq - base_seq
        
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
    total_time = max(end_time - start_time, 1e-9)
    throughput_mbps = (file_size * 8) / (total_time * 1_000_000)
    
    print("\n--- Transfer Complete ---")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Throughput: {throughput_mbps:.2f} Mbps")
    print("Statistics:")
    print(f"  Packets Sent: {stats['packets_sent']}")
    print(f"  Packets Retransmitted: {stats['packets_retransmitted']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs Processed: {stats['sacks_processed']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  Timeouts: {stats['timeouts']}")
    print(f"  Final RTO: {rtt_estimator.get_rto():.3f}s")
    print(f"  Final SRTT: {rtt_estimator.srtt:.3f}s")
    print(f"  Min RTT: {rtt_estimator.get_min_rtt():.3f}s")
    print("-------------------------\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)