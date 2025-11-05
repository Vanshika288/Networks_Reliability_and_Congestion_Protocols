import socket
import sys
import time
import struct
import threading

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN  # 1180 bytes
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2

# --- CUBIC Parameters ---
# CHANGE #1: Fixed MSS definition
# OLD: MSS = MAX_PAYLOAD_SIZE (1200 bytes - included header!)
# NEW: MSS = DATA_LEN (1180 bytes - data only)
# WHY: MSS should represent the data size, not including the 20-byte header
MSS = DATA_LEN  

INITIAL_CWND = 1 * MSS

# CHANGE #2: Adjusted CUBIC_C for better performance
# OLD: CUBIC_C = 0.8
# NEW: CUBIC_C = 0.4 (standard CUBIC value)
# WHY: 0.4 is the standard value used in Linux TCP CUBIC
CUBIC_C = 0.4

# CHANGE #3: Simplified CUBIC_BETA naming
# OLD: CUBIC_BETA_DECREASE = 0.7, CUBIC_BETA_K = 1.0 - CUBIC_BETA_DECREASE
# NEW: CUBIC_BETA = 0.7
# WHY: Clearer naming and correct usage in formulas
CUBIC_BETA = 0.7  # Multiplicative decrease factor

# --- RTO Estimator ---
class RTOEstimator:
    # CHANGE #4: Fixed minimum RTO
    # OLD: min_rto=0.0
    # NEW: min_rto=0.2 (200ms)
    # WHY: Zero min_rto allows RTO to become 0 seconds, causing immediate spurious 
    #      timeouts and massive unnecessary retransmissions
    def __init__(self, alpha=0.125, beta=0.25, initial_rto=1.0, min_rto=0.2, max_rto=60.0):
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
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        self.rto = max(self.min_rto, min(self.srtt + 4 * self.rttvar, self.max_rto))

    def get_rto(self):
        return self.rto

# --- Global Server State ---
rtt_estimator = RTOEstimator()
in_flight_packets = {}  # {seq: (packet, send_time_sec, retransmit_count)}
dup_ack_counts = {}
base_seq = 0
next_seq = 0
file_data = b''
file_size = 0
client_addr = None
transfer_complete = False
state_lock = threading.RLock()

# --- CUBIC State ---
cwnd = INITIAL_CWND
ssthresh = float('inf')
congestion_state = "SLOW_START"
w_max = 0.0
t_epoch = 0.0
k_cubic = 0.0

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
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

def handle_congestion_event(is_timeout):
    """Handle congestion events (timeout or fast retransmit)"""
    global cwnd, ssthresh, w_max, t_epoch, k_cubic, congestion_state
    
    # Record congestion time
    t_epoch = time.time()
    
    # Store current window as W_max
    w_max = cwnd
    
    # Calculate new ssthresh
    ssthresh = max(cwnd * CUBIC_BETA, 2 * MSS)
    
    # CHANGE #5: Fixed K calculation formula
    # OLD: k_cubic = ((w_max * CUBIC_BETA_K) / CUBIC_C) ** (1/3.0)
    #      where CUBIC_BETA_K = 1.0 - CUBIC_BETA_DECREASE = 0.3
    # NEW: k_cubic = ((w_max * (1.0 - CUBIC_BETA)) / CUBIC_C) ** (1/3.0)
    # WHY: The formula should be: K = cubic_root((W_max * (1-β)) / C)
    #      Using (1-0.7)=0.3 directly in the formula, not a separate constant
    #      This gives the correct time to reach W_max again
    try:
        k_cubic = ((w_max * (1.0 - CUBIC_BETA)) / CUBIC_C) ** (1.0/3.0)
    except:
        k_cubic = 0.0

    if is_timeout:
        # Severe congestion - reset to slow start
        cwnd = INITIAL_CWND
        congestion_state = "SLOW_START"
        stats["timeouts"] += 1
        print(f"[TIMEOUT] cwnd={cwnd:.0f}, ssthresh={ssthresh:.0f}, K={k_cubic:.2f}")
    else:
        # Fast retransmit - enter congestion avoidance
        cwnd = ssthresh
        congestion_state = "CONGESTION_AVOIDANCE"
        stats["fast_retransmits"] += 1
        print(f"[FAST_RETX] cwnd={cwnd:.0f}, ssthresh={ssthresh:.0f}, K={k_cubic:.2f}")

# CHANGE #6: New helper function for efficient in-flight calculation
# OLD: Calculated in-flight bytes inline in loops with complex conditions
#      Used packet.__len__() which included the 20-byte header
# NEW: Dedicated function that counts only data bytes (excluding header)
# WHY: More efficient (single calculation vs recalculating in loops)
#      Correct (data bytes only, not including header)
#      Cleaner code
def get_in_flight_bytes():
    """Calculate total bytes in flight (data only, not headers)"""
    total = 0
    for seq in in_flight_packets:
        if seq >= base_seq:
            packet = in_flight_packets[seq][0]
            total += len(packet) - HEADER_LEN  # Data only, subtract header
    return total

def try_send_next_packets(sock):
    """Send new packets if window allows"""
    global next_seq, stats
    
    with state_lock:
        # CHANGE #7: Simplified in-flight calculation using helper function
        # OLD: Recalculated in-flight bytes in the loop body
        # NEW: Use get_in_flight_bytes() helper
        # WHY: Cleaner, more efficient, and consistent
        in_flight_bytes = get_in_flight_bytes()
        
        while in_flight_bytes < cwnd and next_seq < file_size:
            data_chunk_size = min(DATA_LEN, file_size - next_seq)
            data_chunk = file_data[next_seq : next_seq + data_chunk_size]
            timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
            
            packet = make_packet(next_seq, data_chunk, timestamp_ms)
            sock.sendto(packet, client_addr)
            
            in_flight_packets[next_seq] = (packet, time.time(), 0)
            stats["packets_sent"] += 1
            next_seq += data_chunk_size
            in_flight_bytes += data_chunk_size

def process_ack(ack_packet, sock):
    """Process incoming ACK packet"""
    global base_seq, cwnd, ssthresh, congestion_state, t_epoch
    
    try:
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_packet)
    except struct.error:
        return
    
    with state_lock:
        stats["acks_received"] += 1
        
        # Check if base packet was retransmitted (for Karn's algorithm)
        was_retransmitted = False
        if base_seq in in_flight_packets:
            _, _, retrans_count = in_flight_packets[base_seq]
            was_retransmitted = (retrans_count > 0)
        
        # Process SACKs
        if sack_end != 0:
            stats["sacks_processed"] += 1
            for i in range(32):
                if (sack_end >> i) & 1:
                    sacked_seq = sack_start + i * DATA_LEN
                    if sacked_seq in in_flight_packets:
                        in_flight_packets.pop(sacked_seq)
        
        # Process cumulative ACK
        if cum_ack > base_seq:
            # Calculate bytes newly acknowledged
            acked_bytes = cum_ack - base_seq
            
            # CHANGE #8: Added RTT estimation update (CRITICAL BUG FIX)
            # OLD: No RTT update code at all!
            # NEW: Update RTT estimator using Karn's algorithm
            # WHY: Without RTT updates, RTO stays at initial 1.0 second forever
            #      This causes either too many timeouts (if actual RTT < 1s)
            #      or very slow recovery (if we rely only on timeouts)
            #      Karn's algorithm: only use RTT samples from non-retransmitted packets
            if not was_retransmitted and base_seq in in_flight_packets:
                packet, send_time, _ = in_flight_packets[base_seq]
                rtt_sample = time.time() - send_time
                rtt_estimator.update(rtt_sample)
            
            # Update congestion window
            if congestion_state == "SLOW_START":
                # Exponential growth: increase by acked_bytes
                cwnd += acked_bytes
                
                # CHANGE #9: Fixed transition to congestion avoidance
                # OLD: if cwnd >= ssthresh:
                #          congestion_state = "CONGESTION_AVOIDANCE"
                #          cwnd = ssthresh  # ← BUG: This drops the window!
                # NEW: Don't modify cwnd when transitioning
                # WHY: Reducing cwnd defeats the purpose of growing it
                #      Just change state, let cwnd continue from current value
                if cwnd >= ssthresh:
                    congestion_state = "CONGESTION_AVOIDANCE"
                    print(f"[SLOW_START -> CONG_AVOID] cwnd={cwnd:.0f}, ssthresh={ssthresh:.0f}")
                    
            elif congestion_state == "CONGESTION_AVOIDANCE":
                # CHANGE #10: Fixed CUBIC growth formula (MOST CRITICAL BUG)
                # OLD: cwnd = CUBIC_C * ((t_elapsed - k_cubic) ** 3) + w_max
                # NEW: Calculate target, then increment towards it
                # WHY: The old code set cwnd to an absolute value, which:
                #      - Can jump wildly (e.g., from 1KB to megabytes instantly)
                #      - Can go negative when t_elapsed < k_cubic
                #      - Completely ignores current network state
                #      CUBIC should incrementally grow towards the target, not jump to it!
                
                # Calculate CUBIC target window
                current_time = time.time()
                t_elapsed = current_time - t_epoch
                
                # W_cubic(t) = C * (t - K)^3 + W_max
                w_cubic = CUBIC_C * ((t_elapsed - k_cubic) ** 3) + w_max
                
                # Ensure w_cubic is at least current cwnd (never decrease in CA without loss)
                w_cubic = max(w_cubic, cwnd)
                
                # Increment cwnd towards w_cubic gradually
                # Standard approach: increment per ACK by (target - current) / current
                if cwnd > 0:
                    cwnd_increment = (w_cubic - cwnd) / cwnd * acked_bytes
                    # Ensure minimum progress (at least 1 MSS worth per cwnd bytes acked)
                    cwnd_increment = max(cwnd_increment, acked_bytes / cwnd)
                    cwnd += cwnd_increment
            
            # Remove acknowledged packets
            base_seq = cum_ack
            dup_ack_counts.clear()
            
            acked_keys = [seq for seq in list(in_flight_packets.keys()) if seq < cum_ack]
            for seq in acked_keys:
                in_flight_packets.pop(seq, None)
                
        elif cum_ack == base_seq:
            # Duplicate ACK
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            if base_seq in in_flight_packets:
                old_packet, _, retrans_count = in_flight_packets[base_seq]
                
                # Fast retransmit on 3rd duplicate ACK
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    print(f"[3 DUP ACKS] Fast retransmit seq={base_seq}")
                    
                    # Trigger congestion event
                    handle_congestion_event(is_timeout=False)
                    
                    # Retransmit
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    
                    stats["packets_retransmitted"] += 1
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[cum_ack] = 0
        
        # Try to send more packets
        try_send_next_packets(sock)

def ack_receiver_thread(sock):
    """Thread to continuously listen for ACKs"""
    while not transfer_complete:
        try:
            sock.settimeout(1.0)
            ack_packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            if ack_packet:
                process_ack(ack_packet, sock)
        except socket.timeout:
            continue
        except Exception as e:
            if not transfer_complete:
                print(f"ACK receiver error: {e}")
            break

def run_server(server_ip, server_port):
    """Main server logic"""
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete
    global cwnd, ssthresh, congestion_state, t_epoch, sock
    
    # Initialize CUBIC state
    cwnd = INITIAL_CWND
    ssthresh = float('inf')
    congestion_state = "SLOW_START"
    t_epoch = time.time()
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port} with CUBIC")
    
    # Wait for connection request
    while True:
        try:
            request, client_addr = sock.recvfrom(1)
            if request == b'\x01':
                print(f"Connection from {client_addr}")
                break
        except Exception as e:
            print(f"Error: {e}")
            return
    
    # Read file
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
        print(f"File size: {file_size} bytes")
    except FileNotFoundError:
        print("Error: data.txt not found")
        sock.close()
        return
    
    # Start ACK receiver thread
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()
    
    # Main sender loop
    start_time = time.time()
    last_print = start_time
    
    while base_seq < file_size:
        with state_lock:
            # Check for timeouts
            current_time = time.time()
            packets_to_retransmit = []
            
            for seq, (packet, send_time, retrans_count) in list(in_flight_packets.items()):
                packet_rto = min(rtt_estimator.get_rto() * (2 ** retrans_count), 60.0)
                
                if current_time - send_time > packet_rto:
                    packets_to_retransmit.append(seq)
            
            if packets_to_retransmit:
                # Handle as congestion event
                handle_congestion_event(is_timeout=True)
                
                for seq in packets_to_retransmit:
                    if seq in in_flight_packets:
                        old_packet, _, retrans_count = in_flight_packets[seq]
                        data_chunk = old_packet[HEADER_LEN:]
                        new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                        new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                        sock.sendto(new_packet, client_addr)
                        
                        stats["packets_retransmitted"] += 1
                        in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
            
            # CHANGE #11: Simplified send logic using helper function
            # OLD: Recalculated in-flight bytes with complex loop conditions
            # NEW: Use try_send_next_packets() helper
            # WHY: Consistent logic, no code duplication
            try_send_next_packets(sock)
            
            # CHANGE #12: Added periodic status updates for debugging
            # OLD: No progress logging
            # NEW: Print status every 2 seconds
            # WHY: Helps with debugging and monitoring transfer progress
            if current_time - last_print > 2.0:
                progress = base_seq / file_size * 100
                in_flight = get_in_flight_bytes()
                print(f"Progress: {progress:.1f}%, cwnd={cwnd:.0f}, in_flight={in_flight}, state={congestion_state}")
                last_print = current_time
        
        time.sleep(0.001)
    
    # Send EOF
    print("Sending EOF")
    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)
    
    # Cleanup
    transfer_complete = True
    receiver_thread.join()
    sock.close()
    
    end_time = time.time()
    print(f"\n--- Transfer Complete ({end_time - start_time:.2f}s) ---")
    print(f"Packets sent: {stats['packets_sent']}")
    print(f"Retransmissions: {stats['packets_retransmitted']}")
    print(f"Timeouts: {stats['timeouts']}")
    print(f"Fast retransmits: {stats['fast_retransmits']}")
    print(f"ACKs received: {stats['acks_received']}")
    print(f"Final SRTT: {rtt_estimator.srtt:.3f}s")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)