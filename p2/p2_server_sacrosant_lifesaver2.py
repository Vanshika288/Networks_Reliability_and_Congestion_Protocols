import socket
import sys
import time
import struct
import threading
import math

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2

# ============================================================================
# PART 2: TCP CUBIC CONGESTION CONTROL HYPERPARAMETERS
# ============================================================================
CUBIC_C = 0.4                    # CUBIC scaling constant
CUBIC_BETA = 0.7                 # Multiplicative decrease factor (0.7 = 30% reduction)
INITIAL_CWND_MSS = 1             # Initial congestion window (in MSS units)
INITIAL_SSTHRESH_MSS = 100       # Initial slow start threshold (in MSS units)
MIN_CWND_MSS = 1                 # Minimum congestion window
MAX_CWND_MSS = 500               # Maximum congestion window (safety limit)
MSS_BYTES = DATA_LEN             # Maximum Segment Size = 1180 bytes

# CUBIC parameters
CUBIC_FAST_CONVERGENCE = True    # Enable fast convergence mode
CUBIC_TCP_FRIENDLINESS = True    # Enable TCP-friendliness mode

# ============================================================================

# --- RTO Estimator (Jacobson/Karels Algorithm) ---
class RTOEstimator:
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
            # First sample
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            # Subsequent samples
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        self.rto = max(self.min_rto, min(self.srtt + 4 * self.rttvar, self.max_rto))

    def get_rto(self):
        return self.rto

# ============================================================================
# PART 2: TCP CUBIC CONGESTION CONTROL CLASS
# ============================================================================
class CubicCongestionControl:
    """
    Implements TCP CUBIC congestion control algorithm.
    CUBIC is a loss-based congestion control algorithm that uses a cubic function
    of time since last congestion event for window growth.
    """
    def __init__(self):
        # Congestion window (in MSS units)
        self.cwnd = float(INITIAL_CWND_MSS)
        self.ssthresh = float(INITIAL_SSTHRESH_MSS)
        
        # CUBIC-specific state
        self.w_max = 0.0              # Window size before last reduction
        self.k = 0.0                  # Time period for cwnd to grow to w_max
        self.epoch_start = 0.0        # Time when current epoch started
        self.origin_point = 0.0       # Origin point of cubic function
        self.tcp_cwnd = 0.0           # Estimated cwnd for TCP Reno (for friendliness)
        
        # RTT tracking for CUBIC
        self.min_rtt = float('inf')
        self.current_rtt = 1.0        # Default 1 second
        
        print(f"[CUBIC] Initialized: cwnd={self.cwnd:.2f} MSS, ssthresh={self.ssthresh:.2f} MSS")
    
    def update_rtt(self, rtt_sample):
        """Update RTT estimates for CUBIC calculations"""
        self.current_rtt = rtt_sample
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample
    
    def get_cwnd_bytes(self):
        """Return current congestion window in bytes"""
        return int(self.cwnd * MSS_BYTES)
    
    def on_ack(self, bytes_acked, current_time):
        """
        Called when new data is ACKed.
        Implements CUBIC window growth.
        
        PART 2 ADDITION: This is the main CUBIC logic for window increase
        """
        if self.cwnd < MIN_CWND_MSS:
            self.cwnd = MIN_CWND_MSS
        
        # Convert bytes to MSS units
        acked_mss = bytes_acked / float(MSS_BYTES)
        
        if self.cwnd < self.ssthresh:
            # === SLOW START PHASE ===
            # Exponential growth: increase by 1 MSS for each ACK
            self.cwnd += acked_mss
            if self.cwnd >= self.ssthresh:
                print(f"[CUBIC] Exiting slow start: cwnd={self.cwnd:.2f} MSS >= ssthresh={self.ssthresh:.2f} MSS")
        else:
            # === CONGESTION AVOIDANCE PHASE ===
            # Use CUBIC function for window growth
            self._cubic_update(current_time)
        
        # Cap cwnd at maximum
        if self.cwnd > MAX_CWND_MSS:
            self.cwnd = MAX_CWND_MSS
        
        return self.get_cwnd_bytes()
    
    def _cubic_update(self, current_time):
        """
        PART 2 ADDITION: Core CUBIC algorithm for congestion avoidance phase.
        Updates cwnd using cubic function: W(t) = C(t-K)^3 + W_max
        """
        if self.epoch_start == 0.0:
            # First ACK after congestion event
            self.epoch_start = current_time
            if self.cwnd < self.w_max:
                # Fast convergence
                self.k = math.pow((self.w_max - self.cwnd) / CUBIC_C, 1.0/3.0)
                self.origin_point = self.w_max
            else:
                self.k = 0.0
                self.origin_point = self.cwnd
            
            self.tcp_cwnd = self.cwnd
        
        # Time since epoch start (in seconds)
        t = current_time - self.epoch_start
        
        # CUBIC function: W_cubic(t) = C * (t - K)^3 + W_max
        target = self.origin_point + CUBIC_C * math.pow(t - self.k, 3)
        
        # === TCP-FRIENDLINESS CHECK ===
        if CUBIC_TCP_FRIENDLINESS:
            # Estimate what TCP Reno would do (AIMD: +1 MSS per RTT)
            # tcp_cwnd += 1 per RTT = 1 / cwnd per ACK
            self.tcp_cwnd += (1.0 / self.cwnd)
            
            # Use TCP cwnd if it's larger (be fair to TCP flows)
            if self.tcp_cwnd > target:
                target = self.tcp_cwnd
        
        # Calculate increment based on RTT
        if target > self.cwnd:
            # Increase cwnd to approach target
            # Increment by (target - cwnd) / cwnd per ACK
            increment = (target - self.cwnd) / self.cwnd
            self.cwnd += increment
        else:
            # Already at or above target, slow growth
            self.cwnd += 1.0 / self.cwnd
    
    def on_loss_event(self, loss_type='timeout'):
        """
        PART 2 ADDITION: Called when packet loss is detected.
        Implements CUBIC's multiplicative decrease.
        
        loss_type: 'timeout' or 'fast_retransmit' (3 dup ACKs)
        """
        if loss_type == 'timeout':
            # Severe congestion: reset to slow start
            print(f"[CUBIC] TIMEOUT: cwnd={self.cwnd:.2f} -> ssthresh={self.cwnd * CUBIC_BETA:.2f}, cwnd=1 MSS")
            self.ssthresh = max(self.cwnd * CUBIC_BETA, MIN_CWND_MSS)
            
            # Save w_max before reduction
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                # Fast convergence: reduce w_max
                self.w_max = self.cwnd * (2.0 - CUBIC_BETA) / 2.0
            else:
                self.w_max = self.cwnd
            
            self.cwnd = float(INITIAL_CWND_MSS)
            self.epoch_start = 0.0
            
        elif loss_type == 'fast_retransmit':
            # Mild congestion: multiplicative decrease
            old_cwnd = self.cwnd
            
            # Save w_max before reduction
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                # Fast convergence
                self.w_max = self.cwnd * (2.0 - CUBIC_BETA) / 2.0
            else:
                self.w_max = self.cwnd
            
            # Reduce cwnd by (1 - beta)
            self.cwnd = max(self.cwnd * CUBIC_BETA, MIN_CWND_MSS)
            self.ssthresh = self.cwnd
            
            # Reset epoch
            self.epoch_start = 0.0
            
            print(f"[CUBIC] FAST_RETRANSMIT: cwnd={old_cwnd:.2f} -> {self.cwnd:.2f} MSS (beta={CUBIC_BETA}), w_max={self.w_max:.2f}")
    
    def get_state_str(self):
        """Return string representation of current state for logging"""
        phase = "SLOW_START" if self.cwnd < self.ssthresh else "CONGESTION_AVOIDANCE"
        return f"[CUBIC] cwnd={self.cwnd:.2f} MSS ({self.get_cwnd_bytes()} bytes), ssthresh={self.ssthresh:.2f} MSS, w_max={self.w_max:.2f}, phase={phase}"

# ============================================================================

# --- Global Server State ---
rtt_estimator = RTOEstimator()
cubic_cc = None  # PART 2 ADDITION: CUBIC congestion control instance

in_flight_packets = {}  # {seq: (packet, send_time_sec, retransmit_count)}
dup_ack_counts = {}     # {seq: count}
base_seq = 0            # Cumulative ACK (lowest byte in window)
next_seq = 0            # Next byte to be sent
file_data = b''
file_size = 0
client_addr = None
transfer_complete = False
state_lock = threading.RLock()

# --- Statistics ---
stats = {
    "packets_sent": 0,
    "packets_retransmitted": 0,
    "acks_received": 0,
    "sacks_processed": 0,
    "fast_retransmits": 0,
    "timeouts": 0,
    "bytes_acked": 0
}

def make_packet(seq, data, timestamp_ms):
    """Creates a data packet with the 20-byte header."""
    # SACK fields (sack_start, sack_end) are 0 for data packets
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

def try_send_next_packets(sock):
    """
    PART 2 MODIFICATION: Fill the sender window based on CUBIC's cwnd.
    Original Part 1 used fixed SWS; now we use dynamic cwnd from CUBIC.
    Called with state_lock held by caller.
    """
    global next_seq, file_size, stats, in_flight_packets, cubic_cc

    # PART 2 CHANGE: Use CUBIC's cwnd instead of fixed SWS
    cwnd_bytes = cubic_cc.get_cwnd_bytes()
    in_flight_bytes = sum(len(pkt[0]) - HEADER_LEN for pkt in in_flight_packets.values())
    
    # Send packets while we have room in the congestion window
    while in_flight_bytes < cwnd_bytes and next_seq < file_size:
        # Determine how much data to send
        data_chunk_size = min(DATA_LEN, file_size - next_seq)
        
        # Safety check
        if data_chunk_size <= 0:
            break
            
        data_chunk = file_data[next_seq : next_seq + data_chunk_size]
        timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF

        packet = make_packet(next_seq, data_chunk, timestamp_ms)
        
        try:
            sock.sendto(packet, client_addr)
            in_flight_packets[next_seq] = (packet, time.time(), 0)
            stats["packets_sent"] += 1
            next_seq += data_chunk_size
            in_flight_bytes += data_chunk_size
        except Exception as e:
            print(f"Error sending packet at seq {next_seq}: {e}")
            break

def process_ack(ack_packet):
    """
    PART 2 MODIFICATION: Process ACK and update CUBIC congestion control.
    """
    global base_seq, cubic_cc
    
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
            sacked_packets = []
            for i in range(32):
                if (sack_end >> i) & 1:
                    sacked_seq = sack_start + (i) * DATA_LEN
                    sacked_packets.append(sacked_seq)
            
            sack_keys = [seq for seq in list(in_flight_packets.keys())
                        if seq in sacked_packets]
            
            for seq in sack_keys:
                packet, send_time, retrans_count = in_flight_packets.pop(seq)

        # --- 2. Process Cumulative ACK ---
        if cum_ack > base_seq:
            # PART 2 ADDITION: Update RTT and CUBIC on new ACK
            if not was_base_retransmitted:
                current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                sample_rtt_sec = sample_rtt_ms / 1000.0
                rtt_estimator.update(sample_rtt_sec)
                cubic_cc.update_rtt(sample_rtt_sec)
            
            # Calculate bytes newly acknowledged
            bytes_newly_acked = cum_ack - base_seq
            base_seq = cum_ack
            dup_ack_counts.clear()
            
            # Remove all acknowledged packets from in-flight window
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                in_flight_packets.pop(seq)
            
            # PART 2 ADDITION: Update CUBIC on successful ACK
            stats["bytes_acked"] += bytes_newly_acked
            cubic_cc.on_ack(bytes_newly_acked, time.time())
                
        elif cum_ack == base_seq:
            # --- 3. Process Duplicate ACK ---
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            # Fast Retransmit Trigger
            if base_seq in in_flight_packets:
                old_packet, _, retrans_count = in_flight_packets[base_seq]
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    print(f"--- FAST RETRANSMIT for seq {base_seq} ---")
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    # PART 2 ADDITION: Notify CUBIC of loss event
                    cubic_cc.on_loss_event('fast_retransmit')
                    
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[cum_ack] = 0
        
        # Try to send more packets after processing ACK
        try_send_next_packets(sock)

def ack_receiver_thread(sock):
    """Thread to continuously listen for ACK packets."""
    while not transfer_complete:
        try:
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

def run_server(server_ip, server_port):
    """
    PART 2 MODIFICATION: Main server logic with CUBIC congestion control.
    Removed SWS parameter - now using dynamic cwnd from CUBIC.
    """
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock, cubic_cc
    
    # PART 2 ADDITION: Initialize CUBIC congestion control
    cubic_cc = CubicCongestionControl()
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")
    print(cubic_cc.get_state_str())

    # --- 1. Wait for Connection Request ---
    while True:
        try:
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

    # --- 3. Start ACK Receiver Thread ---
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()

    # --- 4. Main Sender Loop ---
    start_time = time.time()
    last_state_print = time.time()
    
    # Send initial packets to fill the window
    with state_lock:
        try_send_next_packets(sock)
    
    while base_seq < file_size:
        with state_lock:
            # --- 4a. Check for Timeouts (RTO) ---
            current_time = time.time()
            packets_to_retransmit = []
            
            for seq, (packet, send_time, retrans_count) in list(in_flight_packets.items()):
                # Apply exponential backoff, capped at max_rto
                current_packet_rto = min(rtt_estimator.get_rto() * (2 ** retrans_count), rtt_estimator.max_rto)
                
                if current_time - send_time > current_packet_rto:
                    packets_to_retransmit.append(seq)
            
            for seq in packets_to_retransmit:
                if seq in in_flight_packets:
                    print(f"--- TIMEOUT for seq {seq} (RTO: {current_packet_rto:.2f}s) ---")
                    stats["packets_retransmitted"] += 1
                    stats["timeouts"] += 1
                    
                    # PART 2 ADDITION: Notify CUBIC of timeout (severe congestion)
                    cubic_cc.on_loss_event('timeout')
                    
                    old_packet, _st, retrans_count = in_flight_packets[seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[seq] = 0
            
            # Periodic state logging
            if current_time - last_state_print > 2.0:
                print(cubic_cc.get_state_str())
                last_state_print = current_time
        
        # Sleep briefly to prevent busy-looping
        time.sleep(0.001)

    # --- 5. Send EOF ---
    print("All file data acknowledged. Sending EOF.")
    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)

    # --- 6. Cleanup ---
    transfer_complete = True
    receiver_thread.join()
    sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput_mbps = (file_size * 8) / (total_time * 1_000_000) if total_time > 0 else 0
    
    print("\n--- Transfer Complete ---")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Throughput: {throughput_mbps:.2f} Mbps")
    print("Statistics:")
    print(f"  Packets Sent: {stats['packets_sent']}")
    print(f"  Packets Retransmitted: {stats['packets_retransmitted']}")
    print(f"  Timeouts: {stats['timeouts']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs Processed: {stats['sacks_processed']}")
    print(f"  Bytes Acknowledged: {stats['bytes_acked']}")
    print(f"  Final RTO: {rtt_estimator.get_rto():.3f}s")
    print(f"  Final SRTT: {rtt_estimator.srtt:.3f}s")
    print(cubic_cc.get_state_str())
    print("-------------------------\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)