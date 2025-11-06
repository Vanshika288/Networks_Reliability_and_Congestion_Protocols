import socket
import sys
import time
import struct
import threading
import math
# LOGGING ADDITION: Import matplotlib for plotting
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server environments
import matplotlib.pyplot as plt

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2
RTO_MULTIPLIER = 2


# ============================================================================
# PART 2: TCP CUBIC CONGESTION CONTROL HYPERPARAMETERS
# ============================================================================
CUBIC_C = 100                   # CUBIC scaling constant
CUBIC_BETA = 0.7                 # Multiplicative decrease factor (0.7 = 30% reduction)
INITIAL_CWND_MSS = 1             # Initial congestion window (in MSS units)
INITIAL_SSTHRESH_MSS = 220       # Initial slow start threshold (in MSS units)
MIN_CWND_MSS = 1                 # Minimum congestion window
MAX_CWND_MSS = 50000               # Maximum congestion window (safety limit)
MSS_BYTES = DATA_LEN             # Maximum Segment Size = 1180 bytes
FAST_RETRANSMIT_BETA = 0.9
INITIAL_W_MAX = INITIAL_SSTHRESH_MSS * 0.0

# CUBIC parameters
CUBIC_FAST_CONVERGENCE = True    # Enable fast convergence mode
CUBIC_TCP_FRIENDLINESS = True    # Enable TCP-friendliness mode

PACKET_CAP_TIMEOUT = 3
EXPONENTIAL_INC = 1
TIMEOUT_CWND_MULT = 0.95
FAST_RETRANSMIT_THRESHOLD = 0

# ============================================================================

# ============================================================================
# LOGGING ADDITION: Global data structures for tracking cwnd evolution
# ============================================================================
cwnd_log = []  # List of (timestamp, cwnd_mss, phase, event_type)
# event_type can be: 'normal', 'timeout', 'fast_retransmit', 'slow_start_exit'
rtt_log = []   # List of (timestamp, rtt_ms)
throughput_log = []  # List of (timestamp, throughput_mbps)
inflight_log = []  # List of (timestamp, bytes_in_flight)
# ============================================================================

# --- RTO Estimator (Jacobson/Karels Algorithm) ---
class RTOEstimator:
    def __init__(self, alpha=0.125, beta=0.25, initial_rto=1.0, min_rto=0.02, max_rto=60.0):
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
        
        self.rto = max(self.min_rto, min(RTO_MULTIPLIER*self.srtt + 4 * self.rttvar, self.max_rto))
        
        # LOGGING ADDITION: Print RTO updates
        print(f"[RTO_UPDATE] SRTT={self.srtt*1000:.2f}ms, RTTVAR={self.rttvar*1000:.2f}ms, RTO={self.rto:.3f}s")

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
        self.w_max = INITIAL_W_MAX             # Window size before last reduction
        self.k = 0.0                  # Time period for cwnd to grow to w_max
        self.epoch_start = 0.0        # Time when current epoch started
        self.origin_point = 0.0       # Origin point of cubic function
        self.tcp_cwnd = 0.0           # Estimated cwnd for TCP Reno (for friendliness)
        
        # RTT tracking for CUBIC
        self.min_rtt = float('inf')
        self.current_rtt = 1.0        # Default 1 second
        
        # LOGGING ADDITION: Track last cwnd value for change detection
        self.last_cwnd = self.cwnd
        
        print(f"[CUBIC_INIT] cwnd={self.cwnd:.2f} MSS, ssthresh={self.ssthresh:.2f} MSS")
        print(f"[CUBIC_INIT] CUBIC_C={CUBIC_C}, CUBIC_BETA={CUBIC_BETA}")
        print(f"[CUBIC_INIT] Fast Convergence: {CUBIC_FAST_CONVERGENCE}, TCP Friendliness: {CUBIC_TCP_FRIENDLINESS}")
    
    def update_rtt(self, rtt_sample):
        """Update RTT estimates for CUBIC calculations"""
        self.current_rtt = rtt_sample
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample
            # LOGGING ADDITION: Print when min RTT is updated
            print(f"[RTT_UPDATE] New min_rtt={self.min_rtt*1000:.2f}ms, current_rtt={self.current_rtt*1000:.2f}ms")
    
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
        
        # LOGGING ADDITION: Store old cwnd to detect changes
        old_cwnd = self.cwnd
        phase_before = "SLOW_START" if self.cwnd < self.ssthresh else "CONGESTION_AVOIDANCE"
        
        if self.cwnd < self.ssthresh:
            # === SLOW START PHASE ===
            # Exponential growth: increase by 1 MSS for each ACK
            self.cwnd += EXPONENTIAL_INC * acked_mss
            
            # LOGGING ADDITION: Print slow start growth
            if self.cwnd != old_cwnd:
                print(f"[SLOW_START] ACK for {bytes_acked} bytes ({acked_mss:.2f} MSS) | cwnd: {old_cwnd:.2f} -> {self.cwnd:.2f} MSS ({self.get_cwnd_bytes()} bytes) | ssthresh: {self.ssthresh:.2f} MSS")
            
            if self.cwnd >= self.ssthresh:
                print(f"[PHASE_CHANGE] *** EXITING SLOW START *** cwnd={self.cwnd:.2f} MSS >= ssthresh={self.ssthresh:.2f} MSS")
                print(f"[PHASE_CHANGE] *** ENTERING CONGESTION AVOIDANCE ***")
                # LOGGING ADDITION: Record phase change event
                cwnd_log.append((time.time(), self.cwnd, "SLOW_START_EXIT", "slow_start_exit"))
        else:
            # === CONGESTION AVOIDANCE PHASE ===
            # Use CUBIC function for window growth
            self._cubic_update(current_time)
            
            # LOGGING ADDITION: Print congestion avoidance growth
            if self.cwnd != old_cwnd:
                change = self.cwnd - old_cwnd
                print(f"[CONG_AVOID] cwnd: {old_cwnd:.2f} -> {self.cwnd:.2f} MSS (Δ={change:.4f}) ({self.get_cwnd_bytes()} bytes) | w_max={self.w_max:.2f}, tcp_cwnd={self.tcp_cwnd:.2f}")
        
        # Cap cwnd at maximum
        if self.cwnd > MAX_CWND_MSS:
            # LOGGING ADDITION: Warn if hitting max
            if old_cwnd <= MAX_CWND_MSS:
                print(f"[WARNING] cwnd capped at MAX_CWND_MSS={MAX_CWND_MSS}")
            self.cwnd = MAX_CWND_MSS
        
        # LOGGING ADDITION: Record cwnd change
        phase = "SLOW_START" if self.cwnd < self.ssthresh else "CONGESTION_AVOIDANCE"
        cwnd_log.append((time.time(), self.cwnd, phase, "normal"))
        
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
                # LOGGING ADDITION: Print epoch start with fast convergence
                print(f"[CUBIC_EPOCH] New epoch started | K={self.k:.3f}s, origin={self.origin_point:.2f}, w_max={self.w_max:.2f} (Fast Convergence)")
            else:
                self.k = 0.0
                self.origin_point = self.cwnd
                # LOGGING ADDITION: Print epoch start without fast convergence
                print(f"[CUBIC_EPOCH] New epoch started | K={self.k:.3f}s, origin={self.origin_point:.2f}, cwnd={self.cwnd:.2f}")
            
        self.tcp_cwnd = self.cwnd
        
        # Time since epoch start (in seconds)
        t = current_time + rtt_estimator.srtt - self.epoch_start
        
        # CUBIC function: W_cubic(t) = C * (t - K)^3 + W_max
        target = self.origin_point + CUBIC_C * math.pow(t - self.k, 3)
        
        # LOGGING ADDITION: Store for comparison
        cubic_target = target
        tcp_target = self.tcp_cwnd
        
        # === TCP-FRIENDLINESS CHECK ===
        if CUBIC_TCP_FRIENDLINESS:
            # Estimate what TCP Reno would do (AIMD: +1 MSS per RTT)
            # tcp_cwnd += 1 per RTT = 1 / cwnd per ACK
            self.tcp_cwnd += 1.0
            
            # Use TCP cwnd if it's larger (be fair to TCP flows)
            if self.tcp_cwnd > target:
                target = self.tcp_cwnd
                # LOGGING ADDITION: Print when TCP-friendliness is active
                if abs(self.tcp_cwnd - cubic_target) > 0.1:
                    print(f"[TCP_FRIENDLY] Using TCP target: tcp_cwnd={self.tcp_cwnd:.2f} > cubic_target={cubic_target:.2f} (t={t:.3f}s)")
        
        # Calculate increment based on RTT
        if target > self.cwnd:
            # Increase cwnd to approach target
            # Increment by (target - cwnd) / cwnd per ACK
            increment = (target - self.cwnd) / self.cwnd
            self.cwnd += increment
        else:
            # Already at or above target, slow growth
            self.cwnd += 1.0 / self.cwnd
    
    def on_loss_event(self, loss_type='timeout',retrans_count = 0):
        """
        PART 2 ADDITION: Called when packet loss is detected.
        Implements CUBIC's multiplicative decrease.
        
        loss_type: 'timeout' or 'fast_retransmit' (3 dup ACKs)
        """
        if loss_type == 'timeout':
            # Severe congestion: reset to slow start
            old_cwnd = self.cwnd
            old_ssthresh = self.ssthresh
            old_w_max = self.w_max
            
            self.ssthresh = max(self.cwnd * CUBIC_BETA, MIN_CWND_MSS)
            
            # Save w_max before reduction
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                # Fast convergence: reduce w_max
                self.w_max = self.cwnd
            else:
                self.w_max = self.cwnd
            
            self.cwnd = self.cwnd * TIMEOUT_CWND_MULT
            self.epoch_start = 0.0
            
            # LOGGING ADDITION: Detailed timeout event logging
            print(f"\n{'='*80}")
            print(f"[TIMEOUT_EVENT] *** SEVERE CONGESTION DETECTED ***")
            print(f"[TIMEOUT_EVENT] cwnd: {old_cwnd:.2f} -> {self.cwnd:.2f} MSS ({old_cwnd*MSS_BYTES} -> {self.get_cwnd_bytes()} bytes)")
            print(f"[TIMEOUT_EVENT] ssthresh: {old_ssthresh:.2f} -> {self.ssthresh:.2f} MSS")
            print(f"[TIMEOUT_EVENT] w_max: {old_w_max:.2f} -> {self.w_max:.2f} MSS")
            print(f"[TIMEOUT_EVENT] RESETTING TO SLOW START")
            print(f"{'='*80}\n")
            
            # LOGGING ADDITION: Record timeout event
            cwnd_log.append((time.time(), self.cwnd, "SLOW_START", "timeout"))
            
        elif loss_type == 'fast_retransmit' and retrans_count == FAST_RETRANSMIT_THRESHOLD:
            # Mild congestion: multiplicative decrease
            old_cwnd = self.cwnd
            old_ssthresh = self.ssthresh
            old_w_max = self.w_max
            
            # Save w_max before reduction
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                # Fast convergence
                self.w_max = self.cwnd
            else:
                self.w_max = self.cwnd
            
            # Reduce cwnd by (1 - beta)
            self.cwnd = max(self.cwnd * FAST_RETRANSMIT_BETA, MIN_CWND_MSS)
            self.ssthresh = self.cwnd
            
            # Reset epoch
            self.epoch_start = 0.0
            
            # LOGGING ADDITION: Detailed fast retransmit event logging
            print(f"\n{'='*80}")
            print(f"[FAST_RETX_EVENT] *** MILD CONGESTION DETECTED (3 DUP ACKs) ***")
            print(f"[FAST_RETX_EVENT] cwnd: {old_cwnd:.2f} -> {self.cwnd:.2f} MSS (×{CUBIC_BETA}) ({old_cwnd*MSS_BYTES} -> {self.get_cwnd_bytes()} bytes)")
            print(f"[FAST_RETX_EVENT] ssthresh: {old_ssthresh:.2f} -> {self.ssthresh:.2f} MSS")
            print(f"[FAST_RETX_EVENT] w_max: {old_w_max:.2f} -> {self.w_max:.2f} MSS")
            print(f"[FAST_RETX_EVENT] ENTERING CONGESTION AVOIDANCE")
            print(f"{'='*80}\n")
            
            # LOGGING ADDITION: Record fast retransmit event
            cwnd_log.append((time.time(), self.cwnd, "CONGESTION_AVOIDANCE", "fast_retransmit"))
        elif loss_type == 'fast_retransmit':
            # LOGGING ADDITION: Record fast retransmit event
            cwnd_log.append((time.time(), self.cwnd, "CONGESTION_AVOIDANCE", "fast_retransmit"))

    
    def get_state_str(self):
        """Return string representation of current state for logging"""
        phase = "SLOW_START" if self.cwnd < self.ssthresh else "CONGESTION_AVOIDANCE"
        return f"[CUBIC_STATE] cwnd={self.cwnd:.2f} MSS ({self.get_cwnd_bytes()} bytes), ssthresh={self.ssthresh:.2f} MSS, w_max={self.w_max:.2f}, phase={phase}"

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

# LOGGING ADDITION: Track transfer start time globally
transfer_start_time = 0.0

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
    
    # LOGGING ADDITION: Track packets sent in this burst
    packets_sent_this_call = 0
    
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
            packets_sent_this_call += 1
            next_seq += data_chunk_size
            in_flight_bytes += data_chunk_size
        except Exception as e:
            print(f"[ERROR] Failed to send packet at seq {next_seq}: {e}")
            break
    
    # LOGGING ADDITION: Print send burst info if packets were sent
    if packets_sent_this_call > 0:
        print(f"[SEND_BURST] Sent {packets_sent_this_call} packets | In-flight: {len(in_flight_packets)} pkts ({in_flight_bytes} bytes) | cwnd: {cwnd_bytes} bytes")
        # Record in-flight bytes
        inflight_log.append((time.time(), in_flight_bytes))

def process_ack(ack_packet):
    """
    PART 2 MODIFICATION: Process ACK and update CUBIC congestion control.
    """
    global base_seq, cubic_cc
    
    try:
        # Unpack ACK: Cum_ACK (I), TS_Echo (I), SACK_Start (I), SACK_End (I)
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_packet)
    except struct.error:
        print("[ERROR] Received malformed ACK.")
        return

    with state_lock:
        stats["acks_received"] += 1
        
        # LOGGING ADDITION: Track ACK details
        ack_time = time.time()
        
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
            
            # LOGGING ADDITION: Print SACK details
            if sack_keys:
                print(f"[SACK] Received SACK for {len(sack_keys)} packets: seqs={sack_keys[:5]}{'...' if len(sack_keys) > 5 else ''}")
            
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
                
                # LOGGING ADDITION: Record RTT sample
                rtt_log.append((ack_time, sample_rtt_ms))
            
            # Calculate bytes newly acknowledged
            bytes_newly_acked = cum_ack - base_seq
            old_base = base_seq
            base_seq = cum_ack
            dup_ack_counts.clear()
            
            # Remove all acknowledged packets from in-flight window
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                in_flight_packets.pop(seq)
            
            # LOGGING ADDITION: Print ACK details
            progress_pct = (base_seq / file_size * 100) if file_size > 0 else 0
            print(f"[ACK] Cum ACK for {bytes_newly_acked} bytes | base_seq: {old_base} -> {base_seq} | Progress: {progress_pct:.1f}% | In-flight: {len(in_flight_packets)} pkts")
            
            # PART 2 ADDITION: Update CUBIC on successful ACK
            stats["bytes_acked"] += bytes_newly_acked
            cubic_cc.on_ack(bytes_newly_acked, time.time())
                
        elif cum_ack == base_seq:
            # --- 3. Process Duplicate ACK ---
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            # LOGGING ADDITION: Print duplicate ACK info
            dup_count = dup_ack_counts[cum_ack]
            print(f"[DUP_ACK] Duplicate ACK #{dup_count} for seq={cum_ack}")
            
            # Fast Retransmit Trigger
            if base_seq in in_flight_packets:
                old_packet, _, retrans_count = in_flight_packets[base_seq]
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    print(f"\n[FAST_RETRANSMIT] *** Triggered at {dup_ack_counts[cum_ack]} dup ACKs for seq={base_seq} ***")
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    # PART 2 ADDITION: Notify CUBIC of loss event
                    
                    cubic_cc.on_loss_event('fast_retransmit',retrans_count)
                    
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
                print(f"[ERROR] ACK receiver error: {e}")
            break
    print("[THREAD] ACK receiver thread stopping.")

# ============================================================================
# LOGGING ADDITION: Function to generate plots
# ============================================================================
def generate_plots(output_prefix="p2_server"):
    """Generate visualization plots from logged data"""
    print("\n[PLOTTING] Generating visualization plots...")
    
    if not cwnd_log:
        print("[PLOTTING] No cwnd data to plot")
        return
    
    # Create figure with subplots
    fig, axes = plt.subplots(4, 1, figsize=(14, 16))
    fig.suptitle('TCP CUBIC Congestion Control Analysis', fontsize=16, fontweight='bold')
    
    # --- Plot 1: CWND Evolution ---
    ax1 = axes[0]
    
    # Extract data
    times = [t - transfer_start_time for t, _, _, _ in cwnd_log]
    cwnds = [c for _, c, _, _ in cwnd_log]
    
    # Plot main cwnd line
    ax1.plot(times, cwnds, 'b-', linewidth=1.5, label='CWND', alpha=0.7)
    
    # Mark events
    timeout_times = [t - transfer_start_time for t, _, _, evt in cwnd_log if evt == 'timeout']
    timeout_cwnds = [c for _, c, _, evt in cwnd_log if evt == 'timeout']
    
    fast_retx_times = [t - transfer_start_time for t, _, _, evt in cwnd_log if evt == 'fast_retransmit']
    fast_retx_cwnds = [c for _, c, _, evt in cwnd_log if evt == 'fast_retransmit']
    
    ss_exit_times = [t - transfer_start_time for t, _, _, evt in cwnd_log if evt == 'slow_start_exit']
    ss_exit_cwnds = [c for _, c, _, evt in cwnd_log if evt == 'slow_start_exit']
    
    if timeout_times:
        ax1.scatter(timeout_times, timeout_cwnds, color='red', s=100, marker='X', 
                   label=f'Timeout ({len(timeout_times)})', zorder=5)
    if fast_retx_times:
        ax1.scatter(fast_retx_times, fast_retx_cwnds, color='orange', s=100, marker='v', 
                   label=f'Fast Retransmit ({len(fast_retx_times)})', zorder=5)
    if ss_exit_times:
        ax1.scatter(ss_exit_times, ss_exit_cwnds, color='green', s=100, marker='^', 
                   label=f'SS Exit ({len(ss_exit_times)})', zorder=5)
    
    # Add ssthresh line (if we can extract it)
    ax1.axhline(y=INITIAL_SSTHRESH_MSS, color='gray', linestyle='--', 
               linewidth=1, label=f'Initial ssthresh ({INITIAL_SSTHRESH_MSS})', alpha=0.5)
    
    ax1.set_xlabel('Time (seconds)', fontsize=11)
    ax1.set_ylabel('Congestion Window (MSS)', fontsize=11)
    ax1.set_title('CWND Evolution Over Time', fontsize=12, fontweight='bold')
    ax1.legend(loc='best', fontsize=9)
    ax1.grid(True, alpha=0.3)
    
    # --- Plot 2: CWND in Bytes with Phase Coloring ---
    ax2 = axes[1]
    
    cwnd_bytes = [c * MSS_BYTES for c in cwnds]
    
    # Color by phase
    slow_start_mask = [ph == 'SLOW_START' for _, _, ph, _ in cwnd_log]
    cong_avoid_mask = [ph == 'CONGESTION_AVOIDANCE' for _, _, ph, _ in cwnd_log]
    
    if any(slow_start_mask):
        ss_times = [t for t, m in zip(times, slow_start_mask) if m]
        ss_cwnds = [c for c, m in zip(cwnd_bytes, slow_start_mask) if m]
        ax2.scatter(ss_times, ss_cwnds, c='lightblue', s=10, label='Slow Start', alpha=0.6)
    
    if any(cong_avoid_mask):
        ca_times = [t for t, m in zip(times, cong_avoid_mask) if m]
        ca_cwnds = [c for c, m in zip(cwnd_bytes, cong_avoid_mask) if m]
        ax2.scatter(ca_times, ca_cwnds, c='lightcoral', s=10, label='Congestion Avoidance', alpha=0.6)
    
    ax2.set_xlabel('Time (seconds)', fontsize=11)
    ax2.set_ylabel('Congestion Window (Bytes)', fontsize=11)
    ax2.set_title('CWND (Bytes) with Phase Indication', fontsize=12, fontweight='bold')
    ax2.legend(loc='best', fontsize=9)
    ax2.grid(True, alpha=0.3)
    
    # --- Plot 3: RTT Evolution ---
    ax3 = axes[2]
    
    if rtt_log:
        rtt_times = [t - transfer_start_time for t, _ in rtt_log]
        rtt_values = [r for _, r in rtt_log]
        
        ax3.plot(rtt_times, rtt_values, 'g-', linewidth=1, alpha=0.5, label='RTT samples')
        
        # Add moving average
        window = min(50, len(rtt_values) // 10 + 1)
        if len(rtt_values) >= window:
            rtt_ma = []
            for i in range(len(rtt_values)):
                start = max(0, i - window // 2)
                end = min(len(rtt_values), i + window // 2 + 1)
                rtt_ma.append(sum(rtt_values[start:end]) / (end - start))
            ax3.plot(rtt_times, rtt_ma, 'darkgreen', linewidth=2, label=f'Moving Avg (window={window})')
        
        ax3.set_xlabel('Time (seconds)', fontsize=11)
        ax3.set_ylabel('RTT (milliseconds)', fontsize=11)
        ax3.set_title('Round-Trip Time Evolution', fontsize=12, fontweight='bold')
        ax3.legend(loc='best', fontsize=9)
        ax3.grid(True, alpha=0.3)
    else:
        ax3.text(0.5, 0.5, 'No RTT data available', ha='center', va='center', 
                transform=ax3.transAxes, fontsize=12)
    
    # --- Plot 4: In-Flight Bytes ---
    ax4 = axes[3]
    
    if inflight_log:
        if_times = [t - transfer_start_time for t, _ in inflight_log]
        if_bytes = [b for _, b in inflight_log]
        
        ax4.plot(if_times, if_bytes, 'm-', linewidth=1.5, label='In-Flight Bytes', alpha=0.7)
        
        # Also plot cwnd for comparison
        ax4_twin = ax4.twinx()
        ax4_twin.plot(times, cwnd_bytes, 'b--', linewidth=1, label='CWND (bytes)', alpha=0.4)
        ax4_twin.set_ylabel('CWND (Bytes)', fontsize=11, color='b')
        ax4_twin.tick_params(axis='y', labelcolor='b')
        ax4_twin.legend(loc='upper right', fontsize=9)
        
        ax4.set_xlabel('Time (seconds)', fontsize=11)
        ax4.set_ylabel('In-Flight Bytes', fontsize=11, color='m')
        ax4.set_title('In-Flight Data vs CWND', fontsize=12, fontweight='bold')
        ax4.tick_params(axis='y', labelcolor='m')
        ax4.legend(loc='upper left', fontsize=9)
        ax4.grid(True, alpha=0.3)
    else:
        ax4.text(0.5, 0.5, 'No in-flight data available', ha='center', va='center', 
                transform=ax4.transAxes, fontsize=12)
    
    plt.tight_layout()
    
    # Save plot
    plot_filename = f"{output_prefix}_analysis.png"
    plt.savefig(plot_filename, dpi=150, bbox_inches='tight')
    print(f"[PLOTTING] Saved plot to {plot_filename}")
    plt.close()
    
    # # Also save raw data to CSV for external analysis
    # csv_filename = f"{output_prefix}_cwnd_log.csv"
    # with open(csv_filename, 'w') as f:
    #     f.write("time_sec,cwnd_mss,cwnd_bytes,phase,event\n")
    #     for t, c, ph, evt in cwnd_log:
    #         f.write(f"{t-transfer_start_time:.6f},{c:.2f},{c*MSS_BYTES:.0f},{ph},{evt}\n")
    # print(f"[PLOTTING] Saved cwnd data to {csv_filename}")
    
    # if rtt_log:
    #     rtt_csv = f"{output_prefix}_rtt_log.csv"
    #     with open(rtt_csv, 'w') as f:
    #         f.write("time_sec,rtt_ms\n")
    #         for t, r in rtt_log:
    #             f.write(f"{t-transfer_start_time:.6f},{r:.3f}\n")
    #     print(f"[PLOTTING] Saved RTT data to {rtt_csv}")

# ============================================================================

def run_server(server_ip, server_port, output_prefix="p2_server"):
    """
    PART 2 MODIFICATION: Main server logic with CUBIC congestion control.
    Removed SWS parameter - now using dynamic cwnd from CUBIC.
    
    Args:
        server_ip: Server IP address
        server_port: Server port number
        output_prefix: Prefix for output files (plots and logs)
    """
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock, cubic_cc
    global transfer_start_time  # LOGGING ADDITION
    
    # PART 2 ADDITION: Initialize CUBIC congestion control
    cubic_cc = CubicCongestionControl()
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"\n[SERVER] Listening on {server_ip}:{server_port}")
    print(cubic_cc.get_state_str())

    # --- 1. Wait for Connection Request ---
    print("\n[SERVER] Waiting for client connection...")
    while True:
        try:
            request, client_addr = sock.recvfrom(1)
            if request == b'\x01':
                print(f"[SERVER] Connection request received from {client_addr}")
                break
        except Exception as e:
            print(f"[ERROR] Error waiting for client: {e}")
            return

    # --- 2. Read File ---
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
        print(f"[SERVER] File 'data.txt' loaded: {file_size} bytes ({file_size/1024:.2f} KB)")
    except FileNotFoundError:
        print("[ERROR] File 'data.txt' not found")
        sock.close()
        return

    # --- 3. Start ACK Receiver Thread ---
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()
    print("[THREAD] ACK receiver thread started")

    # --- 4. Main Sender Loop ---
    print("\n" + "="*80)
    print("STARTING FILE TRANSFER")
    print("="*80 + "\n")
    
    transfer_start_time = time.time()  # LOGGING ADDITION
    start_time = time.time()
    last_state_print = time.time()
    last_progress_print = time.time()
    
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
            
            if len(packets_to_retransmit) > PACKET_CAP_TIMEOUT:
                cubic_cc.on_loss_event('timeout')
            
            for seq in packets_to_retransmit:
                if seq in in_flight_packets:
                    print(f"\n[TIMEOUT] *** Packet timeout detected *** seq={seq}, RTO={current_packet_rto:.2f}s")
                    stats["packets_retransmitted"] += 1
                    stats["timeouts"] += 1
                    
                    # PART 2 ADDITION: Notify CUBIC of timeout (severe congestion)
                    # cubic_cc.on_loss_event('timeout')
                    
                    old_packet, _st, retrans_count = in_flight_packets[seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[seq] = 0
            
            # Periodic state logging
            if current_time - last_state_print > 0.5:  # LOGGING CHANGE: More frequent (was 2.0s)
                print(f"\n{cubic_cc.get_state_str()}")
                print(f"[PROGRESS] {base_seq}/{file_size} bytes ({base_seq/file_size*100:.1f}%) | "
                      f"In-flight: {len(in_flight_packets)} pkts | "
                      f"Stats: {stats['packets_sent']} sent, {stats['packets_retransmitted']} retx, "
                      f"{stats['timeouts']} TO, {stats['fast_retransmits']} FR\n")
                last_state_print = current_time
        
        # Sleep briefly to prevent busy-looping
        time.sleep(0.001)

    # --- 5. Send EOF ---
    print("\n[SERVER] All data acknowledged. Sending EOF...")
    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)

    # LOGGING ADDITION: Generate plots
    generate_plots(output_prefix=output_prefix)
    # time.sleep(5)

    # --- 6. Cleanup ---
    transfer_complete = True
    receiver_thread.join()
    sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput_mbps = (file_size * 8) / (total_time * 1_000_000) if total_time > 0 else 0
    
    print("\n" + "="*80)
    print("TRANSFER COMPLETE")
    print("="*80)
    print(f"Total time: {total_time:.3f} seconds")
    print(f"Throughput: {throughput_mbps:.3f} Mbps")
    print(f"\nFinal Statistics:")
    print(f"  Packets Sent: {stats['packets_sent']}")
    print(f"  Packets Retransmitted: {stats['packets_retransmitted']}")
    print(f"  Timeouts: {stats['timeouts']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs Processed: {stats['sacks_processed']}")
    print(f"  Bytes Acknowledged: {stats['bytes_acked']}")
    print(f"  Final RTO: {rtt_estimator.get_rto():.3f}s")
    print(f"  Final SRTT: {rtt_estimator.srtt*1000:.2f}ms" if rtt_estimator.srtt > 0 else "  Final SRTT: N/A")
    print(f"\n{cubic_cc.get_state_str()}")
    print("="*80 + "\n")
    
    


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT> [OUTPUT_PREFIX]")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    OUTPUT_PREFIX = sys.argv[3] if len(sys.argv) > 3 else "p2_server"
    
    run_server(SERVER_IP, SERVER_PORT, OUTPUT_PREFIX)