import socket
import sys
import time
import struct
import threading
import math

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'  # Seq(4) + TS(4) + SACK_Start(4) + SACK_End(4) + Padding(4)
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN  # 1180 bytes
EOF_MSG = b'EOF'
MSS = 1180  # Maximum Segment Size in bytes

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
        
        self.rto = max(self.min_rto, min(self.srtt + 4 * self.rttvar, self.max_rto))

    def get_rto(self):
        return self.rto


# --- TCP Compound Congestion Control ---
class CompoundTCP:
    """
    TCP Compound: Hybrid loss-based and delay-based congestion control
    Provides excellent fairness (especially RTT fairness) while maintaining high utilization.
    """
    
    def __init__(self, mss=MSS, initial_cwnd=10.0):
        # Loss-based window (Reno-style AIMD)
        self.cwnd = initial_cwnd          # Congestion window in packets
        self.ssthresh = 100000.0          # Slow start threshold (very high = stay in SS longer)
        
        # Delay-based window (Vegas-style)
        self.dwnd = 0.0                   # Delay window component in packets
        self.base_rtt = float('inf')      # Minimum observed RTT (seconds)
        self.last_rtt = 0.001             # Most recent RTT
        
        # Adaptive gamma (target queue size in packets)
        self.gamma = 50.0                 # INCREASED: Initial target queue
        self.gamma_min = 10.0             # INCREASED: Allow more queuing
        self.gamma_max = 100.0            # INCREASED: Much higher ceiling
        
        # CTCP parameters - TUNED FOR AGGRESSIVE GROWTH
        self.alpha = 1.0                  # INCREASED 8x: Much faster dwnd growth
        self.beta = 0.3                   # DECREASED: Less aggressive reduction (keep more window)
        self.eta = 0.5                    # DECREASED: Slower dwnd decrease
        self.k = 0.5                      # DECREASED: More linear growth (faster)
        self.LOW_WINDOW = 10              # DECREASED: Activate CTCP much earlier
        self.lambda_ewma = 0.2            # INCREASED: Faster gamma adaptation
        
        # State tracking
        self.mss = mss
        self.rtt_samples = []             # List of (timestamp, rtt) tuples
        self.last_dwnd_update = 0.0       # Time of last dwnd update
        self.in_fast_recovery = False     # Fast recovery state
        self.dup_ack_count = 0
        self.recovery_seq = 0
        
        # Statistics
        self.stats = {
            'cwnd_reductions': 0,
            'dwnd_increases': 0,
            'dwnd_decreases': 0,
            'gamma_updates': 0,
            'timeouts': 0
        }
    
    def update_rtt(self, rtt_sample):
        """
        Update RTT estimates with outlier filtering.
        Critical for delay-based component accuracy.
        """
        if rtt_sample <= 0 or rtt_sample > 300:  # Sanity check (5 min max)
            return False
        
        # Filter obvious outliers if we have a baseline
        if self.base_rtt < float('inf'):
            if rtt_sample < 0.5 * self.base_rtt:  # ACK compression
                return False
            if rtt_sample > 10 * self.base_rtt:   # Anomaly
                return False
        
        # Update minimum RTT (base RTT)
        self.base_rtt = min(self.base_rtt, rtt_sample)
        self.last_rtt = rtt_sample
        
        # Keep recent samples for analysis
        now = time.time()
        self.rtt_samples.append((now, rtt_sample))
        
        # Maintain only last 10 seconds of samples
        cutoff = now - 10.0
        self.rtt_samples = [(t, r) for t, r in self.rtt_samples if t > cutoff]
        
        return True
    
    def should_update_dwnd(self):
        """Rate-limit dwnd updates to approximately once per RTT"""
        if self.last_rtt <= 0:
            return False
        
        now = time.time()
        # FIXED: Update more frequently (every 0.5 RTT instead of 0.8)
        if now - self.last_dwnd_update >= self.last_rtt * 0.5:
            self.last_dwnd_update = now
            return True
        return False
    
    def update_delay_window(self):
        """
        Update delay-based window component.
        Core of CTCP's fairness mechanism.
        FIXED: Much more aggressive growth for better utilization
        """
        if self.base_rtt >= float('inf') or self.base_rtt == 0:
            return
        
        if self.last_rtt <= 0:
            return
        
        # Calculate expected vs actual throughput (in packets/second)
        total_wnd = self.cwnd + self.dwnd
        expected_throughput = total_wnd / self.base_rtt  # Packets/sec if no queue
        actual_throughput = total_wnd / self.last_rtt    # Actual packets/sec
        
        # Queuing delay in terms of packets
        diff = (expected_throughput - actual_throughput) * self.base_rtt
        
        if diff < self.gamma:
            # Network under-utilized: increase aggressively
            # FIXED: Much more aggressive growth
            if self.dwnd < 1.0:
                increment = self.alpha * 10  # Bootstrap faster
            else:
                # Linear-ish growth for faster convergence
                increment = self.alpha * max(1.0, pow(self.dwnd, self.k))
            
            self.dwnd = max(0, self.dwnd + increment)
            self.stats['dwnd_increases'] += 1
        else:
            # Congestion detected: decrease proportionally
            decrement = self.eta * diff
            self.dwnd = max(0, self.dwnd - decrement)
            self.stats['dwnd_decreases'] += 1
    
    def update_adaptive_gamma(self):
        """
        CRITICAL: Adaptive gamma tuning - CTCP's secret weapon for fairness.
        Emulates standard TCP to estimate fair buffer share.
        """
        if self.base_rtt >= float('inf') or self.last_rtt <= 0:
            return
        
        # Emulate what Reno would observe
        total_wnd = self.cwnd + self.dwnd
        expected_reno = total_wnd / self.base_rtt
        actual_reno = total_wnd / self.last_rtt
        diff_reno = (expected_reno - actual_reno) * self.base_rtt
        
        if diff_reno > 0:
            # Sample the backlog Reno would observe
            gamma_sample = 0.75 * diff_reno
            
            # EWMA smoothing
            self.gamma = (1 - self.lambda_ewma) * self.gamma + self.lambda_ewma * gamma_sample
            
            # Clamp to reasonable range
            self.gamma = max(self.gamma_min, min(self.gamma_max, self.gamma))
            self.stats['gamma_updates'] += 1
    
    def on_ack(self, bytes_acked, rtt_sample):
        """
        Process ACK and update congestion windows.
        Called for each new ACK (cumulative or SACK).
        """
        # Update RTT estimates
        if not self.update_rtt(rtt_sample):
            return self.get_cwnd_packets()
        
        # Number of packets acked
        packets_acked = bytes_acked / self.mss
        
        # Exit fast recovery if we've recovered
        if self.in_fast_recovery:
            # Still in recovery, don't update windows
            return self.get_cwnd_packets()
        
        total_wnd = self.cwnd + self.dwnd
        
        # Below threshold: use standard TCP Reno behavior
        if total_wnd < self.LOW_WINDOW:
            if self.cwnd < self.ssthresh:
                # Slow start: exponential growth
                self.cwnd += packets_acked
            else:
                # Congestion avoidance: linear growth
                self.cwnd += packets_acked / self.cwnd
            
            # CRITICAL FIX: Also update dwnd even below LOW_WINDOW
            if self.should_update_dwnd():
                self.update_delay_window()
            
            return self.get_cwnd_packets()
        
        # CTCP mode: update loss-based component
        if self.cwnd >= self.ssthresh:
            # Congestion avoidance - FIXED: Use cwnd only for denominator
            # This makes growth faster and more aggressive
            self.cwnd += packets_acked / self.cwnd
        else:
            # Slow start
            self.cwnd += packets_acked
        
        # Update delay-based component (rate-limited to ~1 per RTT)
        if self.should_update_dwnd():
            self.update_delay_window()
        
        return self.get_cwnd_packets()
    
    def on_loss(self, loss_type='timeout'):
        """
        Handle packet loss event.
        Updates windows and adaptive gamma.
        """
        # CRITICAL: Update adaptive gamma before reducing windows
        self.update_adaptive_gamma()
        
        if loss_type == 'fast_retransmit':
            # Fast retransmit (3 dup ACKs)
            self.ssthresh = max(2.0, (self.cwnd + self.dwnd) / 2.0)
            self.cwnd = self.ssthresh
            self.dwnd = self.dwnd * (1 - self.beta)
            
            # Enter fast recovery
            self.in_fast_recovery = True
            
        else:  # timeout
            # Timeout: more severe reduction
            self.ssthresh = max(2.0, (self.cwnd + self.dwnd) / 2.0)
            self.cwnd = 1.0
            self.dwnd = 0.0
            
            # Reset RTT estimates to re-measure
            self.base_rtt = float('inf')
            self.rtt_samples.clear()
            
            self.stats['timeouts'] += 1
        
        self.stats['cwnd_reductions'] += 1
        return self.get_cwnd_packets()
    
    def on_fast_recovery_exit(self):
        """Exit fast recovery mode"""
        self.in_fast_recovery = False
        self.dup_ack_count = 0
    
    def get_cwnd_packets(self):
        """Return current congestion window in packets"""
        return int(max(1, self.cwnd + self.dwnd))
    
    def get_cwnd_bytes(self):
        """Return current congestion window in bytes"""
        return int(self.get_cwnd_packets() * self.mss)
    
    def get_stats(self):
        """Return statistics dictionary"""
        return {
            'cwnd': self.cwnd,
            'dwnd': self.dwnd,
            'total_wnd': self.cwnd + self.dwnd,
            'ssthresh': self.ssthresh,
            'base_rtt': self.base_rtt if self.base_rtt < float('inf') else 0,
            'last_rtt': self.last_rtt,
            'gamma': self.gamma,
            **self.stats
        }


# --- Global Server State ---
cca = None              # Congestion control algorithm
rto_estimator = None
in_flight_packets = {}  # {seq: (packet, send_time, retrans_count)}
dup_ack_counts = {}     # {seq: count}
base_seq = 0            # Cumulative ACK
next_seq = 0            # Next byte to send
file_data = b''
file_size = 0
client_addr = None
transfer_complete = False
state_lock = threading.Lock()
sock = None

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
    """Creates a data packet with 20-byte header"""
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data


def process_ack(ack_packet):
    """Process incoming ACK packet"""
    global base_seq, cca
    
    try:
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_packet)
    except struct.error:
        return
    
    with state_lock:
        stats["acks_received"] += 1
        current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
        
        # Check if base was retransmitted (Karn's Rule)
        was_base_retransmitted = False
        if base_seq in in_flight_packets:
            _, _, retrans_count = in_flight_packets[base_seq]
            was_base_retransmitted = (retrans_count > 0)
        
        # --- 1. Process SACKs ---
        if sack_start < sack_end:
            stats["sacks_processed"] += 1
            sack_keys = [seq for seq in list(in_flight_packets.keys())
                        if sack_start <= seq < sack_end]
            
            for seq in sack_keys:
                packet, send_time, _ = in_flight_packets.pop(seq)
                # Don't update CCA for SACKed packets to avoid over-counting
        
        # --- 2. Process Cumulative ACK ---
        if cum_ack > base_seq:
            # Calculate bytes newly acknowledged
            bytes_newly_acked = cum_ack - base_seq
            stats["bytes_acked"] += bytes_newly_acked
            
            # Calculate RTT for CCA update (only if not retransmitted)
            rtt_sample = 0.001  # Default 1ms
            if not was_base_retransmitted:
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                rtt_sample = max(0.001, sample_rtt_ms / 1000.0)
                rto_estimator.update(rtt_sample)
            
            # Update congestion control
            new_cwnd = cca.on_ack(bytes_newly_acked, rtt_sample)
            
            # Exit fast recovery if we're past recovery point
            if cca.in_fast_recovery and cum_ack >= cca.recovery_seq:
                cca.on_fast_recovery_exit()
            
            # Update base and remove acked packets
            base_seq = cum_ack
            dup_ack_counts.clear()
            
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                in_flight_packets.pop(seq)
        
        elif cum_ack == base_seq:
            # --- 3. Duplicate ACK ---
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            # Fast Retransmit on 3rd duplicate
            if dup_ack_counts[cum_ack] == 3:
                if base_seq in in_flight_packets:
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    # Update CCA for loss
                    cca.recovery_seq = next_seq  # Set recovery point
                    cca.on_loss('fast_retransmit')
                    
                    # Retransmit
                    old_packet, _, retrans_count = in_flight_packets[base_seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)


def ack_receiver_thread(sock):
    """Thread to receive ACKs"""
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


def run_server(server_ip, server_port):
    """Main server logic"""
    global file_data, file_size, next_seq, base_seq, client_addr
    global transfer_complete, sock, cca, rto_estimator
    
    # Initialize congestion control
    cca = CompoundTCP(mss=MSS, initial_cwnd=10.0)
    rto_estimator = RTOEstimator()
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")
    print("Using TCP Compound congestion control")
    
    # --- 1. Wait for connection ---
    while True:
        try:
            request, client_addr = sock.recvfrom(1)
            if request == b'\x01':
                print(f"Connection from {client_addr}")
                break
        except Exception as e:
            print(f"Error: {e}")
            return
    
    # --- 2. Read file ---
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
        print(f"File: data.txt ({file_size} bytes)")
    except FileNotFoundError:
        print("Error: data.txt not found")
        sock.close()
        return
    
    # --- 3. Start ACK receiver ---
    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.daemon = True
    receiver_thread.start()
    
    # --- 4. Main sender loop ---
    start_time = time.time()
    last_stats_time = start_time
    
    while base_seq < file_size:
        with state_lock:
            current_time = time.time()
            
            # --- 4a. Check timeouts ---
            packets_to_retransmit = []
            for seq, (packet, send_time, retrans_count) in in_flight_packets.items():
                current_rto = min(rto_estimator.get_rto() * (2 ** retrans_count), 
                                 rto_estimator.max_rto)
                if current_time - send_time > current_rto:
                    packets_to_retransmit.append(seq)
            
            for seq in packets_to_retransmit:
                if seq in in_flight_packets:
                    stats["timeouts"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    # Update CCA for timeout
                    cca.on_loss('timeout')
                    
                    old_packet, _, retrans_count = in_flight_packets[seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
            
            # --- 4b. Send new packets within cwnd ---
            cwnd_bytes = cca.get_cwnd_bytes()
            in_flight_bytes = sum(len(pkt) - HEADER_LEN for pkt, _, _ in in_flight_packets.values())
            
            while in_flight_bytes < cwnd_bytes and next_seq < file_size:
                data_chunk_size = min(DATA_LEN, file_size - next_seq)
                data_chunk = file_data[next_seq : next_seq + data_chunk_size]
                timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                
                packet = make_packet(next_seq, data_chunk, timestamp_ms)
                sock.sendto(packet, client_addr)
                
                in_flight_packets[next_seq] = (packet, time.time(), 0)
                stats["packets_sent"] += 1
                in_flight_bytes += data_chunk_size
                next_seq += data_chunk_size
            
            # --- 4c. Print stats every 5 seconds ---
            if current_time - last_stats_time >= 5.0:
                cca_stats = cca.get_stats()
                elapsed = current_time - start_time
                throughput = (stats["bytes_acked"] * 8) / (elapsed * 1e6) if elapsed > 0 else 0
                print(f"[{elapsed:.1f}s] Progress: {base_seq}/{file_size} "
                      f"({100*base_seq/file_size:.1f}%) | "
                      f"CWND: {cca_stats['cwnd']:.1f} | DWND: {cca_stats['dwnd']:.1f} | "
                      f"Gamma: {cca_stats['gamma']:.1f} | "
                      f"BaseRTT: {cca_stats['base_rtt']*1000:.1f}ms | "
                      f"Throughput: {throughput:.2f} Mbps")
                last_stats_time = current_time
        
        time.sleep(0.0001)  # Brief sleep
    
    # --- 5. Send EOF ---
    print("All data acknowledged. Sending EOF...")
    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)
    
    # --- 6. Cleanup ---
    transfer_complete = True
    receiver_thread.join(timeout=2.0)
    sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput = (file_size * 8) / (total_time * 1e6) if total_time > 0 else 0
    
    print("\n" + "="*60)
    print("TRANSFER COMPLETE")
    print("="*60)
    print(f"Total Time: {total_time:.2f}s")
    print(f"File Size: {file_size} bytes")
    print(f"Throughput: {throughput:.2f} Mbps")
    print(f"\nPacket Statistics:")
    print(f"  Sent: {stats['packets_sent']}")
    print(f"  Retransmitted: {stats['packets_retransmitted']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs: {stats['sacks_processed']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  Timeouts: {stats['timeouts']}")
    
    cca_stats = cca.get_stats()
    print(f"\nCongestion Control (TCP Compound):")
    print(f"  Final CWND: {cca_stats['cwnd']:.2f} packets")
    print(f"  Final DWND: {cca_stats['dwnd']:.2f} packets")
    print(f"  Final Gamma: {cca_stats['gamma']:.2f} packets")
    print(f"  CWND Reductions: {cca_stats['cwnd_reductions']}")
    print(f"  Base RTT: {cca_stats['base_rtt']*1000:.2f} ms")
    print("="*60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)