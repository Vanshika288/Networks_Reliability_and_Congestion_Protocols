import socket
import sys
import time
import struct
import threading
import math

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN
MSS = DATA_LEN
EOF_MSG = b'EOF'

# --- Congestion Control Parameters ---
MIN_CWND = 4 * MSS
MAX_CWND = 1024 * MSS  # Don't grow unbounded
INIT_RTO = 1.0
MIN_RTO = 0.01
MAX_RTO = 60.0
FAST_RETRANSMIT_THRESHOLD = 3
CUBIC_BETA = 0.7  # CUBIC multiplicative decrease factor

# --- RTT Estimation (Jacobson/Karels) ---
class RTOEstimator:
    def __init__(self, alpha=0.125, beta=0.25, initial_rto=1.0):
        self.alpha = alpha
        self.beta = beta
        self.srtt = 0.0
        self.rttvar = 0.0
        self.rto = initial_rto
    
    def update(self, sample_rtt):
        """Update RTO based on new RTT sample (in seconds)"""
        if self.srtt == 0.0:
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        self.rto = max(MIN_RTO, min(self.srtt + 4 * self.rttvar, MAX_RTO))
    
    def get_rto(self):
        return self.rto

# --- Congestion Control Engine (Simplified Hybrid) ---
class CongestionControl:
    def __init__(self):
        self.cwnd = MIN_CWND  # Start with 4 MSS
        self.ssthresh = float('inf')
        self.rto_est = RTOEstimator(initial_rto=INIT_RTO)
        
        # State tracking
        self.state = "STARTUP"  # STARTUP or CONGESTION_AVOIDANCE
        self.bytes_acked_since_loss = 0
        self.rtt_samples = []
        self.srtt = None  # Smoothed RTT
        self.min_rtt = float('inf')
        
        # Loss/recovery tracking
        self.flight_start_seq = {}  # seq -> timestamp for in-flight packets
        self.last_loss_seq = -1
        self.recovery_seq = -1
        
    def on_ack(self, bytes_acked, rtt_sample, is_retransmit):
        """Handle ACK - grow cwnd appropriately"""
        
        # Karn's rule: don't use RTT from retransmitted packets
        if not is_retransmit and rtt_sample > 0:
            self.rto_est.update(rtt_sample)
            self.rtt_samples.append(rtt_sample)
            if self.srtt is None:
                self.srtt = rtt_sample
            else:
                self.srtt = 0.875 * self.srtt + 0.125 * rtt_sample
            self.min_rtt = min(self.min_rtt, rtt_sample)
        
        # Congestion window growth
        if self.state == "STARTUP":
            # Exponential growth: add full bytes_acked to cwnd
            self.cwnd = min(self.cwnd + bytes_acked, MAX_CWND)
            self.bytes_acked_since_loss += bytes_acked
            
            # Exit startup after 10 RTTs or when cwnd > 500 packets
            if len(self.rtt_samples) > 10 and self.cwnd > 500 * MSS:
                self.state = "CONGESTION_AVOIDANCE"
                print("[CC] Exiting STARTUP -> CONGESTION_AVOIDANCE")
        
        else:  # CONGESTION_AVOIDANCE
            # Additive increase: grow by 1 MSS per cwnd of bytes acked (CUBIC-like)
            self.bytes_acked_since_loss += bytes_acked
            if self.bytes_acked_since_loss >= self.cwnd:
                self.cwnd = min(self.cwnd + MSS, MAX_CWND)
                self.bytes_acked_since_loss = 0
    
    def on_loss(self, seq):
        """Handle packet loss - reduce cwnd"""
        if seq <= self.last_loss_seq:
            return  # Already handled this loss
        
        self.last_loss_seq = seq
        
        if self.state == "STARTUP":
            # Exit startup on first loss
            self.state = "CONGESTION_AVOIDANCE"
            self.ssthresh = max(2 * MSS, self.cwnd // 2)
            self.cwnd = self.ssthresh
            print(f"[CC] Loss in STARTUP: cwnd reduced to {self.cwnd/MSS:.0f} MSS")
        else:
            # CUBIC-style multiplicative decrease
            self.ssthresh = max(2 * MSS, int(self.cwnd * CUBIC_BETA))
            self.cwnd = self.ssthresh
            print(f"[CC] Loss in CA: cwnd reduced to {self.cwnd/MSS:.0f} MSS")
    
    def get_cwnd(self):
        return self.cwnd

# --- Global State ---
cc = CongestionControl()
in_flight = {}  # {seq: (packet, send_time, retransmit_count)}
dup_ack_count = {}  # {seq: count}
base_seq = 0
next_seq = 0
file_data = b''
file_size = 0
client_addr = None
transfer_done = False
sock = None
state_lock = threading.Lock()

stats = {
    "packets_sent": 0,
    "packets_retransmitted": 0,
    "acks_received": 0,
    "fast_retransmits": 0,
}

def make_packet(seq, data, ts_ms):
    """Create packet with header"""
    header = struct.pack(PACKET_FORMAT, seq, ts_ms, 0, 0, b'\x00'*4)
    return header + data

def process_ack(ack_data):
    """Process incoming ACK"""
    global base_seq
    
    if len(ack_data) < HEADER_LEN:
        return
    
    try:
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_data[:HEADER_LEN])
    except:
        return
    
    with state_lock:
        stats["acks_received"] += 1
        
        # Check if base was retransmitted (for Karn's rule)
        is_base_retrans = False
        if base_seq in in_flight:
            _, _, retrans_count = in_flight[base_seq]
            is_base_retrans = (retrans_count > 0)
        
        # Process SACK
        if sack_start > 0 and sack_end > sack_start:
            for seq in list(in_flight.keys()):
                if sack_start <= seq < sack_end:
                    del in_flight[seq]
        
        # Process cumulative ACK
        if cum_ack > base_seq:
            # Calculate RTT sample
            rtt = 0
            if not is_base_retrans and ts_echo > 0:
                current_ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
                rtt_ms = (current_ts_ms - ts_echo) & 0xFFFFFFFF
                # Sanity check on RTT
                if 0 < rtt_ms < 60000:  # 0-60 seconds
                    rtt = rtt_ms / 1000.0
            
            bytes_acked = cum_ack - base_seq
            cc.on_ack(bytes_acked, rtt, is_base_retrans)
            
            # Remove acknowledged packets
            keys_to_remove = [seq for seq in in_flight if seq < cum_ack]
            for seq in keys_to_remove:
                del in_flight[seq]
            
            base_seq = cum_ack
            dup_ack_count.clear()
        
        elif cum_ack == base_seq:
            # Duplicate ACK
            dup_ack_count[cum_ack] = dup_ack_count.get(cum_ack, 0) + 1
            
            # Fast retransmit on 3 duplicate ACKs
            if dup_ack_count[cum_ack] == FAST_RETRANSMIT_THRESHOLD:
                if base_seq in in_flight:
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    cc.on_loss(base_seq)
                    
                    old_pkt, _, retrans_count = in_flight[base_seq]
                    data = old_pkt[HEADER_LEN:]
                    new_pkt = make_packet(base_seq, data, int(time.time() * 1000) & 0xFFFFFFFF)
                    sock.sendto(new_pkt, client_addr)
                    in_flight[base_seq] = (new_pkt, time.time(), retrans_count + 1)
                dup_ack_count[cum_ack] = 0

def ack_listener(s):
    """Thread to listen for ACKs"""
    while not transfer_done:
        try:
            s.settimeout(0.5)
            ack_pkt, _ = s.recvfrom(MAX_PAYLOAD_SIZE)
            if ack_pkt:
                process_ack(ack_pkt)
        except socket.timeout:
            continue
        except:
            break

def send_packet(seq, data):
    """Send a single packet with current timestamp"""
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
    pkt = make_packet(seq, data, ts_ms)
    sock.sendto(pkt, client_addr)
    in_flight[seq] = (pkt, time.time(), 0)
    stats["packets_sent"] += 1

def run_server(server_ip, server_port):
    """Main server loop"""
    global next_seq, base_seq, client_addr, transfer_done, sock, file_data, file_size
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")
    
    # Wait for connection
    while not transfer_done:
        try:
            req, client_addr = sock.recvfrom(1)
            if req == b'\x01':
                print(f"Client connected: {client_addr}")
                break
        except:
            pass
    
    # Read file
    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
            file_size = len(file_data)
            print(f"Loaded data.txt: {file_size} bytes")
    except FileNotFoundError:
        print("ERROR: data.txt not found")
        sock.close()
        return
    
    # Start ACK listener
    ack_thread = threading.Thread(target=ack_listener, args=(sock,), daemon=True)
    ack_thread.start()
    
    start_time = time.time()
    last_log = start_time
    
    # Main sender loop
    while base_seq < file_size:
        with state_lock:
            current_time = time.time()
            
            # Log every second
            if current_time - last_log > 1.0:
                elapsed = current_time - start_time
                progress = 100.0 * base_seq / file_size
                throughput = (base_seq * 8 / (elapsed * 1e6)) if elapsed > 0 else 0
                print(f"[{elapsed:.1f}s] {progress:.1f}%, cwnd={cc.cwnd/MSS:.0f}MSS, "
                      f"inflight={len(in_flight)}, thr={throughput:.1f}Mbps")
                last_log = current_time
            
            # Check for timeouts and retransmit
            for seq in list(in_flight.keys()):
                pkt, send_time, retrans_count = in_flight[seq]
                rto = cc.rto_est.get_rto() * (2 ** min(retrans_count, 5))
                
                if current_time - send_time > rto:
                    stats["packets_retransmitted"] += 1
                    cc.on_loss(seq)
                    data = pkt[HEADER_LEN:]
                    new_pkt = make_packet(seq, data, int(current_time * 1000) & 0xFFFFFFFF)
                    sock.sendto(new_pkt, client_addr)
                    in_flight[seq] = (new_pkt, current_time, retrans_count + 1)
            
            # Send new packets up to cwnd limit
            inflight_bytes = sum(len(pkt[HEADER_LEN:]) for pkt, _, _ in in_flight.values())
            
            while inflight_bytes < cc.cwnd and next_seq < file_size:
                chunk_size = min(DATA_LEN, file_size - next_seq)
                chunk = file_data[next_seq:next_seq + chunk_size]
                send_packet(next_seq, chunk)
                next_seq += chunk_size
                inflight_bytes += chunk_size
        
        time.sleep(0.001)  # Small sleep to avoid busy loop
    
    # Send EOF
    print("Transfer complete. Sending EOF...")
    eof_pkt = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(10):
        sock.sendto(eof_pkt, client_addr)
        time.sleep(0.05)
    
    # Cleanup
    transfer_done = True
    ack_thread.join(timeout=1)
    sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput = (file_size * 8) / (total_time * 1e6) if total_time > 0 else 0
    
    print("\n=== Transfer Summary ===")
    print(f"Time: {total_time:.2f}s")
    print(f"Throughput: {throughput:.2f} Mbps")
    print(f"Final cwnd: {cc.cwnd/MSS:.0f} MSS")
    print(f"Packets sent: {stats['packets_sent']}")
    print(f"Retransmitted: {stats['packets_retransmitted']}")
    print(f"ACKs received: {stats['acks_received']}")
    print(f"Fast retransmits: {stats['fast_retransmits']}")
    print(f"Loss rate: {100*stats['packets_retransmitted']/max(1, stats['packets_sent']):.2f}%")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <IP> <PORT>")
        sys.exit(1)
    
    run_server(sys.argv[1], int(sys.argv[2]))