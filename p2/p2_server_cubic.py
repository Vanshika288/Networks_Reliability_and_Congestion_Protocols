import socket
import sys
import time
import struct
import threading
import random

# --- Constants ---
MAX_PAYLOAD_SIZE = 1200
# Header: Seq (I=4B) + Timestamp (I=4B) + SACK_Start (I=4B) + SACK_End (I=4B) + Padding (4s=4B)
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s' # 4+4+4+4+4 = 20 bytes
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN # 1180 bytes
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2

# --- CUBIC CHANGE: CUBIC Hyperparameters ---
MSS = DATA_LEN  # Max Segment Size in bytes (data only)
INITIAL_CWND = 1 * MSS
CUBIC_C = 0.4
CUBIC_BETA_DECREASE = 0.7 # Multiplicative decrease factor (cwnd = cwnd * B)
CUBIC_BETA_K = 1.0 - CUBIC_BETA_DECREASE # This is the 'beta' from the slide's K formula

# --- RTO Estimator (Jacobson/Karels Algorithm) ---
class RTOEstimator:
    def __init__(self, alpha=0.125, beta=0.25, initial_rto=1.0, min_rto=0.2, max_rto=60.0): # --- CUBIC CHANGE: Set min_rto to 200ms ---
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
        # print("Updated RTO: {:.3f}s, SRTT: {:.3f}s, RTTVAR: {:.3f}s".format(self.rto, self.srtt, self.rttvar))

    def get_rto(self):
        return self.rto
    
    def get_srtt(self):
        """Get the smoothed RTT."""
        return self.srtt

# --- Global Server State ---
rtt_estimator = RTOEstimator()
in_flight_packets = {}  # {seq: (packet, send_time_sec, retransmit_count)}
dup_ack_counts = {}   # {seq: count}
base_seq = 0            # Cumulative ACK (lowest byte in window)
next_seq = 0            # Next byte to be sent
file_data = b''
file_size = 0
# SWS = 0                 # --- CUBIC CHANGE: SWS is removed ---
client_addr = None
transfer_complete = False
state_lock = threading.RLock()

# --- CUBIC CHANGE: Congestion Control State Variables ---
cwnd = INITIAL_CWND
ssthresh = float('inf') # Start with "infinite" ssthresh
congestion_state = "SLOW_START" # States: "SLOW_START", "CONGESTION_AVOIDANCE"
w_max = 0.0             # Window max (W_max) from CUBIC formula
t_epoch = 0.0           # Time of last congestion event
k_cubic = 0.0           # K from CUBIC formula
last_loss_seq = -1      # Track last sequence number that triggered congestion

# --- Statistics ---
stats = {
    "packets_sent": 0,
    "packets_retransmitted": 0,
    "acks_received": 0,
    "sacks_processed": 0,
    "fast_retransmits": 0,
    "timeouts": 0 # --- CUBIC CHANGE: Added timeout stat ---
}

def make_packet(seq, data, timestamp_ms):
    """Creates a data packet with the 20-byte header."""
    # SACK fields (sack_start, sack_end) are 0 for data packets
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

# --- CUBIC CHANGE: New function to handle congestion events ---
def handle_congestion_event(is_timeout):
    """
    Called on Fast Retransmit or RTO to update CUBIC state.
    """
    global cwnd, ssthresh, w_max, t_epoch, k_cubic, congestion_state, last_loss_seq
    
    t_epoch = time.time() # Record time of congestion
    w_max = cwnd          # Store current window as W_max
    
    # Calculate new ssthresh (multiplicative decrease)
    ssthresh = cwnd * CUBIC_BETA_DECREASE
    
    # Calculate K (time to reach W_max again) using the slide's formula
    # K = cubic_root(W_max * beta / C)
    try:
        k_cubic = ((w_max * CUBIC_BETA_K) / CUBIC_C) ** (1/3.0)
    except ZeroDivisionError:
        k_cubic = 0.0

    if is_timeout:
        # Timeout is severe. Reset to slow start.
        stats["timeouts"] += 1
        cwnd = INITIAL_CWND
        congestion_state = "SLOW_START"
        print(f"--- CONGESTION (TIMEOUT) ---")
    else:
        # Fast Retransmit. Set new cwnd and enter CUBIC avoidance.
        stats["fast_retransmits"] += 1
        cwnd = ssthresh
        congestion_state = "CONGESTION_AVOIDANCE"
        print(f"--- CONGESTION (FAST RETRANSMIT) ---")

    print(f"  w_max={w_max:.0f}, ssthresh={ssthresh:.0f}, cwnd={cwnd:.0f}, K={k_cubic:.2f}")
    
    # Mark the packet that caused this, to avoid multiple reductions per window
    last_loss_seq = base_seq


def try_send_next_packets(sock):
    """
    Fill the congestion window as long as space is available.
    """
    global next_seq, file_size, stats, in_flight_packets, cwnd

    with state_lock:
        # --- CUBIC CHANGE: Window check is now byte-based using cwnd ---
        # Calculate in-flight bytes
        in_flight_bytes = next_seq - base_seq
        
        while (in_flight_bytes + DATA_LEN) <= cwnd and next_seq < file_size:
            data_chunk_size = min(DATA_LEN, file_size - next_seq)
            data_chunk = file_data[next_seq : next_seq + data_chunk_size]
            timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF

            packet = make_packet(next_seq, data_chunk, timestamp_ms)
            sock.sendto(packet, client_addr)

            in_flight_packets[next_seq] = (packet, time.time(), 0)
            stats["packets_sent"] += 1
            next_seq += data_chunk_size
            
            # Update in-flight bytes for next loop iteration
            in_flight_bytes = next_seq - base_seq

def process_ack(ack_packet):
    """Processes an incoming ACK packet."""
    global base_seq, congestion_state, cwnd, ssthresh
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
            # sack_end is the bitmap, sack_start is the offset
            for i in range(32):
                if (sack_end >> i) & 1:
                    sacked_seq = sack_start + (i) * DATA_LEN
                    sacked_packets.append(sacked_seq)

            sack_keys = [seq for seq in list(in_flight_packets.keys())
                        if seq in sacked_packets]
            # print(f"--- SACK received for seqs {sack_keys} ---")

            for seq in sack_keys:
                if seq in in_flight_packets: # Check if not already acked
                    in_flight_packets.pop(seq)


        # --- 2. Process Cumulative ACK ---
        if cum_ack > base_seq:
            if not was_base_retransmitted:
                # --- RTT Update (Karn's Rule) ---
                current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                rtt_estimator.update(sample_rtt_ms / 1000.0)
            
            # --- CUBIC CHANGE: Handle CWND increase on new ACK ---
            bytes_acked = cum_ack - base_seq
            
            if congestion_state == "SLOW_START":
                cwnd += bytes_acked # Aggressive exponential growth (1 MSS per ACK)
                if cwnd >= ssthresh:
                    congestion_state = "CONGESTION_AVOIDANCE"
                    # print("--- SLOW START -> CONGESTION AVOIDANCE ---")
                    
            elif congestion_state == "CONGESTION_AVOIDANCE":
                # --- CUBIC Growth Logic ---
                current_time = time.time()
                t_elapsed = current_time - t_epoch
                
                # Calculate target W_cubic(t) using the slide's formula
                target_cwnd = CUBIC_C * ((t_elapsed - k_cubic) ** 3) + w_max
                
                # Get current RTT (or RTO as fallback)
                srtt = rtt_estimator.get_srtt()
                rtt = srtt if srtt > 0.0 else rtt_estimator.get_rto()

                # Calculate W_tcp (Reno-style growth for TCP friendliness)
                # w_tcp(t) = w_max * beta_decrease + 3*(1-beta_decrease)/(1+beta_decrease) * (t/RTT) * MSS
                # We use a simpler Reno AI: 1 MSS / RTT
                w_tcp_increase_per_rtt = (MSS * MSS) / cwnd
                
                if target_cwnd > cwnd:
                    # Convex growth (probing)
                    # Increase = (W_cubic(t) - cwnd) / cwnd
                    cwnd_increase = ((target_cwnd - cwnd) / cwnd) * MSS
                else:
                    # Concave growth (TCP friendly)
                    # Use standard Reno Additive Increase
                    cwnd_increase = w_tcp_increase_per_rtt
                
                # Scale increase per ACK (not per RTT)
                # An RTT has (cwnd / MSS) packets.
                # Increase per ACK = Increase_per_RTT / (cwnd / MSS)
                if cwnd > 0:
                    cwnd += (cwnd_increase * MSS) / cwnd
                else:
                    cwnd += INITIAL_CWND # Safety check

            # --- End CUBIC CHANGE ---
            
            base_seq = cum_ack
            dup_ack_counts.clear() # Reset duplicate ACK counter
            
            # Remove all acknowledged packets from in-flight window
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                if seq in in_flight_packets: # Check if not SACKed
                    in_flight_packets.pop(seq)
                
        elif cum_ack == base_seq:
            # --- 3. Process Duplicate ACK ---
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            if base_seq in in_flight_packets:
                old_packet, _, retrans_count = in_flight_packets[base_seq]
                # Fast Retransmit Trigger
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    
                    # --- CUBIC CHANGE: Trigger congestion event ---
                    # Only trigger if this packet hasn't caused a reduction before
                    if base_seq > last_loss_seq:
                        handle_congestion_event(is_timeout=False)
                    
                    stats["packets_retransmitted"] += 1
                    
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[cum_ack] = 0 # Reset after retransmit
                    
        # --- CUBIC CHANGE: Try to send more packets after processing ACK ---
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
    # print("ACK receiver thread stopping.")

def run_server(server_ip, server_port): # --- CUBIC CHANGE: Removed sws argument ---
    """Main server logic."""
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock
    global cwnd, ssthresh, congestion_state, t_epoch, k_cubic # --- CUBIC CHANGE: Init globals ---
    
    # --- CUBIC CHANGE: Initialize CC state ---
    cwnd = INITIAL_CWND
    ssthresh = float('inf')
    congestion_state = "SLOW_START"
    t_epoch = time.time()
    k_cubic = 0.0
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port} with CUBIC CC")

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
        ssthresh = file_size # Set initial ssthresh to file size (effectively infinite)
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
    while base_seq < file_size:
        with state_lock:
            # --- 4a. Check for Timeouts (RTO) ---
            current_time = time.time()
            packets_to_retransmit = []
            
            for seq, (packet, send_time, retrans_count) in in_flight_packets.items():
                current_packet_rto = min(rtt_estimator.get_rto() * (2 ** retrans_count), rtt_estimator.max_rto)
                
                if current_time - send_time > current_packet_rto:
                    packets_to_retransmit.append(seq)
            
            # --- CUBIC CHANGE: Handle RTO as congestion event ---
            if packets_to_retransmit:
                seq_to_retransmit = min(packets_to_retransmit) # Retransmit lowest timed-out packet
                
                if seq_to_retransmit in in_flight_packets: # Check if not SACKed
                    print(f"--- TIMEOUT for seq {seq_to_retransmit} ---")
                    
                    # Trigger congestion event *only if* it's a new loss
                    if seq_to_retransmit > last_loss_seq:
                        handle_congestion_event(is_timeout=True)
                        # After timeout, CUBIC resets cwnd=1MSS and enters SLOW_START
                        # We must also clear the dup_ack_counts
                        dup_ack_counts.clear()

                    stats["packets_retransmitted"] += 1
                    old_packet, _st, retrans_count = in_flight_packets[seq_to_retransmit]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq_to_retransmit, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq_to_retransmit] = (new_packet, time.time(), retrans_count + 1)
                    
                    # After a timeout, don't send new packets immediately.
                    # Let the retransmit go out and wait for its ACK.
                    # We continue the loop to check for other timeouts if any.
                    continue 

            # --- 4b. Send New Packets ---
            # --- CUBIC CHANGE: Use byte-based cwnd check ---
            in_flight_bytes = next_seq - base_seq
            while (in_flight_bytes + DATA_LEN) <= cwnd and next_seq < file_size:
                data_chunk_size = min(DATA_LEN, file_size - next_seq)
                data_chunk = file_data[next_seq : next_seq + data_chunk_size]
                timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                
                packet = make_packet(next_seq, data_chunk, timestamp_ms)
                sock.sendto(packet, client_addr)
                
                in_flight_packets[next_seq] = (packet, time.time(), 0)
                stats["packets_sent"] += 1
                next_seq += data_chunk_size
                in_flight_bytes = next_seq - base_seq # Update for loop check
        
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
    print(f"  Timeouts: {stats['timeouts']}")
    print(f"  Fast Retransmits: {stats['fast_retransmits']}")
    print(f"  ACKs Received: {stats['acks_received']}")
    print(f"  SACKs Processed: {stats['sacks_processed']}")
    print(f"  Final RTO: {rtt_estimator.get_rto():.3f}s")
    print(f"  Final SRTT: {rtt_estimator.srtt:.3f}s")
    print("-------------------------\n")


if __name__ == "__main__":
    # --- CUBIC CHANGE: Updated command-line arguments ---
    if len(sys.argv) != 3:
        print("Usage: python3 p2_server.py <SERVER_IP> <SERVER_PORT>")
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)