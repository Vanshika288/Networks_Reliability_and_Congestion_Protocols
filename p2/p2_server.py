import socket
import sys
import time
import struct
import threading
import math

MAX_PAYLOAD_SIZE = 1200
HEADER_LEN = 20
PACKET_FORMAT = '!IIII4s'
DATA_LEN = MAX_PAYLOAD_SIZE - HEADER_LEN
EOF_MSG = b'EOF'
FAST_RETRANSMIT_K = 2
RTO_MULTIPLIER = 2

CUBIC_C = 100
CUBIC_BETA = 0.7
INITIAL_CWND_MSS = 1
INITIAL_SSTHRESH_MSS = 220
MIN_CWND_MSS = 1
MAX_CWND_MSS = 50000
MSS_BYTES = DATA_LEN
FAST_RETRANSMIT_BETA = 0.9
INITIAL_W_MAX = INITIAL_SSTHRESH_MSS * 0.0

CUBIC_FAST_CONVERGENCE = True
CUBIC_TCP_FRIENDLINESS = True

PACKET_CAP_TIMEOUT = 3
EXPONENTIAL_INC = 1
TIMEOUT_CWND_MULT = 0.95
FAST_RETRANSMIT_THRESHOLD = 0

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
        if self.srtt == 0.0:
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
        else:
            delta = abs(self.srtt - sample_rtt)
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * delta
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * sample_rtt
        
        self.rto = max(self.min_rto, min(RTO_MULTIPLIER*self.srtt + 4 * self.rttvar, self.max_rto))

    def get_rto(self):
        return self.rto

class CubicCongestionControl:
    def __init__(self):
        self.cwnd = float(INITIAL_CWND_MSS)
        self.ssthresh = float(INITIAL_SSTHRESH_MSS)
        self.w_max = INITIAL_W_MAX
        self.k = 0.0
        self.epoch_start = 0.0
        self.origin_point = 0.0
        self.tcp_cwnd = 0.0
        self.min_rtt = float('inf')
        self.current_rtt = 1.0
    
    def update_rtt(self, rtt_sample):
        self.current_rtt = rtt_sample
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample
    
    def get_cwnd_bytes(self):
        return int(self.cwnd * MSS_BYTES)
    
    def on_ack(self, bytes_acked, current_time):
        if self.cwnd < MIN_CWND_MSS:
            self.cwnd = MIN_CWND_MSS
        
        acked_mss = bytes_acked / float(MSS_BYTES)
        
        if self.cwnd < self.ssthresh:
            self.cwnd += EXPONENTIAL_INC * acked_mss
        else:
            self._cubic_update(current_time)
        
        if self.cwnd > MAX_CWND_MSS:
            self.cwnd = MAX_CWND_MSS
        
        return self.get_cwnd_bytes()
    
    def _cubic_update(self, current_time):
        if self.epoch_start == 0.0:
            self.epoch_start = current_time
            if self.cwnd < self.w_max:
                self.k = math.pow((self.w_max - self.cwnd) / CUBIC_C, 1.0/3.0)
                self.origin_point = self.w_max
            else:
                self.k = 0.0
                self.origin_point = self.cwnd
            
        self.tcp_cwnd = self.cwnd
        
        t = current_time + rtt_estimator.srtt - self.epoch_start
        
        target = self.origin_point + CUBIC_C * math.pow(t - self.k, 3)
        
        if CUBIC_TCP_FRIENDLINESS:
            self.tcp_cwnd += 1.0
            
            if self.tcp_cwnd > target:
                target = self.tcp_cwnd
        
        if target > self.cwnd:
            increment = (target - self.cwnd) / self.cwnd
            self.cwnd += increment
        else:
            self.cwnd += 1.0 / self.cwnd
    
    def on_loss_event(self, loss_type='timeout',retrans_count = 0):
        if loss_type == 'timeout':
            self.ssthresh = max(self.cwnd * CUBIC_BETA, MIN_CWND_MSS)
            
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                self.w_max = self.cwnd
            else:
                self.w_max = self.cwnd
            
            self.cwnd = self.cwnd * TIMEOUT_CWND_MULT
            self.epoch_start = 0.0
            
        elif loss_type == 'fast_retransmit' and retrans_count == FAST_RETRANSMIT_THRESHOLD:
            if self.cwnd < self.w_max and CUBIC_FAST_CONVERGENCE:
                self.w_max = self.cwnd
            else:
                self.w_max = self.cwnd
            
            self.cwnd = max(self.cwnd * FAST_RETRANSMIT_BETA, MIN_CWND_MSS)
            self.ssthresh = self.cwnd
            
            self.epoch_start = 0.0

rtt_estimator = RTOEstimator()
cubic_cc = None

in_flight_packets = {}
dup_ack_counts = {}
base_seq = 0
next_seq = 0
file_data = b''
file_size = 0
client_addr = None
transfer_complete = False
state_lock = threading.RLock()

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
    header = struct.pack(PACKET_FORMAT, seq, timestamp_ms, 0, 0, b'\x00'*4)
    return header + data

def try_send_next_packets(sock):
    global next_seq, file_size, stats, in_flight_packets, cubic_cc

    cwnd_bytes = cubic_cc.get_cwnd_bytes()
    in_flight_bytes = sum(len(pkt[0]) - HEADER_LEN for pkt in in_flight_packets.values())
    
    while in_flight_bytes < cwnd_bytes and next_seq < file_size:
        data_chunk_size = min(DATA_LEN, file_size - next_seq)
        
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
        except Exception:
            break

def process_ack(ack_packet):
    global base_seq, cubic_cc
    
    try:
        cum_ack, ts_echo, sack_start, sack_end, _ = struct.unpack(PACKET_FORMAT, ack_packet)
    except struct.error:
        return

    with state_lock:
        stats["acks_received"] += 1
        
        ack_time = time.time()
        
        was_base_retransmitted = False
        if base_seq in in_flight_packets:
            _packet, _send_time, retrans_count = in_flight_packets[base_seq]
            if retrans_count > 0:
                was_base_retransmitted = True
        
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

        if cum_ack > base_seq:
            if not was_base_retransmitted:
                current_time_ms = int(time.time() * 1000) & 0xFFFFFFFF
                sample_rtt_ms = (current_time_ms - ts_echo) & 0xFFFFFFFF
                sample_rtt_sec = sample_rtt_ms / 1000.0
                rtt_estimator.update(sample_rtt_sec)
                cubic_cc.update_rtt(sample_rtt_sec)
            
            bytes_newly_acked = cum_ack - base_seq
            base_seq = cum_ack
            dup_ack_counts.clear()
            
            acked_keys = [seq for seq in in_flight_packets if seq < cum_ack]
            for seq in acked_keys:
                in_flight_packets.pop(seq)
            
            stats["bytes_acked"] += bytes_newly_acked
            cubic_cc.on_ack(bytes_newly_acked, time.time())
                
        elif cum_ack == base_seq:
            dup_ack_counts[cum_ack] = dup_ack_counts.get(cum_ack, 0) + 1
            
            if base_seq in in_flight_packets:
                old_packet, _, retrans_count = in_flight_packets[base_seq]
                if dup_ack_counts[cum_ack] == 3 + FAST_RETRANSMIT_K * retrans_count:
                    stats["fast_retransmits"] += 1
                    stats["packets_retransmitted"] += 1
                    
                    cubic_cc.on_loss_event('fast_retransmit',retrans_count)
                    
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(base_seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    
                    in_flight_packets[base_seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[cum_ack] = 0
        
        try_send_next_packets(sock)

def ack_receiver_thread(sock):
    while not transfer_complete:
        try:
            sock.settimeout(1.0)
            ack_packet, _ = sock.recvfrom(MAX_PAYLOAD_SIZE)
            if ack_packet:
                process_ack(ack_packet)
        except socket.timeout:
            continue
        except Exception:
            if not transfer_complete:
                break

def run_server(server_ip, server_port):
    global file_data, file_size, next_seq, base_seq, client_addr, transfer_complete, sock, cubic_cc
    
    cubic_cc = CubicCongestionControl()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    while True:
        try:
            request, client_addr = sock.recvfrom(1)
            if request == b'\x01':
                break
        except Exception:
            return

    try:
        with open('data.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
    except FileNotFoundError:
        sock.close()
        return

    receiver_thread = threading.Thread(target=ack_receiver_thread, args=(sock,))
    receiver_thread.start()

    start_time = time.time()
    
    with state_lock:
        try_send_next_packets(sock)
    
    while base_seq < file_size:
        with state_lock:
            current_time = time.time()
            packets_to_retransmit = []
            
            for seq, (packet, send_time, retrans_count) in list(in_flight_packets.items()):
                current_packet_rto = min(rtt_estimator.get_rto() * (2 ** retrans_count), rtt_estimator.max_rto)
                
                if current_time - send_time > current_packet_rto:
                    packets_to_retransmit.append(seq)
            
            if len(packets_to_retransmit) > PACKET_CAP_TIMEOUT:
                cubic_cc.on_loss_event('timeout')
            
            for seq in packets_to_retransmit:
                if seq in in_flight_packets:
                    stats["packets_retransmitted"] += 1
                    stats["timeouts"] += 1
                    
                    old_packet, _st, retrans_count = in_flight_packets[seq]
                    data_chunk = old_packet[HEADER_LEN:]
                    new_timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
                    new_packet = make_packet(seq, data_chunk, new_timestamp_ms)
                    sock.sendto(new_packet, client_addr)
                    in_flight_packets[seq] = (new_packet, time.time(), retrans_count + 1)
                    dup_ack_counts[seq] = 0
        
        time.sleep(0.001)

    eof_packet = make_packet(file_size, EOF_MSG, int(time.time() * 1000) & 0xFFFFFFFF)
    for _ in range(5):
        sock.sendto(eof_packet, client_addr)
        time.sleep(0.01)

    transfer_complete = True
    receiver_thread.join()
    sock.close()
    
    end_time = time.time()
    total_time = end_time - start_time
    throughput_mbps = (file_size * 8) / (total_time * 1_000_000) if total_time > 0 else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    
    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    
    run_server(SERVER_IP, SERVER_PORT)