from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import Controller
import time, re, os
import sys
import hashlib
import shutil
import tempfile


RTT_MS = 40         
MSS_BYTES = 1200        

class DumbbellTopo(Topo):
    def build(self, delay_c2_sw1='5ms', bw=100, loss=0, buffer_size=420):
        # Create hosts: two TCP clients/servers 
        c1 = self.addHost('c1')
        c2 = self.addHost('c2')
        s1 = self.addHost('s1')
        s2 = self.addHost('s2')

        # Create switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')

        # Links: client->sw and server->sw links
        # c1 -- sw1 
        self.addLink(c1, sw1, delay='5ms')
        # c2 -- sw1 
        self.addLink(c2, sw1, delay=delay_c2_sw1)

        # s1 -- sw2 (server 1 side)
        self.addLink(s1, sw2, delay='5ms')
        # s2 -- sw2 (server 2 side)
        self.addLink(s2, sw2, delay='5ms')

        # Link between sw1 and sw2 (bottleneck link): set bw, loss, queue size, and one-way delay
        self.addLink(sw1, sw2, bw=bw, delay='10ms', loss=loss, max_queue_size=buffer_size)

        print(f"[topo] bottleneck bw={bw} Mbps, loss={loss}%, buffer={buffer_size} pkts, bot_delay=10ms")


class DumbbellTopoWithUDP(Topo):
    def build(self, delay_c2_sw1='5ms', bw=100, loss=0, buffer_size=420):
        # Create hosts: two TCP clients/servers plus an extra client/server pair for UDP background
        c1 = self.addHost('c1')
        c2 = self.addHost('c2')
        s1 = self.addHost('s1')
        s2 = self.addHost('s2')
        # Extra host pair for UDP background
        c3 = self.addHost('c3')
        s3 = self.addHost('s3')

        # Create switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')

        # Links: client->sw and server->sw links
        # c1 -- sw1 
        self.addLink(c1, sw1, delay='5ms')
        # c2 -- sw1 
        self.addLink(c2, sw1, delay=delay_c2_sw1)
        # extra client for UDP
        self.addLink(c3, sw1, delay='5ms')

        # s1 -- sw2 (server 1 side)
        self.addLink(s1, sw2, delay='5ms')
        # s2 -- sw2 (server 2 side)
        self.addLink(s2, sw2, delay='5ms')
        # extra UDP receiver server
        self.addLink(s3, sw2, delay='5ms')

        # Link between sw1 and sw2 (bottleneck link): set bw, loss, queue size, and one-way delay
        self.addLink(sw1, sw2, bw=bw, delay='10ms', loss=loss, max_queue_size=buffer_size)

        print(f"[topo] (with UDP) bottleneck bw={bw} Mbps, loss={loss}%, buffer={buffer_size} pkts, bot_delay=10ms")




def jain_fairness_index(allocations):
    n = len(allocations)
    if n == 0:
        return 0.0
    sum_of_allocations = sum(allocations)
    sum_of_squares = sum(x ** 2 for x in allocations)
    if sum_of_squares == 0:
        return 0.0
    jfi = (sum_of_allocations ** 2) / (n * sum_of_squares)
    return jfi


def compute_md5(file_path):
    """Compute the MD5 hash of a file on the controller host (local filesystem).
    Returns hex digest or None if file doesn't exist."""
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        # file not present on controller filesystem
        return None


def get_file_size_bytes(file_path):
    try:
        return os.path.getsize(file_path)
    except Exception:
        return None

def run_trial(output_handle, bw=100, loss=0, delay_c2_ms=5, udp_off_mean=None, iteration=0, buffer_size=420):
    setLogLevel('info')
    import time

    controller_ip = '127.0.0.1'
    controller_port = 6653

    # prefixes used by the client (must match client's behavior)
    pref_c1 = "1"
    pref_c2 = "2"
    SERVER_IP1 = "10.0.0.3"  # s1
    SERVER_PORT1 = 6555
    SERVER_IP2 = "10.0.0.4"  # s2
    SERVER_PORT2 = 6556

    OUTFILE = 'received_data.txt'  # client's receives are expected as {pref}received_data.txt
    print(f"--- Running trial: bw={bw}Mbps loss={loss}% delay_c2={delay_c2_ms}ms  udp_off_mean={udp_off_mean} iter={iteration} ---")

    # Build topology 
    topo = DumbbellTopo(delay_c2_sw1=f"{delay_c2_ms}ms", bw=bw, loss=loss, buffer_size=buffer_size)
    
    net = Mininet(topo=topo, link=TCLink, controller=None)
    remote_controller = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(remote_controller)
    net.start()

    # get hosts (c1,c2,c3 and s1,s2,s3 )
    c1 = net.get('c1')
    c2 = net.get('c2')
    s1 = net.get('s1')
    s2 = net.get('s2')

    # Start servers on s1 and s2 and capture their PIDs 
    
    s1_pid_raw = s1.cmd(f"bash -c 'python3 p2_server.py {s1.IP()} {SERVER_PORT1} > /tmp/s1_server.out 2>&1 & echo $!'").strip()
    s2_pid_raw = s2.cmd(f"bash -c 'python3 p2_server.py {s2.IP()} {SERVER_PORT2} > /tmp/s2_server.out 2>&1 & echo $!'").strip()
    s1_pid = s1_pid_raw.split()[0] if s1_pid_raw else None
    s2_pid = s2_pid_raw.split()[0] if s2_pid_raw else None
    print(f"started server s1 pid: {s1_pid}, s2 pid: {s2_pid}")
    time.sleep(1)


    # Startclients on c1 and c2 and capture PIDs 
    
    c1_start_cmd = f"python3 p2_client.py {s1.IP()} {SERVER_PORT1} {pref_c1}"
    c2_start_cmd = f"python3 p2_client.py {s2.IP()} {SERVER_PORT2} {pref_c2}"
    
    start_time_c1 = time.time()
    start_time_c2 = time.time()

    c1_pid_raw = c1.cmd(f"bash -c '{c1_start_cmd} > /tmp/{pref_c1}.out 2>&1 & echo $!'").strip()
    c2_pid_raw = c2.cmd(f"bash -c '{c2_start_cmd} > /tmp/{pref_c2}.out 2>&1 & echo $!'").strip()
    if c1_pid_raw:
        c1_pid = c1_pid_raw.split()[0]
        print(f"started client 1 with PID: {c1_pid}")
    else:
        print(" warning: no pid returned for client1 start; will use pgrep to detect completion")
        c1_pid = None

    if c2_pid_raw:
        c2_pid = c2_pid_raw.split()[0]
        print(f"started client 2 with PID: {c2_pid}")
    else:
        print(" warning: no pid returned for client2 start; will use pgrep to detect completion")
        c2_pid = None

    

    end_time_c1 = None
    end_time_c2 = None


    while end_time_c1 is None or end_time_c2 is None:
        if end_time_c1 is None:
            try:
                pg_c1 = c1.cmd(f"ps -p {c1_pid} -o pid= || true").strip()
                if not pg_c1:
                    end_time_c1 = time.time()
                    print(f" client 1 completed at {end_time_c1}")
            except Exception as e:
                print("error checking client1:", e)
                end_time_c1 = time.time()
        if end_time_c2 is None:
            try:
                pg_c2 = c2.cmd(f"ps -p {c2_pid} -o pid= || true").strip()
                if not pg_c2:
                    end_time_c2 = time.time()
                    print(f"client 2 completed at {end_time_c2}")
            except Exception as e:
                print("error checking client2:", e)
                end_time_c2 = time.time()

    print(f"client 1 finished at {end_time_c1}, client 2 finished at {end_time_c2}")

    # --- Kill any remaining server processes if still running ---
    print("stopping  servers (if still active)")
    s1.cmd("pkill -f p2_server.py || true")
    s2.cmd("pkill -f p2_server.py || true")
    time.sleep(1)


    # Stop the network
    net.stop()

    # compute durations
    dur_c1 = max(end_time_c1 - start_time_c1, 1e-9)
    dur_c2 = max(end_time_c2 - start_time_c2, 1e-9)

    # compute MD5s using controller-local files
    hash1 = compute_md5(f"{pref_c1}received_data.txt")
    hash2 = compute_md5(f"{pref_c2}received_data.txt")

    # compute file sizes if available on controller
    size1 = get_file_size_bytes(f"{pref_c1}received_data.txt")
    size2 = get_file_size_bytes(f"{pref_c2}received_data.txt")

    # compute throughputs (Mbps) if sizes are available, else use 1/duration as a proxy
    if size1 is not None:
        thr1_mbps = (size1 * 8) / (dur_c1 * 1e6)
    else:
        thr1_mbps = (1.0 / dur_c1)

    if size2 is not None:
        thr2_mbps = (size2 * 8) / (dur_c2 * 1e6)
    else:
        thr2_mbps = (1.0 / dur_c2)

    # compute link utilization: sum of measured throughputs divided by bottleneck capacity
    link_util = None
    try:
        link_util = (thr1_mbps + thr2_mbps) / float(bw)
    except Exception:
        link_util = None

    # compute fairness using original script's approach: jfi on [1/dur1, 1/dur2]
    allocs = [1.0 / dur_c1, 1.0 / dur_c2]
    jfi = jain_fairness_index(allocs)

    # write CSV line - include experiment-relevant columns
    # Columns: bw,loss,delay_c2,udp_off_mean,iter,md5_1,md5_2,dur1,dur2,size1_bytes,size2_bytes,thr1_mbps,thr2_mbps,link_util,jfi
    output_handle.write(f"{bw},{loss},{delay_c2_ms},{udp_off_mean},{iteration},{hash1},{hash2},{dur_c1:.6f},{dur_c2:.6f},{size1},{size2},{thr1_mbps:.6f},{thr2_mbps:.6f},{link_util:.6f},{jfi:.6f}\n")
    output_handle.flush()

    print(f"dur1={dur_c1:.3f}s dur2={dur_c2:.3f}s size1={size1} size2={size2} thr1={thr1_mbps:.3f} thr2={thr2_mbps:.3f} link_util={link_util:.3f} jfi={jfi:.3f}")



def experiment_fixed_bandwidth(exp_out, num_iterations=1):

    bw_list = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    RTT_seconds = RTT_MS / 1000.0

    for bw in bw_list:
        # compute buffer size in packets according to formula buffer = RTT * BW
        bw_bps = bw * 1e6
        buf_packets = max(1, int((RTT_seconds * bw_bps) / (MSS_BYTES * 8)))
        print(f"[fixed_bw] bw={bw}Mbps -> buffer_size={buf_packets} packets (RTT={RTT_MS}ms)")
        for i in range(num_iterations):
            run_trial(exp_out, bw=bw,  iteration=i, buffer_size=buf_packets)


def experiment_varying_loss(exp_out, num_iterations=1):
    loss_rates = [0.0, 0.5, 1.0, 1.5, 2.0]
    for loss in loss_rates:
        for i in range(num_iterations):
            run_trial(exp_out, loss=loss, iteration=i)


def experiment_asymmetric_flows(exp_out, num_iterations=1):
    for delay_c2 in range(5, 26, 5):  
        for i in range(num_iterations):
            run_trial(exp_out, delay_c2_ms=delay_c2, iteration=i)


def experiment_background_udp(exp_out, num_iterations=1):
    pass


def run():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 p2_exp.py {Exp_Name} Available Exp_Name values: fixed_bandwidth, varying_loss, asymmetric_flows, background_udp")
        sys.exit(1)

    exp_name = sys.argv[1]

    output_file = f'p2_fairness_{exp_name}.csv'
    header = "bw,loss,delay_c2_ms,udp_off_mean,iter,md5_hash_1,md5_hash_2,ttc1,ttc2,size1_bytes,size2_bytes,thr1_mbps,thr2_mbps,link_util,jfi \n" 
    first_run = not os.path.exists(output_file)
    f_out = open(output_file, 'w')
    if first_run:
        f_out.write(header)

    try:
        if exp_name == 'fixed_bandwidth':
            experiment_fixed_bandwidth(f_out)
        elif exp_name == 'varying_loss':
            experiment_varying_loss(f_out)
        elif exp_name == 'asymmetric_flows':
            experiment_asymmetric_flows(f_out)
        elif exp_name == 'background_udp':
            pass
        else:
            print(f"Unknown experiment name: {exp_name}")
    finally:
        f_out.close()
        print("--- Completed experiments ---")


if __name__ == '__main__':
    run()
