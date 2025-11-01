import socket
import sys
import time
import random

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 udp_server.py <server_ip> <server_port> <off_mean_seconds>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    off_mean_seconds = float(sys.argv[3])
    
    # Create UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    
    print(f"UDP Server started on {server_ip}:{server_port}")
    print(f"OFF period mean: {off_mean_seconds} seconds")
    
    PACKETS_PER_BURST = 1000   
    PACKET_SIZE = 1500         
    BURST_RATE = 0.00001       
    
    client_addr = None
    
    try:
        while True:
            # Wait for client to connect (receive first packet)
            if client_addr is None:
                data, addr = server_socket.recvfrom(1024)
                client_addr = addr
                print(f"UDP client connected from {addr}")
            
            # ON period: send burst
            burst_start = time.time()
            print(f"UDP ON period: sending {PACKETS_PER_BURST} packets...")
            for i in range(PACKETS_PER_BURST):
                packet_data = f"UDP_BURST_{i}_{int(time.time())}".encode()
                if len(packet_data) < PACKET_SIZE:
                    packet_data += b'X' * (PACKET_SIZE - len(packet_data))
                
                server_socket.sendto(packet_data, client_addr)
                time.sleep(BURST_RATE) 
            
            burst_duration = time.time() - burst_start
            burst_throughput = (PACKETS_PER_BURST * PACKET_SIZE * 8) / (burst_duration * 1e6)  
            print(f"UDP burst completed in {burst_duration:.3f}s, throughput: {burst_throughput:.1f} Mbps")
            
            # OFF period: wait for random duration (exponential distribution)
            off_duration = random.expovariate(1.0 / off_mean_seconds)
            print(f"UDP OFF period: waiting {off_duration:.2f} seconds...")
            time.sleep(off_duration)
            
    except KeyboardInterrupt:
        print("UDP Server shutting down...")
    except Exception as e:
        print(f"UDP Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()