import socket
import sys
import time

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 udp_client.py <server_ip> <server_port>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    
    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind to any available port 
    client_socket.bind(('', 0))
    
    print(f"UDP Client listening for packets from {server_ip}:{server_port}")
    
    # Send a dummy packet to establish connection with server
    client_socket.sendto(b"HELLO", (server_ip, server_port))
    print("Sent initial packet to server")
    
    packet_count = 0
    try:
        while True:
            data, addr = client_socket.recvfrom(1500)
            packet_count += 1
            if packet_count % 100 == 0:  
                print(f"Received {packet_count} packets from {addr}")
            
    except KeyboardInterrupt:
        print("UDP Client shutting down...")
    except Exception as e:
        print(f"UDP Client error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()