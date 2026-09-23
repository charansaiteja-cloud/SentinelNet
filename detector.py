import time
import random
import sys

print("="*50)
print("     SentinelNet - AI Network Intrusion Detector")
print("="*50)
print("[*] Initializing AI model weights...")
time.sleep(1.5)
print("[*] Listening on interface: eth0 (Simulated)")
print("[*] Press Ctrl+C to stop.\n")

# Simulated baseline traffic profile
normal_ports = [80, 443, 22, 53]

try:
    while True:
        # Generate mock network packet data
        source_ip = f"192.168.1.{random.randint(2, 254)}"
        dest_port = random.choice([80, 443, 22, 3389, 4444, 1337])
        packet_size = random.randint(64, 1500)
        
        # Simple heuristic/AI-style anomaly flagging
        if dest_port in [4444, 1337] or packet_size > 1400:
            print(f"[!] ALERT: Suspicious activity from {source_ip} on port {dest_port} (Size: {packet_size} bytes) - Potential Intrusion!")
        else:
            print(f"[INFO] Normal traffic: {source_ip} -> Port {dest_port} ({packet_size} bytes)")
            
        time.sleep(1)
        
except KeyboardInterrupt:
    print("\n[*] SentinelNet shutting down. Stay safe!")
    sys.exit(0)
