from scapy.all import sniff, IP, TCP
from datetime import datetime

# Paths
log_path = "D:/Personal Firewall using Python/firewall_logs.txt"

# Rules
BLOCKED_IPS = ["192.168.1.10"]
BLOCKED_PORTS = [80, 443]

# Logging function
def log_blocked_packet(pkt, reason):
    with open(log_path, "a") as log_file:
        log_file.write(f"[{datetime.now()}] BLOCKED: {reason} | {pkt.summary()}\n")

# Packet processing
def process_packet(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        if ip_src in BLOCKED_IPS or ip_dst in BLOCKED_IPS:
            log_blocked_packet(pkt, "IP Block")
            print(f"[BLOCKED - IP] {pkt.summary()}")
            return

    if TCP in pkt:
        port_src = pkt[TCP].sport
        port_dst = pkt[TCP].dport

        if port_src in BLOCKED_PORTS or port_dst in BLOCKED_PORTS:
            log_blocked_packet(pkt, "Port Block")
            print(f"[BLOCKED - Port] {pkt.summary()}")
            return

    print(f"[ALLOWED] {pkt.summary()}")

# Start sniffing
sniff(prn=process_packet, store=False)
