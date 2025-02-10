from scapy.all import sniff
from datetime import datetime

def log_packet(packet):
    # Get current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Detect protocol
    protocol = "Unknown"
    if packet.haslayer("TCP"):
        protocol = "TCP"
    elif packet.haslayer("UDP"):
        protocol = "UDP"
    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    # Extract source and destination info
    src_ip = packet[0].src if packet.haslayer("IP") else "Unknown"
    dst_ip = packet[0].dst if packet.haslayer("IP") else "Unknown"
    src_port = packet.sport if packet.haslayer("TCP") or packet.haslayer("UDP") else "N/A"
    dst_port = packet.dport if packet.haslayer("TCP") or packet.haslayer("UDP") else "N/A"

    # Packet size
    pkt_size = len(packet)

    # Log format
    log_entry = (
        f"[{timestamp}] {protocol} Packet\n"
        f"  - From: {src_ip}:{src_port}\n"
        f"  - To: {dst_ip}:{dst_port}\n"
        f"  - Size: {pkt_size} bytes\n"
        f"  - Raw Data: {packet.summary()}\n"
        f"{'-' * 50}\n"
    )

    # Append to log file (no printing to console)
    with open("traffic_log.txt", "a") as f:
        f.write(log_entry)

# Capture and log 20 packets
sniff(prn=log_packet, count=20)
