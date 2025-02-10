from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        src_port = "N/A"
        dst_port = "N/A"
        extra_info = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Detect HTTP & HTTPS
            if dst_port in [80, 443]:
                extra_info = "(Web Traffic)"

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Detect DNS Query
            if dst_port == 53 and DNS in packet and DNSQR in packet:
                dns_query = packet[DNSQR].qname.decode()
                extra_info = f"(DNS Query: {dns_query})"

        print(f"[{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port} {extra_info}")

# Sniff both TCP and UDP packets, ensuring DNS queries are captured
sniff(filter="tcp or udp", iface="Your_Interface_Name", prn=analyze_packet, store=False, count=50)
