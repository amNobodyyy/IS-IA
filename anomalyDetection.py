from scapy.all import sniff

def detect_anomaly(packet):
    if len(packet) > 1500:  # Detect packets larger than 1500 bytes
        print(f"Anomalous packet detected: {packet.summary()}")

# Monitor network traffic for anomalies
sniff(prn=detect_anomaly, iface="Your_Interface_Name", store=False)
