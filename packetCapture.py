from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Capture 10 packets on the default network interface
sniff(prn=packet_callback, count=20, iface="Your_Interface_Name", filter="ip", store=False)
