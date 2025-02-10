from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Capture 10 packets on the default network interface
sniff(prn=packet_callback, count=20, iface="Realtek RTL8852BE-VS WiFi 6 802.11ax PCIe Adapter", filter="ip", store=False)
