from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process and display packets
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[IP] Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
        
        # Check if the packet is TCP
        if TCP in packet:
            print(f"[TCP] Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        
        # Check if the packet is UDP
        elif UDP in packet:
            print(f"[UDP] Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")
        
        # Check if the packet is ICMP (ping packets)
        elif ICMP in packet:
            print(f"[ICMP] Type: {packet[ICMP].type} Code: {packet[ICMP].code}")
        
        # Print raw payload data (if available)
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")

# Sniff function to capture packets
def start_sniffer(interface=None):
    # Use 'prn' to call a function on each packet captured
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    print("Starting Packet Sniffer... Press Ctrl+C to stop.")
    try:
        # Pass an interface if needed, or leave it as None for default
        start_sniffer(interface=None)
    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer.")
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw  # Import Raw layer

# Function to process and display packets
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[IP] Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
        
        # Check if the packet is TCP
        if TCP in packet:
            print(f"[TCP] Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        
        # Check if the packet is UDP
        elif UDP in packet:
            print(f"[UDP] Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")
        
        # Check if the packet is ICMP (ping packets)
        elif ICMP in packet:
            print(f"[ICMP] Type: {packet[ICMP].type} Code: {packet[ICMP].code}")
        
        # Check for Raw payload data (if available)
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")

# Sniff function to capture packets
def start_sniffer(interface=None):
    # Use 'prn' to call a function on each packet captured
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    print("Starting Packet Sniffer... Press Ctrl+C to stop.")
    try:
        # Pass an interface if needed, or leave it as None for default
        start_sniffer(interface=None)
    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer.")
