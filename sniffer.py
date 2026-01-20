import scapy.all as scapy
from scapy.layers.inet import IP, UDP

# Function to process captured packets
def process_packet(packet):
    if packet.haslayer(UDP):
        # Filter for STUN ports 3478/19302
        if packet[UDP].dport in [3478, 19302] or packet[UDP].sport in [3478, 19302]:
            payload = bytes(packet[UDP].payload)
            
            # Searching for XOR-MAPPED-ADDRESS marker (0x0020)
            if b'\x00\x20' in payload:
                try:
                    idx = payload.find(b'\x00\x20')
                    # Extracting the 4-byte IP address starting 8 bytes after the marker
                    raw_ip = payload[idx+8:idx+12]
                    xor_ip = ".".join(map(str, raw_ip))
                    
                    print(f"\n[!] STUN/TURN Traffic Detected")
                    print(f"[*] Packet Source IP: {packet[IP].src}")
                    print(f"[+] XOR-MAPPED-ADDRESS (Reflexive IP): {xor_ip}")
                except Exception as e:
                    print(f"Error parsing address: {str(e)}")

def capture_turn(iface='eth0'):
    print(f"[*] Starting sniffer on {iface}...")
    # Using UDP filter for standard STUN traffic
    scapy.sniff(iface=iface, filter="udp", prn=process_packet, store=False)

# Correct entry point for Python
if __name__ == "__main__":
    # Ensure eth0 matches your Kali interface name
    capture_turn('eth0')
