import scapy.all as scapy
from scapy.layers.inet import IP, UDP

def process_stun(packet):
    if packet.haslayer(UDP):
        # Extract the payload
        payload = bytes(packet[UDP].payload)
        
        # Searching for the XOR-MAPPED-ADDRESS marker (0x0020)
        # This is the logic from your provided code to find the reflexive IP
        if b'\x00\x20' in payload:
            print(f"\n[!] WebRTC STUN Traffic Captured!")
            print(f"[*] Target Public IP (from IP header): {packet[IP].src}")
            # The XOR extraction logic from your snippet
            try:
                idx = payload.find(b'\x00\x20')
                raw_ip = payload[idx+8:idx+12]
                xor_ip = ".".join(map(str, raw_ip))
                print(f"[+] XOR-MAPPED-ADDRESS Found: {xor_ip}")
            except Exception as e:
                print(f"Error parsing XOR address: {e}")

def start_capture(iface='eth0'):
    print(f"[*] Monitoring interface: {iface} for STUN/TURN (Messenger) traffic...")
    # Port 3478 is the standard port for STUN as per your config
    scapy.sniff(iface=iface, filter="udp port 3478 or port 19302", prn=process_stun, store=False)

if __name__ == "__main__":
    # Change 'eth0' to your interface name if different
    start_capture('eth0')
