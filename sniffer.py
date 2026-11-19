from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import string

def clean_payload(raw_bytes):
    # Filter only printable ASCII characters to keep terminal output clean
    decoded = raw_bytes.decode("utf-8", errors="ignore")
    printable = "".join(ch for ch in decoded if ch in string.printable and ch not in "\n\r\t")
    return printable.strip()

def analyze_packet(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        ports = ""

        if TCP in packet:
            protocol = "TCP"
            ports = f"| Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            ports = f"| Ports: {packet[UDP].sport} -> {packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"[{timestamp}] [{protocol}] {src_ip} -> {dst_ip} {ports}")

        if Raw in packet:
            payload = clean_payload(packet[Raw].load)
            if len(payload) > 4:
                print(f"    └── Payload: {payload[:65]}")

def main():
    print("==================================================")
    print("       CodeAlpha - Basic Network Sniffer          ")
    print("==================================================")
    
    try:
        user_input = input("Enter number of packets to capture (0 for infinite): ").strip()
        packet_count = int(user_input) if user_input.isdigit() else 20
        
        print(f"\n[INFO] Sniffing started (Count: {'Infinite' if packet_count == 0 else packet_count})... Press Ctrl+C to stop.\n")
        sniff(prn=analyze_packet, store=False, count=packet_count)
        print("\n=== Capture Complete ===")
    except PermissionError:
        print("[ERROR] Root privileges required. Run with 'sudo python3 sniffer.py'.")
    except KeyboardInterrupt:
        print("\n[INFO] Sniffer stopped by user.")

if __name__ == "__main__":
    main()
