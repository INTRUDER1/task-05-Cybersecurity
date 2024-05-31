from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Identify the protocol
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Other"

        # Check for payload data
        if Raw in packet:
            payload = packet[Raw].load
        else:
            payload = "No payload"
        
        # Print packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol_name}")
        print(f"Payload: {payload}\n")

def main():
    print("Starting packet sniffer...")
    # Sniff packets
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
