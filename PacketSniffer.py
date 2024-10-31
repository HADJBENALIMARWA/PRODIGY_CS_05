from scapy.all import sniff

protocols = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}

def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        proto_num = packet["IP"].proto
        proto_name = protocols.get(proto_num, f"Unknown ({proto_num})")
        
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {proto_name}")

        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            print(f"Payload: {bytes(payload)}")
        print("-" * 40)

print("Starting packet capture...")
sniff(prn=packet_callback, count=15, iface="Realtek RTL8821CE 802.11ac PCIe Adapter")



