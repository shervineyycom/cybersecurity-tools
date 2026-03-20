from scapy.all import sniff,IP,TCP,UDP,ICMP
from packet_logger import log_packet

packet_count=0

def process_packet(packet):
    global packet_count
    packet_count+=1

    print("\nPacket Number:",packet_count)

    if packet.haslayer(IP):
        source_ip=packet[IP].src
        destination_ip=packet[IP].dst

        print("Source IP:",source_ip)
        print("Destination IP:",destination_ip)

        protocol=""
        if packet.haslayer(TCP):
            protocol="TCP"
            source_port=packet[TCP].sport
            destination_port=packet[TCP].dport

            print("Protocol: TCP")
            print("Source Port:",source_port)
            print("destination Port:",destination_port)
        elif packet.haslayer(UDP):
            protocol="UDP"
            source_port=packet[UDP].sport
            destination_port=packet[UDP].dport

            print("Protocol: UDP")
            print("Source Port:",source_port)
            print("destination Port:",destination_port)
        elif packet.haslayer(ICMP):
            protocol="ICMP"
            print("Protocol:ICMP")
        else:
            protocol="other"
            print("Protocol: Other")
        
        log_data=f"Packet {packet_count}|{source_ip}-->{destination_ip}|Protocol:{protocol}"

        log_packet(log_data)

print("Starting packet sniffer...\n")

sniff(prn=process_packet,store=False)
