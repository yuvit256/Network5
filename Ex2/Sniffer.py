import sys
import scapy.all as scapy
import binascii


def sniff(packet) -> None:
    
    try:

        if packet.haslayer(scapy.TCP):

            with open("packets.txt", "a") as file:
                
                if packet[scapy.TCP].sport == 9999 or packet[scapy.TCP].dport == 9999 or packet[scapy.TCP].sport == 9998 or packet[scapy.TCP].dport == 9998:
                    file.write("{ "
                            + f"source_ip: {packet[scapy.IP].src} "
                            + f"dest_ip: {packet[scapy.IP].dst} "
                            + f"source_port: {packet[scapy.TCP].sport} "
                            + f"dst_prt: {packet[scapy.TCP].dport} "
                            + f"timestamp: {packet[scapy.TCP].options[2][1][0]} "
                            + f"total_length: {len(packet)} "
                            + f"cache_flag: {packet[scapy.TCP].payload[52:53]} "
                            + f"steps_flag: {packet[scapy.TCP].payload[53:54]} "
                            + f"type_flag: {packet[scapy.TCP].payload[54:55]} "
                            + f"status_code: {packet[scapy.TCP].payload[55:65]} "
                            + f"cache_control: {packet[scapy.TCP].payload[66:82]} "
                            + f"data: { 'No Data'} "
                            +"}\n")
                    
                else:
                    
                    file.write("{ "
                            + f"source_ip: {packet[scapy.IP].src} "
                            + f"dest_ip: {packet[scapy.IP].dst} "
                            + f"source_port: {packet[scapy.TCP].sport} "
                            + f"dst_prt: {packet[scapy.TCP].dport} "
                            + f"timestamp: {packet[scapy.TCP].options[2][1][0]} "
                            + f"total_length: {len(packet)} "
                            + f"data: {binascii.hexlify(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else 'No Data'} "
                            +"}\n")

        print(packet)

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        sys.exit(0)


def main():
    scapy.sniff(prn=sniff, filter="tcp or udp or icmp or igmp", iface="lo")

if __name__ == "__main__":
    main()