import sys
import scapy.all as scapy
import binascii
from scapy.layers.inet import IP, ICMP


def spoof_icmp(source_ip, dst_ip):
    
    ip_hdr = scapy.IP(src=source_ip, dst=dst_ip)
    
    icmp_hdr = scapy.ICMP(type=0)

    pkt = ip_hdr / icmp_hdr

    return pkt


def sniff(packet) -> None:
    
    try:

        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.ICMP):
            
            scapy.send(spoof_icmp(packet[scapy.IP].dst, packet[scapy.IP].src), verbose=False)
            
    except KeyboardInterrupt:
        
        sys.exit(0)


def main():

    scapy.sniff(prn=sniff, filter="icmp", iface="wlo1", promisc=True)
    
    
if __name__ == "__main__":
    main()