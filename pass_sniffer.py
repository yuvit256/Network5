import scapy.all as scapy

def sniff_http(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        if packet[scapy.TCP].dport == 80:
            data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            with open('captured_data.txt', 'a') as file:
                file.write(data)

def main():
    scapy.sniff(iface="enp0s3",filter="tcp", prn=sniff_http)

if __name__ == "__main__":
    main()
