from scapy.all import IP, ICMP, sr1

def traceroute(destination):
    ttl = 1
    while True:
        # Create an IP packet with the desired destination and TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()

        # Send the packet and wait for a response
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            print(f"Destination reached in {ttl} hops")
            # No reply received within the timeout, stop the traceroute
            break
        else:
            # We received an ICMP error message, extract the router's IP address
            print(f"TTL={ttl}: {reply.src}")   

        ttl += 1
        


def main():
    ip=input("enter the ip dest \n")
    traceroute(ip)

if __name__ == "__main__":
    main()
