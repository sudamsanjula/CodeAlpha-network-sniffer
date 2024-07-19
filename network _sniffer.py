from scapy.all import sniff, Ether, IP, conf

protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

def process_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        print(f'\nEthernet Frame:')
        print(f'Destination: {eth.dst}, Source: {eth.src}, Protocol: {eth.type}')

        if IP in packet:
            ip = packet[IP]
            proto = protocols.get(ip.proto, 'Other')
            print('IPv4 Packet:')
            print(f'\tVersion: {ip.version}, Header Length: {ip.ihl}, TTL: {ip.ttl}')
            print(f'\tProtocol: {proto} ({ip.proto}), Source: {ip.src}, Target: {ip.dst}')

def main():
    try:
        # Configure Scapy to use Layer 3 socket on Windows
        conf.L3socket
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")

if __name__ == '__main__':
    main()
