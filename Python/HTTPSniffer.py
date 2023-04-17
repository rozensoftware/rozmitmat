import keyboard
from scapy.all import *
from scapy.layers import http, tls
from scapy.layers.http import HTTPRequest, Raw
from scapy.layers.inet import IP

class HTTPSniffer:
    def __init__(self):
        load_layer("tls")

    def __str__(self):
        return "HTTPSniffer"
    
    def check_stop(self, dummy):
        if keyboard.is_pressed('q'):
            return True
        else:
            return False

    def start(self, device_name):
        print("[+] Starting HTTP sniffing")
        sniff(iface = device_name, filter = "tcp", store = False, prn = self.decode_packet, stop_filter = self.check_stop)
        print("[*] HTTP Sniffing finished")

    def decode_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            ip = packet[IP].src
            method = packet[HTTPRequest].Method.decode()

            print("[*] IP: {:<20} Method: {:<4} URL: {}".format(ip, method, url))

            if packet.haslayer(Raw):
                load = bytes(packet[Raw].payload).decode('UTF8', 'replace')
                if len(load) > 0:
                    print("Load: {}".format(load))