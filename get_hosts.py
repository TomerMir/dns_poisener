from scapy.all import *
import math
import logging

logger = logging.getLogger("SPOFFER")

def long2net(arg):
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None

    return net


def scan_for_neighbors(net, interface, timeout=5):
    hosts = []
    try:
        ans, unans = arping(net, iface=interface, timeout=timeout, verbose=False)
        for s, r in ans.res:
            name = conf.manufdb._resolve_MAC(r.hwsrc[:8])
            if name[2] == name[5] == ':':
                name = ""
            hosts.append((r.psrc, name))
        return hosts
    except Exception as e:
        return None


def get_defult_gateway():
    packet = IP(dst="google.com", ttl=0)
    ans = sr1(packet, verbose=False)
    return ans.src

def get_all_hosts(iface):
    
    for network, netmask, _, interface, address, _ in conf.route.routes:

        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if iface != interface:
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        net = to_CIDR_notation(network, netmask)
        if net:
            return scan_for_neighbors(net, interface)
