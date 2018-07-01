import sys
from scapy.all import *

print("remember to put interface in monitor mode before using this script")

if len(sys.argv) < 2:
	print("usage: {0} <interface>".format(sys.argv[0]))
	exit()
print("Available networks:")

networks = []
device = sys.argv[1]

def packet_handler(pkt) :
	if pkt.haslayer(Dot11):
		global networks
		if pkt.haslayer(Dot11Beacon):
			channel = int(ord(pkt[Dot11Elt:3].info))
			bssid = pkt[Dot11].addr3
			ssid = pkt[Dot11Elt].info
			if bssid not in networks:
				networks.append(bssid)
				print("{bssid} - channel {chan} {name}".format(
					name=ssid,
					bssid=bssid,
					chan=channel)
				)
	global device
	import os
	import random
	cmd = "iw dev {dev} set channel {chan}".format(dev=device, chan=random.randrange(1,14))
	os.system(cmd)

sniff(iface=device, prn=packet_handler)

