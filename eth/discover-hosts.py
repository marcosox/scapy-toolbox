import sys

from scapy.layers.l2 import arping

if __name__ == '__main__':
    print("remember to put interface in monitor mode before using this script")
    if "-h" in sys.argv:
        print("usage: {0} [ interface ]".format(sys.argv[0]))
        exit()
    device = None
    if len(sys.argv) > 1:
        device = sys.argv[1]

    # ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"), timeout=10)
    # ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))
    arping("192.168.1.*")
