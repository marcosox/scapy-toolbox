import sys

from scapy.layers.inet import TCP
from scapy.sendrecv import sniff


def packet_handler(pkt):
    if pkt.haslayer(TCP) == 1 \
            and pkt.payload.payload.payload is not None \
            and len(pkt.payload.payload.payload) > 0 \
            and pkt.payload.payload.dport in recognized_ports:
        body = pkt.payload.payload.payload.load
        request_summary = "{first_line}".format(first_line=body.splitlines()[0])
        to_addr = pkt.payload.dst
        if pkt.payload.payload.dport in plaintext_ports:
            for x in body.splitlines():
                if x.startswith("Host: "):
                    to_addr = x[6:]
                    break
        else:
            request_summary = "[encrypted]"
        print("{from_ip} -> {to_ip}:\t{payload}".format(from_ip=pkt.payload.src,
                                                        to_ip=to_addr,
                                                        payload=request_summary))


if __name__ == '__main__':

    print("remember to put interface in monitor mode before using this script")

    if len(sys.argv) < 2:
        print("usage: {0} <interface>".format(sys.argv[0]))
        exit()
    device = sys.argv[1]
    plaintext_ports = [80, 8080, 8088, 8888]
    encrypted_ports = [443, 8443, 8043]
    recognized_ports = plaintext_ports + encrypted_ports

    print("Listening for http connections...")
    sniff(iface=device, prn=packet_handler)
