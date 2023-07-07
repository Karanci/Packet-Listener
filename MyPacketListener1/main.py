import http

import scapy.all as scapy
from scapy.layers.http import http_request
def listen_packet(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)

def analyze_packets(packet):
    #packet.show()
if packet.haslayer(http.HTTPRe)
listen_packet("eth0")

