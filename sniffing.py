from telnetlib import IP
from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
init()

GREEN=Fore.GREEN
RED=Fore.RED
RESET=Fore.RESET

def sniff_packets(iface=None):
    #For HTTP requests use port 80
    if iface:
        sniff(filter="port 80",prn=process_packet,iface=iface,store=False)
    else:
        sniff(filter="port 80",prn=process_packet,store=False)

def  process_packet(packet):
    # Checking the packet is for http protocol
    if packet.haslayer(HTTPRequest):
        url=packet[HTTPRequest].Host.decode()+packet[HTTPRequest].Path.decode()

        ip=packet[IP].src

        method=packet[HTTPRequest].Method.decode()

        print(f"\n{GREEN}[+] {ip} requested {url} with {method}{RESET}")

        if show_raw and packet.haslayer(Raw) and method == "POST":
            print(f"\n{RED}[*] some useful Raw Data: {packet[Raw].load}{RESET}")


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description="HTTP Packet Sniffer")
    parser.add_argument("-i","--iface",help="Default interface by scapy")
    parser.add_argument("--show-raw",dest="show_raw",action="store_true",help="Wheather to p[rint Raw data in POST")
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)



