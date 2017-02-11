#!/usr/bin/env python

import sys
from scapy.all import *

import rlcompleter, readline
readline.parse_and_bind('tab: complete')

if len(sys.argv) < 2:
    sys.exit('No input file specified')

filename = sys.argv[1]
capture = rdpcap(filename)
print('Read %d packets from %s' % (len(capture), filename))

# Initialise lookup tables for IP addresses and MACs
ip_to_mac, mac_to_ip = {}, {}

for i, packet in enumerate(capture):
    # Disregard non-ARP traffic
    if ARP not in packet:
        continue

    arp = packet[ARP]
    if arp.psrc in ip_to_mac and ip_to_mac[arp.psrc] != arp.hwsrc:
        # Malicious activity detected
        print('WARNING: suspected ARP poisoning attack at packet %d' % i)
        print('  Attacker: %s (last seen using %s)' % (arp.hwsrc, mac_to_ip[arp.hwsrc]))
        print('  Victim: %s (%s)' % (arp.hwdst, arp.pdst))
        print('  Hijacked resource: %s (%s)' % (ip_to_mac[arp.psrc], arp.psrc))
    else:
        # The ARP packet appears normal, so update the tables accordingly
        ip_to_mac[arp.psrc] = arp.hwsrc
        mac_to_ip[arp.hwsrc] = arp.psrc
