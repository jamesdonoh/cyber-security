#!/usr/bin/env python

import sys
import collections

from scapy.all import *

import rlcompleter, readline
readline.parse_and_bind('tab: complete')

if len(sys.argv) < 2:
    sys.exit('No input file specified')

filename = sys.argv[1]
capture = rdpcap(filename)
print('Read %d packets from %s' % (len(capture), filename))

print('== Analysis of domain names')

# Filter DNS packets from capture (queries and replies)
dns_packets = capture.filter(lambda x: DNS in x)
for p in dns_packets:
    if p[DNS].an:
        print('DNS reply from {}: {} {}'.format(p[IP].src, p[DNS].an.rrname, p[DNS].an.rdata))
    else:
        print('DNS query from {} to {}: {}'.format(p[IP].src, p[IP].dst, p[DNS].qd.qname))


print('\n== Analysis of IP addresses')

# Filter packets from capture where only TCP SYN flag is set (attempted connection)
syn_packets = capture.filter(lambda x: TCP in x and x.sprintf('%TCP.flags%') == 'S')

# Use Counter class to de-duplicate source and dest IP addresses and provide counts
src_ips = map(lambda x: x[IP].src, syn_packets)
dst_ips = map(lambda x: x.sprintf('%IP.dst%:%r,TCP.dport%'), syn_packets)
src_counter = collections.Counter(src_ips)
dst_counter = collections.Counter(dst_ips)

print('= IPs attempting to establish TCP connections:')
for src_ip, count in src_counter.iteritems():
    print('{}: {} packet(s)'.format(src_ip, count))

print('= IPs and ports being connected to (in order of frequency):')
for dst_ip, count in dst_counter.most_common():
    print('{}: {} packet(s)'.format(dst_ip, count))

print('\n== Analysis of malware')

# Create regular expression to match HTTP request line for Windows executable
malware_pattern = re.compile("^GET /.+\.exe HTTP/")

# Extract packets that resemble HTTP requests from capture
malware_reqs = capture.filter(lambda x: TCP in x and malware_pattern.match(str(x[TCP].payload)))
for p in malware_reqs:
    print(p.sprintf('\nPossible HTTP malware request to %IP.dst%:'))
    print(str(p[TCP].payload).strip())


print('\n== Analysis of sessions')

print('= TCP sessions where data is sent or received:')

def tcp_session_extractor(p):
    # Adapted from https://github.com/secdev/scapy/blob/master/scapy/plist.py#L475
    if 'TCP' in p:
        addresses = [p.sprintf('%IP.src%:%r,TCP.sport%'), p.sprintf('%IP.dst%:%r,TCP.dport%')]
        return ' '.join(sorted(addresses))
    else:
        return 'Other'

# Extract data about TCP sessions where data was sent or received
sessions = capture.sessions(tcp_session_extractor)
empty_sessions = 0
for key, sess_packets in sessions.iteritems():
    if key == 'Other':
        continue
    if any(Raw in p for p in sess_packets):
        print('{}: ({} packets)'.format(key, len(sess_packets)))
    else:
        empty_sessions += 1

if empty_sessions > 0:
    print('= Discarded {} sessions where no data was transmitted'.format(empty_sessions))

