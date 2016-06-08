#! /usr/bin/env python
from scapy.all import *

def monitor_callback(pkt):
    print pkt.summary()

if __name__ == '__main__':
    sniff(prn=monitor_callback, filter=None, store=0)
