#! /usr/bin/env python
from scapy.all import *
from math import log

pktIPSRC = {}
probabilities = {}
src_dst = {}
total = 0
whohas = 0
isat = 0


def arp_monitor_callback(pkt):
	#Hasta aca llegan todos los paquetes ARP
	global total
	total += 1
	global isat
	global whohas

	if(pkt[ARP].op == 2):
		isat += 1
	else:
		whohas +=1

	par = (pkt[ARP].psrc, pkt[ARP].pdst)
	if (par in src_dst.keys()):
		src_dst[par] += 1
	else:
		src_dst[par] = 1
	
	if pkt[ARP].psrc in pktIPSRC.keys():
		pktIPSRC[pkt[ARP].psrc] += 1
	else:
		pktIPSRC[pkt[ARP].psrc] = 1

if __name__ == '__main__':
	sniff(prn=arp_monitor_callback, filter='arp', store=0, timeout=1500)
    
	print "IP src" + "\t" + "IP dst" + "\t" + "Count"
	print "digraph A {"
	for sd, count in src_dst.iteritems():
		print "\"" + str(sd[0]) + "\" -> \"" + str(sd[1]) + "\" [label=\"" + str(count) + "\"]"
	print "}"

	print "Total ARP packets: " + str(total)
	print "Raw counts"
	for ip, count in pktIPSRC.iteritems():
		print str(ip) + "\t" + str(count)
		probabilities[ip] = count / float(total)
        
	print "Probabilities"
	for ip, prob in probabilities.iteritems():
		print str(ip) + "\t" + str(prob)

	print "Information"
	for ip, prob in probabilities.iteritems():
		info = (-1) * log(prob) / log(2.0)
		print str(ip) + "\t" + str(info)
       
	entropy = 0 
	for ip, prob in probabilities.iteritems():
		if prob != 0:
			entropy += (prob * log(prob) / log(2.0))
        
	entropy = (-1) * entropy
	print "Entropy " + str(entropy)
	print "whohast " + str(whohas)
	print "isat " + str(isat)
        
