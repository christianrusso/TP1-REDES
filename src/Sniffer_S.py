#! /usr/bin/env python
from scapy.all import *
from math import log

pktTypes = {}
probabilities = {}
total = 0

def monitor_callback(pkt):
	global total
	total += 1
	if Ether in pkt:
		if pkt.type in pktTypes.keys():
			pktTypes[pkt.type] += 1
		else:
			pktTypes[pkt.type] = 1
    
if __name__ == '__main__':
	sniff(prn=monitor_callback, filter=None, store=0, timeout=1500)

	print "Total packets: " + str(total)
	print "Raw counts"
	for type, count in pktTypes.iteritems():
		print str(type) + "\t" + str(count)
		probabilities[type] = count/float(total)
        
	print "Probabilities"
	for type, prob in probabilities.iteritems():
		print str(type) + "\t" + str(prob)
       

	print "Information"
	for type, prob in probabilities.iteritems():
		info = (-1) * log(prob) / log(2.0)
		print str(type) + "\t" + str(info)
	
	entropy = 0 
	for type, prob in probabilities.iteritems():
		if prob != 0:
			entropy += (prob * log(prob) / log(2.0))

	entropy = (-1) * entropy
        
	print "Entropy " + str(entropy)
