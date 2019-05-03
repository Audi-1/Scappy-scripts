#!/usr/bin/env python

from time import sleep 
import socket
import sys
from scapy.all import *
from dhakkan_dns import *

conf.verb=0

if len(sys.argv) != 4:
	
	print "Usage: ./start-server.py <Host> <port> <Real DNS server IP>  \n"
	
	print "[*].. Host = Host or interface to listen on"
	print "[*].. port = Port to listen on -- Usually 53"
	print "[*].. DNS Server = Name of a real DNS server which can be used to query real responses"
	sys.exit(1)


# Starting up DNS server

host = sys.argv[1]
port = int(sys.argv[2])
dns_server = sys.argv[3]

con = host, port
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# Create a UDP socket object
s.bind((con))   #binding to IP and port

print "[*] Dhakkan_DNS Server Started........."
print "[*] Proof of concept by Audi-1, the biggest Dhakkan"
print "[*] Released, 10 April 2013"

while True:
		print "[*]-------------------------------------------------------------------------"
		
		print '[*] Waiting for connections................'
		
		pkt, addr = s.recvfrom(10240)     # Establish connection with client.
		print '[*] Recieved Connection Request from', addr
		
		
		p=dhakkan_dns(pkt, dns_server)
		resp = p.packet_to_send()
		s.sendto(resp, addr)		

