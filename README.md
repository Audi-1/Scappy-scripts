# Scapy-scripts
Old python scripts I found in my archive -- based on packet manipulation library SCAPPY

1. Dhakkan-DNS (start-server.py, dhakkan_dns.py & spoof.txt)
A Smart DNS Forwarder script based on scapy packet manipulation library. 
This acts as a dns server and responds to client requests by getting a response from a forwarder except for those mentioned in spoof.txt file. 
It returns the corresponding IP for domain mentioned in the file.
 to start server specify the following parameters with start-server.py
      1. Hostname or IP address
      2. UDP Port to listen to
      3. DNS server IP which will be queried to provide response to clients.
      
      USAGE:
          # python start-server.py <host>  <port> <DNS server to get answers>
 

2. ICMP Redirect (icmp-redirect.py)


3. PROXY ARP (arp-proxy.py)
Once run, behaves like a proxy for all ARP requests and accordingly responds with machines IP. To simulate, Ping any IP within the subnet and it would respond with a response.
          
