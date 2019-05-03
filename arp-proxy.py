from scapy.all import *
conf.iface="vmnet8"



def proxy_arp(req):
    
   #making sure we leave Gratituous arp away.
    if(req.pdst != req.psrc):
        #lets make sure its ARP REQUEST
        if (req.op==1):
            #we pretend to be the recipient ;)
            
            #print("Crafting ARP reply")
            arp=ARP()
            arp.op=2
            #arp.pdst=req.payload.psrc
            arp.pdst=req.psrc
            #arp.hwdst=req.payload.hwsrc
            arp.hwdst=req.hwsrc
            #arp.psrc=req.payload.pdst
            arp.psrc=req.pdst
            print("Successfully created ARP reply for machine %s of machine %s") % (arp.pdst, arp.psrc)
            #send(arp)
            return arp
        else:
            arp = '0'
            return arp
    else:
        arp = '0'
        return arp
    




def icmp_response(req):
    src=req.sprintf("%IP.src%")
    dst=req.sprintf("%IP.dst%")
    icmp_id=req.sprintf("%ICMP.id%")
    icmp_seq=req.sprintf("%ICMP.seq%")
    icmp_type= req.sprintf("%ICMP.type%")
    proto=req.sprintf("%IP.proto%")
    load=req.load
    
    #lets make sure its ICMP ping
    if (proto=="icmp" and icmp_type=="echo-request"  ):
        #we pretend to be the recipient ;)
        print("Crafting ICMP PING reply")
        ip2= IP()
        ip2.dst=src
        ip2.src=dst
        
        icmp=ICMP()
        icmp.type=0
        icmp.id=int(icmp_id, 16)
        icmp.seq=int(icmp_seq, 16)
        
        raw=Raw()
        raw.load=load

        print("Replying for ICMP PING to %s on behalf of %s") % (ip2.dst, ip2.src)
        send(ip2/icmp/raw)

    
    
    

print("Sniffing")
while True:
    s=sniff(filter="arp or icmp", count=1, iface='vmnet8')
    pkt=s[0]
    
    #check if packet is ARP
    if(pkt.type == 2054):
        response = proxy_arp(pkt)
        if(len(response) != 1):
            send(response)
        
        else:
            print "Gratituous or Reply ARP detected, discarding packet"
        
        
    #Check if packet is ICMP
    elif(pkt.type == 2048):
        #print "packet type is ICMP"
        icmp_response(pkt)
        
