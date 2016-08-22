from scapy.all import *

def IP_test(ip_src, ip_dst):
    
    print "*********************"
    print "*** Start IP test ***"
    print "*********************\n"

    packet = IP(src = ip_src, dst = ip_dst)

    print "--- Start IP length test ---"
    for l in range(1000):
        packet.len = l
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP length test ---"

    print "--- Start IP flags test ---"
    for flags in range(9):
        packet.flags = flags
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Finish IP flags test ---\n"        

    print "--- Start IP frag test ---"
    for frag in range(1000):
        packet.frag = frag
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP frag test ---\n"
    
    print "--- Start IP id test ---"
    for i in range(1000):
        packet.id = i
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP id test ---\n"

    print "--- Start IP ttl test ---"
    for ttl in range(100):
        packet.ttl = ttl
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP ttl test ---\n"
        
    print "--- Start IP proto test ---"
    for proto in range(100):
        packet.id = proto
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP proto test ---\n"
        
    print "--- Start IP checksum test ---"
    for chksum in range(1000):
        packet.chksum = chksum
        print '--------------------'
        print packet.show()
        print '--------------------'
        send = sr(packet)
    print "--- Start IP checksum test ---\n"

    print "**********************"
    print "*** Finish IP test ***"
    print "**********************\n"
    

def ARP_test(ip_src, ip_dst, hw_src, hw_dst):
    print "**********************"
    print "*** Start arp test ***"
    print "**********************\n"

    packet = ARP(src=ip_src, dst=ip_dst, hwsrc=hw_src, hwdst=hw_dst)


if  __name__ == '__main__':
    src_ip = ''
    dst_ip = ''
    hw_src = ''
    hw_dst = ''
    IP_test(src_ip, dst_ip)
    ARP_test(src_ip, dst_ip, hw_src, hw_dst)
    
    
