#!/usr/bin/python

##
#
#Jake Young, Lanndon Rose
#updated virtual router
#
##

import socket, os, sys
import netifaces
import struct
import binascii
import time

#moved inside of the class(mactobinary function)
#from http://stackoverflow.com/questions/2986702/need-some-help-converting-a-mac-address-to-binary-data-for-use-in-an-ethernet-fr

class vrouter(object):

    def mactobinary(self, mac):
        return binascii.unhexlify(mac.replace(':', ''))

#-------------------------------------------------------------------------------
# Description: Calculates the checksum for an IP header
# from https://www.codeproject.com/Tips/460867/Python-Implementation-of-IP-Checksum
#-------------------------------------------------------------------------------    
    
    #def ip_checksum(self, ip_header, size):    
    #    cksum = 0
    #    pointer = 0
        
        #The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
        #together, converted to integers, and then added to the sum.
    #    while size > 1:
    #        cksum += int((str("%02x" % (ip_header[pointer],)) + str("%02x" % (ip_header[pointer+1],))), 16)
    #        size -= 2
    #        pointer += 2
    #    if size: #This accounts for a situation where the header is odd
    #        cksum += ip_header[pointer]
            
    #    cksum = (cksum >> 16) + (cksum & 0xffff)
    #    cksum += (cksum >>16)
        
    #    return (~cksum) & 0xFFFF

    def readtable(self, name):
        rtable = []
        f=open(name, 'r')
        rtable = f.readlines()
        #for line in f:
        #    rtable.append(line.rstrip().split(' '))
        return rtable

    def __init__(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        except socket.error:
            print 'socket not created.\n'
            sys.exit(-1)

        #read in routing table
        name = raw_input("Enter routing table name: ")
        self.routing = self.readtable(name)
        self.mactable = {}
        #print(self.routing)

    def sniff(self):
        #grabbing packets
        while True:
            packet = self.sock.recvfrom(1024)

            e = packet[0][0:14]
            eheader = struct.unpack("!6s6s2s", e)
            #eType = binascii.hexlify(eheader[2])
            eType = eheader[2]
            #print eType[1]
            if eType == '\x08\x06':
                #get arp header
                ah = packet[0][14:42]
                aHeader = struct.unpack("2s2s1s1s2s6s4s6s4s", ah)
                #is it addressed to us?
                netlist = netifaces.interfaces()
                dest = socket.inet_ntoa(aHeader[8])
                if aHeader[4] == '\x00\x02':
                    key = aHeader[6]
                    if key in self.mactable:
                        self.mactable[key] = aHeader[5]

                for net in netlist:
                    myIP = netifaces.ifaddresses(net)[2][0]['addr']
                    myMAC = netifaces.ifaddresses(net)[17][0]['addr']

                    if dest == myIP:
                        if aHeader[4] == '\x00\x01':
                            key = aHeader[6]
                            if key in self.mactable:
                                self.mactable[key] = aHeader[5]
                            print 'Got an ARP request'
                            dMAC = myMAC
                            self.respondToArp(packet, dMAC)
            elif eType == '\x08\x00':
                ih = packet[0][14:34]
                iheader = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ih)
                protocol = iheader[6]
                if protocol == '\x01':
                    ph = packet[0][34:42]
                    pheader = struct.unpack("1s1s2s4s", ph)
                    if pheader[0] == '\x08':
                        netlist = netifaces.interfaces()
                        dest = socket.inet_ntoa(iheader[9])
                        for net in netlist:
                            myIP = netifaces.ifaddresses(net)[2][0]['addr']
                            myMAC = netifaces.ifaddresses(net)[17][0]['addr']
                            if dest == myIP:
                                print 'got an icmp request'
                                dMAC = myMAC
                                self.respondToIcmp(packet, dMAC)
                else:
                    #forward others
                    dip = iheader[9]
                    dest = socket.inet_ntoa(iheader[9])
                    fDest = self.check(dest)
                    if fDest == 'nomatch':
                        #send icmp error request
                        #self.sendError(0, packet)
                        continue

                    key = dip
                    print key
                    if key in self.mactable:
                        forwardMAC = self.mactable[dip]
                        self.forward(packet,forwardMAC)
                        continue
                    else:
                        forwardMAC = self.getMAC(packet, fDest, dip)

                    self.forward(packet, forwardMAC)

    #def sendError(self, code, packet, mac, dmac, dip):
    #    e = packet[0][0:14]
    #    eheader = list(struct.unpack("!6s6s2s", e))
    #    i = packet[0][14:34]
    #    iheader = list(struct.unpack("1s1s2s2s2s1s1s2s4s4s", i))
    #    p = packet[0][34:42]
    #    pheader = list(struct.unpack("1s1s2s4s", p))
    #    eheader[0] = dmac
    #    eheader[1] = mac
    #    eheader[2] = '\x08\x00'
    #    iheader[0] = '\x04'
    #    #iheader[8] = myip
    #    iheader[9] = dip
    #    #pheader[0] = type
    #    pheader[1] = code
    #    #pheader[3] = packet add last 8 bytes
    #    sendpacket = eheader+iheader+pheader
    #    #create address for send
    #    temp = list(packet[1])
    #    temp[0] = self.interface.strip()
    #    temp[3] = int(self.interface[6:7])
    #    addr = tuple(p)
    #    self.sock.sendto(sendpacket, addr)
    #    print 'icmp denial sent'

                    
    def forward(self, packet, mac):
        e = packet[0][0:14]
        eheader = list(struct.unpack("!6s6s2s", e))
        #i = packet[0][14:34]
        #IHeader = struct.unpack("1s1s2s2s2s1s1s2s4s4s", i)
        #print "printing checksum"
        #checksumReturn = self.ip_checksum(binascii.hexlify(i),len(i))
        #print checksumReturn
        temp = eheader
        eheader[0] = mac
        eheader[1] = temp[0]
        fe = struct.pack("6s6s2s", *eheader)

        ######### ttl altering stuff, stops packets from forwarding not sure why
        #i = packet[0][14:34]
        #iheader = list(struct.unpack("1s1s2s2s2s1s1s2s4s4s", i))
        #ttl = int(binascii.hexlify(iheader[5]))
        #ttl -= 1
        #if ttl < 0:
        #   print 'packet died on wire'
        #   continue
        #nttl = str(ttl)
        #nwttl = binascii.unhexlify(nttl)
        #iheader[5] = nwttl
        #fi = struct.pack("1s1s2s2s2s1s1s2s4s4s", *iheader)
        #finalPacket = fe+fi+packet[0][34:]
        ######### end of ttl

        finalPacket = fe+packet[0][14:] 
        p = list(packet[1])
        p[0] = self.interface.strip()
        p[3] = int(self.interface[6:7])
        addr = tuple(p)
        self.sock.sendto(finalPacket, addr)
        print 'packet forwarded'

    def getMAC(self, packet, nexthop, dip):
        e = packet[0][0:14]
        newE = list(struct.unpack("!6s6s2s", e))
        temp = e
        newE[0] = self.mactobinary('ff:ff:ff:ff:ff:ff:')
        print self.interface[3:]
        newE[1] = self.mactobinary(netifaces.ifaddresses(self.interface.strip())[17][0]['addr'])#temp[0]
        newE[2] = '\x08\x06'
        finalE = struct.pack("6s6s2s", *newE)
        
        i = packet[0][14:34]
        newI = struct.unpack("1s1s2s2s2s1s1s2s4s4s", i)
        
        a = packet[0][14:42]
        ahdr = struct.unpack("2s2s1s1s2s6s4s6s4s", a)
        aheader = list(ahdr)
        aheader[0] = '\x00\x01'
        aheader[1] = '\x08\x00'
        aheader[2] = '\x06'
        aheader[3] = '\x04'
        aheader[4] = '\x00\x01'
        myip=''
        netlist = netifaces.interfaces()
        for net in netlist:
            myIP = netifaces.ifaddresses(net)[2][0]['addr']
            myMAC = netifaces.ifaddresses(net)[17][0]['addr']
            if self.mactobinary(myMAC) == newE[0]:
                #myip = myIP
                myip = socket.inet_aton(myIP)
        aheader[5] = self.mactobinary(netifaces.ifaddresses(self.interface.strip())[17][0]['addr'])
        #if myip == '':
        #    sys.exit(-1)
        aheader[6] = socket.inet_aton(netifaces.ifaddresses(self.interface.strip())[2][0]['addr']) #myip
        aheader[7] = self.mactobinary('00:00:00:00:00:00')
        
        if nexthop == '-' or nexthop == '':
            nexthop = newI[9]
        else:
            nexthop = socket.inet_aton(nexthop)
        aheader[8] = nexthop
        sendA = struct.pack("2s2s1s1s2s6s4s6s4s", *aheader)
        sendpacket = finalE+sendA
        #self.sock.sendto(sendpacket, (socket.inet_aton(myip), net)) #packet[1] is not a right destination
        #for x in packet[1]:
            #print x
        p = list(packet[1])
        p[0] = self.interface.strip()
        p[3] = int(self.interface[6:7])
        addr = tuple(p)
        #for y in addr:
            #print y
        asock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        asock.sendto(sendpacket, addr)
        count = 0
        #change this bit down to the ####
        while count == 0:
            newerpacket = asock.recvfrom(1024)
            q = newerpacket[0][14:42]
            qq = struct.unpack("2s2s1s1s2s6s4s6s4s", q)
            #print count
            if qq[4] == '\x00\x02':
                count = count + 1
        asock.close()
        ############################    
        e2 = newerpacket[0][0:14]
        e3 = struct.unpack("!6s6s2s", e)
        print 'forward mac', binascii.hexlify(e3[1])
        self.mactable[dip] = e3[1]
        return e3[1]
        #############################

    def check(self, dest):
        #routing is the table
        maps = {'16':4, '24':6}
        for addr in self.routing:
            a = addr.split(' ')
            mask = a[0][9:]
            if dest[0:maps[mask]] == a[0][0:maps[mask]]:
                print 'found match'
                self.interface = a[2]
                return a[1]
        return 'nomatch'


    def respondToIcmp(self, packet, dMAC):
        e = struct.unpack("!6s6s2s", packet[0][0:14])
        temp = e
        eh = list(e)
        i = struct.unpack("1s1s2s2s2s1s1s2s4s4s", packet[0][14:34])
        temp2 = i
        ih = list(i)
        p = struct.unpack("1s1s2s4s", packet[0][34:42])
        ph = list(p)
        eh[0] = temp[1]
        eh[1] = temp[0]
        ih[8] = temp2[9]
        ih[9] = temp2[8]
        ph[0] = '\x00'
        newE = struct.pack("6s6s2s", *eh)
        newI = struct.pack("1s1s2s2s2s1s1s2s4s4s", *ih)
        newP = struct.pack("1s1s2s4s", *ph)
        sendPacket = newE+newI+newP+packet[0][42:]
        self.sock.sendto(sendPacket, packet[1])
        print 'icmp response sent'

    def respondToArp(self, packet, dMAC):
        e = struct.unpack("!6s6s2s", packet[0][0:14])
        eh = list(e)
        eh[0] = e[1]
        eh[1] = self.mactobinary(dMAC)
        a = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
        ah = list(a)
        ah[4] = '\x00\x02'
        ah[6] = a[8]
        ah[8] = a[6]
        ah[7] = a[5]
        ah[5] = self.mactobinary(dMAC)
        #pack n send
        newE = struct.pack("6s6s2s", *eh)
        newA = struct.pack("2s2s1s1s2s6s4s6s4s", *ah)
        sendPacket = newE+newA
        self.sock.sendto(sendPacket, packet[1])
        print 'arp response sent'


def main(argv):
    router = vrouter()
    router.sniff()

if __name__ == "__main__":
    main(sys.argv)
