#!/usr/bin/python

##
#
#Jake Young
#updated virtual router
#
##

import socket, os, sys
import netifaces
import struct
import binascii
import time

#1
#def mactobinary(mac):
#    return binascii.unhexlify(mac.replace(':', ''))
#1
#from http://stackoverflow.com/questions/2986702/need-some-help-converting-a-mac-address-to-binary-data-for-use-in-an-ethernet-fr

class vrouter(object):

    def mactobinary(self, mac):
        return binascii.unhexlify(mac.replace(':', ''))

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
                print aHeader[4]

                for net in netlist:
                    myIP = netifaces.ifaddresses(net)[2][0]['addr']
                    myMAC = netifaces.ifaddresses(net)[17][0]['addr']

                    if dest == myIP:
                        if aHeader[4] == '\x00\x01':
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
                        #print 'no ip match found'
                        continue
                        #maybe exit or break
                    forwardMAC = self.getMAC(packet, fDest, dip)
                    self.forward(packet, forwardMAC)
                    #getMAC //sends arp and returns mac
                    #forward //fixes ethernet header and sends
                    
    def forward(self, packet, mac):
        e = packet[0][0:14]
        eheader = list(struct.unpack("!6s6s2s", e))
        temp = eheader
        eheader[0] = mac
        eheader[1] = temp[0]
        fe = struct.pack("6s6s2s", *eheader)
        finalPacket = fe+packet[0][14:]
        self.sock.sendto(finalPacket, packet[1]) #i dont think packet[1] is right
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
        
        #sendE = []
        #sendE.append(self.mactobinary('ff:ff:ff:ff:ff:ff'))
        #sendE.append(newE[0])
        #sendE.append('\x08\x06')
        #finalE = struct.pack("6s6s2s", *sendE)
        
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
        aheader[8] = nexthop
        sendA = struct.pack("2s2s1s1s2s6s4s6s4s", *aheader)
        sendpacket = finalE+sendA
        #self.sock.sendto(sendpacket, (socket.inet_aton(myip), net)) #packet[1] is not a right destination
        for x in packet[1]:
            print x
        p = list(packet[1])
        p[0] = self.interface.strip()
        p[3] = int(self.interface[6:7])
        addr = tuple(p)
        for y in addr:
            print y
        self.sock.sendto(sendpacket, addr)  #try putting interface num for port              #packet[1])                #(net, 1024, 0, int(net[6:]), myip)) no error but doesn't show in wireshark
        print 'arp request sent'
        newerpacket = self.sock.recv(1024)    
        e2 = newerpacket[0][0:14]
        e3 = struct.unpack("!6s6s2s", e)
        print 'forward mac', e3[1]
        return e3[1]

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
                #if a[1] != '-':
                #    return a[1]
                #else:
                #    return '-'
                    #found matching ip and the next hop is not null
                    #ping router and forward to router
                    #else if next hop is null ping dest and forward


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
