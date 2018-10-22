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
def mactobinary(mac):
    return binascii.unhexlify(mac.replace(':', ''))
#1
#from http://stackoverflow.com/questions/2986702/need-some-help-converting-a-mac-address-to-binary-data-for-use-in-an-ethernet-fr

routing = "global"
class vrouter(object):
    
    def readtable(self, name):
        rtable = []
        f=open(name, 'r')
        for line in f:
            rtable.append(line.replace("/"," ").rstrip().split(' '))
        return rtable

    def __init__(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        except socket.error:
            print 'socket not created.\n'
            sys.exit(-1)

        #read in routing table
        name = raw_input("Enter routing table name: ")
        global routing
        routing = self.readtable(name)
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
                            elif aHeader[4] == '\x00\x02':
                                
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
                                print 'Not for me need to route'
                                #trying to match the destination ip with and ip in the table to find
                                #an interface to send another arp over to 
                                #having trouble matching the destination ip with the ips
                                #in the file
                                #if dest == self.check(dest):
                                    #print 'found one'
                                    #the 3 spot in the table file is the interface, just trying to 
                                    #matht the interface to send packet over
                                if net == self.check(dest) :
                                    print 'Not for me need to route'                                        
                                    self.respondToArp(packet,dest)

                #elif protocol == '\x06':
                #   print 'n'
                    #tcp
                #elif protocol == '\x11':
                #   print 'n'
                    #udp

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
        eh[1] = mactobinary(dMAC)
        a = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
        ah = list(a)
        ah[4] = '\x00\x02'
        ah[6] = a[8]
        ah[8] = a[6]
        ah[7] = a[5]
        ah[5] = mactobinary(dMAC)
        #pack n send
        newE = struct.pack("6s6s2s", *eh)
        newA = struct.pack("2s2s1s1s2s6s4s6s4s", *ah)
        sendPacket = newE+newA
        self.sock.sendto(sendPacket, packet[1])
        print 'arp response sent'

    #new method to send and ARP to fine the mac for the next node instead of sending mac
    #it send the ip of the mac it is looking for
    def SendingArp(self, packet, dest):
        e = struct.unpack("!6s6s2s", packet[0][0:14])
        eh = list(e)
        eh[0] = e[1]
        eh[1] = mactobinary(netifaces.ifaddresses(net)[17][0]['addr'])
        a = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
        ah = list(a)
        ah[4] = '\x00\x02'
        ah[6] = a[8]
        ah[8] = dest
        ah[7] = a[5]
        ah[5] = mactobinary(netifaces.ifaddresses(net)[17][0]['addr'])
        #pack n send
        newE = struct.pack("6s6s2s", *eh)
        newA = struct.pack("2s2s1s1s2s6s4s6s4s", *ah)
        sendPacket = newE+newA
        self.sock.sendto(sendPacket, packet[1])
        print 'arp response sent'

    def check(self,dest):
        maps = {'16':4,'24':6}
        for addr in routing:            
            if dest[:maps[addr[1]]] == addr[0][:maps[addr[1]]]:
                print 'found match'
                return addr[3]

def main(argv):
    router = vrouter()
    router.sniff()

if __name__ == "__main__":
    main(sys.argv)
