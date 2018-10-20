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

class vrouter(object):

    def readtable(self, name):
        rtable = []
        f=open(name, 'r')
        for line in f:
            rtable.append(line.rstrip().split(' '))
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
            eType = binascii.hexlify(eheader[2])
            if eType[1] == '\x06':
                #get arp header
                ah = packet[0][14:42]
                aHeader = struct.unpack("2s2s1s1s2s6s4s6s4s", ah)
                #is it addressed to us?
                netlist = netifaces.interfaces()
                dest = socket.inet_ntoa(aHeader[8])

                for net in netlist:
                    myIP = netifaces.ifaddresses(net)[2][0]['addr']
                    myMAC = netifaces.ifaddresses(net)[17][0]['addr']

                    if dest == myIP:
                        if aHeader[4] == '\x00\x01':
                            print 'Got an ARP request'
                            respondToArp(packet)
            else:
                #forward packet
                print 'packet to forward'





    def respondToArp(self, packet):
        eh = list(struct.unpack("!6s6s2s", packet[0][0:14]))
        temp = eh
        #switch mac addresses
        eh[0] = temp[1]
        eh[1] = temp[0]
        ah = list(struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42]))
        temp2 = ah
        ah[4] = '\x00\x02'
        #MAC
        ah[5] = temp2[7]
        ah[7] = temp2[5]
        #IP
        ah[6] = temp2[8]
        ah[8] = temp2[6]
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
