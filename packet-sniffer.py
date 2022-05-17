# packet sniffer in Python using socket package

import socket as s
import struct
import sys
from getmac import get_mac_address # from github, to parse mac addresses from headers

# setting everything up
# creating a TCP AF_INET (IPv4) socket as base
socket = s.socket(s.AF_INET, s.SOCK_RAW, s.IPPROTO_TCP)


# ethernet parser class
class EthernetParser():
    def __init__(self, data):
        self.data = data
        # ethernet header is 14 bytes long so parse up to there
        self.parsedData = struct.unpack('! 6s 6s H', self.data[:14])

        # translating to network-byte order so compatible with machines of both endian-nesses
        self.proto = s.htons(self.parsedData[2])

    def getMacAddresses(self):
        ethDest, ethSrc = self.parsedData
        macDest = get_mac_address(ethDest)
        macSrc = get_mac_address(ethSrc)
        return macSrc, macDest

    def getRawData(self):
        # after ethernet header
        return self.data[14:]

    def getProtocol(self):
        return self.proto


# print all data received by socket
while True:
    data = socket.recvfrom(bufsize=1024)[0]
    eP = EthernetParser(data)
    print('Ethernet Parsed:')
    source, dest = eP.getMacAddresses()
    proto = eP.getProtocol()
    print('\tSource: ', source, '; Destination: ', dest, '; Protocol: ', proto)

