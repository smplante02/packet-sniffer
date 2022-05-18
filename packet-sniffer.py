# packet sniffer in Python using socket package

import socket as s
import struct
import sys
from getmac import get_mac_address # from github, to parse mac addresses from headers

# setting everything up
# creating a TCP AF_INET (IPv4) socket as base
socket = s.socket(s.AF_INET, s.SOCK_RAW, s.ntohs(3))


# ethernet parser class, takes in full data
class EthernetParser:
    def __init__(self, data):
        self.data = data
        # ethernet header is 14 bytes long so parse up to there
        self.parsedData = struct.unpack('! 6s 6s H', self.data[:14])

        # translating to network-byte order so compatible with machines of both endian-nesses
        self.proto = s.htons(self.parsedData[2])

    def getMacAddresses(self):
        # can also use binascii.hexlify()
        ethDest, ethSrc = self.parsedData
        macDest = get_mac_address(ethDest)
        macSrc = get_mac_address(ethSrc)
        return macSrc, macDest

    def getRawData(self):
        # after ethernet header
        return self.data[14:]

    def getProtocol(self):
        return self.proto

    def printEther(self):
        print('\tSource: ', self.getMacAddresses()[0], '; Destination: ',
              self.getMacAddresses()[1], '; Protocol: ', self.getProtocol())


# ip address parser, takes in ethernet packet data TODO: FIX THIS
class IPParser:
    def __init__(self, data):
        self.data = data
        self.parsedData = struct.unpack('!BBHHHBBH4s4s', data)

    def getVersion(self):
        return self.parsedData[0]

    def getTOS(self):
        return self.parsedData[1]

    def getHeaderLength(self):
        return self.parsedData[2]

    def getID(self):
        return self.parsedData[3]

    def getFragOffset(self):
        return self.parsedData[4]

    def getTTL(self):
        return self.parsedData[5]

    def getProto(self):
        return self.parsedData[6]

    def getChecksum(self):
        return self.parsedData[7]

    def getSrcAddress(self):
        ipAddress = self.parsedData[8]
        return s.inet_ntoa(ipAddress)

    def getDestAddress(self):
        ipAddress = self.parsedData[9]
        return s.inet_ntoa(ipAddress)

    def printIP(self):
        print('\tVersion: ', self.getVersion(),
              '; TTL: ', self.getTTL(),
              '; Source: ', self.getSrcAddress(),
              '; Destination: ', self.getDestAddress(),
              '; Protocol: ', self.getProto())


class UDPParser:
    def __init__(self, data):
        self.data = data
        self.parsedData = struct.unpack('!HHHH', data)

    def getPorts(self):
        #source, destination ports
        return self.parsedData[0], self.parsedData[1]

    def getHeaderLength(self):
        return self.parsedData[2]

    def getChecksum(self):
        return self.parsedData[3]

    def printUDP(self):
        print('\tSource Port: ', self.getPorts()[0],
              '; Destination Port: ', self.getPorts()[1])


class TCPParser:
    def __init__(self, data):
        self.data = data
        self.parsedData = struct.unpack('!HHLLBBHHH', data)

    def getPorts(self):
        # source port, destination port
        return self.parsedData[0], self.parsedData[1]

    def getSeqNum(self):
        return self.parsedData[2]

    def getAckNum(self):
        return self.parsedData[3]

    def getOffset(self):
        return self.parsedData[4]

    def getFlag(self):
        return self.parsedData[5]

    def getWindow(self):
        return self.parsedData[6]

    def getChecksum(self):
        return self.parsedData[7]

    def getUrgency(self):
        return self.parsedData[8]

    def printTCP(self):
        print('\tSource Port: ', self.getPorts()[0],
              '; Destination Port: ', self.getPorts()[1])


class ICMPParser:
    def __init__(self, data):
        self.data = data
        self.parsedData = struct.unpack('!BBH', data)

    def getType(self):
        return self.parsedData[0]

    def getCode(self):
        return self.parsedData[1]

    def getCheckSum(self):
        return self.parsedData[2]

    def printICMP(self):
        print('\tType: ', self.getType())

# print all data received by socket
while True:
    data = socket.recvfrom(bufsize=1024)[0]
    eP = EthernetParser(data)
    print('Ethernet Parsed:')
    eP.printEther()

    # if ethernet specifies IP
    if eP.getProtocol() == 8:
        ip = IPParser(data[14:34])
        print('IP Parsed:')
        ip.printIP()

        # IP Proto #s from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        # if IP specifies UDP
        if ip.getProto == 17:
            udp = UDPParser(data[34:])
            print('UDP Parsed:')
            udp.printUDP()

        # if IP specifies TCP
        if ip.getProto() == 6:
            tcp = TCPParser(data[34:])
            print('TCP Parsed:')
            tcp.printTCP()

        # if IP specifies ICMP
        if ip.getProto() == 1:
            icmp = ICMPParser(data[34:])
            print('ICMP Parsed:')
            icmp.printICMP()

            
