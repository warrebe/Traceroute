# Author: Benjamin Warren
# Date: 01/31/2022
# Description: Trace Route and Send Ping application

# Citation for the following program:
      # Date: 01/31/2022
      # Based on: Skeleton code provided by OSU Online CS 372 course

# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        def __init__(self, ttl=None):
            if ttl is None:
                self.__ttl = 255                     # Time to live
            else:
                self.__ttl = ttl # For traceRoute

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):

            # Check Sequence reply to see if it matches
            if icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber():
                if self.__DEBUG_IcmpPacket:
                    print("Sequence Number match:", self.getPacketSequenceNumber())
                icmpReplyPacket.setIcmpSequence_IsValid(True)
            else:
                if self.__DEBUG_IcmpPacket:
                    print("Expected Sequence Number return to be:", self.getPacketSequenceNumber())
                    print("Instead ICMP reply returned:", icmpReplyPacket.getIcmpSequenceNumber())
                icmpReplyPacket.setIcmpSequence_IsValid(False)

            # Check Identifier reply to see if it matches
            if icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier():
                if self.__DEBUG_IcmpPacket:
                    print("Packet Identifier match:", self.getPacketIdentifier())
                icmpReplyPacket.setIcmpIdentifier_IsValid(True)
            else:
                if self.__DEBUG_IcmpPacket:
                    print("Expected Packet Identifier return to be:", self.getPacketIdentifier())
                    print("Instead ICMP reply returned:", icmpReplyPacket.getIcmpIdentifier())
                icmpReplyPacket.setIcmpIdentifier_IsValid(False)

            # Check Raw Data reply to see if it matches
            if icmpReplyPacket.getIcmpData() == self.getDataRaw():
                if self.__DEBUG_IcmpPacket:
                    print("Raw Data match:", self.getDataRaw())
                icmpReplyPacket.setIcmpRawData_IsValid(True)
            else:
                if self.__DEBUG_IcmpPacket:
                    print("Expected Raw Data return to be:", self.getDataRaw())
                    print("Instead ICMP reply returned:", icmpReplyPacket.getIcmpData())
                icmpReplyPacket.setIcmpRawData_IsValid(False)

            # Check if reply is valid (if reply matches original ping)
            if icmpReplyPacket.getIcmpIdentifier_IsValid():
                if icmpReplyPacket.getIcmpSequence_IsValid():
                    if icmpReplyPacket.getIcmpRawData_IsValid():
                        # Valid response
                        icmpReplyPacket.setIsValidResponse(True)
                        print("ICMP reply is valid") if self.__DEBUG_IcmpPacket else 0
                        return
            # Invalid response (does not match original ping)
            print("ICMP packet does not match original ping data") if self.__DEBUG_IcmpPacket else 0
            icmpReplyPacket.setIsValidResponse(False)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, trace = False):
            end = False
            ret = None
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            if self.__icmpTarget != self.__destinationIpAddress:
                if not trace:
                    print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            else:
                if not trace:
                    print("Pinging " + self.__icmpTarget)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    if not trace:
                        print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    if not trace:
                        print("  *        *        *        *        *  Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        ret = (timeReceived - pingStartTime) * 1000
                        if not trace:
                            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                    (
                                        self.getTtl(),
                                        (timeReceived - pingStartTime) * 1000,
                                        icmpType,
                                        icmpCode,
                                        addr[0]
                                    )
                                  )

                    elif icmpType == 3:                         # Destination Unreachable
                        ret = (timeReceived - pingStartTime) * 1000
                        if not trace:
                            print("Destination Unreachable")
                            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                      (
                                          self.getTtl(),
                                          (timeReceived - pingStartTime) * 1000,
                                          icmpType,
                                          icmpCode,
                                          addr[0]
                                      )
                                  )
                            # Source for codes:https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
                            if icmpCode == 0:
                                print("  Destination Network Unreachable")
                            elif icmpCode == 1:
                                print("  Destination Host Unreachable")
                            elif icmpCode == 2:
                                print("  Destination Protocol Unreachable")
                            elif icmpCode == 3:
                                print("  Destination Port Unreachable")
                            elif icmpCode == 4:
                                print("  Fragmentation Needed and Don't Fragment was Set")
                            elif icmpCode == 5:
                                print("  Source Route Failed")
                            elif icmpCode == 6:
                                print("  Destination Network Unknown")
                            elif icmpCode == 7:
                                print("  Destination Host Unknown")
                            elif icmpCode == 8:
                                print("  Source Host Isolated")
                            elif icmpCode == 9:
                                print("  Communication with Destination Network is Administratively Prohibited")
                            elif icmpCode == 10:
                                print("  Communication with Destination Host is Administratively Prohibited")
                            elif icmpCode == 11:
                                print("  Destination Network Unreachable for Type of Service")
                            elif icmpCode == 12:
                                print("  Destination Host Unreachable for Type of Service")
                            elif icmpCode == 13:
                                print("  Communication Administratively Prohibited")
                            elif icmpCode == 14:
                                print("  Host Precedence Violation")
                            elif icmpCode == 15:
                                print("  Precedence cutoff in effect")

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        ret = icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self, trace)
                        end = True
                        return ret, addr, end # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                addr = None
            finally:
                mySocket.close()
                return ret, addr, end

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __DEBUG_IcmpPacket_EchoReply = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket
            self.IcmpSequence_IsValid = False # Variable for identifying if sequence number is valid
            self.IcmpIdentifier_isValid = False # Variable for identifying if packet identifier is valid
            self.IcmpRawData_IsValid = False # Variable for identifying if raw data is valid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def getIcmpSequence_IsValid(self):
            # Returns IcmpSequence_IsValid variable boolean
            return self.IcmpSequence_IsValid

        def getIcmpIdentifier_IsValid(self):
            # Returns IcmpIdentifier_IsValid variable boolean
            return self.IcmpIdentifier_isValid

        def getIcmpRawData_IsValid(self):
            # Returns IcmpRawData_IsValid variable boolean
            return self.IcmpRawData_IsValid

        def isValidResponse(self):
            return self.__isValidResponse


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpSequence_IsValid(self, booleanValue):
            # Sets IcmpSequence_IsValid variable with boolean
            self.IcmpSequence_IsValid = booleanValue

        def setIcmpIdentifier_IsValid(self, booleanValue):
            # Sets IcmpIdentifier_IsValid variable with boolean
            self.IcmpIdentifier_isValid = booleanValue

        def setIcmpRawData_IsValid(self, booleanValue):
            # Sets IcmpRawData_IsValid variable with boolean
            self.IcmpRawData_IsValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, packet, trace):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            if not trace:
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                      (
                          ttl,
                          (timeReceived - timeSent) * 1000,
                          self.getIcmpType(),
                          self.getIcmpCode(),
                          self.getIcmpIdentifier(),
                          self.getIcmpSequenceNumber(),
                          addr[0]
                      )
                     )

            if self.isValidResponse():
                if self.__DEBUG_IcmpPacket_EchoReply:
                    # If ICMP response returned valid for all parameters
                    print("  ICMP response is valid")
            else:
                if self.__DEBUG_IcmpPacket_EchoReply:
                    # Find which parameters returned invalid and information on error
                    if not self.IcmpSequence_IsValid:
                        print("  Sequence number received:", self.getIcmpSequenceNumber())
                        print("  does not match original:", packet.getPacketSequenceNumber())
                    if not self.IcmpIdentifier_isValid:
                        print("  Packet identifier received:", self.getIcmpIdentifier())
                        print("  does not match original:", packet.getPacketIdentifier())
                    if not self.IcmpRawData_IsValid:
                        print("  Sequence number received:", self.getIcmpSequenceNumber())
                        print("  does not match original:", packet.getPacketSequenceNumber())
            return (timeReceived - timeSent) * 1000


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output
    __rttAve = 0  # Return time average for all pings
    __rttMin = 0  # Return time minimum over all pings
    __rttMax = 0  # Return time max over all pings
    __rtt = []  # List of return time values for operations

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host, ttl = None, trace = False):
        end = False
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            packetLoss = 0
            icmpPacket = IcmpHelperLibrary.IcmpPacket(ttl)

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            ret, traceIP, end = icmpPacket.sendEchoRequest(trace)                                            # Build IP
            if traceIP is None and trace:
                return
            if ret is not None:
                self.__rtt.append(ret)
                if self.__rtt is not None:
                    self.__rttAve = sum(self.__rtt) / len(self.__rtt)
                    self.__rttMin = min(self.__rtt)
                    self.__rttMax = max(self.__rtt)
                    if self.__DEBUG_IcmpHelperLibrary:
                        print("  RTT Average=%.0f ms    RTT Minimum=%.0f ms    RTT Maximum=%.0f ms" %
                              (
                                self.__rttAve,
                                self.__rttMin,
                                self.__rttMax,
                              )
                              )
            else:
                if self.__DEBUG_IcmpHelperLibrary:
                    print("Packet lost")
                packetLoss += 1

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
        received = 4 - packetLoss
        percent = str((packetLoss // 4) * 100) + "%"
        if not trace:
            print("""                    Ping statistics for %s:
                        Packets: Sent = 4, Received = %d, Lost = %d (%s percent loss),
                    Approximate round trip times in milli-seconds:
                        Minimum = %.0f ms, Maximum = %.0f ms, Average = %.0f ms""" %
                  (
                      host,
                      received,
                      packetLoss,
                      percent,
                      self.__rttAve,
                      self.__rttMin,
                      self.__rttMax,
                  )
                  )
        else:
            print("%3d      %3d ms      %3d ms      %3d ms      %s" %
            (
                ttl,
                self.__rttAve,
                self.__rttMax,
                self.__rttMin,
                traceIP[0]
            )
            )
        self.__rtt.clear()
        return end

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here
        hops = 30
        print("""            Tracing route to %s
            over a maximum of %d hops:""" %
              (
                  host,
                  hops,
              )
              )
        for i in range(1, hops):
            traceIcmpPing = IcmpHelperLibrary()
            end = traceIcmpPing.__sendIcmpEchoRequest(host, i, True)
            if end:
                print()
                print("Trace complete.")
                break


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    icmpHelperPing.traceRoute("www.telstra.net") # Australia
    # icmpHelperPing.traceRoute("www.kiwiinternet.co.nz") # New Zealand
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.traceRoute("facebook.com")
    # icmpHelperPing.traceRoute("oregonstate.edu")
    # icmpHelperPing.traceRoute("google.com")


if __name__ == "__main__":
    main()
