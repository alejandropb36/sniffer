import socket
import sys
import struct
import re


def reciveData (s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print("An error happened. ")
        sys.exc_info()
    return data[0]
# Obtiene el tiempo de servicio - 8bits
def getTOS (data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 
        5: "CRITIC/ECP", 6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS
 
 # Obtener bandera de 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

def getProtocol(protocolNr):
    protocolFile = open('Protocolo.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocolNr), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No such protocol."
# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

data = reciveData(s)
# En el unpack se utiliza ! cuando hablamos de red
# y las letras B H ... son para saber que tamano de
# desplazamiento se va a hacer el :20 es que son los
# primero 20 bytes
unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])
#print (unpackedData)
version_IHL = unpackedData[0]
version = version_IHL >> 4
IHL = version_IHL & 0xf
#print (version) esto fue una prueba
TOS = unpackedData[1]
totalLength = unpackedData[2]
ID = unpackedData[3]
flags = unpackedData[4]
fragmentOffset = unpackedData[4] & 0x1FFF
TTL = unpackedData[6]
protocolNr = unpackedData[6]
checksum = unpackedData[7]
sourceAddress = socket.inet_ntoa(unpackedData[8])
destinationAddress = socket.inet_ntoa(unpackedData[9])
print ('\n\n')
print("-------------------------------------------------------------------------------")
print ("An IP packet with the size %i was captured." % (unpackedData[2]))
print ("Raw data: " + str(data))
print ("\nParsed data")
print ("Version:\t\t" + str(version))
print ("Header Length:\t\t" + str(IHL*4) + " bytes")
print ("Type of Service:\t" + getTOS(TOS))
print ("Length:\t\t\t" + str(totalLength))
print ("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
print ("Flags:\t\t\t" + getFlags(flags))
print ("Fragment offset:\t" + str(fragmentOffset))
print ("TTL:\t\t\t" + str(TTL))
print ("Protocol:\t\t" + getProtocol(protocolNr))
print ("Checksum:\t\t" + str(checksum))
print ("Source:\t\t\t" + sourceAddress)
print ("Destination:\t\t" + destinationAddress)
print ("Payload:\n" + str(data[20:]))
print("-------------------------------------------------------------------------------")
print ('\n\n')


# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)