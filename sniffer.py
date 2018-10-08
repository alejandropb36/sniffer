import socket
import sys
import struct


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
#print (version)
TOS = unpackedData[1]
totalLength = unpackedData[2]
ID = unpackedData[3]


# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)