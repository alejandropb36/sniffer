import socket, struct, binascii

__headers_support__="""
Ethernet header Extraction
IPv4 header Extraction
Tcp header Extraction
ICMP header Extraction
UDP header Extraction

"""

class unpack:
 def __cinit__(self):
  self.data=None

 # Ethernet Header
 def eth_header(self, data):
  storeobj=data
  storeobj=struct.unpack("!6s6sH",storeobj)
  destination_mac=binascii.hexlify(storeobj[0])
  source_mac=binascii.hexlify(storeobj[1])
  eth_protocol=storeobj[2]
  data={"MAC Destino":destination_mac,
  "MAC Origen":source_mac,
  "Protocolo":eth_protocol}
  return data

 # ICMP HEADER Extraction
 def icmp_header(self, data):
  icmph=struct.unpack('!BBH', data)
  icmp_type = icmph[0]
  code = icmph[1]
  checksum = icmph[2]
  data={'Tipo ICMP':icmp_type,
  "Code":code,
  "CheckSum":checksum}
  return data

 # UDP Header Extraction
 def udp_header(self, data):
  storeobj=struct.unpack('!HHHH', data)
  source_port = storeobj[0]
  dest_port = storeobj[1]
  length = storeobj[2]
  checksum = storeobj[3]
  data={"Puerto Origen":source_port,
  "Puerto Destino":dest_port,
  "Tamaño":length,
  "CheckSum":checksum}
  return data

 # IP Header Extraction
 def ip_header(self, data):
  storeobj=struct.unpack("!BBHHHBBH4s4s", data)
  _version=storeobj[0] 
  _tos=storeobj[1]
  _total_length =storeobj[2]
  _identification =storeobj[3]
  _fragment_Offset =storeobj[4]
  _ttl =storeobj[5]
  _protocol =storeobj[6]
  _header_checksum =storeobj[7]
  _source_address =socket.inet_ntoa(storeobj[8])
  _destination_address =socket.inet_ntoa(storeobj[9])

  data={'Version':_version,
  "TOS":_tos,
  "Tamaño total":_total_length,
  "Identificacion":_identification,
  "Fragment":_fragment_Offset,
  "TTL":_ttl,
  "Protocolo":_protocol,
  "Ecabezado CheckSum":_header_checksum,
  "Direccion Origen":_source_address,
  "Direccion Destino":_destination_address}
  return data

 # Tcp Header Extraction
 def tcp_header(self, data):
  storeobj=struct.unpack('!HHLLBBHHH',data)
  _source_port =storeobj[0] 
  _destination_port  =storeobj[1]
  _sequence_number  =storeobj[2]
  _acknowledge_number  =storeobj[3]
  _offset_reserved  =storeobj[4]
  _tcp_flag  =storeobj[5]
  _window  =storeobj[6]
  _checksum  =storeobj[7]
  _urgent_pointer =storeobj[8]
  data={"Puerto Origen":_source_port,
  "Puerto Destino":_destination_port,
  "Sequencia de numeros":_sequence_number,
  "Acknowledge Number":_acknowledge_number,
  "Offset & Reserved":_offset_reserved,
  "Tcp Flag":_tcp_flag,
  "Window":_window,
  "CheckSum":_checksum,
  "Urgent Pointer":_urgent_pointer
  }
  return data 

# Mac Address Formating
def mac_formater(a):
 b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
 return b

def get_host(q):
 try:
  k=socket.gethostbyaddr(q)
 except:
  k='Unknown'
 return k