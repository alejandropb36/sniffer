from io import open
import os
import sys
from scapy.all import * 
from lib.menu import *

class Sniffer(object):
    pkts = 0
    def capturarPaquetes(protocolo,cantidad):
        pkts = sniff(protocolo,cantidad)
    
    def importarPaquetes(archvio):
        pkts = rdpcap(archvio)
    
    def paqueteHexadecimal(numeroPaquete):
        pkt_hex = hexdump(pkts[numpkt])
        print(pkt_hex)
    
    