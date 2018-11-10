from io import open
import os
import sys
from scapy.all import * 
from lib.menu import *

class Sniffer():

    pkts = 0

    def capturarPaquetes(protocolo,cantidad):
        pkts = sniff(filter = protocolo,count = cantidad)
    
    def importarPaquetes(archvio):
        pkts = rdpcap(archvio)
    
    def paqueteHexadecimal(numeroPaquete):
        pkt_hex = hexdump(pkts[numeroPaquete])
        print(pkt_hex)

    def detallarPaquete(numeroPaquete):
        pkt_show = pkts[numeroPaquete].show()
        print(pkt_show)
    
    def exportarPaquetes(archivo):
        wrpcap(archivo,pkts)
    
    def mostrarPaquetes():
        print("",pkts.nsummary())
    
    