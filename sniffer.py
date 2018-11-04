#!/usr/bin/python
#
# Simplest Form Of Packet sniffer in python
# Works On Linux Platform
from io import open
import os
import sys
from scapy.all import * 
from lib.menu import *

opcionMenu = "1"
while opcionMenu != "0":
    menu()
    opcionMenu = input ("Elige una opcion: ")
    # if opcionMenu == "1":
    #     #capturarPaquetes()
    # elif opcionMenu == "2":
    #     #importarPaquete()
    # elif opcionMenu == "3":
    #     #Trabajando
    # else:
    #     print("Adios !!! :V")
    #     os.system("pause")
    cant = int(input('\t\t\t\tIngrese la cantidad de paquetes que desea capturar: '))
    a=sniff(filter="tcp", count=cant)
    print("",a.nsummary())
    os.system("pause")
	#numpck = int(input('\nIngrese el numero del paquete que quiere visualizar: '))
    #print(hexdump(a[numpck]))
