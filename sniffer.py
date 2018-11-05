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
    if opcionMenu == "1":
        #capturarPaquetes()
        cant = int(input('\t\t\t\tIngrese la cantidad de paquetes que desea capturar: '))
        a=sniff(filter="tcp", count=cant)
        print("",a.nsummary())
        os.system("pause")
    elif opcionMenu == "2":
        #importarPaquete()
        print("Opcion 2 del menu")
        os.system("pause")
    elif opcionMenu == "3":
        #Trabajando
        print("Opcion 3 del menu")
        os.system("pause")
    else:
        print("Adios !!! :V")
        os.system("pause")
    
	#numpck = int(input('\nIngrese el numero del paquete que quiere visualizar: '))
    #print(hexdump(a[numpck]))
