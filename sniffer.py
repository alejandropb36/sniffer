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
        pkt_count = int(input('\t\t\t\tIngrese la cantidad de paquetes que desea capturar: '))
        pkts = sniff(filter="tcp", count = pkt_count)
        print("",pkts.nsummary())

        numpkt = int(input('\nIngrese el numero del paquete que quiere visualizar: '))
        os.system("cls")
        
        print("\n\t-------- Paquete visualizado en hexadecimal --------\n")
        pkt_hex = hexdump(pkts[numpkt])
        #print(hexdump(pkt[numpkt]))
        print(pkt_hex)
        os.system("pause")

        os.system("cls")
        print(pkts[numpkt].show())
        os.system("pause")

        guardar = input("\t Desea guardar el paquete en un archivo .cap [y/n]: ")
        if guardar == "y":
            wrpcap(str(numpkt) + ".cap",pkts[numpkt]) #(1.cap,1)
        os.system("pause")

    elif opcionMenu == "2":
        #importarPaquete()
        print("Opcion 2 del menu")
        file_name = input("\tEscribe el nombre del archivo .cap a importar: ")
        pkts = rdpcap(file_name)

        print("",pkts.nsummary())

        numpkt = int(input('\nIngrese el numero del paquete que quiere visualizar: '))
        os.system("cls")
        
        print("\n\t-------- Paquete visualizado en hexadecimal --------\n")
        pkt_hex = hexdump(pkts[numpkt])
        #print(hexdump(pkt[numpkt]))
        print(pkt_hex)
        os.system("pause")

        os.system("cls")
        print(pkts[numpkt].show())
        os.system("pause")
    elif opcionMenu == "3":
        #Trabajando
        print("Trabajndo ... ! :D")
        os.system("pause")
    else:
        print("Adios !!! :V")
        os.system("pause")
