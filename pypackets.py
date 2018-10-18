# import modules
import socket 
import struct
import binascii
import os
import pye

# Si el OS en windows
if os.name == "nt":
    # Esto nos sirve para referirnos al nuestro propio host
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind((HOST,0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
# Si el OS es linux
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

# ciclo para que no deje de capturar
#while True:
for x in range(0,5):  
    # Capture packets from network
    pkt=s.recvfrom(65565)

    # extract packets with the help of pye.unpack class 
    unpack=pye.unpack()
    print ("\n\n[+] ---------------- Paquete # %d ---- [+]" % x)
    print ("[+] ------------ Cabecera Ethernet ----- [+]")

    # print data on terminal
    for i in unpack.eth_header(pkt[0][0:14]).items():
        a,b=i
        print ("{} : {} | ".format(a,b))
    print ("\n[+] ------------ Cabecera IP ------------[+]")
    for i in unpack.ip_header(pkt[0][14:34]).items():
        a,b=i
        print ("{} : {} | ".format(a,b))
    print ("\n[+] ------------ Cabecera TCP ----------- [+]")
    for  i in unpack.tcp_header(pkt[0][34:54]).items():
        a,b=i
        print ("{} : {} | ".format(a,b))