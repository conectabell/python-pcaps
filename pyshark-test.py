# -*- coding: utf-8 -*-
import pyshark
import argparse


parser = argparse.ArgumentParser(description="Descripcion del comando")
parser.add_argument("--verbosity", help="activate verbosity", action="store_true")
parser.add_argument("-L", "--live", help="Inicia captura Live de eth0")
parser.add_argument("-t", "--timeout", help="Indica el timeout de la captura Live, si se pone a 0 el sniff se hace contínuo.")
parser.add_argument("-l", "--packet_limit", help="Limita el número de paquetes que recoger")
parser.add_argument("-f", "--file", help="Adjunta el archivo indicado y busca http-auths")
parser.add_argument("-o", "--output", help="guardar pcap capturada a un archivo")
args = parser.parse_args()

if args.verbosity:
    print(">>> Verbosity Activado")

if args.live:
    if args.output:
        print ">>> Se guardarán los datos en: ", args.output
    else:
        args.output = "./temp.pcap"
    print ">>> Generando Captura Live escuchando en ", args.live
    capture = pyshark.LiveCapture(interface=args.live, display_filter='http.authbasic', output_file=args.output)
    if not args.timeout:
        args.timeout = 50
        print ">>> Timeout configurado a ", args.timeout, " segundos"
        # capture.sniff(timeout=50)
    elif not args.packet_limit:
        args.packet_limit = 10
    #print capture
    if args.timeout == 0:
        print ">>> Iniciando Captura ininterrumpida (timeout 0), limitando por el contados de paquetes: ", args.packet_limit
        for i, packet in enumerate(capture.sniff_continuously(packet_count=int(args.packet_limit))):
            print 'Packet num: ', i
            if args.verbosity:
                print 'Packet Content --=> ', packet
    elif args.timeout > 0:
        print ">>> Iniciando captura con timeout de ", args.timeout, " segundos"
        sniff = capture.sniff(packet_count=int(args.packet_limit), timeout=int(args.timeout))
        if not sniff:
            print ">>> No se ha capturado nada"
        else:
            for i, packet in enumerate():
                print "Default Limit set to ", args.packet_limit, " Packets"
                print 'Packet num: ' + str(i)
                if args.verbosity:
                    print 'Packet Content --=> ', packet

if args.file:
    capt = pyshark.FileCapture(args.file, display_filter='http.authbasic')
    # print capt
    for i, packet in enumerate(capt):
        print 'Packet num: ', str(i)
        if args.verbosity:
            print 'Packet Content --=> ', packet
