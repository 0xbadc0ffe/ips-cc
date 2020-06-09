#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue

numero_queue = 33

def print_and_accept(pkt):
	print('-------------')
	payload = pkt.get_payload()
	payload_hex = payload.hex()
	
	# Verifica della versione di IP del pacchetto:
	# Se non e' 4, non effettuo controlli
	# e lo accetto.
	versioneIP = payload_hex[0]
	if versioneIP != '4':
		print("Pacchetto non IPv4")
		pkt.accept()
		return

	inizioTCP = calcola_lunghezza_ipv4(payload_hex[1])

	portaSource = payload[inizioTCP:inizioTCP+2].hex()
	portaSourceint = int(portaSource, 16)
	print("porta source: " + str(portaSourceint))
	
	portaDest = payload[inizioTCP+2:inizioTCP+4].hex()
	portaDestint = int(portaDest, 16)
	print("porta destinazione: " + str(portaDestint))
	
	# TODO: verificare se SYN e' settato, in tal caso -> accept()
	print(pkt)
	print(payload_hex)
	print('-------------')
	pkt.accept()

# Funzione che calcola la lunghezza del pacchetto IPv4
# basandosi sul valore IHL (Internet Header Length).
#
# Documentazione di riferimento:
# https://en.wikipedia.org/wiki/IPv4#IHL
def calcola_lunghezza_ipv4(carattere):
	lunghezza = 20
	ihl = int(carattere, 16)
	lunghezza = (ihl*32)//8
	return lunghezza

nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, print_and_accept)

try:
	nfqueue.run()
except KeyboardInterrupt:
	print('')

nfqueue.unbind()
