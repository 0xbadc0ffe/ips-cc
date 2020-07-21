#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
import re #TODO: si puo' importare meno?
import time
import my_logging as mylog


# Parametri
numero_queue = 33
regexp_compilata = re.compile(b'CC{\w+}')

# Funzione che analizza un pacchetto ricevuto
# dalla coda. Dopo aver verificato che il
# pacchetto e' IPv4, calcola la lunghezza
# dell'header IP, estrae porta sorgente e
# porta di destinazione, stampa a video i
# byte ricevuti e infine, dopo aver
# sottoposto i byte ricevuti ad una
# ricerca in base all'espressione regolare
# fornita, decide se lasciar passare il
# pacchetto o rifiutarlo.
def gestisci_pacchetto(pkt):
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
	#print(payload_hex)
	print(payload)
	print('-------------')
	
	# Ricerca dell'espressione regolare
	match = regexp_compilata.search(payload)
	if match:
		pkt.drop()
		print("Pacchetto droppato")
	else:
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


# Creazione e bind dell'oggetto di classe NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, gestisci_pacchetto)

log = mylog.Log(time.time())
log.uplog("ips-cc avviato")

try:
	nfqueue.run()
except KeyboardInterrupt:
	print('')

nfqueue.unbind()
log.uplog("ips-cc terminato")
log.endlog()
