#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue

def print_and_accept(pkt):
	print('-------------')
	payload = pkt.get_payload()
	#Fino al 20 sicuro e' la parte di IPv4
	portaSource = payload[20:22].hex()
	portaSourceint = int(portaSource, 16)
	print("porta source: " + str(portaSourceint))
	portaDest = payload[22:24].hex()
	portaDestint = int(portaDest, 16)
	print("porta destinazione: " + str(portaDestint))
	print(pkt)
	print(payload.hex())
	print('-------------')
	pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(33, print_and_accept)

try:
	nfqueue.run()
except KeyboardInterrupt:
	print('')

nfqueue.unbind()
