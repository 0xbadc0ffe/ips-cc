[English](README.md) | [Italian](README.it.md)
# Un mini-IPS per CC
Un programma che ha lo scopo di bloccare il transito di pacchetti TCP contenenti un dato pattern.  
Fa uso di iptables, disponibili nel Kernel Linux a partire dalla versione 2.4 .  
Può essere programmato per bloccare traffico in entrata o in uscita semplicemente modificando la regola iptables.  
Non gestisce i pacchetti IPv6.  
Può inoltre essere programmato per inviare risposte RST/ACK ai pacchetti bloccati per killare/continuare la connessione.

## Arch Linux: Quick Start
Installazione:
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo pacman -S base-devel`
1. Installare git: `sudo pacman -S git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Installare NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py -d`  (-d serve per il debug)

## Debian: Quick Start 
Installazione:
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo apt install build-essential`
1. Installare git: `sudo apt install git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo apt install libnetfilter-queue-dev`
1. Installare NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py -d`  (-d serve per il debug)

## Regole di esempio iptables
1. Default: Blocca traffico in uscita da una applicazione in esecuzione sulla macchina (server) verso i clients: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`
1. Blocca traffico in entrata dai clients verso una applicazione in esecuzione sulla macchina (server): `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`

## Debug mode
In modalità di debug il programmerà stamperà a schermo ogni pacchetto che gestisce e lo salverà in un file .pcap.  
Per attivarla: `sudo ./main.py -d` or `sudo ./main.py --debug`
