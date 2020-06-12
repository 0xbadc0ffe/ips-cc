# Un mini-IPS per CC
Un programma che ha lo scopo di bloccare l'uscita di pacchetti TCP contenenti un particolare pattern.  
Fa uso di iptables, disponibili a partire dal Kernel Linux 2.4.  


#### ARCH

## Quick Start (Italiano) 
Installazione (su Arch per ora):
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo pacman -S base-devel`
1. Installare git: `sudo pacman -S git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Installare NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py`  

## Quick Start (English)
Installing on Arch:
1. Make sure to have Python > 3.7
1. Install compile tools: `sudo pacman -S base-devel`
1. Install git: `sudo pacman -S git`
1. Make sure to have iptables
1. Install libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Install NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Append the iptables rule: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py`  


#### DEBIAN

## Quick Start (Italiano) 
Installazione (su Arch per ora):
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo apt install build-essential`
1. Installare git: `sudo apt install git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo apt install libnetfilter-queue-dev`
1. Installare NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py`  

## Quick Start (English)
Installing on Arch:
1. Make sure to have Python > 3.7
1. Install compile tools: `sudo apt install build-essential`
1. Install git: `sudo apt install git`
1. Make sure to have iptables
1. Install libnetfilter_queue: `sudo apt install libnetfilter-queue-dev`
1. Install NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Append the iptables rule: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py`  

