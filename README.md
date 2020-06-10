# Un mini-IPS per CC
Un programma che ha lo scopo di bloccare l'uscita di pacchetti TCP contenenti un particolare pattern.  
Fa uso di iptables, disponibili a partire dal Kernel Linux 2.4.  

Installazione (su Arch per ora):
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo pacman -S base-devel`
1. Installare git: `sudo pacman -S git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Installare NetfilterQueue:  `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py`  
