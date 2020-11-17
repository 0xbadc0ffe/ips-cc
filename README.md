[English](README.md) | [Italian](README.it.md)
# A mini-IPS for CC
A program that has the purpose to block TCP data packets containing a given pattern.  
It uses iptables, available in the Linux Kernel >=2.4 .  
It can be programmed to block incoming or outgoing traffic just by editing the iptables rule.  
It doesn't handle IPv6 packets.  
It can also be programmed to send RST/ACK replies to dropped packets in order to kill/continue the connection.

## Arch Linux: Quick Start
Installing:
1. Make sure to have Python > 3.7
1. Install compile tools: `sudo pacman -S base-devel`
1. Install git: `sudo pacman -S git`
1. Make sure to have iptables
1. Install libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Install NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Append the iptables rule: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py -d`  (-d stands for debug)

## Debian: Quick Start
Installing:
1. Make sure to have Python > 3.7
1. Install compile tools: `sudo apt install build-essential`
1. Install git: `sudo apt install git`
1. Make sure to have iptables
1. Install libnetfilter_queue: `sudo apt install libnetfilter-queue-dev`
1. Install NetfilterQueue:   `git clone https://github.com/kti/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Append the iptables rule: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py -d`  (-d stands for debug)

## iptables example rules
1. Default: Block outgoing traffic from an application running on the machine (server) to clients: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`
1. Block incoming traffic from clients to an application running on the machine (server): `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`

## Debug mode
In debug mode the program will print on screen each packet it handles and save it in a .pcap file.  
To activate it: `sudo ./main.py -d` or `sudo ./main.py --debug`
