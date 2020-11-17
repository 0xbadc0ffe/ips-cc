#!/usr/bin/env python3
'''
 ips-cc main script.
 Edit parameters, append the iptables rule, then launch it
 with "sudo ./main.py" or "sudo ./main.py -d" for debug mode.
 This script will block any packet with the Data field matching
 at least one of the regular expressions in regex_list.
 In debug mode every packet will be printed on screen and saved in pcap file.
'''
from netfilterqueue import NetfilterQueue
import logger
import analysis
import utils
import packet_handling
import pcap
import stats
import atexit
import os

# Parameters
queue_number = 33
log_file = "logfile.log"
pcap_file = "dropped-packets.pcap"
services_file = "default-services.json"


# Parameter that controls the packet dropping policy:
# 0: only drop the packet;
# 1: drop the packet and send a RST packet to kill the connection;
# 2: drop the packet and send a ACK packet to continue the connection;
# 3: no drop, only substitute (censor mode).
dropping_policy = 1

# Checking root privileges
if not utils.is_root():
    print("You need root privileges to run this application!")
    exit(-1)

# Clear the screen
os.system("clear")


# Checking debug flag status (-d or --debug)
debug = utils.is_debug()

# This sets the logger treshold level
if debug:
    log_level = "DEBUG"
else:
    log_level = "INFO"

flags = utils.Flags()
dropping_policy = flags.dropping_policy
log_level = flags.log_level
# convertire la variabile debug con log_level e fare i controlli 
# if log_level == "DEBUG" or log_level == "ALL"?
# oppure aggiungere la variabile self.debug ad utils se si vuole distinguere
# modalità debug da log debug
debug = flags.debug
print(flags)

# Indispensable objects instantiation
log = logger.Log(log_file, log_level)
shield = analysis.Shield(log, queue_number, services_file)
handling = packet_handling.PacketHandling(log, shield, debug, dropping_policy)

# Optional objects instantiation: comment them to disable
statistics = stats.Stats(log, handling)
pcap_exporter = pcap.PCAP(log, handling, pcap_file)

log.uplog("Starting ips-cc")

# NetfilterQueue object instantiation and binding
nfqueue = NetfilterQueue()
nfqueue.bind(queue_number, handling.handle_packet)

# Define IPS behavior on exit
def exit_handler():
    log.uplog("Received Interrupt, shutting down")
    shield.close_shield()
    nfqueue.unbind()
    log.uplog("Stopped ips-cc")
    log.endlog()


atexit.register(exit_handler)

# "run()" is a blocking method. The program will close on CTRL-C
try:
    nfqueue.run()
except KeyboardInterrupt:
    pass
