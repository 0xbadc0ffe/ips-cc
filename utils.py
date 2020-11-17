# Tools module
import os
import sys
import socket

class Flags:
    # TODO spostare in packet handling?
    # TODO lasicare in caps tutto? magari solo log ...
    # TODO loggare la dropping policy quando si inizializza Flags o quando si settano a runtime?
    # TODO usare le set invece di self.bla = bla ?
    # TODO passare il log?
    ACCEPTABLE = {
        "-log": ["ALL", "DEBUG", "INFO", "WARN", "DEFENCE", "ERROR", "FATAL"],
        "-dropping-policy": ["0", "DROP-ALL", "1", "RST", "2", "ACK", "3", "CENS"],
        "-pcap": ["NONE", "ALL", "DROPPED"]
    }

    def __init__(self):
        if os.geteuid() != 0:
            self.is_root = False
        else:
            self.is_root = True

        if len(sys.argv) > 1:

            log.uplog("cIAO")
            
            # TODO, se sono presenti sia -d che -log? rimuovere -d?
            # allo stato attuale -d viene ignorato se si mette -log loglevel
            if "-log" in sys.argv:
                log_level = sys.argv[sys.argv.index("-log") + 1]
                if  log_level in self.ACCEPTABLE["-log"]:
                    self.log_level = log_level
                else:
                    # passare il loggere all'oggetto flag?
                    # self.log.uplog("Bad argument for -log","WARN")
                    # self.log.print_usage() # da aggiungere
                    self.log_level = "INFO"
                    pass
            else:
                # if log flag is not set but the IPS is
                # running as debug mode, set log level to DEBUG
                if "-d" in sys.argv or "--debug" in sys.argv:
                    self.log_level = "DEBUG"
                else:
                    self.log_level = "INFO"

            # this is debug mode, not debug logging level
            if "-d" in sys.argv or "--debug" in sys.argv:
                self.debug = True
            else:
                self.debug = False
            
            # TODO fornire la stringa di censura se -dropping-policy CENS o 3? 
            if "-dropping-policy" in sys.argv:
                drop_pol = sys.argv[sys.argv.index("-dropping-policy") + 1]
                if drop_pol in self.ACCEPTABLE["-dropping-policy"]:
                    if drop_pol == "DROP-ALL":
                        drop_pol = 0
                    if drop_pol == "RST":
                        drop_pol = 1
                    if drop_pol == "ACK":
                        drop_pol = 2
                    if drop_pol == "CENS":
                        drop_pol = 3
                    self.dropping_policy = int(drop_pol)
                else:
                    # self.log.uplog("Bad argument for -dropping policy","WARN")
                    # self.log.print_usage() # da aggiungere
                    self.dropping_policy = 1  #RST
                    pass
            else:
                self.dropping_policy = 1  #RST

           
            if "-pcap" in sys.argv:
                pcap = sys.argv[sys.argv.index("-pcap") + 1]
                if  pcap in self.ACCEPTABLE["-pcap"]:
                    self.pcap = pcap
                else:
                    # self.log.uplog("Bad argument for -pcap","WARN")
                    # self.log.print_usage() # da aggiungere
                    self.pcap = "NONE"
                    pass
            else:
                self.pcap = "NONE"

        else:
            self.log_level = "INFO"
            self.dropping_policy = 1  #RST
            self.pcap = "NONE"
            self.debug = False


    def __str__(self):
        string = "Root: " + str(self.is_root) + "\n"
        string += "Debug mode: " + str(self.debug) + "\n"
        string += "Logging Level: " + self.log_level + "\n"
        string += "Dropping policy: " + str(self.dropping_policy) + "\n"
        string += "Pcap policy: " +self.pcap + "\n"
        return string

    def set_log_level(self, level):
        self.log_level = level

    def set_pcap_policy(self, pcap_pol): # TODO cambia nome
        self.pcap = pcap

    def set_dropping_policy(self, dropping_policy):
        self.dropping_policy = dropping_policy


# Funzione che calcola la lunghezza dell'header IPv4
# basandosi sul valore IHL (Internet Header Length).
#
# Documentazione di riferimento:
# https://en.wikipedia.org/wiki/IPv4#IHL
def calcola_lunghezza_header(carattere):
    lunghezza = 20
    ihl = int(carattere, 16)
    lunghezza = (ihl * 32) // 8
    return lunghezza

# Funzione che ritorna la stringa dell'indirizzo IPv4 (dotted)
# basandosi sulla stringa esadecimale passatagli.
def IPv4HexToDotted(stringa_hex):
    if len(stringa_hex) != 8:
        raise ValueError
    primo = int(stringa_hex[0:2], 16)
    secondo = int(stringa_hex[2:4], 16)
    terzo = int(stringa_hex[4:6], 16)
    quarto = int(stringa_hex[6:8], 16)
    return '%d.%d.%d.%d' % (primo, secondo, terzo, quarto)

# Funzione che controlla se l'utente che ha avviato lo script e' root.
def is_root():
    if os.geteuid() != 0:
        return False
    return True

# Funzione che ritorna True se il programma e'
# stato avviato passando l'argomento -d o --debug
def is_debug():
    if len(sys.argv) > 1:
        if "-d" in sys.argv or "--debug" in sys.argv:
            return True
    return False

# TODO Docs
# IPSorgente: FF113344 Porta: O8AE
def genera_RST(IPSorgente, IPDestinatario, PortaSorgente,
               PortaDestinazione, newACK, newSeq, rst_ack):

    # IP Header with no checksum set
    header = {}
    header[0] = 0x45  # IPv4, Length=20
    header[1] = 0x00
    header[2] = 0x00
    header[3] = 0x28  # Total Length
    header[4] = 0x61  # Identification 1
    header[5] = 0xb5  # Identification 2
    header[6] = 0x00
    header[7] = 0x00
    header[8] = 0x40  # TTL
    header[9] = 0x06  # Protocol = TCP
    header[10] = 0x00  # Checksum 1
    header[11] = 0x00  # Checksum 2
    header[12] = int(IPSorgente[0:2], 16)  # Source 1
    header[13] = int(IPSorgente[2:4], 16)  # Source 2
    header[14] = int(IPSorgente[4:6], 16)  # Source 3
    header[15] = int(IPSorgente[6:8], 16)  # Source 4
    header[16] = int(IPDestinatario[0:2], 16)  # Dest 1
    header[17] = int(IPDestinatario[2:4], 16)  # Dest 2
    header[18] = int(IPDestinatario[4:6], 16)  # Dest 3
    header[19] = int(IPDestinatario[6:8], 16)  # Dest 4

    # Calculating checksum
    checksum = checksum_IPv4_header(header)  # e.g. 0xB861
    checksum1 = checksum[2:4]  # e.g. B8
    checksum2 = checksum[4:6]  # e.g. 61
    # Setting checksum in header
    header[10] = int(checksum1, 16)
    header[11] = int(checksum2, 16)

    # TCP Header with no checksum set
    TCPheader = {}
    TCPheader[0] = int(PortaSorgente[0:2], 16)  # Source Port 1
    TCPheader[1] = int(PortaSorgente[2:4], 16)  # Source Port 2
    TCPheader[2] = int(PortaDestinazione[0:2], 16)  # Dest Port 1
    TCPheader[3] = int(PortaDestinazione[2:4], 16)  # Dest Port 2
    TCPheader[4] = newSeq[0]   # Sequence Number 1
    TCPheader[5] = newSeq[1]   # Sequence Number 2
    TCPheader[6] = newSeq[2]   # Sequence Number 3
    TCPheader[7] = newSeq[3]   # Sequence Number 4
    TCPheader[8] = newACK[0]   # Acknowledgment 1
    TCPheader[9] = newACK[1]   # Acknowledgment 2
    TCPheader[10] = newACK[2]  # Acknowledgment 3
    TCPheader[11] = newACK[3]  # Acknowledgment 4
    TCPheader[12] = 0x50  # Header Length
    if rst_ack == 1:
        TCPheader[13] = 0x04  # Flags RST 04
        TCPheader[14] = 0x00  # Window size 1
        TCPheader[15] = 0x00  # Window size 2
    else:
        TCPheader[13] = 0x10  # Flags ACK 10
        TCPheader[14] = 0xff  # Window size 1
        TCPheader[15] = 0xff  # Window size 2
    TCPheader[16] = 0x00  # Checksum 1
    TCPheader[17] = 0x00  # Checksum 2
    TCPheader[18] = 0x00  # Urgent pointer 1
    TCPheader[19] = 0x00  # Urgent pointer 2

    # TCP checksum: Generating PseudoHeader.
    #
    # Documentation:
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
    PseudoHeader = {}
    PseudoHeader[0] = int(IPSorgente[0:2], 16)      # Source 1
    PseudoHeader[1] = int(IPSorgente[2:4], 16)      # Source 2
    PseudoHeader[2] = int(IPSorgente[4:6], 16)      # Source 3
    PseudoHeader[3] = int(IPSorgente[6:8], 16)      # Source 4
    PseudoHeader[4] = int(IPDestinatario[0:2], 16)  # Dest 1
    PseudoHeader[5] = int(IPDestinatario[2:4], 16)  # Dest 2
    PseudoHeader[6] = int(IPDestinatario[4:6], 16)  # Dest 3
    PseudoHeader[7] = int(IPDestinatario[6:8], 16)  # Dest 4
    PseudoHeader[8] = 0x00
    PseudoHeader[9] = 0x06   # Protocol
    PseudoHeader[10] = 0x00  # TCP length 1
    PseudoHeader[11] = 0x14  # TCP length 2 (20 in esadecimale)

    # Merging dictionaries
    merged_dict = PseudoHeader.copy()
    for i in range(20):
        merged_dict[i + 12] = TCPheader[i]

    # Calculating checksum
    checksum = checksum_IPv4_header(merged_dict)  # e.g. 0xB861
    checksum1 = checksum[2:4]  # e.g. B8
    checksum2 = checksum[4:6]  # e.g. 61
    # Setting checksum in header
    TCPheader[16] = int(checksum1, 16)
    TCPheader[17] = int(checksum2, 16)

    # Dictionary to byte
    packet = b''
    for i in header:
        packet = packet + bytes([header[i]])
    for j in TCPheader:
        packet = packet + bytes([TCPheader[j]])

    # Sending the packet
    #
    # Documentation:
    # https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Calculating the destination IP address (Dotted Notation)
    destIPv4 = ""
    for i in range(0, 8, 2):
        destIPv4 += str(int(IPDestinatario[i] + IPDestinatario[i + 1], 16))
        destIPv4 += "."
    destIPv4 = destIPv4[:-1]
    # TODO spostare invio in Handling?
    s.sendto(packet, (destIPv4, 0))

# Calculates the checksum for an IP header
# Author: Grant Curell
def checksum_IPv4_header(ip_header):
    cksum = 0
    pointer = 0
    size = len(ip_header)
    while size > 1:
        cksum += int((str("%02x" % (ip_header[pointer],))
                      + str("%02x" % (ip_header[pointer + 1],))), 16)
        size -= 2
        pointer += 2
    if size:
        cksum += ip_header[pointer]
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)
    cksum = hex((~cksum) & 0xFFFF)
    lenght = len(cksum)
    # Filling with zero (e.g. 0xb1a => 0x0b1a)
    return "0x" + (6 - lenght) * "0" + cksum[2:]

# Ricalcola il checksum
# TODO: ricalcola i campi che definiscono la lunghezza
# scambio ip perchè il pacchetto e' in INPUT
# TODO: gestire se in output... stessa storia del riconoscimento del servizio
def recomp_checksum(payload, inizioTCP, IPDestinatario, IPSorgente):
    temp = IPSorgente
    IPSorgente = IPDestinatario
    IPDestinatario = temp

    # Costruisco pseudo-header
    PseudoHeader = {}
    PseudoHeader[0] = int(IPSorgente[0:2], 16)      # Source 1
    PseudoHeader[1] = int(IPSorgente[2:4], 16)      # Source 2
    PseudoHeader[2] = int(IPSorgente[4:6], 16)      # Source 3
    PseudoHeader[3] = int(IPSorgente[6:8], 16)      # Source 4
    PseudoHeader[4] = int(IPDestinatario[0:2], 16)  # Dest 1
    PseudoHeader[5] = int(IPDestinatario[2:4], 16)  # Dest 2
    PseudoHeader[6] = int(IPDestinatario[4:6], 16)  # Dest 3
    PseudoHeader[7] = int(IPDestinatario[6:8], 16)  # Dest 4
    PseudoHeader[8] = 0x00
    PseudoHeader[9] = 0x06  # Protocol
    PseudoHeader[10] = 0x00  # TCP length 1
    PseudoHeader[11] = 0x14 + 7  # TCP length 2 (20 in Hex) + 7(python\n)
    # python e' li' perche' testing della censura di python\n
    # TODO SOMMARE LA LUNGHEZZA DEI DATI PER BENE

    # Azzero il checksum
    zeros = b'\x00\x00'
    # print("\nFunzione checksum:")
    # print(payload[inizioTCP:])
    payload = payload[:inizioTCP + 16] + zeros + payload[inizioTCP + 18:]
    # print(payload[inizioTCP:])

    # Costruzione disionario per la funzione di checksum
    pay_dict = {}
    nh = len(PseudoHeader)
    for i in range(nh):
        pay_dict[i] = PseudoHeader[i]
    for i in range(nh, len(payload) + nh - inizioTCP):
        # Qui va bene che venga convertito ad int
        pay_dict[i] = payload[i - nh + inizioTCP]
    # print(pay_dict)

    # Calcolo il checksum e lo rimetto al suo posto
    # print("InzioTcp: "+str(inizioTCP)+"  Lunghezza Pseudoheader: "
    # +str(nh)+"  Posizione checksum nel dizionario: "+str(nh+16))
    checksum = int(checksum_IPv4_header(pay_dict), 16)
    print("Checksum: " + str(checksum.to_bytes(2, "big")) + str(checksum))
    # print(payload[inizioTCP:])
    payload = payload[:inizioTCP + 16] + checksum.to_bytes(2, "big")
    payload += payload[inizioTCP + 18:]
    # payload = payload[: inizioTCP+16]+b'\xcf\x9a'+payload[inizioTCP+18:]
    # print(payload[inizioTCP:])
    # print(payload)
    return payload

# TODO Docs
def genera_argomenti(payload_hex, inizioTCP, shield, rst_ack, data_length):
    # TODO rischio che la porta del client sia uguale ad una di
    # quelle su cui vige una regola. Basso rischio.

    startTCPhex = 2 * inizioTCP
    ipSource = payload_hex[24:32]
    ipDest = payload_hex[32:40]
    portaSource = payload_hex[startTCPhex:startTCPhex + 4]
    portaDest = payload_hex[startTCPhex + 4:startTCPhex + 8]
    # print("genera argomenti")
    # print("ipSource: " + ipSource + " ipDest: " + ipDest +
    # " portaSource: " + portaSource + " portaDest: " + portaDest)

    # TODO FIXME Al posto di True ci va pacchettoRicevutoInINPUT
    if(True):
        # rule = shield.services[int(portaDest, 16)]
        rule = "INPUT"
        if rule == "INPUT":

            oldAck = [0, 0, 0, 0]
            oldAck[0] = int(payload_hex[startTCPhex + 16:startTCPhex + 18], 16)
            oldAck[1] = int(payload_hex[startTCPhex + 18:startTCPhex + 20], 16)
            oldAck[2] = int(payload_hex[startTCPhex + 20:startTCPhex + 22], 16)
            oldAck[3] = int(payload_hex[startTCPhex + 22:startTCPhex + 24], 16)

            if rst_ack == 1:
                # RST in risposta ad un pacchetto bloccato in input
                newAck = [0, 0, 0, 0]
                newSeq = oldAck

            if rst_ack == 2:
                # ACK in risposta ad un pacchetto bloccato in input
                newSeq = oldAck

                oldSeqN = payload_hex[startTCPhex + 8: startTCPhex + 16]
                oldSeqN = int(oldSeqN, 16)
                oldSeqN = hex(oldSeqN + data_length)
                oldSeq = [0, 0, 0, 0]
                oldSeq[0] = int(oldSeqN[2:4], 16)
                oldSeq[1] = int(oldSeqN[4:6], 16)
                oldSeq[2] = int(oldSeqN[6:8], 16)
                oldSeq[3] = int(oldSeqN[8:10], 16)

                newAck = oldSeq
            # Il return ha i valori IP e Porte invertiti perche'
            # il pacchetto e' stato bloccato in input.
            return ipDest, ipSource, portaDest, portaSource, newAck, newSeq

        # TODO controlla il caso rule == OUTPUT.
        # In teoria è un caso falsato.

    else:
        rule = shield.rules[int(portaSource, 16)]

        if rule == "OUTPUT":

            oldAck = [0, 0, 0, 0]
            oldAck[0] = int(payload_hex[startTCPhex + 16:startTCPhex + 18], 16)
            oldAck[1] = int(payload_hex[startTCPhex + 18:startTCPhex + 20], 16)
            oldAck[2] = int(payload_hex[startTCPhex + 20:startTCPhex + 22], 16)
            oldAck[3] = int(payload_hex[startTCPhex + 22:startTCPhex + 24], 16)

            oldSeq = [0, 0, 0, 0]
            oldSeq[0] = int(payload_hex[startTCPhex + 8: startTCPhex + 10], 16)
            oldSeq[1] = int(payload_hex[startTCPhex + 10:startTCPhex + 12], 16)
            oldSeq[2] = int(payload_hex[startTCPhex + 12:startTCPhex + 14], 16)
            oldSeq[3] = int(payload_hex[startTCPhex + 14:startTCPhex + 16], 16)

            if rst_ack == 1:
                # RST in risposta ad un pacchetto bloccato in output
                newSeq = oldSeq
                newAck = [0, 0, 0, 0]

            if rst_ack == 2:
                # ACK in risposta ad un pacchetto bloccato in output
                newSeq = oldSeq
                newAck = oldAck

            return ipSource, ipDest, portaSource, portaDest, newAck, newSeq

        return None, None, None, None, None, None

        # TODO controlla il caso rule == INPUT.
        # In teoria è un caso falsato.
