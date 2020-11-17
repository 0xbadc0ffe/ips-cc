# PCAP export module
import time
import binascii
import os


class PCAP:

    # Metodo costruttore dell'oggetto.
    # Al momento distrugge il vecchio file PCAP,
    # crea un header PCAP e lo scrive nel file.
    # Prende in input un oggetto di classe Log, un oggetto di classe Handling
    # e una stringa contenente il nome del file di output.
    def __init__(self, log, handling, filename="dropped_packets.pcap"):
        self.log = log
        self.handling = handling
        log.uplog("Starting PCAP exporting Module")

        # File opening (mode write binary).
        # If it fails, pcap exporter cannot work.
        try:
            self.outputFile = open(filename, "wb")
        except OSError:
            log.uplog("Error while opening " + filename)
            log.uplog("PCAP export will shutdown")
            self.outputFile = None
            return

        # Reporting self to the Handling object
        handling.pcap_hook(self)

        # PCAP file header. Generated with the make_header method.
        self.header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\xe4\x00\x00\x00'
        self.outputFile.write(self.header)
        # Flush is used to confirm the writing to the file.
        self.outputFile.flush()
        os.fsync(self.outputFile.fileno())

    # Funzione distruttore dell'oggetto: chiude il file di output.
    def __del__(self):
        if self.outputFile is not None:
            self.outputFile.close()

    # Metodo che ritorna i bytes dell'header di un file PCAP.
    #
    # Documentazione di riferimento:
    # http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-gharris-opsawg-pcap.xml&modeAsFormat=html/ascii&type=ascii#packet_record
    def make_header(self):
        header = 'D4C3B2A1'   # Magic Number in little endian
        header += '02000400'  # Version 2.4
        header += '00000000'  # Reserved 1
        header += '00000000'  # Reserved 2

        # SnapLen: maximum number of octets captured from each packet
        header += '00000400'

        # LinkType: Raw IPv4
        # Documentazione di riferimento:
        # http://www.tcpdump.org/linktypes.html
        header += 'E4000000'  # E4 (Hex) = 228 (Dec)

        header_byte = binascii.unhexlify(header)
        return header_byte

    # Metodo che aggiunge un record al file PCAP.
    # Per ogni pacchetto da aggiungere e' necessario un record.
    # Richiede in ingresso una stringa contenente
    # un pacchetto IP (In genere inizia con '450000').
    def make_packet_record(self, IP_packet):
        # TODO : hex può ritornare 0x3322 (elimina gli zero davanti)
        # si puo' usare la soluzione di sotto?
        # Seconds and microseconds
        time_hex = hex(int(time.time()))[2:10]  # Seconds from epoch
        time_1 = time_hex[0:2]
        time_2 = time_hex[2:4]
        time_3 = time_hex[4:6]
        time_4 = time_hex[6:8]
        time_dec = '00000000'  # We don't care about ms
        # Reversed order (Little Endian)
        packet_record = time_4 + time_3 + time_2 + time_1 + time_dec

        # Packet Length
        # IP_packet is a string, a byte is represented by two characters.
        packet_length_int = len(IP_packet) // 2
        packet_length_hex = hex(packet_length_int)[2:]
        # Fill the rest with zero
        packet_length = '0' * (8 - len(packet_length_hex)) + packet_length_hex
        # Reversed order (Little Endian)
        packet_length_le = ""
        packet_length_le = packet_length[6:8]
        packet_length_le += packet_length[4:6]
        packet_length_le += packet_length[2:4]
        packet_length_le += packet_length[0:2]
        packet_record += packet_length_le  # Captured Packet Length
        packet_record += packet_length_le  # Original Packet Length

        # IP Packet
        packet_record += IP_packet

        # Converting to bytes and writing to the file.
        packet_record_bytes = binascii.unhexlify(packet_record)
        self.outputFile.write(packet_record_bytes)
        # Flush is used to confirm the writing to the file.
        self.outputFile.flush()
        os.fsync(self.outputFile.fileno())
