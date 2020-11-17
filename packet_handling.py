# Packet Handling Module
import utils


class PacketHandling:

    # Metodo costruttore dell'oggetto.
    # Prende in input un oggetto di classe Log,
    # un oggetto di classe Shield, un valore booleano utilizzato
    # per determinare se stampare o meno le linee di debug e
    # la policy di drop dei pacchetti:
    # 0: only drop; 1: RST in reply; 2: ACK in reply; 3: Censor mode.
    def __init__(self, log, shield, debug=False, dropping_policy=0):
        self.log = log
        self.shield = shield
        self.debug = debug
        self.rst_ack = dropping_policy  # TODO CHANGE
        self.stats = None
        self.pcap = None
        self.log.uplog("Starting Packet Handling Module")
        if self.debug:
            self.log.uplog("Debug mode, logging each packet")

    # Metodo setter di self.stats:
    # Viene chiamato dall'oggetto di classe Stats.
    # Necessario per l'aggiornamento delle statistiche.
    def stats_hook(self, statistics):
        if statistics is not None:
            self.stats = statistics
            self.log.uplog("Statistics Module hooked to Handling Module")

    # Metodo setter di self.pcap:
    # Viene chiamato dall'oggetto di classe PCAP.
    # Necessario per l'export dei pacchetti droppati.
    def pcap_hook(self, pcap_obj):
        if pcap_obj is not None:
            self.pcap = pcap_obj
            self.log.uplog("PCAP Module hooked to Handling Module")

    # Metodo che verra' chiamato dal main e
    # deve essere specificato in:
    # nfqueue.bind(numero_queue, PacketHandling::handle_packet).
    # Prende in input un oggetto di classe Packet e
    # verifica se e' presente la flag di debug.
    # Se e' presente stampa i dati del pacchetto
    # a video e scrive il pacchetto nel file pcap.
    # Infine, facendo uso dell'oggetto di classe
    # Shield, decreta il verdetto del pacchetto.
    def handle_packet(self, pkt):
        payload = pkt.get_payload()
        payload_hex = payload.hex()

        # Verifica della versione di IP del pacchetto:
        # Se non e' 4, non effettuo controlli e lo rifiuto.
        versioneIP = payload_hex[0]
        if versioneIP != '4':
            self.log.uplog("Got a non-IPv4 packet, dropping it", "DEFENCE")
            pkt.drop()
            if self.stats:
                self.stats.add_dropped()
            return

        # Calcolo Header Length: Uso campo IHL dell'header IPv4
        inizioTCP = utils.calcola_lunghezza_header(payload_hex[1])

        # TODO: Da qui implementare comportamento se il pacchetto non e' TCP.
        # Usare Protocol (ip.proto) di IPv4. 0x06 = TCP
        # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        # Se il pacchetto ricevuto non e' TCP, lo accetto TODO FIXME
        if payload_hex[19] != '6':
            self.log.uplog("Got a non-TCP packet, accepting it", "DEFENCE")
            pkt.accept()
            if self.stats:
                self.stats.add_accepted()
            return

        # Uso campo Data Offset dell'header TCP
        data_offset = payload_hex[inizioTCP * 2 + 24]
        lunghezza_header_TCP = utils.calcola_lunghezza_header(data_offset)
        # Dimensione totale degli header IPv4 + TCP, da qui iniziano i dati.
        dim_header = inizioTCP + lunghezza_header_TCP

        # Se il debug e' abilitato, scrive il pacchetto
        # nel file pcap, stampa a video gli indirizzi
        # e porte sorgente/destinazione. Infine
        # decodifica (UTF-8) e stampa a video
        # il campo Data del segmento TCP.
        if self.debug:
            # Salva OGNI pacchetto nel file .pcap, se l'exporter e' attivo
            if self.pcap:
                self.pcap.make_packet_record(payload_hex)

            self.log.nt_uplog('-------------')

            # "TCP Packet, x bytes"
            self.log.uplog(pkt)

            # Source/Dest IPv4 and ports
            try:
                ipSource = payload_hex[24:32]
                ipDest = payload_hex[32:40]
                ipSourceint = utils.IPv4HexToDotted(ipSource)
                ipDestint = utils.IPv4HexToDotted(ipDest)
                self.log.uplog("Source IPv4: " + ipSourceint
                               + "  Destination IPv4: " + ipDestint)

                portaSource = payload[inizioTCP:inizioTCP + 2].hex()
                portaSourceint = int(portaSource, 16)
                portaDest = payload[inizioTCP + 2:inizioTCP + 4].hex()
                portaDestint = int(portaDest, 16)
                self.log.uplog("Source port: " + str(portaSourceint)
                               + "  Destination Port: " + str(portaDestint))
            except ValueError:
                self.log.uplog("Error while decoding IPv4 or port", "ERROR")

            # TCP Data
            try:
                data_received = payload[dim_header:-1].decode('utf-8')
                self.log.uplog('Data received: ' + data_received)
            except UnicodeDecodeError:
                self.log.uplog("Can't decode received data")

            self.log.nt_uplog('-------------')

        # Verifica se il pacchetto e' da scartare
        match = self.shield.is_droppable(payload, dim_header)
        if match:
            if(self.rst_ack == 3):
                # payload = self.shield.censor(payload,dim_header)
                # print(self.shield.censor(payload,dim_header)[dim_header:])
                # TODO: set del pacchetto e accept()
                # ipSource = payload_hex[24:32]
                # ipDest = payload_hex[32:40]
                # payload2 = utils.recomp_checksum(payload, inizioTCP,
                #                                 ipDest, ipSource)
                # print(payload)
                # print(payload2)
                # if(payload == payload2):
                #    print("Checksums match")
                # pkt.set_payload(payload2)
                self.log.uplog("Censor mode not implemented yet", "ERROR")
                pkt.accept()
                if self.stats:
                    self.stats.add_accepted()
                return
            else:
                pkt.drop()
                if self.stats:
                    self.stats.add_dropped()

            # Salvataggio del pacchetto solo se l'IPS non e' in debug mode
            # e l'exporter e' attivo, altrimenti e' stato gia' salvato sopra.
            if not self.debug:
                if self.pcap:
                    self.pcap.make_packet_record(payload_hex)

            self.log.uplog("Packet dropped", "DEFENCE")

            # Verifico se devo solo droppare il pacchetto (rst_ack == 0);
            # dropparlo e inviare un pacchetto RST (rst_ack == 1) oppure
            # dropparlo e inviare un pacchetto ACK (rst_ack == 2).
            if self.rst_ack != 0 and self.rst_ack != 3:
                # Dal campo Total Length di IPv4
                total_packet_length = int(payload_hex[4:8], 16)

                [ipSource, ipDest, portaSource, portaDest, newAck, newSeq] = utils.genera_argomenti(
                    payload_hex, inizioTCP, self.shield, self.rst_ack,
                    total_packet_length - dim_header)

                utils.genera_RST(ipSource, ipDest, portaSource, portaDest,
                                 newAck, newSeq, self.rst_ack)
        else:
            pkt.accept()
            if self.stats:
                self.stats.add_accepted()
