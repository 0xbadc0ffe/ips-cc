# Statistics module

# Parameters
# TODO EVERY al posto di EACH
PRINT_EACH_DROPPED_PACKETS = 5
PRINT_EACH_ACCEPTED_PACKETS = 500
PRINT_AFTER_QUEUED_PACKETS = 9


class Stats:
    # Metodo costruttore dell'oggetto.
    # Prende in input un oggetto di classe Log e uno di classe Handling.
    def __init__(self, log, handling):
        self.log = log
        log.uplog("Starting Statistics Module")
        # Comunico a Handling il riferimento di Stats
        handling.stats_hook(self)
        # Inizializzo il conto totale dei pacchetti a zero
        self.acceptedPkt = 0
        self.droppedPkt = 0
        # Questi due contatori servono per triggerare la
        # stampa delle statistiche senza usare un Timer.
        self.acceptedDelta = 0
        self.droppedDelta = 0

    # Metodo distruttore dell'oggetto.
    # Stampa un messaggio a video e
    # salva il resoconto in un file.
    # def __del__(self):
        # self.log.uplog("Stopping Statistics Module")
        # self.log.uplog("Total Accepted Packets: " + str(self.acceptedPkt))
        # self.log.uplog("Total Dropped Packets : " + str(self.droppedPkt))

    # Metodo chiamato ogni volta che un pacchetto viene droppato
    def add_dropped(self):
        self.droppedPkt += 1
        self.droppedDelta += 1
        # Stampa le stats se e' stato superato il limite di pacchetti droppati
        if self.droppedDelta >= PRINT_EACH_DROPPED_PACKETS:
            self.droppedDelta = 0  # Reset contatore
            self.print_stats()

    # Metodo chiamato ogni volta che un pacchetto viene accettato
    def add_accepted(self):
        self.acceptedPkt += 1
        self.acceptedDelta += 1
        # Stampa le stats se e' stato superato il limite di pacchetti accettati
        if self.acceptedDelta >= PRINT_EACH_ACCEPTED_PACKETS:
            self.acceptedDelta = 0  # Reset contatore
            self.print_stats()

    # Metodo che stampa a video quanti pacchetti sono stati accettati,
    # quanti ne sono stati droppati e la percentuale di drop.
    def print_stats(self):
        totalPkt = self.acceptedPkt + self.droppedPkt
        # Se il totale e' zero, non ha senso stampare nulla.
        if totalPkt != 0:
            self.droppedPercentage = self.droppedPkt * 100 // totalPkt
            stats_string = "Accepted pkts: {}; ".format(self.acceptedPkt)
            stats_string += "Dropped pkts: {} ".format(self.droppedPkt)
            stats_string += "({}%)".format(self.droppedPercentage)

            # Statistiche di netfilter_queue
            [nf2, nf5, nf6] = self.apriFileQueue()
            # Se nf2 != None ed e' stato superato uno dei limiti
            if nf2 and (int(nf2) > PRINT_AFTER_QUEUED_PACKETS
                        or int(nf5) > 0 or int(nf6) > 0):
                queue_string = "Queued pkts: {}; ".format(nf2)
                queue_string += "Pkts dropped by queue: {}; ".format(nf5)
                queue_string += "Pkts dropped by userspace: {}".format(nf6)
                self.log.uplog(queue_string, "WARN")

            self.log.uplog(stats_string, "DEFENCE")

    # Metodo che apre il file nfnetlink_queue
    # ed estrae le statistiche della coda.
    # TODO : E se ci sono piu' code?
    #
    # Documentazione di riferimento:
    # https://github.com/kti/python-netfilterqueue/blob/master/README.rst#usage
    def apriFileQueue(self):
        # Apertura del file
        try:
            queueFile = open("/proc/net/netfilter/nfnetlink_queue", "r")
        except FileNotFoundError:
            # Succede se non c'e' un programma bindato ad una nfqueue.
            self.log.uplog("Cannot find nfnetlink_queue.", "ERROR")
            return None, None, None
        except OSError:
            # Puo' succedere se ci sono problemi con i permessi.
            self.log.uplog("Cannot open nfnetlink_queue.", "WARN")
            return None, None, None

        # Lettura del file in una stringa e creazione di un array da essa.
        try:
            nf_string = queueFile.read().strip()
            queueFile.close()
            nf_array = nf_string.split()
        except OSError:
            self.log.uplog("Error while reading nfnetlink_queue.", "WARN")
            return None, None, None

        # Verifica che il file abbia il numero di campi atteso.
        if len(nf_array) != 9:
            self.log.uplog("nfnetlink_queue file: unknown format.", "WARN")
            return None, None, None

        # Ritorno dei dati letti:
        # nf_array[2] Number of currently queued packets
        # nf_array[5] Number of packets dropped because queue was full
        # nf_array[6] Number of packets dropped because netlink message could
        #             not be sent to userspace.
        return nf_array[2], nf_array[5], nf_array[6]
