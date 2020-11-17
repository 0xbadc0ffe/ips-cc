# Logging module
import time
from datetime import datetime


class Log:

    ENDSTRING = "\033[0;37;39m"
    STARTSTRING = "\033[{};{};{}m"

    # Metodo costruttore dell'oggetto.
    # Il logging ha inizio dal time passato
    # tramite parametro. Se non e' stato
    # passato, ha inizio da time.time().
    # Apre il file passatogli tramite parametro
    # e vi appende una linea iniziale.
    # level e' una stringa che specifica la
    # severita' sotto la quale non vengono
    # stampati i messaggi di logging.
    def __init__(self, logfile="logfile.log", level="INFO",
                 time_start=time.time(), erase_old_logfile=False):
        if time_start is None:
            time_start = time.time()
        self.time_start = time_start

        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # Time String

        # Prova ad aprire il file di logging.
        # Se non riesce stampa un errore.
        try:
            if erase_old_logfile:
                self.logfile = open(logfile, "w")
                self.logfile.write("[" + ts + "]: Erasing old Log session\n")
            else:
                self.logfile = open(logfile, "a")

            self.logfile.write("[" + ts + "]: Starting Log session\n")
        except OSError:
            print(self.STARTSTRING.format(1, 33, 40) + "[" + ts
                  + "] WARN: Error while opening logfile." + self.ENDSTRING)

        # Dictionary of log levels
        self.level_dict = {
            "ALL": 0,      # Gotta log 'em all
            "DEBUG": 1,    # Logs debug messages
            "INFO": 2,     # Logs info about progress of the service
            "WARN": 3,     # Logs potentially unwanted or harmful situations
            "DEFENCE": 4,  # Custom Level. Logs packets dropped by the IPS or notable external causes
            "ERROR": 5,    # Logs error events that might still allow the application to continue running
            "FATAL": 6     # Shit get real. Abort of service
        }

        try:
            self.level = self.level_dict[level]    # Level Treshold of logger
        except KeyError:
            self.level = self.level_dict["INFO"]
            print(self.STARTSTRING.format(1, 33, 40) + "[" + ts
                  + "] WARN: Wrong logging level." + self.ENDSTRING)

    # Set the logging level
    def set_log_level(self, level):
        self.level = level

    # Metodo di Update Log (log a livelli):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    # La stringa viene loggata solo se il suo livello
    # e' maggiore o uguale a quello impostato
    # alla creazione dell'oggetto log.
    def uplog(self, s, level="INFO", new_line=1):
        try:
            act_level = self.level_dict[level]
        except KeyError:
            level = "ALL"
            act_level = 0
            self.uplog("Wrong log level setted for string:\n" + s, "DEBUG")

        # If the actual logging level is < of the setted level
        # the method will print nothing.
        if act_level < self.level:
            return

        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string

        # Print the name of the level if > INFO
        if act_level > 2:
            log_s = "[" + ts + "]: " + level + ": " + s
        else:
            log_s = "[" + ts + "]: " + s

        # Try to log on file:
        # If failed a warn is added to the string (independently from the
        # treshold level). If it is going to be printed it is important!
        try:
            self.logfile.write(log_s + "\n")
        except OSError:
            log_s = log_s + "\n[WARN: Unable to write on Logfile]"

        log_s += "\n" * new_line

        # Set the color of the logging string
        #
        # Documentation:
        # https://ozzmaker.com/add-colour-to-text-in-python/
        if level == "ALL":
            clog = log_s  # clog = colored log string
        elif level == "DEBUG":
            # Green
            clog = self.STARTSTRING.format(1, 32, 38) + log_s + self.ENDSTRING
        elif level == "INFO":
            clog = log_s
        elif level == "WARN":
            # Yellow (bold)
            clog = self.STARTSTRING.format(1, 33, 38) + log_s + self.ENDSTRING
        elif level == "DEFENCE":
            # Cyan (bold)
            clog = self.STARTSTRING.format(1, 36, 38) + log_s + self.ENDSTRING
        elif level == "ERROR":
            # Red (bold)
            clog = self.STARTSTRING.format(1, 31, 38) + log_s + self.ENDSTRING
        elif level == "FATAL":
            # White on red (bold)
            clog = self.STARTSTRING.format(1, 37, 41) + log_s + self.ENDSTRING

        print(clog)  # Print on console

    # Metodo di custom update Log (Aggiornamento Log customizzato):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    # bold definisce se la stringa deve essere in grassetto mentre
    # color definisce il colore (tra quelli implmentati).
    # bold puo' essere 0 o 1 (grassetto).
    def cust_uplog(self, s, new_line=1, color=None, bold=0):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        log_s = "[" + ts + "]: " + s + "\n" * new_line

        try:
            self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)
        except OSError:
            self.uplog("Error while opening logfile", "DEBUG")

        if color is not None or bold != 0:
            if color is None:
                log_s = self.STARTSTRING.format(bold, 37, 39) + log_s
            elif color == "red":
                log_s = self.STARTSTRING.format(bold, 31, 39) + log_s
            elif color == "yellow":
                log_s = self.STARTSTRING.format(bold, 33, 39) + log_s
            elif color == "cyan":
                log_s = self.STARTSTRING.format(bold, 36, 39) + log_s
            log_s += self.ENDSTRING
        print(log_s)

    # Metodo di Relative Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo
    # relativo dall'avvio del logging.
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def rt_uplog(self, s, new_line=1):
        s = str(s)
        rts = "[%.3f]: " + s + "\n" * new_line  # relative time string
        print(rts % (time.time() - self.time_start))
        self.logfile.write(rts % (time.time() - self.time_start))

    # Funzione di No Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro, senza
    # indicazioni sul tempo.
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def nt_uplog(self, s, new_line=1):
        s = str(s)
        print(s + '\n' * (new_line - 1))
        try:
            self.logfile.write(s + "\n" * new_line)
        except OSError:
            self.uplog("Error while opening logfile", "DEBUG")

    # Metodo di Only File Update Log (Aggiornamento Log):
    # Stampa solo nel file di log la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale
    # (datetime.now)
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def of_uplog(self, s, new_line=1):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)

    # Metodo di chiusura logging:
    # Appende nel file una linea di terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n\n\n\n")
        self.logfile.close()
