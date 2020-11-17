# Analysis Module
# Kowalski, Analysis!
import re
import subprocess
import json


# This class defines the object Service, whose fields describe the port, type and rule applied.
# This last field implies that different rules (input/output) are represented by different objects.
class Service:
    CREATE_RULE_COMM = 'iptables -A {} -j NFQUEUE --queue-num {} -p tcp --{} {}'
    ERASE_RULE_COMM = 'iptables -D {} {}'
    RULE_STR1 = "NFQUEUE    tcp  --  0.0.0.0/0            0.0.0.0/0            tcp {}:{} NFQUEUE num {}"
    RULE_STR2 = "NFQUEUE    tcp  --  anywhere             anywhere             tcp {}:{} NFQUEUE num {}"

    def __init__(self, port, regex_list, log, queue_num,
                 ipt_list=[], firewall_direction="INPUT",
                 service_type="Raw", name="SERVICE"):
        self.firewall_direction = firewall_direction
        self.service_type = service_type
        self.regex_list = regex_list
        self.compiled_regex = []
        self.log = log
        self.port = port
        self.key = firewall_direction[0] + "-" + str(port)
        self.queue_num = queue_num
        self.ipt_list = ipt_list
        self.name = name
        # Initializing Service obj, setting
        # the corresponding iptables rule
        # and compiling all regex
        self.set_compiled_regex()
        self.set_rule()

    # TODO add:
    #def _str_(self):

    #def _repr_(self):
    # json

    # equal override
    #def _eq_(self, obj):
    #   return isinstance(obj, Service) and obj.equalityprop == self.equalityprop

    # not equal override
    #def __ne__(self, obj):
    #   return not self == obj

    # Setting iptables rule on creation for this instance
    # e.g.:
    #'iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`
    #'iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`
    def set_rule(self):
        # if rule exists, return
        if self.check_rule()[0] != -1:
            self.log.uplog("Rule already setted", "INFO")
            return

        chain = self.firewall_direction
        if chain == "INPUT":
            port_str = 'dport'
        elif chain == "OUTPUT":
            port_str = 'sport'
        else:
            self.log.uplog("Wrong or unimplemented Chain", "ERROR")
            return
        command = self.CREATE_RULE_COMM.format(self.firewall_direction,
                                               self.queue_num, port_str,
                                               self.port)
        setProcess = subprocess.run(command.split(), 
                                    stdout=subprocess.PIPE, timeout=5)

        if setProcess.returncode != 0:
            self.log.uplog("Error while setting the iptables rule for "
                           + f"{self.key}", "ERROR")
            return
        
        port_str = port_str[0] + "pt" # dport -> dpt; sport -> spt
        rule = self.RULE_STR1.format(port_str, self.port, self.queue_num)
        self.ipt_list.append(rule)


    # Check for the presence of the iptables rule relative to the
    # Service obj parameters.
    # This method returns a tuple containing:
    # 1: its number in the chain (so that can be easily erased)
    #    or -1 if not found.
    # 2: the position of the rule in the list or -1 if the rule format is wrong
    # WARNING: this number may change if other rules in the same
    # chain are erased while the program is running.
    def check_rule(self):
        chain = self.firewall_direction
        if chain == "INPUT":
            port_str = 'dpt'
        elif chain == "OUTPUT":
            port_str = 'spt'
        else:
            self.log.uplog("Wrong or unimplemented Chain ","ERROR")
            return -1, -1

        # Counters
        cnt_in_chain = 0
        counter = 0
        for r in self.ipt_list:

            if r == self.RULE_STR1.format(port_str, self.port, self.queue_num) or r == self.RULE_STR2.format(port_str, self.port, self.queue_num):
                # Rule found
                cnt_in_chain += 1
                return cnt_in_chain, counter

            elif f"    tcp {port_str}:" in r and  f'NFQUEUE num {self.queue_num}' in r:
                cnt_in_chain += 1
            counter += 1
        return -1, -1 


    # Erase the iptables rule relative to this service.
    # This happens even if the rule existed before the service creation,
    # because it belongs to the same Queue.
    def erase_rule(self):
        num_in_chain, num_in_list = self.check_rule()
        if num_in_chain > 0:
            comm = self.ERASE_RULE_COMM.format(self.firewall_direction, 
                                                num_in_chain)
            proc = subprocess.run(comm.split(), stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, timeout=5)
            if proc.returncode != 0:
                self.log.uplog("Error while removing the iptables rule for "
                               + f"{self.key}", "ERROR")
        else:
            self.log.uplog(f"Rule not initialized or removed before closure for {self.key}", "WARN")

        # TODO Comment
        if num_in_list >= 0:
            self.ipt_list.pop(num_in_list)


    # Build the compiled regex list and print all the
    # regex for this service.
    def set_compiled_regex(self):
        if len(self.regex_list) == 0:
            self.log.cust_uplog("Service " + self.key + " [Type: "
                                + self.service_type + "]"
                                + " has an empty regex list", new_line=0,
                                color=None, bold=1)
            self.log.uplog("The IPS will accept all packets on " + self.key, "WARN", 0)
            self.log.nt_uplog("\n")
            return

        self.log.cust_uplog("Service " + self.key
                            + " [Type: " + self.service_type + "]", new_line=0,
                            color=None, bold=1)
        for r in self.regex_list:
            self.compiled_regex.append(re.compile(r.encode()))
            self.log.uplog("Regex added: " + r, "INFO", 0)
        self.log.nt_uplog("\n")



class Shield:
    # Metodo costruttore dell'oggetto.
    # Riceve in input un oggetto di classe Log, il numero della coda,
    # il nome del file in cui sono presenti i servizi di default,
    # e un dizionario di oggetti Service.
    # Fa cose TODO
    def __init__(self, log, queue_num,
                 def_serv_file="default-services.json", services={}):
        log.uplog("Generating Shield object:","INFO",1)
        self.log = log
        self.services = services
        self.disabled_services = {}
        self.queue_num = queue_num
        self.ipt_list =[]
        self.def_serv_file = def_serv_file
        # INITIALIZING
        self.gen_list_iptables()
        self.restore_defaults()


    # This method executes 'iptables -L -n' and
    # returns its output as a list. If the logging has been set
    # to debug, this method will also log the iptables list.
    def gen_list_iptables(self):
        process = subprocess.run(["iptables", "-L", "-n"],
                                 stdout=subprocess.PIPE, timeout=5)
        if process.returncode != 0:
            self.log.uplog("iptables listing failed", "ERROR")
            return

        ip_str = process.stdout.decode()

        # Debug mode: print iptables list
        self.log.uplog(ip_str, "DEBUG")
        identifier =  "NFQUEUE num " + str(self.queue_num)

        ipt_list = []
        for line in ip_str.split("\n"):
            if identifier in line:
                ipt_list.append(line)
        self.ipt_list = ipt_list


    # This method executes 'iptables -L -n' and updates
    # the property self.ipt_list shared by all services.
    # If remove_olds is set as True it will erase the 
    # service, otherwise it will disable it. 
    def update_iptables_list(self, remove_olds=False):
        process = subprocess.run(["iptables", "-L", "-n"],
                                 stdout=subprocess.PIPE, timeout=5)

        if process.returncode != 0:
            self.log.uplog("iptables listing failed", "ERROR")
            return

        ip_str = process.stdout.decode()
        identifier =  "NFQUEUE num " + str(self.queue_num)

        ipt_list =[]
        for line in ip_str.split("\n"):
            if identifier in line:
                ipt_list.append(line)

        # Updates the old ipt_list and disable services 
        # whose rules has been (externally) removed 
        for r in self.ipt_list:
            if r in ipt_list:
                pass
            else:
                # rule removed during runtime
                if "dpt" in r:
                    fw_dir = "I-"
                    d_str = "dpt"
                elif "spt" in r:
                    fw_dir = "O-"
                    d_str = "spt"
                port = r.split(":")[1]
                port = port.split()[0]
                key = fw_dir + port
                # Removing rule from ipt_list
                RULE_STR1 = "NFQUEUE    tcp  --  0.0.0.0/0            0.0.0.0/0            tcp {}:{} NFQUEUE num {}"
                rule = RULE_STR1.format(d_str, port, self.queue_num)
                try:
                    self.ipt_list.remove(rule)
                except ValueError:
                    self.log.uplog("The removed rule for "+ key + " has not been deleted","ERROR")
                if remove_olds:
                    # remove service
                    self.erase_service_by_key(key)
                else:
                    # disabling service
                    self.disable_serv(key)
        self.ipt_list = ipt_list


    # disable the given service
    def disable_serv(self, key):
        serv = self.services.pop(key)
        self.disabled_services[key] = serv

    # enable the given service
    def enable_serv(self, key):
        serv = self.disabled_services.pop(key)
        self.add_service_by_object(serv)




    # Create a service and add it to services list.
    # Returns the created service object.
    def add_service(self, port, regex_list, firewall_direction="INPUT",
                    service_type="Raw", service_name="SERVICE"):
        key = firewall_direction[0] + "-" + str(port)
        for k in self.services:
            if k == key:
                self.log.uplog("Existing Service found during creation of the object, overwriting the old Service","WARN")
        service = Service(port, regex_list, self.log,
                          self.queue_num, self.ipt_list, firewall_direction,
                          service_type, service_name)
        self.services[key] = service
        self.log.uplog("Added Service on Port "
                        + str(port) + ", Type " + service_type, "ALL")
        return self.services[key]

    # Create a service and add it to services list.
    # Returns the created service object.
    def add_service_by_object(self, service):
        for k in self.services:
            if k == service.key:
                self.log.uplog("Existing Service found during creation of the object, overwriting the old Service","WARN")
        self.services[service.key] = service
        self.log.uplog("Added Service on Port "
                        + str(service.port) + ", Type " + service.service_type, "ALL")
        return self.services[service.key]


    # Erase a service, removes it from the list and
    # erase its iptables rule
    def erase_service(self, port, firewall_direction="INPUT"):
        sr_str = firewall_direction[0] + "-" + str(port)
        sr = self.services[sr_str]
        sr.erase_rule()
        self.services.pop(sr_str)

    def erase_service_by_key(self, service_key):
        sr = self.services[service_key]
        sr.erase_rule()
        self.services.pop(service_key)



    # Looks at the def_serv_file extension and chooses
    # the restore method to call
    def restore_defaults(self):
        ext = self.def_serv_file.split(".")[-1]
        if ext == "json":
            self.restore_defaults_from_json()
        elif ext == "conf":
            self.restore_defaults_from_conf()
        else:
            self.log.uplog("Stored default services has an unknown format, interpreting as .conf", "WARN")
            self.restore_defaults_from_conf()

    # Restore default services and their settings from
    # def_serv_file.conf
    def restore_defaults_from_conf(self):
        try:
            with open(self.def_serv_file, "r") as file:
                str_list = [line.rstrip() for line in file]

                # if empty file
                if len(str_list) == 0:
                    self.log.uplog("Stored default services is empty, all traffic will pass", "WARN")
                    return

                i = 0
                self.log.uplog("Attempting to restore previous Services configurations")
                while i < len(str_list):
                    # Service header in def_serv_file:
                    # SERVICE_NAME FIREWALL_DIRECTION_CHR-PORT SERVICETYPE SAVED_REGEX_LEN
                    serv_list = str_list[i].split(" ")
                    try:
                        serv_name = serv_list[0]
                        serv_port = int(serv_list[1])
                        serv_fw_direction = serv_list[2]
                        serv_type = serv_list[3]
                        serv_len_reg = int(serv_list[4])
                        serv_regex = []
                        # Building regex list from extracted data
                        for n in range(serv_len_reg):
                            serv_regex.append(str_list[n+i+1])

                        i += serv_len_reg + 1

                        service = self.add_service(serv_port, serv_regex,
                                                   serv_fw_direction,
                                                   serv_type, serv_name)
                    # int() can raise ValueError; accessing to list KeyError
                    except (ValueError, KeyError) as e:
                        self.log.uplog("Unknown format for stored services settings, initializing empty IPS", "WARN")
                        self.log.uplog(e, "DEBUG")
                        break

        except FileNotFoundError as e:
            self.log.uplog("Default services file not found, initializing empty IPS", "WARN")
            self.log.uplog(e, "DEBUG")

    # Restore default services and their settings from
    # def_serv_file.json
    def restore_defaults_from_json(self):
        try:
            with open("default-services.json", "r") as json_file:
                data = json.load(json_file)

                # if empty list (empty file)
                if not data:
                    self.log.uplog("Stored default services is empty, all traffic will pass", "WARN")
                    return

                self.log.uplog("Attempting to restore previous Services configurations")
                for serv_data in data:
                    try:
                        service = self.add_service(serv_data["port"], serv_data["regex_list"],
                                                   serv_data["firewall_direction"],
                                                   serv_data["service_type"], serv_data["name"])
                    # accessing to list may cause KeyError; bad function arguements ValueError or TypeError
                    except (KeyError, ValueError, TypeError) as e:
                        self.log.uplog("Unknown format for stored services settings, initializing empty IPS", "WARN")
                        self.log.uplog(e, "DEBUG")
                        break

        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.log.uplog("Default services file not found, initializing empty IPS", "WARN")
            self.log.uplog(e, "DEBUG")



    # Looks at the def_serv_file extension and chooses
    # the store method to call
    def set_defaults(self):
        ext = self.def_serv_file.split(".")[-1]
        if ext == "json":
            self.store_defaults_in_json()
        elif ext == "conf":
            self.store_defaults_in_conf()
        else:
            # warn already shown, this will be called as "ALL"
            self.log.uplog("Stored default services has an unknown format, interpreting as .conf", "ALL")
            self.restore_defaults_from_conf()

    # Set default services (mainly used before closing)
    # Overwrites the def_serv_file with the actual services.
    # This will save data in a .conf file
    def store_defaults_in_conf(self):
        # Merging of all services (enabled or disabled)
        merged = {}
        for k in self.disabled_services:
            merged[k] = self.disabled_services[k]
        for k in self.services:
            merged[k] = self.services[k]       

        try:
            file = open(self.def_serv_file, "w")
            for key in merged:
                service = merged[key]
                serv_name = service.name
                serv_port = service.port
                serv_fw_direction = service.firewall_direction
                serv_type = service.service_type
                serv_len_reg = len(service.regex_list)
                serv_regex = service.regex_list
                header = " ".join([serv_name, str(serv_port), serv_fw_direction, serv_type, str(serv_len_reg)])
                # write header and regex in file for a Service
                file.write(header + "\n")
                for r in serv_regex:
                    file.write(r + "\n")
            file.close()
            self.log.uplog("Default Services successfully updated")

        except OSError:
            self.log.uplog("Error in opening default Services file, cannot save data", "ERROR")

    # Set default services (mainly used before closing)
    # Overwrites the def_serv_file with the actual services.
    # This will save data in a .json file
    def store_defaults_in_json(self):
        # Merging of all services (enabled or disabled)
        merged = {}
        for k in self.disabled_services:
            merged[k] = self.disabled_services[k]
        for k in self.services:
            merged[k] = self.services[k] 
        try:
            with open(self.def_serv_file, "w") as json_file:
                # Building Json data struct
                data = []
                for key in merged:
                    service = {}
                    serv_obj = merged[key]
                    service["name"] = serv_obj.name
                    service["port"] = serv_obj.port
                    service["firewall_direction"] = serv_obj.firewall_direction
                    service["service_type"] = serv_obj.service_type
                    service["regex_list"] = serv_obj.regex_list
                    data.append(service)
                json.dump(data, json_file, indent=4)
            self.log.uplog("Default Services successfully updated")

        except OSError:
            self.log.uplog("Error in opening default Services file, cannot save data", "ERROR")



    # Close the shield: deletes all services TODO
    def close_shield(self):
        self.log.uplog("Closing Shield")
        # Updating ipt_list
        self.update_iptables_list(remove_olds=False)
        # save Services configuration
        self.set_defaults()
        # clear objects and iptables rules set by the service
        keys = []
        for key in self.services:
            keys.append(key)
        for i in range(len(keys)):
            self.log.uplog("Deleting Service " + keys[i], "ALL")
            self.erase_service_by_key(keys[i])
        return


    # Metodo che effettua il matching di una delle regex
    # presenti nelle regex di un servizio.
    # Se matcha -> True, altrimenti False.
    # Se il servizio non e' fornito (None) fa un controllo
    # del payload usando tutte le regex di tutti i servizi.
    def regex_trigger(self, payload, service):
        # Search in all services
        if service is None:
            for s in self.services:
                for cr in self.services[s].compiled_regex:
                    # TODO: log that the service s triggerd the payload?
                    if (cr.search(payload)):
                        return True
            return False

        # If service is not None: Search in service regex
        for cr in self.services[service].compiled_regex:
            if (cr.search(payload)):
                return True
        return False


    # Metodo che determina se un pacchetto e' da droppare.
    # Se ignore_TCP_header e' settato a True la ricerca ignora
    # i primi dim_header bytes del pacchetto.
    def is_droppable(self, payload, dim_header=52,
                     service=None, ignore_TCP_header=True):
        if (ignore_TCP_header):
            payload = payload[dim_header:]

        if (self.regex_trigger(payload,service)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False

    # Method that, for each service, prints its name, its port and its type.
    def print_services(self):
        for s in self.services:
            self.log.uplog(f"[{s.name}]: Port " + str(s.port)
                           + " Service " + self.services[s].service_type)
        self.log.nt_uplog("\n")
        return


    # Metodo che sostituisce TUTTO il payload, non solo
    # la parte flaggata, con la stringa di censura.
    # es.: "python e' bello" -> "xxxxxxxxxxxxxxx"
    def cens_subst_all(self, payload, censor_string):
        b_cens = censor_string.encode()
        n = len(b_cens)
        bayload = b''
        for i in range(len(payload)):
            #payload[i]=b_cens[i%n]
            if(payload[i]==13 or payload[i]==10):   # 10 = ord('\n'), 13 = ord('\r')
                bayload = bayload + payload[i].to_bytes(1, "big")
            else:
                k = b_cens[i%n]
                bayload = bayload + k.to_bytes(1, "big")
        return bayload


    # Metodo che sostituisce le stringhe date (flagged_strings)
    # contenute nel payload con la stringa di censura
    # es.: "python e' bello" -> "xxxxxx e' bello"
    def cens_subst(self, payload, censor_string, flagged_strings):
        fl_strings = []
        for s in flagged_strings:  # rimuove i duplicati
            if s not in fl_strings:
                fl_strings.append(s)

        b_cens = censor_string.encode()
        n = len(b_cens)
        bayload = b''
        bayload = payload
        for s in flagged_strings: # per ogni stringa flaggata trovata censura
            print(str(s) + " " + str(len(s)))
            bay = b''
            for i in range(len(s)):
                bay += b_cens[i%n].to_bytes(1, "big")
            print(str(bay) + " " + str(len(bay)))
            bayload = bayload.replace(s, bay)
        return bayload


    # TODO: fare replace direttamente su tutte le regex
    # (senza cercare quali sono attive)
    #      oppure usando re.finditer, esempio:
    #
    #      stringa = 'we sono un lol e odio i lol lers'
    #      matches = re.finditer("lol", stringa)
    #      for match in matches:
    #      print(match)
    #
    #      Risultato:
    #      <re.Match object; span=(11, 14), match='lol'>
    #      <re.Match object; span=(24, 27), match='lol'>


    # Metodo che censura i payload malevoli con
    # censor_string (eg "python" -> "xxxxxx")
    def censor(self, payload, dim_header=52,
               censor_string="x", service=None, ignore_TCP_header=True):
        if (ignore_TCP_header):
            payload_d = payload[dim_header:]
        else:
            payload_d = payload

        # FIXME
        lol = []
        for s in self.services:
            for cr in s.compiled_regex:
                s = cr.findall(payload_d)
                if (len(s)):
                    lol += s

        #payload_d = self.cens_subst_all(payload_d, censor_string)
        payload_d = self.cens_subst(payload_d, censor_string, lol)
        return payload[0:dim_header] + payload_d
