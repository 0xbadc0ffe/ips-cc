
import time
from datetime import datetime

class Log:
    

    def __init__(self, time_start):
        if (time_start == None):
            time_start = time.time()
        self.time_start = time_start
        self.logfile = open("logfile.log","a")
        now = datetime.now()
        self.logfile.write("["+now.strftime("%d/%m/%Y %H:%M:%S")+"]: Starting Log session\n")

    
    def uplog(self, s):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")      #time string
        print("["+ts+"]: "+ s +"\n")
        self.logfile.write("["+ts+"]: "+ s +"\n")

    def rt_uplog(self, s):
        rts = "[%.3f]: " + s +"\n"                  #relative time string
        print(rts % (time.time()-self.time_start)) 
        self.logfile.write(rts % (time.time()-self.time_start))

    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")      
        self.logfile.write("["+ts+"]: Log session has been stopped")
        self.logfile.write("\n\n")
        self.logfile.close()


