from gevent import Greenlet
from scapy.all import *

import sys
import threading
import time

class PacketCounter(threading.Thread):
    count = 0
    capture = True

    def __init__(self, iface=None, tfilter=""):
        """
        iface   Interface to capture traffic. By default capture on all.
        tfilter A Berkeley Packet Filter. http://biot.com/capstats/bpf.html
        """
        threading.Thread.__init__(self)
        self.iface   = iface
        self.tfilter = tfilter
    
    def run(self):
        try:
            sniff(iface=self.iface, prn=self._pkt_handler, filter=self.tfilter, store=0)
        except Exception:
            print sys.exc_info()[0]

    def stop(self):
        self.capture = False

    def _pkt_handler(self, pkt):
        if not self.capture:
            raise Exception("EXIT: PacketCounter")
        else:
            self.count += 1

