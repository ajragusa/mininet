from gevent import Greenlet
from scapy.all import *

import sys
import threading
import time

class PacketCounter(threading.Thread):
    count = 0
    capture = True

    def __init__(self, iface=None, tfilter="", timeout=3):
        """
        iface   Interface to capture traffic. By default capture on all.
        tfilter A Berkeley Packet Filter. http://biot.com/capstats/bpf.html
        """
        threading.Thread.__init__(self)
        self.iface   = iface
        self.tfilter = tfilter
        self.timeout = timeout
    
    def run(self):
        sniff(iface=self.iface, prn=self._pkt_handler, filter=self.tfilter, store=0, timeout=self.timeout)
        time.sleep(1) # Hack to ensure sniff can be used in a multi-thread context

    def _pkt_handler(self, pkt):
        self.count += 1

