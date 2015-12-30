from gevent import Greenlet
from scapy.all import *

import sys
import threading
import time

#class PacketCounter(threading.Thread):
class PacketCounter(object):
    count = 0
    capture = True

    #
    on_data_handler = None
    on_finish_handler = None
    #

    # def __init__(self, iface=None, tfilter=""):
    def __init__(self, iface=None, tfilter="", timeout=3):
        """
        iface   Interface to capture traffic. By default capture on all.
        tfilter A Berkeley Packet Filter. http://biot.com/capstats/bpf.html
        """
        #threading.Thread.__init__(self)
        self.iface   = iface
        self.tfilter = tfilter
        self.timeout = timeout

    def on_data(self, f):
        self.on_data_handler = f

    def on_finish(self, f):
        self.on_finish_handler = f

    #def run(self):
    def start(self):
        try:
            # sniff(iface=self.iface, prn=self._pkt_handler, filter=self.tfilter, store=0)
            def f():
                sniff(iface=self.iface, prn=self._pkt_handler, filter=self.tfilter, store=0, timeout=self.timeout)
                self.on_data_handler( str({"count": self.count}) )    
                self.on_finish_handler()

            Greenlet.spawn(f)
        except Exception:
            print sys.exc_info()[0]

    def stop(self):
        self.capture = False

    def _pkt_handler(self, pkt):
        # if not self.capture:
        #     #
        #     self.on_data_handler( str({'count': self.count}) )
        #     #
        #     raise Exception("EXIT: PacketCounter")
        # else:
        #     self.count += 1
        self.count += 1
