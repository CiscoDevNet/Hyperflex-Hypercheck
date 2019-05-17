# -*- coding: utf-8 -*-
"""
ProgressBar Module 
Created on 17-Dec-18
@author: Kiranraj(kjogleka)
"""
import sys
import threading
import time

class ProgressBarThread(threading.Thread):
    def __init__(self, delay=0.2):
        super(ProgressBarThread, self).__init__()
        self.delay = delay  # interval between updates
        self.toolbar_width = 24
        self.running = False

    def start(self, prefix):
        self.prefix = prefix + " "
        sys.stdout.write(self.prefix)
        self.running = True
        super(ProgressBarThread, self).start()

    def run(self):
        while self.running:
            sys.stdout.write("[%s]" % (" " * self.toolbar_width))
            sys.stdout.flush()
            sys.stdout.write("\b" * (self.toolbar_width+1))
            for i in range(self.toolbar_width):
                time.sleep(self.delay) # do real work here
                # Update the bar
                sys.stdout.write("#")
                sys.stdout.flush()
            sys.stdout.write("\b" * (self.toolbar_width+1))

    def stop(self, suffix):
        self.running = False
        self.suffix = suffix
        self.join()  # wait for run() method to terminate
        sys.stdout.write("[%s] %s" % ("#" * self.toolbar_width, self.suffix))
        sys.stdout.flush()
        sys.stdout.write("\n")

