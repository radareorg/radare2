#!/usr/bin/env python
# -*- coding: utf-8 -*
from r2.r_core import *

class PyApp():
   def __init__(self):
       self.previous_rss = 0
       self.a = 0
       pass

   def print_rss_mem(self):
       import resource
       current_rss = resource.getrusage(resource.RUSAGE_SELF)[2]
       print current_rss, "bytes on RSS memory,", current_rss - self.previous_rss, "bytes leaked!"
       self.previous_rss = current_rss

   def io_va(self):
       if self.a==0:
            self.core.cmd0("e io.va=0")
	    self.a=1
       else:
            self.core.cmd0("e io.va=1")
	    self.a=0

   def load_radare(self, widget=False):
       self.core = RCore()
       # Preparamos el archivo
       file = "/tmp/elf-linux-x86-64" #usr/bin/tar"
       self.core.file_open(file, 0, 0)
       self.core.bin_load(None)

app = PyApp()
import time
#time.sleep(10)

app.print_rss_mem()
app.load_radare()
app.print_rss_mem()
for i in range(0, 30):
   app.io_va()
   f = app.core.anal.get_fcns()
   print len(f)
   app.print_rss_mem()
