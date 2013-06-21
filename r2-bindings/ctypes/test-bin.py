#!/usr/bin/python
from r_bin import *
import ctypes

a=RBin()
if not a.load("/bin/ls", False):
	print "Fuck. cannot load /bin/ls"
	exit(1)

print ("------")
info = a.get_info ()
print ("type: "+info.type)
print ("arch: "+info.arch)
print ("mach: "+info.machine)
print ("os: "+info.os)
print ("subsys: "+info.subsystem)

print ("------")

#o = a.get_object ()
#print ("object: "+str(o))

baddr = a.get_baddr ()
print ("base address: "+str(baddr))
print ("------")

# TODO: make to_list() unnecessary!
for s in a.get_sections(): #.to_list(RBinSection):
	print (s.name,s.rva)

exit(0)
