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

o = a.get_object ()
print ("object: "+str(o))

baddr= a.get_baddr ()
print ("base address: "+str(baddr))

sect = a.get_sections ()
#sect._o = addressof (sect)
print(dir(sect))

it = sect.iterator ()
print(dir(it))
while True:
	data = it.get_data ()
	print ("+++++",sect._o)
	ds = cast (data, POINTER(RBinSection)).contents
	print ("Section: ", ds.name)
	if it.n == None:
		print ("GO BREAK")
		break
	it = it.get_next ()

exit(0)
sect._o = addressof (sect)
print ("_________________O ",a._o)

print ("sections: "+str(sect))
print dir(sect)
#sectlist = cast(a, ctypes.c_void_p)
#print ("iter "+str(iter))
