from r_bin import *

b=RBin ()
b.load ("/bin/ls", None)
baddr = b.get_baddr ()
for i in b.get_imports ():
	print "offset=0x%08x va=0x%08x name=%s" % (
		i.offset, baddr+i.rva, i.name)
