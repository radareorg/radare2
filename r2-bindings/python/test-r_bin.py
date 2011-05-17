from r2.r_bin import *
b = RBin ()
b.load("/bin/ls", None)
baddr= b.get_baddr()
print '-> Sections'
for i in b.get_sections ():
	print 'offset=0x%08x va=0x%08x size=%05i %s' % (
			i.offset, baddr+i.rva, i.size, i.name)

