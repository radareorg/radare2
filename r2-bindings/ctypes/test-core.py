from r_core import *

def flush(c):
	c = RCons()
	c.flush()

def flush2(c):
	k = c.cons
	k.flush()

c = RCore ()

h = c.file_open ("/bin/ls", 0, 0);
c.bin_load (None)
print (c.cmd_str ("px"))
c.cmd0 ("pd 10 @ entry0")
c.cmd0 ("px 20 @ 0")

print ("*** "+c.cmd_str('p8 16'))
c.cmd0 ("p8 20")
c.cmd_flush()

print "---"
c.cmd0 ("p8 20 @ $$+1")
#c.cmd_flush()
flush2(c)

c.cmd0 ("pd 3")
flush(c)
