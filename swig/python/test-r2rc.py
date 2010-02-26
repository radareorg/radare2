#!/usr/bin/python
# -- pancake

import sys
from r_asm import *
from r_util import *
from r_bin import *

try:
	program = sys.argv[1]
except:
	print "Usage: test-r2rc [path-to-program]"
	sys.exit (1)

a = RAsm ()
a.use ("x86.nasm")

b = RBin ()
off_printf = 0
b.load (program, None)
baddr = b.get_baddr ()
for i in b.get_imports ():
	if i.name == "printf":
		off_printf = baddr+i.rva
		break

if off_printf == 0:
	print "Program %s does not imports 'printf'"%program
	sys.exit(1)

r2rc_code="""
printf@alias(0x%08lx);

main@global(32,32) {
	printf ("Hello World\n");
}
"""%(off_printf)

r2rc_asm = RSystem.cmd_str ("r2rc", r2rc_code)[0]
code = a.massemble (r2rc_asm)
if code is None:
	print "Cannot assemble"
else:
	print code.buf_hex
