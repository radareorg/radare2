from r_asm import *

def ass(a, arch, op):
	print "---------------------------->8- - - - - -"
	print "OPCODE: %s"%op
	a.use (arch)
	print "ARCH: %s"%arch
	code = a.massemble (op)
	if code is None:
		print "HEX: Cannot assemble opcode"
	else:
		print "HEX: %s"%code.buf_hex
	
a = RAsm()
ass (a, 'x86.olly', 'mov eax, 33')
ass (a, 'java', 'bipush 33')
