from r_asm import *

def disasm(a, arch, op):
	print "---------------------------->8- - - - - -"
	print "OPCODE: %s"%op
	a.use (arch)
	print "ARCH: %s"%arch
	code = a.massemble (op)
	if code is None:
		print "HEX: Cannot assemble opcode"
	else:
		print "HEX: %s"%code.buf_hex
	
a = rAsm()
print "---[ name ]-----[ description ]----------"
a.list()

disasm (a, 'x86.olly', 'mov eax, 33')
disasm (a, 'java', 'bipush 33')
disasm (a, 'java', 'invalid opcode')
