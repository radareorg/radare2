#!/usr/bin/python
from r_asm import *

a=RAsm()
a.use("arm")
a.set_bits(32)  # use .set_bits(16) for thumb/thumb2
a.set_pc (0x40010)

print ("=> Assemble arm opcode")
ret = a.massemble("mov r0, r3\nmov r1, r4\nnop")
if ret:
	print ("Len = %d"%(ret.len))
	print ("Hex = %s"%(ret.buf_hex))

print ('')
print ("=> Disassemble hexpairs")
ret = a.mdisassemble_hexstr ("0300a0e1 10203040 50607080");
if ret:
	print (ret.buf_asm)
