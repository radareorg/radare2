#!/usr/bin/python
from r_asm import *

a=RAsm()
a.use("x86")
ret = a.massemble("mov eax, 33")
print ("RET = %d"%(ret.len))
print ("RET = %s"%(ret.buf_hex))
