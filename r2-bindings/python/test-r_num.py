try:
	from r_util import *
except:
	from r2.r_asm import RNum

a = RNum (None, None);

print "The value is: %d"%(a.get("33"))
print "The math is: %d"%(a.math("33+(4*2)"))
