# XXX: r_hash is not bindable atm :(
#from r2.r_hash import rHash, Size_MD4
try:
	from r_core import RHash, Size_MD4
except:
	from r2.r_core import RHash, Size_MD4

hash = RHash(False)
ret = hash.do_md4 ("food", 4)
str = "md4: "
for i in range(0, Size_MD4):
	str += "%02x"%ord(ret[i])
print str
