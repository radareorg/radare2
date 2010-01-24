#from r2.r_hash import rHash, Size_MD4
from libr import rHash, Size_MD4

hash = rHash(False)
ret = hash.do_md4 ("food", 4)
str = "md4: "
for i in range(0, Size_MD4):
	str += "%02x"%ord(ret[i])
print str
