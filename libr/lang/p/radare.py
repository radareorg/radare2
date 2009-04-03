"""python api for it

This is the API provided with radare to use python inside radare as
scripting language for extending its features or automatize some
tasks analyzing code, patching binaries or debugging programs.

Here's a small example of use:

from radare import *

seek(0x1024)
print hex(3)
write("90 90 90")
print hex(3)

quit()

"""
# Already imported from radare's core
import r
import string
import binascii
import array

def hex2bin(str):
	"""
	Converts an ascii-hexpair based string into a binary array of bytes
	"""
	return binascii.a2b_hex(str.replace(' ',''))

def bin2hex(binstr):
	"""
	Converts a binary array of bytes into an ascii-hexpair based string
	"""
	str = string.lower(binascii.b2a_hex(binstr))
	return str

# TODO: skip commented lines
def slurp_hexpair(file):
	"""
	Returns the hexpair string contained in a hexpair-based file
	in a single line
	"""
	fd = open(file, 'r')
	str = join(fd.readlines(),'\n')
	fd.close()
	return str

# slurp a raw file or a symbol, returning the hexpair string
def slurp(file):
	"""
	Returns the hexpair-based representation of a binary file
	"""
	fd = open(file, 'r')
	str = bin2hex(fd.read())
	fd.close()
	return str

#def slurp_symbol(file,symbol):

def __str_to_hash(str):
	list = str.split("\n")
	w = []
	t = {}
	for i in range(1, len(list)):
		w = list[i].split("=")
		if (len(w)>1):
			a = w[0].strip()
			b = w[1].strip()
			if (b[0:2] == '0x'):
				t[a] = long(b,16)
			elif (b.find(' ') == -1) and (b[0]>='0' and b[0]<='9'):
				t[a] = long(b,10)
			else:
				t[a] = b
	return t

def analyze_opcode(addr=None):
	"""
	Returns a hashtable containing the information of the analysis of the opcode in the current seek.
	This is: 'opcode', 'size', 'type', 'bytes', 'offset', 'ref', 'jump' and 'fail'
	"""
	if addr == None:
		return __str_to_hash(r.cmd("ao"))
	return __str_to_hash(r.cmd("ao @ 0x%x"%addr))

def analyze_block(addr=None):
	"""
	Returns a hashtable containing the information of the analysis of the basic block found in the current seek.
	This is: 'offset', 'type', 'size', 'call#', 'n_calls', 'true', 'false' and 'bytes'
	"""
	if addr == None:
		return __str_to_hash(r.cmd("ab"))
	return __str_to_hash(r.cmd("ab @ 0x%x"%addr))

def endian_set(big):
	r.cmd("eval cfg.bigendian=%d"%big)

def write(hexpair):
	r.cmd("wx %s"%hexpair)

def write_asm(opcode):
	r.cmd("wa %s"%opcode)

def write_string(str):
	r.cmd("w %s"%str)

def write_wide_string(str):
	r.cmd("ww %s"%str)

def write_from_file(file):
	r.cmd("wf %s"%file)

def write_from_hexpair_file(file):
	r.cmd("wF %s"%file)

def seek_undo():
	r.cmd("undo")

def seek_redo():
	r.cmd("uu")

def seek_history():
	ret = []
	list = r.cmd("u*").split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["addr"] = w[0].strip()
			ret.append(t)
	return ret

def seek_history_reset():
	r.cmd("u!")

def write_undo(num):
	return r.cmd("uw %d"%num)

def write_redo(num):
	return r.cmd("uw -%d"%num)

def write_history():
	ret = []
	list = r.cmd("wu").split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["size"] = long(w[2].strip(),10)
			t["addr"] = long(w[3].strip(),16)
			# TODO moar nfo here
			ret.append(t)
	return ret

def flag_space_set(name):
	r.cmd("fs %s"%name)

def flag_list(mask):
	ret = []
	list = r.cmd("f~%s"%mask).split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["addr"] = long(w[1].strip(),16)
			t["size"] = long(w[3].strip(),10)
			t["name"] = w[4].strip()
			ret.append(t)
	return ret

def flag_set(name, addr=None):
	if addr == None:
		r.cmd("f %s"%name)
	else:
		r.cmd("f %s @ 0xx"%name, addr)

def flag_rename(old_name, new_name):
	r.cmd("fr %s %s"%(old_name,new_name))

def flag_unset(name):
	r.cmd("f -%s"%name)

def flag_get(name):
	return r.cmd("? %s"%name).split(" ")[0].strip()

def meta_comment_add(msg):
	r.cmd("CC %s"%msg)

def type_code(len):
	r.cmd("Cc %d"%len)

def type_data(len):
	r.cmd("Cd %d"%len)

def type_string(len):
	r.cmd("Cs %d"%len)

def copy(num, addr=None):
	if addr == None:
		r.cmd("y %d"%num)
	else:
		r.cmd("y %d @ 0x%x"%(num,addr))

def paste(addr=None):
	if addr == None:
		r.cmd("yy"%num)
	else:
		r.cmd("yy @ 0x%x"%(num,addr))

def asm(opcode):
	"""
	Returns the hexpair strin representation of the assembled opcode
	"""
	return r.cmd("!rasm '%s'"%opcode)

def dis(num, addr=None):
	"""
	Disassemble 'num' opcodes from the current seek and returns the output
	"""
	if addr == None:
		return r.cmd("pd %d"%num)
	return r.cmd("pd %d @ 0x%x"%(num,addr))

def str(addr=None):
	"""
	Returns a zero-terminated string found in current seek
	"""
	if addr == None:
		return r.cmd("pz").strip()
	return r.cmd("pz @ 0x%x"%addr).strip()

def dword(num, addr=None):
	if addr == None:
		return r.cmd("p64 %d"%num).strip()
	return r.cmd("p64 %d @ 0x%x"%(num,addr)).strip()

def word(num, addr=None):
	if addr == None:
		return r.cmd("p32 %d"%num).strip()
	return r.cmd("p32 %d @ 0x%x"%(num,addr)).strip()

def half(num, addr=None):
	if addr == None:
		return r.cmd("p16 %d"%num).strip()
	return r.cmd("p16 %d @ 0x%x"%(num,addr)).strip()

def hex(num, addr=None):
	if addr == None:
		return r.cmd("p8 %d"%num).strip()
	return r.cmd("p8 %d @ 0x%x"%(num,addr)).strip()

def eval_get(key):
	return r.cmd("eval %s"%key).strip()

def eval_set(key,value):
	r.cmd("eval %s = %s"%(key,value))

def eval_hash_get():
	return __str_to_hash("e")

def eval_hash_set(hash):
	list = hash.keys()
	for i in range (0, len(list)):
		key = list[i]
		value = hash[key]
		r.cmd("e %s=%s"%(key,value))

def get_byte(addr):
	return r.cmd("? [1:%s]~[0]"%addr)

def write_to_files(file, size):
	r.cmd("wT %s %s", file, size)

def seek(addr):
	r.cmd("s %s"%addr)

def cmp(hexpairs, addr):
	r.cmd("c %s @ 0x%x"%(hexpairs,addr))

def cmp_file(file, addr):
	r.cmd("cf %s @ 0x%x"%(file,addr))

def dbg_attach(pid):
	print r.cmd("!attach %d"%pid)

def dbg_detach(pid):
	print r.cmd("!detach %d"%pid)

def dbg_continue():
	print r.cmd("!cont")

def dbg_step(num):
	if num < 1:
		num = 1
	r.cmd("!step %d"%num)

def dbg_step_over(num):
	if num < 1:
		num = 1
	r.cmd("!stepo %d",num)

def dbg_jmp(addr):
	r.cmd("!jmp "+addr)

def dbg_call(addr):
	r.cmd("!call "+addr)

def dbg_bp_set(addr, type):
	r.cmd("!bp "+addr)

def dbg_bp_unset(addr, type):
	r.cmd("!bp -"+addr)

def dbg_alloc(size):
	return r.cmd("!alloc %s"%size)

def dbg_free(addr):
	r.cmd("!free %s"%addr)

def dbg_backtrace():
	ret = []
	list = r.cmd("!bt").split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["addr"]    = long(w[1].strip(),16)
			t["framesz"] = long(w[2].strip(),10)
			t["varsz"]   = long(w[3].strip(),10)
			ret.append(t)
	return ret

def dbg_dump(name):
	r.cmd("!dump %s"%name)

def dbg_restore(name):
	r.cmd("!restore %s"%name)

def dbg_register_get(name):
	r.cmd("!reg %s"%(name))

def dbg_register_set(name, value):
	r.cmd("!reg %s=%s"%(name,value))

def trace_at(addr):
	return __str_to_hash(r.cmd("at %s"%addr))

def trace_list():
	return r.cmd("at*").split("\n")

def trace_reset():
	r.cmd("at-")

def trace_ranges():
	return r.cmd("at").split("\n")

def hash(algo,size):
	return r.cmd("#%s %d"%(algo,size))

def graph(addr=None):
	if addr == None:
		r.cmd("ag")
	else:
		r.cmd("ag @ %s"%addr)

def cmd(str):
	return r.cmd(str)

def quit():
	r.cmd("q!")
