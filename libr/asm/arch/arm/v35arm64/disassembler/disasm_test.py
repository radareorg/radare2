#!/usr/bin/env python

# run disassembly tests in test_cases.txt
# ensure you built gofer.so (see Makefile-local)

import os, sys, struct, ctypes, re

#------------------------------------------------------------------------------
# disassemble
#------------------------------------------------------------------------------

cbuf = None
gofer = None

def normalize(instxt):
	#print('normalizing: %s' % instxt)
	instxt = instxt.strip()

	# collapse runs of whitespace to one space character
	instxt = re.sub('\s+', ' ', instxt)

	# remove comments
	if ' //' in instxt:
		instxt = instxt[0:instxt.find(' //')]

	# change that range notation
	# st4w {z14.s-z17.s}, p2, [x11, x19, lsl #2]
	# ->
	# st4w {z14.s, z15.s, z16.s, z17.s}, p2, [x11, x19, lsl #2]
	m = re.search(r'{z(\d+)\.(.)-z(\d+)\.(.)}', instxt)
	if m:
		(lhs, suffix_a, rhs, suffix_b) = m.group(1,2,3,4)
		assert suffix_a == suffix_b
		(lhs, rhs) = (int(lhs), int(rhs))
		if rhs-lhs+1 == 4:
			replacement = '{z%d.%s, z%d.%s, z%d.%s, z%d.%s}' % \
				(lhs, suffix_a, (lhs+1)%32, suffix_a, (lhs+2)%32, suffix_a, (lhs+3)%32, suffix_a)
		elif rhs-lhs+1 == 3:
			replacement = '{z%d.%s, z%d.%s, z%d.%s}' % \
				(lhs, suffix_a, (lhs+1)%32, suffix_a, (lhs+2)%32, suffix_a)
		instxt = instxt.replace(m.group(0), replacement)

	# remove spaces from { list }
	# eg: { v5.b, v6.b, v7.b, v8.b } -> {v5.b, v6.b, v7.b, v8.b}
	instxt = re.sub(r'{ (.*?) }', r'{\1}', instxt)

	# remove leading hex zeros
	# 0x00000000071eb000 -> 0x71eb000
	instxt = re.sub(r'0x00+', r'0x', instxt)

	# decimal immediates to hex
	# add x29, x15, x25, lsl #6 -> add x29, x15, x25, lsl #0x6
	for dec_imm in re.findall(r'#\d+[,\]]', instxt):
		hex_imm = '#0x%x' % int(dec_imm[1:-1]) + dec_imm[-1]
		instxt = instxt.replace(dec_imm, hex_imm, 1)
	for dec_imm in re.findall(r'#\d+$', instxt):
		if not instxt.endswith(dec_imm): continue
		hex_imm = '#0x%x' % int(dec_imm[1:])
		instxt = instxt[0:-len(dec_imm)] + hex_imm

	# #-3.375000000000000000e+00 -> #-3.375
	for x in re.findall(r'#[-\+\.\de]{8,}', instxt):
		instxt = instxt.replace(x, '#'+str(float(x[1:])))

	# 0x0.000000 -> 0x0.0
	instxt = instxt.replace('0.000000', '0.0')
	instxt = instxt.replace('0.000', '0.0')

	# lowercase everything
	instxt = instxt.lower()

	# done
	return instxt

def disassemble(insnum):
	global cbuf, gofer
	insword = struct.pack('<I', insnum)
	cbuf.value = b'(uninitialized)'
	gofer.disassemble(0, insword, 4, ctypes.byref(cbuf), False)
	return normalize(cbuf.value.decode('utf-8').strip())

#------------------------------------------------------------------------------
# slightly smarter than strcmp() disassembly comparison
#------------------------------------------------------------------------------

def compare_disassembly_token(a, b):
	if a==b: return 0

	trash = '#{}[]!,'
	while a[0] in trash:
		if a[0]!=b[0]: return -1
		(a,b) = (a[1:], b[1:])
	while a[-1] in trash:
		if a[-1]!=b[-1]: return -1;
		(a,b) = (a[:-1], b[:-1])

	# x4.d is equivalent to x4
	if a.startswith('x') and a.startswith(b) and a[len(b):] == '.d': return 0
	if b.startswith('x') and b.startswith(a) and b[len(a):] == '.d': return 0
	if a=='sp' and b=='sp.d': return 0
	if a=='sp.d' and b=='sp': return 0

	# cs is equivalent to hs (carry set vs. higher or same)
	if (a,b)==('cs','hs') or (a,b)==('hs','cs'): return 0
	# cc is equivalent to lo (carry clear vs. lower)
	if (a,b)==('cc','lo') or (a,b)==('lo','cc'): return 0

	#print('after trash removal:')
	#print('a: ', a)
	#print('b: ', b)
	if a[0] in trash or b[0] in trash: return -1;
	if a[-1] in trash or b[-1] in trash: return -1;
	try:
		# 0xff == 255
		if '0x' in a: a_val = int(a,16)
		elif '.' in a: a_val = float(a)
		else: a_val = int(a)
		if '0x' in b: b_val = int(b,16)
		elif '.' in b: b_val = float(b)
		else: b_val = int(b)

		#print('a=%s, a_val=%d' % (a, a_val))
		#print('b=%s, b_val=%d' % (b, b_val))
		if a_val == b_val: return 0
		# 0xbc == -68
		if a.startswith('0x') and len(a)==4 and b.startswith('-'):
			if struct.unpack('<b', struct.pack('<B', a_val))[0] == b_val: return 0
		if b.startswith('0x') and len(b)==4 and a.startswith('-'):
			if struct.unpack('<b', struct.pack('<B', b_val))[0] == a_val: return 0
		# 0xfffffffe == -2
		if a.startswith('0x') and len(a)==10 and b.startswith('-'):
			if struct.unpack('<i', struct.pack('<I', a_val))[0] == b_val: return 0
		if b.startswith('0x') and len(b)==10 and a.startswith('-'):
			if struct.unpack('<i', struct.pack('<I', b_val))[0] == a_val: return 0
		# 0xffffffffffffffff == -2
		if a.startswith('0x') and len(a)==18 and b.startswith('-'):
			if struct.unpack('<q', struct.pack('<Q', a_val))[0] == b_val: return 0
		if b.startswith('0x') and len(b)==18 and a.startswith('-'):
			if struct.unpack('<q', struct.pack('<Q', b_val))[0] == a_val: return 0

		return -1

	except ValueError:
		return -1

	return 0

def compare_disassembly(a, b):
	if (a and not b) or (b and not a): return -1
	a = a.split()
	b = b.split()
	if len(a) != len(b): return -1
	if a[0] != b[0]: return -1
	for (ta,tb) in zip(a,b):
		if compare_disassembly_token(ta,tb):
			return -1
	return 0

def excusable_difference(actual, expected):
	if actual=='dgh' and expected.startswith('hint'): return True
	if actual=='cfinv' and expected.startswith('msr'): return True
	if actual.startswith('mov') and expected.startswith('dupm'): return True # spec is screwed up here
	if actual == 'sb' and expected.startswith('msr'): return True
	if actual == 'xaflag' and expected.startswith('msr'): return True
	if actual.startswith('at ') and expected.startswith('sys'): return True
	if actual.startswith('dc ') and expected.startswith('sys'): return True
	if actual.startswith('cfp ') and expected.startswith('sys'): return True
	if actual.startswith('cmpp ') and expected.startswith('subps '): return True
	if actual.startswith('tlbi') and expected.startswith('sys '): return True
	if actual.startswith('msr ssbs') and expected.startswith('msr s0_'): return True
	if actual.startswith('msr pan') and expected.startswith('msr s0_'): return True
	if actual.startswith('axflag'): return True
	return False

#------------------------------------------------------------------------------
# main
#------------------------------------------------------------------------------

def main():
	global cbuf, gofer
	cbuf = ctypes.create_string_buffer(1024)
	gofer = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'gofer.so'))
	assert gofer

	if sys.argv[1:]:
		insnum = int(sys.argv[1], 16)
		print(disassemble(insnum))

	else:
		with open('test_cases.txt') as fp:
			lines = fp.readlines()

		for (i,line) in enumerate(lines):
			if line.startswith('// '): continue
			assert line[8] == ' '
			insnum = int(line[0:8], 16)
			actual = disassemble(insnum)
			expected = line[9:].rstrip()
			print('%08X: -%s- vs -%s-' % (insnum, actual, expected))
			if compare_disassembly(actual, expected):
				if excusable_difference(actual, expected):
					continue
				print('0x%08X' % insnum)
				print('actual:', actual)
				print('expected:', expected)
				print('line %d/%d (%.2f%%)' % (i, len(lines), i/len(lines)*100))
				sys.exit(-1)

		print('PASS')

if __name__ == '__main__':
	main()
