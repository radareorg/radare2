from r2 import r_core

rc = r_core.RCore()
rc.file_open("/bin/ls", 0, 0)
rc.bin_load("", 0)

rc.anal_all()
funcs = rc.anal.get_fcns()

for f in funcs:
	blocks = f.get_bbs()
	print("+" + (72 * "-"))
	print("| FUNCTION: %s @ 0x%x" % (f.name, f.addr))
	print("| (%d blocks)" % (len (blocks)))
	print("+" + (72 * "-"))

	for b in blocks:
		print("---[ Block @ 0x%x ]---" % (b.addr))
		print("   | size:        %d" % (b.size))
		print("   | jump:        0x%x" % (b.jump))
		print("   | conditional: %d" % (b.conditional))
		print("   | return:      %d" % (b.returnbb))

		end_byte = b.addr + b.size
		cur_byte = b.addr

		while (cur_byte < end_byte):
			#anal_op = rc.op_anal(cur_byte)
			asm_op = rc.disassemble(cur_byte)

			if asm_op.inst_len == 0:
				print("Bogus op")
				break

			#print("0x%x %s" % (anal_op.addr, anal_op.mnemonic))
			print("0x%x %s %s" % (cur_byte, asm_op.buf_hex, asm_op.buf_asm))
			cur_byte += asm_op.inst_len
