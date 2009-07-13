uses
	Radare

init
	var st = new Asm()
	st.set("asm_x86_olly")
	st.set_syntax(Asm.Syntax.INTEL)
	st.set_bits(32)
	st.set_big_endian(false)
	st.set_pc(0x8048000)

	/* Disassembler test */
	op : Radare.Asm.Aop
	var buf = "\x83\xe4\xf0"
	st.disassemble(out op, buf, 3)
	print "opcode: %s", op.buf_asm
	print "bytes: %s", op.buf_hex
	print "length: %d", op.inst_len
