uses
	Radare

init
	var st = new RAsm()
	st.use("x86")
	st.set_syntax(RAsm.Syntax.INTEL)
	st.set_bits(32)
	st.set_big_endian(false)
	st.set_pc(0x8048000)

	/* Disassembler test */
	op : RAsm.Aop
	var buf = "\x83\xe4\xf0"
	st.disassemble(out op, buf, 3)
	print "opcode: %s", op.buf_asm
	print "bytes: %s", op.buf_hex
	print "length: %d", op.inst_len
