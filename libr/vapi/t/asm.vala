/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

using Radare;

public class rAsmExample
{
	public static void main(string[] args)
	{
		rAsm st = new rAsm();
		st.use("x86.olly");
		st.set_syntax(rAsm.Syntax.INTEL);
		st.set_bits(32);
		st.set_big_endian(false);
		st.set_pc(0x8048000);
/*
		st.set_parser(rAsm.Parser.PSEUDO,
			(st) => {
				stdout.printf("pseudo: %s --> %s\n", st.buf_asm, (string)st.aux);
				return 0;
			}, pseudo);
*/

		rAsm.Aop op;
		uint8 *buf = "\x83\xe4\xf0";
		string buf2 = "jmp _foo;nop;nop;nop;_foo:push eax";
		if (st.disassemble(out op, buf, 3) <1) {
			stderr.printf("internal error\n");
		} else {
			stdout.printf("disasm: %s\n", op.buf_asm);
		}
		rAsm.Code? code = st.massemble(buf2);
		if (code == null) {
			stderr.printf("internal error\n");
		} else {
			stdout.printf("asm: %s\n", code.buf_hex);
		}

		stdout.printf("Enumerate fastcall arguments:\n");
		for(int i=0;i<4;i++) {
			stdout.printf(" - %s\n", st.fastcall(i, 4));
		}
	}
}
