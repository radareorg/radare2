/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

using Radare;

public class RAsmExample
{
	public static void main(string[] args)
	{
		RAsm st = new RAsm();
		st.use("x86.olly");
		st.set_syntax(RAsm.Syntax.INTEL);
		st.set_bits(32);
		st.set_big_endian(false);
		st.set_pc(0x8048000);
/*
		st.set_parser(RAsm.Parser.PSEUDO,
			(st) => {
				stdout.printf("pseudo: %s --> %s\n", st.buf_asm, (string)st.aux);
				return 0;
			}, pseudo);
*/

		RAsm.Op op;
		uint8 *buf = "\x83\xe4\xf0";
		string buf2 = "jmp _foo;nop;nop;nop;_foo:push eax";
		if (st.disassemble(out op, buf, 3) <1) {
			stderr.printf("internal error\n");
		} else {
			stdout.printf("disasm: %s\n", op.buf_asm);
		}
		RAsm.Code? code = st.massemble(buf2);
		if (code == null) {
			stderr.printf("internal error\n");
		} else {
			stdout.printf("asm: %s\n", code.buf_hex);
		}

		print ("arg0: %s\n", st.fastcall (0, 4));
		print ("arg1: %s\n", st.fastcall (1, 4));
		print ("arg2: %s\n", st.fastcall (2, 4));
/*
		stdout.printf("Enumerate fastcall arguments:\n");
		for(int i=0;i<4;i++) {
			stdout.printf(" - %s\n", st.fastcall(i, 4));
		}
*/
	}
}
