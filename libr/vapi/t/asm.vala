/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

using Radare;

public class AsmExample
{
	public static void main(string[] args)
	{
		string pseudo = "";
		Asm st = new Asm();
		st.set_arch(Asm.Arch.X86);
		st.set_syntax(Asm.Syntax.INTEL);
		st.set_bits(32);
		st.set_big_endian( false);
		st.set_pc(0x8048000);
		st.set_parser(Asm.Parser.PSEUDO,
			(st) => {
				stdout.printf("pseudo: %s --> %s\n", st.buf_asm, (string)st.aux);
				return 0;
			},pseudo);

		uint8 *buf = "\x83\xe4\xf0";
		st.disasm(buf, 3);
		st.parse();
		stdout.printf("asm: %s\n", st.buf_asm);
	}
}
