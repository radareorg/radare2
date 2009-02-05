/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_asm.h", cprefix="r_asm_", lower_case_cprefix="r_asm_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_asm_t", free_function="r_asm_free", cprefix="r_asm_")]
	public class Asm {
		public enum Arch {
			NULL  = 0,
		  	X86   = 1,
		  	ARM   = 2,
		  	PPC   = 3,
		  	M68K  = 4,
		  	JAVA  = 5,
		  	MIPS  = 6,
		  	SPARC = 7,
		  	CSR   = 8,
		  	MSIL  = 9,
		  	OBJD  = 10,
		  	BF    = 11
		}

		[CCode (cprefix="R_ASM_SYN_")]
		public enum Syntax {
			NULL  = 0,
			INTEL = 1,
			ATT   = 2,
			OLLY  = 3
		}
		
		[CCode (cprefix="R_ASM_PAR_")]
		public enum Parser {
			NULL    = 0,
			PSEUDO  = 1,
			REALLOC = 2
		}

		public int arch;
		public int bits;
		public bool big_endian;
		public int syntax;
		public int parser;
		public uint64 pc;
		public string buf_asm;
		public string buf_hex;
		public string buf_err;
		public void *aux;

		public Asm();

		public int init();
		public bool set_arch(Arch arch);
		public bool set_bits(int bits);
		public bool set_syntax(Syntax syntax);
		public bool set_pc(uint64 addr);
		public bool set_big_endian(bool big);
		public bool set_parser(Parser parser, parse_cb cb, void *aux);
		public int disasm(uint8 *buf, uint64 length);
		public int asm(string buf);
		public int parse();
	}

	public static delegate int parse_cb(Asm a);
}
