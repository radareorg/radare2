/* radare - LGPL - Copyright 2009, 2010 nibble<.ds@gmail.com> */

[Compact]
[CCode (cheader_filename="r_asm.h", cname="struct r_asm_t", free_function="r_asm_free", cprefix="r_asm_")]
public class Radare.RAsm {
	[CCode (cprefix="R_ASM_ARCH_", cname="int")]
	public enum Arch {
		NONE,
		X86,
		ARM,
		PPC,
		M68K,
		JAVA,
		MIPS,
		SPARC,
		CSR,
		MSIL,
		OBJD,
		BF
	}

	[CCode (cprefix="R_ASM_SYNTAX_", cname="int")]
	public enum Syntax {
		NONE,
		INTEL,
		ATT
	}

	[Compact]
	[CCode (cname="struct r_asm_aop_t", destroy_function="" )]
	public struct Aop {
		public int inst_len;
		public uint8 *buf;
		public string buf_asm;
		public string buf_hex;
		public string buf_err;
		//pointer 
	}

	[CCode (cname="struct r_asm_code_t", destroy_function="" )]
	public struct Code {
		public int len;
		public uint8* buf;
		public string buf_hex;
		public string buf_asm;
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

	public RAsm();
	public weak RAsm init();
	public int list();
	public bool use(string name);
	public bool set_bits(int bits);
	public bool set_syntax(Syntax syntax);
	public bool set_pc(uint64 addr);
	public bool set_big_endian(bool big);
	//public bool set_parser(RAsm.Parser parser, parse_cb cb, void *aux);
	public int disassemble(out Aop aop, uint8 *buf, uint64 length);
	public int assemble(out Aop aop, string buf);
	public Code? mdisassemble(uint8 *buf, uint64 length);
	public Code? massemble(string buf);
//	public weak string fastcall(int idx, int num);
	//public int parse();
	// This is the destructor
	public void free();

	public delegate int parse_cb();
}
