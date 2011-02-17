/* radare - LGPL - Copyright 2009, 2010 nibble<.ds@gmail.com> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_asm.h", cname="struct r_asm_t", free_function="r_asm_free", cprefix="r_asm_")]
public class RAsm {
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

	[CCode (cprefix="R_ASM_MOD_", cname="int")]
	public enum Mod {
		RAWVALUE,
		VALUE,
		DSTREG,
		SRCREG0,
		SRCREG1,
		SRCREG2
	}

	[Compact]
	[CCode (cname="RAsmPlugin", destroy_function="", free_function="")]
	public class Plugin {
		public string name;
		public string arch;
		public string desc;
		[CCode (array_length = false)]
		public int[] bits;
	}

	[Compact]
	[CCode (cname="RAsmAop", destroy_function="")]
	public class Aop {
		public int inst_len;
		public uint8 *buf;
		public string buf_asm;
		public string buf_hex;
		public string buf_err;
		// accessors for bindings
		public string get_hex();
		public string get_asm();
	}

	[Compact]
	[CCode (cname="RAsmCode", cprefix="r_asm_code_", free_function="r_asm_code_free")]
	public class Code {
		public int len;
		public uint8* buf;
		public string buf_hex;
		public string buf_asm;
		public int set_equ (string key, string val);
		//public int equ_replace (string key);
		//public void* free();
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

	public RList<RAsm.Plugin> plugins;
	public RAsm();
	public bool use(string name);
	public bool set_bits(int bits);
	public bool set_syntax(Syntax syntax);
	public bool set_pc(uint64 addr);
	public bool set_big_endian(bool big);
	// TODO: Use Code? instead of aop??
	public int disassemble(out Aop aop, uint8 *buf, uint64 length);
	public int assemble(out Aop aop, string buf);
	public Code? mdisassemble(uint8 *buf, uint64 length);
	public Code? mdisassemble_hexstr(string hexstr);
	public Code? massemble(string buf);

	/* TODO: not directy defined here */
	public void free();
}
}
