
namespace Radare {
/**
 * Radare2 Assembler module
 */
[CCode (cheader_filename="r_asm.h", cname="RAsm", free_function="r_asm_free", cprefix="r_asm_")]
public class RAsm {
	/**
	 * Architectures supported.
	 */
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
		BF,
		SH,
		Z80,
		I8080,
		ARC
	}

	/**
	 * The supported assembler syntax variations.
	 */
	[CCode (cprefix="R_ASM_SYNTAX_", cname="int")]
	public enum Syntax {
		NONE,
		INTEL,
		ATT
	}

	/**
	 * The different types of fields in opcodes.
	 */
	[CCode (cprefix="R_ASM_MOD_", cname="int")]
	public enum Mod {
		/**
		 * A raw value, like 6DEF20h in {{{ mov eax, 6DEF20h }}}
		 */
		RAWVALUE,
		/**
		 * A literal value, as in {{{ push -1 }}}
		 */
		VALUE,
		/**
		 * The destination register. EBP in {{{ MOV EBP, ESP }}}
		 */
		DSTREG,
		/**
		 * The first source register. EBX in {{{ SUB EDX, EBX }}}
		 */
		SRCREG0,
		/**
		 * The second source register, for example in {{{ PUSHA AX, CX, DX }}}
		 */
		SRCREG1,
		/**
		 * The third source register.
		 */
		SRCREG2
	}

	/**
	 * Represents assembly opcodes.
	 */
	[CCode (cname="RAsmOp", destroy_function="", unref_function="")]
	public struct Op {
		/**
		 * The instruction length.
		 */
		public int inst_len;
		/**
		 * The instruction payload.
		 */
		public int payload;
		public uint8 buf[1024]; // FIXME proper static buffers w/o hardcoded size
		/**
		 * The assembly representation.
		 */
		public char buf_asm[1024]; // FIXME proper static strings w/o hardcoded size
		/**
		 * The hexadecimal representation.
		 */
		public char buf_hex[1024]; // FIXME proper static strings w/o hardcoded size
		public char buf_err[1024]; // FIXME proper static strings w/o hardcoded size
		// accessors for bindings
		/**
		 * Retrieves the hexadecimal representation of the instruction.
		 * @return the actual opcode, in hexadecimal.
		 */
		public string get_hex();
		/**
		 * Retrieves the assembly representation of the instruction.
		 * @return such representation.
		 */
		public string get_asm();
	}

	/**
	 * Models decompiled assembly code.
	 */
	[CCode (cname="RAsmCode", cprefix="r_asm_code_", free_function="r_asm_code_free", unref_function="r_asm_code_free")]
	public class Code {
		/**
		 * The code length.
		 */
		public int len;
		public uint8* buf;
		/**
		 * The hexadecimal representation of the dissasembled code.
		 */
		public string buf_hex;
		/**
		 * The assembly representation of the dissasembled code.
		 */
		public string buf_asm;
		/**
		 * Replaces all occurrences of a code fragment with another text, usually
		 * to enhance readability.
		 * @param key the code to replace.
		 * @param val the replacement value.
		 * @return the number of replacements made.
		 */
//		public int set_equ (<RAsmCode> code, string key, string val);
		//public int equ_replace (string key);
		//public void* free();
	}

	/**
	 * The bit size.
	 */
	public int bits;
	/**
	 * Whether it's assuming big endian or little endian.
	 * See [[http://en.wikipedia.org/wiki/Endianness]]
	 */
	public bool big_endian;
	/**
	 * The syntax.
	 */
	public int syntax;
	public uint64 pc;
	/**
	 * The list of active plugins.
	 */
	public RList<RAsm.Plugin> plugins;

	public RAsm();
	public bool use(string name);
	public bool set_bits(int bits);
	public bool set_syntax(Syntax syntax);
	public bool set_pc(uint64 addr);
	public bool set_big_endian(bool big);
	// TODO: Use Code? instead of op??
	public int disassemble(out Op op, uint8* buf, uint64 length);
	public int assemble(out Op op, string buf);
	public Code? mdisassemble(uint8 *buf, uint64 length);
	public Code? mdisassemble_hexstr(string hexstr);
	public Code? massemble(string buf);
	public Code? assemble_file(string file);

	public bool filter_input(string filter);
	public bool filter_output(string filter);

	/* TODO: not directy defined here */
	public void free();

	/**
	 * Represents Radare2 assembly plugins.
	 */
	[Compact]
	[CCode (cname="RAsmPlugin", destroy_function="", free_function="")]
	public class Plugin {
		/**
		 * The plugin name.
		 */
		public string name;
		/**
		 * The architecture the plugin supports.
		 */
		public string arch;
		/**
		 * The plugin description.
		 */
		public string desc;
		/**
		 * Supported bit sizes.
		 * Warning, future releases will probably use a bitmask approach instead.
		 */
		[CCode (array_length = false)]
		public int[] bits;
		/**
		 * The callback to be notified when the code is modified.
		 */
//		public RAsmModifyCallback modify;
	}
}
}
