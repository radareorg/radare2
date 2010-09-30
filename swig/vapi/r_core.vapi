/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_core.h,r_list.h,r_types_base.h", cname="RCore", free_function="r_core_free", cprefix="r_core_")]
public class RCore {
	public RFlag flags;
	public RNum num;
	/* lifecycle */
	public RCore();
	public RIO io;
	public RCons cons;
	public RConfig config;
	public RAsm assembler;
	public RAnal anal;

	public static unowned RCore cast(uint64 ptr);
	public bool loadlibs();
	/* commands */
	public int prompt(bool sync);
	public int prompt_exec();
	//[CCode (PrintfFormat)]
	//public int cmdf(...);
	public int cmd(string cmd, bool log);
	public int cmd0(string cmd);
	/**
	 * Execute every line of the given file as radare commands
	 */
	public int cmd_file(string file);
	public int cmd_command(string cmd);
	public unowned string cmd_str(string cmd);

	public string op_str(uint64 addr);
	public RAnal.Op op_anal(uint64 addr);

	/* io */
	public int read_at(uint64 addr, out uint8 *buf, int size);
	public int write_at(uint64 addr, uint8 *buf, int size);
	public int block_read(bool next);
	public int block_size(int size);
	public int seek(uint64 addr, bool rb);
	public int seek_align(uint64 addr, int count);

	/* asm */
	public RList<RCore.AsmHit> asm_strsearch(string input, uint64 from, uint64 to);

	// XXX mode = Radare.Io.Mode
	[Compact]
	[CCode (cname="RCoreFile", cprefix="r_core_file_", free_function="")]
	public class File {
		//public static bool set(string file, Core.File file);
		//public static bool close(string file, Core.File file);
		/* attributes */
		public string uri;
		public string filename;
		public uint64 offset;
		public uint64 size;
		public int rwx;
		public int fd;
	}

	[CCode (cname="RCoreAsmHit", free_function="", ref_function="", unref_function="")]
	public class AsmHit {
		public string code;
		public uint64 addr;
	}

	/* files */
	public RCore.File file_open(string file, int mode);
	//public bool file_close_fd(int fd);

	public RCore.File file;
}
}
