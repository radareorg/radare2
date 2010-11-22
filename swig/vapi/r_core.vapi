/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_core.h,r_bin.h,r_parse.h,r_lang.h,r_sign.h,r_reg.h,r_list.h,r_types_base.h", cname="RCore", free_function="r_core_free", cprefix="r_core_")]
public class RCore {
	public RFlag flags;
	public RNum num;
	/* lifecycle */
	public RCore();
	public RIO io;
	public RCons cons;
	public RDebug debug;
	public RConfig config;
	public RAsm assembler;
	public RAnal anal;
	public RBin bin;
	public RSyscall syscall;
	public RParse parser;
	public RLang lang;
	public RSearch search;
	public RSign sign;
	public RPrint print;
	// TODO: public RVm vm;
	public uint64 offset;

	public static unowned RCore cast(uint64 ptr);
	public bool loadlibs();
	/* commands */
	public int prompt(bool sync);
	public int prompt_exec();
	//[CCode (PrintfFormat)]
	//public int cmdf(...);
	public int cmd(string cmd, bool log);
	public int cmd0(string cmd);
	public void cmd_init ();

	// XXX. must be const in .h public int cmd_foreach(string cmd, string each);
	/**
	 * Execute every line of the given file as radare commands
	 */
	public int cmd_file(string file);
	public int cmd_command(string cmd);
	public unowned string cmd_str(string cmd);

	public string op_str(uint64 addr);
	public RAnal.Op op_anal(uint64 addr);

	public unowned string disassemble_instr(uint64 addr, int l);
	public unowned string disassemble_bytes(uint64 addr, int b);

	public int anal_search (uint64 from, uint64 to, uint64 ref);
	public void anal_refs(uint64 addr, int gv);
	public int anal_bb(uint64 at, int depth, int head);
	public int anal_bb_list(bool rad);
	public int anal_bb_seek(uint64 addr);
	public int anal_fcn(uint64 at, uint64 from, int depth);
	public int anal_fcn_list(string input, bool rad);
	public int anal_graph(uint64 addr, int opts);
	//public int anal_graph_fcn(string input, int opts);
	public int anal_ref_list(bool rad);

	public int project_open (string file);
	public int project_save (string file);
	public string project_info (string file);

	//public int gdiff(string file1, string file2, bool va);

	public void sysenv_update ();

	public void rtr_help();
	public void rtr_pushout(string input);
	public void rtr_list();
	public void rtr_add(string input);
	public void rtr_remove(string input);
	public void rtr_session(string input);
	public void rtr_cmd(string input);
	/* io */
	public int read_at(uint64 addr, uint8 *buf, int size);
	public int write_at(uint64 addr, uint8 *buf, int size);
	//public int write_op(uint64 addr, string arg, char op);
	public int block_read(bool next);
	public int block_size(int size);
	public int seek(uint64 addr, bool rb);
	public int seek_align(uint64 addr, int count);

	public bool yank(uint64 addr, int len);
	public bool yank_paste(uint64 addr, int len);

	public int visual(string input);
	public int visual_cmd(int ch);

	public int serve(int fd);

	/* asm */
	//public static RCore.AsmHit asm_hit_new();
	public RList<RCore.AsmHit> asm_strsearch(string input, uint64 from, uint64 to);
	public RList<RCore.AsmHit> asm_bwdisassemble(uint64 addr, int n, int len);

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
		public int len;
		public uint64 addr;
		public AsmHit ();
		// public static RList<RCoreAsmHit> AsmHit.list();
	}

	public delegate int SearchCallback (uint64 from, uint8 *buf, int len);
	public bool search_cb(uint64 from, uint64 to, SearchCallback cb);

	/* files */
	public RCore.File file_open(string file, int mode);
	public bool file_close(RCore.File cf);
	public bool file_close_fd(int fd);
	public bool file_list();

	public int seek_delta(int64 addr);

	public RCore.File file;
}
}
