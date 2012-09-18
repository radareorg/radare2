/* radare - LGPL - Copyright 2009-2012 pancake<nopcode.org> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_flags.h,r_anal.h,r_core.h,r_bin.h,r_parse.h,r_lang.h,r_sign.h,r_reg.h,r_list.h,r_types_base.h", cname="RCore", free_function="r_core_free", cprefix="r_core_")]
public class RCore {
	public RBin bin;
	public RConfig config;

	public uint64 offset;
	public uint32 blocksize;
	public uint32 blocksize_max;
	public uint8 *block;
	public uint8 *oobi;
	public int ffio;
	public int oobi_len;
	public uint8 *_yank;
	public int _yank_len;
	public int tmpseek;
	public bool _visual;
	public uint64 _yank_off;
	public int interrupted;

	public RCons cons;
	public RPair pair;
	public RIO io;
	public RCore.File file;
	public void* files; // XXX RList<???>
	public RNum num;
	public RLib lib;
	public void* rcmd;
	public RAnal anal;
	public RAsm assembler;
	public void *reflines;
	public void *reflines2;
	public RParse parser;
	public RPrint print;
	public RLang lang;

	public RDebug dbg;
	public RFlag flags;
	public RSearch search;
	public RSign sign;

	public RFS fs;
	public REgg egg;
public string cmdqueue;
public string lastcmd;
public int cmdrepeat;
public uint64 inc;
// rtr_n ...
	// TODO: public RVm vm;
	/* lifecycle */
	public RCons* get_cons ();
	public RConfig* get_config ();
	public RCore();

	public static unowned RCore cast(uint64 ptr);
	public bool loadlibs();
	/* commands */
	public int prompt(bool sync);
	public void prompt_loop ();
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
	public unowned string cmd_str_pipe(string cmd);

	public string op_str(uint64 addr);
	public RAnal.Op op_anal(uint64 addr);
	public RAsm.Op* disassemble(uint64 addr); // memory leak here

	public unowned string disassemble_instr(uint64 addr, int l);
	public unowned string disassemble_bytes(uint64 addr, int b);

	public int search_preludes();
	public int search_prelude(uint64 from, uint64 to, uint8 *k, int ksz, uint8 *m, int msz);

	public bool anal_all();
	public int anal_search (uint64 from, uint64 to, uint64 ref);
	public void anal_refs(uint64 addr, int gv);
	public int anal_bb(RAnal.Function fcn, uint64 at, int head);
	public int anal_bb_seek(uint64 addr);
	public int anal_fcn(uint64 at, uint64 from, int reftype, int depth);
	public int anal_fcn_list(string input, bool rad);
	public int anal_graph(uint64 addr, int opts);
	//public int anal_graph_fcn(string input, int opts);
	public int anal_ref_list(bool rad);

	public int project_open (string file);
	public int project_save (string file);
	public string project_info (string file);

	public int gdiff(RCore *c2);

	public void rtr_help();
	public void rtr_pushout(string input);
	public void rtr_list();
	public void rtr_add(string input);
	public void rtr_remove(string input);
	public void rtr_session(string input);
	public void rtr_cmd(string input);
	/* io */
	public bool read_at(uint64 addr, uint8 *buf, int size);
	public bool write_at(uint64 addr, uint8 *buf, int size);
	//public int write_op(uint64 addr, string arg, char op);
	public int block_read(bool next);
	public int block_size(int size);
	public int seek(uint64 addr, bool rb);
	public int seek_align(uint64 addr, int count);

	public bool yank(uint64 addr, int len);
	public bool yank_paste(uint64 addr, int len);

	public int visual(string input);
	public int visual_cmd(int ch);

	public int serve(RIO.Desc fd);

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
		public uint64 seek;
		public uint64 size;
		public RIO.Map map;
		public int rwx;
		public bool dbg;
		public RIO.Desc fd;
	}

	[CCode (cname="RCoreAsmHit", free_function="", ref_function="", unref_function="")]
	public class AsmHit {
		public string code;
		public int len;
		public uint64 addr;
		public AsmHit ();
		// public static RList<RCoreAsmHit> AsmHit.list();
	}

	[CCode (cname="RCoreSearchCallback")]
	public delegate int SearchCallback (uint64 from, uint8 *buf, int len);
	public bool search_cb(uint64 from, uint64 to, SearchCallback cb);

	/* files */
	public RCore.File file_open(string file, int mode, uint64 loadaddr=0);
	public bool file_close(RCore.File cf);
	public bool file_close_fd(int fd);
	public bool file_list();

	public int seek_delta(int64 addr);

	public bool bin_load(string? file);
	public void bin_set(RBin b);

}
}
