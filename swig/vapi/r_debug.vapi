/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

[Compact]
[CCode (cheader_filename="r_debug.h", cname="struct r_debug_t", free_function="r_debug_free", cprefix="r_debug_")]
public class Radare.RDebug {
	public RBreakpoint bp;
	public RDebug(int hard);

	public bool use(string plugin);

	/* life cycle */
	public bool attach(int pid);
	public bool detach(int pid);
	// TODO: add attribute to invert arraylen
	//public bool startv(string[] argv); // XXX
	public bool start(string cmd);
	public RDebug.Reason stop_reason();

	/* control flow */
	[CCode (cname="r_debug_wait")]
	public bool hold();

	public bool kill(int sig);
	public bool kill_setup(int sig, int action); // XXX must be uint64 action
	public bool select (int pid, int tid);
	public bool step(int count);
	public bool step_over(int count);
	public bool @continue();
	public bool continue_kill(int sig);
	public bool continue_until(uint64 addr);
	public bool continue_until_optype(int type, int over);
	public bool continue_until_nontraced();
	public bool continue_syscall(int syscall);

	//public bool map_list(RDebug.Map map);
	public bool map_alloc (RDebug.Map map);
	public bool map_dealloc (RDebug.Map map);
	//public RList<RDebug.Map> map_list_new ();
	//public void map_list_free (RList<RDebug.Map> maps);
	public void map_list (uint64 addr);
	public RDebug.Map map_get(uint64 addr);
	public bool map_sync ();

	public RList<RDebug.Frame> frames ();

	public uint64 arg_get (int fast, int num);
	public bool arg_set (int fast, int num, uint64 val);

	public uint64 execute(uint8 *buf, int len); // XXX: uint8
	public int desc_open (string path);
	public int desc_close (int fd);
	public int desc_dup (int fd, int newfd);
	public int desc_read (int fd, uint64 addr, int len);
	public int desc_seek (int fd, uint64 addr);
	public int desc_write (int fd, uint64 addr, int len);
	public int desc_list (int rad);

	//public bool mmu_alloc(uint64 size, out uint64 size);
	//public bool mmu_free(uint64 addr);

	public bool reg_sync(RReg.Type type, bool set);
	public bool reg_list(int type, int size, bool rad); // TODO must be depreacted
	//public bool reg_set(string name, uint64 num);
	//public uint64 reg_get(string name);
	
	public int pid_list (int pid);
	public int thread_list (int pid);

	public void trace_reset (bool liberate);
	public int trace_pc ();
	public void trace_at (string str);
	//public RDebug.Tracepoint trace_get(uint64 addr);
	public void trace_list(int mode);
	//public RDebug.Tracepoint trace_add(uint64 addr, int size);
	public bool trace_tag (int tag);

	[CCode (cname="RDebugPid", free_function="r_debug_pid_free", cprefix="r_debug_pid_")]
	public struct Pid {
		public int pid;
		public int status;
		public int runnable;
		public string path;
		// list for childs
		// list for threads
		//public struct Process *parent;
		public Pid ();
	}

// XXX cname=int must be deprecated by valaswig
	[CCode (cprefix="R_DBG_PROC_", cname="int")]
	public enum ProcessStatus {
		STOP,
		RUN,
		SLEEP,
		ZOMBIE,
	}

	[CCode (cprefix="R_DBG_REASON_", cname="int")]
	public enum Reason {
		NEWPROC,
		TRAP,
		ILL,
		SIGNAL,
		FPU,
		BP,
		UNKNOWN
	}

	[CCode (cname="RDebugFrame")]
	public struct Frame {
		uint64 addr;
		int size;
	}

	[Compact]
	[CCode (cname="RDebugMap", cprefix="r_debug_map_", free_function="r_debug_map_free")]
	public class Map {
		public string name;
		public uint64 addr;
		public uint64 addr_end;
		public uint64 size;
		public string file;
		public int perm;
		public int user;

		//public Map(string name, uint64 addr, uint64 addr_end, int perm, int user);
	}

	[CCode (cname="RDebugTrace")]
	public struct Trace {
		RList<RDebug.Tracepoint> traces;
		int count;
		int enabled;
		int tag;
		int dup;
		string addresses;
	}

	[CCode (cname="RDebugTracepoint")]
	public struct Tracepoint {
		uint64 addr;
		uint64 tags;
		int tag;
		int size;
		int count;
		int times;
		uint64 stamp;
	}


	public int steps;
	public int pid;
	public int tid;
	public bool swstep;
	public int newstate;
	public RDebug.Trace trace;
	public bool stop_all_threads;
	public string reg_profile;
	public RReg reg;
	public RAnal anal;

	public RList<RDebug.Map> maps;
	public RList<RDebug.Map> maps_user;


	//public int pid_add();
	//public int pid_del();
	//public int pid_add_thread();
	//public int pid_del_thread();
	//public Process pid_get(int pid); // XXX wrong api syntax 'get' is keyword
	//public bool pid_set_status(ProcessStatus status);
}
