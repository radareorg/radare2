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
	public int stop_reason();

	/* control flow */
	public bool wait();
	public bool step(int count);
	//public bool kill(int pid, int sig);
	public bool step_over(int count);
	public bool @continue();
	public bool continue_until(uint64 addr);
	public bool continue_syscall(int syscall);

	//public bool mmu_alloc(uint64 size, out uint64 size);
	//public bool mmu_free(uint64 addr);

	/* registers */
	[Compact]
	[CCode (cname="struct r_debug_t", free_function="r_debug_free", cprefix="r_debug_")]
	public struct Register {
		
	}
	bool reg_sync(bool set);
	bool reg_list(int type, int size, bool rad); // TODO must be depreacted
	
	/* processes */
	public struct Process {
		public int pid;
		public int status;
		public int runnable;
		// list for childs
		// list for threads
		//public struct Process *parent;
	}

// XXX cname=int must be deprecated by valaswig
	[CCode (cprefix="R_DBG_PROC_", cname="int")]
	public enum ProcessStatus {
		STOP,
		RUN,
		SLEEP,
		ZOMBIE,
	}
	//public int pid_add();
	//public int pid_del();
	//public int pid_add_thread();
	//public int pid_del_thread();
	//public Process pid_get(int pid); // XXX wrong api syntax 'get' is keyword
	//public bool pid_set_status(ProcessStatus status);
}
