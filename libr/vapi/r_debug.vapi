/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_debug.h", cprefix="r_debug", lower_case_cprefix="r_debug_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_debug_t", free_function="r_debug_free", cprefix="r_debug_")]
	public class Debug {
		public Debug();

		/* life cycle */
		public bool attach(int pid);
		public bool detach(int pid);
		// TODO: add attribute to invert arraylen
		public bool startv(string[] argv); // XXX
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

		public bool mmu_alloc(uint64 size, out uint64 size);
		public bool mmu_free(uint64 addr);

		/* registers */
		[Compact]
		[CCode (cname="struct r_debug_t", free_function="r_debug_free", cprefix="r_debug_")]
		public struct Register {
			
		}
		bool reg_sync(bool set);
		uint64 reg_get(string name);
		bool reg_set(string name, uint64 val);
		bool reg_list(string name, uint64 val); // TODO must be deprecated
		
		/* breakpoints */
		public bool bp_enable(uint64 addr, bool set);
		public bool bp_add(uint64 addr, int sz, bool hw, int rwx);
		public bool bp_del(uint64 addr);
		public bool bp_restore(bool set);
		public bool bp_list(bool rad); // XXX to be deprecated
		/* processes */
		struct Process {
			int pid;
			int status;
			int runnable;
			// list for childs
			// list for threads
			struct Process parent;
		}

		enum ProcessStatus {
			STOP,
			RUN,
			SLEEP,
			ZOMBIE,
		}
		public int pid_add();
		public int pid_del();
		public int pid_add_thread();
		public int pid_del_thread();
		public Debug.Process pid_get(int pid);
		public bool pid_set_status(Debug.ProcessStatus status);

	}
}
