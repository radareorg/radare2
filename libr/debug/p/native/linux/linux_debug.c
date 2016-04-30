/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <elf.h>
#include <signal.h>
#include <sys/procfs.h>
#include "linux_debug.h"

/* Coredump */
#define ELF_HDR_SIZE sizeof(Elf64_Ehdr)

#define R_DEBUG_REG_T struct user_regs_struct

#define SIZE_NT_FILE_DESCSZ sizeof(unsigned long) * 3   /* start_address * end_address * offset_address */
                                                        /* 
                                                        NT_FILE layout:
                                                        [number of mappings]
                                                        [page size]
                                                        [foreach(mapping)
                                                                [start_address]
                                                                [end_address]
                                                                [offset_address]
                                                        [filenames]
                                                        */
#define DEFAULT_NOTE    6

static unsigned int n_notes = DEFAULT_NOTE;

typedef struct map_file {
        unsigned int count;
        unsigned int size;
}map_file_t;

map_file_t mapping_file = {0,0};

typedef struct auxv_buff {
        void *data;
        size_t size;
} auxv_buff_t;

typedef struct linux_map_entry {
        unsigned long long start_addr;
        unsigned long long end_addr;
        unsigned long long offset;
        unsigned long long inode;
        unsigned long int perms;
        unsigned int anonymous;
        unsigned int s_name;
        char *name;
        struct linux_map_entry *n;
}linux_map_entry_t;
                   
#define ADD_MAP_NODE(p)         do {                                                    \
                                        if(me_head == NULL) {                           \
                                                me_head = p;                            \
                                                me_tail = p;                            \
                                        } else {                                        \
                                                p->n = NULL;                            \
                                                me_tail->n = p;                         \
                                                me_tail = p;                            \
                                        }                                               \
                                } while(0)


typedef struct linux_elf_note {
        prpsinfo_t *prpsinfo;
        prstatus_t *prstatus;
        siginfo_t *siginfo;
        auxv_buff_t *auxv;
        elf_fpregset_t *fp_regset;
        linux_map_entry_t *maps;
}linux_elf_note_t;

typedef enum {
        PID_E = 0,
        TCOMM_E,
        STATE_E,
        PPID_E,
        PGRP_E,
        SID_E,
        TTY_NR_E,
        TTY_PGRP_E,
        FLAGS_E,
        MIN_FLT_E,
        CMIN_FLT_E,
        MAJ_FLT_E,
        UTIME_E,
        STIME_E,
        CUTIME_E,
        CSTIME_E,
        PRIORITY_E,
        NICE_E,
        NUM_THREADS_E,
        IT_REAL_VALUE_E,
        START_TIME_E,
        VSIZE_E,
        RSS_E,
        RSSLIM_E,
        START_CODE_E,
        END_CODE_E,
        START_STACK_E,
        ESP_E,
        EIP_E,
        PENDING_E,
        BLOCKED_E,
        SIGIGN_E,
        SIGCATCH_E,
        PLACE_HOLDER_1E,
        PLACE_HOLDER_2E,
        PLACE_HOLDER_3E,
        EXIT_SIGNAL_E,
        TASK_CPU_E,
        RT_PRIORITY_E,
        POLICY_E,
        BLKIO_TICKS_E,
        GTIME_E,
        START_DATA_E,
        END_DATA_E,
        START_BRK_E,
        ARG_START_E,
        ARG_END_E,
        ENV_START_E,
        ENV_END_E,
        EXIT_CODE_E
}proc_stat_entry;

/*		*/


const char *linux_reg_profile (RDebug *dbg) {
#if __arm__
#include "reg/linux-arm.h"
#elif __arm64__ || __aarch64__
#include "reg/linux-arm64.h"
#elif __MIPS__ || __mips__
#include "reg/linux-mips.h"
#elif (__i386__ || __x86_64__)
	if (dbg->bits & R_SYS_BITS_32) {
#if __x86_64__
#include "reg/linux-x64-32.h"
#else
#include "reg/linux-x86.h"
#endif
	} else {
#include "reg/linux-x64.h"
	}
#elif __ppc__ || __powerpc__ || __POWERPC__
#include "reg/linux-ppc.h"
#else
#error "Unsupported Linux CPU"
#endif
}

	

int linux_handle_signals (RDebug *dbg) {
	siginfo_t siginfo = {0};
	int ret = ptrace (PTRACE_GETSIGINFO, dbg->pid, 0, &siginfo);
	if (ret != -1 && siginfo.si_signo > 0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason.type = R_DEBUG_REASON_SIGNAL;
		dbg->reason.signum = siginfo.si_signo;
		//dbg->stopaddr = siginfo.si_addr;
		//dbg->errno = siginfo.si_errno;
		// siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
#warning DO MORE RDEBUGREASON HERE
		switch (dbg->reason.signum) {
		case SIGABRT: // 6 / SIGIOT // SIGABRT
			dbg->reason.type = R_DEBUG_REASON_ABORT;
			break;
		case SIGSEGV:
			dbg->reason.type = R_DEBUG_REASON_SEGFAULT;
			eprintf ("[+] SIGNAL %d errno=%d addr=%p code=%d ret=%d\n",
				siginfo.si_signo, siginfo.si_errno,
				siginfo.si_addr, siginfo.si_code, ret);
			break;
		default: break;
		}
		return true;
	}
	return false;
}

int linux_step (RDebug *dbg) {
	int ret = false;
	ut64 addr = 0; /* should be eip */
	//ut32 data = 0;
	//printf("NATIVE STEP over PID=%d\n", pid);
	addr = r_debug_reg_get (dbg, "PC");
	ret = ptrace (PTRACE_SINGLESTEP, dbg->pid,
			(void*)(size_t)addr, 0);
	linux_handle_signals (dbg);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}

int linux_attach (RDebug *dbg, int pid) {
	int ret = -1;
	int traceflags = 0;
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEFORK;
		traceflags |= PTRACE_O_TRACEVFORK;
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_clone) {
		// threads
		traceflags |= PTRACE_O_TRACECLONE;
	}
	//traceflags |= PTRACE_O_TRACESYSGOOD; mark 0x80| on signal event, x86-only
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	traceflags |= PTRACE_O_TRACEEXIT;
	if (ptrace (PTRACE_SETOPTIONS, pid, 0, traceflags) == -1) {
		/* ignore ptrace-options errors */
	}
	ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
	if (ret != -1) perror ("ptrace (PT_ATTACH)");
	return pid;
}

RDebugInfo *linux_info (RDebug *dbg, const char *arg) {
	char procpid_cmdline[1024];
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) return NULL;
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;// TODO : use readlink
	rdi->exe = NULL;// TODO : use readlink!
	snprintf (procpid_cmdline, sizeof(procpid_cmdline), 
		"/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = r_file_slurp (procpid_cmdline, NULL);
	return rdi;
}

RList *linux_thread_list (int pid, RList *list) {
	int i, fd = -1, thid = 0;
	char *ptr, cmdline[1024];

	if (!pid) {
		r_list_free (list);
		return NULL;
	}
	r_list_append (list, r_debug_pid_new ("(current)", pid, 's', 0));
	/* list parents */

	/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
	//while ((de = readdir (dh))) {
	snprintf (cmdline, sizeof(cmdline), "/proc/%d/task", pid);
	if (r_file_is_directory (cmdline)) {
		struct dirent *de;
		DIR *dh = opendir (cmdline);
		while ((de = readdir (dh))) {
			int tid = atoi (de->d_name);
			// TODO: get status, pc, etc..
			r_list_append (list, r_debug_pid_new (cmdline, tid, 's', 0));
		}
		closedir (dh);
	} else {
		/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
		//while ((de = readdir (dh))) {
#undef MAXPID
#define MAXPID 99999
		for (i = pid; i < MAXPID; i++) { // XXX
			snprintf (cmdline, sizeof(cmdline), "/proc/%d/status", i);
			if (fd != -1)
				close (fd);
			fd = open (cmdline, O_RDONLY);
			if (fd == -1) continue;
			if (read (fd, cmdline, 1024)<2) {
				// read error
				close (fd);
				break;
			}
			cmdline[sizeof(cmdline) - 1] = '\0';
			ptr = strstr (cmdline, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr + 5);
				if (tgid != pid) {
					close (fd);
					continue;
				}
				if (read (fd, cmdline, sizeof(cmdline) - 1) <2) {
					break;
				}
				snprintf (cmdline, sizeof(cmdline), "thread_%d", thid++);
				cmdline[sizeof (cmdline) - 1] = '\0';
				r_list_append (list, r_debug_pid_new (cmdline, i, 's', 0));
			}
		}
		if (fd != -1) {
			close (fd);
			fd = -1;
		}
	}
	return list;
}

#define PRINT_FPU(fpregs) \
	eprintf ("cwd = 0x%04x  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04x  ; status\n", (fpregs).swd);\
	eprintf ("ftw = 0x%04x              ", (fpregs).ftw);\
	eprintf ("fop = 0x%04x\n", fpregs.fop);\
	eprintf ("rip = 0x%016"PFMT64x"  ", (ut64)(fpregs).rip);\
	eprintf ("rdp = 0x%016"PFMT64x"\n", (ut64)(fpregs).rdp);\
	eprintf ("mxcsr = 0x%08x        ", (fpregs).mxcsr);\
	eprintf ("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)\

#define PRINT_FPU_NOXMM(fpregs) \
	eprintf ("cwd = 0x%04lx  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04lx  ; status\n", (fpregs).swd);\
	eprintf ("twd = 0x%04lx              ", (fpregs).twd);\
	eprintf ("fip = 0x%04lx          \n", (fpregs).fip);\
	eprintf ("fcs = 0x%04lx              ", (fpregs).fcs);\
	eprintf ("foo = 0x%04lx          \n", (fpregs).foo);\
	eprintf ("fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu (void *f, int r){
#if __x86_64__ || __i386__
	int i;
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct*)f;
#if __x86_64__
#if !__ANDROID__
	eprintf ("---- x86-64 ----\n");
	PRINT_FPU (fpregs);
	eprintf ("size = 0x%08x\n", (ut32)sizeof (fpregs));
	for (i = 0; i < 16; i++) {
		ut32 *a = (ut32*)&fpregs.xmm_space;
		a = a + (i * 4);
		eprintf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
			(int)a[2], (int)a[3] );
		if (i < 8) {
			ut64 *b = (ut64*)&fpregs.st_space[i * 4];
			ut32 *c = (ut32*)&fpregs.st_space;
			float *f = (float *)&fpregs.st_space;
			double *d = (double *)&fpregs.st_space[i*4];
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  |\
				%0.3f (%08x) \n", i, *d, *b,
				(float)f[0], c[0], (float)f[1], c[1]);
		} else {
			eprintf ("\n");
		}
	}
#else
	PRINT_FPU (fpregs);
	for(i = 0;i < 8; i++) {
		ut64 *b = (ut64 *)&fpregs.st_space[i*4];
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  | \
			%0.3f (%08x) \n", i,
			(double)*((double*)&fpregs.st_space[i*4]), *b, (float) f[0],
			c[0], (float) f[1], c[1]);
	}
#endif	// !__ANDROID__
#elif __i386__
	if (!r) {
#if !__ANDROID__
		struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct*)f;
		eprintf ("---- x86-32 ----\n");
		eprintf ("cwd = 0x%04x  ; control   ", fpxregs.cwd);
		eprintf ("swd = 0x%04x  ; status\n", fpxregs.swd);
		eprintf ("twd = 0x%04x ", fpxregs.twd);
		eprintf ("fop = 0x%04x\n", fpxregs.fop);
		eprintf ("fip = 0x%08x\n", fpxregs.fip);
		eprintf ("fcs = 0x%08x\n", fpxregs.fcs);
		eprintf ("foo = 0x%08x\n", fpxregs.foo);
		eprintf ("fos = 0x%08x\n", fpxregs.fos);
		eprintf ("mxcsr = 0x%08x\n", fpxregs.mxcsr);
		for(i = 0; i < 8; i++) {
			ut32 *a = (ut32*)(&fpxregs.xmm_space);
			ut64 *b = (ut64 *)(&fpxregs.st_space[i * 4]);
			ut32 *c = (ut32*)&fpxregs.st_space;
			float *f = (float *)&fpxregs.st_space;
			a = a + (i * 4);
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0],
				(int)a[1], (int)a[2], (int)a[3] );
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) |\
				%0.3f (0x%08x)\n", i,
				(double)*((double*)(&fpxregs.st_space[i*4])), b[0],
				f[0], c[0], f[1], c[1]);
		}
#endif // !__ANDROID__
	} else {
		eprintf ("---- x86-32-noxmm ----\n");
		PRINT_FPU_NOXMM (fpregs);
		for(i = 0; i < 8; i++) {
			ut64 *b = (ut64 *)(&fpregs.st_space[i*4]);
			double *d = (double*)b;
			ut32 *c = (ut32*)&fpregs.st_space;
			float *f = (float *)&fpregs.st_space;
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x)  | \
				%0.3f (0x%08x)\n", i, d[0], b[0], f[0], c[0], f[1], c[1]);
		}
	}
#endif
#else 
#warning not implemented for this platform
#endif
}

int linux_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __i386__ || __x86_64__
#if !__ANDROID__
	{
		int i;
		for (i = 0; i < 8; i++) { //DR0-DR7
			if (i == 4 || i == 5) continue;
			long ret = ptrace (PTRACE_PEEKUSER, pid, 
					r_offsetof (struct user, u_debugreg[i]), 0);
			memcpy (buf + (i * sizeof(ret)), &ret, sizeof(ret));
		}
		return sizeof (R_DEBUG_REG_T);
	}
#else
	#warning Android X86 does not support DRX
#endif
#endif
		return true;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_MMX:
	case R_REG_TYPE_XMM:
#if __x86_64__ || __i386__
		{
		int ret1 = 0;
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
#if __x86_64__
#if !__ANDROID__
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) print_fpu ((void *)&fpregs, 0);
			if (ret1 != 0) return false;
			if (sizeof(fpregs) < size) size = sizeof(fpregs);
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs);
#else
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) print_fpu ((void *)&fpregs, 0);
			if (ret1 != 0) return false;
			if (sizeof(fpregs) < size) size = sizeof(fpregs);
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs)
#endif // !__ANDROID__
#elif __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret1 = ptrace (PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret1 == 0) {
				if (showfpu) print_fpu ((void *)&fpxregs, ret1);
				if (sizeof(fpxregs) < size) size = sizeof(fpxregs);
				memcpy (buf, &fpxregs, size);
				return sizeof(fpxregs);
			} else {
				ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) print_fpu ((void *)&fpregs, ret1);
				if (ret1 != 0) return false;
				if (sizeof(fpregs) < size) size = sizeof(fpregs);
				memcpy (buf, &fpregs, size);
				return sizeof(fpregs);
			}
#else
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) print_fpu ((void *)&fpregs, 1);
			if (ret1 != 0) return false;
			if (sizeof(fpregs) < size) size = sizeof(fpregs);
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs);
#endif // !__ANDROID__
#endif // __i386__
		}
		}
#else
	#warning not implemented for this platform
#endif
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
			R_DEBUG_REG_T regs;
			memset (&regs, 0, sizeof (regs));
			memset (buf, 0, size);
#if __arm64__ || __aarch64__
			{
			struct iovec io = {
				.iov_base = &regs,
				.iov_len = sizeof (regs)
			};
			ret = ptrace (PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
			}
#elif __POWERPC__
			ret = ptrace (PTRACE_GETREGS, pid, &regs, NULL);
#else
			/* linux -{arm/x86/x86_64} */
			ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
#endif
			/*
			 * if perror here says 'no such process' and the 
			 * process exists still.. is because there's a missing call 
			 * to 'wait'. and the process is not yet available to accept 
			 * more ptrace queries.
			 */
			if (ret != 0) return false;
			if (sizeof (regs) < size) size = sizeof(regs);
			memcpy (buf, &regs, size);
			return sizeof (regs);
		}
		break;
	}
	return true;

}

int linux_reg_write (RDebug *dbg, int type, const ut8 *buf, int size) {
	if (type == R_REG_TYPE_DRX) {
// XXX: this android check is only for arm
#if !__ANDROID__
		int i;
		long *val = (long*)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) continue;
			if (ptrace (PTRACE_POKEUSER, dbg->pid, r_offsetof (
					struct user, u_debugreg[i]), val[i])) {
				eprintf ("ptrace error for dr %d\n", i);
				perror ("ptrace");
			}
		}
		return sizeof(R_DEBUG_REG_T);
#else
		return false;
#endif
	}
	if (type == R_REG_TYPE_GPR) {
#if __arm64__ || __aarch64__
		struct iovec io = {
			.iov_base = buf,
			.iov_len = sizeof (R_DEBUG_REG_T)
		};
		int ret = ptrace (PTRACE_SETREGSET, dbg->pid, NT_PRSTATUS, &io);
#elif __POWERPC__
		int ret = ptrace (PTRACE_SETREGS, dbg->pid, &regs, NULL);
#else 
		int ret = ptrace (PTRACE_SETREGS, dbg->pid, 0, (void*)buf);
#endif
		if (size > sizeof (R_DEBUG_REG_T)) size = sizeof (R_DEBUG_REG_T);
		return (ret != 0) ? false : true;
	}
	return false;
}

RList *linux_desc_list (int pid) {
	RList *ret = NULL;
	char path[512], file[512], buf[512];
	struct dirent *de;
	RDebugDesc *desc;
	int type, perm;
	int len, len2;
	struct stat st;
	DIR *dd = NULL;

	snprintf (path, sizeof (path), "/proc/%i/fd/", pid);
	if (!(dd = opendir (path))) {
		eprintf ("Cannot open /proc\n");
		return NULL;
	}
	ret = r_list_new ();
	if (!ret) {
		closedir (dd);
		return NULL;
	}
	ret->free = (RListFree)r_debug_desc_free;
	while ((de = (struct dirent *)readdir(dd))) {
		if (de->d_name[0] == '.') continue;
		len = strlen (path);
		len2 = strlen (de->d_name);
		if (len + len2 + 1 >= sizeof(file)) {
			r_list_free (ret);
			closedir (dd);
			eprintf ("Filename is too long");
			return NULL;
		}
		memcpy (file, path, len);
		memcpy (file + len, de->d_name, len2 + 1);
		memset (buf, 0, sizeof(buf));
		readlink (file, buf, sizeof (buf) - 1);
		buf[sizeof (buf)-1] = 0;
		type = perm = 0;
		if (stat (file, &st) != -1) {
			type  = st.st_mode & S_IFIFO  ? 'P':
#ifdef S_IFSOCK
				st.st_mode & S_IFSOCK ? 'S':
#endif
				st.st_mode & S_IFCHR  ? 'C':'-';
		}
		if (lstat(path, &st) != -1) {
			if (st.st_mode & S_IRUSR) perm |= R_IO_READ;
			if (st.st_mode & S_IWUSR) perm |= R_IO_WRITE;
		}
		//TODO: Offset
		desc = r_debug_desc_new (atoi (de->d_name), buf, perm, type, 0);
		if (!desc) break;
		r_list_append (ret, desc);
	}
	closedir (dd);
	return ret;
}


/* Coredump  functions */

static int is_a_right_entry(proc_stat_entry entry)
{
        return !(entry ==  STATE_E || entry == PPID_E || entry == PGRP_E || entry == SID_E || entry == FLAGS_E || entry == NICE_E || entry ==  NUM_THREADS_E);
}

static int is_data(char c)
{
        return !isalnum(c);
}

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg) {

        FILE *f;
        char file[128];
        long nice;
        int c;
        int pos;
        pid_t mypid;
        char *pbuff;
        char *tpbuff;
        char *temp_uid;
        char *temp_gid;
        char *p_uid;
        char *p_gid;
        char data[80];
        char buff[4096];
        char prog_states[6] = "RSDTZW";
        unsigned int n_threads;
        proc_stat_entry current_entry;
        prpsinfo_t *p;

        p = (prpsinfo_t *)malloc(sizeof(prpsinfo_t));

        /* /proc/pid/stat: let's have some fun. Documentation about the fields can be found under /Documentation/filesystem/proc.txt: Table 1-4 */
        p->pr_pid = mypid = dbg->pid;
        snprintf(file, sizeof(file), "/proc/%d/stat", mypid);

        f = fopen(file, "r");
        if (f == NULL) {
                printf ("Cannot open '%s' for writing\n", file);
                goto error;
        }

        pos = 0;
        /* Need to find which function radare2 exposes to read files */
        while((c = fgetc(f)) != EOF && c!= '\n' && pos < sizeof(buff))
                buff[pos++] = c;

        buff[pos] = '\0';
        pbuff = buff;

        /* Parsing /proc/%d/stat */
        for(tpbuff = pbuff, current_entry = PID_E; *pbuff != '\0'; tpbuff = pbuff) {
                int len;

                while(!is_data(*pbuff++))
			;

		pbuff--;
                len = pbuff - tpbuff;

                if(len) {
                        strncpy(data, tpbuff, len);
                        data[pbuff - tpbuff] = '\0';
                        if(!is_a_right_entry(current_entry)) {
                                switch(current_entry) {
                                        case TCOMM_E:
                                                strncpy(p->pr_fname, data, sizeof(p->pr_fname));
                                                break;
                                        case STATE_E:
                                                p->pr_sname = data[0];
                                                p->pr_zomb = (p->pr_sname == 'Z') ? 1 : 0;
                                                p->pr_state = strchr(prog_states, p->pr_sname) - prog_states;
                                                break;
                                        case PPID_E:
                                                p->pr_ppid = atoi(data);
                                                break;
                                        case PGRP_E:
                                                p->pr_pgrp = atoi(data);
                                                break;
                                        case SID_E:
                                                p->pr_sid = atoi(data);
                                                break;
                                        case FLAGS_E:
                                                p->pr_flag = atol(data);
                                                break;
                                        case NICE_E:
                                                nice = atol(data);
                                                p->pr_nice = nice;
                                                break;
                                        case NUM_THREADS_E:
                                                n_threads = atoi(data);
                                                break;
                                }
                        }
                        current_entry++;
                }

                while(*pbuff == ' ' || *pbuff == '(' || *pbuff == ')')
                        pbuff++;
        }

        /* Since we can't find pr_uid and pr_gid in /proc/%d/stat, we need to look for that in /proc/%d/status */
        snprintf(file, sizeof(file), "/proc/%d/status", mypid);
	
	f = fopen(file, "r");
        if (f == NULL) {
                printf ("Cannot open '%s' for writing\n", file);
                goto error;
        }

        pos = 0;

        while((c = fgetc(f)) != EOF && pos < sizeof(buff))
                buff[pos++] = c;
        buff[pos] = '\0';

        /* Let's search for Uid */
        temp_uid = strstr(buff, "Uid:");
        temp_gid = strstr(buff, "Gid:");

        while(!isdigit(*temp_uid++))
                ;
        p_uid = temp_uid-1;

        while(isdigit(*temp_uid++))
                ;
        p_uid[temp_uid-p_uid-1] = '\0';


        /* Do the same for Gid */
        while(!isdigit(*temp_gid++))
                ;
        p_gid = temp_gid-1;

        while(isdigit(*temp_gid++))
                ;
        p_gid[temp_gid-p_gid-1] = '\0';


        p->pr_uid = atoi(p_uid);
        p->pr_gid = atoi(p_gid);

        /*      We still need to get pr_psargs          */
        /* is radare2 storing the arg_list somewhere? If not we have to get that from /proc/ */
        /*                                              */

        return p;

        error:
                if(p)
			free(p);
		return NULL;
}

static prstatus_t *linux_get_prstatus(RDebug *dbg) {
        prstatus_t *p;
        char *reg_buff;
        int rbytes;
        size_t size_gp_regset;

        reg_buff = malloc(sizeof(struct user_regs_struct));

        size_gp_regset = sizeof(elf_gregset_t);
        rbytes = linux_reg_read(dbg, R_REG_TYPE_GPR, reg_buff, size_gp_regset);
        if(rbytes != size_gp_regset) {                    /* something went wrong */
                printf("linux_get_prstatus: error in (rbytes != size_gp_regset)\n");
                return NULL;
        }

        p = (prstatus_t *)malloc(sizeof(prstatus_t));
        p->pr_pid = dbg->pid;
        /*p->pr_cursig: is radare2 storing that somehere? */
        memcpy(p->pr_reg, reg_buff, rbytes);

        return p;
}

static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg) {

        elf_fpregset_t *p;
        char *reg_buff;
        int rbytes;
        size_t size_fp_regset;

        reg_buff = malloc(sizeof(struct user_fpregs_struct));

        size_fp_regset = sizeof(elf_fpregset_t);
        rbytes = linux_reg_read(dbg, R_REG_TYPE_FPU, reg_buff, size_fp_regset);
        if(rbytes != size_fp_regset)
                return NULL;

        p = (elf_fpregset_t *)malloc(sizeof(elf_fpregset_t));
        memcpy(p, reg_buff, rbytes);

        return p;
}

static siginfo_t *linux_get_siginfo(RDebug *dbg) {

        siginfo_t *siginfo;
        int ret;

        siginfo = (siginfo_t *)malloc(sizeof(siginfo_t));
        ret = ptrace(PTRACE_GETSIGINFO, dbg->pid, 0, siginfo);

        if(!siginfo->si_signo) {
                free(siginfo);
                siginfo = NULL;
        }

        return siginfo;
}

static int get_map_address_space(char *pstr, unsigned long long *start_addr, unsigned long long *end_addr)
{
        char *pp;

        pp = pstr;

        *start_addr = strtoul(pp, &pp, 16);
        pp++;   /*Skip '-' */
        *end_addr = strtoul(pp, &pp, 16);

        return 0;
}

#define X_MEM 0x1
#define W_MEM 0x2
#define R_MEM 0x4
#define P_MEM 0x8
#define S_MEM 0x10

static int get_map_perms(char *pstr, unsigned long int *fl_perms)
{
        char *pp;
        int len;
        unsigned long int flags;

        len = strlen(pstr);
        flags = 0;

        pp = memchr(pstr, 'r', len);
        if(pp)
                flags |= R_MEM;

        pp = memchr(pstr, 'w', len);
        if(pp)
                flags |= W_MEM;

        pp = memchr(pstr, 'x', len);
        if(pp)
                flags |= X_MEM;

        pp = memchr(pstr, 'p', len);
        if(pp)
                flags |= P_MEM;

        pp = memchr(pstr, 's', len);
        if(pp)
                flags |= S_MEM;

        *fl_perms = flags;

        if((flags & P_MEM) && (flags & S_MEM))
                return -1;

        return 0;
}

static int get_map_offset(char *pstr, unsigned long long *offset)
{
        char *pp;

        pp = pstr;
        *offset = strtoul(pp, &pp, 16);

        return 0;
}


static int get_map_name(char *pstr, char **name)
{
        *name = strdup(pstr);
        return 0;
}

typedef enum {
        ADDR,
        PERM,
        OFFSET,
        DEV,
        INODE,
        NAME
}MAPS_FIELD;

int get_anonymous_value(char *keyw)
{
        while(!isspace(*keyw))
                keyw++;

        while(isspace(*keyw))
                keyw++;

        return *keyw != '0';
}


int is_map_anonymous(FILE *f, unsigned long long start_addr, unsigned long long end_addr)
{
        char identity[80];
        char buff[1024];
        char buff_tok[256];
        char *keyw;
        int is_anonymous;

        snprintf(identity, sizeof(identity), "%08lx-%08lx", start_addr, end_addr);
        while(fgets(buff, sizeof(buff), f) != NULL) {
                if(strstr(buff, identity) != NULL) {
                        while(fgets(buff_tok, sizeof(buff_tok), f) != NULL) {
                                if((keyw = strstr(buff_tok, "Anonymous:")) != NULL) {
                                        is_anonymous = get_anonymous_value(keyw);
                                        fseek(f, 0, SEEK_SET);
                                        return is_anonymous;
                                }
                        }
                }
        }

        fseek(f, 0, SEEK_SET);
        return 0;
}

static linux_map_entry_t *linux_get_mapped_files(RDebug *dbg) {

        linux_map_entry_t *me_head, *me_tail;
        linux_map_entry_t *pmentry;
        FILE *f;
        unsigned long long start_addr;
        unsigned long long end_addr;
        unsigned long long offset;
        unsigned long int flag_perm;
        pid_t mypid;
        char buff[4906];
        char file[80];
        char *name;
        char *p;
        char *end_line;
        char *end_token;
        FILE *f_smaps;
        MAPS_FIELD maps_current;

        me_head = me_tail = NULL;
        name = NULL;
        mypid = dbg->pid;

        snprintf(file, sizeof(file), "/proc/%d/smaps", mypid);
        f_smaps = fopen(file, "r");

        memset(file, '\0', sizeof(file));

        snprintf(file, sizeof(file), "/proc/%d/maps", mypid);

        f = fopen(file, "r");
        if (f == NULL) {
                printf ("Cannot open '%s' for reading\n", file);
                return NULL;
        }

        fread(buff, sizeof(buff), 1, f);

        p = strtok_r(buff, "\n", &end_line);
        while(p != NULL) {
                char *pp;
                pp = strtok_r(p, " ", &end_token);
                maps_current = ADDR;

                while(pp != NULL) {
			switch(maps_current) {

                                case ADDR:
                                                get_map_address_space(pp, &start_addr, &end_addr);
                                                break;
                                case PERM:
                                                get_map_perms(pp, &flag_perm);
                                                break;
                                case OFFSET:
                                                get_map_offset(pp, &offset);
                                                break;
                                case DEV:
                                                maps_current++;
                                                pp = strtok_r(NULL, " ", &end_token);
                                case INODE:
                                                maps_current++;
                                                pp = strtok_r(NULL, " ", &end_token);
                                case NAME:
                                                if(pp)  /* Has this map a name? */
                                                        get_map_name(pp, &name);
                                                break;
                        }
                        maps_current++;
                        pp = strtok_r(NULL, " ", &end_token);
                }

                pmentry = (linux_map_entry_t *)malloc(sizeof(linux_map_entry_t));
                pmentry->start_addr = start_addr;
                pmentry->end_addr = end_addr;
                pmentry->perms = flag_perm;
                pmentry->offset = offset;
                pmentry->inode = 0;
                if(name) {
                        pmentry->name = strdup(name);
                        pmentry->s_name = strlen(pmentry->name) + 1;
                        free(name);
                        name = NULL;
                }
                if(     pmentry->name != NULL &&
                        (strcmp(pmentry->name, "[vsyscall]") == 0 ||
                        strcmp(pmentry->name, "[vvar]") == 0 ||
                        strcmp(pmentry->name, "[vdso]") == 0))
                        pmentry->anonymous = 1;
                else
                        pmentry->anonymous = is_map_anonymous(f_smaps, start_addr, end_addr);   /* Fix this, we can make it much faster, was just for test purposes */
		
		if(pmentry->name &&     strcmp(pmentry->name, "[vsyscall]") != 0
                                        && strcmp(pmentry->name, "[vvar]") != 0
                                        && strcmp(pmentry->name, "[vdso]") != 0
                                        && strcmp(pmentry->name, "[stack]")) {
                        mapping_file.size += SIZE_NT_FILE_DESCSZ + pmentry->s_name;
                        mapping_file.count++;
                }

                ADD_MAP_NODE(pmentry);
                p = strtok_r(NULL, "\n", &end_line);
        }

        mapping_file.size += sizeof(unsigned long) * 2; /* number of mappings and page size */
        printf("mapping_file.size: %d\n", mapping_file.size);


        fclose(f_smaps);
        fclose(f);

        return me_head;
}

static auxv_buff_t *linux_get_auxv(RDebug *dbg)
{
        Elf64_auxv_t auxv_entry;
        auxv_buff_t *auxv;
        int auxv_entries;
        char file[80];
        size_t size;
        FILE *f;

        auxv = NULL;
        snprintf(file, sizeof(file), "/proc/%d/auxv", dbg->pid);
        f = fopen(file, "r");
        if(f == NULL) {
                printf("File error\n");
                return NULL;
        }

        auxv_entries = 0;

        while(fread(&auxv_entry, sizeof(Elf64_auxv_t), 1, f) == 1)
                auxv_entries++;

        if(auxv_entries > 0) {
                size = auxv_entries * sizeof(Elf64_auxv_t);
                auxv = (auxv_buff_t *)malloc(sizeof(auxv_buff_t));
                auxv->size = size;
                auxv->data = malloc(auxv->size);
                fseek(f, 0, SEEK_SET);
                fread(auxv->data, auxv->size, 1, f);
        }

        return auxv;
}

Elf64_Ehdr *build_elf_hdr(unsigned int n_segments)
{
        int pad_byte;
        int ph_size;
        int ph_offset;
        Elf64_Ehdr *h;

        h = malloc(sizeof(Elf64_Ehdr));
        if(h == NULL)
                return NULL;

        ph_offset = ELF_HDR_SIZE;
        ph_size = sizeof(Elf64_Phdr);

        h->e_ident[EI_MAG0] = ELFMAG0;
        h->e_ident[EI_MAG1] = ELFMAG1;
        h->e_ident[EI_MAG2] = ELFMAG2;
        h->e_ident[EI_MAG3] = ELFMAG3;
        h->e_ident[EI_CLASS] = ELFCLASS64;     /*64bits */
        h->e_ident[EI_DATA] = ELFDATA2LSB;
        h->e_ident[EI_VERSION] = EV_CURRENT;
        h->e_ident[EI_OSABI] = ELFOSABI_NONE;
        h->e_ident[EI_ABIVERSION] = 0x0;

        for(pad_byte = EI_PAD; pad_byte < EI_NIDENT; pad_byte++)
                h->e_ident[pad_byte] = '\0';

        h->e_ident[EI_NIDENT] = EI_NIDENT;

        h->e_type = ET_CORE;                    /* CORE */
        h->e_machine = EM_X86_64;
        h->e_version = EV_CURRENT;
        h->e_entry = 0x0;
        h->e_ehsize = ELF_HDR_SIZE;
        h->e_phoff = ph_offset;                 /* Program header table's file offset */
        h->e_phentsize = ph_size; 
        h->e_phnum = n_segments + 1;            /* n_segments  + NOTE segment */
        h->e_flags = 0x0;
        /* Coredump contains no sections */
        h->e_shoff = 0x0;
        h->e_shentsize = 0x0;
        h->e_shnum = 0x0;
        h->e_shstrndx = 0x0;

        return h;
}

int get_n_mappings(linux_map_entry_t *me_head)
{
        linux_map_entry_t *p;
        int n_entries;

        for(n_entries = 0, p = me_head; p != NULL ; p = p->n)
                if((p->perms & R_MEM) || (p->perms & W_MEM))            /* We don't count maps which does not have r/w perms */
                        n_entries++;

        return n_entries;
}


int dump_elf_header(FILE *f, Elf64_Ehdr *hdr)
{
        int ret;

        ret = fwrite(hdr, sizeof(Elf64_Ehdr), 1, f);
        return ret == 0 ? 0 : 1;
}

typedef enum {
        T_PRPSINFO,
        T_PRSTATUS,
        T_FPREGSET,
        T_X86_XSTATE,
        T_SIGINFO,
        T_AUXV,
        T_FILE,
} note_t;

const char *note_name[7] =      {
                                        ".note.linux.prspinfo",
                                        ".note.linux.reg",
                                        ".note.linux.fpreg",
                                        ".note.linux.xstate",
                                        ".note.linux.siginfo",
                                        ".note.linux.auxv",
                                        ".note.linux.ntfile"
                                };

int get_nt_size(linux_map_entry_t *head)
{
        linux_map_entry_t *p;
        size_t size;
        int i;

        size = 0;
        for(p = head; p != NULL; p = p->n) {
                if(p->name && strcmp(p->name, "[vdso]") != 0
                                && strcmp(p->name, "[vsyscall]") != 0
                                && strcmp(p->name, "[vvar]") != 0
                                && strcmp(p->name, "[stack]") != 0) {
                        size += SIZE_NT_FILE_DESCSZ + p->s_name;
                }
        }

        return size;
}


void *get_nt_data(linux_map_entry_t *head, size_t *nt_file_size)
{
        char *maps_data;
        char *pp;
        linux_map_entry_t *p;
        size_t size;            /* global size */
        size_t size_nt_file;
        unsigned long long n_segments;
        unsigned long long n_pag;

        size = mapping_file.size;
        printf("get_nt_size: %d\n", size);
        n_segments = mapping_file.count;
        printf("n_segments: %d\n", n_segments);
        n_pag = 1;

        maps_data = malloc(size);
        pp = maps_data;

        memcpy(maps_data, &n_segments, sizeof(n_segments));
        memcpy(maps_data + sizeof(n_segments), &n_pag, sizeof(n_pag));
        pp += sizeof(n_segments) + sizeof(n_pag);

        for(p = head; p != NULL; p = p->n) {
                if(p->name && strcmp(p->name, "[vdso]") != 0
                                && strcmp(p->name, "[vsyscall]") != 0
                                && strcmp(p->name, "[vvar]") != 0
                                && strcmp(p->name, "[stack]") != 0) {
                        printf("get_nt_data: %s\n", p->name);

                        memcpy(pp, &p->start_addr, sizeof(p->start_addr));
                        pp += sizeof(p->start_addr);

                        memcpy(pp, &p->end_addr, sizeof(p->end_addr));
                        pp += sizeof(p->end_addr);

                        memcpy(pp, &p->offset, sizeof(p->offset));
                        pp += sizeof(p->offset);
                }
        }

        for(p = head; p != NULL; p = p->n) {
                if(p->name && strcmp(p->name, "[vdso]") != 0
                                && strcmp(p->name, "[vsyscall]") != 0
                                && strcmp(p->name, "[vvar]") != 0
                                && strcmp(p->name, "[stack]") != 0) {
			memcpy(pp, p->name, p->s_name);
                        pp += strlen(p->name) + 1;
                }
        }

        *nt_file_size = size;
        return maps_data;
}

char *build_note_section(linux_elf_note_t *sec_note, size_t *size_note_section)
{
        prpsinfo_t *prpsinfo;
        prstatus_t *prstatus;
        siginfo_t *siginfo;
        auxv_buff_t *auxv;
        elf_fpregset_t *fp_regset;
        linux_map_entry_t *maps;
        Elf64_Nhdr note_hdr;
        char *note_data;
        char *pnote_data;
        char *maps_data;
        char n_core[] = "CORE";
        char n_lnx[] = "LINUX";
        size_t size;
        size_t size_prpsinfo;
        size_t size_prstatus;
        size_t size_siginfo;
        size_t size_auxv;
        size_t size_elf_fpregset;
        size_t size_core_name;
        size_t size_nt_file;
        size_t size_nt_file_pad;
        size_t i_size_core;
        size_t size_linux;
        size_t note_hdr_size;
        int i;

        i_size_core = size_core_name = 0;
        i_size_core = sizeof(n_core) + ((4 - (sizeof(n_core) % 4)) % 4);

        for(i = 0; i < n_notes ; i++)
                size_core_name += sizeof(n_core) + ((4 - (sizeof(n_core) % 4)) % 4);

        auxv = sec_note->auxv;
        maps = sec_note->maps;

        note_hdr_size = sizeof(Elf64_Nhdr) * n_notes;

        size_prpsinfo = sizeof(prpsinfo_t) + ((4 - (sizeof(prpsinfo_t) % 4)) % 4);
        size_prstatus = sizeof(prstatus_t) + ((4 - (sizeof(prstatus_t) % 4)) % 4);
        size_siginfo = sizeof(siginfo_t) + ((4 - (sizeof(siginfo_t) % 4)) % 4);
        size_elf_fpregset = sizeof(elf_fpregset_t) + ((4 - (sizeof(elf_fpregset_t) % 4)) % 4);
        size_auxv = auxv->size + ((4 - (auxv->size % 4)) % 4);
        maps_data = get_nt_data(maps, &size_nt_file);
        size_nt_file_pad = size_nt_file + ((4 - (size_nt_file % 4)) % 4);
	
	size = 0;

        size += size_core_name;

        size += size_prpsinfo;
        printf("sizeof(prpsinfo_t) 0x%08lx\n", size_prpsinfo);

        size += size_prstatus;
        printf("sizeof(prstatus_t) 0x%08lx\n", size_prstatus);

        size += size_elf_fpregset;
        printf("sizeof(elf_fpregset_t) 0x%08lx\n", size_elf_fpregset);

        size += size_siginfo;
        printf("sizeof(siginfo_t) 0x%08lx\n", size_siginfo);

        size += size_auxv;
        printf("sizeof(auxv_t) 0x%08lx\n", size_auxv);


        size += size_nt_file_pad;
        printf("size_nt_file: 0x%08lx\n", size_nt_file_pad);

        size += note_hdr_size;

        size = size + ((4 - (size % 4)) % 4);
        printf("total_size: 0x%08lx\n", size);

        *size_note_section = size;

        /******************** Start creating note **********************/
        note_data = malloc(size);
        pnote_data = note_data;
        /* prpsinfo */
        prpsinfo = sec_note->prpsinfo;
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = sizeof(prpsinfo_t);
        note_hdr.n_type = NT_PRPSINFO;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, prpsinfo, size_prpsinfo);
        note_data += size_prpsinfo;

        /* prstatus */
	prstatus = sec_note->prstatus;
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = sizeof(prstatus_t);
        note_hdr.n_type = NT_PRSTATUS;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, prstatus, size_prstatus);
        note_data += size_prstatus;

        /* fpregset */
        fp_regset = sec_note->fp_regset;
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = sizeof(elf_fpregset_t);
        note_hdr.n_type = NT_FPREGSET;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, fp_regset, size_elf_fpregset);
        note_data += size_elf_fpregset;

        /* auxv */
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = auxv->size;
        note_hdr.n_type = NT_AUXV;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, auxv->data, size_auxv);
        note_data += size_auxv;



        /* siginfo */
        siginfo = sec_note->siginfo;
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = sizeof(siginfo_t);
        note_hdr.n_type = NT_SIGINFO;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, siginfo, size_siginfo);
	note_data += size_siginfo;


        /* nt_file */
        note_hdr.n_namesz = sizeof(n_core);
        note_hdr.n_descsz = size_nt_file;
        note_hdr.n_type = NT_FILE;
        memcpy(note_data, (void *)&note_hdr, sizeof(note_hdr));
        note_data += sizeof(note_hdr);
        memcpy(note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy(note_data, maps_data, size_nt_file_pad);
        note_data += size_nt_file_pad;

        note_data = pnote_data;

        return note_data;
}

int dump_elf_pheaders(FILE *f, linux_elf_note_t *sec_note, unsigned long offset_to_note)
{
        Elf64_Phdr phdr;
        linux_map_entry_t *me_p;
        size_t note_section_size;
        unsigned long flags;
        char *note_data;
        unsigned long offset_to_next;

        printf("offset_to_note: %ld\n", offset_to_note);
        note_data = build_note_section(sec_note, &note_section_size);
        printf("note_section_size : %d\n", note_section_size);

        /* Start with note */
        phdr.p_type = PT_NOTE;
        phdr.p_flags = PF_R;
        phdr.p_offset = offset_to_note;
        phdr.p_vaddr = 0x0;
        phdr.p_paddr = 0x0;
        phdr.p_filesz = note_section_size;
        phdr.p_memsz = 0x0;
        phdr.p_align = 0x1;
        fwrite(&phdr, sizeof(Elf64_Phdr), 1, f);

        offset_to_next = offset_to_note + note_section_size;

        /* write program headers */

        for(me_p = sec_note->maps; me_p != NULL; me_p = me_p->n) {
                if(!(me_p->perms & R_MEM) && !(me_p->perms & W_MEM))
                        continue;
                phdr.p_type = PT_LOAD;
                phdr.p_flags = me_p->perms;
                phdr.p_vaddr = me_p->start_addr;
                phdr.p_paddr = 0x0;
                phdr.p_memsz = me_p->end_addr - me_p->start_addr;
                phdr.p_filesz = me_p->anonymous == 0 ? 0 : phdr.p_memsz;
                phdr.p_offset = offset_to_next;;
                phdr.p_align = 0x1;

                offset_to_next += phdr.p_filesz == 0 ? 0 : phdr.p_filesz;

                fwrite(&phdr, sizeof(Elf64_Phdr), 1, f);
                memset(&phdr, '\0', sizeof(Elf64_Phdr));
        }

	printf("pheaders writen\n");

        fwrite(note_data, note_section_size, 1, f);
        printf("note writen\n");

        return 0;
}

	
bool linux_generate_corefile (RDebug *dbg, RBuffer *dest) {

	char *core_file = "core.oscar";
        Elf64_Ehdr *elf_hdr;
        linux_elf_note_t *sec_note;
        unsigned int n_segments;
        int ret;
        FILE *f;
	RBuffer note_buff[4096];

	sec_note = (linux_elf_note_t *)malloc(sizeof(linux_elf_note_t));
	
	/* Let's start getting elf_prpsinfo */
        sec_note->prpsinfo = linux_get_prpsinfo(dbg);             /* NT_PRPSINFO          */            /* pr_psargs missing */
        sec_note->prstatus = linux_get_prstatus(dbg);             /* NT_PRSTATUS          */            /* p->pr_cursig      */
        sec_note->fp_regset = linux_get_fp_regset(dbg);           /* NT_FPREGSET          */
        sec_note->siginfo = linux_get_siginfo(dbg);               /* NT_SIGINFO           */
                                                                  /* NT_X86_XSTATE        */
        sec_note->auxv = linux_get_auxv(dbg);                     /* NT_AUXV              */
        sec_note->maps = linux_get_mapped_files(dbg);        	  /* NT_FILE              */         /* We still need to take a look at /proc/%d/coredumpfilter */
        n_segments = get_n_mappings(sec_note->maps);

        elf_hdr = build_elf_hdr(n_segments);

        dump_elf_header(f, elf_hdr);
        dump_elf_pheaders(f, sec_note, elf_hdr->e_ehsize + (elf_hdr->e_phnum * elf_hdr->e_phentsize));
/*      dump_elf_map_content(f, sec_note->maps);        */
							
        return true;
}

/*		*/
