/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <signal.h>
#include <sys/uio.h>
#include "linux_debug.h"


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

static map_file_t mapping_file = {0,0};

static char *prpsinfo_get_fname(FILE *f) {
        char *p;
        int c;
        int pos;
	char *test;

        p = calloc(SIZE_PR_FNAME, sizeof(char));
	if (!p) return NULL;

        pos = 0;
        while ((c = fgetc(f)) != EOF && c != '\0' && pos < SIZE_PR_FNAME)
                p[pos++] = c;

        if (c == '\0')
                p[pos] = c;

        return p;
}

static char *get_basename(char *pfname, int len) {
        char *p;

        for (p = pfname + len; p != pfname ; p--) {
                if (*p == '/') return (p + 1);
	}

        return p;
}

static char *prpsinfo_get_psargs(FILE *f, char *pfname, int size_psargs) {
        char paux[ELF_PRARGSZ];
        char *p;
        int c;
        int pos;
        int bytes_left;

	p = r_mem_dup (pfname, size_psargs);
	if (!p) return NULL;

        bytes_left = strlen (pfname);
        pos = 0;
	paux[pos++] = ' ';
        while ((c = fgetc(f)) != EOF && bytes_left < (size_psargs - 1)) {
                if (c == '\0')
                        c = ' ';
                paux[pos++] = c;
                bytes_left++;
        }

        paux[pos] = '\0';
        strncat (p, paux, size_psargs - strlen (pfname) - 1);

        return p;
}

static void debug_print_prpsinfo(prpsinfo_t *p) {

        printf("prpsinfo.pr_state: %d\n", p->pr_state);
        printf("prpsinfo.pr_sname: %c\n", p->pr_sname);
        printf("prpsinfo.pr_zomb: %d\n", p->pr_zomb);
        printf("prpsinfo.pr_nice: %d\n", p->pr_nice);
        printf("prpsinfo.pr_flags: %ld\n", p->pr_flag);
        printf("prpsinfo.pr_uid: %ld\n", p->pr_uid);
        printf("prpsinfo.pr_gid: %ld\n", p->pr_gid);
        printf("prpsinfo.pr_pid: %ld\n", p->pr_pid);
        printf("prpsinfo.pr_ppid: %ld\n", p->pr_ppid);
        printf("prpsinfo.pr_pgrp: %ld\n", p->pr_pgrp);
        printf("prpsinfo.pr_sid: %ld\n", p->pr_sid);
        printf("prpsinfo.pr_fname: %s\n", p->pr_fname);
	printf("prpsinfo.pr_psargs: %s\n", p->pr_psargs);
}

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg, proc_stat_content_t *proc_data) {
        FILE *f;
        char file[128];
        long nice;
        int c;
        int pos;
	int size_file;
        pid_t mypid;
	char *test;
	char *pfname;
        char *ppsargs;
        char *basename; /* pr_fname stores just the exec, withouth the path */
	const char prog_states[] = "RSDTZW";				/* fs/binfmt_elf.c from kernel */
        prpsinfo_t *p;

	pfname = ppsargs = basename = NULL;

	p = R_NEW0 (prpsinfo_t);
	if (!p) {
		eprintf ("Couldn't allocate memory for prpsinfo_t\n");
		return NULL;
	}

        p->pr_pid = mypid = dbg->pid;

	/* Start filling pr_fname and pr_psargs */
        snprintf (file, sizeof(file), "/proc/%d/cmdline", mypid);
        f = fopen (file, "r");
        if (!f) {
                printf("Cannot open '%s' for reading\n", file);
                goto error;
        }

	test = r_file_slurp (file, &size_file);
	eprintf ("r_file_slurp: %s\n", test);
	if (!test) {
		eprintf ("r_file_slurp failed!\n");
	}

	pfname = prpsinfo_get_fname (f);
	if (!pfname) {
		eprintf ("prpsinfo_get_fname: couldn't allocate memory\n");
		fclose(f);
		goto error;
	}
	
        basename = get_basename (pfname, strlen(pfname));
        strncpy (p->pr_fname, basename, sizeof(p->pr_fname));

	ppsargs = prpsinfo_get_psargs (f, pfname, sizeof(p->pr_psargs));
	if (!ppsargs) {
		eprintf ("prpsinfo_get_psargs: couldn't allocate memory\n");
		return NULL;
	}

        strncpy (p->pr_psargs, ppsargs, sizeof(p->pr_psargs));
        free (ppsargs);
        free (pfname);

	p->pr_sname = proc_data->s_name;
	p->pr_zomb = (p->pr_sname == 'Z') ? 1 : 0;
	p->pr_state = strchr (prog_states, p->pr_sname) - prog_states;
	p->pr_ppid = proc_data->ppid;
	p->pr_pgrp = proc_data->pgrp;
	p->pr_sid = proc_data->sid;
	p->pr_flag = proc_data->flag;
	p->pr_nice = proc_data->nice;

	p->pr_uid = proc_data->uid;
	p->pr_gid = proc_data->gid;
	
	debug_print_prpsinfo(p);

        return p;

        error:
		if (f) fclose (f);
		free (p);
		free (pfname);
		free (ppsargs);

		return NULL;
}

void debug_prstatus(prstatus_t *p) {
	eprintf("\n== debug_prstatus ==\n");
	eprintf("p->pr_cursig: %d\n", p->pr_cursig);
	eprintf("p->pr_info.si_signo: %d\n", p->pr_info.si_signo);
	eprintf("p->pr_pid: %d\n", p->pr_pid);
	eprintf("p->pr_ppid: %d\n", p->pr_ppid);
	eprintf("p->pr_pgrp: %d\n", p->pr_pgrp);
	eprintf("p->pr_sid: %d\n", p->pr_sid);
	eprintf("p->pr_sigpend: %d\n", p->pr_sigpend);
	eprintf("p->pr_sighold: %d\n", p->pr_sighold);
}

static prstatus_t *linux_get_prstatus(RDebug *dbg, proc_stat_content_t *proc_data, short int signr) {
        prstatus_t *p;
	ut8 *reg_buff;
        int rbytes;
        size_t size_gp_regset;

        reg_buff = R_NEW0 (struct user_regs_struct);
	if (!reg_buff)
		return NULL;

        size_gp_regset = sizeof (elf_gregset_t);
        rbytes = linux_reg_read (dbg, R_REG_TYPE_GPR, reg_buff, size_gp_regset);
        if (rbytes != size_gp_regset) {                    /* something went wrong */
                printf("linux_get_prstatus: error in (rbytes != size_gp_regset)\n");
		goto error;
        }

	/* http://lxr.free-electrons.com/source/arch/x86/include/asm/signal.h#L24 */
	
	p = R_NEW0 (prstatus_t);
	if (!p) goto error;

	p->pr_cursig = p->pr_info.si_signo = signr;
        p->pr_pid = dbg->pid;
	p->pr_ppid = proc_data->ppid;
	p->pr_pgrp = proc_data->pgrp;
	p->pr_sid = proc_data->sid;
	p->pr_sigpend = proc_data->sigpend;
	p->pr_sighold = proc_data->sighold;

	/*
	p->pr_cutime
	p->pr_cstime
	p->pr_utime
	p->pr_stime
	*/

	/*debug_prstatus(p);*/

        memcpy (p->pr_reg, reg_buff, rbytes);

        return p;

	error:
		eprintf	("linux_get_prstatus: error\n");
		free(reg_buff);
		return NULL;
		
}

static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg) {
        elf_fpregset_t *p;
        ut8 *reg_buff;
        int rbytes;
        size_t size_fp_regset;

	reg_buff = R_NEW0 (struct user_fpregs_struct);
	if (!reg_buff)
		return NULL;

        size_fp_regset = sizeof (elf_fpregset_t);
        rbytes = linux_reg_read (dbg, R_REG_TYPE_FPU, reg_buff, size_fp_regset);
        if (rbytes != size_fp_regset) {
		printf("linux_get_fp_regset: error in (rbytes != size_gp_regset)\n");
		goto error;
	}

	p = R_NEW0 (elf_fpregset_t);
	if (!p) goto error;

        memcpy (p, reg_buff, rbytes);

        return p;

	error:
		eprintf ("linux_get_fp_regset: error\n");
		free (reg_buff);
		return NULL;
}

static siginfo_t *linux_get_siginfo(RDebug *dbg) {
	int ret;
        siginfo_t *siginfo;

	siginfo = R_NEW0 (siginfo_t);
	if (!siginfo)
		return NULL;

        ret = ptrace (PTRACE_GETSIGINFO, dbg->pid, 0, siginfo);

        if (!siginfo->si_signo) {
                free(siginfo);
                return NULL;
        }

        return siginfo;
}

static void get_map_address_space(char *pstr, ut64 *start_addr, ut64 *end_addr) {
        char *pp;

        pp = pstr;

        *start_addr = strtoul (pp, &pp, 16);
        pp++;   /*Skip '-' */
        *end_addr = strtoul (pp, &pp, 16);
}

static void get_map_perms(char *pstr, ut8 *fl_perms) {
        char *pp;
        int len;
        ut8 flags;

        len = strlen(pstr);
        flags = 0;

        pp = memchr (pstr, 'r', len);
        if (pp)
                flags |= R_MEM;

        pp = memchr (pstr, 'w', len);
        if (pp)
                flags |= W_MEM;

        pp = memchr (pstr, 'x', len);
        if (pp)
                flags |= X_MEM;

        pp = memchr (pstr, 'p', len);
        if (pp)
                flags |= P_MEM;

        pp = memchr (pstr, 's', len);
        if (pp)
                flags |= S_MEM;

        *fl_perms = flags;

        if (((flags & P_MEM) && (flags & S_MEM)) || (!(flags & R_MEM) && !(flags & W_MEM))) {
		eprintf("setting WRG_PERM\n");
                *fl_perms = WRG_PERM;
	}
}

static void get_map_offset(char *pstr, ut64 *offset) {
        char *pp;

        pp = pstr;
        *offset = strtoul (pp, &pp, 16);
}


static void get_map_name(char *pstr, char **name) {
        *name = strdup (pstr);
}

static bool has_map_deleted_part(char *name) {
	char deleted_str[] = "(deleted)";
	int len_suffx;
	int len_name;
	int ret;

	len_name = strlen (name);
	len_suffx = strlen (deleted_str);

	ret = strncmp (name + len_name - len_suffx, deleted_str, len_suffx);

	return ret ? false : true;
}
	

static bool get_anonymous_value(char *keyw) {
/*        while (!isspace (*keyw))
                keyw++; */

	keyw = strchr (keyw, ' ');

        while (isspace (*keyw))
                keyw++;

        return *keyw != '0';
}

static bool has_map_anonymous_content(FILE *f, ut64 start_addr, ut64 end_addr) {
        char identity[80];
        char buff[1024];
        char buff_tok[256];
        char *keyw;
        bool is_anonymous;

        snprintf (identity, sizeof (identity), "%08llx-%08llx", start_addr, end_addr);
        while (fgets (buff, sizeof (buff), f) != NULL) {
                if (strstr (buff, identity) != NULL) {
                        while (fgets (buff_tok, sizeof (buff_tok), f) != NULL) {
                                if ((keyw = strstr (buff_tok, "Anonymous:")) != NULL || (keyw = strstr (buff_tok, "AnonHugePages:")) != NULL) {
                                        is_anonymous = get_anonymous_value (keyw);
                                        fseek (f, 0, SEEK_SET);
                                        return is_anonymous;
                                }
                        }
                }
        }

        fseek (f, 0, SEEK_SET);
        return 0;
}

static bool is_a_kernel_mapping(char *map_name) {
	bool ret;

	if (strcmp (map_name, "[vsyscall]") == 0 ||
		strcmp (map_name, "[vvar]") == 0 ||
		strcmp (map_name, "[vdso]") == 0) {
		ret = true;
	} else {
		ret = false;
	}

	return ret;
}

static bool dump_this_map(FILE *f, ut64 start_addr, ut64 end_addr, bool file_backed, bool anonymous, ut8 perms, ut8 filter_flags) {
	char identity[80];
	char buff[1024];
	char buff_tok[256];
	char *flags_str;
	char *p;
	bool found;
	unsigned char vmflags;

	/* if the map doesn't have r/w quit right here */
	if (perms & WRG_PERM) {
		eprintf("[dump_this_map] wrong perm detected on %lx-%lx\n", start_addr, end_addr);
		return false;
	}

	eprintf ("[dump_this_map] %lx-%lx: file: %d - anonymous - %d - flags: %lx\n", start_addr, end_addr, file_backed, anonymous, filter_flags);

	snprintf (identity, sizeof(identity), "%08llx-%08llx", start_addr, end_addr);

	found = 0;
	vmflags = 0;
	flags_str = NULL;
	while (fgets (buff, sizeof (buff), f) != NULL && !found) {
                if (strstr (buff, identity) != NULL) {
                        while (fgets (buff_tok, sizeof (buff_tok), f) != NULL) {
                                if ((flags_str = strstr (buff_tok, "VmFlags:")) != NULL) {
					fseek (f, 0, SEEK_SET);
					found = true;
					break;
                                }
                        }
                }
        }
	
	if (!flags_str) {
		eprintf ("VmFlags: not found\n");
	}

	if (!flags_str)
		return true;	/* if we don't have VmFlags, just dump it. I'll fix it later on */

	flags_str = strchr (flags_str, ' ');
	
	while(*flags_str++ == ' ')
		;
	flags_str--;

	p = strtok (flags_str, " ");
	while (p) {
		eprintf ("dump_this_map: %s\n", p);
		if (strncmp (p, "sh", 2) == 0) {
			eprintf ("vmflags |= SH_FLAG\n");
			vmflags |= SH_FLAG;
		}
		if (strncmp (p, "io", 2) == 0) {
			eprintf ("vmflags |= IO_FLAG\n");
			vmflags |= IO_FLAG;
		}
		if (strncmp (p, "ht", 2) == 0) {
			eprintf ("vmflags |= HT_FLAG\n");
			vmflags |= HT_FLAG;
		}
		if (strncmp (p, "dd", 2) == 0) {
			eprintf ("vmflags |= DD_FLAG\n");
			vmflags |= DD_FLAG;
		}

		p = strtok (NULL, " ");
	}


	if (!(vmflags & SH_FLAG))
		vmflags |= PV_FLAG;
	
	eprintf ("vmflags: %u\n", vmflags);

	/* first check for dd and io flags */
	if (vmflags & DD_FLAG)
		return false;
	if (vmflags & IO_FLAG)
		return false;

	if (vmflags & HT_FLAG) {
		if ((filter_flags & MAP_HUG_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_HUG_PRIV\n");
			return true;
		}
		if (filter_flags & MAP_HUG_SHR) {
			eprintf ("filter_flags & MAP_HUG_SHR\n");
			return true;
		}
	}

	if (vmflags & SH_FLAG) {
		if (filter_flags & MAP_ANON_SHR) {
			eprintf ("filter_flags & MAP_ANON_SHR\n");
			return true;
		}
		if (filter_flags & MAP_HUG_SHR) {
			eprintf ("filter_flags & MAP_HUG_SHR\n");
			return true;
		}
	}

	if (vmflags & PV_FLAG) {	
		if ((filter_flags & MAP_ANON_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_ANON_PRIV\n");
			return true;
		}
		if ((filter_flags & MAP_HUG_PRIV) && anonymous) {
			eprintf ("filter_flags & MAP_HUG_PRIV\n");
			return true;
		}
	}
	
	if (file_backed) {
		if (filter_flags & MAP_FILE_PRIV) {
			eprintf ("filter_flags & MAP_FILE_PRIV\n");
			return true;
		}
		if (filter_flags & MAP_FILE_SHR) {
			eprintf ("filter_flags & MAP_FILE_PRIV\n");
			return true;
		}
	}

	fseek (f, 0, SEEK_SET);

	eprintf ("dump_this_map: nothing found, returning false\n");
	return false;
}
	
static linux_map_entry_t *linux_get_mapped_files(RDebug *dbg, ut8 filter_flags) {
        linux_map_entry_t *me_head, *me_tail;
        linux_map_entry_t *pmentry;
        FILE *f;
        ut64 start_addr;
        ut64 end_addr;
        ut64 offset;
	ut64 inode;
        ut8 flag_perm;
        pid_t mypid;
	int len_name;
	bool is_anonymous;
	bool file_backed;
	bool ret;
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

        snprintf (file, sizeof (file), "/proc/%d/smaps", mypid);
        f_smaps = fopen (file, "r");
	if (!f_smaps)
		return NULL;

        snprintf (file, sizeof (file), "/proc/%d/maps", mypid);
        f = fopen (file, "r");
        if (!f) {
                printf ("Cannot open '%s' for reading\n", file);
		fclose (f_smaps);
                return NULL;
        }

        fread (buff, sizeof (buff), 1, f);

        p = strtok_r (buff, "\n", &end_line);
        while (p != NULL) {
                char *pp;
                pp = strtok_r (p, " ", &end_token);
                maps_current = ADDR;
		file_backed = false;

                while(pp != NULL) {
			switch (maps_current) {
                        case ADDR:
                        	get_map_address_space (pp, &start_addr, &end_addr);
				break;
			case PERM:
				get_map_perms (pp, &flag_perm);
				break;
			case OFFSET:
				get_map_offset (pp, &offset);
				break;
			case DEV:
				maps_current++;
				pp = strtok_r (NULL, " ", &end_token);
			case INODE:
				maps_current++;
				pp = strtok_r (NULL, " ", &end_token);
			case NAME:
                        	if (pp)   /* Has this map a name? */
                                	get_map_name (pp, &name);
				break;
                        }
                        maps_current++;
                        pp = strtok_r (NULL, " ", &end_token);
                }

		if (start_addr == 0 || end_addr == 0) {
                        break;
		}

		pmentry = R_NEW0 (linux_map_entry_t);
		if (!pmentry) goto error;
                pmentry->start_addr = start_addr;
                pmentry->end_addr = end_addr;
                pmentry->perms = flag_perm;
                pmentry->offset = offset;
		pmentry->name = NULL;
                pmentry->inode = 0;

		if (name) {
                        pmentry->name = strdup (name);
			len_name = strlen (pmentry->name) + 1;
                        free (name);
                        name = NULL;
                }

		eprintf ("\n\n[checking] %llx-%llx\n", pmentry->start_addr, pmentry->end_addr);

		/* Check if the map comes from the kernel (vsyscall, vvar, vdso) (they are always dumped, but not vvar) */
		if (pmentry->name && is_a_kernel_mapping (pmentry->name)) {
			pmentry->anonymous = pmentry->kernel_mapping = true;
			eprintf("kernel_mapping: %d\n", pmentry->anonymous);
		} else {
			/* Check if map has anonymous content by checking Anonymous and AnonHugePages */
			is_anonymous = has_map_anonymous_content (f_smaps, start_addr, end_addr);
			eprintf ("has_map_anonymous_content: %d\n", is_anonymous);
			/* Check if pathname has a (deleted) part. Actually what kernel does is: file_inode(vma->vm_file)->i_nlink == 0 */
			if (!is_anonymous && pmentry->name) {
				is_anonymous = has_map_deleted_part (pmentry->name);
				eprintf("has_map_deleted_part called: %d\n", is_anonymous);
			}
			pmentry->anonymous = is_anonymous;
		}

		if (!pmentry->kernel_mapping) {
			if (pmentry->name && strcmp (pmentry->name, "[stack]")) {
				if (!pmentry->kernel_mapping)
					pmentry->file_backed = true;
				eprintf (":%s - kernel : %d , file :%d\n", pmentry->name, pmentry->kernel_mapping, pmentry->file_backed);
			}
			
			pmentry->dumpeable = dump_this_map (f_smaps, pmentry->start_addr, pmentry->end_addr, pmentry->file_backed, pmentry->anonymous, pmentry->perms, filter_flags);
			eprintf (" %llx-%llx - anonymous: %d, kernel_mapping: %d, file_backed: %d, dumpeable: %d\n\n", 
													pmentry->start_addr, 
													pmentry->end_addr, 
													pmentry->anonymous, 
													pmentry->kernel_mapping, 
													pmentry->file_backed, 
													pmentry->dumpeable);

			if (pmentry->file_backed) {
				eprintf ("pmentry->name adding: %s as a SIZE_NT_FILE_DESCSZ\n", pmentry->name);
				mapping_file.size += SIZE_NT_FILE_DESCSZ + len_name;
				mapping_file.count++;
			}
		} else {
			/* kernel mappings are always dumped */
			pmentry->dumpeable = 1;
		}
			
                ADD_MAP_NODE (pmentry);
                p = strtok_r (NULL, "\n", &end_line);
        }

        mapping_file.size += sizeof (unsigned long) * 2; /* number of mappings and page size */
        eprintf ("mapping_file.size: %d\n", mapping_file.size);
	
	if (f_smaps)
	        fclose (f_smaps);
	if (f)
	        fclose (f);

        return me_head;

	error:
		fclose (f);
		fclose (f_smaps);
		clean_maps (me_head);
		return NULL;
	return NULL;
}

static auxv_buff_t *linux_get_auxv(RDebug *dbg) {
        Elf64_auxv_t auxv_entry;
        auxv_buff_t *auxv;
        int auxv_entries;
        char file[80];
        size_t size;
        FILE *f;

        auxv = NULL;
        snprintf (file, sizeof (file), "/proc/%d/auxv", dbg->pid);
        f = fopen (file, "r");
        if (!f) {
		printf("linux_get_auxv: file error\n");
                return NULL;
        }

        auxv_entries = 0;

        while (fread (&auxv_entry, sizeof (Elf64_auxv_t), 1, f) == 1)
                auxv_entries++;

        if (auxv_entries > 0) {
                size = auxv_entries * sizeof (Elf64_auxv_t);
		auxv = R_NEW0 (auxv_buff_t);
		if (!auxv) {
			fclose (f);
			return NULL;
		}
                auxv->size = size;
                auxv->data = malloc (auxv->size);
		if (!auxv->data) {
			fclose (f);
			free (auxv);
			return NULL;
		}
                fseek (f, 0, SEEK_SET);
                fread (auxv->data, auxv->size, 1, f);
        }

        return auxv;
}

static Elf64_Ehdr *build_elf_hdr(int n_segments) {
        int pad_byte;
        int ph_size;
        int ph_offset;
        Elf64_Ehdr *h;

	h = R_NEW0 (Elf64_Ehdr);
        if (!h)
                return NULL;

        ph_offset = ELF_HDR_SIZE;
        ph_size = sizeof (Elf64_Phdr);

        h->e_ident[EI_MAG0] = ELFMAG0;
        h->e_ident[EI_MAG1] = ELFMAG1;
        h->e_ident[EI_MAG2] = ELFMAG2;
        h->e_ident[EI_MAG3] = ELFMAG3;
        h->e_ident[EI_CLASS] = ELFCLASS64;     /*64bits */
        h->e_ident[EI_DATA] = ELFDATA2LSB;
        h->e_ident[EI_VERSION] = EV_CURRENT;
        h->e_ident[EI_OSABI] = ELFOSABI_NONE;
        h->e_ident[EI_ABIVERSION] = 0x0;

        for (pad_byte = EI_PAD; pad_byte < EI_NIDENT; pad_byte++)
                h->e_ident[pad_byte] = '\0';

        h->e_ident[EI_NIDENT] = EI_NIDENT;

        h->e_type = ET_CORE;                    /* CORE */
        h->e_machine = EM_X86_64;
        h->e_version = EV_CURRENT;
        h->e_entry = 0x0;
        h->e_ehsize = ELF_HDR_SIZE;
        h->e_phoff = ph_offset;                 /* Program header table's file offset */
        h->e_phentsize = ph_size; 
        h->e_phnum = (n_segments + 1) > PN_XNUM ? PN_XNUM : n_segments + 1;            /* n_segments  + NOTE segment */
        h->e_flags = 0x0;
        /* Coredump contains no sections */
        h->e_shoff = 0x0;
        h->e_shentsize = 0x0;
        h->e_shnum = 0x0;
        h->e_shstrndx = 0x0;

        return h;
}

static int get_n_mappings(linux_map_entry_t *me_head) {
        linux_map_entry_t *p;
        int n_entries;

        for (n_entries = 0, p = me_head; p != NULL ; p = p->n)
                if ((p->perms & R_MEM) || (p->perms & W_MEM))            /* We don't count maps which does not have r/w perms */
                        n_entries++;

        return n_entries;
}


static bool dump_elf_header(RBuffer *dest, Elf64_Ehdr *hdr) {
        bool ret;

	ret = r_buf_append_bytes (dest, (const ut8*)hdr, hdr->e_ehsize);
	if (ret != true) {
		perror ("dump_elf_header: error");
	}

        return ret;
}


static void *get_nt_data(linux_map_entry_t *head, size_t *nt_file_size) {
        char *maps_data;
        char *pp;
        linux_map_entry_t *p;
        size_t size;            /* global size */
        unsigned long long n_segments;
        unsigned long long n_pag;

        size = mapping_file.size;
        eprintf ("get_nt_size: %ld\n", size);
        n_segments = mapping_file.count;
        eprintf ("n_segments: %lld\n", n_segments);
        n_pag = 1;

        maps_data = malloc (size);
	if (!maps_data)
		return NULL;

        pp = maps_data;

        memcpy (maps_data, &n_segments, sizeof (n_segments));
        memcpy (maps_data + sizeof (n_segments), &n_pag, sizeof (n_pag));
        pp += sizeof (n_segments) + sizeof (n_pag);

        for (p = head; p != NULL; p = p->n) {
                if (p->name && strcmp (p->name, "[vdso]") != 0
                                && strcmp (p->name, "[vsyscall]") != 0
                                && strcmp (p->name, "[vvar]") != 0
                                && strcmp (p->name, "[stack]") != 0) {
                        eprintf ("get_nt_data: %s\n", p->name);

                        memcpy (pp, &p->start_addr, sizeof(p->start_addr));
                        pp += sizeof (p->start_addr);

                        memcpy (pp, &p->end_addr, sizeof(p->end_addr));
                        pp += sizeof (p->end_addr);

                        memcpy (pp, &p->offset, sizeof(p->offset));
                        pp += sizeof (p->offset);
                }
        }
        for (p = head; p != NULL; p = p->n) {
                if (p->name && strcmp (p->name, "[vdso]") != 0
                                && strcmp (p->name, "[vsyscall]") != 0
                                && strcmp (p->name, "[vvar]") != 0
                                && strcmp (p->name, "[stack]") != 0) {
			eprintf ("size - (pp - maps_data): %d\n", size - (pp - maps_data));
			strncpy (pp, p->name, size - (pp - maps_data));
                        pp += strlen (p->name) + 1;
                }
        }

        *nt_file_size = size;
        return maps_data;
}

static const ut8 *build_note_section(linux_elf_note_t *sec_note, size_t *size_note_section) {
        prpsinfo_t *prpsinfo;
        prstatus_t *prstatus;
        siginfo_t *siginfo;
        auxv_buff_t *auxv;
        elf_fpregset_t *fp_regset;
        linux_map_entry_t *maps;
        Elf64_Nhdr note_hdr;
        ut8 *note_data;
        ut8 *pnote_data;
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
        size_t note_hdr_size;
        int i;

        i_size_core = size_core_name = 0;
        i_size_core = sizeof (n_core) + ((4 - (sizeof (n_core) % 4)) % 4);

        for (i = 0; i < n_notes ; i++)
                size_core_name += sizeof (n_core) + ((4 - (sizeof (n_core) % 4)) % 4);

        auxv = sec_note->auxv;
        maps = sec_note->maps;

        note_hdr_size = sizeof (Elf64_Nhdr) * n_notes;

        size_prpsinfo = sizeof (prpsinfo_t) + ((4 - (sizeof (prpsinfo_t) % 4)) % 4);
        size_prstatus = sizeof(prstatus_t) + ((4 - (sizeof (prstatus_t) % 4)) % 4);
        size_siginfo = sizeof (siginfo_t) + ((4 - (sizeof (siginfo_t) % 4)) % 4);
        size_elf_fpregset = sizeof (elf_fpregset_t) + ((4 - (sizeof (elf_fpregset_t) % 4)) % 4);
        size_auxv = auxv->size + ((4 - (auxv->size % 4)) % 4);
        maps_data = get_nt_data (maps, &size_nt_file);
	if (!maps_data)
		return NULL;

        size_nt_file_pad = size_nt_file + ((4 - (size_nt_file % 4)) % 4);
	
	size = 0;

        size += size_core_name;

        size += size_prpsinfo;
        eprintf ("sizeof(prpsinfo_t) 0x%08lx\n", size_prpsinfo);

        size += size_prstatus;
        eprintf ("sizeof(prstatus_t) 0x%08lx\n", size_prstatus);

        size += size_elf_fpregset;
        eprintf ("sizeof(elf_fpregset_t) 0x%08lx\n", size_elf_fpregset);

        size += size_siginfo;
        eprintf ("sizeof(siginfo_t) 0x%08lx\n", size_siginfo);

        size += size_auxv;
        eprintf ("sizeof(auxv_t) 0x%08lx\n", size_auxv);

        size += size_nt_file_pad;
        eprintf ("size_nt_file: 0x%08lx\n", size_nt_file_pad);

        size += note_hdr_size;

        size = size + ((4 - (size % 4)) % 4);
        eprintf ("total_size: 0x%08lx\n", size);

        *size_note_section = size;

        /******************** Start creating note **********************/
        note_data = malloc (size);
	if (!note_data) {
		free(maps_data);
		return NULL;
	}

        pnote_data = note_data;
        /* prpsinfo */
        prpsinfo = sec_note->prpsinfo;
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = sizeof (prpsinfo_t);
        note_hdr.n_type = NT_PRPSINFO;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, prpsinfo, size_prpsinfo);
        note_data += size_prpsinfo;

        /* prstatus */
	prstatus = sec_note->prstatus;
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = sizeof (prstatus_t);
        note_hdr.n_type = NT_PRSTATUS;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, prstatus, size_prstatus);
        note_data += size_prstatus;

        /* fpregset */
        fp_regset = sec_note->fp_regset;
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = sizeof (elf_fpregset_t);
        note_hdr.n_type = NT_FPREGSET;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, fp_regset, size_elf_fpregset);
        note_data += size_elf_fpregset;

        /* auxv */
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = auxv->size;
        note_hdr.n_type = NT_AUXV;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, auxv->data, size_auxv);
        note_data += size_auxv;



        /* siginfo */
        siginfo = sec_note->siginfo;
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = sizeof (siginfo_t);
        note_hdr.n_type = NT_SIGINFO;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, siginfo, size_siginfo);
	note_data += size_siginfo;


        /* nt_file */
        note_hdr.n_namesz = sizeof (n_core);
        note_hdr.n_descsz = size_nt_file;
        note_hdr.n_type = NT_FILE;
        memcpy (note_data, (void *)&note_hdr, sizeof (note_hdr));
        note_data += sizeof (note_hdr);
        memcpy (note_data, n_core, i_size_core);
        note_data += i_size_core;
        memcpy (note_data, maps_data, size_nt_file_pad);
        note_data += size_nt_file_pad;

        note_data = pnote_data;

        return note_data;
}

static bool dump_elf_pheaders(RBuffer *dest, linux_elf_note_t *sec_note, st64 *offset) {
        Elf64_Phdr phdr;
        linux_map_entry_t *me_p;
        size_t note_section_size;
        ut8 *note_data;
	bool ret;
        st64 offset_to_next;

        eprintf ("offset_to_note: %ld\n", *offset);

        note_data = build_note_section (sec_note, &note_section_size);
	if (!note_data)
		return false;

        eprintf ("note_section_size : %ld\n", note_section_size);

        /* Start with note */
        phdr.p_type = PT_NOTE;
        phdr.p_flags = PF_R;
        phdr.p_offset = *offset;
        phdr.p_vaddr = 0x0;
        phdr.p_paddr = 0x0;
        phdr.p_filesz = note_section_size;
        phdr.p_memsz = 0x0;
        phdr.p_align = 0x1;

	ret = r_buf_append_bytes (dest, (const ut8 *)&phdr, sizeof (Elf64_Phdr));
	if (ret != true) {
		printf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
		free (note_data);
		return false;
    	}

        offset_to_next = *offset + note_section_size;

        /* write program headers */

        for (me_p = sec_note->maps; me_p != NULL; me_p = me_p->n) {
                if (!(me_p->perms & R_MEM) && !(me_p->perms & W_MEM))
                        continue;
                phdr.p_type = PT_LOAD;
                phdr.p_flags = me_p->perms;
                phdr.p_vaddr = me_p->start_addr;
                phdr.p_paddr = 0x0;
                phdr.p_memsz = me_p->end_addr - me_p->start_addr;
                phdr.p_filesz = me_p->dumpeable == 0 ? 0 : phdr.p_memsz;
                phdr.p_offset = offset_to_next;
                phdr.p_align = 0x1;

                offset_to_next += phdr.p_filesz == 0 ? 0 : phdr.p_filesz;

		ret = r_buf_append_bytes (dest, (const ut8*)&phdr, sizeof (Elf64_Phdr));
		if (!ret) {
			printf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
			free (note_data);
			return false;
		}

                memset (&phdr, '\0', sizeof(Elf64_Phdr));
        }

	*offset = offset_to_next;
	eprintf ("pheaders writen\n");

	ret = r_buf_append_bytes (dest, (const ut8*)note_data, note_section_size);
	if (!ret) {
		printf ("dump_elf_pheaders: r_buf_append_bytes error!\n");
		free (note_data);
		return false;
	}

        eprintf ("note writen\n");

        return true;
}


static void show_maps(linux_map_entry_t *head) {
        linux_map_entry_t *p;

        eprintf ("SHOW MAPS ===================\n");
        for (p = head; p ; p = p->n) {
                if (p->name)
                        eprintf ("p->name: %s\n", p->name);

                eprintf ("p->start_addr - %lx, p->end_addr - %lx\n", p->start_addr, p->end_addr);
        }
        eprintf ("SHOW MAPS ===================\n");
}

static bool dump_elf_map_content(RBuffer *dest, linux_map_entry_t *head, pid_t pid) {
        linux_map_entry_t *p;
        struct iovec local;
        struct iovec remote;
        char *map_content;
        size_t size;
        size_t rbytes;

        for (p = head; p != NULL ; p = p->n) {

                eprintf ("\n\nTrying to dump: %p - %p\n", p->name, p->start_addr);

		if (p->dumpeable) {

			size = p->end_addr - p->start_addr;
			map_content = malloc (size);
			if (map_content == NULL) {
				printf ("dump_elf_map_content: map_content == NULL\n");
 	       			return false;
 	       		}

			eprintf ("p->name: %s - %p to %p - size: %d\n", p->name, p->start_addr, map_content, size);

			local.iov_base = (void *)map_content;
			local.iov_len = size;

			remote.iov_base = (void *)p->start_addr;
			remote.iov_len = size;

			rbytes = process_vm_readv (pid, &local, 1, &remote, 1, 0);
			eprintf ("dump_elf_map_content: rbytes: %ld\n", rbytes);

			if (rbytes != size) {
				printf ("dump_elf_map_content: size not equal\n");
				perror ("process_vm_readv");
			} else {
				r_buf_append_bytes (dest, (const ut8*)map_content, size);
			}

			free (map_content);
		}
        }

	return true;
}

static void print_p(proc_stat_content_t *p) {
        eprintf ("p->ppid: %d\n", p->ppid);
        eprintf ("p->pgrp: %d\n", p->pgrp);
        eprintf ("p->sid: %d\n", p->sid);
        eprintf ("p->s_name: %c\n", p->s_name);
        eprintf ("p->flags: %ld\n", p->flag);
        eprintf ("p->flags: %ld\n", p->flag);
        eprintf ("p->utime: %ld\n", p->utime);
        eprintf ("p->stime: %ld\n", p->stime);
        eprintf ("p->cutime: %ld\n", p->cutime);
        eprintf ("p->cstime: %ld\n", p->cstime);
        eprintf ("p->nice: %ld\n", p->nice);
        eprintf ("p->num_threads: %u\n", p->num_threads);
        eprintf ("p->sigpend: %ld\n", p->sigpend);
        eprintf ("p->sighold: %ld\n", p->sighold);
        eprintf ("p->uid: %u\n", p->uid);
        eprintf ("p->gid: %u\n", p->gid);
        eprintf ("p->coredump_filter: %lx\n", p->coredump_filter);
}

static proc_stat_content_t *get_proc_content(RDebug *dbg) {
        FILE *f;
        int pos;
        int c;
        char file[128];
        char buff[4096];
        char s_sigpend[] = "SigPnd";
        char s_sighold[] = "SigBlk";
        char *temp_p_uid;
        char *temp_p_gid;
        char *p_uid;
        char *p_gid;
        char *temp_p_sigpend;
        char *temp_p_sighold;
        char *p_sigpend;
        char *p_sighold;
	unsigned char filter_flags;
        proc_stat_content_t *p;

        snprintf (file, sizeof (file), "/proc/%d/stat", dbg->pid);
        eprintf ("file: %s\n", file);
        f = fopen (file, "r");

        if (!f) {
                printf ("get_proc_stat: error file\n");
                return NULL;
        }

	p = R_NEW0 (proc_stat_content_t);
	if(!p) {
		fclose (f);
		return NULL;
	}

        pos = 0;
        while ((c = fgetc(f)) != EOF && c!= '\n' && pos < sizeof (buff))
                buff[pos++] = c;

        buff[pos] = '\0';

        /* /proc/[pid]/stat */
        sscanf (buff, "%d %*s %c %d %d %d %*d %*d %u %*lu %*lu %*lu %*lu %lu %lu %ld %ld %*ld %ld %ld",   &p->pid,
                                                                                                        &p->s_name,
                                                                                                        &p->ppid,
                                                                                                        &p->pgrp,
                                                                                                        &p->sid,
                                                                                                        &p->flag,
													&p->utime,
													&p->stime,
													&p->cutime,
													&p->cstime,
                                                                                                        &p->nice,
                                                                                                        &p->num_threads);

	fclose (f);
        /* /proc/[pid]/status for uid, gid, sigpend and sighold */

        snprintf (file, sizeof(file), "/proc/%d/status", dbg->pid);

        f = fopen (file, "r");
        if (!f) {
		printf ("get_proc_stat: error file\n");
		free (p);
		return NULL;
        }

        pos = 0;
        while ((c = fgetc(f)) != EOF && pos < sizeof(buff))
                buff[pos++] = c;
        buff[pos] = '\0';

        temp_p_sigpend = strstr (buff, s_sigpend);
        temp_p_sighold = strstr (buff, s_sighold);

        /* sigpend */
        while (!isdigit (*temp_p_sigpend++))
                ;

        p_sigpend = temp_p_sigpend-1;

        while (isdigit (*temp_p_sigpend++))
                ;

	p_sigpend[temp_p_sigpend-p_sigpend-1] = '\0';


        /* sighold */
        while (!isdigit (*temp_p_sighold++))
                ;

        p_sighold = temp_p_sighold-1;

        while (isdigit (*temp_p_sighold++))
                ;

        p_sighold[temp_p_sighold-p_sighold-1] = '\0';

        p->sigpend = atol (p_sigpend);
        p->sighold = atol (p_sighold);



        /***************************/
        temp_p_uid = strstr (buff, "Uid:");
        temp_p_gid = strstr (buff, "Gid:");

        while (!isdigit (*temp_p_uid++))
                ;
        p_uid = temp_p_uid-1;

        while (isdigit (*temp_p_uid++))
                ;
        p_uid[temp_p_uid-p_uid-1] = '\0';


        /* Do the same for Gid */
        while (!isdigit (*temp_p_gid++))
                ;
        p_gid = temp_p_gid-1;

        while (isdigit (*temp_p_gid++))
                ;
        p_gid[temp_p_gid-p_gid-1] = '\0';


        p->uid = atoi (p_uid);
        p->gid = atoi (p_gid);

	/* Check the coredump_filter value */
	snprintf (file, sizeof (file), "/proc/%d/coredump_filter", dbg->pid);
        f = fopen (file, "r");
	memset (buff, '\0', sizeof (buff));
	pos = 0;
        while ((c = fgetc(f)) != EOF && c!= '\n' && pos < sizeof (buff))
                buff[pos++] = c;

        buff[pos] = '\0';

	sscanf (buff, "%hx", &filter_flags);
	p->coredump_filter = filter_flags;

	eprintf ("p->coredump_filter: %lx\n", p->coredump_filter);

        return p;
}

static void clean_maps(linux_map_entry_t *h) {
	linux_map_entry_t *p;
	linux_map_entry_t *aux;

	eprintf("clean_maps\n");
	p = h;
	while (p) {
		aux = p;
		p = p->n;
		free (aux);
	}
}
		

static void may_clean_all(linux_elf_note_t *sec_note, proc_stat_content_t *proc_data, Elf64_Ehdr *elf_hdr) {
	if (sec_note->prpsinfo)
		free (sec_note->prpsinfo);
	if (sec_note->siginfo)
		free (sec_note->siginfo);
	if (sec_note->fp_regset)
		free (sec_note->fp_regset);
	if (sec_note->prstatus)
		free (sec_note->prstatus);
	if (sec_note->auxv)
		free (sec_note->auxv);
	if (sec_note->maps)
		clean_maps (sec_note->maps);
	if (sec_note)
		free (sec_note);
	if (proc_data)
		free (proc_data);
	if(elf_hdr)
		free (elf_hdr);
}

static Elf64_Shdr *get_extra_sectionhdr(Elf64_Ehdr *elf_hdr, st64 offset, int n_segments) {
	Elf64_Shdr *shdr;

	eprintf ("get_extra_sectionhdr\n");

	shdr = R_NEW0 (Elf64_Shdr);
	if (!shdr) return NULL;
	
	elf_hdr->e_shoff = offset;
	elf_hdr->e_shentsize = sizeof (shdr);
	elf_hdr->e_shnum = 1;
	elf_hdr->e_shstrndx = SHN_UNDEF;

	shdr->sh_type = SHT_NULL;
	shdr->sh_size = elf_hdr->e_shnum;
	shdr->sh_link = elf_hdr->e_shstrndx;
	shdr->sh_info = n_segments + 1;

	return shdr;
}
	
static bool dump_elf_sheader_pxnum(RBuffer *dest, Elf64_Shdr *shdr) {
	return r_buf_append_bytes (dest, (const ut8 *)shdr, sizeof (*shdr));
}
	
bool linux_generate_corefile (RDebug *dbg, RBuffer *dest) {
        Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *shdr_pxnum;
	proc_stat_content_t *proc_data;
        linux_elf_note_t *sec_note;
	ut32 hdr_size;
	st64 offset;
        int n_segments;
        bool ret;
	bool is_error;

	elf_hdr = proc_data = sec_note = NULL;

	is_error = false;
	sec_note = R_NEW0 (linux_elf_note_t);
	if (!sec_note)
		return false;

	proc_data = get_proc_content (dbg);
	if (!proc_data)
		return false;

	print_p (proc_data);

	/* Let's start getting elf_prpsinfo */
        sec_note->prpsinfo = linux_get_prpsinfo (dbg, proc_data);             		/* NT_PRPSINFO          */ 
	if (!sec_note->prpsinfo) {
		is_error = true;
		goto cleanup;
	}

        sec_note->siginfo = linux_get_siginfo (dbg);               			/* NT_SIGINFO           */
	if (!sec_note->siginfo) {
		is_error = true;
		goto cleanup;
	}

        sec_note->fp_regset = linux_get_fp_regset (dbg);           			/* NT_FPREGSET          */
	if (!sec_note->fp_regset) {
		is_error = true;
		goto cleanup;
	}

        sec_note->prstatus = linux_get_prstatus (dbg, 
						proc_data,
						sec_note->siginfo->si_signo);		/* NT_PRSTATUS          */
	if (!sec_note->prstatus) {
		is_error = true;
		goto cleanup;
	}
                                                                  			/* NT_X86_XSTATE        */		/* stil missing */
        sec_note->auxv = linux_get_auxv (dbg);                     			/* NT_AUXV              */
	if (!sec_note->auxv) {
		is_error = true;
		goto cleanup;
	}

        sec_note->maps = linux_get_mapped_files (dbg, proc_data->coredump_filter);	/* NT_FILE              */
	if (!sec_note->maps) {
		is_error = true;
		goto cleanup;
	}

        n_segments = get_n_mappings (sec_note->maps);

	show_maps (sec_note->maps);

	elf_hdr = build_elf_hdr (n_segments);
	if (!elf_hdr) {
		is_error = true;
		goto cleanup;
	}

	if (elf_hdr->e_phnum == PN_XNUM)
		shdr_pxnum = get_extra_sectionhdr (elf_hdr, offset, n_segments);

	hdr_size = (proc_data->coredump_filter & MAP_ELF_HDR) ? elf_hdr->e_ehsize : 0;

	if (hdr_size)
		ret = dump_elf_header (dest, elf_hdr);

	offset = hdr_size + (elf_hdr->e_phnum * elf_hdr->e_phentsize);
	
	/* Write to file */
        ret = dump_elf_pheaders (dest, sec_note, &offset);
      	ret = dump_elf_map_content (dest, sec_note->maps, dbg->pid);
	if (elf_hdr->e_phnum == PN_XNUM)
		ret = dump_elf_sheader_pxnum(dest, shdr_pxnum);

	cleanup:
		may_clean_all (sec_note, proc_data, elf_hdr);
		
							
        return is_error == false;

}

/*		*/
