/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_debug.h>

#if __linux__ || __BSD__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

typedef struct {
	int pid;
	int tid;
	int fd;
	int opid;
} RIOPtrace;
#define RIOPTRACE_OPID(x) (((RIOPtrace*)x->data)->opid)
#define RIOPTRACE_PID(x) (((RIOPtrace*)x->data)->pid)
#define RIOPTRACE_FD(x) (((RIOPtrace*)x->data)->fd)
static void open_pidmem (RIOPtrace *iop);

#undef R_IO_NFDS
#define R_IO_NFDS 2
#ifndef __ANDROID__
extern int errno;
#endif

#if 0
procpidmem is buggy.. running this sometimes results in ffff

	while : ; do r2 -qc 'oo;x' -d ls ; done
#endif
#define USE_PROC_PID_MEM 0

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid (pid, &st, 0) != -1);
}

#if __OpenBSD__ || __KFBSD__
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, (pid_t)(x), (caddr_t)(y), 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, (pid_t)(x), (caddr_t)(y), (int)(size_t)(z))
typedef int ptrace_word;   // int ptrace(int request, pid_t pid, caddr_t addr, int data);
#else
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, x, y, 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, x, y, z)
typedef size_t ptrace_word; // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
// XXX. using int read fails on some addresses
// XXX. using long here breaks 'w AAAABBBBCCCCDDDD' in r2 -d
#endif

static int debug_os_read_at(int pid, ut32 *buf, int sz, ut64 addr) {
	ut32 words = sz / sizeof (ut32);
	ut32 last = sz % sizeof (ut32);
	ut32 x, lr, *at = (ut32*)(size_t)addr;
	if (sz<1 || addr==UT64_MAX)
		return -1;
	for (x=0; x<words; x++)
		buf[x] = (ut32)debug_read_raw (pid, (void*)(at++));
	if (last) {
		lr = (ut32)debug_read_raw (pid, at);
		memcpy (buf+x, &lr, last) ;
	}
	return sz;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
#if USE_PROC_PID_MEM
	int ret, fd;
#endif
	ut64 addr = io->off;
	if (!desc || !desc->data)
		return -1;
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	/* reopen procpidmem if necessary */
#if USE_PROC_PID_MEM
	fd = RIOPTRACE_FD (desc);
	if (RIOPTRACE_PID(desc) != RIOPTRACE_OPID(desc)) {
		if (fd != -1)
			close (fd);
		open_pidmem ((RIOPtrace*)desc->data);
		fd = RIOPTRACE_FD (desc);
		RIOPTRACE_OPID(desc) = RIOPTRACE_PID(desc);
	}
	// /proc/pid/mem fails on latest linux
	if (fd != -1) {
		ret = lseek (fd, addr, SEEK_SET);
		if (ret >=0) {
			ret = read (fd, buf, len);
			// Workaround for the buggy Debian Wheeze's /proc/pid/mem
			if (ret != -1) return ret;
		}
	}
#endif
	return debug_os_read_at (RIOPTRACE_PID (desc), (ut32*)buf, len, addr);
}

static int ptrace_write_at(int pid, const ut8 *pbuf, int sz, ut64 addr) {
	ptrace_word *buf = (ptrace_word*)pbuf;
	ut32 words = sz / sizeof (ptrace_word);
	ut32 last = sz % sizeof (ptrace_word);
	ptrace_word x, *at = (ptrace_word *)(size_t)addr;
	ptrace_word lr;
	if (sz < 1 || addr == UT64_MAX) {
		return -1;
	}
	for (x = 0; x < words; x++) {
		int rc = debug_write_raw (pid, at++, buf[x]); //((ut32*)(at)), buf[x]);
		if (rc) {
			return -1;
		}
	}
	if (last) {
		lr = debug_read_raw (pid, (void*)at);
		memcpy (&lr, buf + x, last);
		if (debug_write_raw (pid, (void*)at, lr)) {
			return sz - last;
		}
	}
	return sz;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (!fd || !fd->data) {
		return -1;
	}
	return ptrace_write_at (RIOPTRACE_PID (fd), buf, len, io->off);
}

static void open_pidmem (RIOPtrace *iop) {
#if USE_PROC_PID_MEM
	char pidmem[32];
	snprintf (pidmem, sizeof (pidmem), "/proc/%d/mem", iop->pid);
	iop->fd = open (pidmem, O_RDWR);
	if (iop->fd == -1)
		iop->fd = open (pidmem, O_RDONLY);
#if 0
	if (iop->fd == -1)
		eprintf ("Warning: Cannot open /proc/%d/mem. "
			"Fallback to ptrace io.\n", iop->pid);
#endif
#else
	iop->fd = -1;
#endif
}

static void close_pidmem(RIOPtrace *iop) {
	if (iop->fd != -1) {
		close (iop->fd);
		iop->fd = -1;
	}
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	if (!strncmp (file, "ptrace://", 9)) {
		return true;
	}
	if (!strncmp (file, "attach://", 9)) {
		return true;
	}
	return false;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *desc = NULL;
	int ret = -1;
	if (__plugin_open (io, file,0)) {
		int pid = atoi (file+9);
		ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
		if (file[0]=='p')  //ptrace
			ret = 0;
		else if (ret == -1) {
#ifdef __ANDROID__
			eprintf ("ptrace_attach: Operation not permitted\n");
#else
			switch (errno) {
			case EPERM:
				ret = pid;
				eprintf ("ptrace_attach: Operation not permitted\n");
				break;
			case EINVAL:
				perror ("ptrace: Cannot attach");
				eprintf ("ERRNO: %d (EINVAL)\n", errno);
				break;
			}
#endif
		} else if (__waitpid (pid)) {
			ret = pid;
		} else eprintf ("Error in waitpid\n");
		if (ret != -1) {
			RIOPtrace *riop = R_NEW0 (RIOPtrace);
			if (!riop) return NULL;
			riop->pid = riop->tid = pid;
			open_pidmem (riop);
			desc = r_io_desc_new (io, &r_io_plugin_ptrace, file, rw | R_IO_EXEC, mode, riop);
		}
	}
	return desc;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case 0: // abs
		io->off = offset;
		break;
	case 1: // cur
		io->off += (int)offset;
		break;
	case 2: // end
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __close(RIODesc *desc) {
	int pid, fd;
	if (!desc || !desc->data)
		return -1;
	pid = RIOPTRACE_PID (desc);
	fd = RIOPTRACE_FD (desc);
	if (fd!=-1) close (fd);
	free (desc->data);
	desc->data = NULL;
	return ptrace (PTRACE_DETACH, pid, 0, 0);
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOPtrace *iop = (RIOPtrace*)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "help")) {
		eprintf ("Usage: =!cmd args\n"
			" =!ptrace   - use ptrace io\n"
			" =!mem      - use /proc/pid/mem io if possible\n"
			" =!pid      - show targeted pid\n"
			" =!pid <#>  - select new pid\n");
	} else
	if (!strcmp (cmd, "ptrace")) {
		close_pidmem (iop);
	} else
	if (!strcmp (cmd, "mem")) {
		open_pidmem (iop);
	} else
	if (!strncmp (cmd, "pid", 3)) {
		if (iop) {
			int pid = iop->pid;
			if (cmd[3] == ' ') {
				pid = atoi (cmd+4);
				if (pid > 0 && pid != iop->pid) {
					(void)ptrace (PTRACE_ATTACH, pid, 0, 0);
					// TODO: do not set pid if attach fails?
					iop->pid = iop->tid = pid;
				}
			} else {
				io->cb_printf ("%d\n", iop->pid);
			}
			return pid;
		}
	} else eprintf ("Try: '=!pid'\n");
	return true;
}

static int __getpid (RIODesc *fd) {
	RIOPtrace *iop = (RIOPtrace *)fd->data;
	if (!iop)
		return -1;
	return iop->pid;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
RIOPlugin r_io_plugin_ptrace = {
	.name = "ptrace",
	.desc = "ptrace and /proc/pid/mem (if available) io",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.isdbg = true
};
#else
struct r_io_plugin_t r_io_plugin_ptrace = {
	.name = NULL
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace,
	.version = R2_VERSION
};
#endif
