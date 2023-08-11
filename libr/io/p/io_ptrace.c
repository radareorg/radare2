/* radare - LGPL - Copyright 2008-2022 - pancake */

#include <r_userconf.h>
#include <r_util.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_debug.h>

#if DEBUGGER && (__linux__ || R2__BSD__ || defined(__serenity__))

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
#define RIOPTRACE_OPID(x) (((RIOPtrace*)(x)->data)->opid)
#define RIOPTRACE_PID(x) (((RIOPtrace*)(x)->data)->pid)
#define RIOPTRACE_FD(x) (((RIOPtrace*)(x)->data)->fd)
static void open_pidmem(RIOPtrace *iop);

#undef R_IO_NFDS
#define R_IO_NFDS 2
#ifndef __ANDROID__
extern int errno;
#endif

// PTRACE_GETSIGINFO is defined only since glibc 2.4 but appeared much
// earlier in linux kernel - since 2.3.99-pre6
// So we define it manually
#if __linux__ && defined(__GLIBC__)
#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif
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

#define debug_read_raw(io,x,y) r_io_ptrace((io), PTRACE_PEEKTEXT, (x), (void *)(y), R_PTRACE_NODATA)
#define debug_write_raw(io,x,y,z) r_io_ptrace((io), PTRACE_POKEDATA, (x), (void *)(y), (r_ptrace_data_t)(z))
#if __OpenBSD__ || __NetBSD__ || __KFBSD__ || defined(__serenity__)
typedef int ptrace_word;   // int ptrace(int request, pid_t pid, caddr_t addr, int data);
#else
typedef long ptrace_word; // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
#endif

static int debug_os_read_at(RIO *io, int pid, ut8 *buf, int sz, ut64 addr) {
	ut32 amod = addr % sizeof (ptrace_word);
	ut64 aaddr = addr - amod;
	ut32 x, first = amod ? sizeof (ptrace_word) - amod: 0;
	ptrace_word lr;
	if (sz < 1 || addr == UT64_MAX) {
		return -1;
	}

	if (first) {
		lr = debug_read_raw (io, pid, (size_t)aaddr) >> (amod * 8);
		memcpy (buf, &lr, first);
		aaddr += sizeof (ptrace_word);
		buf += first;
	}
	for (x = first; x < sz; x += sizeof (ptrace_word)) {
		ut32 size = R_MIN (sz - x, sizeof (ptrace_word));
		lr = debug_read_raw (io, pid, (size_t)aaddr);
		memcpy (buf, &lr, size);
		aaddr += sizeof (ptrace_word);
		buf += sizeof (ptrace_word);
	}
	return sz;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
#if USE_PROC_PID_MEM
	int ret, fd;
#endif
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	/* reopen procpidmem if necessary */
#if USE_PROC_PID_MEM
	fd = RIOPTRACE_FD (desc);
	if (RIOPTRACE_PID (desc) != RIOPTRACE_OPID (desc)) {
		if (fd != -1) {
			close (fd);
		}
		open_pidmem ((RIOPtrace*)desc->data);
		fd = RIOPTRACE_FD (desc);
		RIOPTRACE_OPID(desc) = RIOPTRACE_PID(desc);
	}
	// /proc/pid/mem fails on latest linux
	if (fd != -1) {
		ret = lseek (fd, addr, SEEK_SET);
		if (ret >= 0) {
			// Workaround for the buggy Debian Wheeze's /proc/pid/mem
			if (read (fd, buf, len) != -1) {
				return ret;
			}
		}
	}
#endif
	ut8 *aligned_buf = (ut8*)r_malloc_aligned (len, sizeof (ptrace_word));
	if (aligned_buf) {
		int res = debug_os_read_at (io, RIOPTRACE_PID (desc), aligned_buf, len, addr);
		memcpy (buf, aligned_buf, len);
		r_free_aligned (aligned_buf);
		return res;
	}
	return -1;
}

static int ptrace_write_at(RIO *io, int pid, const ut8 *pbuf, int sz, ut64 addr) {
	ptrace_word *buf = (ptrace_word*)pbuf;
	ut32 words = sz / sizeof (ptrace_word);
	ut32 last = sz % sizeof (ptrace_word);
	ptrace_word x, *at = (ptrace_word *)(size_t)addr;
	ptrace_word lr;
	if (sz < 1 || addr == UT64_MAX) {
		return -1;
	}
	for (x = 0; x < words; x++) {
		int rc = debug_write_raw (io, pid, at++, buf[x]); //((ut32*)(at)), buf[x]);
		if (rc) {
			return -1;
		}
	}
	if (last) {
		lr = debug_read_raw (io, pid, (void *)at);
		memcpy (&lr, buf + x, last);
		if (debug_write_raw (io, pid, (void*)at, lr)) {
			return sz - last;
		}
	}
	return sz;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (!fd || !fd->data) {
		return -1;
	}
	return ptrace_write_at (io, RIOPTRACE_PID (fd), buf, len, io->off);
}

static void open_pidmem(RIOPtrace *iop) {
#if USE_PROC_PID_MEM
	char pidmem[32];
	snprintf (pidmem, sizeof (pidmem), "/proc/%d/mem", iop->pid);
	iop->fd = open (pidmem, O_RDWR);
	if (iop->fd == -1) {
		iop->fd = open (pidmem, O_RDONLY);
	}
	if (iop->fd == -1) {
		R_LOG_DEBUG ("Cannot open /proc/%d/mem. Fallback to ptrace io", iop->pid);
	}
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
	if (r_str_startswith (file, "ptrace://")) {
		return true;
	}
	if (r_str_startswith (file, "attach://")) {
		return true;
	}
	return false;
}

static inline bool is_pid_already_attached(RIO *io, int pid) {
#if defined(__linux__)
	siginfo_t sig = {0};
	return r_io_ptrace (io, PTRACE_GETSIGINFO, pid, NULL, &sig) != -1;
#elif defined(__FreeBSD__)
	struct ptrace_lwpinfo info = {0};
	int len = (int)sizeof (info);
	return r_io_ptrace (io, PT_LWPINFO, pid, &info, len) != -1;
#elif defined(__OpenBSD__) || defined(__NetBSD__)
	ptrace_state_t state = {0};
	int len = (int)sizeof (state);
	return r_io_ptrace (io, PT_GET_PROCESS_STATE, pid, &state, len) != -1;
#else
	return false;
#endif
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *desc = NULL;
	int ret = -1;

	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}

	int pid = atoi (file + 9);

	// Safely check if the PID has already been attached to avoid printing errors
	// and attempt attaching on failure
	if (!is_pid_already_attached (io, pid)) {
		ret = r_io_ptrace (io, PTRACE_ATTACH, pid, 0, 0);
		if (ret == -1) {
#ifdef __ANDROID__
			R_LOG_ERROR ("ptrace_attach: Operation not permitted");
#else
			switch (errno) {
			case EPERM:
				R_LOG_ERROR ("ptrace_attach: Operation not permitted");
				break;
			case EINVAL:
				r_sys_perror ("ptrace: Cannot attach");
				R_LOG_ERROR ("errno: %d (EINVAL)", errno);
				break;
			default:
				break;
			}
			return NULL;
#endif
		} else if (__waitpid (pid)) {
			/*Do Nothing*/
		} else {
			R_LOG_ERROR ("waitpid");
			return NULL;
		}
	}

	RIOPtrace *riop = R_NEW0 (RIOPtrace);
	if (!riop) {
		return NULL;
	}

	riop->pid = riop->tid = pid;
	open_pidmem (riop);
	desc = r_io_desc_new (io, &r_io_plugin_ptrace, file, rw | R_PERM_X, mode, riop);
	desc->name = r_sys_pid_to_path (pid);

	return desc;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = ST64_MAX;
	}
	return io->off;
}

static bool __close(RIODesc *desc) {
	if (!desc || !desc->data) {
		return false;
	}
	int pid = RIOPTRACE_PID (desc);
	int fd = RIOPTRACE_FD (desc);
	if (fd != -1) {
		close (fd);
	}
	RIOPtrace *riop = desc->data;
	desc->data = NULL;
	(void) r_io_ptrace (desc->io, PTRACE_DETACH, pid, 0, 0);
	free (riop);
	// always return true, even if ptrace fails, otherwise the link is lost and the fd cant be removed
	return true;
}

static void show_help(void) {
	eprintf ("Usage: :cmd args\n"
		" :ptrace   - use ptrace io\n"
		" :mem      - use /proc/pid/mem io if possible\n"
		" :pid      - show targeted pid\n"
		" :pid <#>  - select new pid\n");
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOPtrace *iop = (RIOPtrace*)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "")) {
		return NULL;
	}
	if (!strcmp (cmd, "help")) {
		show_help ();
	} else if (!strcmp (cmd, "ptrace")) {
		close_pidmem (iop);
	} else if (!strcmp (cmd, "mem")) {
		open_pidmem (iop);
	} else if (r_str_startswith (cmd, "pid")) {
		if (iop) {
			if (cmd[3] == ' ') {
				int pid = atoi (cmd + 4);
				if (pid > 0 && pid != iop->pid) {
					(void)r_io_ptrace (io, PTRACE_ATTACH, pid, 0, 0);
					// TODO: do not set pid if attach fails?
					iop->pid = iop->tid = pid;
				}
			} else {
				io->cb_printf ("%d\n", iop->pid);
			}
			return r_str_newf ("%d", iop->pid);
		}
	} else {
		show_help ();
	}
	return NULL;
}

static int __getpid(RIODesc *fd) {
	RIOPtrace *iop = (RIOPtrace *)fd->data;
	if (!iop) {
		return -1;
	}
	return iop->pid;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
RIOPlugin r_io_plugin_ptrace = {
	.meta = {
		.name = "ptrace",
		.desc = "Ptrace and /proc/pid/mem (if available) io plugin",
		.license = "LGPL3",
	},
	.uris = "ptrace://,attach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.gettid = __getpid,
	.isdbg = true
};
#else
struct r_io_plugin_t r_io_plugin_ptrace = {
	.meta = {
		.name = NULL
	},
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace,
	.version = R2_VERSION
};
#endif
