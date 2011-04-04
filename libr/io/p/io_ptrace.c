/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

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
} RIOPtrace;
#define RIOPTRACE_PID(x) (((RIOPtrace*)x->data)->pid)

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid (pid, &st, 0) != -1);
}

#if __OpenBSD__
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, (pid_t)(x), (caddr_t)(y), 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, (pid_t)(x), (caddr_t)(y), (int)(size_t)(z))
#else
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, x, y, 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, x, y, z)
#endif

static int debug_os_read_at(int pid, void *buf, int sz, ut64 addr) {
	unsigned long words = sz / sizeof (long);
	unsigned long last = sz % sizeof (long);
	long x, lr, s = 0;

	if (sz<0 || addr==-1)
		return -1; 
	for (x=0; x<words; x++) {
		((long *)buf)[x] = debug_read_raw (pid,
			(void *)(&((long*)(long)addr)[x]));
		s += sizeof (s);
	}
	if (last) {
		lr = debug_read_raw (pid, &((long*)(long)addr)[x]);
		if (lr == -1) // && errno)
			return s;
		memcpy (&((long *)buf)[x], &lr, last) ;
	}
	return sz; 
}

static int __read(struct r_io_t *io, RIODesc *fd, ut8 *buf, int len) {
	ut64 addr = io->off;
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (RIOPTRACE_PID (fd), buf, len, addr);
}

static int ptrace_write_at(int pid, const ut8 *buf, int sz, ut64 addr) {
	long words = sz / sizeof(long);
	long last = (sz - words*sizeof(long)) * 8;
	long x, lr;

	for (x=0; x<words; x++)
		if (debug_write_raw (pid, &((long *)(long)addr)[x], ((long *)buf)[x]))
			goto err;
	if (last) {
		lr = debug_read_raw (pid, &((long *)(long)addr)[x]);
		lr = ((lr&(-1L<<last))|(((long *)buf)[x]&(~(-1L<<last))));
		if (debug_write_raw (pid, (void*)((long)addr+(x*sizeof(void*))), (void*)lr))
			goto err;
	}
	return sz;
err:
	return --x * sizeof(long) ;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return ptrace_write_at (RIOPTRACE_PID (fd), buf, len, io->off);
}

static int __plugin_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "ptrace://", 9))
		return R_TRUE;
	if (!memcmp (file, "attach://", 9))
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *__open(struct r_io_t *io, const char *file, int rw, int mode) {
	int ret = -1;
	if (__plugin_open (io, file)) {
		int pid = atoi (file+9);
		ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
		if (file[0]=='p')  //ptrace
			ret = 0;
		else
		if (ret == -1) {
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
		} else
		if (__waitpid (pid))
			ret = pid;
		else eprintf ("Error in waitpid\n");
		if (ret != -1) {
			RIOPtrace *riop = R_NEW (RIOPtrace);
			riop->pid = riop->tid = pid;
			return r_io_desc_new (&r_io_plugin_ptrace, -1, file, R_TRUE, 0, riop);
		}
	}
	return NULL;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}

static int __close(RIODesc *fd) {
	int pid = RIOPTRACE_PID (fd);
	free (fd->data);
	fd->data = NULL;
	return ptrace (PTRACE_DETACH, pid, 0, 0);
}

static int __system(struct r_io_t *io, RIODesc *fd, const char *cmd) {
	RIOPtrace *iop = (RIOPtrace*)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "mem")) {
		char b[128];
		int ret = debug_os_read_at (iop->pid, b, 128, 0x8048500);
		printf ("ret = %d , pid = %d\n", ret, iop->pid);
		printf ("%x %x %x %x\n", b[0], b[1], b[2], b[3]);
	} else
	if (!strcmp (cmd, "pid")) {
		int pid = atoi (cmd+4);
		if (pid != 0)
			iop->pid = iop->tid = pid;
		io->printf ("%d\n", iop->pid);
		return pid;
	} else eprintf ("Try: '=!pid'\n");
	return R_TRUE;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
struct r_io_plugin_t r_io_plugin_ptrace = {
        //void *plugin;
	.name = "io_ptrace",
	.desc = "ptrace io",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};
#else
struct r_io_plugin_t r_io_plugin_ptrace = {
	.name = "ptrace",
	.desc = "ptrace io (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace
};
#endif
