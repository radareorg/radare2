/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_util.h>

#if __WINDOWS__

#include <windows.h>
#include <tlhelp32.h>

typedef struct {
	int pid;
	int tid;
	PROCESS_INFORMATION pi;
} RIOW32Dbg;
#define RIOW32DBG_PID(x) (((RIOW32Dbg*)x->data)->pid)

#undef R_IO_NFDS
#define R_IO_NFDS 2

static int debug_os_read_at(RIOW32Dbg *dbg, void *buf, int len, ut64 addr) {
	DWORD ret;
        ReadProcessMemory (dbg->pi.hProcess, (void*)(size_t)addr, buf, len, &ret);
//	if (len != ret)
//		eprintf ("Cannot read 0x%08llx\n", addr);
	return len; // XXX: Handle read correctly and not break r2 shell
	//return (int)ret; //(int)len; //ret;
}

static int __read(struct r_io_t *io, RIODesc *fd, ut8 *buf, int len) {
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (fd->data, buf, len, io->off);
}

static int w32dbg_write_at(RIOW32Dbg *dbg, const ut8 *buf, int len, ut64 addr) {
	DWORD ret;
    return 0 != WriteProcessMemory (dbg->pi.hProcess, (void *)(size_t)addr, buf, len, &ret)? len: 0;
}

static int __write(struct r_io_t *io, RIODesc *fd, const ut8 *buf, int len) {
	return w32dbg_write_at (fd->data, buf, len, io->off);
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	if (!strncmp (file, "attach://", 9))
		return R_TRUE;
	return (!strncmp (file, "w32dbg://", 9))? R_TRUE: R_FALSE;
}

static int __attach (RIOW32Dbg *dbg) {
	eprintf ("---> attach to %d\n", dbg->pid);
	dbg->pi.hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (dbg->pi.hProcess == NULL)
		return -1;
	return dbg->pid;
}

static RIODesc *__open(struct r_io_t *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		char *pidpath;
		RIOW32Dbg *dbg = R_NEW (RIOW32Dbg);
		if (dbg == NULL)
			return NULL;
		dbg->pid = atoi (file+9);
		if (__attach (dbg) == -1) {
			free (dbg);
			return NULL;
		}
		pidpath = r_sys_pid_to_path (dbg->pid);
		RETURN_IO_DESC_NEW (&r_io_plugin_w32dbg, -1,
			pidpath, rw | R_IO_EXEC, mode, dbg);
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}

static int __close(RIODesc *fd) {
	// TODO: detach
	return R_TRUE;
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOW32Dbg *iop = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "pid")) {
		int pid = atoi (cmd+4);
		if (pid != 0)
			iop->pid = iop->tid = pid;
		io->printf ("\n");
		//printf("PID=%d\n", io->fd);
		return pid;
	} else eprintf ("Try: '=!pid'\n");
	return R_TRUE;
}

static int __init(struct r_io_t *io) {
//	eprintf ("w32dbg init\n");
	return R_TRUE;
}

// TODO: rename w32dbg to io_w32dbg .. err io.w32dbg ??
RIOPlugin r_io_plugin_w32dbg = {
        //void *plugin;
	.name = "w32dbg",
        .desc = "w32dbg io",
	.license = "LGPL3",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
	.isdbg = R_TRUE
};
#else
struct r_io_plugin_t r_io_plugin_w32dbg = {
	.name = NULL
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg
};
#endif
