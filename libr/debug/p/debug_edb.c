/* radare - LGPL - Copyright 2014 - condret */

#include <r_debug.h>
#include <r_socket.h>
#include <string.h>

typedef struct r_edb_t {
	ut64 job;
	ut64 value;
} REdb;

enum {
	EMU_READ_PR = 0,
	EMU_WRITE_PR,
	EMU_SEEK_PR,
	EMU_DR_PR,
	EMU_DRW_PR,
	EMU_DRP_PR,
	EMU_STEP_PR,
	EMU_CLOSE_PR
};


static int r_debug_edb_step(RDebug *dbg) {
	REdb edb;
	RSocket *edb_fd = (RSocket *)dbg->iob.io->fd->data;
	edb.job = EMU_STEP_PR;
	r_socket_write (edb_fd, (ut8 *)&edb, 16);
	r_socket_flush (edb_fd);
	return R_TRUE;
}

static int r_debug_edb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	REdb edb;
	int len = 0;
	if (strcmp (dbg->iob.io->plugin->name, "edb")) {
		eprintf ("io is not edb\n");
		return R_FALSE;
	}
	RSocket *edb_fd = (RSocket *)dbg->iob.io->fd->data;
	edb.job = EMU_DR_PR;
	edb.value = ((ut64)type | ((ut64)size<<32));
	r_socket_write (edb_fd, (ut8 *)&edb, 16);
	r_socket_flush (edb_fd);
	r_socket_read_block (edb_fd, (ut8 *)&len, 4);
	r_socket_read_block (edb_fd, buf, len);
	return len;
}

static int r_debug_edb_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	REdb edb;
	RSocket *edb_fd;
	if (strcmp (dbg->iob.io->plugin->name, "edb")) {
		eprintf ("io is not edb\n");
		return R_FALSE;
	}
	edb_fd = (RSocket *)dbg->iob.io->fd->data;
	edb.job = EMU_DRW_PR;
	edb.value = ((ut64)type +  ((ut64)size<<32));
	r_socket_write (edb_fd, (ut8 *)&edb, 16);
	r_socket_flush (edb_fd);
	r_socket_write (edb_fd, buf, size);
	r_socket_flush (edb_fd);
	return R_TRUE;
}

static int r_debug_edb_wait(RDebug *dbg, int pid) {
	return R_TRUE;
}

static int r_debug_edb_attach(RDebug *dbg, int pid) {
	return dbg->iob.io->fd->fd;
}

static int r_debug_edb_detach(int pid) {
	return pid;
}

static char *r_debug_edb_reg_profile(RDebug *dbg) {
	return strdup (
		"=pc	mpc\n"
		"=sp	sp\n"
		"=a0	af\n"
		"=a1	bc\n"
		"=a2	de\n"
		"=a3	hl\n"

		"gpr	mpc	.32	0	0\n"
		"gpr	pc	.16	0	0\n"
		"gpr	m	.16	2	0\n"

		"gpr	sp	.16	4	0\n"

		"gpr	af	.16	6	0\n"
		"gpr	f	.8	6	0\n"
		"gpr	a	.8	7	0\n"
		"gpr	Z	.1	.55	0\n"
		"gpr	N	.1	.54	0\n"
		"gpr	H	.1	.53	0\n"
		"gpr	C	.1	.52	0\n"

		"gpr	bc	.16	8	0\n"
		"gpr	c	.8	8	0\n"
		"gpr	b	.8	9	0\n"

		"gpr	de	.16	10	0\n"
		"gpr	e	.8	10	0\n"
		"gpr	d	.8	11	0\n"

		"gpr	hl	.16	12	0\n"
		"gpr	l	.8	12	0\n"
		"gpr	h	.8	13	0\n"

		"gpr	mbcrom	.16	14	0\n"
		"gpr	mbcram	.16	16	0\n"

		"gpr	ime	.1	18	0\n");
}


RDebugPlugin r_debug_plugin_edb = {
	.name = "edb",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_Z80,			//unknown
	.bits = R_SYS_BITS_32,			//unknown
	.init = NULL,
	.step = r_debug_edb_step,
	.step_over = NULL,
	.cont = NULL,
	.contsc = NULL,
	.attach = &r_debug_edb_attach,
	.detach = &r_debug_edb_detach,
	.wait = &r_debug_edb_wait,
	.pids = NULL,
	.stop = NULL,
	.tids = NULL,
	.threads = NULL,
	.kill = NULL,
	.frames = NULL,
	.breakpoint = NULL,
	.reg_read = &r_debug_edb_reg_read,
	.reg_write = &r_debug_edb_reg_write,
	.reg_profile = r_debug_edb_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_edb
};
#endif
