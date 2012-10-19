/* radare - LGPL - Copyright 2010-2012 pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
////#include "../../debug/p/libgdbwrap/include/gdbwrapper.h"
#define IRAPI static
#include <gdbwrapper.h>
#include "../../debug/p/libgdbwrap/gdbwrapper.c"
//#include "../../debug/p/libgdbwrap/interface.c"

typedef struct {
	RSocket *fd;
	gdbwrap_t *desc;
} RIOGdb;
#define RIOGDB_FD(x) (((RIOGdb*)(x))->fd)
#define RIOGDB_DESC(x) (((RIOGdb*)(x->data))->desc)
#define RIOGDB_IS_VALID(x) (x && x->plugin==&r_io_plugin_gdb && x->data)
#define NUM_REGS 28

static int __plugin_open(RIO *io, const char *file) {
	return (!memcmp (file, "gdb://", 6));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char host[128], *port, *p;
	RSocket *_fd;
	RIOGdb *riog;
	if (!__plugin_open (io, file))
		return NULL;
	strncpy (host, file+6, sizeof (host)-1);
	port = strchr (host , ':');
	if (!port) {
		eprintf ("Port not specified. Please use gdb://[host]:[port]\n");
		return NULL;
	}
	*port = '\0';
	port++;
	p = strchr (port, '/');
	if (p) *p=0;

	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: Cannot use network\n");
		return NULL;
	}
	_fd = r_socket_new (R_FALSE);
	if (_fd && r_socket_connect_tcp (_fd, host, port)) {
		riog = R_NEW (RIOGdb);
		riog->fd = _fd;
		riog->desc = gdbwrap_init (_fd->fd, NUM_REGS, 4);
		if (!riog->desc) {
			r_socket_free (_fd);
			free (riog);
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_gdb, _fd->fd, file, rw, mode, riog);
	}
	eprintf ("gdb.io.open: Cannot connect to host.\n");
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	gdbwrap_writemem (RIOGDB_DESC (fd), io->off, (void *)buf, count);
	return count;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
//if (whence==2) return UT64_MAX;
        return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (RIOGDB_IS_VALID (fd)) {
		char *ptr = gdbwrap_readmem (RIOGDB_DESC (fd), (la32)io->off, count);
		if (ptr == NULL)
			return -1;
		return r_hex_str2bin (ptr, buf);
	}
	return -1;
}

static int __close(RIODesc *fd) {
	// TODO
	return -1;
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	/* XXX: test only for x86-32 */
	if(!strcmp(cmd,"regs")){
		int i;
		gdbwrap_readgenreg (RIOGDB_DESC (fd));
		for (i=0; i<NUM_REGS; i++){
		    ut32 v = gdbwrap_getreg (RIOGDB_DESC (fd), i) & 0xFFFFFFFF;
		    printf ("Reg #%d - %#x\n", i, v);
		}
	} else if (!strcmp (cmd, "stepi")) {
		gdbwrap_stepi (RIOGDB_DESC (fd));
	} else if (!strcmp (cmd, "cont")) {
		gdbwrap_continue (RIOGDB_DESC (fd));
	} else if (!strncmp (cmd, "bp", 2) && r_str_word_count (cmd)==2) {
		char *saddr = strrchr (cmd, ' '); //Assuming only spaces as separator, get last space
		if (saddr) {
			int addr;
			r_hex_str2bin (saddr, (ut8*)&addr); //TODO handle endianness local machine
			gdbwrap_simplesetbp (RIOGDB_DESC (fd), addr);
		}
	}
	return -1;
}

struct r_io_plugin_t r_io_plugin_gdb = {
        //void *plugin;
	.name = "gdb",
        .desc = "Attach to a running 'gdbserver', 'qemu -s' or other, gdb://localhost:1234", 
        .open = __open,
        .close = __close,
	.read = __read,
	.write = __write,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.debug = (void *)1,
};
