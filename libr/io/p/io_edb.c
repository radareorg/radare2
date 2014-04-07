/* radare - LGPL - Copyright 2014 - condret

This stuff is very experimental
*/

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>

typedef struct r_emu_remote_t {
	ut64 job;
	ut64 size;
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

static int edb_write(struct r_io_t *io, RIODesc *fd, const ut8 *buf, int count) {
        return -1;		//Todo
}

static int edb_read(struct r_io_t *io, RIODesc *fd, ut8 *buf, int count) {
	RSocket *edb_fd;
	REdb edb;
	int i;
	if (fd && fd->data) {
		edb_fd = (RSocket *)fd->data;
		if (r_socket_is_connected(edb_fd)) {
			edb.job = EMU_READ_PR;
			edb.size = (ut64)count;
			r_socket_write (edb_fd, (ut8 *)&edb, 16);
			r_socket_flush (edb_fd);
			for (i = count; i > 0; i -= 1024) {
				if (i > 1024) {
					r_socket_read_block (edb_fd, buf, 1024);
					buf += 1024;
				} else	r_socket_read_block (edb_fd, buf, i);
			}
			return count;
		}
	}
	return -1;
}

static int edb_close(RIODesc *fd) {
	RSocket *edb_fd;
	REdb edb;
	if (fd && fd->data) {
		edb_fd = (RSocket *)fd->data;
		if (r_socket_is_connected (edb_fd)) {
			edb.job = EMU_CLOSE_PR;
			r_socket_write(edb_fd, (ut8 *)&edb, 16);
			r_socket_flush (edb_fd);
			r_socket_close (edb_fd);
			r_socket_free (edb_fd);
			fd->data = NULL;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

static ut64 edb_lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	RSocket *edb_fd;
	REdb edb;
	if(fd && fd->data) {
		edb_fd = (RSocket *)fd->data;
		if (r_socket_is_connected(edb_fd)) {
			edb.job = EMU_SEEK_PR;
			edb.size = offset;
				r_socket_write (edb_fd, (ut8 *)&edb, 16);
			r_socket_flush (edb_fd);
			return offset;
		}
	}
	return NULL;
}

static int edb_plugin_open(struct r_io_t *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname,"edb://",6));
}

static RIODesc *edb_open(struct r_io_t *io, const char *pathname, int rw, int mode) {
	RSocket *edb_fd = r_socket_new(0);
	RIODesc *desc;
	char *ip, *port;
	ip = strdup (&pathname[6]);
	if ((port = strchr (ip, (int)':'))) {
		*port = '\0';
		port++;
	} else {
		free (ip);
		return NULL;
	}
	if (r_socket_connect_tcp (edb_fd, ip, port, 30) == R_FALSE) {
		r_socket_free (edb_fd);
		free (ip);
		return NULL;
	}
	desc = r_io_desc_new (&r_io_plugin_edb, edb_fd->fd , pathname, rw, mode, edb_fd);
	free (ip);
	return desc;
}

RIOPlugin r_io_plugin_edb = {
	.name = "edb",
	.desc = "ramulate network protocol (edb://addr:port)",
	.license = "LGPL3",
	.listener = NULL,
	.open = edb_open,
	.close = edb_close,
	.read = edb_read,
	.plugin_open = edb_plugin_open,
	.lseek = edb_lseek,
	.system = NULL,
	.write = edb_write,
	.accept = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_edb
};
#endif
