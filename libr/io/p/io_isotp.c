/* radare - LGPL - Copyright 2021-2024 - pancake */

#include <r_io.h>

#if __linux__ && HAVE_LINUX_CAN_H

#include <r_lib.h>
#include <r_cons.h>
#include "../io_memory.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#define ISOTPURI "isotp://"

typedef struct {
	RSocket *sc;
	int count;
} RIOSocketData;

static void free_socketdata(RIOSocketData *sd) {
	if (sd) {
		r_socket_free (sd->sc);
		free (sd);
	}
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		RSocket *s = ((RIOSocketData*)(mal->data))->sc;
		return r_socket_write (s, buf, count);
	}
	return -1;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		ut64 addr = mal->offset;
		RIOSocketData *sdat = mal->data;
		RSocket *s = sdat->sc;
		ut8 *mem = malloc (4096);
		if (mem) {
			int c = r_socket_read (s, mem, 4096);
			if (c > 0) {
				int osz = mal->size;
				io_memory_resize (io, desc, mal->size + c);
				memcpy (mal->buf + osz, mem, c);
				io->coreb.cmdf (io->coreb.core, "f nread_%d %d %d",
					sdat->count, c, mal->size);
				// io->coreb.cmdf (io->coreb.core, "omr 1 %d", mal->size);
				sdat->count++;
			}
			free (mem);
		}
		mal->offset = addr;
		return io_memory_read (io, desc, buf, count);
	}
	return -1;
}

static bool __close(RIODesc *desc) {
	R_FREE (desc->data);
	return true;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, ISOTPURI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("The " ISOTPURI " uri is not permitted in sandbox mode");
		return NULL;
	}
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	RIOMalloc *mal = R_NEW0 (RIOMalloc);
	if (!mal) {
		return NULL;
	}
	RIOSocketData *data = R_NEW0 (RIOSocketData);
	if (!mal || !data) {
		free (mal);
		free_socketdata (data);
		return NULL;
	}
	mal->data = data;
	mal->buf = calloc (1, 1);
	if (!mal->buf) {
		free (mal);
		free_socketdata (data);
		return NULL;
	}
	mal->size = 1;
	mal->offset = 0;
	pathname += strlen (ISOTPURI);

	if (*pathname == '?') {
		R_LOG_ERROR ("Usage: r2 isotp://interface/source/destination");
	} else {
		char *host = strdup (pathname);
		const char *port = "";
		char *slash = strchr (host, '/');
		if (slash) {
			*slash = 0;
			port = slash + 1;
		}
		data->sc = r_socket_new (false);
		if (!r_socket_connect (data->sc, host, port, R_SOCKET_PROTO_CAN, 0)) {
			R_LOG_ERROR ("Cannot connect");
			free (host);
			free_socketdata (data);
			return NULL;
		}
		r_socket_block_time (data->sc, false, 0, 0);
		free (host);
	}
	if (io->va) {
		R_LOG_WARN ("This is a raw stream and growing io plugin, You may disable io.va to not depend on maps");
	}
	return r_io_desc_new (io, &r_io_plugin_isotp, pathname, R_PERM_RW | (rw & R_PERM_X), mode, mal);
}

RIOPlugin r_io_plugin_isotp = {
	.meta = {
		.name = "isotp",
		.author = "pancake",
		.desc = "Connect using the ISOTP protocol (isotp://interface/srcid/dstid)",
		.license = "MIT",
	},
	.uris = ISOTPURI,
	.open = __open,
	.close = __close,
	.read = __read,
	.seek = io_memory_lseek,
	.check = __check,
	.write = __write,
};

#else
RIOPlugin r_io_plugin_isotp = {
	.meta = {
		.name = "isotp",
		.author = "pancake",
		.license = "MIT",
		.desc = "shared memory resources (not for this platform)",
	},
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_isotp,
	.version = R2_VERSION
};
#endif
