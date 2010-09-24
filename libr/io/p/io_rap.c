/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

// TODO: implement the rap API in r_socket ?
#include "r_io.h"
#include "r_lib.h"
#include "r_core.h"
#include "r_socket.h"
#include <sys/types.h>

static int rap_fd = -1;
static int is_listener = 0;
static int endian = 0;

static int rap__write(struct r_io_t *io, int fd, const ut8 *buf, int count) {
	int ret;
	unsigned int size = (int)count;
	ut8 *tmp = (ut8 *)malloc(count+5);

	if (count>RMT_MAX)
		count = RMT_MAX;
	tmp[0] = RMT_WRITE;
	r_mem_copyendian((ut8 *)tmp+1, (ut8*)&size, 4, endian);
	memcpy(tmp+5, buf, size);

	ret = r_socket_write (rap_fd, tmp, size+5);
	read(rap_fd, tmp, 5);

	free(tmp);
	// TODO: get reply
        return ret;
}

static int rap__read(struct r_io_t *io, int fd, ut8 *buf, int count) {
	ut8 tmp[5];
	int i = (int)count;

	if (count>RMT_MAX)
		count = RMT_MAX;
	// send
	tmp[0] = RMT_READ;
	r_mem_copyendian (tmp+1, (ut8*)&i, 4, endian);
	r_socket_write (rap_fd, tmp, 5);

	// recv
	read(rap_fd, tmp, 5);
	if (tmp[0] != (RMT_READ|RMT_REPLY)) {
		eprintf ("Unexpected rap read reply (0x%02x)\n", tmp[0]);
		return -1;
	}
	r_mem_copyendian ((ut8*)&i, tmp+1, 4, endian);
	if (i>count) {
		eprintf ("Unexpected data size %d\n", i);
		return -1;
	} else r_socket_read_block (rap_fd, buf, i);
	if (i>0&&i<RMT_MAX) {
		eprintf ("READ %d\n" ,i);
	} else i=0;
        return i;
}

static int rap__close(struct r_io_t *io, int fd) {
	int ret = -1;
	if (rap_fd != -1 && fd==rap_fd) {
		ret = close (fd);
		rap_fd = -1;
	}
	return ret; // return true/false here?
}

static ut64 rap__lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	int ret;
	ut8 tmp[10];
	// query
	tmp[0] = RMT_SEEK;
	tmp[1] = (ut8)whence;
	r_mem_copyendian (tmp+2, (ut8*)&offset, 8, endian);
	write (rap_fd, &tmp, 10);
	// get reply
	ret = r_socket_read_block (fildes, (ut8*)&tmp, 9);
	if (ret!=9)
		return -1;
	if (tmp[0] != (RMT_SEEK | RMT_REPLY)) {
		eprintf ("Unexpected lseek reply\n");
		return -1;
	}
	r_mem_copyendian ((ut8 *)&offset, tmp+1, 8, !endian);
	return offset;
}

static int rap__plugin_open(struct r_io_t *io, const char *pathname) {
	return (!memcmp (pathname, "rap://", 6));
}

static int rap__open(struct r_io_t *io, const char *pathname, int flags, int mode) {
	char *file, *port, *ptr;
	char buf[1024];
	int i, p, listenmode;

	strncpy (buf, pathname, sizeof (buf)-1);
	if (!memcmp (buf, "rap://", 6)) {
		ptr = buf + 6;
		if (!(port = strchr (ptr, ':'))) {
			eprintf ("rap: wrong uri\n");
			return -1;
		}
		listenmode = (*ptr==':');
		*port = 0;
		p = atoi (port+1);
		if ((file = strchr (port+1, '/'))) {
			*file = 0;
			file++;
		}
		if (listenmode) {
			if (p<=0) {
				eprintf ("rap: cannot listen here. Try rap://:9999\n");
				return -1;
			}
			//TODO: Handle ^C signal (SIGINT, exit); // ???
			eprintf ("rap: listening at port %d\n", p);
			is_listener = R_TRUE;
			return r_socket_listen (p);
		} else {
			if ((rap_fd=r_socket_connect (ptr, p))==-1) {
				eprintf ("Cannot connect to '%s' (%d)\n", ptr, p);
				return -1;
			} else eprintf ("Connected to: %s at port %d\n", ptr, p);
			if (file&&*file) {
				// send
				buf[0] = RMT_OPEN;
				buf[1] = flags;
				buf[2] = (ut8)strlen(file);
				memcpy (buf+3, file, buf[2]);
				r_socket_write (rap_fd, buf, 3+buf[2]);
				// read
				eprintf ("waiting... ");
				read (rap_fd, (ut8*)buf, 5);
				if (buf[0] != (char)(RMT_OPEN|RMT_REPLY))
					return -1;
				r_mem_copyendian ((ut8 *)&i, (ut8*)buf+1, 4, endian);
				if (i>0) eprintf ("ok\n");
			}
			is_listener = R_FALSE;
			return rap_fd;
		}
	}
	return rap_fd;
}

static int rap__init(struct r_io_t *io) {
	return R_TRUE;
}

static int rap__listener(struct r_io_t *io) {
	return is_listener;
}

static int rap__system(RIO *io, int fd, const char *command) {
	ut8 buf[1024];
	char *ptr;
	int ret, i, j;

	// send
	buf[0] = RMT_SYSTEM;
	i = strlen (command);
	r_mem_copyendian (buf+1, (ut8*)&i, 4, endian);
	memcpy (buf+5, command, i);
	r_socket_write (rap_fd, buf, i+5);

	// read
	ret = r_socket_read_block (rap_fd, buf, 5);
	if (ret != 5) {
		return -1;
	}
	if (buf[0] != (RMT_SYSTEM | RMT_REPLY)) {
		eprintf ("Unexpected system reply\n");
		return -1;
	}
	r_mem_copyendian ((ut8*)&i, buf+1, 4, !endian);
	if (i == -1)
		return -1;
	if (i>RMT_MAX)
		i = RMT_MAX;
	ptr = (char *)malloc (i);
	if (ptr) {
		r_socket_read_block (rap_fd, (ut8*)ptr, i);
		j = write (1, ptr, i);
		free (ptr);
	}
	return i-j;
}

struct r_io_plugin_t r_io_plugin_rap = {
	.name = "rap",
        .desc = "radare protocol over tcp/ip (rap://:port rap://host:port/file)",
	.listener = rap__listener,
        .open = rap__open,
        .close = rap__close,
	.read = rap__read,
        .plugin_open = rap__plugin_open,
	.lseek = rap__lseek,
	.system = rap__system,
	.init = rap__init,
	.write = rap__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_rap
};
#endif
