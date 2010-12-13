/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#if __UNIX__

#include "r_io.h"
#include "r_lib.h"
#include "r_socket.h"
#include <sys/types.h>

int haret_fd = -1;

static int haret__write(struct r_io_t *io, int fd, const ut8 *buf, int count)
{
	return 0;
}

static void haret_wait_until_prompt()
{
	unsigned char buf;
	int off = 0;

	while(1) {
		r_socket_read (haret_fd, &buf, 1);
		switch(off) {
		case 0: if (buf == ')') off =1; break;
		case 1: if (buf == '#') return; else off = 0; break;
		}
	}
}

static int haret__read(struct r_io_t *io, int fd, ut8 *buf, int count)
{
	char tmp[1024];
	int i = 0;
	ut64 off, j;

	off = io->off & -4;
	sprintf (tmp, "pdump 0x%"PFMT64x" %i\r\n", off, count+4);
	r_socket_write (haret_fd, tmp, strlen(tmp));
	r_socket_read_block (haret_fd, (unsigned char *) tmp, strlen (tmp)+1);
	j = (io->off - off)*2;
	while (i<count && j >= 0) {
		r_socket_read_block (haret_fd, (unsigned char *) tmp, 11);
		r_socket_read_block (haret_fd, (unsigned char *) tmp, 35);
		if (i+16 < count || (io->off-off) == 0) {
			tmp[35] = 0;
			i += r_hex_str2bin (tmp+j, buf+i);
			r_socket_read_block (haret_fd, (unsigned char *) tmp, 21);
		} else {
			tmp[(io->off - off)*2] = 0;
			i += r_hex_str2bin (tmp+j, buf+i);
		}
		j=0;
	}
	haret_wait_until_prompt ();
	return i;
}

static int haret__close(struct r_io_t *io, int fd)
{
	int ret = -1;
	if (haret_fd != -1 && fd==haret_fd) {
		ret = r_socket_close (fd);
		haret_fd = -1;
	}
	return ret; // return true/false here?
}

static int haret__plugin_open(struct r_io_t *io, const char *pathname)
{
	return (!memcmp (pathname, "haret://", 8));
}

static int haret__open(struct r_io_t *io, const char *pathname, int flags, int mode)
{
	char *port, *ptr;
	char buf[1024];
	int p;

	strncpy (buf, pathname, sizeof (buf)-1);
	if (!memcmp (buf, "haret://", 8)) {
		ptr = buf + 8;
		if (!(port = strchr (ptr, ':'))) {
			eprintf ("haret: wrong url\n");
			return -1;
		}
		*port = 0;
		p = atoi (port+1);
		if ((haret_fd = r_socket_connect (ptr, p)) == -1) {
			eprintf ("Cannot connect to '%s' (%d)\n", ptr, p);
			return -1;
		} else eprintf ("Connected to: %s at port %d\n", ptr, p);
		haret_wait_until_prompt ();
	}
	return haret_fd;
}

static int haret__system(RIO *io, int fd, const char *command) {
	char buf;
	int off = 0;

	r_socket_write (haret_fd, (char *)command, strlen(command));
	r_socket_write (haret_fd, "\r\n", 2);
	while(1) {
		r_socket_read_block (haret_fd, (unsigned char *)&buf, 1);
		eprintf ("%c", buf);
		switch(off) {
		case 0: if (buf == ')') off =1; break;
		case 1: if (buf == '#') return 0; else off = 0; break;
		}
	}

	return 0;
}

static ut64 haret__lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	return offset;
}

static int haret__init(struct r_io_t *io)
{
	return R_TRUE;
}

struct r_io_plugin_t r_io_plugin_haret = {
	.name = "haret",
	.desc = "Attach to Haret WCE application (haret://host:port)",
	.init = haret__init,
	.system = haret__system,
	.open = haret__open,
	.read = haret__read,
	.lseek = haret__lseek,
	.write = haret__write,
	.close = haret__close,
	.plugin_open = haret__plugin_open,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_haret
};
#endif

#endif
