/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define MALLOC_FD 98479
static int malloc_fd = -1;
static unsigned char *malloc_buf = NULL;
static unsigned int malloc_bufsz = 0;
// XXX shitty vars -- should be state
static ut64 malloc_seek = 0;

static int __write(struct r_io_t *io, int fd, const ut8 *buf, int count)
{
	if (malloc_buf == NULL)
		return 0;
	return (ssize_t)memcpy(malloc_buf+io->off, buf, count);
}

static int __read(struct r_io_t *io, int fd, ut8 *buf, int count)
{
	if (malloc_buf == NULL)
		return 0;

	if (malloc_seek + count > malloc_bufsz) {
		//config.seek = 0; // ugly hack
		//count = config.seek+count-config.size;
		return 0;
	}
	if (malloc_seek + count > malloc_bufsz)
		malloc_seek = malloc_bufsz;

	return (ssize_t)memcpy(buf, malloc_buf+malloc_seek, count);
}

static int __close(struct r_io_t *io, int fd)
{
	if (malloc_buf == NULL)
		return -1;
	free(malloc_buf);
	malloc_buf = malloc(malloc_bufsz);
	return 0;
}

extern ut64 posix_lseek(int fildes, ut64 offset, int whence);
static ut64 __lseek(struct r_io_t *io, int fildes, ut64 offset, int whence)
{
	switch(whence) {
	case SEEK_SET:
		malloc_seek = offset;
		break;
	case SEEK_CUR:
		malloc_seek += offset;
		break;
	case SEEK_END:
		malloc_seek = malloc_bufsz;
		break;
	}
	return malloc_seek;
}

static int __handle_open(struct r_io_t *io, const char *pathname)
{
	return (!memcmp(pathname, "malloc://", 9));
}

static int __open(struct r_io_t *io, const char *pathname, int flags, int mode)
{
	char buf[1024];
	char *ptr = buf;

	strncpy(buf, pathname, 1000);

	if (!memcmp(ptr , "malloc://", 9)) {
		ptr = ptr+6;
		// connect
		malloc_fd = MALLOC_FD;
		malloc_bufsz = atoi(pathname+9);
		malloc_buf = malloc(malloc_bufsz);

		if (malloc_buf == NULL) {
			printf("Cannot allocate (%s)%d bytes\n", pathname+9, malloc_bufsz);
			malloc_buf = NULL;
			malloc_bufsz = 0;
			malloc_fd = -1;
		} else memset(malloc_buf, '\0', malloc_bufsz);
	}
	return malloc_fd;
}

static int __init(struct r_io_t *io)
{
	return R_TRUE;
}

static int __system(struct r_io_t *io, int fd, const char *cmd)
{
	/* */
	return 0;
}

struct r_io_plugin_t r_io_plugin_malloc = {
        //void *handle;
	.name = "malloc",
        .desc = "memory allocation ( malloc://size-in-bytes )",
        .open = __open,
        .close = __close,
	.read = __read,
        .handle_open = __handle_open,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
        //void *widget;
/*
        struct debug_t *debug;
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_malloc
};
#endif
