/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#if __UNIX__

#include "r_io.h"
#include "r_lib.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static int shm_fd = -1;
static unsigned char *shm_buf = NULL;
static unsigned int shm_bufsz = 32*1024*1024; /* 32MB */

static int shm__write(struct r_io_t *io, int fd, const u8 *buf, int count)
{
	if (shm_buf != NULL)
        	return (ssize_t)memcpy(shm_buf+io->seek, buf, count);
	return -1;
}

static int shm__read(struct r_io_t *io, int fd, u8 *buf, int count)
{
	if (shm_buf == NULL)
		return -1;
	if (io->seek > shm_bufsz)
		io->seek = shm_bufsz;
	memcpy(buf, shm_buf+io->seek, count);
        return 0;
}

static int shm__close(struct r_io_t *io, int fd)
{
	if (shm_buf == NULL)
		return -1;
	return shmdt(shm_buf);
}

static u64 shm__lseek(struct r_io_t *io, int fildes, u64 offset, int whence)
{
	if (shm_buf == NULL)
		return -1;
	switch(whence) {
	case SEEK_SET:
		return offset;
	case SEEK_CUR:
		if (io->seek+offset>shm_bufsz)
			return shm_bufsz;
		return io->seek + offset;
	case SEEK_END:
		return 0xffffffff;
	}
	return io->seek;
}

static int shm__handle_fd(struct r_io_t *io, int fd)
{
	return (fd == shm_fd);
}

static int shm__handle_open(struct r_io_t *io, const char *pathname)
{
	return (!memcmp(pathname, "shm://", 6));
}

static int shm__open(struct r_io_t *io, const char *pathname, int flags, int mode)
{
	char buf[1024];
	char *ptr = buf;

	strncpy(buf, pathname, 1000);

	if (!memcmp(ptr , "shm://", 6)) {
		ptr= ptr+6;
		// connect
		shm_buf= shmat(atoi(ptr), 0, 0);

		if (((int)(shm_buf)) != -1) {
			printf("Connected to shared memory 0x%08x\n", atoi(ptr));
			shm_fd = (int)&shm_buf;
		} else	{
			printf("Cannot connect to shared memory (%d)\n", atoi(ptr));
			shm_buf = NULL;
			shm_fd = -1;
		}
	}
	return shm_fd;
}

static int shm__init(struct r_io_t *io)
{
	return R_TRUE;
}

static struct r_io_handle_t r_io_plugin_shm = {
        //void *handle;
	.name = "shm",
        .desc = "shared memory resources (shm://key)",
        .open = shm__open,
        .close = shm__close,
	.read = shm__read,
        .handle_open = shm__handle_open,
        .handle_fd = shm__handle_fd,
	.lseek = shm__lseek,
	.system = NULL, // shm__system,
	.init = shm__init,
	.write = shm__write,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_shm
};

#endif
