/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#if __linux__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__

#include <r_io.h>
#include <r_lib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#undef R_IO_NFDS
#define R_IO_NFDS 2
int fds[3];
int nfds = 0;

static int __waitpid(int pid)
{
	int st = 0;
	if (waitpid(pid, &st, 0) == -1)
		return R_FALSE;
	return R_TRUE;
}

#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, x, y, 0)

static int debug_os_read_at(int pid, void *buff, int sz, u64 addr)
{
        unsigned long words = sz / sizeof(long) ;
        unsigned long last = sz % sizeof(long) ;
        long x, lr ;
        int ret ;

        if (sz<0)
                return -1; 

        if (addr==-1)
                return 0;

        for(x=0;x<words;x++) {
                ((long *)buff)[x] = debug_read_raw(pid, (void *)(&((long*)(long )addr)[x]));

                if (((long *)buff)[x] == -1) // && errno)
                        goto err;
        }

        if (last) {
                //lr = ptrace(PTRACE_PEEKTEXT,pid,&((long *)addr)[x],0) ;
                lr = debug_read_raw(pid, &((long*)(long)addr)[x]);

                if (lr == -1) // && errno)
                        goto err;

                memcpy(&((long *)buff)[x],&lr,last) ;
        }

        return sz; 
err:
        ret = --x * sizeof(long);

        return ret ;
}

static int __read(struct r_io_t *io, int pid, u8 *buf, int len)
{
	int ret;
	u64 addr = io->seek;
	memset(buf, '\xff', len);
	ret = debug_os_read_at(pid, buf, len, addr);
//printf("READ(0x%08llx)\n", addr);
	//if (ret == -1)
	//	return -1;

	return len;
}

static int __write(struct r_io_t *io, int pid, const u8 *buf, int len)
{
	//int ret;
	//u64 addr = r_io_seek;
	//ret = debug_os_write_at(pid, buf, len, addr);
//printf("READ(0x%08llx)\n", addr);
	//if (ret == -1)
	//	return -1;

	return len;
}

static int __handle_open(struct r_io_t *io, const char *file)
{
	if (!memcmp(file, "ptrace://", 9))
		return R_TRUE;
	if (!memcmp(file, "attach://", 9))
		return R_TRUE;
	return R_FALSE;
}

//extern int errno;

static int __open(struct r_io_t *io, const char *file, int rw, int mode)
{
	int ret = -1;
	if (__handle_open(io, file)) {
		int pid = atoi(file+9);
		if (file[0]=='a') {
			ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
			if (ret == -1) {
				switch(errno) {
				case EPERM:
					ret = pid;
					fprintf(stderr, "Operation not permitted\n");
					break;
				case EINVAL:
					perror("ptrace: Cannot attach");
					fprintf(stderr, "ERRNO: %d (EINVAL)\n", errno);
					break;
				}
			} else
			if (__waitpid(pid)) {
				ret = pid;
			} else fprintf(stderr, "Error in waitpid\n");
		} else ret = pid;
	}
	fds[0] = ret;
	return ret;
}

static int __handle_fd(struct r_io_t *io, int fd)
{
	int i;
	for(i=0;i<nfds;i++) {
		if (fds[i]==fd)
			return R_TRUE;
	}
	return R_FALSE;
}

static u64 __lseek(struct r_io_t *io, int fildes, u64 offset, int whence)
{
	return -1;
}

static int __close(struct r_io_t *io, int pid)
{
	return ptrace(PTRACE_DETACH, pid, 0, 0);
}

static int __system(struct r_io_t *io, int fd, const char *cmd)
{
	printf("ptrace io command. %s\n", cmd);
	return R_TRUE;
}

static int __init(struct r_io_t *io)
{
	printf("ptrace init\n");
	return R_TRUE;
}

static struct r_io_handle_t r_io_plugin_ptrace = {
        //void *handle;
	.name = "ptrace",
        .desc = "ptrace io",
        .open = __open,
        .close = __close,
	.read = __read,
        .handle_open = __handle_open,
        .handle_fd = __handle_fd,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
        //void *widget;
/*
        struct debug_t *debug;
        u32 (*write)(int fd, const u8 *buf, u32 count);
	int fds[R_IO_NFDS];
*/
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace
};

#endif
