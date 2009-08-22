/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <r_userconf.h>

#if DEBUGGER

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#if __linux__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;
static int fds[3];
static int nfds = 0;

static int __waitpid(int pid)
{
	int st = 0;
	if (waitpid(pid, &st, 0) == -1)
		return R_FALSE;
	return R_TRUE;
}

#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, x, y, 0)

// FIX: the goto 'err' is buggy
static int debug_os_read_at(int pid, void *buff, int sz, ut64 addr)
{
        unsigned long words = sz / sizeof(long) ;
        unsigned long last = sz % sizeof(long) ;
        long x, lr;

        if (sz<0 || addr==-1)
                return -1; 

        for(x=0;x<words;x++) {
                ((long *)buff)[x] = debug_read_raw(pid, (void *)(&((long*)(long )addr)[x]));
                if (((long *)buff)[x] == -1) // && errno)
                        goto err;
        }

        if (last) {
                lr = debug_read_raw(pid, &((long*)(long)addr)[x]);
                if (lr == -1) // && errno)
                        goto err;
                memcpy(&((long *)buff)[x], &lr, last) ;
        }

        return sz; 
err:
        return --x * sizeof(long);
}

static int __read(struct r_io_t *io, int pid, ut8 *buf, int len)
{
	int ret;
	ut64 addr = io->seek;
	memset(buf, '\xff', len);
	ret = debug_os_read_at(pid, buf, len, addr);
//printf("READ(0x%08llx)\n", addr);
	//if (ret == -1)
	//	return -1;

	return len;
}

static int ptrace_write_at(int pid, const ut8 *buff, int sz, ut64 addr)
{
        long words = sz / sizeof(long) ;
        long last = (sz % sizeof(long))*8;
        long  lr ;
	int x;

/*
	long *word=&buf;
	char buf[4];
        En los fuentes del kernel se encuentra un #ifdef para activar el soporte de escritura por procFS.
        Por razones de seguridad se encuentra deshabilitado, pero nunca esta de mas intentar ;)
*/
#if 0
	word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, (void *)buf);
	if (word==-1)
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, (void *)buf);
	buf[0]=buff[0];
	ptrace(PTRACE_POKEDATA, (pid_t)pid, (void *)addr, (void *)buf);
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)buf);
	return sz;
#endif
//eprintf("%d ->%d (0x%x)\n",pid, (int)sz, (long)addr);


	for(x=0;x<words;x++)
		if (ptrace(PTRACE_POKEDATA,pid,&((long *)(long)addr)[x],((long *)buff)[x]))
			goto err ;

	if (last) {
		lr = ptrace(PTRACE_PEEKTEXT,pid,&((long *)(long)addr)[x], 0) ;

		/* Y despues me quejo que lisp tiene muchos parentesis... */
		if ((lr == -1 && errno) ||
		    (
			ptrace(PTRACE_POKEDATA,pid,&((long *)(long)addr)[x],((lr&(-1L<<last)) |
			(((long *)buff)[x]&(~(-1L<<last)))))
		    )
		   )
                goto err;
	}

	return sz;

        err:
	return --x * sizeof(long) ;
}

static int __write(struct r_io_t *io, int pid, const ut8 *buf, int len)
{
	return ptrace_write_at(pid, buf, len, io->seek);
}

static int __handle_open(struct r_io_t *io, const char *file)
{
	if (!memcmp(file, "ptrace://", 9))
		return R_TRUE;
	if (!memcmp(file, "attach://", 9))
		return R_TRUE;
	return R_FALSE;
}

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

static ut64 __lseek(struct r_io_t *io, int fildes, ut64 offset, int whence)
{
	return -1;
}

static int __close(struct r_io_t *io, int pid)
{
	return ptrace(PTRACE_DETACH, pid, 0, 0);
}

static int __system(struct r_io_t *io, int fd, const char *cmd)
{
	//printf("ptrace io command (%s)\n", cmd);
#if __linux__
#include <sys/user.h>
#include <limits.h>
	/* XXX ugly hack for testing purposes */
	if (!strcmp(cmd, "reg")) {
		struct user_regs_struct regs;
		memset(&regs,0, sizeof(regs));
		// TODO: swap 3-4 args in powerpc
		ptrace(PTRACE_GETREGS, fd, 0, &regs);
#if __WORDSIZE == 64
		r_cons_printf("f rax @ 0x%08lx\n", regs.rax);
		r_cons_printf("f rbx @ 0x%08lx\n", regs.rbx);
		r_cons_printf("f rcx @ 0x%08lx\n", regs.rcx);
		r_cons_printf("f rdx @ 0x%08lx\n", regs.rdx);
		r_cons_printf("f r8 @ 0x%08lx\n", regs.r8);
		r_cons_printf("f r9 @ 0x%08lx\n", regs.r9);
		r_cons_printf("f r10 @ 0x%08lx\n", regs.r10);
		r_cons_printf("f r11 @ 0x%08lx\n", regs.r11);
		r_cons_printf("f r12 @ 0x%08lx\n", regs.r12);
		r_cons_printf("f r13 @ 0x%08lx\n", regs.r13);
		r_cons_printf("f r14 @ 0x%08lx\n", regs.r14);
		r_cons_printf("f r15 @ 0x%08lx\n", regs.r15);
		r_cons_printf("f rsi @ 0x%08lx\n", regs.rsi);
		r_cons_printf("f rdi @ 0x%08lx\n", regs.rdi);
		r_cons_printf("f rsp @ 0x%08lx\n", regs.rsp);
		r_cons_printf("f rbp @ 0x%08lx\n", regs.rbp);
		r_cons_printf("f rip @ 0x%08lx\n", regs.rip);
#else
		r_cons_printf("f eax @ 0x%08x\n", regs.eax);
		r_cons_printf("f ebx @ 0x%08x\n", regs.ebx);
		r_cons_printf("f ecx @ 0x%08x\n", regs.ecx);
		r_cons_printf("f edx @ 0x%08x\n", regs.edx);
		r_cons_printf("f eip @ 0x%08x\n", regs.eip);
		r_cons_printf("f ebp @ 0x%08x\n", regs.ebp);
		r_cons_printf("f esp @ 0x%08x\n", regs.esp);
#endif
	} else {
		printf("Try: '|reg'\n");
	}
#endif
	return R_TRUE;
}

static int __init(struct r_io_t *io)
{
	printf("ptrace init\n");
	return R_TRUE;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
struct r_io_handle_t r_io_plugin_ptrace = {
        //void *handle;
	.name = "io_ptrace",
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
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace
};
#endif
#endif

#endif

