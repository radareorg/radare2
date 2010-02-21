/* radare 2008-2010 GPL -- pancake <youterm.com> */

#include "r_types.h"
#include "r_syscall.h"
#include <stdio.h>
#include <string.h>

extern struct r_syscall_list_t syscalls_netbsd_x86[];
extern struct r_syscall_list_t syscalls_linux_x86[];
extern struct r_syscall_list_t syscalls_freebsd_x86[];
extern struct r_syscall_list_t syscalls_darwin_x86[];

R_API RSyscall* r_syscall_new() {
	RSyscall *ctx;
	ctx = (RSyscall*) malloc (sizeof (RSyscall));
	if (ctx == NULL)
		return NULL;
	ctx->fd = NULL;
	ctx->sysptr = syscalls_linux_x86;
	return ctx;
}

R_API void r_syscall_init(struct r_syscall_t *ctx) {
	ctx->fd = NULL;
	ctx->sysptr = syscalls_linux_x86;
}

R_API void r_syscall_free(struct r_syscall_t *ctx) {
	free (ctx);
}

R_API int r_syscall_setup(struct r_syscall_t *ctx, int os, int arch) {
	switch(arch) {
	case R_SYSCALL_ARCH_X86:
	default:
		switch(os) {
		case R_SYSCALL_OS_LINUX:
			ctx->sysptr = syscalls_linux_x86;
			break;
		case R_SYSCALL_OS_NETBSD:
		case R_SYSCALL_OS_OPENBSD:
			ctx->sysptr = syscalls_netbsd_x86;
			break;
		case R_SYSCALL_OS_FREEBSD:
			ctx->sysptr = syscalls_freebsd_x86;
			break;
		case R_SYSCALL_OS_DARWIN:
			ctx->sysptr = syscalls_darwin_x86;
			break;
		}
		break;
	}
	if (ctx->fd)
		fclose (ctx->fd);
	ctx->fd = NULL;
	return 0;
}

R_API int r_syscall_setup_file(struct r_syscall_t *ctx, const char *path) {
	if (ctx->fd)
		fclose (ctx->fd);
	ctx->fd = fopen (path, "r");
	if (ctx->fd == NULL)
		return 1;
	/* TODO: load info from file */
	return 0;
}

R_API int r_syscall_get(struct r_syscall_t *ctx, const char *str) {
	int i;
	for (i=0;ctx->sysptr[i].num;i++)
		if (!strcmp (str, ctx->sysptr[i].name))
			return ctx->sysptr[i].num;
	return 0;
}

R_API RSyscallList *r_syscall_get_n(struct r_syscall_t *ctx, int n)
{
	int i;
	for (i=0;ctx->sysptr[i].num && i!=n;i++)
		return &ctx->sysptr[i];
	return NULL;
}

R_API const char *r_syscall_get_i(struct r_syscall_t *ctx, int num, int swi)
{
	int i;
	for (i=0;ctx->sysptr[i].num;i++)
		if (num == ctx->sysptr[i].num && (swi == -1 || swi == ctx->sysptr[i].swi))
			return ctx->sysptr[i].name;
	return NULL;
}

R_API void r_syscall_list(struct r_syscall_t *ctx) {
	int i;
	for (i=0; ctx->sysptr[i].num; i++) {
		printf("%02x: %d = %s\n",
			ctx->sysptr[i].swi, ctx->sysptr[i].num, ctx->sysptr[i].name);
	}
}
