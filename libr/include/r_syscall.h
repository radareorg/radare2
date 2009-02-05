#ifndef _INCLUDE_R_SYSCALL_H_
#define _INCLUDE_R_SYSCALL_H_

#include "r_types.h"

struct r_syscall_list_t {
	const char *name;
	int swi;
	int num;
	int args;
};

// TODO: use this as arg to store state :)
struct r_syscall_t {
#if 0
	int arch; // XXX char *??
	int os;
#endif
	FILE *fd;
	struct r_syscall_list_t *sysptr;
};

enum {
	R_SYSCALL_OS_LINUX = 0,
	R_SYSCALL_OS_NETBSD,
	R_SYSCALL_OS_OPENBSD,
	R_SYSCALL_OS_FREEBSD,
	R_SYSCALL_OS_DARWIN
};

enum {
	R_SYSCALL_ARCH_X86 = 0,
	R_SYSCALL_ARCH_PPC,
	R_SYSCALL_ARCH_ARM,
	R_SYSCALL_ARCH_MIPS,
	R_SYSCALL_ARCH_SPARC
};

#define R_SYSCALL_CTX struct r_syscall_t 
R_SYSCALL_CTX *r_syscall_new();
void r_syscall_free(R_SYSCALL_CTX *ctx);
void r_syscall_init(struct r_syscall_t *ctx);

int r_syscall_setup(R_SYSCALL_CTX *ctx, int arch, int os);
int r_syscall_setup_file(R_SYSCALL_CTX *ctx, const char *path);
int r_syscall_get(R_SYSCALL_CTX *ctx, const char *str);
struct r_syscall_list_t *r_syscall_get_n(R_SYSCALL_CTX *ctx, int n);
const char *r_syscall_get_i(R_SYSCALL_CTX *ctx, int num, int swi);
void r_syscall_list(R_SYSCALL_CTX *ctx);

#endif

