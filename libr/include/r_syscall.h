#ifndef _INCLUDE_R_SYSCALL_H_
#define _INCLUDE_R_SYSCALL_H_

#include "r_types.h"
#include "list.h"

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

typedef struct r_syscall_list_t {
	const char *name;
	int swi;
	int num;
	int args;
	char *sargs;
} RSyscallList;

// TODO: use this as arg to store state :)
typedef struct r_syscall_t {
#if 0
	int arch; // XXX char *??
	int os;
#endif
	FILE *fd;
	struct r_syscall_list_t *sysptr;
} RSyscall;

//#define R_SYSCALL_CTX struct r_syscall_t 
/* plugin struct */
typedef struct r_syscall_handle_t {
	char *name;
	char *arch;
	char *os;
	char *desc;
	int bits;
	int nargs;
	struct r_syscall_args_t *args;
	struct list_head list;
} RSyscallHandle;

typedef struct r_syscall_arch_handle_t {
	char *name;
	char *arch;
	char *desc;
	int *bits;
	int nargs;
	struct r_syscall_args_t **args;
	struct list_head list;
} RSyscallArchHandle;

#ifdef R_API
struct r_syscall_t *r_syscall_new();
void r_syscall_free(struct r_syscall_t *ctx);
void r_syscall_init(struct r_syscall_t *ctx);

int r_syscall_setup(struct r_syscall_t *ctx, int arch, int os);
int r_syscall_setup_file(struct r_syscall_t *ctx, const char *path);
int r_syscall_get(struct r_syscall_t *ctx, const char *str);
struct r_syscall_list_t *r_syscall_get_n(struct r_syscall_t *ctx, int n);
const char *r_syscall_get_i(struct r_syscall_t *ctx, int num, int swi);
void r_syscall_list(struct r_syscall_t *ctx);
#endif

#endif
