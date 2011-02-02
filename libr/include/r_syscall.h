/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#ifndef _INCLUDE_R_SYSCALL_H_
#define _INCLUDE_R_SYSCALL_H_

#include <r_types.h>
#include <list.h>

#define R_SYSCALL_ARGS 6

typedef struct r_syscall_regs_t {
	const char *arg[16];
} RSyscallRegs;

typedef struct r_syscall_item_t {
	const char *name;
	int swi;
	int num;
	int args;
	char *sargs;
} RSyscallItem;

typedef struct r_syscall_port_t {
	int port;
	const char *name;
} RSyscallPort;

typedef struct r_syscall_t {
	FILE *fd;
	// TODO char *arch;
	// TODO char *os;
	RSyscallRegs *regs;
	RSyscallItem *sysptr;
	RSyscallPort *sysport;
	PrintfCallback printf;
} RSyscall;

/* plugin struct */
typedef struct r_syscall_plugin_t {
	char *name;
	char *arch;
	char *os;
	char *desc;
	int bits;
	int nargs;
	struct r_syscall_args_t *args;
	struct list_head list;
} RSyscallPlugin;

typedef struct r_syscall_arch_plugin_t {
	char *name;
	char *arch;
	char *desc;
	int *bits;
	int nargs;
	struct r_syscall_args_t **args;
	struct list_head list;
} RSyscallArchPlugin;

#ifdef R_API
R_API RSyscall *r_syscall_new();
R_API void r_syscall_free(RSyscall *ctx);
R_API int r_syscall_setup(RSyscall *ctx, const char *arch, const char *os);
R_API int r_syscall_setup_file(RSyscall *ctx, const char *path);
R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi);
R_API int r_syscall_get_num(RSyscall *ctx, const char *str);
R_API RSyscallItem *r_syscall_get_n(RSyscall *ctx, int n); // broken iterator.. must remove
R_API const char *r_syscall_get_i(RSyscall *ctx, int num, int swi); // XXX const char *
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num);
R_API void r_syscall_list(RSyscall *ctx);
#endif

#endif
