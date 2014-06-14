/* radare - LGPL - Copyright 2009-2013 - pancake */

#ifndef R2_SYSCALL_H
#define R2_SYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>
#include <r_db.h>
#include <list.h>

R_LIB_VERSION_HEADER (r_syscall);

#define R_SYSCALL_ARGS 7

typedef struct r_syscall_regs_t {
	const char *arg[R_SYSCALL_ARGS];
} RSyscallRegs;

typedef struct r_syscall_item_t {
	char *name;
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
	// memoization
	char *arch;
	char *os;
	int bits;
	// database
	RSyscallRegs *regs;
	RSyscallItem *sysptr;
	RSyscallPort *sysport;
	Sdb *db;
	// TODO: deprecate
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
R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s);
R_API void r_syscall_item_free(RSyscallItem *si);

R_API RSyscall *r_syscall_new();
R_API void r_syscall_free(RSyscall *ctx);
R_API int r_syscall_setup(RSyscall *ctx, const char *arch, const char *os, int bits);
R_API int r_syscall_setup_file(RSyscall *ctx, const char *path);
R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi);
R_API int r_syscall_get_num(RSyscall *ctx, const char *str);
R_API const char *r_syscall_get_i(RSyscall *ctx, int num, int swi);
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num);
R_API RList *r_syscall_list(RSyscall *ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif
