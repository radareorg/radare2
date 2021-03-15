/* radare - LGPL - Copyright 2009-2021 - pancake */

#ifndef R2_SYSCALL_H
#define R2_SYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>
#include <r_util.h>
#include <sdb.h>

R_LIB_VERSION_HEADER (r_syscall);

#define R_SYSCALL_ARGS 7

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
	char *cpu;
	// database
	RSyscallItem *sysptr;
	RSyscallPort *sysport;
	Sdb *db;
	Sdb *srdb;
	int refs;
} RSyscall;

#if 0
// todo: add the ability to describe particular bits
typedef struct r_sysregs_item_t {
	ut64 address;
	ut64 size;
	int type;
	const char *name;
	const char *description;
} RSysregsItem;

typedef struct r_sysregs_t {
	FILE *fd;
	char *arch;
	char *cpu;
	RSysregsItem *sysregs;
	Sdb *db;
} RSysregs;
#endif

/* plugin struct */
typedef struct r_syscall_plugin_t {
	char *name;
	char *arch;
	char *os;
	char *desc;
	int bits;
	int nargs;
	struct r_syscall_args_t *args;
} RSyscallPlugin;

typedef struct r_syscall_arch_plugin_t {
	char *name;
	char *arch;
	char *desc;
	int *bits;
	int nargs;
	struct r_syscall_args_t **args;
} RSyscallArchPlugin;

#ifdef R_API
R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s);
R_API void r_syscall_item_free(RSyscallItem *si);

R_API RSyscall *r_syscall_new(void);
R_API void r_syscall_free(RSyscall *ctx);
R_API RSyscall* r_syscall_ref(RSyscall *sc);
R_API bool r_syscall_setup(RSyscall *s, const char *arch, int bits, const char *cpu, const char *os);
R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi);
R_API int r_syscall_get_num(RSyscall *ctx, const char *str);
R_API const char *r_syscall_get_i(RSyscall *ctx, int num, int swi);
R_API const char* r_syscall_sysreg(RSyscall *s, const char *type, ut64 num);
R_API RList *r_syscall_list(RSyscall *ctx);
R_API int r_syscall_get_swi(RSyscall *s);

/* io */
R_API const char *r_syscall_get_io(RSyscall *s, int ioport);
#endif

#ifdef __cplusplus
}
#endif

#endif
