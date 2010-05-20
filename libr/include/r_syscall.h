#ifndef _INCLUDE_R_SYSCALL_H_
#define _INCLUDE_R_SYSCALL_H_

#include <r_types.h>
#include <list.h>

typedef struct r_syscall_item_t {
	const char *name;
	int swi;
	int num;
	int args;
	char *sargs;
} RSyscallItem;

typedef struct r_syscall_t {
	FILE *fd;
	// TODO char *arch;
	// TODO char *os;
	RSyscallItem *sysptr;
} RSyscall;

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
R_API RSyscall *r_syscall_new();
R_API void r_syscall_free(RSyscall *ctx);
R_API int r_syscall_setup(RSyscall *ctx, const char *arch, const char *os);
R_API int r_syscall_setup_file(RSyscall *ctx, const char *path);
R_API RSyscallItem *r_syscall_get(RSyscall *ctx, int num, int swi);
R_API int r_syscall_get_num(RSyscall *ctx, const char *str);
R_API RSyscallItem *r_syscall_get_n(RSyscall *ctx, int n); // broken iterator.. must remove
R_API const char *r_syscall_get_i(RSyscall *ctx, int num, int swi); // XXX const char *
R_API void r_syscall_list(RSyscall *ctx);
#endif

#endif
