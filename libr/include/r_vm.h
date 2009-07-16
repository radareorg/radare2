#ifndef _INCLUDE_R_VM_H_
#define _INCLUDE_R_VM_H_

#include "r_types.h"
#include "r_io.h"
#include "r_util.h"
#include "list.h"

#if R_VM_USE_CONS
#define printf r_cons_printf
#endif

#define R_VM_ALEN 5 // XXX //

#define R_VMREG_BIT   1
#define R_VMREG_INT8  2
#define R_VMREG_INT16 3
#define R_VMREG_INT32 4
#define R_VMREG_INT64 5
#define R_VMREG_FLOAT32 6
#define R_VMREG_FLOAT64 7

struct r_vm_reg_t {
	char name[16];
	ut64 value;
	int type;
	char *get;
	char *set;
	struct list_head list;
};

struct r_vm_op_t {
	char opcode[32];
	char code[1024];
	struct list_head list;
};

struct r_vm_reg_type {
	int type;
	char *str;
};

struct r_vm_cpu_t {
	const char *pc;
	const char *sp;
	const char *bp;
	const char *ctr;
	const char *a0;
	const char *a1;
	const char *a2;
	const char *a3;
	const char *ret;
	const char *zf;
};

struct r_vm_change_t {
	ut64 from;
	ut64 to;
	ut8 *data;
	struct list_head list;
};

struct r_vm_t {
	struct r_vm_reg_t *rec;
	struct list_head regs;
	struct r_vm_cpu_t cpu;
	struct list_head ops;
	ut64 vm_stack_base;
	ut8 *vm_stack;
	struct list_head mmu_cache;
	int realio;
	/* io callbacks */
	int (*read)(void *user, ut64 addr, ut8 *buf, int len);
	int (*write)(void *user, ut64 addr, ut8 *buf, int len);
	void *user;
};

R_API ut64 vm_reg_get(const char *name);
R_API void vm_stack_push(ut64 _val);

#if 0
static ut64 r_vm_get_value(struct r_vm_t *vm, const char *str);
static ut64 r_vm_get_math(struct r_vm_t *vm, const char *str);
#endif
R_API void r_vm_print(struct r_vm_t *vm, int type);
R_API int r_vm_import(struct r_vm_t *vm, int in_vm);
R_API void r_vm_cpu_call(struct r_vm_t *vm, ut64 addr);
R_API int r_vm_init(struct r_vm_t *vm, int init);
R_API int r_vm_eval_cmp(struct r_vm_t *vm, const char *str);
R_API int r_vm_eval_eq(struct r_vm_t *vm, const char *str, const char *val);
R_API int r_vm_eval_single(struct r_vm_t *vm, const char *str);
R_API int r_vm_eval(struct r_vm_t *vm, const char *str);
R_API int r_vm_eval_file(struct r_vm_t *vm, const char *str);
R_API int r_vm_emulate(struct r_vm_t *vm, int n);
R_API int r_vm_cmd_reg(struct r_vm_t *vm, const char *_str);
R_API int r_vm_op_add(struct r_vm_t *vm, const char *op, const char *str);
R_API int r_vm_op_eval(struct r_vm_t *vm, const char *str);
R_API int r_vm_op_cmd(struct r_vm_t *vm, const char *op);

/* reg */
R_API void r_vm_reg_type_list();
R_API int r_vm_reg_add(struct r_vm_t *vm, const char *name, int type, ut64 value);
R_API ut64 r_vm_reg_get(struct r_vm_t *vm, const char *name);
R_API int r_vm_reg_alias_list(struct r_vm_t *vm);
R_API const char *r_vm_reg_type(int type);
R_API const int r_vm_reg_type_i(const char *str);
R_API int r_vm_reg_del(struct r_vm_t *vm, const char *name);
R_API int r_vm_reg_set(struct r_vm_t *vm, const char *name, ut64 value);
R_API int r_vm_reg_alias(struct r_vm_t *vm, const char *name, const char *get, const char *set);

/* cfg */
R_API void r_vm_setup_flags(struct r_vm_t *vm, const char *zf);
R_API void r_vm_setup_cpu(struct r_vm_t *vm, const char *eip, const char *esp, const char *ebp);
R_API void r_vm_setup_fastcall(struct r_vm_t *vm, const char *eax, const char *ebx, const char *ecx, const char *edx);
R_API void r_vm_setup_ret(struct r_vm_t *vm, const char *eax);

/* stack */
R_API void r_vm_stack_push(struct r_vm_t *vm, ut64 _val);
R_API void r_vm_stack_pop(struct r_vm_t *vm, const char *reg);

/* mmu */
R_API int r_vm_mmu_cache_write(struct r_vm_t *vm, ut64 addr, ut8 *buf, int len);
R_API int r_vm_mmu_cache_read(struct r_vm_t *vm, ut64 addr, ut8 *buf, int len);
R_API int r_vm_mmu_read(struct r_vm_t *vm, ut64 off, ut8 *data, int len);
R_API int r_vm_mmu_write(struct r_vm_t *vm, ut64 off, ut8 *data, int len);
R_API int r_vm_mmu_real(struct r_vm_t *vm, int set);
R_API void r_vm_mmu_set_io(struct r_vm_t *vm,
	int (*read)(void *user, ut64 addr, ut8 *buf, int len),
	int (*write)(void *user, ut64 addr, ut8 *buf, int len),
	void *user);

/* extra */
int r_vm_cmd_op_help();
int r_vm_op_list(struct r_vm_t *vm);

#endif
