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
	u64 value;
	int type;
	char *get;
	char *set;
	struct list_head list;
};

struct r_vm_op_t {
	const char opcode[32];
	const char code[1024];
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
	u64 from;
	u64 to;
	u8 *data;
	struct list_head list;
};

struct r_vm_t {
	struct r_vm_reg_t *rec;
	struct list_head regs;
	struct r_vm_cpu_t cpu;
	struct list_head ops;
	u64 vm_stack_base;
	u8 *vm_stack;
	struct list_head mmu_cache;
	int realio;
};

u64 vm_reg_get(const char *name);
void vm_stack_push(u64 _val);

#if 0
static u64 r_vm_get_value(struct r_vm_t *vm, const char *str);
static u64 r_vm_get_math(struct r_vm_t *vm, const char *str);
#endif
void r_vm_print(struct r_vm_t *vm, int type);
int r_vm_import(struct r_vm_t *vm, int in_vm);
void r_vm_cpu_call(struct r_vm_t *vm, u64 addr);
int r_vm_init(struct r_vm_t *vm, int init);
int r_vm_eval_cmp(struct r_vm_t *vm, const char *str);
int r_vm_eval_eq(struct r_vm_t *vm, const char *str, const char *val);
int r_vm_eval_single(struct r_vm_t *vm, const char *str);
int r_vm_eval(struct r_vm_t *vm, const char *str);
int r_vm_eval_file(struct r_vm_t *vm, const char *str);
int r_vm_emulate(struct r_vm_t *vm, int n);
int r_vm_cmd_reg(struct r_vm_t *vm, const char *_str);
int r_vm_op_add(struct r_vm_t *vm, const char *op, const char *str);
int r_vm_op_eval(struct r_vm_t *vm, const char *str);
int r_vm_op_cmd(struct r_vm_t *vm, const char *op);

/* reg */
void r_vm_reg_type_list();
int r_vm_reg_add(struct r_vm_t *vm, const char *name, int type, u64 value);
u64 r_vm_reg_get(struct r_vm_t *vm, const char *name);
int r_vm_reg_alias_list(struct r_vm_t *vm);
const char *r_vm_reg_type(int type);
const int r_vm_reg_type_i(const char *str);
int r_vm_reg_del(struct r_vm_t *vm, const char *name);
int r_vm_reg_set(struct r_vm_t *vm, const char *name, u64 value);
int r_vm_reg_alias(struct r_vm_t *vm, const char *name, const char *get, const char *set);

/* cfg */

void r_vm_setup_flags(struct r_vm_t *vm, const char *zf);
void r_vm_setup_cpu(struct r_vm_t *vm, const char *eip, const char *esp, const char *ebp);
void r_vm_setup_fastcall(struct r_vm_t *vm, const char *eax, const char *ebx, const char *ecx, const char *edx);
void r_vm_setup_ret(struct r_vm_t *vm, const char *eax);

/* stack */
void r_vm_stack_push(struct r_vm_t *vm, u64 _val);
void r_vm_stack_pop(struct r_vm_t *vm, const char *reg);

/* mmu */
int r_vm_mmu_cache_write(struct r_vm_t *vm, u64 addr, u8 *buf, int len);
int r_vm_mmu_cache_read(struct r_vm_t *vm, u64 addr, u8 *buf, int len);
int r_vm_mmu_read(struct r_vm_t *vm, u64 off, u8 *data, int len);
int r_vm_mmu_write(struct r_vm_t *vm, u64 off, u8 *data, int len);
int r_vm_mmu_real(struct r_vm_t *vm, int set);

#endif
