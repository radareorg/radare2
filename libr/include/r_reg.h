#ifndef _INCLUDE_R_REG_H_
#define _INCLUDE_R_REG_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>
R_LIB_VERSION_HEADER(r_reg);

enum {
	R_REG_TYPE_GPR,
	R_REG_TYPE_DRX,
	R_REG_TYPE_FPU,
	R_REG_TYPE_MMX,
	R_REG_TYPE_XMM,
	R_REG_TYPE_FLG,
	R_REG_TYPE_SEG,
	R_REG_TYPE_LAST,
	R_REG_TYPE_ALL = -1,
};

enum {
	R_REG_NAME_PC, // program counter
	R_REG_NAME_SP, // stack pointer
	R_REG_NAME_SR, // status register
	R_REG_NAME_BP, // base pointer
	R_REG_NAME_A0, // arguments
	R_REG_NAME_A1,
	R_REG_NAME_A2,
	R_REG_NAME_A3,
	R_REG_NAME_LAST,
};

typedef struct r_reg_item_t {
	char *name;
	int type;
	int size; /* 8,16,32,64 ... 128/256 ??? */
	int offset; // offset in data structure
	int packed_size; /* 0 means no packed register, 1byte pack, 2b pack... */
	char *flags;
} RRegItem;

typedef struct r_reg_arena_t {
	ut8 *bytes;
	int size;
} RRegArena;

typedef struct r_reg_set_t {
	RRegArena *arena;
	RList *pool; /* RRegArena */
	RList *regs; /* RRegItem */
} RRegSet;

typedef struct r_reg_t {
	char *profile;
	char *reg_profile_str;
	char *name[R_REG_NAME_LAST];
	RRegSet regset[R_REG_TYPE_LAST];
	int iters;
} RReg;


#ifdef R_API
R_API void r_reg_free(RReg *reg);
R_API RReg *r_reg_new();
R_API int r_reg_set_name(RReg *reg, int role, const char *name);
R_API int r_reg_set_profile_string(RReg *reg, const char *profile);
R_API int r_reg_set_profile(RReg *reg, const char *profile);

R_API ut64 r_reg_getv(RReg *reg, const char *name);
R_API const char *r_reg_get_type(int idx);
R_API const char *r_reg_get_name(RReg *reg, int kind);
R_API RRegItem *r_reg_get(RReg *reg, const char *name, int type);
R_API RList *r_reg_get_list(RReg *reg, int type);

/* XXX: dupped ?? */
R_API int r_reg_type_by_name(const char *str);
R_API int r_reg_get_name_idx(const char *type);

/* value */
R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item);
R_API int r_reg_set_value(RReg *reg, RRegItem *item, ut64 value);
R_API float r_reg_get_fvalue(RReg *reg, RRegItem *item);
R_API int r_reg_set_fvalue(RReg *reg, RRegItem *item, float value);
R_API ut64 r_reg_get_pvalue(RReg *reg, RRegItem *item, int packidx);
R_API char *r_reg_get_bvalue(RReg *reg, RRegItem *item);
R_API int r_reg_set_pvalue(RReg *reg, RRegItem *item, ut64 value, int packidx);

/* byte arena */
R_API ut8* r_reg_get_bytes(RReg *reg, int type, int *size);
R_API int r_reg_set_bytes(RReg *reg, int type, const ut8* buf, int len);
R_API RRegArena *r_reg_arena_new (int size);
R_API void r_reg_arena_free(RRegArena* ra);
R_API int r_reg_fit_arena(RReg *reg);
R_API int r_reg_arena_set(RReg *reg, int n, int copy);
R_API void r_reg_arena_swap(RReg *reg, int copy);
R_API int r_reg_arena_push(RReg *reg);
R_API void r_reg_arena_pop(RReg *reg);
R_API ut64 r_reg_cmp(RReg *reg, RRegItem *item);
#endif

#endif
