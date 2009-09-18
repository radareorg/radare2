#ifndef _INCLUDE_R_REG_H_
#define _INCLUDE_R_REG_H_

#include <r_types.h>
#include <list.h>

enum {
	R_REG_TYPE_GPR,
	R_REG_TYPE_DRX,
	R_REG_TYPE_FPU,
	R_REG_TYPE_MMX,
	R_REG_TYPE_XMM,
	R_REG_TYPE_LAST,
};

struct r_reg_item_t {
	char *name;
	int type;
	int size; /* 8,16,32,64 ... 128/256 ??? */
	int offset; // offset in data structure
	int packed_size; /* 0 means no packed register, 1byte pack, 2b pack... */
	struct list_head list;
};

struct r_reg_arena_t {
	ut8 *bytes;
	int size;
	struct list_head list;
};

struct r_reg_set_t {
	struct r_reg_arena_t *arena;
	struct list_head arenas; /* r_reg_arena_t */
	struct list_head regs;   /* r_reg_item_t */
};

struct r_reg_t {
	char *profile;
	struct r_reg_set_t regset[R_REG_TYPE_LAST];
};

#endif
