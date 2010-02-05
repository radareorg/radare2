#ifndef _INCLUDE_R_REG_H_
#define _INCLUDE_R_REG_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>

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
	R_REG_NAME_PC,
	R_REG_NAME_SP,
	R_REG_NAME_BP,
	R_REG_NAME_A0,
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
	struct list_head list;
} RRegisterItem;

typedef struct r_reg_arena_t {
	ut8 *bytes;
	int size;
	struct list_head list;
} RRegisterArena;

typedef struct r_reg_set_t {
	struct r_reg_arena_t *arena;
	struct list_head arenas; /* r_reg_arena_t */
	struct list_head regs;   /* r_reg_item_t */
} RRegisterSet;

typedef struct r_reg_t {
	char *profile;
	char *name[R_REG_NAME_LAST];
	struct r_reg_set_t regset[R_REG_TYPE_LAST];
} RRegister;

#define r_reg_new() r_reg_init (R_NEW (RRegister))

#ifdef R_API
extern const char *r_reg_types[R_REG_TYPE_LAST+1];
R_API struct r_reg_t *r_reg_free(struct r_reg_t *reg);
R_API struct r_reg_t *r_reg_init(struct r_reg_t *reg);
//R_API struct r_reg_t *r_reg_new();
R_API int r_reg_set_profile_string(struct r_reg_t *reg, const char *profile);
R_API int r_reg_set_profile(struct r_reg_t *reg, const char *profile);

R_API int r_reg_get_name_idx(const char *type);
R_API const char *r_reg_get_name(struct r_reg_t *reg, int kind);
R_API int r_reg_set_name(struct r_reg_t *reg, int role, const char *name);

R_API struct r_reg_item_t *r_reg_get(struct r_reg_t *reg, const char *name, int type);
R_API struct list_head *r_reg_get_list(struct r_reg_t *reg, int type);
R_API int r_reg_type_by_name(const char *str);

/* value */
R_API ut64 r_reg_get_value(struct r_reg_t *reg, struct r_reg_item_t *item);
R_API int r_reg_set_value(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value);
R_API float r_reg_get_fvalue(struct r_reg_t *reg, struct r_reg_item_t *item);
R_API int r_reg_set_fvalue(struct r_reg_t *reg, struct r_reg_item_t *item, float value);
R_API ut64 r_reg_get_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, int packidx);
R_API int r_reg_set_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value, int packidx);

/* byte arena */
R_API ut8* r_reg_get_bytes(struct r_reg_t *reg, int type, int *size);
R_API int r_reg_set_bytes(struct r_reg_t *reg, int type, const ut8* buf, int len);
R_API RRegisterArena *r_reg_arena_new (int size);
R_API int r_reg_fit_arena(struct r_reg_t *reg);
#endif

#endif
