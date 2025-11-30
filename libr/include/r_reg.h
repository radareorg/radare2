#ifndef R2_REG_H
#define R2_REG_H

#include <r_list.h>
#include <r_types.h>
#include <r_util/r_ref.h>
#include <r_util/r_sys.h>
#include <r_util/r_hex.h>
#include <r_util/r_assert.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_reg);

/*
 * various CPUs have registers within various types/classes
 * this enum aims to cover them all.
 */
typedef enum r_reg_type_t {
	R_REG_TYPE_GPR = 0, // general purpose registers
	R_REG_TYPE_DRX, // debug register state
	R_REG_TYPE_FPU, // floating point unit
	R_REG_TYPE_VEC64, // MMX
	R_REG_TYPE_VEC128, // XMM
	R_REG_TYPE_VEC256, // YMM
	R_REG_TYPE_VEC512, // ZMM
	R_REG_TYPE_FLG, // cpu flags
	R_REG_TYPE_SEG, // segment registers
	R_REG_TYPE_PRI, // privileged registers
	R_REG_TYPE_LAST,
	R_REG_TYPE_ALL = -1, // TODO; rename to ANY
} RRegType;

/*
 * pretty much all CPUs share some common registers
 * this enum aims to create an abstraction to ease cross-arch handling.
 */
typedef enum r_reg_alias_t {
	R_REG_ALIAS_PC, // program counter
	R_REG_ALIAS_SP, // stack pointer
	R_REG_ALIAS_GP, // global pointer
	R_REG_ALIAS_RA, // return address register
	R_REG_ALIAS_SR, // status register
	R_REG_ALIAS_BP, // base pointer
	R_REG_ALIAS_LR, // link register
	R_REG_ALIAS_RS, // default register size
	/* args */
	R_REG_ALIAS_A0, // arguments
	R_REG_ALIAS_A1,
	R_REG_ALIAS_A2,
	R_REG_ALIAS_A3,
	R_REG_ALIAS_A4,
	R_REG_ALIAS_A5,
	R_REG_ALIAS_A6,
	R_REG_ALIAS_A7,
	R_REG_ALIAS_A8,
	R_REG_ALIAS_A9,
	/* retval */
	R_REG_ALIAS_R0, // return registers
	R_REG_ALIAS_R1,
	R_REG_ALIAS_R2,
	R_REG_ALIAS_R3,
	R_REG_ALIAS_F0, // float return registers
	R_REG_ALIAS_F1,
	R_REG_ALIAS_F2,
	R_REG_ALIAS_F3,
	/* flags */
	R_REG_ALIAS_ZF,
	R_REG_ALIAS_SF,
	R_REG_ALIAS_CF,
	R_REG_ALIAS_OF,
	/* thread register */
	R_REG_ALIAS_TR,
	/* syscall number (orig_eax,rax,r0,x0) */
	R_REG_ALIAS_SN,
	R_REG_ALIAS_LAST,
} RRegAlias;

// TODO: use enum here?
#define R_REG_COND_EQ 0
#define R_REG_COND_NE 1
#define R_REG_COND_CF 2
#define R_REG_COND_CARRY 2
#define R_REG_COND_NEG 3
#define R_REG_COND_NEGATIVE 3
#define R_REG_COND_OF 4
#define R_REG_COND_OVERFLOW 4
// unsigned
#define R_REG_COND_HI 5
#define R_REG_COND_HE 6
#define R_REG_COND_LO 7
#define R_REG_COND_LOE 8
// signed
#define R_REG_COND_GE 9
#define R_REG_COND_GT 10
#define R_REG_COND_LT 11
#define R_REG_COND_LE 12
#define R_REG_COND_LAST 13

typedef struct r_reg_item_t {
	char *name;
	int /*RRegType*/ type;
	int size; /* 8,16,32,64 ... 128/256??? rename to bitsize */
	int offset; /* offset in data structure */
	int packed_size; /* 0 means no packed register, 1byte pack, 2b pack... */
	bool is_float;
	char *flags;
	char *comment;
	int index;
	int arena; /* in which arena is this reg living */
	bool ro;
	R_REF_TYPE;
} RRegItem;

typedef struct r_reg_arena_t {
	ut8 *bytes;
	int size;
} RRegArena;

typedef struct r_reg_set_t {
	RRegArena *arena;
	RList *pool; /* RRegArena */
	RList *regs; /* RRegItem */
	HtPP *ht_regs; /* name:RRegItem */
	RListIter *cur; /* RRegArenaIter */
	int maskregstype; /* which type of regs have this reg set (logic mask with RRegType  R_REG_TYPE_XXX) */
} RRegSet; // Rename to RegGroup, because Set can be confusing with the 'set' keyword

typedef struct r_reg_t {
	char *profile;
	char *reg_profile_cmt;
	char *reg_profile_str;
	char *alias[R_REG_ALIAS_LAST];
	RRegSet regset[R_REG_TYPE_LAST];
	RList *allregs;
	char *roregs;
	RSysBits hasbits;
	int iters;
	int size;
	int bits_default;
	ut32 endian;
	R_REF_TYPE;
} RReg;

R_API bool r_reg_hasbits_check(RReg *reg, int size);
R_API bool r_reg_hasbits_use(RReg *reg, int size);
R_API void r_reg_hasbits_clear(RReg *reg);
R_API RReg *r_reg_clone(RReg *reg);

typedef struct r_reg_flags_t {
	bool s; // sign, negative number (msb)
	bool z; // zero
	bool a; // half-carry adjust (if carry happens at nibble level)
	bool c; // carry
	bool o; // overflow
	bool p; // parity (lsb)
} RRegFlags;

#ifdef R_API

// internal
R_IPI void r_reg_free_internal(RReg *reg, bool init);
R_IPI void r_reg_reindex(RReg *reg);
R_IPI void r_reg_item_free(RRegItem *item);

// lifecicle
R_API void r_reg_free(RReg *reg);
R_API RReg *r_reg_new(void);
R_API RReg *r_reg_init(RReg *reg);

// alias
R_API bool r_reg_alias_setname(RReg *reg, RRegAlias alias, const char *name);
R_API const char *r_reg_alias_tostring(RRegAlias alias);
R_API const char *r_reg_alias_getname(RReg *reg, RRegAlias alias);
R_API int r_reg_alias_fromstring(const char *type);

// profile // R2_600 - refactor this api
R_API bool r_reg_set_profile_string(RReg *reg, const char *profile);
R_API char *r_reg_profile_to_cc(RReg *reg);
R_API bool r_reg_set_profile(RReg *reg, const char *profile);
R_API char *r_reg_parse_gdb_profile(const char *profile);

R_API bool r_reg_ro_reset(RReg *reg, const char *arg);

R_API RRegSet *r_reg_regset_get(RReg *r, int type);
R_API ut64 r_reg_getv(RReg *reg, const char *name);
R_API bool r_reg_setv(RReg *reg, const char *name, ut64 val);
R_API const char *r_reg_32_to_64(RReg *reg, const char *rreg32);
R_API const char *r_reg_64_to_32(RReg *reg, const char *rreg64);

R_API RRegItem *r_reg_get(RReg *reg, const char *name, int type);
R_API RList *r_reg_get_list(RReg *reg, int type);
R_API RRegItem *r_reg_get_at(RReg *reg, int type, int regsize, int delta);
R_API RRegItem *r_reg_next_diff(RReg *reg, int type, const ut8 *buf, int buflen, RRegItem *prev_ri, int regsize);

// TODO: rename to RReg.getAt?
R_API RRegItem *r_reg_index_get(RReg *reg, int idx);

R_API int r_reg_type_by_name(const char *str); // rename to rreg_type_fromstring
R_API const char *r_reg_type_tostring(int idx);

// cond apis
R_API bool r_reg_cond(RReg *r, int type);
R_API RRegItem *r_reg_cond_get(RReg *reg, const char *name);
R_API void r_reg_cond_apply(RReg *r, RRegFlags *f);
R_API bool r_reg_cond_set(RReg *reg, const char *name, bool val);
R_API bool r_reg_cond_get_value(RReg *r, const char *name);
R_API bool r_reg_cond_bits_set(RReg *r, int type, RRegFlags *f, bool v);
R_API bool r_reg_cond_bits(RReg *r, int type, RRegFlags *f);
R_API RRegFlags *r_reg_cond_retrieve(RReg *r, RRegFlags *);

/* integer value 8-64 bits */
R_API ut64 r_reg_get_value(RReg *reg, RRegItem *item);
R_API ut64 r_reg_get_value_big(RReg *reg, RRegItem *item, utX *val);
R_API ut64 r_reg_get_value_by_role(RReg *reg, RRegAlias alias);
R_API bool r_reg_set_value(RReg *reg, RRegItem *item, ut64 value);
R_API bool r_reg_set_value_by_role(RReg *reg, RRegAlias alias, ut64 value);

/* float */
R_API float r_reg_get_float(RReg *reg, RRegItem *item);
R_API bool r_reg_set_float(RReg *reg, RRegItem *item, float value);

/* double */
R_API double r_reg_get_double(RReg *reg, RRegItem *item);
R_API bool r_reg_set_double(RReg *reg, RRegItem *item, double value);

/* long double */
R_API long double r_reg_get_longdouble(RReg *reg, RRegItem *item);
R_API bool r_reg_set_longdouble(RReg *reg, RRegItem *item, long double value);

/* boolean */
R_API char *r_reg_get_bvalue(RReg *reg, RRegItem *item);
R_API ut64 r_reg_set_bvalue(RReg *reg, RRegItem *item, const char *str);

/* packed registers */
R_API bool r_reg_set_pack(RReg *reg, RRegItem *item, int packidx, int packbits, ut64 val);
R_API ut64 r_reg_get_pack(RReg *reg, RRegItem *item, int packidx, int packbits);

R_API int r_reg_default_bits(RReg *reg);
R_API int r_reg_default_endian(RReg *reg);

/* byte arena */
R_API ut8 *r_reg_get_bytes(RReg *reg, int type, int *size);
R_API bool r_reg_set_bytes(RReg *reg, int type, const ut8 *buf, const int len);
R_API bool r_reg_read_regs(RReg *reg, ut8 *buf, const int len);
R_API int r_reg_arena_set_bytes(RReg *reg, const char *str);
R_API RRegArena *r_reg_arena_new(int size);
R_API RRegArena *r_reg_arena_clone(RRegArena *a);
R_API void r_reg_arena_free(RRegArena *ra);
R_API void r_reg_fit_arena(RReg *reg);
R_API void r_reg_arena_swap(RReg *reg, int copy);
R_API int r_reg_arena_push(RReg *reg);
R_API void r_reg_arena_pop(RReg *reg);
R_API void r_reg_arena_zero(RReg *reg);

R_API ut8 *r_reg_arena_peek(RReg *reg, int *len);
R_API void r_reg_arena_poke(RReg *reg, const ut8 *buf, int len);
R_API ut8 *r_reg_arena_dup(RReg *reg, const ut8 *source);
R_API const char *r_reg_cond_tostring(int n);
R_API int r_reg_cond_from_string(const char *str);
R_API void r_reg_arena_shrink(RReg *reg);

#ifdef __cplusplus
}
#endif

#endif
#endif
