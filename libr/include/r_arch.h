/* radare2 - LGPL - Copyright 2022 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_anal/op.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_arch);
#include <r_util.h>
struct r_reg_item_t;
struct r_reg_t;
#include <r_reg.h>
#include <r_io.h>
#include <sdb.h>

enum {
	R_ARCH_SYNTAX_NONE = 0,
	R_ARCH_SYNTAX_INTEL,
	R_ARCH_SYNTAX_ATT,
	R_ARCH_SYNTAX_MASM,
	R_ARCH_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	R_ARCH_SYNTAX_JZ, // hack to use jz instead of je on x86
};

// TODO: add reference counting and accessor APIs
typedef struct r_arch_config_t {
	char *decoder;
	char *arch;
	char *cpu;
	char *os;
	int bits;
	union {
		int big_endian;
		ut32 endian;
	};
	int syntax;
	//
	int pcalign;
	int dataalign;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *abi;
	R_REF_TYPE;
} RArchConfig;

#define	R_ARCH_CONFIG_IS_BIG_ENDIAN(cfg_)	(((cfg_)->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG)


#define R_ARCH_INFO_MIN_OP_SIZE	0
#define R_ARCH_INFO_MAX_OP_SIZE	1
#define R_ARCH_INFO_INV_OP_SIZE	2
#define R_ARCH_INFO_ALIGN	4
#define R_ARCH_INFO_DATA_ALIGN	8
#define R_ARCH_INFO_JMPMID	16	//supported jmpmid

#if 0
// R2_580 use this format instead?
#define	R_ARCH_OP_MASK_BASIC	0	// Just fills basic op info , it's fast
#define R_ARCH_OP_MASK_ESIL	1	// It fills RAnalop->esil info
#define R_ARCH_OP_MASK_VAL	2	// It fills RAnalop->dst/src info
#define	R_ARCH_OP_MASK_OPEX	4	// It fills RAnalop->opex info
#define	R_ARCH_OP_MASK_DISASM	8	// It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
#else
// TODO rename to RAnalDecodeMask.ESIL, ...
typedef enum {
	R_ARCH_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
	R_ARCH_OP_MASK_ESIL  = 1, // It fills RAnalop->esil info
	R_ARCH_OP_MASK_VAL   = 2, // It fills RAnalop->dst/src info
	R_ARCH_OP_MASK_HINT  = 4, // It calls r_anal_op_hint to override anal options
	R_ARCH_OP_MASK_OPEX  = 8, // It fills RAnalop->opex info
	R_ARCH_OP_MASK_DISASM = 16, // It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
	R_ARCH_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16
} RAnalOpMask;

// XXX backward compatible, shouldnt be used
#define R_ANAL_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
#define R_ANAL_OP_MASK_ESIL  = 1, // It fills RAnalop->esil info
#define R_ANAL_OP_MASK_VAL   = 2, // It fills RAnalop->dst/src info
#define R_ANAL_OP_MASK_HINT  = 4, // It calls r_anal_op_hint to override anal options
#define R_ANAL_OP_MASK_OPEX  = 8, // It fills RAnalop->opex info
#define R_ANAL_OP_MASK_DISASM = 16, // It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
#define R_ANAL_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16
#endif

typedef struct r_arch_decoder_t {
	struct r_arch_plugin_t *p;
	void *user;
	ut32 refctr;
} RArchDecoder;

typedef struct r_arch_t {
	RList *plugins;	//all plugins
	RArchDecoder *current;	//currently used decoder
	HtPP *decoders;	//as decoders instantiated plugins
	RArchConfig *cfg;	//config
	bool autoselect;
} RArch;

typedef struct r_arch_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	char *cpus;
	ut32 endian;
	ut32 bits;
	ut32 addr_bits;
	bool esil;
	bool (*init)(void **user);
	void (*fini)(void *user);
	int (*info)(RArchConfig *cfg, ut32 query);
	int (*decode)(RArchConfig *cfg, struct r_anal_op_t *op, ut64 addr, const ut8 *data, int len, ut32 mask, void *user);
	bool (*set_reg_profile)(RArchConfig *cfg, struct r_reg_t *reg);
//TODO: reenable this later
//	bool (*esil_init)(RAnalEsil *esil);
//	void (*esil_fini)(RAnalEsil *esil);
} RArchPlugin;

// decoder.c
//dname is name of decoder to use, NULL if current
R_API bool r_arch_load_decoder(RArch *arch, const char *dname);
R_API bool r_arch_use_decoder(RArch *arch, const char *dname);
R_API bool r_arch_unload_decoder(RArch *arch, const char *dname);
R_API int r_arch_info(RArch *arch, const char *dname, ut32 query);
R_API int r_arch_decode(RArch *arch, const char *dname, struct r_anal_op_t *op, ut64 addr, const ut8 *data, int len, ut32 mask);
R_API bool r_arch_set_reg_profile(RArch *arch, const char *dname, struct r_reg_t *reg);
//R_API bool r_arch_esil_init(RArch *arch, const char *dname, RAnalEsil *esil);
//R_API void r_arch_esil_fini(RArch *arch, const char *dname, RAnalEsil *esil);

// arch.c
R_API RArch *r_arch_new(void);
R_API bool r_arch_use(RArch *arch, RArchConfig *config);
R_API bool r_arch_set_bits(RArch *arch, ut32 bits);
R_API bool r_arch_set_endian(RArch *arch, ut32 endian);
R_API bool r_arch_set_arch(RArch *arch, char *archname);
R_API bool r_arch_add(RArch *arch, RArchPlugin *ap);
R_API bool r_arch_del(RArch *arch, const char *name);
R_API void r_arch_free(RArch *arch);

// aconfig.c
R_API void r_arch_config_use(RArchConfig *config, R_NULLABLE const char *arch);
R_API void r_arch_config_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu);
R_API void r_arch_config_set_bits(RArchConfig *config, int bits);
R_API RArchConfig *r_arch_config_new(void);

// switchop
#if 0
R_API RArchSwitchOp *r_arch_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val);
R_API RArchCaseOp *r_arch_case_op_new(ut64 addr, ut64 val, ut64 jump);
R_API void r_arch_switch_op_free(RArchSwitchOp *swop);
R_API RArchCaseOp* r_arch_switch_op_add_case(RArchSwitchOp *swop, ut64 addr, ut64 value, ut64 jump);
#endif

// archvalue.c
#if 0
// still in anal
R_API RAnalValue *r_arch_value_new(void);
R_API RArchValue *r_arch_value_copy(RArchValue *ov);
R_API void r_arch_value_free(RArchValue *value);
R_API ut64 r_arch_value_to_ut64(RArchValue *val, struct r_reg_t *reg);
R_API bool r_arch_value_set_ut64(RArchValue *val, struct r_reg_t *reg, RIOBind *iob, ut64 num);
R_API char *r_arch_value_tostring(RArchValue *value);
#endif

R_API int r_arch_optype_from_string(const char *type);
R_API const char *r_arch_optype_tostring(int t);
R_API const char *r_arch_stackop_tostring(int s);

// MOVE BACK TO ANAL
// archop.c
#if 0
R_API RAnalOp *r_arch_op_new(void);
R_API void r_arch_op_init(RAnalOp *op);
R_API void r_arch_op_fini(RAnalOp *op);
R_API void r_arch_op_free(void *_op);
#endif
R_API const char *r_arch_op_family_tostring(int n);
R_API int r_arch_op_family_from_string(const char *f);
R_API const char *r_arch_op_direction_tostring(struct r_anal_op_t *op);

// archcond.c
// R_API const char *r_arch_cond_tostring(RArchCond cc);

extern RArchPlugin r_arch_plugin_null;
extern RArchPlugin r_arch_plugin_i4004;
extern RArchPlugin r_arch_plugin_amd29k;

#ifdef __cplusplus
}
#endif

#endif
