/* radare2 - LGPL - Copyright 2022 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_anal/op.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_arch);

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
	int pcalign;
	int dataalign;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *abi;
	R_REF_TYPE;
} RArchConfig;

#define	R_ARCH_CONFIG_IS_BIG_ENDIAN(cfg_) (((cfg_)->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG)

#define R_ARCH_INFO_MIN_OP_SIZE	0
#define R_ARCH_INFO_MAX_OP_SIZE	1
#define R_ARCH_INFO_INV_OP_SIZE	2
#define R_ARCH_INFO_ALIGN	4
#define R_ARCH_INFO_DATA_ALIGN	8
#define R_ARCH_INFO_JMPMID	16

typedef enum {
	R_ARCH_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
	R_ARCH_OP_MASK_ESIL  = 1, // It fills RAnalop->esil info
	R_ARCH_OP_MASK_VAL   = 2, // It fills RAnalop->dst/src info
	R_ARCH_OP_MASK_HINT  = 4, // It calls r_anal_op_hint to override anal options
	R_ARCH_OP_MASK_OPEX  = 8, // It fills RAnalop->opex info
	R_ARCH_OP_MASK_DISASM = 16, // It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
	R_ARCH_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16
} RAnalOpMask;

// XXX R2_590 - backward compatible, shouldnt be used
#define R_ANAL_OP_MASK_BASIC = 0, // Just fills basic op info , it's fast
#define R_ANAL_OP_MASK_ESIL  = 1, // It fills RAnalop->esil info
#define R_ANAL_OP_MASK_VAL   = 2, // It fills RAnalop->dst/src info
#define R_ANAL_OP_MASK_HINT  = 4, // It calls r_anal_op_hint to override anal options
#define R_ANAL_OP_MASK_OPEX  = 8, // It fills RAnalop->opex info
#define R_ANAL_OP_MASK_DISASM = 16, // It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
#define R_ANAL_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16

typedef struct r_arch_decoder_t {
	struct r_arch_plugin_t *p;
	void *user;
	ut32 refctr;
} RArchDecoder;

typedef struct r_arch_t {
	RList *plugins;	       // all plugins
	struct r_arch_instance_t *cur; // this var must deprecate current!
	RArchDecoder *current; // currently used decoder
	HtPP *decoders;        // as decoders instantiated plugins
	RArchConfig *cfg;      // config
	bool autoselect;
} RArch;

typedef struct r_arch_instance_t {
	struct r_arch_t *arch;
	struct r_arch_plugin_t *plugin;
	RArchConfig *config; // TODO remove arch->config!
	void *data;
	void *user;
} RArchInstance;

typedef int (*RArchOpAsmCallback)(RArch *a, ut64 addr, const char *str, ut8 *outbuf, int outlen);
// typedef int (*RArchPluginInfoCallback)(RArchInstance *i, ut32 query);
typedef int (*RArchPluginInfoCallback)(RArchConfig *cfg, ut32 query);
// typedef int (*RArchPluginDecodeCallback)(RArchConfig *cfg, struct r_anal_op_t *op, ut64 addr, const ut8 *data, int len, ut32 mask, void *user);
typedef int (*RArchPluginDecodeCallback)(RArch *cfg, struct r_anal_op_t *op, ut64 addr, const ut8 *data, int len, ut32 mask, void *user);
#if 0
// addr, data/len and *user can be taken from RAnalOp, so the user must fill those fields before calling this functions
R_API int r_arch_op_setbytes(op, ut64 addr, const ut8* data, int len);
typedef bool (*RArchPluginDecodeCallback)(RArchInstance *cfg, struct r_anal_op_t *op, RArchDecodeMask mask);
typedef bool (*RArchPluginEncodeCallback)(RArchInstance *cfg, struct r_anal_op_t *op);
/*
   RArchOp op;
   RArch *a = r_arch_new ();
   RArchConfig *cfg = r_arch_config_new ();
   RArchInstance *ai = r_arch_use (a, cfg, "x86");
   RArchOp *op = r_arch_new ();
   r_arch_op_setbytes (op, 0x10080840, "\x90", 1);
   if (r_arch_instance_decode (ai, op)) {
	r_cons_printf ("Disasm of 0x90 is %s\n", r_arch_op_tostring (op));
   } else {
   	R_LOG_ERROR ("Cannot disassemble");
   }
   r_arch_op_free (op);
   r_arch_instance_free (ai);
   r_arch_free (a);
   */
#endif

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
	bool (*init)(void **user); // Should return an RArchSession, this struct contains all the info we need
	void (*fini)(void *user);
	RArchPluginInfoCallback info;
	RArchPluginDecodeCallback decode;
	bool (*set_reg_profile)(RArchConfig *cfg, struct r_reg_t *reg);
	RArchOpAsmCallback opasm; // rename to encode
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
R_API int r_arch_encode(RArch *a, ut64 addr, const char *s, ut8 *outbuf, int outlen);
R_API bool r_arch_set_reg_profile(RArch *arch, const char *dname, struct r_reg_t *reg);
//R_API bool r_arch_esil_init(RArch *arch, const char *dname, RAnalEsil *esil);
//R_API void r_arch_esil_fini(RArch *arch, const char *dname, RAnalEsil *esil);

// instance.c
// R_API RArchInstance r_arch_use(RArch *arch, RArchConfig *config, const char *name);

// arch.c
R_API RArch *r_arch_new(void);
R_API bool r_arch_use(RArch *arch, RArchConfig *config, const char *name);
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

// XXX deprecate those names are uglyies and we can reuse R_PERM
typedef enum {
	R_ANAL_ACC_UNKNOWN = 0,
	R_ANAL_ACC_R = (1 << 0),
	R_ANAL_ACC_W = (1 << 1),
} RArchValueAccess;

typedef enum {
	R_ANAL_VAL_REG,
	R_ANAL_VAL_MEM,
	R_ANAL_VAL_IMM,
} RArchValueType;
#define RAnalValueType RArchValueType

#define USE_REG_NAMES 0

// base + reg + regdelta * mul + delta
typedef struct r_arch_value_t {
	RArchValueType type;
	RArchValueAccess access;
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
#if USE_REG_NAMES
	const char *seg;
	const char *reg;
	const char *regdelta;
#else
	// XXX can be invalidated if regprofile changes causing an UAF
	RRegItem *seg; // segment selector register
	RRegItem *reg; // register item reference
	RRegItem *regdelta; // register index used
#endif
} RArchValue;
// backward compat
#define RAnalValue RArchValue
R_API RArchValue *r_arch_value_new(void);
#if 0
// switchop
R_API RArchSwitchOp *r_arch_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val);
R_API RArchCaseOp *r_arch_case_op_new(ut64 addr, ut64 val, ut64 jump);
R_API void r_arch_switch_op_free(RArchSwitchOp *swop);
R_API RArchCaseOp* r_arch_switch_op_add_case(RArchSwitchOp *swop, ut64 addr, ut64 value, ut64 jump);
// archvalue.c
R_API RArchValue *r_arch_value_copy(RArchValue *ov);
R_API void r_arch_value_free(RArchValue *value);
R_API ut64 r_arch_value_to_ut64(RArchValue *val, struct r_reg_t *reg);
R_API bool r_arch_value_set_ut64(RArchValue *val, struct r_reg_t *reg, RIOBind *iob, ut64 num);
R_API char *r_arch_value_tostring(RArchValue *value);
R_API RAnalOp *r_arch_op_new(void);
R_API void r_arch_op_init(RAnalOp *op);
R_API void r_arch_op_fini(RAnalOp *op);
R_API void r_arch_op_free(void *_op);
#endif

R_API int r_arch_optype_from_string(const char *type);
R_API const char *r_arch_optype_tostring(int t);
R_API const char *r_arch_stackop_tostring(int s);

R_API const char *r_arch_op_family_tostring(int n);
R_API int r_arch_op_family_from_string(const char *f);
R_API const char *r_arch_op_direction_tostring(struct r_anal_op_t *op);

extern RArchPlugin r_arch_plugin_null;
extern RArchPlugin r_arch_plugin_i4004;
extern RArchPlugin r_arch_plugin_amd29k;
extern RArchPlugin r_arch_plugin_jdh8;
extern RArchPlugin r_arch_plugin_sh;

#ifdef __cplusplus
}
#endif

#endif
