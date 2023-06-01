/* radare2 - LGPL - Copyright 2022-2023 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_bin.h>
#include <r_reg.h>

// Rename to R_ARCH_VALTYPE_*
typedef enum {
	R_ANAL_VAL_REG,
	R_ANAL_VAL_MEM,
	R_ANAL_VAL_IMM,
} RArchValueType;
#define RAnalValueType RArchValueType

#if R2_590
#define USE_REG_NAMES 1
#define R_ARCH_INFO_MIN_OP_SIZE 0
#define R_ARCH_INFO_MAX_OP_SIZE 1
#define R_ARCH_INFO_INV_OP_SIZE 2
#define R_ARCH_INFO_ALIGN 4
#define R_ARCH_INFO_DATA_ALIGN 8
#define R_ARCH_INFO_DATA2_ALIGN 16
#define R_ARCH_INFO_DATA4_ALIGN 32
#define R_ARCH_INFO_DATA8_ALIGN 64
#else
#define USE_REG_NAMES 0
#define R_ANAL_ARCHINFO_MIN_OP_SIZE 0
#define R_ANAL_ARCHINFO_MAX_OP_SIZE 1
#define R_ANAL_ARCHINFO_INV_OP_SIZE 2
#define R_ANAL_ARCHINFO_ALIGN 4
#define R_ANAL_ARCHINFO_DATA_ALIGN 8
#endif


// base + reg + regdelta * mul + delta
typedef struct r_arch_value_t {
	RArchValueType type;
	int access; // rename to `perm` and use R_PERM_R | _W | _X
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
#if USE_REG_NAMES
	const char * const seg;
	const char * const reg;
	const char * const regdelta;
#else
	// XXX can be invalidated if regprofile changes causing an UAF
	RRegItem *seg; // segment selector register
	RRegItem *reg; // register item reference
	RRegItem *regdelta; // register index used
#endif
} RArchValue;
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
#include <sdb/sdb.h>

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
	int addrbytes;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *abi;
#if R2_590
	ut64 gp;
#endif
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

#if 0
// XXX R2_590 - backward compatible, shouldnt be used
#define R_ANAL_OP_MASK_BASIC 0, // Just fills basic op info , it's fast
#define R_ANAL_OP_MASK_ESIL  1, // It fills RAnalop->esil info
#define R_ANAL_OP_MASK_VAL   2, // It fills RAnalop->dst/src info
#define R_ANAL_OP_MASK_HINT  4, // It calls r_anal_op_hint to override anal options
#define R_ANAL_OP_MASK_OPEX  8, // It fills RAnalop->opex info
#define R_ANAL_OP_MASK_DISASM 16, // It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
#define R_ANAL_OP_MASK_ALL   (1 | 2 | 4 | 8 | 16)
#endif

typedef struct r_arch_t {
	RList *plugins;	       // all plugins
	RBinBind binb; // required for java, dalvik, wasm, pickle and pyc plugin... pending refactor
	RNum *num; // XXX maybe not required
	struct r_arch_session_t *session;
	RArchConfig *cfg; // global / default config
} RArch;

typedef struct r_arch_session_t {
#if R2_590
	char *name; // used by .use to chk if it was set already
	// TODO: name it "peer" instead of encoder. so the encoder can back reference the decoder
	struct r_arch_session_t *encoder; // used for encoding when plugin->encode is not set
#endif
	struct r_arch_t *arch;
	struct r_arch_plugin_t *plugin; // used for decoding
	RArchConfig *config; // TODO remove arch->config!
	void *data;
	void *user;
	R_REF_TYPE;
} RArchSession;

typedef ut32 RArchDecodeMask;
typedef ut32 RArchEncodeMask; // syntax ?
typedef ut32 RArchModifyMask; // syntax ?

typedef int (*RArchPluginInfoCallback)(RArchSession *cfg, ut32 query);
typedef char *(*RArchPluginRegistersCallback)(RArchSession *ai);
typedef char *(*RArchPluginMnemonicsCallback)(RArchSession *s, int id, bool json);
typedef bool (*RArchPluginDecodeCallback)(RArchSession *s, struct r_anal_op_t *op, RArchDecodeMask mask);
typedef bool (*RArchPluginEncodeCallback)(RArchSession *s, struct r_anal_op_t *op, RArchEncodeMask mask);
typedef bool (*RArchPluginModifyCallback)(RArchSession *s, struct r_anal_op_t *op, RArchModifyMask mask);
typedef RList *(*RArchPluginPreludesCallback)(RArchSession *s);
typedef bool (*RArchPluginInitCallback)(RArchSession *s);
typedef bool (*RArchPluginFiniCallback)(RArchSession *s);

// TODO: use `const char *const` instead of `char*`
typedef struct r_arch_plugin_t {
	// RPluginMeta meta; //  = { .name = ... }
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;

	// all const
	char *arch;
	char *cpus;
	ut32 endian;
	RSysBits bits;
	RSysBits addr_bits;
	RArchPluginInitCallback init;
	RArchPluginFiniCallback fini;
	RArchPluginInfoCallback info;
	RArchPluginRegistersCallback regs;
	RArchPluginEncodeCallback encode;
	RArchPluginDecodeCallback decode;
	RArchPluginModifyCallback patch;
	RArchPluginMnemonicsCallback mnemonics;
	RArchPluginPreludesCallback preludes;
//TODO: reenable this later? maybe it should be called reset() or setenv().. but esilinit/fini
// 	seems to specific to esil and those functions may want to do moreo things like io stuff
//	bool (*esil_init)(REsil *esil);
//	void (*esil_fini)(REsil *esil);
} RArchPlugin;

// decoder.c
//dname is name of decoder to use, NULL if current
R_API bool r_arch_load_decoder(RArch *arch, const char *dname);
R_API bool r_arch_use_decoder(RArch *arch, const char *dname);
R_API bool r_arch_unload_decoder(RArch *arch, const char *dname);

// deprecate
R_API int r_arch_info(RArch *arch, int query);
R_API bool r_arch_decode(RArch *a, RAnalOp *op, RArchDecodeMask mask);
R_API bool r_arch_encode(RArch *a, RAnalOp *op, RArchEncodeMask mask);
//R_API bool r_arch_esil_init(RArch *arch, const char *dname, REsil *esil);
//R_API void r_arch_esil_fini(RArch *arch, const char *dname, REsil *esil);

R_API RArchSession *r_arch_session(RArch *arch, RArchConfig *cfg, RArchPlugin *ap);
R_API bool r_arch_session_decode(RArchSession *ai, RAnalOp *op, RArchDecodeMask mask);
R_API bool r_arch_session_encode(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask);
R_API bool r_arch_session_patch(RArchSession *ai, RAnalOp *op, RArchModifyMask mask);
R_API int r_arch_session_info(RArchSession *ai, int q);
R_API RList *r_arch_session_preludes(RArchSession *ai);

// arch.c
R_API RArch *r_arch_new(void);
R_API bool r_arch_use(RArch *arch, RArchConfig *config, const char *name);

// arch plugins management apis
R_API bool r_arch_add(RArch *arch, RArchPlugin *ap);
R_API bool r_arch_del(RArch *arch, const char *name);
R_API void r_arch_free(RArch *arch);

// R2_590 - deprecate
R_API bool r_arch_set_bits(RArch *arch, ut32 bits);
R_API bool r_arch_set_endian(RArch *arch, ut32 endian);
R_API bool r_arch_set_arch(RArch *arch, char *archname);

// aconfig.c
R_API void r_arch_config_use(RArchConfig *config, R_NULLABLE const char *arch);
R_API void r_arch_config_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu);
R_API bool r_arch_config_set_syntax(RArchConfig *config, int syntax);
R_API bool r_arch_config_set_bits(RArchConfig *c, int bits);
R_API RArchConfig *r_arch_config_new(void);
R_API RArchConfig *r_arch_config_clone(RArchConfig *c);
R_API void r_arch_config_free(RArchConfig *);

// backward compat
#define RAnalValue RArchValue
R_API RArchValue *r_arch_value_new(void);

#if R2_590
R_API RArchValue *r_arch_value_new_reg(const char * const regname);
#endif
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
extern RArchPlugin r_arch_plugin_kvx;
extern RArchPlugin r_arch_plugin_pickle;
extern RArchPlugin r_arch_plugin_sh;
extern RArchPlugin r_arch_plugin_sh_cs;
extern RArchPlugin r_arch_plugin_v810;
extern RArchPlugin r_arch_plugin_rsp;
extern RArchPlugin r_arch_plugin_riscv;
extern RArchPlugin r_arch_plugin_riscv_cs;
extern RArchPlugin r_arch_plugin_any_as;
extern RArchPlugin r_arch_plugin_any_vasm;
extern RArchPlugin r_arch_plugin_arm;
extern RArchPlugin r_arch_plugin_wasm;
extern RArchPlugin r_arch_plugin_x86_nz;
extern RArchPlugin r_arch_plugin_x86_nasm;
extern RArchPlugin r_arch_plugin_snes;
extern RArchPlugin r_arch_plugin_6502;
extern RArchPlugin r_arch_plugin_xap;
extern RArchPlugin r_arch_plugin_v850;
extern RArchPlugin r_arch_plugin_propeller;
extern RArchPlugin r_arch_plugin_mcore;
extern RArchPlugin r_arch_plugin_nios2;
extern RArchPlugin r_arch_plugin_xtensa;
extern RArchPlugin r_arch_plugin_or1k;
extern RArchPlugin r_arch_plugin_evm;
extern RArchPlugin r_arch_plugin_dis;
extern RArchPlugin r_arch_plugin_mcs96;
extern RArchPlugin r_arch_plugin_ws;
extern RArchPlugin r_arch_plugin_lanai;
extern RArchPlugin r_arch_plugin_lua;
extern RArchPlugin r_arch_plugin_z80;
extern RArchPlugin r_arch_plugin_lm32;
extern RArchPlugin r_arch_plugin_bpf;
extern RArchPlugin r_arch_plugin_bpf_cs;
extern RArchPlugin r_arch_plugin_alpha;
extern RArchPlugin r_arch_plugin_vax;
extern RArchPlugin r_arch_plugin_tricore;
extern RArchPlugin r_arch_plugin_tricore_cs;
extern RArchPlugin r_arch_plugin_pic;
extern RArchPlugin r_arch_plugin_arm_v35;
extern RArchPlugin r_arch_plugin_cris;
extern RArchPlugin r_arch_plugin_cr16;
extern RArchPlugin r_arch_plugin_arc;
extern RArchPlugin r_arch_plugin_pdp11;
extern RArchPlugin r_arch_plugin_lh5801;
extern RArchPlugin r_arch_plugin_ebc;
extern RArchPlugin r_arch_plugin_msp430;
extern RArchPlugin r_arch_plugin_pyc;
extern RArchPlugin r_arch_plugin_h8300;
extern RArchPlugin r_arch_plugin_bf;
extern RArchPlugin r_arch_plugin_sparc_gnu;
extern RArchPlugin r_arch_plugin_sparc_cs;
extern RArchPlugin r_arch_plugin_hppa_gnu;
extern RArchPlugin r_arch_plugin_s390_cs;
extern RArchPlugin r_arch_plugin_s390_gnu;
extern RArchPlugin r_arch_plugin_m68k_gnu;
extern RArchPlugin r_arch_plugin_m68k_cs;
extern RArchPlugin r_arch_plugin_ppc_gnu;
extern RArchPlugin r_arch_plugin_loongarch_gnu;
extern RArchPlugin r_arch_plugin_6502_cs;
extern RArchPlugin r_arch_plugin_m680x_cs;
extern RArchPlugin r_arch_plugin_xcore_cs;
extern RArchPlugin r_arch_plugin_chip8;
extern RArchPlugin r_arch_plugin_mips_gnu;
extern RArchPlugin r_arch_plugin_sm5xx;
extern RArchPlugin r_arch_plugin_tms320;
extern RArchPlugin r_arch_plugin_ppc_cs;
extern RArchPlugin r_arch_plugin_i8080;
extern RArchPlugin r_arch_plugin_java;

#ifdef __cplusplus
}
#endif

#endif
