/* radare2 - LGPL - Copyright 2022-2025 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_bin.h>
#include <r_reg.h>
#include <r_lib.h>

// Rename to R_ARCH_VALTYPE_*
typedef enum {
	R_ANAL_VAL_REG,
	R_ANAL_VAL_MEM,
	R_ANAL_VAL_IMM,
} RArchValueType;
#define RAnalValueType RArchValueType

#define R_ARCH_INFO_MINOP_SIZE 0
#define R_ARCH_INFO_MAXOP_SIZE 1
#define R_ARCH_INFO_INVOP_SIZE 2
#define R_ARCH_INFO_CODE_ALIGN 4
#define R_ARCH_INFO_DATA_ALIGN 8
#define R_ARCH_INFO_FUNC_ALIGN 16
#define R_ARCH_INFO_DATA2_ALIGN 32
#define R_ARCH_INFO_DATA4_ALIGN 64
#define R_ARCH_INFO_DATA8_ALIGN 128
#define R_ARCH_INFO_JMPMID 256
#define R_ARCH_INFO_ISVM 512

// base + reg + regdelta * mul + delta
typedef struct r_arch_value_t {
	RArchValueType type;
	int access; // rename to `perm` and use R_PERM_R | _W | _X
	bool absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	const char *seg;
	const char *reg;
	const char *regdelta;
} RArchValue;
#include <r_anal/op.h>
#include <r_esil.h>

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
	char arch[16];
	char *cpu;
	char *os;
	int bits;
	union {
		int big_endian; // R2_600 - deprecate and just use typed endian for more than little+big
		ut32 endian;
	};
	int syntax;
	int codealign;
	int dataalign;
	int addrbytes;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *abi;
	ut64 gp;
	RCFloatProfile cfloat_profile;
	R_REF_TYPE;
} RArchConfig;

#define	R_ARCH_CONFIG_IS_BIG_ENDIAN(cfg_) (((cfg_)->endian & R_SYS_ENDIAN_BIG) == R_SYS_ENDIAN_BIG)

typedef enum {
	R_ARCH_OP_MASK_BASIC = 0, // Just fills basic op info (fast)
	R_ARCH_OP_MASK_ESIL  = 1, // fills RAnalop->esil info
	R_ARCH_OP_MASK_VAL   = 2, // fills RAnalop->dst/src info
	R_ARCH_OP_MASK_HINT  = 4, // calls r_anal_op_hint to override anal options
	R_ARCH_OP_MASK_OPEX  = 8, // fills RAnalop->opex info
	R_ARCH_OP_MASK_DISASM = 16, // fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()
	R_ARCH_OP_MASK_ALL   = 1 | 2 | 4 | 8 | 16
} RAnalOpMask;

typedef struct r_arch_t {
	RList *plugins;	// all plugins
	RBinBind binb; // required for java, dalvik, wasm, pickle and pyc plugin... pending refactor
	struct r_esil_t *esil;
	RNum *num; // XXX maybe not required
	struct r_arch_session_t *session;
	RArchConfig *cfg; // global / default config
	char *platform;
	void *user; // probably RCore*
} RArch;

typedef struct r_arch_session_t {
	char *name; // used by .use to chk if it was set already
	// TODO: name it "peer" instead of encoder. so the encoder can back reference the decoder
	struct r_arch_t *arch;
	struct r_arch_plugin_t *plugin; // used for decoding
	struct r_arch_session_t *encoder; // used for encoding when plugin->encode is not set
	RArchConfig *config; // TODO remove arch->config and keep archsession->config
	void *data; // store plugin-specific data
	void *user; // holds user pointer provided by user
	R_REF_TYPE;
} RArchSession;

typedef enum {
	R_ARCH_ESIL_ACTION_INIT,
	R_ARCH_ESIL_ACTION_MAPS,
	// R_ARCH_ESIL_EVAL,
	R_ARCH_ESIL_ACTION_RESET,
	R_ARCH_ESIL_ACTION_FINI,
} RArchEsilAction;

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
typedef bool (*RArchPluginEsilCallback)(RArchSession *s, RArchEsilAction action);

// TODO: use `const char *const` instead of `char*`
typedef struct r_arch_plugin_t {
	RPluginMeta meta;

	// all const
	char *arch;
	char *cpus;
	ut32 endian;
	RSysBits bits;
	RSysBits addr_bits;

	const RArchPluginInitCallback init;
	const RArchPluginFiniCallback fini;
	const RArchPluginInfoCallback info;
	const RArchPluginRegistersCallback regs;
	const RArchPluginEncodeCallback encode;
	const RArchPluginDecodeCallback decode;
	const RArchPluginModifyCallback patch;
	const RArchPluginMnemonicsCallback mnemonics;
	const RArchPluginPreludesCallback preludes;
	const RArchPluginEsilCallback esilcb;
} RArchPlugin;

R_API char *r_arch_platform_unset(RArch *arch, const char *name);
R_API char *r_arch_platform_set(RArch *arch, const char *name);
R_API void r_arch_platform_list(RArch *arch);

// decoder.c
//dname is name of decoder to use, NULL if current
R_API bool r_arch_load_decoder(RArch *arch, const char *dname);
R_API bool r_arch_use_decoder(RArch *arch, const char *dname);
R_API bool r_arch_unload_decoder(RArch *arch, const char *dname);

// deprecate
R_API int r_arch_info(RArch *arch, int query);
R_API bool r_arch_decode(RArch *a, RAnalOp *op, RArchDecodeMask mask);
R_API bool r_arch_encode(RArch *a, RAnalOp *op, RArchEncodeMask mask);
R_API bool r_arch_esilcb(RArch *a, RArchEsilAction action);
//R_API bool r_arch_esil_init(RArch *arch, const char *dname, REsil *esil);
//R_API void r_arch_esil_fini(RArch *arch, const char *dname, REsil *esil);

R_API RArchSession *r_arch_session(RArch *arch, RArchConfig *cfg, RArchPlugin *ap);
R_API bool r_arch_session_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask);
R_API bool r_arch_session_encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask);
R_API bool r_arch_session_patch(RArchSession *as, RAnalOp *op, RArchModifyMask mask);
R_API int r_arch_session_info(RArchSession *as, int q);
R_API RList *r_arch_session_preludes(RArchSession *as);

// arch.c
R_API RArch *r_arch_new(void);
R_API RArchPlugin *r_arch_find(RArch *arch, const char *name);
R_API bool r_arch_use(RArch *arch, RArchConfig *config, const char *name);

// arch plugins management apis
R_API bool r_arch_plugin_add(RArch *arch, RArchPlugin *ap);
R_API bool r_arch_plugin_remove(RArch *arch, RArchPlugin *ap);
R_API bool r_arch_del(RArch *arch, const char *name);
R_API void r_arch_free(RArch *arch);

// aconfig.c
R_API void r_arch_config_use(RArchConfig *config, const char * R_NULLABLE arch);
R_API void r_arch_config_set_cpu(RArchConfig *config, const char * R_NULLABLE cpu);
R_API bool r_arch_config_set_syntax(RArchConfig *config, int syntax);
R_API bool r_arch_config_set_bits(RArchConfig *c, int bits);
R_API RArchConfig *r_arch_config_new(void);
R_API RArchConfig *r_arch_config_clone(RArchConfig *c);
R_API void r_arch_config_free(RArchConfig *);

// backward compat
#define RAnalValue RArchValue
R_API RArchValue *r_arch_value_new(void);

R_API RArchValue *r_arch_value_new_reg(const char * const regname);
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

#if 1
// R2_600 Deprecate! this is part of archconfig!
R_API bool r_arch_set_endian(RArch *arch, ut32 endian);
R_API bool r_arch_set_bits(RArch *arch, ut32 bits);
R_API bool r_arch_set_arch(RArch *arch, char *archname);
#endif

R_API int r_arch_optype_from_string(const char *type);
R_API const char *r_arch_optype_tostring(int t);
R_API const char *r_arch_stackop_tostring(int s);

R_API const char *r_arch_op_family_tostring(int n);
R_API int r_arch_op_family_from_string(const char *f);
R_API const char *r_arch_op_direction_tostring(struct r_anal_op_t *op);

extern const RArchPlugin r_arch_plugin_6502;
extern const RArchPlugin r_arch_plugin_6502_cs;
extern const RArchPlugin r_arch_plugin_8051;
extern const RArchPlugin r_arch_plugin_alpha;
extern const RArchPlugin r_arch_plugin_amd29k;
extern const RArchPlugin r_arch_plugin_any_as;
extern const RArchPlugin r_arch_plugin_any_vasm;
extern const RArchPlugin r_arch_plugin_arc;
extern const RArchPlugin r_arch_plugin_arm;
extern const RArchPlugin r_arch_plugin_arm_cs;
extern const RArchPlugin r_arch_plugin_arm_gnu;
extern const RArchPlugin r_arch_plugin_arm_v35;
extern const RArchPlugin r_arch_plugin_avr;
extern const RArchPlugin r_arch_plugin_bf;
extern const RArchPlugin r_arch_plugin_bpf;
extern const RArchPlugin r_arch_plugin_bpf_cs;
extern const RArchPlugin r_arch_plugin_sbpf_cs;
extern const RArchPlugin r_arch_plugin_chip8;
extern const RArchPlugin r_arch_plugin_cr16;
extern const RArchPlugin r_arch_plugin_cris;
extern const RArchPlugin r_arch_plugin_dalvik;
extern const RArchPlugin r_arch_plugin_dis;
extern const RArchPlugin r_arch_plugin_ebc;
extern const RArchPlugin r_arch_plugin_evm;
extern const RArchPlugin r_arch_plugin_fslsp;
extern const RArchPlugin r_arch_plugin_gb;
extern const RArchPlugin r_arch_plugin_h8300;
extern const RArchPlugin r_arch_plugin_hppa_gnu;
extern const RArchPlugin r_arch_plugin_i4004;
extern const RArchPlugin r_arch_plugin_i8080;
extern const RArchPlugin r_arch_plugin_java;
extern const RArchPlugin r_arch_plugin_jdh8;
extern const RArchPlugin r_arch_plugin_kvx;
extern const RArchPlugin r_arch_plugin_lanai;
extern const RArchPlugin r_arch_plugin_lh5801;
extern const RArchPlugin r_arch_plugin_lm32;
extern const RArchPlugin r_arch_plugin_loongarch_gnu;
extern const RArchPlugin r_arch_plugin_lua;
extern const RArchPlugin r_arch_plugin_m680x_cs;
extern const RArchPlugin r_arch_plugin_m68k_cs;
extern const RArchPlugin r_arch_plugin_m68k_gnu;
extern const RArchPlugin r_arch_plugin_mcore;
extern const RArchPlugin r_arch_plugin_mcs96;
extern const RArchPlugin r_arch_plugin_mips_cs;
extern const RArchPlugin r_arch_plugin_mips_gnu;
extern const RArchPlugin r_arch_plugin_msp430;
extern const RArchPlugin r_arch_plugin_nds32;
extern const RArchPlugin r_arch_plugin_nios2;
extern const RArchPlugin r_arch_plugin_null;
extern const RArchPlugin r_arch_plugin_or1k;
extern const RArchPlugin r_arch_plugin_pdp11;
extern const RArchPlugin r_arch_plugin_pic;
extern const RArchPlugin r_arch_plugin_pickle;
extern const RArchPlugin r_arch_plugin_ppc_cs;
extern const RArchPlugin r_arch_plugin_ppc_gnu;
extern const RArchPlugin r_arch_plugin_propeller;
extern const RArchPlugin r_arch_plugin_pyc;
extern const RArchPlugin r_arch_plugin_riscv;
extern const RArchPlugin r_arch_plugin_riscv_cs;
extern const RArchPlugin r_arch_plugin_rsp;
extern const RArchPlugin r_arch_plugin_s390_cs;
extern const RArchPlugin r_arch_plugin_s390_gnu;
extern const RArchPlugin r_arch_plugin_sh;
extern const RArchPlugin r_arch_plugin_sh_cs;
extern const RArchPlugin r_arch_plugin_sm5xx;
extern const RArchPlugin r_arch_plugin_snes;
extern const RArchPlugin r_arch_plugin_sparc_cs;
extern const RArchPlugin r_arch_plugin_sparc_gnu;
extern const RArchPlugin r_arch_plugin_stm8;
extern const RArchPlugin r_arch_plugin_tms320;
extern const RArchPlugin r_arch_plugin_tms320_gnu;
extern const RArchPlugin r_arch_plugin_tricore;
extern const RArchPlugin r_arch_plugin_tricore_cs;
extern const RArchPlugin r_arch_plugin_uxn;
extern const RArchPlugin r_arch_plugin_v810;
extern const RArchPlugin r_arch_plugin_v850;
extern const RArchPlugin r_arch_plugin_vax;
extern const RArchPlugin r_arch_plugin_cil;
extern const RArchPlugin r_arch_plugin_wasm;
extern const RArchPlugin r_arch_plugin_ws;
extern const RArchPlugin r_arch_plugin_x86_cs;
extern const RArchPlugin r_arch_plugin_x86_nasm;
extern const RArchPlugin r_arch_plugin_x86_nz;
extern const RArchPlugin r_arch_plugin_xap;
extern const RArchPlugin r_arch_plugin_xcore_cs;
extern const RArchPlugin r_arch_plugin_xtensa;
extern const RArchPlugin r_arch_plugin_z80;
extern const RArchPlugin r_arch_plugin_cosmac;

#ifdef __cplusplus
}
#endif

#endif
