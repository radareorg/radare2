/* radare2 - LGPL - Copyright 2022 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_util.h>
#if 0
#include <r_anal.h>	//remove this later
#include <r_reg.h>
#include <sdb.h>
#endif

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
	char *arch;
	char *cpu;
	char *os;
	int bits;
	int big_endian;
	int syntax;
	//
	int pcalign;
	int dataalign;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *features;
	R_REF_TYPE;
} RArchConfig;

#if 0
#define R_ARCH_INFO_MIN_OP_SIZE	0
#define R_ARCH_INFO_MAX_OP_SIZE	1
#define R_ARCH_INFO_INV_OP_SIZE	2
#define R_ARCH_INFO_ALIGN	4
#define R_ARCH_INFO_DATA_ALIGN	8
#define R_ARCH_INFO_BITS	16	//supported bitness
#define R_ARCH_INFO_ENDIAN	32	//supported endianness
#define R_ARCH_INFO_ESIL	64	//support for esil

#define	R_ARCH_OP_MASK_BASIC	0	// Just fills basic op info , it's fast
#define R_ARCH_OP_MASK_ESIL	1	// It fills RAnalop->esil info
#define R_ARCH_OP_MASK_VAL	2	// It fills RAnalop->dst/src info
#define	R_ARCH_OP_MASK_OPEX	4	// It fills RAnalop->opex info
#define	R_ARCH_OP_MASK_DISASM	8	// It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()

typedef	RAnalOp	RArchOp;	//define this properly later

typedef struct r_arch_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	char *cpus;
	bool (*init)(void **user);
	void (*fini)(void *user);
	int (*info)(ut32 query);
	int (*decode)(RArch *a, RArchOp *op, ut64 addr, const ut8 *data, int len, ut32 mask);
	bool (*set_reg_profile)(RArchConfig *cfg, RReg *reg);
	bool (*esil_init)(RAnalEsil *esil);
	void (*esil_fini)(RAnalEsil *esil);
} RArchPlugin;

typedef struct r_arch_decoder_t {
	RArchPlugin *p;
	void *user;
	ut32 refctr;
} RArchDecoder;

typedef struct r_arch_t {
	RList *plugins;	//all plugins
	RArchDecoder *current;	//currently used decoder
	HtPP *decoders;	//as decoders instantiated plugins
	RArchConfig *cfg;	//config
} RArch;

R_API RArch *r_arch_new(void);
R_API void r_arch_free(RArch *arch);
//dname is name of decoder to use, NULL if current
R_API bool r_arch_load_decoder(RArch *arch, const char *dname);
R_API bool r_arch_use_decoder(RArch *arch, const char *dname);
R_API bool r_arch_unload_decoder(RArch *arch, const char *dname);
R_API int r_arch_info(RArch *arch, const char *dname, ut32 query);
R_API int r_arch_decode(RArch *arch, const char *dname, RArchOp *op, ut64 addr, const ut8 *data, int len, ut32 mask);
R_API bool r_arch_set_reg_profile(RArch *arch, const char *dname, RReg *reg);
R_API bool r_arch_esil_init(RArch *arch, const char *dname, RAnalEsil *esil);
R_API void r_arch_esil_fini(RArch *arch, const char *dname, RAnalEsil *esil);

#endif

R_API void r_arch_use(RArchConfig *config, R_NULLABLE const char *arch);
R_API void r_arch_config_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu);
R_API void r_arch_config_set_bits(RArchConfig *config, int bits);
R_API RArchConfig *r_arch_config_new(void);

#ifdef __cplusplus
}
#endif

#endif
