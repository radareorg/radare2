/* radare2 - LGPL - Copyright 2020 - pancake */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_bind.h>
#include <r_io.h> // Just for RIOBind which is needed for some plugins

#ifdef __cplusplus
extern "C" {
#endif

typedef int RArchBits;

typedef enum r_arch_endian_t {
	R_ARCH_ENDIAN_NONE = 1 << 0,
	R_ARCH_ENDIAN_LITTLE = 1 << 1,
	R_ARCH_ENDIAN_BIG = 1 << 2,
	R_ARCH_ENDIAN_BI = 1 << 3,
} RArchEndian;

typedef enum r_arch_output_options_t {
	R_ARCH_OUTOPT_CODE = 1 << 0,
	R_ARCH_OUTOPT_SIZE = 1 << 1,
	R_ARCH_OUTOPT_ANAL = 1 << 2,
	R_ARCH_OUTOPT_ESIL = 1 << 3,
	R_ARCH_OUTOPT_OPEX = 1 << 4,
	R_ARCH_OUTOPT_DESC = 1 << 5,
	R_ARCH_OUTOPT_DATA = 1 << 6,
} RArchOutputOptions;

typedef enum r_arch_input_options_t {
	R_ARCH_INOPT_CODE = 1 << 0,
	R_ARCH_INOPT_DATA = 1 << 1,
	R_ARCH_INOPT_ESIL = 1 << 3,
} RArchInputOptions;

typedef enum r_arch_syntax_t {
	R_ARCH_SYNTAX_NONE = 0,
	R_ARCH_SYNTAX_INTEL,
	R_ARCH_SYNTAX_ATT,
	R_ARCH_SYNTAX_MASM,
	R_ARCH_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	R_ARCH_SYNTAX_JZ, // hack to use jz instead of je on x86
} RArchSyntax;

typedef struct r_arch_setup_t {
	RArchEndian endian;
	RArchBits bits;
	RArchSyntax syntax;
	char *cpu;
} RArchSetup;

typedef struct r_arch_t {
	RList *plugins;
	RIOBind iob;
} RArch;

typedef struct r_arch_info_t {
	size_t minisz;
	size_t maxisz;
	size_t align;
	size_t dataalign;
	char *regprofile;
} RArchInfo;


typedef struct r_arch_instruction_t {
	ut64 addr;
	size_t size; // inherit from thisi.data.len?
	ut32 opid; // opcode identifier
	ut64 type; // opcode type
	RStrBuf code; // disasm
	RStrBuf data; // bytes
	RStrBuf esil; // emulation
	RStrBuf opex; // analysis
	RArchSyntax syntax; // used for disasm
	RVector dest; // array of destinations
} RArchInstruction;


typedef struct r_arch_plugin_t RArchPlugin;

typedef struct r_arch_callbacks_t {
	int (*read_at)(void *user, ut64 addr, R_OUT ut8 *buf, size_t len);
	ut64 (*get_offset)(void *user, const char *name);
	const char *(*get_name)(void *user, ut64 addr);
} RArchCallbacks;

typedef struct r_arch_session {
	RArch *arch;
	RArchPlugin *cur;
	RArchSetup setup;
	RArchInfo info;
	RArchCallbacks *cbs;
	R_REF_TYPE;
} RArchSession;


typedef bool (*RArchPluginCallback)(RArch *a);
typedef bool (*RArchSessionCallback)(RArchSession *a);
typedef bool (*RArchXXcodeCallback)(RArchSession *a, RArchInstruction *ins, RArchInputOptions inopt, RArchOutputOptions outopt);
typedef bool (*RArchDefaultSetupCallback)(RArchSetup *as);

R_API RArchSession *r_arch_session_new(RArch *a, RArchPlugin *ap, RArchSetup *setup);
R_API void r_arch_session_free(RArchSession *as);
R_API bool r_arch_session_can_xxcode(RArchSession *ai, RArchInputOptions inopt, RArchOutputOptions outopt);
R_API bool r_arch_session_xxcode(RArchSession *ai, RArchInstruction *ins, RArchInputOptions inopt, RArchOutputOptions outopt);
R_REF_FUNCTIONS(RArchSession, r_arch_session);

typedef struct r_arch_plugin_t {
	// RArchInfo setup;
	const char *name;
	const char *arch;
	const char *cpus;
	const char *features;
	RArchInputOptions inopts;
	RArchOutputOptions outopts;
	// RArchSetup setup;
	RArchBits bits;
	RArchEndian endian;
	// copyright
	const char *author;
	const char *desc;
	const char *license;
	const char *version;
	// callbacks
	RArchXXcodeCallback xxcode;
	RArchPluginCallback init;
	RArchPluginCallback fini;
	RArchSessionCallback init_session;
	RArchSessionCallback fini_session;
	RArchDefaultSetupCallback default_setup;
} RArchPlugin;

R_API RArchInstruction *r_arch_instruction_new();
R_API void r_arch_instruction_free(RArchInstruction *ins);
R_API void r_arch_instruction_init(RArchInstruction *ins);
R_API void r_arch_instruction_init_data(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len);
R_API void r_arch_instruction_init_code(RArchInstruction *ins, ut64 addr, const char *opstr);
R_API void r_arch_instruction_fini(RArchInstruction *ins);

R_API RArch *r_arch_new();
R_API void r_arch_free(RArch *arch);
R_API RArchPlugin *r_arch_get_plugin (RArch *a, const char *name);
R_API bool r_arch_add(RArch *a, RArchPlugin *foo);
R_API bool r_arch_del(RArch *a, RArchPlugin *ap);

#ifdef __cplusplus
}
#endif

#endif
