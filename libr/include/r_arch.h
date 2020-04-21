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
typedef int RArchEndian;
typedef int RArchSyntax;

typedef enum r_arch_decode_options_t {
	R_ARCH_OPTION_CODE = 1 << 0, // 1,
	R_ARCH_OPTION_SIZE = 1 << 1, // 2,
	R_ARCH_OPTION_ANAL = 1 << 2, //4,
	R_ARCH_OPTION_ESIL = 1 << 3, //8,
	R_ARCH_OPTION_OPEX = 1 << 4, //16,
	R_ARCH_OPTION_DESC = 1 << 5, // 32, // instruction description
} RArchOptions;

typedef struct r_arch_setup_t {
	RArchEndian endian;
	RArchBits bits;
	RArchSyntax syntax;
	char *cpu;
} RArchSetup;

typedef struct r_arch_callbacks_t {
	void *user;
	int (*read_at)(void *user, ut64 addr, R_OUT ut8 *buf, size_t len);
	ut64 (*get_offset)(void *user, const char *name);
	const char *(*get_name)(void *user, ut64 addr);
} RArchCallbacks;

typedef struct r_arch_t {
	RList *plugins;
	RArchCallbacks cbs;
} RArch;

typedef struct r_arch_info_t {
	size_t minisz;
	size_t maxisz;
	size_t align;
	size_t dataalign;
	char *regprofile;
	// size_t payload;
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


typedef struct r_arch_plugin_t *RArchPluginP;

typedef struct r_arch_session {
	RArch *arch;
	RArchPluginP cur;
	RArchSetup setup;
	RArchInfo info;
	RArchCallbacks *cbs;
	R_REF_TYPE;
} RArchSession;


typedef bool (*RArchPluginCallback)(RArch *a);
typedef bool (*RArchSessionCallback)(RArchSession *a);
typedef bool (*RArchEncodeCallback)(RArchSession *a, RArchInstruction *ins, RArchOptions options);
typedef bool (*RArchDecodeCallback)(RArchSession *a, RArchInstruction *ins, RArchOptions options);

R_API RArchSession *r_arch_session_new(RArch *a, RArchPluginP ap, RArchSetup *setup);
R_API void r_arch_session_free(RArchSession *as);
R_API bool r_arch_session_can_decode(RArchSession *ai);
R_API bool r_arch_session_can_encode(RArchSession *ai);
R_API bool r_arch_session_encode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt);
R_API bool r_arch_session_decode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt);
R_REF_FUNCTIONS(RArchSession, r_arch_session);

typedef struct r_arch_plugin_t {
	// RArchInfo setup;
	const char *name;
	const char *arch;
	const char *cpus;
	const char *features;
	// RArchSetup setup;
	RArchBits bits;
	RArchEndian endian;
	RArchSyntax syntax;
	// copyright
	const char *author;
	const char *desc;
	const char *license;
	const char *version;
	// callbacks
	RArchEncodeCallback encode;
	RArchDecodeCallback decode;
	RArchPluginCallback init;
	RArchPluginCallback fini;
	RArchSessionCallback init_session;
	RArchSessionCallback fini_session;
} RArchPlugin;

// $ grep -re '^R_API' ../arch/*.c | cut -d : -f 2- | sed -e 's, {,;,' | sort

R_API RArch *r_arch_new(void);
R_API RArchInfo *r_arch_info_new(void);
R_API RArchInstruction *r_arch_instruction_new();
R_API RArchPlugin *r_arch_get_plugin(RArch *a, const char *name);
R_API RArchSession *r_arch_session_new(RArch *a, RArchPlugin *ap, RArchSetup *setup);
R_API bool r_arch_add(RArch *a, RArchPlugin *foo);
R_API bool r_arch_del(RArch *a, RArchPlugin *ap);
R_API bool r_arch_session_can_decode(RArchSession *ai);
R_API bool r_arch_session_can_encode(RArchSession *ai);
R_API bool r_arch_session_decode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt);
R_API bool r_arch_session_decode_bytes (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len);
R_API bool r_arch_session_decode_esil (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len);
R_API bool r_arch_session_encode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt);
R_API bool r_arch_session_encode_instruction (RArchSession *as, RArchInstruction *ins, ut64 addr, const char *opstr);
R_API bool r_arch_session_set_bits(RArchSession *ai, RArchBits bits);
R_API const char *r_arch_instruction_get_esil(RArchInstruction *ins);
R_API const char *r_arch_instruction_get_esil(RArchInstruction *ins);
R_API const char *r_arch_instruction_get_string(RArchInstruction *ins);
R_API const char *r_arch_instruction_get_string(RArchInstruction *ins);
R_API void r_arch_free(RArch *arch);
R_API void r_arch_info_free(RArchInfo *info);
R_API void r_arch_instruction_fini(RArchInstruction *ins);
R_API void r_arch_instruction_free(RArchInstruction *ins);
R_API void r_arch_instruction_init(RArchInstruction *ins);
R_API void r_arch_instruction_init_code(RArchInstruction *ins, ut64 addr, const char *opstr);
R_API void r_arch_instruction_init_data(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t size);
R_API void r_arch_instruction_set_bytes(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t size);
R_API void r_arch_instruction_set_opstr(RArchInstruction *ins, ut64 addr, const char *opstr);
R_API void r_arch_session_free(RArchSession *as);

extern RArchPlugin r_arch_plugin_bf;

#ifdef __cplusplus
}
#endif

#endif
