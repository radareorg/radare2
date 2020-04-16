/* radare2 - LGPL - Copyright 2020 - pancake */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>
#include <r_bind.h>
#include <r_io.h> // Just for RIOBind which is needed for some plugins

typedef int RArchBits;
typedef int RArchEndian;

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
	size_t syntax;
	char *cpu;
} RArchSetup;

typedef struct r_arch_t {
	struct r_arch_plugin_t *cur;
	RArchSetup setup;
	RList *plugins;
	RIOBind iob;
} RArch;

typedef struct r_arch_info_t {
	size_t minisz;
	size_t maxisz;
	size_t align;
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
	size_t syntax; // used for disasm
	RVector dest; // array of destinations
} RArchInstruction;


typedef bool (*RArchEncodeCallback)(RArch *a, RArchInstruction *ins, RArchOptions options);
typedef bool (*RArchDecodeCallback)(RArch *a, RArchInstruction *ins, RArchOptions options);
typedef char * (*RArchRegistersCallback)(RArch *a);
typedef void (*RArchInfoCallback)(RArch *a);

typedef struct r_arch_plugin_t {
	const char *name;
	const char *arch;
	const char *cpus;
	const char *features;
#if 1
	RArchBits bits;
	RArchEndian endian;
#else
	RArchSetup setup;
#endif
	// copyright
	const char *author;
	const char *desc;
	const char *license;
	const char *version;
	// callbacks
	RArchEncodeCallback encode;
	RArchDecodeCallback decode;
	RArchRegistersCallback registers;
	RArchInfoCallback info; // dynamic info
	bool (*init)(void *user);
	bool (*fini)(void *user);
} RArchPlugin;

R_API RArchInstruction *r_arch_instruction_new();
R_API void r_arch_instruction_free(RArchInstruction *ins);
R_API void r_arch_instruction_init(RArchInstruction *ins);
R_API void r_arch_instruction_init_data(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len);
R_API void r_arch_instruction_init_code(RArchInstruction *ins, ut64 addr, const char *opstr);
R_API void r_arch_instruction_fini(RArchInstruction *ins);

R_API RArch *r_arch_new();
R_API void r_arch_free(RArch *arch);

R_API bool r_arch_encode(RArch *a, RArchInstruction *ins, RArchOptions opt);
R_API bool r_arch_decode(RArch *a, RArchInstruction *ins, RArchOptions opt);

R_API bool r_arch_setup(RArch *a, const char *arch, RArchBits bits, RArchEndian endian);
R_API bool r_arch_set_syntax(RArch *a, int syntax);
R_API bool r_arch_set_cpu(RArch *a, const char *cpu);
R_API bool r_arch_set_endian(RArch *a, RArchEndian endian);
R_API bool r_arch_set_bits(RArch *a, int bits);
R_API bool r_arch_use(RArch *a, const char *name);
R_API bool r_arch_add(RArch *a, RArchPlugin *foo);
R_API bool r_arch_del(RArch *a, const char *name);

extern RArchPlugin r_arch_plugin_bf;

#endif
