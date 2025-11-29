/* radare2 - LGPL - Copyright 2017-2018 - cgvwzq */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_vector.h>

#ifndef _INCLUDE_WASM_H_
#define _INCLUDE_WASM_H_

// version 0x1 (WIP)
// https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md

#define R_BIN_WASM_MAGIC_BYTES "\x00" \
			       "asm"
#define R_BIN_WASM_VERSION 0x1
#define R_BIN_WASM_END_OF_CODE 0xb

#define R_BIN_WASM_SECTION_CUSTOM 0x0
#define R_BIN_WASM_SECTION_TYPE 0x1
#define R_BIN_WASM_SECTION_IMPORT 0x2
#define R_BIN_WASM_SECTION_FUNCTION 0x3
#define R_BIN_WASM_SECTION_TABLE 0x4
#define R_BIN_WASM_SECTION_MEMORY 0x5
#define R_BIN_WASM_SECTION_GLOBAL 0x6
#define R_BIN_WASM_SECTION_EXPORT 0x7
#define R_BIN_WASM_SECTION_START 0x8
#define R_BIN_WASM_SECTION_ELEMENT 0x9
#define R_BIN_WASM_SECTION_CODE 0xa
#define R_BIN_WASM_SECTION_DATA 0xb

/*
 * Value types From:
 * https://webassembly.github.io/spec/core/binary/types.html#value-types,
 * https://webassembly.github.io/spec/core/binary/types.html#binary-numtype
 * https://github.com/sunfishcode/wasm-reference-manual/blob/master/WebAssembly.md#type-encoding-type
 */
typedef enum {
	R_BIN_WASM_VALUETYPE_i32 = 0x7f,
	R_BIN_WASM_VALUETYPE_i64 = 0x7e,
	R_BIN_WASM_VALUETYPE_f32 = 0x7d,
	R_BIN_WASM_VALUETYPE_f64 = 0x7c,
	R_BIN_WASM_VALUETYPE_v128 = 0x7b,
	R_BIN_WASM_VALUETYPE_REFTYPE = 0x70,
	R_BIN_WASM_VALUETYPE_EXTERNREF = 0x6f,
	R_BIN_WASM_VALUETYPE_FUNC = 0x60,
	R_BIN_WASM_VALUETYPE_VOID = 0x40,
} r_bin_wasm_value_type_t;

typedef enum {
	R_BIN_WASM_EXTERNALKIND_Function = 0x0,
	R_BIN_WASM_EXTERNALKIND_Table = 0x1,
	R_BIN_WASM_EXTERNALKIND_Memory = 0x2,
	R_BIN_WASM_EXTERNALKIND_Global = 0x3,
} r_bin_wasm_external_kind_t;

typedef enum {
	R_BIN_WASM_NAMETYPE_Module = 0x0,
	R_BIN_WASM_NAMETYPE_Function = 0x1,
	R_BIN_WASM_NAMETYPE_Local = 0x2,
	R_BIN_WASM_NAMETYPE_None = 0xff,
} r_bin_wasm_custom_name_type_t;

struct r_bin_wasm_init_expr_t {
	// bytecode	terminated in 0xb
	size_t len;
};

struct r_bin_wasm_resizable_limits_t {
	ut8 flags; // 1 if max field is present, 0 otherwise
	ut32 initial;
	ut32 maximum;
};

typedef struct r_bin_wasm_section_t {
	ut8 id;
	ut32 size;
	ut32 name_len;
	char *name;
	ut32 offset;
	ut32 payload_data;
	ut32 payload_len;
} RBinWasmSection;

typedef struct r_bin_wasm_type_vector_t {
	ut32 count;
	ut8 *types;
} RBinWasmTypeVec;

typedef struct r_bin_wasm_type_t {
	ut32 sec_i;
	ut64 file_offset;
	ut8 form;
	RBinWasmTypeVec *args;
	RBinWasmTypeVec *rets;
	char *to_str;
} RBinWasmTypeEntry;

// Other Types
struct r_bin_wasm_global_type_t {
	r_bin_wasm_value_type_t content_type;
	ut8 mutability;
};

struct r_bin_wasm_table_type_t {
	r_bin_wasm_value_type_t elem_type;
	struct r_bin_wasm_resizable_limits_t limits;
};

struct r_bin_wasm_memory_type_t {
	struct r_bin_wasm_resizable_limits_t limits;
};

typedef struct r_bin_wasm_import_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 module_len;
	char *module_str;
	ut32 field_len;
	char *field_str;
	ut8 kind;
	union {
		ut32 type_f;
		struct r_bin_wasm_global_type_t type_g;
		struct r_bin_wasm_table_type_t type_t;
		struct r_bin_wasm_memory_type_t type_m;
	};
} RBinWasmImportEntry;

typedef struct r_bin_wasm_function_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 typeindex;
} RBinWasmFunctionEntry;

typedef struct r_bin_wasm_table_t {
	ut32 sec_i;
	ut64 file_offset;
	ut8 element_type; // only anyfunc
	struct r_bin_wasm_resizable_limits_t limits;
} RBinWasmTableEntry;

typedef struct r_bin_wasm_memory_t {
	ut32 sec_i;
	ut64 file_offset;
	struct r_bin_wasm_resizable_limits_t limits;
} RBinWasmMemoryEntry;

typedef struct r_bin_wasm_global_t {
	ut32 sec_i;
	ut64 file_offset;
	r_bin_wasm_value_type_t content_type;
	ut8 mutability; // 0 if immutable, 1 if mutable
	struct r_bin_wasm_init_expr_t init;
} RBinWasmGlobalEntry;

typedef struct r_bin_wasm_export_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 field_len;
	char *field_str;
	ut8 kind;
	ut32 index;
} RBinWasmExportEntry;

typedef struct r_bin_wasm_start_t {
	ut32 index;
} RBinWasmStartEntry;

struct r_bin_wasm_local_entry_t {
	ut32 count;
	st8 type; // r_bin_wasm_value_type_t
};

typedef struct r_bin_wasm_element_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 index;
	struct r_bin_wasm_init_expr_t init;
	ut32 num_elem;
	ut32 elems[];
} RBinWasmElementEntry;

typedef struct r_bin_wasm_code_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 body_size;
	ut32 local_count; // numer of local entries
	struct r_bin_wasm_local_entry_t *locals;
	ut32 code; // offset
	ut32 len; // real bytecode length
} RBinWasmCodeEntry;

typedef struct r_bin_wasm_data_t {
	ut32 sec_i;
	ut64 file_offset;
	ut32 index; // linear memory index (0 in MVP)
	struct r_bin_wasm_init_expr_t offset; // bytecode evaluated at runtime
	ut32 size;
	ut32 data; // offset
} RBinWasmDataEntry;

typedef struct r_bin_wasm_custom_module {
	ut64 file_offset;
	char *name;
} RBinWasmCustomModule;

typedef struct r_bin_wasm_custom_function {
	ut64 file_offset;
	RIDStorage *store; // RIDStorage of char *
} RBinWasmCustomFunction;

typedef struct r_bin_wasm_custom_locals {
	ut64 file_offset;
	RIDStorage *store; // 2d idstore, RIDStorage of RIDStorage of char *
} RBinWasmCustomLocals;

typedef struct r_bin_wasm_custom_names {
	RBinWasmCustomModule mod;
	RBinWasmCustomFunction funcs;
	RBinWasmCustomLocals locals;
} RBinWasmCustomNames;

typedef struct r_bin_wasm_obj_t {
	RBuffer *buf;
	size_t size;

	ut32 entrypoint;

	// cache purposes
	RList *g_sections;
	RPVector *g_types;
	RPVector *g_imports_arr[4];
	RPVector *g_funcs;
	RPVector *g_tables;
	RPVector *g_memories;
	RPVector *g_globals;
	RPVector *g_exports;
	RPVector *g_elements;
	RPVector *g_codes;
	RPVector *g_datas;
	ut32 g_start;

	// custom sections
	RBinWasmCustomNames *names;
} RBinWasmObj;

RBinWasmObj *r_bin_wasm_init(RBinFile *bf, RBuffer *buf);
void r_bin_wasm_destroy(RBinFile *bf);
RList *r_bin_wasm_get_sections(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_types(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_imports_kind(RBinWasmObj *bin, ut32 kind);
RPVector *r_bin_wasm_get_functions(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_tables(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_memories(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_globals(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_exports(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_elements(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_codes(RBinWasmObj *bin);
RPVector *r_bin_wasm_get_datas(RBinWasmObj *bin);
RBinWasmCustomNames *r_bin_wasm_get_custom_names(RBinWasmObj *bin);
ut32 r_bin_wasm_get_entrypoint(RBinWasmObj *bin);
const char *r_bin_wasm_get_function_name(RBinWasmObj *bin, ut32 idx);
const char *r_bin_wasm_valuetype_tostring(r_bin_wasm_value_type_t type);

#endif
