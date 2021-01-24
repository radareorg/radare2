/* radare2 - LGPL - Copyright 2017-2018 - cgvwzq */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#ifndef _INCLUDE_WASM_H_
#define _INCLUDE_WASM_H_

// version 0x1 (WIP)
// https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md

#define R_BIN_WASM_MAGIC_BYTES "\x00" \
			       "asm"
#define R_BIN_WASM_VERSION 0x1
#define R_BIN_WASM_STRING_LENGTH 256
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

typedef enum {
	R_BIN_WASM_VALUETYPE_i32 = 0x1,
	R_BIN_WASM_VALUETYPE_i64 = 0x2,
	R_BIN_WASM_VALUETYPE_f32 = 0x3,
	R_BIN_WASM_VALUETYPE_f64 = 0x4,
	R_BIN_WASM_VALUETYPE_v128 = 0x5,
	R_BIN_WASM_VALUETYPE_ANYFUNC = 0x10,
	R_BIN_WASM_VALUETYPE_FUNC = 0x20,
	R_BIN_WASM_VALUETYPE_EMPTY = 0x40,
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

typedef struct r_bin_wasm_name_t {
	ut32 len;
	ut8 *name;
} RBinWasmName;

typedef struct r_bin_wasm_section_t {
	ut8 id;
	ut32 size;
	ut32 name_len;
	char *name;
	ut32 offset;
	ut32 payload_data;
	ut32 payload_len;
	ut32 count;
} RBinWasmSection;

typedef struct r_bin_wasm_type_t {
	ut8 form;
	ut32 param_count;
	r_bin_wasm_value_type_t *param_types;
	st8 return_count; // MVP = 1
	r_bin_wasm_value_type_t return_type;
	char to_str[R_BIN_WASM_STRING_LENGTH];
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
	ut32 module_len;
	char module_str[R_BIN_WASM_STRING_LENGTH];
	ut32 field_len;
	char field_str[R_BIN_WASM_STRING_LENGTH];
	ut8 kind;
	union {
		ut32 type_f;
		struct r_bin_wasm_global_type_t type_g;
		struct r_bin_wasm_table_type_t type_t;
		struct r_bin_wasm_memory_type_t type_m;
	};

} RBinWasmImportEntry;

typedef struct r_bin_wasm_function_t {
	ut32 type_index; // index to Type entries
} RBinWasmFunctionEntry;

typedef struct r_bin_wasm_table_t {
	ut8 element_type; // only anyfunc
	struct r_bin_wasm_resizable_limits_t limits;
} RBinWasmTableEntry;

typedef struct r_bin_wasm_memory_t {
	struct r_bin_wasm_resizable_limits_t limits;
} RBinWasmMemoryEntry;

typedef struct r_bin_wasm_global_t {
	r_bin_wasm_value_type_t content_type;
	ut8 mutability; // 0 if immutable, 1 if mutable
	struct r_bin_wasm_init_expr_t init;
} RBinWasmGlobalEntry;

typedef struct r_bin_wasm_export_t {
	ut32 field_len;
	char field_str[R_BIN_WASM_STRING_LENGTH];
	ut8 kind;
	ut32 index;
} RBinWasmExportEntry;

typedef struct r_bin_wasm_start_t {
	ut32 index;
} RBinWasmStartEntry;

struct r_bin_wasm_local_entry_t {
	ut32 count;
	r_bin_wasm_value_type_t type;
};

typedef struct r_bin_wasm_element_t {
	ut32 index;
	struct r_bin_wasm_init_expr_t init;
	ut32 num_elem;
	ut32 elems[];
} RBinWasmElementEntry;

typedef struct r_bin_wasm_code_t {
	ut32 body_size;
	ut32 local_count; // numer of local entries
	struct r_bin_wasm_local_entry_t *locals;
	ut32 code; // offset
	ut32 len; // real bytecode length
	ut8 byte; // 0xb, indicating end of the body
	char *name;
	char *signature;
} RBinWasmCodeEntry;

typedef struct r_bin_wasm_data_t {
	ut32 index; // linear memory index (0 in MVP)
	struct r_bin_wasm_init_expr_t offset; // bytecode evaluated at runtime
	ut32 size;
	ut32 data; // offset
} RBinWasmDataEntry;

// TODO: custom sections


typedef struct r_bin_wasm_custom_name_function_names_t {
	ut32 count;
	RIDStorage *names;
} RBinWasmCustomNameFunctionNames;

typedef struct r_bin_wasm_custom_name_local_name_t {
	ut32 index; // function index

	ut32 names_count;
	RIDStorage *names; // local names
} RBinWasmCustomNameLocalName;

typedef struct r_bin_wasm_custom_name_local_names_t {
	ut32 count;
	RList *locals; // RBinWasmCustomNameLocalName
} RBinWasmCustomNameLocalNames;

// "name" section entry
typedef struct r_bin_wasm_custom_name_entry_t {
	ut8 type;
	ut32 size;

	ut8 payload_data;
	union {
		struct r_bin_wasm_name_t* mod_name;
		RBinWasmCustomNameFunctionNames *func;
		RBinWasmCustomNameLocalNames *local;
	};
} RBinWasmCustomNameEntry;

typedef struct r_bin_wasm_obj_t {

	RBuffer *buf;
	size_t size;

	ut32 entrypoint;

	// cache purposes
	RList *g_sections;
	RList *g_types;
	RList *g_imports;
	RList *g_exports;
	RList *g_tables;
	RList *g_memories;
	RList *g_globals;
	RList *g_elements;
	RList *g_codes;
	RList *g_datas;
	RBinWasmStartEntry *g_start;

	RList *g_names;
	// etc...

} RBinWasmObj;

RBinWasmObj *r_bin_wasm_init(RBinFile *bf, RBuffer *buf);
void r_bin_wasm_destroy(RBinFile *bf);
RList *r_bin_wasm_get_sections(RBinWasmObj *bin);
RList *r_bin_wasm_get_types(RBinWasmObj *bin);
RList *r_bin_wasm_get_imports(RBinWasmObj *bin);
RList *r_bin_wasm_get_exports(RBinWasmObj *bin);
RList *r_bin_wasm_get_tables(RBinWasmObj *bin);
RList *r_bin_wasm_get_memories(RBinWasmObj *bin);
RList *r_bin_wasm_get_globals(RBinWasmObj *bin);
RList *r_bin_wasm_get_elements(RBinWasmObj *bin);
RList *r_bin_wasm_get_codes(RBinWasmObj *bin);
RList *r_bin_wasm_get_datas(RBinWasmObj *bin);
RList *r_bin_wasm_get_custom_names(RBinWasmObj *bin);
ut32 r_bin_wasm_get_entrypoint(RBinWasmObj *bin);
const char *r_bin_wasm_get_function_name(RBinWasmObj *bin, ut32 idx);
const char *r_bin_wasm_valuetype_to_string(r_bin_wasm_value_type_t type);

#endif
