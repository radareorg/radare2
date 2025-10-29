/* radare2 - LGPL - Copyright 2025 - pancake */

#ifndef R_BIN_SOM_H
#define R_BIN_SOM_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

// only for programs
#define SOM_BADDR ((ut32)0xC0000000)

/* SOM file format constants */
#define SOM_MAGIC_EXEC 0x0107
#define SOM_MAGIC_RELOC 0x0106
#define SOM_MAGIC_SHARE 0x0108
#define SOM_MAGIC_SHMEM 0x0109
#define SOM_MAGIC_DEMAND 0x010b
#define SOM_MAGIC_DL 0x010d
#define SOM_MAGIC_SHL 0x010e

/* SOM subspace flags */
#define SOM_SUBSPACE_ACCESS_CONTROL_BITS_SH 25
#define SOM_SUBSPACE_ACCESS_CONTROL_BITS_MASK 0x7fU
#define SOM_SUBSPACE_MEMORY_RESIDENT (1U << 24)
#define SOM_SUBSPACE_DUP_COMMON (1U << 23)
#define SOM_SUBSPACE_IS_COMMON (1U << 22)
#define SOM_SUBSPACE_IS_LOADABLE (1U << 21)
#define SOM_SUBSPACE_QUADRANT_SH 19
#define SOM_SUBSPACE_QUADRANT_MASK 0x3U
#define SOM_SUBSPACE_INITIALLY_FROZEN (1U << 18)
#define SOM_SUBSPACE_IS_FIRST (1U << 17)
#define SOM_SUBSPACE_CODE_ONLY (1U << 16)
#define SOM_SUBSPACE_SORT_KEY_SH 8
#define SOM_SUBSPACE_SORT_KEY_MASK 0xffU
#define SOM_SUBSPACE_REPLICATE_INIT (1U << 7)
#define SOM_SUBSPACE_CONTINUATION (1U << 6)
#define SOM_SUBSPACE_IS_TSPECIFIC (1U << 5)
#define SOM_SUBSPACE_IS_COMDAT (1U << 4)

/* SOM symbol flags */
#define SOM_SYMBOL_HIDDEN (1u << 31)
#define SOM_SYMBOL_SECONDARY_DEF (1 << 30)
#define SOM_SYMBOL_TYPE_SH 24
#define SOM_SYMBOL_TYPE_MASK 0x3f
#define SOM_SYMBOL_SCOPE_SH 20
#define SOM_SYMBOL_SCOPE_MASK 0xf

/* SOM symbol types */
#define ST_NULL 0
#define ST_ABSOLUTE 1
#define ST_DATA 2
#define ST_CODE 3
#define ST_PRI_PROG 4
#define ST_SEC_PROG 5
#define ST_ENTRY 6
#define ST_STORAGE 7
#define ST_STUB 8
#define ST_MODULE 9
#define ST_SYM_EXT 10
#define ST_ARG_EXT 11
#define ST_MILLICODE 12
#define ST_PLABEL 13
#define ST_OCT_DIS 14
#define ST_MILLI_EXT 15
#define ST_TSTORAGE 16
#define ST_COMDAT 17

/* Internal structures */
typedef struct r_bin_som_header_t {
	ut16 system_id;
	ut16 magic;
	ut32 version_id;
	struct {
		ut32 secs;
		ut32 nanosecs;
	} file_time;
	ut32 entry_space;
	ut32 entry_subspace;
	ut32 entry_offset;
	ut32 aux_header_location;
	ut32 aux_header_size;
	ut32 som_length;
	ut32 presumed_dp;
	ut32 space_location;
	ut32 space_total;
	ut32 subspace_location;
	ut32 subspace_total;
	ut32 loader_fixup_location;
	ut32 loader_fixup_total;
	ut32 space_strings_location;
	ut32 space_strings_size;
	ut32 init_array_location;
	ut32 init_array_total;
	ut32 compiler_location;
	ut32 compiler_total;
	ut32 symbol_location;
	ut32 symbol_total;
	ut32 fixup_request_location;
	ut32 fixup_request_total;
	ut32 symbol_strings_location;
	ut32 symbol_strings_size;
	ut32 unloadable_sp_location;
	ut32 unloadable_sp_size;
	ut32 checksum;
} RBinSomHeader;

typedef struct r_bin_som_space_t {
	ut32 name;
	ut32 flags;
	ut32 space_number;
	ut32 subspace_index;
	ut32 subspace_quantity;
} RSomSpace;

typedef struct r_bin_som_subspace_t {
	ut32 space_index;
	ut32 flags;
	ut32 file_loc_init_value;
	ut32 initialization_length;
	ut32 subspace_start;
	ut32 subspace_length;
	ut32 alignment;
	ut32 name;
	ut32 fixup_request_index;
	ut32 fixup_request_quantity;
} RSomSubspace;

typedef struct r_bin_som_symbol_t {
	ut32 name;
	ut32 qualifier_name;
	ut32 symbol_value;
	ut8 symbol_type;
	ut8 symbol_scope;
	ut8 check_sum;
	ut8 flags;
} RSomSymbol;

typedef struct r_bin_som_dl_header_t {
	ut32 hdr_version;
	ut32 ltptr_value;
	ut32 shlib_list_loc;
	ut32 shlib_list_count;
	ut32 import_list_loc;
	ut32 import_list_count;
	ut32 hash_table_loc;
	ut32 hash_table_size;
	ut32 export_list_loc;
	ut32 export_list_count;
	ut32 string_table_loc;
	ut32 string_table_size;
	ut32 dreloc_loc;
	ut32 dreloc_count;
	ut32 dlt_loc;
	ut32 plt_loc;
	ut32 dlt_count;
	ut32 plt_count;
	ut16 highwater_mark;
	ut16 flags;
	ut32 export_ext_loc;
	ut32 module_loc;
	ut32 module_count;
	ut32 elaborator;
	ut32 initializer;
	ut32 embedded_path;
	ut32 initializer_count;
	ut32 tdsize;
	ut32 fastbind_list_loc;
} RSomDlHeader;

typedef struct r_bin_som_shlib_list_entry_t {
	ut32 shlib_name;
	ut8 reserved1;
	ut8 internal_name;
	ut8 dash_l_reference;
	ut8 bind;
	ut16 highwater_mark;
} RSomShlibListEntry;

typedef struct r_bin_som_import_list_entry_t {
	ut32 import_name;
	ut8 import_type;
	ut8 import_qualifier;
	ut16 reserved;
} RSomImportListEntry;

typedef struct r_bin_som_file_t {
	Sdb *kv;
	RBuffer *buf;
	ut64 baddr;
	RList *spaces;
	RList *subspaces;
	RList *symbols;
	char *space_strings;
	char *symbol_strings;
	RBinSomHeader hdr;
	RSomDlHeader *dl_hdr;
	RList *shlibs;
	RList *imports;
	char *dl_strings;
	char *interp;
} RSomFile;

R_IPI bool r_bin_som_check_buffer(RBuffer *b);
R_IPI void *r_bin_som_load_buffer(RBinFile *bf, RBuffer *b, ut64 laddr, Sdb *s);
R_IPI void r_bin_som_free_buffer(void *bf_o);
R_IPI RList *r_bin_som_get_sections(void *o);
R_IPI RList *r_bin_som_get_symbols(void *o);
R_IPI RList *r_bin_som_get_imports(void *o);
R_IPI RList *r_bin_som_get_libs(void *o);
R_IPI RList *r_bin_som_get_relocs(void *o);
R_IPI RList *r_bin_som_get_entries(void *o);
R_IPI RBinInfo *r_bin_som_get_info(void *o);
R_IPI ut64 r_bin_som_get_baddr(void *o);
R_IPI ut64 r_bin_som_get_size(void *o);

void r_bin_som_free(RSomFile *obj);

#ifdef __cplusplus
}
#endif

#endif
