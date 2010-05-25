/* radare - LGPL - Copyright 2008-2010 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_BIN_H_
#define _INCLUDE_R_BIN_H_

#include <r_util.h>
#include <r_types.h>
#include <r_list.h>
#include <list.h>

#define R_BIN_SCN_EXECUTABLE(x) x & 0x1
#define R_BIN_SCN_WRITABLE(x)   x & 0x2
#define R_BIN_SCN_READABLE(x)   x & 0x4
#define R_BIN_SCN_SHAREABLE(x)  x & 0x8

#define R_BIN_DBG_STRIPPED(x) x & 0x01
#define R_BIN_DBG_STATIC(x)   x & 0x02
#define R_BIN_DBG_LINENUMS(x) x & 0x04
#define R_BIN_DBG_SYMS(x)     x & 0x08
#define R_BIN_DBG_RELOCS(x)   x & 0x10

#define R_BIN_SIZEOF_STRINGS 256

typedef struct r_bin_t {
	const char *file;
	int size;
	void *bin_obj;
	ut64 baddr;
	struct r_bin_info_t *info;
	RList* entries;
	RList* sections;
	RList* symbols;
	RList* imports;
	RList* strings;
	RList* fields;
	RList* libs;
	RBuffer *buf;
	void *user;
	struct r_bin_plugin_t *cur;
	struct list_head bins;
} RBin;

typedef struct r_bin_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*load)(RBin *bin);
	int (*destroy)(RBin *bin);
	int (*check)(RBin *bin);
	ut64 (*baddr)(RBin *bin);
	RList* (*entries)(RBin *bin);
	RList* (*sections)(RBin *bin);
	RList* (*symbols)(RBin *bin);
	RList* (*imports)(RBin *bin);
	RList* (*strings)(RBin *bin);
	struct r_bin_info_t* (*info)(RBin *bin);
	RList* (*fields)(RBin *bin);
	RList* (*libs)(RBin *bin);
	struct r_bin_meta_t *meta;
	struct r_bin_write_t *write;
	struct list_head list;
} RBinPlugin;

typedef struct r_bin_entry_t {
	ut64 rva;
	ut64 offset;
} RBinEntry;

typedef struct r_bin_section_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 size;
	ut64 vsize;
	ut64 rva;
	ut64 offset;
	ut64 characteristics;
} RBinSection;

typedef struct r_bin_symbol_t {
	char name[R_BIN_SIZEOF_STRINGS];
	char forwarder[R_BIN_SIZEOF_STRINGS];
	char bind[R_BIN_SIZEOF_STRINGS];
	char type[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
	ut64 size;
	ut64 ordinal;
} RBinSymbol;

typedef struct r_bin_import_t {
	char name[R_BIN_SIZEOF_STRINGS];
	char bind[R_BIN_SIZEOF_STRINGS];
	char type[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
	ut64 ordinal;
	ut64 hint;
} RBinImport;

typedef struct r_bin_string_t {
	char string[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
	ut64 ordinal;
	ut64 size;
} RBinString;

typedef struct r_bin_info_t {
	char file[R_BIN_SIZEOF_STRINGS];
	char type[R_BIN_SIZEOF_STRINGS];
	char bclass[R_BIN_SIZEOF_STRINGS];
	char rclass[R_BIN_SIZEOF_STRINGS];
	char arch[R_BIN_SIZEOF_STRINGS];
	char machine[R_BIN_SIZEOF_STRINGS];
	char os[R_BIN_SIZEOF_STRINGS];
	char subsystem[R_BIN_SIZEOF_STRINGS];
	char rpath[R_BIN_SIZEOF_STRINGS];
	int bits;
	int big_endian;
	ut64 dbg_info;
} RBinInfo;

typedef struct r_bin_field_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
} RBinField;

typedef struct r_bin_meta_t {
	int (*get_line)(RBin *bin, ut64 addr, char *file, int len, int *line);
} RBinMeta;

typedef struct r_bin_write_t {
	ut64 (*scn_resize)(RBin *bin, const char *name, ut64 size);
	int (*rpath_del)(RBin *bin);
} RBinWrite;

#ifdef R_API

/* bin.c */
R_API int r_bin_add(RBin *bin, RBinPlugin *foo);
R_API void* r_bin_free(RBin *bin);
R_API int r_bin_list(RBin *bin);
R_API int r_bin_load(RBin *bin, const char *file, const char *plugin_name);
R_API ut64 r_bin_get_baddr(RBin *bin);
R_API RList* r_bin_get_entries(RBin *bin);
R_API RList* r_bin_get_fields(RBin *bin);
R_API RList* r_bin_get_imports(RBin *bin);
R_API RBinInfo* r_bin_get_info(RBin *bin);
R_API RList* r_bin_get_libs(RBin *bin);
R_API RList* r_bin_get_sections(RBin *bin);
R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va);
R_API RList* r_bin_get_strings(RBin *bin);
R_API RList* r_bin_get_symbols(RBin *bin);
R_API int r_bin_is_big_endian (RBin *bin);
R_API int r_bin_is_stripped (RBin *bin);
R_API int r_bin_is_static (RBin *bin);
R_API int r_bin_has_dbg_linenums (RBin *bin);
R_API int r_bin_has_dbg_syms (RBin *bin);
R_API int r_bin_has_dbg_relocs (RBin *bin);
R_API RBin* r_bin_new();
R_API void r_bin_set_user_ptr(RBin *bin, void *user);

/* bin_meta.c */
R_API int r_bin_meta_get_line(RBin *bin, ut64 addr, char *file, int len, int *line);
R_API char *r_bin_meta_get_source_line(RBin *bin, ut64 addr);

/* bin_write.c */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
R_API int r_bin_wr_rpath_del(RBin *bin);
R_API int r_bin_wr_output(RBin *bin, const char *filename);
#endif

#endif
