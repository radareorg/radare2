/* radare - LGPL - Copyright 2008-2012 nibble<.ds@gmail.com>, pancake <nopcode.org> */

#ifndef _INCLUDE_R_BIN_H_
#define _INCLUDE_R_BIN_H_

#include <r_util.h>
#include <r_types.h>
#include <r_list.h>

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
#define R_BIN_MAX_ARCH 1024

enum {
	R_BIN_SYM_ENTRY,
	R_BIN_SYM_INIT,
	R_BIN_SYM_MAIN,
	R_BIN_SYM_FINI,
	R_BIN_SYM_LAST
};

// name mangling types
enum {
	R_BIN_NM_JAVA,
	R_BIN_NM_CXX,
	R_BIN_NM_ANY=-1,
};

enum {
	R_BIN_CLASS_PRIVATE,
	R_BIN_CLASS_PUBLIC,
	R_BIN_CLASS_FRIENDLY,
	R_BIN_CLASS_PROTECTED,
};

// XXX: isnt this a copy of Obj ?
typedef struct r_bin_arch_t {
	char *file;
	int size;
	ut64 baddr;
	ut64 offset;
	struct r_bin_addr_t *binsym[R_BIN_SYM_LAST];
	struct r_bin_info_t *info;
	RList* entries;
	RList* sections;
	RList* symbols;
	RList* imports;
	RList* strings;
	RList* fields;
	RList* libs;
	RList* relocs;
	RList* classes;
	RBuffer *buf;
	void *bin_obj;
	struct r_bin_plugin_t *curplugin;
} RBinArch;

typedef struct r_bin_t {
	char *file;
	RBinArch curarch;
	int narch;
	void *user;
	void *bin_obj;
	struct r_bin_xtr_plugin_t *curxtr;
	RList *plugins;
	RList *binxtrs;
} RBin;

typedef struct r_bin_xtr_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*check)(RBin *bin);
	int (*extract)(RBin *bin, int idx);
	int (*load)(RBin *bin);
	int (*destroy)(RBin *bin);
} RBinXtrPlugin;

typedef struct r_bin_plugin_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*load)(RBinArch *arch);
	int (*destroy)(RBinArch *arch);
	int (*check)(RBinArch *arch);
	ut64 (*baddr)(RBinArch *arch);
	struct r_bin_addr_t* (*binsym)(RBinArch *arch, int num);
	RList* (*entries)(RBinArch *arch);
	RList* (*sections)(RBinArch *arch);
	RList* (*symbols)(RBinArch *arch);
	RList* (*imports)(RBinArch *arch);
	RList* (*strings)(RBinArch *arch);
	struct r_bin_info_t* (*info)(RBinArch *arch);
	RList* (*fields)(RBinArch *arch);
	RList* (*libs)(RBinArch *arch);
	RList* (*relocs)(RBinArch *arch);
	RList* (*classes)(RBinArch *arch);
	int (*demangle_type)(const char *str);
	struct r_bin_meta_t *meta;
	struct r_bin_write_t *write;
	int (*get_offset)(RBinArch *arch, int type, int idx);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen);
} RBinPlugin;

typedef struct r_bin_addr_t {
	ut64 rva;
	ut64 offset;
} RBinAddr;

typedef struct r_bin_section_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 size;
	ut64 vsize;
	ut64 rva;
	ut64 offset;
	ut64 srwx;
} RBinSection;

typedef struct r_bin_class_t {
	char *name;
	char *super;
	RList *methods;
	RList *fields;
	int visibility;
} RBinClass;

#define RBinSectionName r_offsetof(RBinSection, name)
#define RBinSectionOffset r_offsetof(RBinSection, offset)
// usage:
// r_list_get_by_name(bin->sections, RBinSectionName, ".text");
// bin.sections.get_by_name(SectionName, ".text");

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
	ut64 size;
	ut64 ordinal;
	ut64 hint;
} RBinImport;

typedef struct r_bin_reloc_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
	int sym;
	int type;
} RBinReloc;

typedef struct r_bin_string_t {
	// TODO: rename string->name (avoid colisions)
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
	int has_va;
	int big_endian;
	ut64 dbg_info;
} RBinInfo;

typedef struct r_bin_field_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
} RBinField;

typedef struct r_bin_meta_t {
	int (*get_line)(RBinArch *arch, ut64 addr, char *file, int len, int *line);
} RBinMeta;

typedef struct r_bin_write_t {
	ut64 (*scn_resize)(RBinArch *arch, const char *name, ut64 size);
	int (*rpath_del)(RBinArch *arch);
} RBinWrite;

/* totally unused */
typedef struct r_bin_obj_t {
	ut64 baddr;
	RList/*<RBinSection>*/ *sections;
	RList/*<RBinImport>*/ *imports;
	RList/*<RBinSymbol>*/ *symbols;
	RList/*<??>*/ *entries;
	RList/*<??>*/ *fields;
	RList/*<??>*/ *libs;
	RList/*<??>*/ *relocs;
	RList/*<??>*/ *strings;
	RList/*<RBinClass>*/ *classes;
	RBinInfo *info;
	RBinAddr *binsym[R_BIN_SYM_LAST];
// TODO: deprecate r_bin_is_big_endian
// TODO: r_bin_is_stripped .. wrapped inside rbinobj?
// TODO: has_dbg_syms... maybe flags?
} RBinObj;

typedef int (*RBinGetOffset)(RBin *bin, int type, int idx);

typedef struct r_bin_bind_t {
	RBin *bin;
	RBinGetOffset get_offset;
} RBinBind;


#ifdef R_API
R_API void r_bin_bind(RBin *b, struct r_bin_bind_t *bnd);
/* bin.c */
R_API int r_bin_add(RBin *bin, RBinPlugin *foo);
R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo);
R_API void* r_bin_free(RBin *bin);
R_API int r_bin_list(RBin *bin);
R_API int r_bin_load(RBin *bin, const char *file, int dummy);
R_API RBinObj *r_bin_get_object(RBin *bin, int flags);
R_API ut64 r_bin_get_baddr(RBin *bin);
R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym);
R_API char* r_bin_demangle(RBin *bin, const char *str);
R_API int r_bin_demangle_type (const char *str);
R_API char *r_bin_demangle_java(const char *str);
R_API char *r_bin_demangle_cxx(const char *str);
R_API RList* r_bin_get_entries(RBin *bin);
R_API RList* r_bin_get_fields(RBin *bin);
R_API RList* r_bin_get_imports(RBin *bin);
R_API RBinInfo* r_bin_get_info(RBin *bin);
R_API RList* r_bin_get_libs(RBin *bin);
R_API RList* r_bin_get_relocs(RBin *bin);
R_API RList* r_bin_get_sections(RBin *bin);
R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin);
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
R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name);
R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name);
R_API int r_bin_select_idx(RBin *bin, int idx);
R_API void r_bin_list_archs(RBin *bin);
R_API void r_bin_set_user_ptr(RBin *bin, void *user);
R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen);
/* bin_meta.c */
R_API int r_bin_meta_get_line(RBin *bin, ut64 addr, char *file, int len, int *line);
R_API char *r_bin_meta_get_source_line(RBin *bin, ut64 addr);
R_API ut64 r_bin_get_offset (RBin *bin);
/* bin_write.c */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
R_API int r_bin_wr_rpath_del(RBin *bin);
R_API int r_bin_wr_output(RBin *bin, const char *filename);

/* plugin pointers */
extern RBinPlugin r_bin_plugin_any;
extern RBinPlugin r_bin_plugin_fs;
extern RBinPlugin r_bin_plugin_elf;
extern RBinPlugin r_bin_plugin_elf64;
extern RBinPlugin r_bin_plugin_p9;
extern RBinPlugin r_bin_plugin_pe;
extern RBinPlugin r_bin_plugin_pe64;
extern RBinPlugin r_bin_plugin_mach0;
extern RBinPlugin r_bin_plugin_mach064;
extern RBinPlugin r_bin_plugin_java;
extern RBinPlugin r_bin_plugin_dex;
extern RBinPlugin r_bin_plugin_dummy;
extern RBinXtrPlugin r_bin_xtr_plugin_fatmach0;
extern RBinXtrPlugin r_bin_xtr_plugin_dyldcache;
#endif
#endif
