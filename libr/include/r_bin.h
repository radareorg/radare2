/* radare - LGPL - Copyright 2008-2014 - nibble, pancake */

#ifndef R2_BIN_H
#define R2_BIN_H

#include <r_util.h>
#include <r_types.h>
#include <r_db.h>
#include <r_io.h>
#include <r_list.h>
#include <r_bin_dwarf.h>
#include <r_pdb.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_bin);

#define R_BIN_SCN_EXECUTABLE 0x1
#define R_BIN_SCN_WRITABLE   0x2
#define R_BIN_SCN_READABLE   0x4
#define R_BIN_SCN_SHAREABLE  0x8

#define R_BIN_DBG_STRIPPED 0x01
#define R_BIN_DBG_STATIC   0x02
#define R_BIN_DBG_LINENUMS 0x04
#define R_BIN_DBG_SYMS     0x08
#define R_BIN_DBG_RELOCS   0x10

#define R_BIN_SIZEOF_STRINGS 512
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
	R_BIN_NM_NONE = 0,
	R_BIN_NM_JAVA = 1,
	R_BIN_NM_CXX = 2,
	R_BIN_NM_OBJC= 3,
	R_BIN_NM_ANY = -1,
};

enum {
	R_BIN_CLASS_PRIVATE,
	R_BIN_CLASS_PUBLIC,
	R_BIN_CLASS_FRIENDLY,
	R_BIN_CLASS_PROTECTED,
};

enum {
	R_BIN_RELOC_8 = 8,
	R_BIN_RELOC_16 = 16,
	R_BIN_RELOC_32 = 32,
	R_BIN_RELOC_64 = 64
};

typedef struct r_bin_addr_t {
	ut64 vaddr;
	ut64 paddr;
} RBinAddr;

typedef struct r_bin_hash_t {
	const char *type;
	ut64 addr;
	int len;
	ut64 from;
	ut64 to;
	ut8 buf[32];
	const char *cmd;
} RBinHash;

typedef struct r_bin_info_t {
	char file[R_BIN_SIZEOF_STRINGS+1];
	char type[R_BIN_SIZEOF_STRINGS+1];
	char bclass[R_BIN_SIZEOF_STRINGS+1];
	char rclass[R_BIN_SIZEOF_STRINGS+1];
	char arch[R_BIN_SIZEOF_STRINGS+1];
	char cpu[R_BIN_SIZEOF_STRINGS+1];
	char machine[R_BIN_SIZEOF_STRINGS+1];
	char os[R_BIN_SIZEOF_STRINGS+1];
	char subsystem[R_BIN_SIZEOF_STRINGS+1];
	char rpath[R_BIN_SIZEOF_STRINGS+1];
	char guid[R_BIN_SIZEOF_STRINGS+1];
	char debug_file_name[R_BIN_SIZEOF_STRINGS+1];
	const char *lang;
	int bits;
	int has_va;
	int has_pi; // pic/pie
	int has_canary;
	int has_crypto;
	int has_nx;
	int big_endian;
	ut64 dbg_info;
	RBinHash sum[3];
#if 0
// stored in sdb
	/* crypto (iOS bins) */
	int crypt_offset;
	int crypt_size;
	int crypt_enabled;
#endif
} RBinInfo;

typedef struct r_bin_object_t {
	ut32 id;
	ut64 baddr;
	ut64 loadaddr;
	ut64 boffset;
	int size;
	ut64 obj_size;
	RList/*<RBinSection>*/ *sections;
	RList/*<RBinImport>*/ *imports;
	RList/*<RBinSymbol>*/ *symbols;
	RList/*<??>*/ *entries;
	RList/*<??>*/ *fields;
	RList/*<??>*/ *libs;
	RList/*<??>*/ *relocs;
	RList/*<??>*/ *strings;
	RList/*<RBinClass>*/ *classes;
	RList/*<RBinDwarfRow>*/ *lines;
	RBinInfo *info;
	RBinAddr *binsym[R_BIN_SYM_LAST];
	struct r_bin_plugin_t *plugin;
	int referenced;
	int lang;
	Sdb *kv;
	void *bin_obj; // internal pointer used by formats
} RBinObject;

// XXX: this is a copy of RBinObject
typedef struct r_bin_file_t {
	char *file;
	int fd;
	int size;
	int rawstr;
	ut32 id;
	RBuffer *buf;
	ut64 offset;
	RBinObject *o;
	void *xtr_obj;
	ut64 loadaddr;
	/* values used when searching the strings */
	int minstrlen;
	int maxstrlen;
	int narch;
	struct r_bin_xtr_plugin_t *curxtr;
	struct r_bin_plugin_t *curplugin;
	RList *objs;
	Sdb *sdb;
	Sdb *sdb_info;
	Sdb *sdb_addrinfo;
	struct r_bin_t *rbin;
} RBinFile;

typedef struct r_bin_t {
	const char *file;
	RBinFile *cur;
	int narch;
	void *user;
	/* preconfigured values */
	int minstrlen;
	int maxstrlen;
	int rawstr;
	Sdb *sdb;
	RList/*<RBinPlugin>*/ *plugins;
	RList/*<RBinXtrPlugin>*/ *binxtrs;
	RList/*<RBinFile>*/ *binfiles;
	PrintfCallback printf;
	int loadany;
	RIOBind iob;
} RBin;

typedef int (*FREE_XTR)(void *xtr_obj);
typedef struct r_bin_xtr_extract_t {
	char *file;
	RBuffer *buf;
	ut64 size;
	ut64 offset;
	int file_count;
	void *xtr_obj;
	FREE_XTR free_xtr;
} RBinXtrData;

R_API RBinXtrData * r_bin_xtrdata_new (void *xtr_obj, FREE_XTR free_xtr, RBuffer *buf, ut64 offset, ut64 size, ut32 file_count);
R_API void r_bin_xtrdata_free (void /*RBinXtrData*/ *data);

typedef struct r_bin_xtr_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*check)(RBin *bin);
	int (*check_bytes)(const ut8 *bytes, ut64 sz);
	RBinXtrData * (*extract_from_bytes)(const ut8 *buf, ut64 size, int idx);
	RList * (*extractall_from_bytes)(const ut8 *buf, ut64 size);
	RBinXtrData * (*extract)(RBin *bin, int idx);
	RList * (*extractall)(RBin *bin);
	int (*load)(RBin *bin);
	int (*size)(RBin *bin);
	int (*destroy)(RBin *bin);
	int (*free_xtr)(void *xtr_obj);
} RBinXtrPlugin;

typedef struct r_bin_plugin_t {
	char *name;
	char *desc;
	char *license;
	int (*init)(void *user);
	int (*fini)(void *user);
	Sdb * (*get_sdb)(RBinObject *obj);
	int (*load)(RBinFile *arch);
	void *(*load_bytes)(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb);
	int (*size)(RBinFile *bin); // return ut64 maybe? meh
	int (*destroy)(RBinFile *arch);
	int (*check)(RBinFile *arch);
	int (*check_bytes)(const ut8 *buf, ut64 length);
	ut64 (*baddr)(RBinFile *arch);
	ut64 (*boffset)(RBinFile *arch);
	RBinAddr* (*binsym)(RBinFile *arch, int num);
	RList* (*entries)(RBinFile *arch);
	RList* (*sections)(RBinFile *arch);
	RList* (*lines)(RBinFile *arch);
	RList* (*symbols)(RBinFile *arch);
	RList* (*imports)(RBinFile *arch);
	RList* (*strings)(RBinFile *arch);
	RBinInfo* (*info)(RBinFile *arch);
	RList* (*fields)(RBinFile *arch);
	RList* (*libs)(RBinFile *arch);
	RList* (*relocs)(RBinFile *arch);
	RList* (*classes)(RBinFile *arch);
	int (*demangle_type)(const char *str);
	struct r_bin_dbginfo_t *dbginfo;
	struct r_bin_write_t *write;
	int (*get_offset)(RBinFile *arch, int type, int idx);
	ut64 (*get_vaddr)(RBinFile *arch, ut64 baddr, ut64 paddr, ut64 vaddr);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen);
	/* default value if not specified by user */
	int minstrlen;
	void *user;
} RBinPlugin;

typedef struct r_bin_section_t {
	char name[R_BIN_SIZEOF_STRINGS+1];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 srwx;
	// per section platform info
	const char *arch;
	int bits;
} RBinSection;

typedef struct r_bin_class_t {
	char *name;
	char *super;
	char *visibility_str;
	int index;
	RList *methods; // <RBinSymbol>
	RList *fields; // <RBinField>
	int visibility;
} RBinClass;

#define RBinSectionName r_offsetof(RBinSection, name)
#define RBinSectionOffset r_offsetof(RBinSection, offset)
// usage:
// r_list_get_by_name(bin->sections, RBinSectionName, ".text");
// bin.sections.get_by_name(SectionName, ".text");

typedef struct r_bin_symbol_t {
	char name[R_BIN_SIZEOF_STRINGS+1];
	char forwarder[R_BIN_SIZEOF_STRINGS+1];
	char bind[R_BIN_SIZEOF_STRINGS+1];
	char type[R_BIN_SIZEOF_STRINGS+1];
	char visibility_str[R_BIN_SIZEOF_STRINGS+1];
	char classname[R_BIN_SIZEOF_STRINGS+1];
	char descriptor[R_BIN_SIZEOF_STRINGS+1];
	ut64 vaddr;
	ut64 paddr;
	ut32 size;
	ut32 ordinal;
	ut32 visibility;
	// int bits;
} RBinSymbol;

typedef struct r_bin_import_t {
	char name[R_BIN_SIZEOF_STRINGS+1];
	char bind[R_BIN_SIZEOF_STRINGS+1];
	char type[R_BIN_SIZEOF_STRINGS+1];
	char classname[R_BIN_SIZEOF_STRINGS+1];
	char descriptor[R_BIN_SIZEOF_STRINGS+1];
	ut32 ordinal;
	ut32 visibility;
} RBinImport;

typedef struct r_bin_reloc_t {
	ut8 type;
	ut8 additive;
	RBinSymbol *symbol;
	RBinImport *import;
	st64 addend;
	ut64 vaddr;
	ut64 paddr;
	ut32 visibility;
} RBinReloc;

typedef struct r_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char string[R_BIN_SIZEOF_STRINGS+1];
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	char type; // Ascii Wide cp850 utf8 ...
} RBinString;

typedef struct r_bin_field_t {
	char name[R_BIN_SIZEOF_STRINGS+1];
	ut64 vaddr;
	ut64 paddr;
	ut32 visibility;
} RBinField;

typedef struct r_bin_dbginfo_t {
	int (*get_line)(RBinFile *arch, ut64 addr, char *file, int len, int *line);
} RBinDbgInfo;

typedef struct r_bin_write_t {
	ut64 (*scn_resize)(RBinFile *arch, const char *name, ut64 size);
	int (*rpath_del)(RBinFile *arch);
} RBinWrite;

// TODO: deprecate r_bin_is_big_endian
// TODO: has_dbg_syms... maybe flags?

typedef int (*RBinGetOffset)(RBin *bin, int type, int idx);
typedef const char *(*RBinGetName)(RBin *bin, int off);

typedef struct r_bin_bind_t {
	RBin *bin;
	RBinGetOffset get_offset;
	RBinGetName get_name;
	ut32 visibility;
} RBinBind;

#ifdef R_API

#define r_bin_class_free(x) { free(x->name);free(x->super);free (x); }

/* bin.c */
R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr);
R_API int r_bin_reload(RBin *bin, RIODesc *desc, ut64 baseaddr);
R_API int r_bin_load_as(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr, int fileoffset, const char *name);
R_API int r_bin_load_io(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx);
R_API int r_bin_load_io_at_offset_as(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name);
R_API int r_bin_load_io_at_offset_as_sz(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name, ut64 sz);
R_API void r_bin_bind(RBin *b, RBinBind *bnd);
R_API int r_bin_add(RBin *bin, RBinPlugin *foo);
R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo);
R_API void* r_bin_free(RBin *bin);
R_API int r_bin_load_languages(RBinFile *binfile);
R_API int r_bin_dump_strings(RBinFile *a, int min);
// ref
R_API int r_bin_file_deref_by_bind (RBinBind * binb);
R_API int r_bin_file_deref (RBin *bin, RBinFile * a);
R_API int r_bin_file_ref_by_bind (RBinBind * binb);
R_API int r_bin_file_ref (RBin *bin, RBinFile * a);
R_API int r_bin_list(RBin *bin);
R_API RBinObject *r_bin_get_object(RBin *bin);
R_API ut64 r_bin_get_baddr(RBin *bin);
R_API void r_bin_set_baddr(RBin *bin, ut64 baddr);
R_API ut64 r_bin_get_boffset(RBin *bin);
R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym);

R_API char* r_bin_demangle(RBinFile *binfile, const char *str);
R_API int r_bin_demangle_type (const char *str);
R_API char *r_bin_demangle_java(const char *str);
R_API char *r_bin_demangle_cxx(const char *str);
R_API char *r_bin_demangle_objc(RBinFile *binfile, const char *sym);
R_API int r_bin_lang_objc(RBinFile *binfile);
R_API int r_bin_lang_cxx(RBinFile *binfile);

R_API RList* r_bin_get_entries(RBin *bin);
R_API RList* r_bin_get_fields(RBin *bin);
R_API RList* r_bin_get_imports(RBin *bin);
R_API RBinInfo* r_bin_get_info(RBin *bin);
R_API RList* r_bin_get_libs(RBin *bin);
R_API ut64 r_bin_get_size (RBin *bin);
R_API RList* r_bin_get_relocs(RBin *bin);
R_API RList* r_bin_get_sections(RBin *bin);
R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin);

R_API RBinClass *r_bin_class_get (RBinFile *binfile, const char *name);
R_API RBinClass *r_bin_class_new (RBinFile *binfile, const char *name, const char *super, int view);
R_API int r_bin_class_add_method (RBinFile *binfile, const char *classname, const char *name, int nargs);
R_API void r_bin_class_add_field (RBinFile *binfile, const char *classname, const char *name);

R_API RBinSection* r_bin_get_section_at(RBinObject *o, ut64 off, int va);
R_API RList* r_bin_get_strings(RBin *bin);
R_API RList* r_bin_reset_strings(RBin *bin);
R_API RList* r_bin_get_symbols(RBin *bin);
R_API int r_bin_is_big_endian (RBin *bin);
R_API int r_bin_is_stripped (RBin *bin);
R_API int r_bin_is_static (RBin *bin);
R_API int r_bin_has_dbg_linenums (RBin *bin);
R_API int r_bin_has_dbg_syms (RBin *bin);
R_API int r_bin_has_dbg_relocs (RBin *bin);
R_API RBin* r_bin_new();
R_API void r_bin_iobind(RBin *bin, RIO *io);
R_API RBinFile * r_bin_cur (RBin *bin);
R_API RBinObject * r_bin_cur_object (RBin *bin);
R_API int r_bin_file_set_cur_binfile_obj (RBin * bin, RBinFile *bf, RBinObject *obj);
R_API int r_bin_io_load(RBin *bin, RIO *io, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int dummy);

R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name);
R_API int r_bin_select_idx(RBin *bin, const char *name, int idx);
R_API int r_bin_select_by_ids(RBin *bin, ut32 binfile_id, ut32 binobj_id );
R_API int r_bin_object_delete (RBin *bin, ut32 binfile_id, ut32 binobj_id);
R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name);
R_API RBinFile * r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits, const char *name);
R_API RBinObject * r_bin_object_find_by_arch_bits (RBinFile *binfile, const char *arch, int bits, const char *name);
R_API void r_bin_list_archs(RBin *bin, int mode);
R_API void r_bin_set_user_ptr(RBin *bin, void *user);
R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen);
R_API ut64 r_bin_get_offset (RBin *bin);
R_API ut64 r_bin_get_vaddr (RBin *bin, ut64 baddr, ut64 paddr, ut64 vaddr);
R_API int r_bin_file_delete(RBin *bin, ut32 bin_fd);
R_API int r_bin_file_set_cur_by_fd (RBin *bin, ut32 bin_fd);
R_API int r_bin_file_set_cur_by_name (RBin * bin, const char * name);
R_API RBinFile * r_bin_file_find_by_fd (RBin *bin, ut32 bin_fd);
R_API RBinFile * r_bin_file_find_by_name (RBin * bin, const char * name);
R_API RBinFile * r_bin_file_find_by_name_n (RBin * bin, const char * name, int idx);
R_API int r_bin_file_set_cur_binfile (RBin * bin, RBinFile *bf);
R_API RBinPlugin * r_bin_file_cur_plugin (RBinFile *binfile);



/* dbginfo.c */
R_API int r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line);
R_API char *r_bin_addr2text(RBin *bin, ut64 addr);
R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr);
/* bin_write.c */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
R_API int r_bin_wr_rpath_del(RBin *bin);
R_API int r_bin_wr_output(RBin *bin, const char *filename);
R_API int r_bin_dwarf_parse_info(RBinDwarfDebugAbbrev *da, RBin *a, int mode);
R_API RList *r_bin_dwarf_parse_line(RBin *a, int mode);
R_API RList *r_bin_dwarf_parse_aranges(RBin *a, int mode);
R_API RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev(RBin *a, int mode);

R_API RBinPlugin * r_bin_get_binplugin_by_bytes (RBin *bin, const ut8* bytes, ut64 sz);

/* plugin pointers */
extern RBinPlugin r_bin_plugin_any;
extern RBinPlugin r_bin_plugin_fs;
extern RBinPlugin r_bin_plugin_elf;
extern RBinPlugin r_bin_plugin_elf64;
extern RBinPlugin r_bin_plugin_p9;
extern RBinPlugin r_bin_plugin_pe;
extern RBinPlugin r_bin_plugin_mz;
extern RBinPlugin r_bin_plugin_pe64;
extern RBinPlugin r_bin_plugin_pebble;
extern RBinPlugin r_bin_plugin_bios;
extern RBinPlugin r_bin_plugin_bf;
extern RBinPlugin r_bin_plugin_te;
extern RBinPlugin r_bin_plugin_mach0;
extern RBinPlugin r_bin_plugin_mach064;
extern RBinPlugin r_bin_plugin_java;
extern RBinPlugin r_bin_plugin_dex;
extern RBinPlugin r_bin_plugin_dummy;
extern RBinPlugin r_bin_plugin_rar;
extern RBinPlugin r_bin_plugin_coff;
extern RBinPlugin r_bin_plugin_ningb;
extern RBinPlugin r_bin_plugin_ningba;
extern RBinPlugin r_bin_plugin_ninds;
extern RBinPlugin r_bin_plugin_xbe;
extern RBinXtrPlugin r_bin_xtr_plugin_fatmach0;
extern RBinXtrPlugin r_bin_xtr_plugin_dyldcache;

#ifdef __cplusplus
}
#endif

#endif
#endif
