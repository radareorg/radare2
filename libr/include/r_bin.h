#ifndef R2_BIN_H
#define R2_BIN_H

#include <r_util.h>
#include <r_types.h>
#include <r_io.h>
#include <r_cons.h>
#include <r_list.h>

typedef struct r_bin_t RBin;

#include <r_bin_dwarf.h>
#include <r_pdb.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_bin);

#define R_BIN_DBG_STRIPPED 0x01
#define R_BIN_DBG_STATIC   0x02
#define R_BIN_DBG_LINENUMS 0x04
#define R_BIN_DBG_SYMS     0x08
#define R_BIN_DBG_RELOCS   0x10

#define R_BIN_ENTRY_TYPE_PROGRAM 0
#define R_BIN_ENTRY_TYPE_MAIN    1
#define R_BIN_ENTRY_TYPE_INIT    2
#define R_BIN_ENTRY_TYPE_FINI    3
#define R_BIN_ENTRY_TYPE_TLS     4
#define R_BIN_ENTRY_TYPE_PREINIT 5

#define R_BIN_SIZEOF_STRINGS 512
#define R_BIN_MAX_ARCH 1024

#define R_BIN_REQ_ALL       UT64_MAX
#define R_BIN_REQ_UNK       0x000000
#define R_BIN_REQ_ENTRIES   0x000001
#define R_BIN_REQ_IMPORTS   0x000002
#define R_BIN_REQ_SYMBOLS   0x000004
#define R_BIN_REQ_SECTIONS  0x000008
#define R_BIN_REQ_INFO      0x000010
#define R_BIN_REQ_OPERATION 0x000020
#define R_BIN_REQ_HELP      0x000040
#define R_BIN_REQ_STRINGS   0x000080
#define R_BIN_REQ_FIELDS    0x000100
#define R_BIN_REQ_LIBS      0x000200
#define R_BIN_REQ_SRCLINE   0x000400
#define R_BIN_REQ_MAIN      0x000800
#define R_BIN_REQ_EXTRACT   0x001000
#define R_BIN_REQ_RELOCS    0x002000
#define R_BIN_REQ_LISTARCHS 0x004000
#define R_BIN_REQ_CREATE    0x008000
#define R_BIN_REQ_CLASSES   0x010000
#define R_BIN_REQ_DWARF     0x020000
#define R_BIN_REQ_SIZE      0x040000
#define R_BIN_REQ_PDB       0x080000
#define R_BIN_REQ_PDB_DWNLD 0x100000
#define R_BIN_REQ_DLOPEN    0x200000
#define R_BIN_REQ_EXPORTS   0x400000
#define R_BIN_REQ_VERSIONINFO 0x800000
#define R_BIN_REQ_PACKAGE   0x1000000
#define R_BIN_REQ_HEADER    0x2000000
#define R_BIN_REQ_LISTPLUGINS 0x4000000
#define R_BIN_REQ_RESOURCES 0x8000000
#define R_BIN_REQ_INITFINI  0x10000000
#define R_BIN_REQ_SEGMENTS  0x20000000
#define R_BIN_REQ_HASHES    0x40000000
#define R_BIN_REQ_SIGNATURE 0x80000000
#define R_BIN_REQ_TRYCATCH 0x100000000
#define R_BIN_REQ_SECTIONS_MAPPING 0x200000000

/* RBinSymbol->method_flags : */
#define R_BIN_METH_CLASS 0x0000000000000001L
#define R_BIN_METH_STATIC 0x0000000000000002L
#define R_BIN_METH_PUBLIC 0x0000000000000004L
#define R_BIN_METH_PRIVATE 0x0000000000000008L
#define R_BIN_METH_PROTECTED 0x0000000000000010L
#define R_BIN_METH_INTERNAL 0x0000000000000020L
#define R_BIN_METH_OPEN 0x0000000000000040L
#define R_BIN_METH_FILEPRIVATE 0x0000000000000080L
#define R_BIN_METH_FINAL 0x0000000000000100L
#define R_BIN_METH_VIRTUAL 0x0000000000000200L
#define R_BIN_METH_CONST 0x0000000000000400L
#define R_BIN_METH_MUTATING 0x0000000000000800L
#define R_BIN_METH_ABSTRACT 0x0000000000001000L
#define R_BIN_METH_SYNCHRONIZED 0x0000000000002000L
#define R_BIN_METH_NATIVE 0x0000000000004000L
#define R_BIN_METH_BRIDGE 0x0000000000008000L
#define R_BIN_METH_VARARGS 0x0000000000010000L
#define R_BIN_METH_SYNTHETIC 0x0000000000020000L
#define R_BIN_METH_STRICT 0x0000000000040000L
#define R_BIN_METH_MIRANDA 0x0000000000080000L
#define R_BIN_METH_CONSTRUCTOR 0x0000000000100000L
#define R_BIN_METH_DECLARED_SYNCHRONIZED 0x0000000000200000L

#define R_BIN_BIND_LOCAL_STR "LOCAL"
#define R_BIN_BIND_GLOBAL_STR "GLOBAL"
#define R_BIN_BIND_WEAK_STR "WEAK"
#define R_BIN_BIND_NUM_STR "NUM"
#define R_BIN_BIND_LOOS_STR "LOOS"
#define R_BIN_BIND_HIOS_STR "HIOS"
#define R_BIN_BIND_LOPROC_STR "LOPROC"
#define R_BIN_BIND_HIPROC_STR "HIPROC"
#define R_BIN_BIND_UNKNOWN_STR "UNKNOWN"

#define R_BIN_TYPE_NOTYPE_STR "NOTYPE"
#define R_BIN_TYPE_OBJECT_STR "OBJ"
#define R_BIN_TYPE_FUNC_STR "FUNC"
#define R_BIN_TYPE_METH_STR "METH"
#define R_BIN_TYPE_STATIC_STR "STATIC"
#define R_BIN_TYPE_SECTION_STR "SECT"
#define R_BIN_TYPE_FILE_STR "FILE"
#define R_BIN_TYPE_COMMON_STR "COMMON"
#define R_BIN_TYPE_TLS_STR "TLS"
#define R_BIN_TYPE_NUM_STR "NUM"
#define R_BIN_TYPE_LOOS_STR "LOOS"
#define R_BIN_TYPE_HIOS_STR "HIOS"
#define R_BIN_TYPE_LOPROC_STR "LOPROC"
#define R_BIN_TYPE_HIPROC_STR "HIPROC"
#define R_BIN_TYPE_SPECIAL_SYM_STR "SPCL"
#define R_BIN_TYPE_UNKNOWN_STR "UNK"

typedef enum {
	R_BIN_SYM_ENTRY,
	R_BIN_SYM_INIT,
	R_BIN_SYM_MAIN,
	R_BIN_SYM_FINI,
	R_BIN_SYM_LAST
} RBinSym;

// name mangling types
// TODO: Rename to R_BIN_LANG_
typedef enum {
	R_BIN_LANG_NONE = 0,
	R_BIN_LANG_JAVA = 1,
	R_BIN_LANG_C = 1<<1,
	R_BIN_LANG_GO = 1<<2,
	R_BIN_LANG_CXX = 1<<3,
	R_BIN_LANG_OBJC = 1<<4,
	R_BIN_LANG_SWIFT = 1<<5,
	R_BIN_LANG_DLANG = 1<<6,
	R_BIN_LANG_MSVC = 1<<7,
	R_BIN_LANG_RUST = 1<<8,
	R_BIN_LANG_KOTLIN = 1<<9,
	R_BIN_LANG_PASCAL = 1<<10,
	R_BIN_LANG_DART = 1<<11,
	R_BIN_LANG_GROOVY = 1<<12,
	R_BIN_LANG_JNI = 1U<<13,
	R_BIN_LANG_BLOCKS = 1U<<31,
	R_BIN_LANG_ANY = -1,
} RBinNameMangling;

typedef enum {
	R_STRING_TYPE_DETECT = '?',
	R_STRING_TYPE_ASCII = 'a',
	R_STRING_TYPE_UTF8 = 'u',
	R_STRING_TYPE_WIDE = 'w', // utf16 / widechar string
	R_STRING_TYPE_WIDE32 = 'W', // utf32
	R_STRING_TYPE_BASE64 = 'b',
} RStringType;

typedef enum {
	// R2_590 rename to R_BIN_VISIBILITY // R_BIN_SCOPE_(PRIVATE|PUBLIC|..) ?
	R_BIN_CLASS_PRIVATE,
	R_BIN_CLASS_PUBLIC,
	R_BIN_CLASS_FRIENDLY,
	R_BIN_CLASS_PROTECTED,
	// ?? R_BIN_CLASS_HIDDEN,
	// ?? R_BIN_CLASS_INTERNAL,
} RBinClassVisibility; // R2_590 - RBinScope

typedef enum {
	R_BIN_RELOC_1 = 1,
	R_BIN_RELOC_2 = 2,
	R_BIN_RELOC_4 = 4,
	R_BIN_RELOC_8 = 8,
	R_BIN_RELOC_16 = 16,
	R_BIN_RELOC_24 = 24,
	R_BIN_RELOC_32 = 32,
	R_BIN_RELOC_48 = 48,
	R_BIN_RELOC_64 = 64
} RBinRelocType;

typedef enum {
	R_BIN_TYPE_DEFAULT = 0,
	R_BIN_TYPE_CORE = 1
} RBinType;

typedef struct r_bin_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 hvaddr;
	ut64 hpaddr;
	int type;
	int bits;
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

typedef struct r_bin_file_hash_t {
	const char *type;
	const char *hex;
} RBinFileHash;

typedef struct r_bin_info_t {
	char *file;
	char *type;
	char *bclass;
	char *rclass;
	char *arch;
	char *cpu;
	char *machine;
	char *flags; // elf.flags, which can ship info about cpu features or the abi used
	char *abi;
	char *os;
	char *subsystem;
	char *rpath;
	char *guid;
	char *debug_file_name;
	const char *lang;
	char *default_cc;
	RList/*<RBinFileHash>*/ *file_hashes;
	int bits;
	int has_retguard; // can be -1 , 0 and 1
	bool has_va;
	bool has_pi; // pic/pie
	bool has_canary;
	bool has_sanitizers;
	bool has_crypto;
	bool has_nx;
	bool has_nobtcfi; // only used by OpenBSD for now no branch target control flow integrity
	bool has_libinjprot; // binary allows libraries to be injected
	int big_endian;
	bool has_lit;
	char *actual_checksum;
	char *claimed_checksum;
	int pe_overlay;
	bool signature;
	ut64 dbg_info;
	RBinHash sum[3];
	ut64 baddr;
	char *intrp;
	char *compiler;
	char *charset;
} RBinInfo;

typedef struct r_bin_symbol_t {
	/* heap-allocated */
	char *name;
	char *dname;
	char *libname;
	char *classname;
	/* const-unique-strings */
	const char *forwarder;
	const char *bind;
	const char *type;
  	const char *rtype;
	bool is_imported;
	/* only used by java */
	const char *visibility_str;
	ut64 vaddr;
	ut64 paddr;
	ut32 size;
	ut32 ordinal;
	ut32 visibility;
	int lang;
	int bits;
	/* see R_BIN_METH_* constants */
	ut64 method_flags;
	int dup_count;
} RBinSymbol;

typedef struct r_bin_section_t {
	char *name;
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut32 perm;
	const char *type;
	const char *arch;
	char *format;
	int bits;
	bool has_strings;
	bool add; // indicates when you want to add the section to io `S` command
	bool is_data;
	bool is_segment;
} RBinSection;

typedef struct r_bin_import_t {
	char *name;
	char *libname;
	const char *bind;
	const char *type;
	char *classname;
	char *descriptor;
	ut32 ordinal;
	ut32 visibility;
	// used by elf, so we just expose them here, so we can remove the internal representation dupe
	bool in_shdr;
	bool is_sht_null;
	bool is_vaddr; /* when true, offset is virtual address, otherwise it's physical */
	bool is_imported;
} RBinImport;

#include <r_vec.h>

// XXX only forward declare here for better compile times
R_API void r_bin_symbol_fini(RBinSymbol *sym);
R_API void r_bin_import_fini(RBinImport *sym);
R_VEC_TYPE_WITH_FINI (RVecRBinImport, RBinImport, r_bin_import_fini);
R_VEC_TYPE_WITH_FINI (RVecRBinSymbol, RBinSymbol, r_bin_symbol_fini);
R_VEC_TYPE(RVecRBinSection, RBinSection);

typedef struct r_bin_object_t {
	ut64 baddr;
	st64 baddr_shift;
	ut64 loadaddr;
	ut64 boffset;
	ut64 size;
	ut64 obj_size;
	RStrpool *pool;
	RList/*<RBinSection>*/ *sections; // DEPRECATE
	RList/*<RBinImport>*/ *imports; // DEPRECATE
	RList/*<RBinSymbol>*/ *symbols; // DEPRECATE
	RVecRBinImport imports_vec;
	RVecRBinSymbol symbols_vec;
	RVecRBinSection sections_vec;
	RList/*<??>*/ *entries;
	RList/*<??>*/ *fields;
	RList/*<??>*/ *libs;
	RRBTree/*<RBinReloc>*/ *relocs;
	RList/*<??>*/ *strings;
	RList/*<RBinClass>*/ *classes;
	HtPP *classes_ht;
	HtPP *methods_ht;
	RList/*<RBinDwarfRow>*/ *lines;
	HtUP *strings_db;
	RList/*<??>*/ *mem; // RBinMem maybe?
	RList/*<BinMap*/ *maps;
	char *regstate;
	RBinInfo *info;
	RBinAddr *binsym[R_BIN_SYM_LAST];
	struct r_bin_plugin_t *plugin;
	int lang;
	Sdb *kv;
	HtUP *addr2klassmethod;
	void *bin_obj; // internal pointer used by formats... TODO: RENAME TO internal object or sthg
	bool is_reloc_patched; // used to indicate whether relocations were patched or not
} RBinObject;

// XXX: RbinFile may hold more than one RBinObject?
/// XX curplugin == o->plugin
typedef struct r_bin_file_t {
	char *file;
	int fd;
	ut64 size;
	int rawstr;
	int strmode;
	ut32 id;
	RBuffer *buf;
	ut64 offset; // XXX
	RBinObject *bo;
	void *xtr_obj;
	ut64 user_baddr; // XXX
	ut64 loadaddr; // XXX
	/* values used when searching the strings */
	int minstrlen;
	int maxstrlen;
	int narch;
	struct r_bin_xtr_plugin_t *curxtr;
	// struct r_bin_plugin_t *curplugin; // use o->plugin
	RList *xtr_data;
	Sdb *sdb;
// #warning RBinFile.sdb_info will be removed in r2-5.7.0
	Sdb *sdb_info;
	Sdb *sdb_addrinfo;
	struct r_bin_t *rbin;
} RBinFile;

typedef struct r_bin_file_options_t {
	const char *pluginname;
	ut64 baseaddr; // where the linker maps the binary in memory
	ut64 loadaddr; // starting physical address to read from the target file
	// ut64 paddr; // offset
	ut64 sz;
	int xtr_idx; // load Nth binary
	int rawstr;
	int fd;
	const char *filename;
} RBinFileOptions;

typedef struct r_bin_create_options_t {
	const char *pluginname;
	ut64 baseaddr; // where the linker maps the binary in memory
	ut64 loadaddr; // starting physical address to read from the target file
	ut8 *code;
	int codelen;
	ut8 *data;
	int datalen;
	const char *arch;
	int bits;
} RBinCreateOptions;

struct r_bin_t {
	const char *file;
	RBinFile *cur; // TODO: deprecate
	int narch;
	void *user;
	/* preconfigured values */
	int debase64;
	int minstrlen;
	int maxstrlen;
	int maxsymlen;
	int limit; // max symbols
	ut64 maxstrbuf;
	int rawstr;
	bool strings_nofp; // move to options struct passed instead of min, dump raw on every getstrings call
	Sdb *sdb;
	RIDStorage *ids;
	RList/*<RBinPlugin>*/ *plugins;
	RList/*<RBinXtrPlugin>*/ *binxtrs;
	RList/*<RBinLdrPlugin>*/ *binldrs;
	RList/*<RBinFile>*/ *binfiles;
	PrintfCallback cb_printf;
	int loadany;
	RIOBind iob;
	RConsBind consb;
	char *force;
	bool want_dbginfo;
	int filter; // symbol filtering
	char strfilter; // string filtering
	char *strpurge; // purge false positive strings
	char *srcdir; // dir.source
	char *prefix; // bin.prefix
	char *strenc;
	ut64 filter_rules;
	bool demangle_usecmd;
	bool demangle_trylib;
	bool verbose;
	bool use_xtr; // use extract plugins when loading a file?
	bool use_ldr; // use loader plugins when loading a file?
	RStrConstPool constpool;
};

typedef struct r_bin_xtr_metadata_t {
	char *arch;
	int bits;
	char *libname;
	char *machine;
	char *type;
	const char *xtr_type;
} RBinXtrMetadata;

typedef int (*FREE_XTR)(void *xtr_obj);
typedef struct r_bin_xtr_data_t {
	char *file;
	RBuffer *buf;
	ut64 size;
	ut64 offset;
	ut64 baddr;
	ut64 laddr;
	int file_count;
	bool loaded;
	RBinXtrMetadata *metadata;
} RBinXtrData;

R_API RBinXtrData *r_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RBinXtrMetadata *metadata);
R_API void r_bin_xtrdata_free(void /*RBinXtrData*/ *data);

typedef struct r_bin_xtr_plugin_t {
	RPluginMeta meta;

	bool (*check)(RBinFile *bf, RBuffer *buf);
	RBinXtrData *(*extract_from_bytes)(RBin *bin, const ut8 *buf, ut64 size, int idx);
	RBinXtrData *(*extract_from_buffer)(RBin *bin, RBuffer *buf, int idx);
	RList *(*extractall_from_bytes)(RBin *bin, const ut8 *buf, ut64 size);
	RList *(*extractall_from_buffer)(RBin *bin, RBuffer *buf);
	RBinXtrData *(*extract)(RBin *bin, int idx);
	RList *(*extractall)(RBin *bin);
	bool loadbuf;

	bool (*load)(RBin *bin);
	int (*size)(RBin *bin);
	void (*destroy)(RBin *bin);
	void (*free_xtr)(void *xtr_obj);
} RBinXtrPlugin;

typedef struct r_bin_ldr_plugin_t {
	RPluginMeta meta;
	bool (*load)(RBin *bin);
} RBinLdrPlugin;

// R2_590 - deprecate this struct which looks dupe from RArchConfig
typedef struct r_bin_arch_options_t {
	const char *arch;
	int bits;
} RBinArchOptions;

typedef struct r_bin_trycatch_t {
	ut64 source;
	ut64 from;
	ut64 to;
	ut64 handler;
	ut64 filter;
	// TODO: add type/name of exception
} RBinTrycatch;

R_API RBinTrycatch *r_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter);
R_API void r_bin_trycatch_free(RBinTrycatch *tc);

typedef struct r_bin_plugin_t {
	RPluginMeta meta;
	Sdb * (*get_sdb)(RBinFile *obj);
	bool (*load)(RBinFile *bf, RBuffer *buf, ut64 laddr);
	ut64 (*size)(RBinFile *bin); // return ut64 maybe? meh
	void (*destroy)(RBinFile *bf);
	bool (*check)(RBinFile *bf, RBuffer *buf);
	ut64 (*baddr)(RBinFile *bf);
	RBinAddr* (*binsym)(RBinFile *bf, int num);
	RList/*<RBinAddr>*/* (*entries)(RBinFile *bf);
	// R2_600 - deprecate in r2-6.0.0
	RList/*<RBinSection>*/* (*sections)(RBinFile *bf);
	RList/*<RBinSymbol>*/* (*symbols)(RBinFile *bf); // R2_590: return VecBinSymbol* for better memory usage and perf
	RList/*<RBinImport>*/* (*imports)(RBinFile *bf); // R2_590: return VecBinImport*
	// R2_590 - implement them in all the plugins
	bool (*sections_vec)(RBinFile *bf); // R2_590
	bool (*symbols_vec)(RBinFile *bf);
	bool (*imports_vec)(RBinFile *bf);
	R_BORROW RList/*<RBinDwarfRow>*/* (*lines)(RBinFile *bf);
	RList/*<RBinString>*/* (*strings)(RBinFile *bf);
	RBinInfo/*<RBinInfo>*/* (*info)(RBinFile *bf);
	RList/*<RBinField>*/* (*fields)(RBinFile *bf);
	RList/*<char *>*/* (*libs)(RBinFile *bf);
	RList/*<RBinReloc>*/* (*relocs)(RBinFile *bf);
	RList/*<RBinTrycatch>*/* (*trycatch)(RBinFile *bf);
	RList/*<RBinClass>*/* (*classes)(RBinFile *bf);
	RList/*<RBinMem>*/* (*mem)(RBinFile *bf);
	RList/*<RBinReloc>*/* (*patch_relocs)(RBinFile *bf);
	RList/*<RBinMap>*/* (*maps)(RBinFile *bf);
	RList/*<RBinFileHash>*/* (*hashes)(RBinFile *bf);
	void (*header)(RBinFile *bf);
	char* (*signature)(RBinFile *bf, bool json);
	int (*demangle_type)(const char *str);
	struct r_bin_dbginfo_t *dbginfo;
	struct r_bin_write_t *write;
	ut64 (*get_offset) (RBinFile *bf, int type, int idx);
	const char* (*get_name)(RBinFile *bf, int type, int idx, bool simplified);
	ut64 (*get_vaddr)(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt);
	// TODO: R2_600 RBuffer* (*create)(RBin *bin, RBinCreateOptions *opt);
	char* (*demangle)(const char *str);
	char* (*regstate)(RBinFile *bf);
	int (*file_type)(RBinFile *bf);
	/* default value if not specified by user */
	int minstrlen;
	char strfilter;
	void *user;
} RBinPlugin;

typedef void (*RBinSymbollCallback)(RBinObject *obj, void *symbol);


typedef struct r_bin_class_t {
	char *name;
	// TODO: char *module;
	RList *super; // list of char*
	char *visibility_str; // XXX only used by java
	int index;
	ut64 addr;
	char *ns; // namespace
	RList *methods; // <RBinSymbol>
	RList *fields; // <RBinField>
	// RList *interfaces; // <char *>
	int visibility;
	int lang;
} RBinClass;

#define RBinSectionName r_offsetof(RBinSection, name)
#define RBinSectionOffset r_offsetof(RBinSection, offset)

#define REBASE_PADDR(o, l, type_t)\
	do { \
		RListIter *_it;\
		type_t *_el;\
		r_list_foreach ((l), _it, _el) { \
			_el->paddr += (o)->loadaddr;\
		}\
	} while (0)

typedef struct r_bin_reloc_t {
	ut8 type; // type have implicit size.. but its anoying
	ut8 additive;
	RBinSymbol *symbol;
	RBinImport *import;
	ut64 laddr; // local symbol address | UT64_MAX
	// RBinSymbol *lsymbol; // still unused
	st64 addend;
	ut64 vaddr;
	ut64 paddr;
	ut32 visibility;
	/* is_ifunc: indirect function, `addend` points to a resolver function
	 * that returns the actual relocation value, e.g. chooses
	 * an optimized version depending on the CPU.
	 * cf. https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
	 */
	bool is_ifunc;
} RBinReloc;

typedef struct r_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char *string;
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	char type; // Ascii Wide cp850 utf8 base64 ...
} RBinString;

typedef struct r_bin_field_t {
	ut64 vaddr;
	ut64 paddr;
	int size;
	int offset;
	ut32 visibility;
	char *name;
	char *type;
	char *comment;
	char *format;
	bool format_named; // whether format is the name of a format or a raw pf format string
	ut64 flags;
} RBinField;

R_API RBinField *r_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named);
R_API void r_bin_field_free(void *);

typedef struct r_bin_mem_t {
	char *name;
	ut64 addr;
	int size;
	int perms;
	RList *mirrors;		//for mirror access; stuff here should only create new maps not new fds
} RBinMem;

typedef struct r_bin_map_t {
	ut64 addr;
	ut64 offset;
	int size;
	int perms;
	char *file;
} RBinMap;

typedef struct r_bin_dbginfo_t {
	bool (*get_line)(RBinFile *arch, ut64 addr, char *file, int len, int *line, int *column);
} RBinDbgInfo;

typedef struct r_bin_write_t {
	ut64 (*scn_resize)(RBinFile *bf, const char *name, ut64 size);
	bool (*scn_perms)(RBinFile *bf, const char *name, int perms);
	int (*rpath_del)(RBinFile *bf);
	bool (*entry)(RBinFile *bf, ut64 addr);
	bool (*addlib)(RBinFile *bf, const char *lib);
} RBinWrite;

typedef int (*RBinGetOffset)(RBin *bin, int type, int idx);
typedef const char *(*RBinGetName)(RBin *bin, int type, int idx, bool sd);
typedef RList *(*RBinGetSections)(RBin *bin);
typedef RBinSection *(*RBinGetSectionAt)(RBin *bin, ut64 addr);
typedef char *(*RBinDemangle)(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs);

typedef struct r_bin_bind_t {
	RBin *bin;
	RBinGetOffset get_offset;
	RBinGetName get_name;
	RBinGetSections get_sections;
	RBinGetSectionAt get_vsect_at;
	RBinDemangle demangle;
	ut32 visibility;
} RBinBind;

R_IPI RBinSection *r_bin_section_new(const char *name);
R_API RBinSection *r_bin_section_clone(RBinSection *s);
R_IPI void r_bin_section_free(RBinSection *bs);
R_API void r_bin_info_free(RBinInfo *rb);
R_API void r_bin_import_free(RBinImport *imp);
R_API void r_bin_symbol_free(void *sym);
R_API RBinSymbol *r_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr);
R_API RBinSymbol *r_bin_symbol_clone(RBinSymbol *bs);
R_API void r_bin_string_free(void *_str);

#ifdef R_API

R_API RBinImport *r_bin_import_clone(RBinImport *o);
typedef void (*RBinSymbolCallback)(RBinObject *obj, RBinSymbol *symbol);

// options functions
R_API void r_bin_file_options_init(RBinFileOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr);
R_API void r_bin_arch_options_init(RBinArchOptions *opt, const char *arch, int bits);
// R_API void r_bin_create_options_init(RBinCreateOptions *opt, const char *arch, int bits);

// open/close/reload functions
R_API RBin *r_bin_new(void);
R_API void r_bin_free(RBin *bin);
R_API bool r_bin_open(RBin *bin, const char *file, RBinFileOptions *opt);
R_API bool r_bin_open_io(RBin *bin, RBinFileOptions *opt);
R_API bool r_bin_open_buf(RBin *bin, RBuffer *buf, RBinFileOptions *opt);
R_API bool r_bin_reload(RBin *bin, ut32 bf_id, ut64 baseaddr);

R_API RBinClass *r_bin_class_new(const char *name, const char *super, int view);
R_API void r_bin_class_free(RBinClass *);
// uhm should be tied used because we dont want bincur to change because of open
R_API RBinFile *r_bin_file_open(RBin *bin, const char *file, RBinFileOptions *opt);

// plugins/bind functions
R_API void r_bin_bind(RBin *b, RBinBind *bnd);
R_API bool r_bin_plugin_add(RBin *bin, RBinPlugin *plugin);
R_API bool r_bin_plugin_remove(RBin *bin, RBinPlugin *plugin);
R_API bool r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo);
R_API bool r_bin_ldr_add(RBin *bin, RBinLdrPlugin *foo);
R_API void r_bin_list(RBin *bin, PJ *pj, int format);
R_API bool r_bin_list_plugin(RBin *bin, const char *name, PJ *pj, int json);
R_API RBinPlugin *r_bin_get_binplugin_by_buffer(RBin *bin, RBinFile *bf, RBuffer *buf);
R_API void r_bin_force_plugin(RBin *bin, const char *pname);

// get/set various bin information
R_API ut64 r_bin_get_baddr(RBin *bin);
R_API ut64 r_bin_file_get_baddr(RBinFile *bf);
R_API void r_bin_set_user_ptr(RBin *bin, void *user);
R_API RBinInfo *r_bin_get_info(RBin *bin);
R_API void r_bin_set_baddr(RBin *bin, ut64 baddr);
R_API ut64 r_bin_get_laddr(RBin *bin);
R_API ut64 r_bin_get_size(RBin *bin);
R_API RBinAddr *r_bin_get_sym(RBin *bin, int sym);
R_API RList *r_bin_raw_strings(RBinFile *a, int min);
R_API RList *r_bin_dump_strings(RBinFile *a, int min, int raw);

// use RBinFile instead
R_API const RList *r_bin_get_entries(RBin *bin);
R_API RList *r_bin_get_fields(RBin *bin);
R_API const RList *r_bin_get_imports(RBin *bin);
R_API RList *r_bin_get_libs(RBin *bin);
R_API RRBTree *r_bin_patch_relocs(RBinFile *bin);
R_API RRBTree *r_bin_get_relocs(RBin *bin);
R_API RList *r_bin_get_sections(RBin *bin);
R_API RList *r_bin_get_classes(RBin *bin);
R_API RList *r_bin_get_strings(RBin *bin);
R_API RList *r_bin_file_get_trycatch(RBinFile *bf);
R_API RList *r_bin_get_symbols(RBin *bin);
R_API RVecRBinSymbol *r_bin_get_symbols_vec(RBin *bin);
R_API RList *r_bin_reset_strings(RBin *bin);
R_API int r_bin_is_big_endian(RBin *bin); // R2_590: deprecate. also it returns -1, false and true
R_API bool r_bin_is_static(RBin *bin); // R2_590: deprecate
R_API ut64 r_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr);
R_API ut64 r_bin_file_get_vaddr(RBinFile *bf, ut64 paddr, ut64 vaddr);

R_API int r_bin_load_languages(RBinFile *binfile);
R_API RBinFile *r_bin_cur(RBin *bin);
R_API RBinObject *r_bin_cur_object(RBin *bin);

// select/list binfiles functions
R_API bool r_bin_select(RBin *bin, const char *arch, int bits, const char *name);
R_API bool r_bin_select_bfid(RBin *bin, ut32 bf_id);
R_API bool r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name);
R_API void r_bin_list_archs(RBin *bin, PJ *pj, int mode);
R_API RBuffer *r_bin_create(RBin *bin, const char *plugin_name, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt);
R_API RBuffer *r_bin_package(RBin *bin, const char *type, const char *file, RList *files);

R_API const char *r_bin_string_type(int type);
R_API const char *r_bin_entry_type_string(int etype);

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data);


// RBinFile lifecycle
// R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
R_API bool r_bin_file_close(RBin *bin, int bd);
R_API void r_bin_file_free(void /*RBinFile*/ *bf_);
// RBinFile.get
R_API RBinFile *r_bin_file_at(RBin *bin, ut64 addr);
R_API RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
R_API RList *r_bin_file_get_symbols(RBinFile *bf);
R_API RVecRBinSymbol *r_bin_file_get_symbols_vec(RBinFile *bf);
//
R_API ut64 r_bin_file_get_vaddr(RBinFile *bf, ut64 paddr, ut64 vaddr);
// RBinFile.add
R_API RBinClass *r_bin_file_add_class(RBinFile *binfile, const char *name, const char *super, int view);
R_API RBinSymbol *r_bin_file_add_method(RBinFile *bf, const char *classname, const char *name, int nargs);
R_API RBinField *r_bin_file_add_field(RBinFile *binfile, const char *classname, const char *name);
// RBinFile.find
R_API RBinFile *r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits);
R_API RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 bin_id);
R_API RBinFile *r_bin_file_find_by_fd(RBin *bin, ut32 bin_fd);
R_API RBinFile *r_bin_file_find_by_name(RBin *bin, const char *name);

R_API bool r_bin_file_set_cur_binfile(RBin *bin, RBinFile *bf);
R_API bool r_bin_file_set_cur_by_name(RBin *bin, const char *name);
R_API bool r_bin_file_deref(RBin *bin, RBinFile *a);
R_API bool r_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd);
R_API bool r_bin_file_set_cur_by_id(RBin *bin, ut32 bin_id);
R_API bool r_bin_file_set_cur_by_name(RBin *bin, const char *name);
R_API ut64 r_bin_file_delete_all(RBin *bin);
R_API bool r_bin_file_delete(RBin *bin, ut32 bin_id);
R_API void r_bin_file_merge(RBinFile *bo, RBinFile *b);
R_API RList *r_bin_file_compute_hashes(RBin *bin, ut64 limit);
R_API RList *r_bin_file_set_hashes(RBin *bin, RList *new_hashes);
R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *binfile);
R_API void r_bin_file_hash_free(RBinFileHash *fhash);

// binobject functions
R_API int r_bin_object_set_items(RBinFile *binfile, RBinObject *o);
R_API bool r_bin_object_delete(RBin *bin, ut32 binfile_id);
R_API void r_bin_mem_free(void *data);

// demangle functions
R_API char *r_bin_demangle(RBinFile *binfile, const char *lang, const char *str, ut64 vaddr, bool libs);
R_API char *r_bin_demangle_java(const char *str);
R_API char *r_bin_demangle_freepascal(const char *str);
R_API char *r_bin_demangle_cxx(RBinFile *binfile, const char *str, ut64 vaddr);
R_API char *r_bin_demangle_msvc(const char *str);
R_API char *r_bin_demangle_swift(const char *s, bool syscmd, bool trylib);
R_API char *r_bin_demangle_objc(RBinFile *binfile, const char *sym);
R_API char *r_bin_demangle_rust(RBinFile *binfile, const char *str, ut64 vaddr);
R_API int r_bin_demangle_type(const char *str);
R_API void r_bin_demangle_list(RBin *bin);
R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str);
R_API const char *r_bin_get_meth_flag_string(ut64 flag, bool compact);

R_API RBinSection *r_bin_get_section_at(RBinObject *o, ut64 off, int va);

/* dbginfo.c */
R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line, int *column);
R_API bool r_bin_addr2line2(RBin *bin, ut64 addr, char *file, int len, int *line, int *column);
R_API char *r_bin_addr2text(RBin *bin, ut64 addr, int origin);
R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr);
/* bin_write.c */
R_API bool r_bin_wr_addlib(RBin *bin, const char *lib);
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
R_API bool r_bin_wr_scn_perms(RBin *bin, const char *name, int perms);
R_API bool r_bin_wr_rpath_del(RBin *bin);
R_API bool r_bin_wr_entry(RBin *bin, ut64 addr);
R_API bool r_bin_wr_output(RBin *bin, const char *filename);

R_API const char *r_bin_lang_tostring(int type);

R_API RList *r_bin_get_mem(RBin *bin);

/* filter.c */
typedef struct HtSU_t HtSU;

R_API void r_bin_load_filter(RBin *bin, ut64 rules);
R_API void r_bin_filter_symbols(RBinFile *bf, RList *list);
R_API void r_bin_filter_sections(RBinFile *bf, RList *list);
R_API char *r_bin_filter_name(RBinFile *bf, HtSU *db, ut64 addr, const char *name);
R_API void r_bin_filter_sym(RBinFile *bf, HtPP *ht, ut64 vaddr, RBinSymbol *sym);
R_API bool r_bin_strpurge(RBin *bin, const char *str, ut64 addr);
R_API bool r_bin_string_filter(RBin *bin, const char *str, ut64 addr);

/* plugin pointers */
extern RBinPlugin r_bin_plugin_any;
extern RBinPlugin r_bin_plugin_fs;
extern RBinPlugin r_bin_plugin_cgc;
extern RBinPlugin r_bin_plugin_elf;
extern RBinPlugin r_bin_plugin_elf64;
extern RBinPlugin r_bin_plugin_p9;
extern RBinPlugin r_bin_plugin_ne;
extern RBinPlugin r_bin_plugin_le;
extern RBinPlugin r_bin_plugin_pe;
extern RBinPlugin r_bin_plugin_mz;
extern RBinPlugin r_bin_plugin_pe64;
extern RBinPlugin r_bin_plugin_pebble;
extern RBinPlugin r_bin_plugin_bios;
extern RBinPlugin r_bin_plugin_bf;
extern RBinPlugin r_bin_plugin_te;
extern RBinPlugin r_bin_plugin_symbols;
extern RBinPlugin r_bin_plugin_mach0;
extern RBinPlugin r_bin_plugin_mach064;
extern RBinPlugin r_bin_plugin_mdmp;
extern RBinPlugin r_bin_plugin_java;
extern RBinPlugin r_bin_plugin_dex;
extern RBinPlugin r_bin_plugin_dis;
extern RBinPlugin r_bin_plugin_coff;
extern RBinPlugin r_bin_plugin_xcoff64;
extern RBinPlugin r_bin_plugin_ningb;
extern RBinPlugin r_bin_plugin_ningba;
extern RBinPlugin r_bin_plugin_ninds;
extern RBinPlugin r_bin_plugin_nin3ds;
extern RBinPlugin r_bin_plugin_xbe;
extern RBinPlugin r_bin_plugin_bflt;
extern RBinXtrPlugin r_bin_xtr_plugin_xtr_fatmach0;
extern RBinXtrPlugin r_bin_xtr_plugin_xtr_xalz;
extern RBinXtrPlugin r_bin_xtr_plugin_xtr_dyldcache;
extern RBinXtrPlugin r_bin_xtr_plugin_xtr_pemixed;
extern RBinXtrPlugin r_bin_xtr_plugin_xtr_sep64;
extern RBinLdrPlugin r_bin_ldr_plugin_ldr_linux;
extern RBinPlugin r_bin_plugin_zimg;
extern RBinPlugin r_bin_plugin_omf;
extern RBinPlugin r_bin_plugin_art;
extern RBinPlugin r_bin_plugin_bootimg;
extern RBinPlugin r_bin_plugin_dol;
extern RBinPlugin r_bin_plugin_rel;
extern RBinPlugin r_bin_plugin_nes;
extern RBinPlugin r_bin_plugin_qnx;
extern RBinPlugin r_bin_plugin_mbn;
extern RBinPlugin r_bin_plugin_smd;
extern RBinPlugin r_bin_plugin_msx;
extern RBinPlugin r_bin_plugin_s390;
extern RBinPlugin r_bin_plugin_sms;
extern RBinPlugin r_bin_plugin_psxexe;
extern RBinPlugin r_bin_plugin_vsf;
extern RBinPlugin r_bin_plugin_dyldcache;
extern RBinPlugin r_bin_plugin_xnu_kernelcache;
extern RBinPlugin r_bin_plugin_avr;
extern RBinPlugin r_bin_plugin_menuet;
extern RBinPlugin r_bin_plugin_wad;
extern RBinPlugin r_bin_plugin_wasm;
extern RBinPlugin r_bin_plugin_nro;
extern RBinPlugin r_bin_plugin_nso;
extern RBinPlugin r_bin_plugin_sfc;
extern RBinPlugin r_bin_plugin_z64;
extern RBinPlugin r_bin_plugin_prg;
extern RBinPlugin r_bin_plugin_dmp64;
extern RBinPlugin r_bin_plugin_pyc;
extern RBinPlugin r_bin_plugin_off;
extern RBinPlugin r_bin_plugin_tic;
extern RBinPlugin r_bin_plugin_lua;
extern RBinPlugin r_bin_plugin_hunk;
extern RBinPlugin r_bin_plugin_xalz;
extern RBinPlugin r_bin_plugin_lua;
extern RBinPlugin r_bin_plugin_xtac;
extern RBinPlugin r_bin_plugin_pdp11;
extern RBinPlugin r_bin_plugin_pcap;

#ifdef __cplusplus
}
#endif

#endif
#endif
