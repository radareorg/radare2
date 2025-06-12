/* radare - LGPL - Copyright 2009-2025 - pancake */

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
#define R_BIN_REQ_ADDRLINE  0x020000
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

// TODO integrate with R_BIN_ATTR
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
} RBinLanguage;

typedef enum {
	R_STRING_TYPE_DETECT = '?',
	R_STRING_TYPE_ASCII = 'a',
	R_STRING_TYPE_UTF8 = 'u',
	R_STRING_TYPE_WIDE = 'w', // utf16 / widechar string
	R_STRING_TYPE_WIDE32 = 'W', // utf32
	R_STRING_TYPE_BASE64 = 'b',
} RStringType;

// used for symbols, classes, methods... generic for elf, dex, pe, swift, ...
// unifies symbol flags, visibility, bind, type into a single generic field
// 64bit enums are problematic for old msvc and tcc, maybe just use defines here
// typedef enum { } RBinAttribute;
typedef uint64_t RBinAttribute;
#define R_BIN_ATTR_NONE (0)
#define R_BIN_ATTR_PUBLIC (1ULL << 0)
#define R_BIN_ATTR_OPEN (1ULL << 1)
#define R_BIN_ATTR_FILEPRIVATE (1ULL << 2)
#define R_BIN_ATTR_PRIVATE (1ULL << 3)
#define R_BIN_ATTR_HIDDEN (1ULL << 4)
#define R_BIN_ATTR_INTERNAL (1ULL << 5) // same as fileprivate?
#define R_BIN_ATTR_FRIENDLY (1ULL << 6)
#define R_BIN_ATTR_PROTECTED (1ULL << 7)
#define R_BIN_ATTR_SEALED (1ULL << 8)
#define R_BIN_ATTR_GLOBAL (1ULL << 9)
#define R_BIN_ATTR_WEAK (1ULL << 10)
#define R_BIN_ATTR_UNSAFE (1ULL << 11)
#define R_BIN_ATTR_CLASS (1ULL << 12) // class method (not instance method)
#define R_BIN_ATTR_EXTERN (1ULL << 13)
#define R_BIN_ATTR_READONLY (1ULL << 14)
#define R_BIN_ATTR_STATIC (1ULL << 15) // same as class attribute?
#define R_BIN_ATTR_CONST (1ULL << 16)
#define R_BIN_ATTR_VIRTUAL (1ULL << 17)
#define R_BIN_ATTR_MUTATING (1ULL << 18)
#define R_BIN_ATTR_FINAL (1ULL << 19)
#define R_BIN_ATTR_ABSTRACT (1ULL << 20)
#define R_BIN_ATTR_INTERFACE (1ULL << 21)
#define R_BIN_ATTR_SYNTHETIC (1ULL << 22) // synthesized methods
#define R_BIN_ATTR_SYMBOLIC (1ULL << 23)
#define R_BIN_ATTR_VERIFIED (1ULL << 24)
#define R_BIN_ATTR_MIRANDA (1ULL << 25)
#define R_BIN_ATTR_CONSTRUCTOR (1ULL << 26)
#define R_BIN_ATTR_GETTER (1ULL << 27) // accessor
#define R_BIN_ATTR_SETTER (1ULL << 28) // accessor
#define R_BIN_ATTR_OPTIMIZED (1ULL << 29)
//#define R_BIN_ATTR_ANNOTATED (1ULL << 30)
#define R_BIN_ATTR_BRIDGE (1ULL << 31)
#define R_BIN_ATTR_STRICT (1ULL << 32)
#define R_BIN_ATTR_ASYNC (1ULL << 33)
#define R_BIN_ATTR_SYNCHRONIZED (1ULL << 34)
#define R_BIN_ATTR_DECLARED_SYNCHRONIZED (1ULL << 35)
#define R_BIN_ATTR_VOLATILE (1ULL << 36)
#define R_BIN_ATTR_TRANSIENT (1ULL << 37)
#define R_BIN_ATTR_ENUM (1ULL << 38)
#define R_BIN_ATTR_NATIVE (1ULL << 39)
#define R_BIN_ATTR_RACIST (1ULL << 40)
#define R_BIN_ATTR_VARARGS (1ULL << 41)
#define R_BIN_ATTR_SUPER (1ULL << 42)
#define R_BIN_ATTR_ANNOTATION (1ULL << 43)

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
#if 0
R_BIN_RELOC_64     S + A        Pointers, addresses
R_BIN_RELOC_PC64   S + A - P    Jumps, branches, GOT/PLT
#endif

typedef struct r_bin_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 hvaddr;
	ut64 hpaddr;
	int type;
	int bits;
} RBinAddr;

typedef struct r_bin_name_t {
	char *name; // demangled name
	char *oname; // original (mangled) name
	char *fname; // flag name
	// char *uname; // user-defined custom name TODO
} RBinName;

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
	RBinName *name;
	char *classname;
	char *libname;
	/* const-unique-strings */
	const char *forwarder;
	const char *bind; // tied to attr already
	// RBinName *type;
	const char *type;
  	const char *rtype;
	bool is_imported;
	/* only used by java */
	ut64 vaddr;
	ut64 paddr;
	ut32 size;
	ut32 ordinal;
	int lang;
	int bits;
	RBinAttribute attr; // previously known as method_flags + visibility
	int dup_count;
} RBinSymbol;

typedef struct r_bin_section_t {
	char *name;
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut32 perm;
	ut32 flags;
	const char *type;
	const char *arch;
	char *format;
	int bits;
	bool has_strings;
	bool add; // indicates when you want to add the section to io `S` command
	bool is_data;
	bool is_segment;
	int backing_fd;
} RBinSection;

typedef struct r_bin_import_t {
	RBinName *name;
// 	char *name;
	char *libname;
	const char *bind;
	const char *type;
	char *classname;
	char *descriptor;
	ut32 ordinal;
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
R_VEC_TYPE(RVecRBinEntry, RBinSymbol);

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
	RVecRBinEntry entries_vec;
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

typedef struct r_bin_file_options_t {
	const char *pluginname;
	ut64 baseaddr; // where the linker maps the binary in memory
	ut64 loadaddr; // starting physical address to read from the target file
	// ut64 paddr; // offset
	ut64 sz;
	int xtr_idx; // load Nth binary
	int fd;
	int rawstr;
	bool nofuncstarts;
	const char *filename;
} RBinFileOptions;

typedef struct r_bin_addrline_store_t RBinAddrLineStore;
typedef bool (*RBinAddrLineAdd)(RBinAddrLineStore *bin, RBinAddrline item); // ut64 addr, const char *file, int line, int column);
typedef RBinAddrline* (*RBinAddrLineGet)(RBinAddrLineStore *bin, ut64 addr);
typedef void (*RBinAddrLineReset)(RBinAddrLineStore *bin);
typedef void (*RBinAddrLineResetAt)(RBinAddrLineStore *bin, ut64 addr);
typedef void (*RBinAddrLineDel)(RBinAddrLineStore *bin, ut64 addr);
typedef bool (*RBinDbgInfoCallback)(void *user, RBinAddrline *item);
typedef RList *(*RBinAddrLineFiles)(RBinAddrLineStore *bin);
typedef void (*RBinAddrLineForeach)(RBinAddrLineStore *bin, RBinDbgInfoCallback cb, void *user);

struct r_bin_addrline_store_t {
	bool used; // deprecated when finished
	void *storage;
	RBinAddrLineAdd al_add;
	RBinAddrLineAdd al_add_cu;
	RBinAddrLineGet al_get;
	RBinAddrLineDel al_del;
	RBinAddrLineReset al_reset;
	RBinAddrLineFiles al_files;
	RBinAddrLineForeach al_foreach;
};

// XXX: RBinFile may hold more than one RBinObject?
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
	Sdb *sdb_info;
	Sdb *sdb_addrinfo; // deprecate
	RBinAddrLineStore addrline;
	void *addrinfo_priv; // future use to store abi-safe addrline info instead of k/v
	struct r_bin_t *rbin;
	int string_count;
	RBinFileOptions *options;
} RBinFile;

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

// R2_600 - move all the options from rbin into this struct
typedef struct r_bin_options_t {
	bool fake_aslr;
	bool demangle_usecmd;
	bool demangle_trylib;
	bool verbose;
	bool use_xtr; // use extract plugins when loading a file?
	bool use_ldr; // use loader plugins when loading a file?
	bool debase64;
	int minstrlen;
	int maxstrlen;
	int maxsymlen;
	ut64 maxstrbuf;
	int limit; // max symbols
	int rawstr;
} RBinOptions;

struct r_bin_t {
	const char *file;
	RBinFile *cur; // TODO: deprecate
	int narch;
	void *user;
	/* preconfigured values */
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
	char *srcdir_base; // dir.source.base
	char *prefix; // bin.prefix
	char *strenc;
	ut64 filter_rules;
	RStrConstPool constpool;
	RBinOptions options;
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
	bool weak_guess;

	bool (*load)(RBin *bin); // TODO: rename to init?
	int (*size)(RBin *bin);
	void (*destroy)(RBin *bin); // TODO: rename to fini
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
	void (*init)(RBin *bin);
	void (*fini)(RBin *bin);
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
	RList/*<RBinMap>*/* (*maps)(RBinFile *bf); // this should be segments!
	RList/*<RBinFileHash>*/* (*hashes)(RBinFile *bf);
	void (*header)(RBinFile *bf);
	char* (*signature)(RBinFile *bf, bool json);
	int (*demangle_type)(const char *str);
	struct r_bin_write_t *write;
	ut64 (*get_offset) (RBinFile *bf, int type, int idx);
	const char* (*get_name)(RBinFile *bf, int type, int idx, bool simplified);
	ut64 (*get_vaddr)(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt);
	char* (*demangle)(const char *str);
	char* (*regstate)(RBinFile *bf);
	bool (*cmd)(RBinFile *bf, const char *command);
	// TODO: R2_600 RBuffer* (*create)(RBin *bin, RBinCreateOptions *opt);
	/* default value if not specified by user */
	int minstrlen;
	char strfilter;
	bool weak_guess;
	void *user;
} RBinPlugin;

typedef void (*RBinSymbollCallback)(RBinObject *obj, void *symbol);

typedef struct r_bin_class_t {
	RBinName *name;
	RList *super; // list of RBinName
	char *visibility_str; // XXX R2_600 - only used by dex+java should be ut32 or bitfield.. should be usable for swift too
	int index; // should be unsigned?
	ut64 addr;
	char *ns; // namespace // maybe RBinName?
	// R2_600 - Use RVec here
	RList *methods; // <RBinSymbol>
	RList *fields; // <RBinField>
	// RList *interfaces; // <char *>
	RBinAttribute attr;
	ut64 lang;
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
	ut64 ntype; // type number coming from the bin file
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
	char *string; // TODO: rename to text or so
	ut64 vaddr;
	ut64 paddr;
	ut32 ordinal;
	ut32 size; // size of buffer containing the string in bytes
	ut32 length; // length of string in chars
	char type; // Ascii Wide cp850 utf8 base64 ...
} RBinString;

typedef enum {
	R_BIN_FIELD_KIND_VARIABLE,
	R_BIN_FIELD_KIND_FIELD,
	R_BIN_FIELD_KIND_PROPERTY,
} RBinFieldKind;

typedef struct r_bin_field_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 value;
	int size;
	int offset;
	RBinName *name;
	RBinName *type;
	RBinFieldKind kind;
	char *comment;
	char *format;
	bool format_named; // whether format is the name of a format or a raw pf format string
	RBinAttribute attr;
} RBinField;

R_API const char *r_bin_field_kindstr(RBinField *f);
R_API RBinField *r_bin_field_new(ut64 paddr, ut64 vaddr, ut64 value, int size, const char *name, const char *comment, const char *format, bool format_named);
R_API void r_bin_field_free(void *);

typedef struct r_bin_mem_t {
	char *name;
	ut64 addr;
	int size;
	int perms;
	RList *mirrors;	//for mirror access; stuff here should only create new maps not new fds
} RBinMem;

typedef struct r_bin_map_t {
	ut64 addr;
	ut64 offset;
	int size;
	int perms;
	char *file;
} RBinMap;

typedef bool (*RBinWriteAddLib)(RBinFile *bf, const char *lib);
typedef ut64 (*RBinWriteScnResize)(RBinFile *bf, const char *name, ut64 newsize);
typedef bool (*RBinWriteScnPerms)(RBinFile *bf, const char *name, int perms);
typedef bool (*RBinWriteEntry)(RBinFile *bf, ut64 addr);
typedef int (*RBinWriteRpathDel)(RBinFile *bf);
typedef struct r_bin_write_t {
	RBinWriteScnResize scn_resize;
	RBinWriteScnPerms scn_perms;
	RBinWriteRpathDel rpath_del;
	RBinWriteEntry entry;
	RBinWriteAddLib addlib;
} RBinWrite;

typedef int (*RBinGetOffset)(RBin *bin, int type, int idx);
typedef const char *(*RBinGetName)(RBin *bin, int type, int idx, bool sd);
typedef RList *(*RBinGetSections)(RBin *bin);
typedef RBinSection *(*RBinGetSectionAt)(RBin *bin, ut64 addr);
typedef char *(*RBinDemangle)(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs);
typedef ut64 (*RBinBaddr)(RBinFile *bf, ut64 addr);

typedef struct r_bin_bind_t {
	RBin *bin;
	RBinGetOffset get_offset;
	RBinGetName get_name;
	RBinGetSections get_sections;
	RBinGetSectionAt get_vsect_at;
	RBinDemangle demangle;
	RBinAddrLineAdd addrline_add;
	RBinAddrLineGet addrline_get;
	RBinBaddr baddr;
	ut32 visibility;
} RBinBind;

R_API RBinSection *r_bin_section_clone(RBinSection *s);
R_API void r_bin_info_free(RBinInfo *rb);
R_API void r_bin_import_free(RBinImport *imp);
R_API void r_bin_symbol_free(void *sym);
R_API const char *r_bin_import_tags(RBin *bin, const char *name);
R_API RBinSymbol *r_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr);
R_API RBinSymbol *r_bin_symbol_clone(RBinSymbol *bs);
R_API void r_bin_symbol_copy(RBinSymbol *dst, RBinSymbol *src);
R_API void r_bin_string_free(void *_str);

#ifdef R_API

R_API RBinImport *r_bin_import_clone(RBinImport *o);
typedef void (*RBinSymbolCallback)(RBinObject *obj, RBinSymbol *symbol);

// options functions
R_API void r_bin_file_options_init(RBinFileOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr);
R_API void r_bin_arch_options_init(RBinArchOptions *opt, const char *arch, int bits);

// open/close/reload functions
R_API RBin *r_bin_new(void);
R_API void r_bin_free(RBin *bin);
R_API bool r_bin_open(RBin *bin, const char *file, RBinFileOptions *opt);
R_API bool r_bin_open_io(RBin *bin, RBinFileOptions *opt);
R_API bool r_bin_open_buf(RBin *bin, RBuffer *buf, RBinFileOptions *opt);
R_API bool r_bin_reload(RBin *bin, ut32 bf_id, ut64 baseaddr);
R_API bool r_bin_command(RBin *bin, const char *input);

R_API RBinClass *r_bin_class_new(const char *name, const char *super, ut64 attr);
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
R_API void r_bin_list_archs(RBin *bin, PJ *pj, RTable *t, int mode);
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
R_API RBinClass *r_bin_file_add_class(RBinFile *binfile, const char *name, const char *super, ut64 attr);
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
R_API void r_bin_addrline_reset(RBin *bin);
R_API void r_bin_addrline_reset_at(RBin *bin, ut64 addr);
R_API bool r_bin_addrline_foreach(RBin *bin, RBinDbgInfoCallback item, void *user);
R_API RList *r_bin_addrline_files(RBin *bin);
R_API RBinAddrline *r_bin_addrline_at(RBin *bin, ut64 addr);
R_API void r_bin_addrline_free(RBinAddrline *di);
R_API RBinAddrline *r_bin_addrline_get(RBin *bin, ut64 addr);
R_API char *r_bin_addrline_tostring(RBin *bin, ut64 addr, int origin);

/* bin_write.c */
R_API bool r_bin_wr_addlib(RBin *bin, const char *lib);
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size);
R_API bool r_bin_wr_scn_perms(RBin *bin, const char *name, int perms);
R_API bool r_bin_wr_rpath_del(RBin *bin);
R_API bool r_bin_wr_entry(RBin *bin, ut64 addr);
R_API bool r_bin_wr_output(RBin *bin, const char *filename);

R_API const char *r_bin_lang_tostring(int type);

R_API RList *r_bin_get_mem(RBin *bin);

R_API RBinName *r_bin_name_new(const char *name);
R_API RBinName *r_bin_name_new_from(R_OWN char *name);
R_API RBinName *r_bin_name_clone(RBinName *bn);
R_API void r_bin_name_update(RBinName *bn, const char *name);
R_API char *r_bin_name_tostring(RBinName *bn);
R_API char *r_bin_name_tostring2(RBinName *bn, int type);
R_API void r_bin_name_demangled(RBinName *bn, const char *dname);
R_API void r_bin_name_filtered(RBinName *bn, const char *fname);
R_API void r_bin_name_free(RBinName *bn);

R_API char *r_bin_attr_tostring(ut64 attr, bool singlechar);
R_API ut64 r_bin_attr_fromstring(const char *s, bool compact);

/* filter.c */
typedef struct HtSU_t HtSU;

R_API void r_bin_load_filter(RBin *bin, ut64 rules);
R_API void r_bin_filter_symbols(RBinFile *bf, RList *list);
R_API void r_bin_filter_sections(RBinFile *bf, RList *list);
R_API char *r_bin_filter_name(RBinFile *bf, HtSU *db, ut64 addr, const char *name);
R_API bool r_bin_strpurge(RBin *bin, const char *str, ut64 addr);
R_API bool r_bin_string_filter(RBin *bin, const char *str, ut64 addr);

// internal apis
R_IPI bool r_bin_filter_sym(RBinFile *bf, HtPP *ht, ut64 vaddr, RBinSymbol *sym);
R_IPI RBinSection *r_bin_section_new(const char *name);
R_IPI void r_bin_section_free(RBinSection *bs);

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
extern RBinPlugin r_bin_plugin_mdt;
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
extern RBinPlugin r_bin_plugin_uf2;
extern RBinPlugin r_bin_plugin_io;
extern RBinPlugin r_bin_plugin_pef;

#ifdef __cplusplus
}
#endif

#endif
#endif
