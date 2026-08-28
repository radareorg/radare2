#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_vec.h>
#include <sdb/ht_uu.h>

#include "elf_specs.h"

#ifndef _INCLUDE_ELF_H_
#define _INCLUDE_ELF_H_

#define SBPF_PROGRAM_ADDR 	0x100000000ULL
#define SBPF_STACK_ADDR 	0x200000000ULL

#define R_BIN_ELF_SCN_IS_EXECUTABLE(x) x & SHF_EXECINSTR
#define R_BIN_ELF_SCN_IS_READABLE(x)   x & SHF_ALLOC
#define R_BIN_ELF_SCN_IS_WRITABLE(x)   x & SHF_WRITE
#define R_BIN_ELF_SCN_IS_COMPRESSED(x)   x & SHF_COMPRESSED

#define R_BIN_ELF_SYMTAB_SYMBOLS 1 << 0
#define R_BIN_ELF_DYNSYM_SYMBOLS 1 << 1
#define R_BIN_ELF_IMPORT_SYMBOLS (1 << 2 | (eo->ehdr.e_type == ET_REL ? R_BIN_ELF_SYMTAB_SYMBOLS : R_BIN_ELF_DYNSYM_SYMBOLS))
#define R_BIN_ELF_ALL_SYMBOLS (R_BIN_ELF_SYMTAB_SYMBOLS | R_BIN_ELF_DYNSYM_SYMBOLS)
#define ELFOBJ struct Elf_(obj_t)

#if R_BIN_ELF64
#define R_BIN_ELF_WORDSIZE 0x8
#define R_BIN_ELF_WORD_MAX UT64_MAX
#define R_BIN_ELF_READWORD(x, i) READ64 (x, i)
#define R_BIN_ELF_BREADWORD(x, i) BREAD64 (x, i)
#define R_BIN_ELF_ADDR_MAX UT64_MAX
#define R_BIN_ELF_XWORD_MAX UT64_MAX
#else
#define R_BIN_ELF_WORDSIZE 0x4
#define R_BIN_ELF_WORD_MAX UT32_MAX
#define R_BIN_ELF_READWORD(x, i) READ32 (x, i)
#define R_BIN_ELF_BREADWORD(x, i) BREAD32 (x, i)
#define R_BIN_ELF_ADDR_MAX UT32_MAX
#define R_BIN_ELF_XWORD_MAX UT64_MAX
#endif

typedef struct r_bin_elf_section_t {
	ut64 offset;
	ut64 rva;
	ut64 size;
	ut64 align;
	ut32 flags;
	ut32 link;
	ut32 info;
	char name[ELF_STRING_LENGTH];
	int type;
} RBinElfSection;

typedef struct r_bin_elf_symbol_t {
	ut64 offset;
	ut64 size;
	ut32 ordinal;
	bool in_shdr;
	bool is_sht_null;
	bool is_vaddr; /* when true, offset is virtual address, otherwise it's physical */
	bool is_imported;
	const char *bind;
	const char *type;
	char name[ELF_STRING_LENGTH];
	char libname[ELF_STRING_LENGTH];
} RBinElfSymbol;

typedef struct r_bin_elf_reloc_t {
	int sym;
	int type;
	Elf_(Xword) mode;
	st64 addend;
	ut64 offset;
	ut64 rva;
	ut16 section;
	ut64 sto;
	ut64 laddr; // local symbol address
} RBinElfReloc;

typedef struct r_bin_elf_field_t {
	ut64 offset;
	char name[ELF_STRING_LENGTH];
} RBinElfField;

R_VEC_TYPE (RVecElfOff, Elf_(Off));

typedef struct Elf_(dynamic_info) {
	Elf_(Xword) dt_pltrelsz;
	Elf_(Addr) dt_pltgot;
	Elf_(Addr) dt_hash;
	Elf_(Addr) dt_gnu_hash;
	Elf_(Addr) dt_strtab;
	Elf_(Addr) dt_symtab;
	Elf_(Addr) dt_rela;
	Elf_(Addr) dt_relr;
	Elf_(Xword) dt_relasz;
	Elf_(Xword) dt_relrsz;
	Elf_(Xword) dt_relrent;
	Elf_(Xword) dt_relaent;
	Elf_(Xword) dt_strsz;
	Elf_(Xword) dt_syment;
	Elf_(Addr) dt_fini;
	Elf_(Addr) dt_rel;
	Elf_(Xword) dt_relsz;
	Elf_(Xword) dt_relent;
	Elf_(Xword) dt_pltrel;
	Elf_(Addr) dt_jmprel;
	Elf_(Addr) dt_mips_pltgot;
	Elf_(Xword) dt_mips_local_gotno;
	Elf_(Xword) dt_mips_gotsym;
	Elf_(Xword) dt_mips_symtabno;
	Elf_(Addr) dt_ppc64_glink; /* PPC64 ELFv1: DT_PPC64_GLINK lazy PLT resolver anchor */
	Elf_(Addr) dt_crel;    // Address of Crel relocs
	Elf_(Addr) dt_android_rel;    // Address of Android packed (APS2) relocs
	Elf_(Xword) dt_android_relsz; // Size in bytes of the packed reloc stream
	bool dt_android_is_rela;      // true for DT_ANDROID_RELA, false for DT_ANDROID_REL
	bool dt_bind_now;
	bool dt_aarch64_pac_plt; /* AArch64 -z pac-plt: 24 byte plt entries */
	Elf_(Xword) dt_flags;
	Elf_(Xword) dt_flags_1;
	Elf_(Xword) dt_rpath;
	Elf_(Xword) dt_runpath;
	RVecElfOff dt_needed;
} RBinElfDynamicInfo;

typedef struct r_bin_elf_lib_t {
	char name[ELF_STRING_LENGTH];
} RBinElfLib;

#include <r_vec.h>
R_VEC_TYPE (RVecRBinElfSection, RBinElfSection);
R_VEC_TYPE (RVecRBinElfReloc, RBinElfReloc);
R_VEC_TYPE (RVecRBinElfSymbol, RBinElfSymbol);
R_VEC_TYPE (RVecRBinElfLib, RBinElfLib);
R_VEC_TYPE (RVecRBinElfField, RBinElfField);

struct Elf_(obj_t) {
	Elf_(Ehdr) ehdr;
	Elf_(Phdr) *phdr;
	ut64 phnum;
	Elf_(Shdr) *shdr;

	Elf_(Shdr) *strtab_section;
	ut64 strtab_size;
	char *strtab;

	Elf_(Shdr) *shstrtab_section;
	ut64 shstrtab_size;
	char *shstrtab;

	RBinElfDynamicInfo dyn_info;

	ut64 version_info[DT_VERSIONTAGNUM];

	char *dynstr;
	ut32 dynstr_size;

	RBinImport **imports_by_ord;
	size_t imports_by_ord_size;
	RBinSymbol **symbols_by_ord;
	size_t symbols_by_ord_size;

	int bss;
	ut64 size;
	ut64 baddr;
	ut64 user_baddr;
	ut64 boffset;
	int endian;
	bool verbose;
	bool load_unnamed;
	bool has_nobtcfi;
	bool has_nx;
	int bits_cache;
	const char* file;
	RBuffer *b;
	Sdb *kv;
	/*cache purpose*/
	RVecRBinElfSymbol *g_symbols_vec;
	RVecRBinElfSymbol *g_imports_vec;
	// cached converted symbols/imports for direct transfer to bin layer
	RVecRBinSymbol symbols_cache;
	RVecRBinImport imports_cache;
	RVecRBinSymbol plt_symbols_cache; // PLT entries from imports with size > 0
	bool symbols_cached;
	bool imports_cached;
	bool plt_symbols_cached;
	RList *inits;
	HtUU *rel_cache;
	HtUU *ppc64_plt_stubs; // ppc64: slot_vaddr -> stub_vaddr (lazy, NULL until first use)
	ut64 arm64_plt_esize; // aarch64: measured plt entry stride, 0 until probed
	ut64 *ppc32_thunks; // ppc32: plt slot index -> call thunk vaddr, lazy
	ut64 ppc32_nthunks;
	bool ppc32_thunks_done;
	ut32 g_reloc_num;
	bool relocs_loaded;
	RVecRBinElfReloc g_relocs;
	bool sections_loaded;
	bool sections_cached;
	RVecRBinElfSection g_sections;
	RVecRBinSection cached_sections;
	RBinElfSection *last_section; // RBinSection
	bool libs_loaded;
	RVecRBinElfLib g_libs;
	bool fields_loaded;
	RVecRBinElfField g_fields;
	int limit;
	char *osabi;
	RList *trycatch_list; // cache of RBinTrycatch for the trycatch plugin callback
};

int Elf_(has_va)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_section_addr)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_section_offset)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_section_size)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_baddr)(struct Elf_(obj_t) *bin);
ut64 Elf_(p2v)(struct Elf_(obj_t) *bin, ut64 paddr);
ut64 Elf_(v2p)(struct Elf_(obj_t) *bin, ut64 vaddr);
ut64 Elf_(get_boffset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_entry_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_main_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_init_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_fini_offset)(struct Elf_(obj_t) *bin);
char *Elf_(intrp)(struct Elf_(obj_t) *bin);
char *Elf_(compiler)(ELFOBJ *bin);
bool Elf_(get_stripped)(struct Elf_(obj_t) *bin, bool *have_lines, bool *have_syms, bool *have_uncaps);
bool Elf_(is_static)(struct Elf_(obj_t) *bin);
char* Elf_(get_data_encoding)(struct Elf_(obj_t) *bin);
char* Elf_(get_arch)(struct Elf_(obj_t) *bin);
char* Elf_(get_machine_name)(struct Elf_(obj_t) *bin);
char* Elf_(get_head_flag)(ELFOBJ *bin); //yin
char* Elf_(get_abi)(ELFOBJ *bin);
char* Elf_(get_cpu)(ELFOBJ *bin);
char* Elf_(get_file_type)(struct Elf_(obj_t) *bin);
char* Elf_(get_elf_class)(struct Elf_(obj_t) *bin);
int Elf_(get_bits)(struct Elf_(obj_t) *bin);
char* Elf_(get_osabi_name)(struct Elf_(obj_t) *bin);
int Elf_(is_big_endian)(struct Elf_(obj_t) *bin);
const RVecRBinElfReloc *Elf_(load_relocs)(struct Elf_(obj_t) *bin);
const RVecRBinElfLib *Elf_(load_libs)(struct Elf_(obj_t) *bin);
const RVecRBinSection *Elf_(load_sections)(RBinFile *bf, ELFOBJ *eo);
bool Elf_(load_gresources)(RBinFile *bf, ELFOBJ *eo, RVecRBinResource *resources);
bool Elf_(load_symbols)(ELFOBJ *eo);
bool Elf_(load_imports)(ELFOBJ *eo);
RVecRBinSymbol *Elf_(load_symbols_vec)(RBinFile *bf, ELFOBJ *eo);
RVecRBinImport *Elf_(load_imports_vec)(ELFOBJ *eo);
RVecRBinSymbol *Elf_(load_plt_symbols_vec)(RBinFile *bf, ELFOBJ *eo);
const RVecRBinElfField *Elf_(load_fields)(struct Elf_(obj_t) *bin);
char *Elf_(get_rpath)(struct Elf_(obj_t) *bin);

struct Elf_(obj_t)* Elf_(new)(const char* file, bool verbose);
struct Elf_(obj_t)* Elf_(new_buf)(RBuffer *buf, ut64 user_baddr, bool verbose);
void Elf_(free)(struct Elf_(obj_t)* bin);

ut64 Elf_(resize_section)(RBinFile *bf, const char *name, ut64 size);
bool Elf_(section_perms)(RBinFile *bf, const char *name, int perms);
bool Elf_(segment_perms)(RBinFile *bf, const char *name, int perms);
bool Elf_(entry_write)(RBinFile *bf, ut64 addr);
bool Elf_(del_rpath)(RBinFile *bf);

ut64 Elf_(get_phnum)(ELFOBJ *bin);
bool Elf_(is_executable)(ELFOBJ *bin);
int Elf_(has_relro)(struct Elf_(obj_t) *bin);
bool Elf_(has_nx)(struct Elf_(obj_t) *bin);
bool Elf_(has_nobtcfi)(ELFOBJ *eo);
ut8 *Elf_(grab_regstate)(struct Elf_(obj_t) *bin, int *len);
RList *Elf_(get_maps)(ELFOBJ *bin);
ut64 Elf_(ppc64_get_plt_stub_for_slot)(ELFOBJ *eo, ut64 slot_vaddr);
#if R_BIN_ELF64
void Elf_(plt_ppc64v1_load_text_stubs)(RBinFile *bf, ELFOBJ *eo);
#endif
/* plt.c */
ut64 Elf_(plt_get_import_addr)(ELFOBJ *eo, int sym);
int Elf_(plt_ppc64_abi)(ELFOBJ *eo);
ut64 Elf_(plt_arm64_entry)(ELFOBJ *eo, ut64 plt_addr, ut64 pos);
ut64 Elf_(plt_ppc32_thunk)(ELFOBJ *eo, ut64 slot_vaddr);
/* elf.c helpers exported for plt.c */
RBinElfSection *Elf_(plt_section_by_name)(ELFOBJ *eo, const char *name);
ut64 Elf_(plt_num_relocs)(ELFOBJ *eo);
#endif
