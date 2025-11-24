#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
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
	const char *bind;
	const char *type;
	char name[ELF_STRING_LENGTH];
	char libname[ELF_STRING_LENGTH];
	bool in_shdr;
	bool is_sht_null;
	bool is_vaddr; /* when true, offset is virtual address, otherwise it's physical */
	bool is_imported;
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

typedef struct Elf_(dynamic_info) {
	Elf_(Xword) dt_pltrelsz;
	Elf_(Addr) dt_pltgot;
	Elf_(Addr) dt_hash;
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
	Elf_(Addr) dt_crel;    // Address of Crel relocs
	bool dt_bind_now;
	Elf_(Xword) dt_flags;
	Elf_(Xword) dt_flags_1;
	Elf_(Xword) dt_rpath;
	Elf_(Xword) dt_runpath;
	RVector dt_needed;
} RBinElfDynamicInfo;

typedef struct r_bin_elf_lib_t {
	char name[ELF_STRING_LENGTH];
} RBinElfLib;

#include <r_vec.h>
R_VEC_TYPE (RVecRBinElfSymbol, RBinElfSymbol);

struct Elf_(obj_t) {
	Elf_(Ehdr) ehdr;
	Elf_(Phdr) *phdr;
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
	bool has_nobtcfi;
	const char* file;
	RBuffer *b;
	Sdb *kv;
	/*cache purpose*/
	RVecRBinElfSymbol *g_symbols_vec;
	RVecRBinElfSymbol *g_imports_vec;
	RVecRBinElfSymbol *phdr_symbols_vec;
	RVecRBinElfSymbol *phdr_imports_vec;
	RList *inits;
	HtUU *rel_cache;
	ut32 g_reloc_num;
	bool relocs_loaded;
	RVector g_relocs;  // RBinElfReloc
	RList *relocs_list;
	bool sections_loaded;
	bool sections_cached;
#if R2_590
	RVecRBinElfSection g_sections_elf;
#else
	RVector g_sections; // RBinElfSection
#endif
	RVector cached_sections; // RBinSection
	RBinElfSection *last_section; // RBinSection
	bool libs_loaded;
	RVector g_libs; // RBinElfLib
	bool fields_loaded;
	RVector g_fields;  // RBinElfField
	int limit;
	char *osabi;
};

int Elf_(has_va)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_section_addr)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_section_offset)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_section_size)(struct Elf_(obj_t) *bin, const char *section_name);
ut64 Elf_(get_baddr)(struct Elf_(obj_t) *bin);
ut64 Elf_(p2v)(struct Elf_(obj_t) *bin, ut64 paddr);
ut64 Elf_(v2p)(struct Elf_(obj_t) *bin, ut64 vaddr);
ut64 Elf_(p2v_new)(struct Elf_(obj_t) *bin, ut64 paddr);
ut64 Elf_(v2p_new)(struct Elf_(obj_t) *bin, ut64 vaddr);
ut64 Elf_(get_boffset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_entry_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_main_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_init_offset)(struct Elf_(obj_t) *bin);
ut64 Elf_(get_fini_offset)(struct Elf_(obj_t) *bin);
char *Elf_(intrp)(struct Elf_(obj_t) *bin);
char *Elf_(compiler)(ELFOBJ *bin);
bool Elf_(get_stripped)(struct Elf_(obj_t) *bin, bool *have_lines, bool *have_syms);
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
const RVector *Elf_(load_relocs)(struct Elf_(obj_t) *bin);  // RBinElfReloc
const RVector* Elf_(load_libs)(struct Elf_(obj_t) *bin);  // RBinElfLib
const RVector* Elf_(load_sections)(RBinFile *bf, ELFOBJ *eo);
bool Elf_(load_symbols)(ELFOBJ *eo);
bool Elf_(load_imports)(ELFOBJ *eo);
const RVector* Elf_(load_fields)(struct Elf_(obj_t) *bin);  // RBinElfField
char *Elf_(get_rpath)(struct Elf_(obj_t) *bin);

struct Elf_(obj_t)* Elf_(new)(const char* file, bool verbose);
struct Elf_(obj_t)* Elf_(new_buf)(RBuffer *buf, ut64 user_baddr, bool verbose);
void Elf_(free)(struct Elf_(obj_t)* bin);

ut64 Elf_(resize_section)(RBinFile *bf, const char *name, ut64 size);
bool Elf_(section_perms)(RBinFile *bf, const char *name, int perms);
bool Elf_(entry_write)(RBinFile *bf, ut64 addr);
bool Elf_(del_rpath)(RBinFile *bf);

ut64 Elf_(get_phnum)(ELFOBJ *bin);
bool Elf_(is_executable)(ELFOBJ *bin);
int Elf_(has_relro)(struct Elf_(obj_t) *bin);
bool Elf_(has_nx)(struct Elf_(obj_t) *bin);
bool Elf_(has_nobtcfi)(ELFOBJ *eo);
ut8 *Elf_(grab_regstate)(struct Elf_(obj_t) *bin, int *len);
RList *Elf_(get_maps)(ELFOBJ *bin);
RBinSymbol *Elf_(convert_symbol)(struct Elf_(obj_t) *bin, RBinElfSymbol *symbol);
R_API RBinSection *r_bin_section_clone(RBinSection *s);
#endif
