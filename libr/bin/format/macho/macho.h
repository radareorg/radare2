#include <r_bin.h>
#include <r_types.h>
#include <r_vec.h>
#include "macho_specs.h"

#ifndef _INCLUDE_R_BIN_MACHO_H_
#define _INCLUDE_R_BIN_MACHO_H_

#define R_BIN_MACHO_STRING_LENGTH 256


#define CSMAGIC_CODEDIRECTORY      0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1 /* multi-arch collection of embedded signatures */
#define CSMAGIC_ENTITLEMENTS       0xfade7171
#define CSMAGIC_DER_ENTITLEMENTS   0xfade7172
#define CSMAGIC_REQUIREMENT        0xfade0c00 /* single Requirement blob */
#define CSMAGIC_REQUIREMENTS       0xfade0c01 /* Requirements vector (internal requirements) */

#define CS_PAGE_SIZE 4096

// CodeDirectory flags (subset used for signing classification)
#define CS_VALID          0x00000001
#define CS_ADHOC          0x00000002
#define CS_GET_TASK_ALLOW 0x00000004
#define CS_HARD           0x00000100
#define CS_KILL           0x00000200
#define CS_RESTRICT       0x00000800
#define CS_ENFORCEMENT    0x00001000
#define CS_REQUIRE_LV     0x00002000
#define CS_RUNTIME        0x00010000
#define CS_LINKER_SIGNED  0x00020000

#define CS_HASHTYPE_SHA1 1
#define CS_HASHTYPE_SHA256 2
#define CS_HASHTYPE_SHA256_TRUNCATED 3

#define CS_HASH_SIZE_SHA1 20
#define CS_HASH_SIZE_SHA256 32
#define CS_HASH_SIZE_SHA256_TRUNCATED 20

#define CSSLOT_CODEDIRECTORY 0
#define CSSLOT_INFOSLOT 1
#define CSSLOT_REQUIREMENTS  2
#define CSSLOT_RESOURCEDIR 3
#define CSSLOT_APPLICATION 4
#define CSSLOT_ENTITLEMENTS  5
#define CSSLOT_DER_ENTITLEMENTS 7
#define CSSLOT_LAUNCH_CONSTRAINT_SELF 8
#define CSSLOT_LAUNCH_CONSTRAINT_PARENT 9
#define CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE 10
#define CSSLOT_LIBRARY_CONSTRAINT 11
#define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000
#define CSSLOT_ALTERNATE_CODEDIRECTORY_MAX 5
#define CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT (CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX)
#define CSSLOT_SIGNATURESLOT 0x10000
#define CSSLOT_IDENTIFICATIONSLOT 0x10001
#define CSSLOT_TICKETSLOT 0x10002
#define CSSLOT_CMS_SIGNATURE CSSLOT_SIGNATURESLOT

typedef struct {
	ut32 magic; /* magic number (CSMAGIC_CODEDIRECTORY) */
	ut32 length; /* total length of CodeDirectory blob */
	ut32 version; /* compatibility version */
	ut32 flags; /* setup and mode flags */
	ut32 hashOffset; /* offset of hash slot element at index zero */
	ut32 identOffset; /* offset of identifier string */
	ut32 nSpecialSlots; /* number of special hash slots */
	ut32 nCodeSlots; /* number of ordinary (code) hash slots */
	ut32 codeLimit; /* limit to main image signature range */
	ut8 hashSize; /* size of each hash in bytes */
	ut8 hashType; /* type of hash (cdHashType* constants) */
	ut8 platform; /* unused (must be zero) */
	ut8 pageSize; /* log2 (page size in bytes); 0 => infinite */
	ut32 spare2; /* unused (must be zero) */
	/* followed by dynamic content as located by offset fields above */
	ut32 scatterOffset;
	ut32 teamIDOffset;
	ut32 spare3;
	ut64 codeLimit64;
	ut64 execSegBase;
	ut64 execSegLimit;
	ut64 execSegFlags;
} CS_CodeDirectory;

typedef enum {
	R_FIXUP_EVENT_NONE = 0,
	R_FIXUP_EVENT_REBASE = 1,
	R_FIXUP_EVENT_REBASE_AUTH = 2,
	R_FIXUP_EVENT_BIND = 4,
	R_FIXUP_EVENT_BIND_AUTH = 8,
} RFixupEvent;

#define R_FIXUP_EVENT_MASK_BIND_ALL (R_FIXUP_EVENT_BIND | R_FIXUP_EVENT_BIND_AUTH)
#define R_FIXUP_EVENT_MASK_REBASE_ALL (R_FIXUP_EVENT_REBASE | R_FIXUP_EVENT_REBASE_AUTH)
#define R_FIXUP_EVENT_MASK_ALL (R_FIXUP_EVENT_MASK_BIND_ALL | R_FIXUP_EVENT_MASK_REBASE_ALL)

struct section_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	ut64 vsize;
	ut32 align;
	ut32 flags;
	int perm;
	char name[R_BIN_MACHO_STRING_LENGTH];
};

R_VEC_TYPE (RVecSection, struct section_t);

struct reloc_t {
	ut64 offset;
	ut64 addr;
	st64 addend;
	ut8 type;
	ut64 ntype;
	int ord;
	char name[256];
	bool external;
	bool pc_relative;
	ut8 size;
};

struct addr_t {
	ut64 offset;
	ut64 addr;
	ut64 haddr;
	int last;
};

struct blob_index_t {
	ut32 type;
	ut32 offset;
};

struct blob_t {
	ut32 magic;
	ut32 length;
};

struct super_blob_t {
	struct blob_t blob;
	ut32 count;
	struct blob_index_t index[];
};

// TODO generalize into RBinFileOptions
struct MACHO_(opts_t) {
	bool verbose;
	bool show_codesign;
	ut64 header_at;
	ut64 symbols_off;
	int maxsymlen;
	bool parse_start_symbols;
	bool load_unnamed;
	RBinFile *bf;
};

R_VEC_TYPE_WITH_FINI(RVecSegment, RBinSection, r_bin_section_fini);

static inline void macho_lib_fini (char **lib) {
	free (*lib);
}

R_VEC_TYPE_WITH_FINI (RVecMachoLib, char *, macho_lib_fini);

struct MACHO_(obj_t) {
	struct MACHO_(mach_header) hdr;
	struct MACHO_(segment_command) *segs;
	char *intrp;
	char *compiler;
	int nsegs;
	int segs_count;
	struct r_dyld_chained_starts_in_segment **chained_starts;
	struct dyld_chained_fixups_header fixups_header;
	ut64 fixups_offset;
	ut64 fixups_size;
	struct MACHO_(section) *sects;
	int nsects;
	struct MACHO_(nlist) *symtab;
	ut8 *symstr;
	ut8 *func_start; //buffer that hold the data from LC_FUNCTION_STARTS
	int symstrlen;
	int nsymtab;
	ut32 *indirectsyms;
	int nindirectsyms;
	int maxsymlen;

	HtPP *imports_by_name;
	struct MACHO_(opts_t) options;

	struct dysymtab_command dysymtab;
	struct load_command main_cmd;
	struct dyld_info_command *dyld_info;
	struct dylib_table_of_contents *toc;
	int ntoc;
	struct MACHO_(dylib_module) *modtab;
	int nmodtab;
	struct thread_command thread;
	ut8 *signature;
	ut8 *signature_der; // CSSLOT_DER_ENTITLEMENTS payload (slot 7, magic 0xfade7172)
	ut32 signature_der_size; // size of signature_der payload
	bool cs_present; // LC_CODE_SIGNATURE parsed successfully
	ut64 cs_paddr;
	ut64 cs_size;
	ut64 cert_paddr;
	ut64 cert_size;
	bool cs_has_cms; // CMS blob (developer signature) present and non-empty
	ut32 cs_flags; // CodeDirectory flags word
	ut8 cs_platform; // CodeDirectory platform byte (nonzero => platform binary)
	union {
		struct x86_thread_state32 x86_32;
		struct x86_thread_state64 x86_64;
		struct ppc_thread_state32 ppc_32;
		struct ppc_thread_state64 ppc_64;
		struct arm_thread_state32 arm_32;
		struct arm_thread_state64 arm_64;
	} thread_state;
	bool libs_loaded;
	RVecMachoLib libs_cache;
	int nlibs;
	ut64 size;
	ut64 baddr;
	ut64 entry;
	bool big_endian;
	const char *file;
	RBuffer *b;
	int os;
	Sdb *kv;
	bool has_crypto;
	int has_canary;
	int has_retguard;
	int has_sanitizers;
	int has_libinjprot;
	int has_blocks_ext;
	int dbg_info;
	const char *lang;
	int uuidn;
	int func_size;
	bool verbose;
	ut64 header_at;
	bool parse_start_symbols;
	bool symbols_loaded;
	RVecRBinSymbol *symbols_vec; // pointer to &bf->bo->symbols_vec
	RVecSegment *segments_vec;  // R2_590 pointer of &bf->bo->segments_vec
	ut64 symbols_off;
	void *user;
	ut64 (*va2pa)(ut64 p, ut32 *offset, ut32 *left, RBinFile *bf);
	ut64 main_addr;
	int (*original_io_read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	bool rebasing_buffer;
	bool sections_loaded;
	RVecSection sections_cache;
	bool imports_loaded;
	RVecRBinImport imports_cache;
	bool relocs_loaded;
	RSkipList *relocs_cache;
	RVecRBinReloc reloc_fixups;
	ut8 *internal_buffer;
	int internal_buffer_size;
	int limit; // user defined
	bool nofuncstarts;
	ut64 exports_trie_off;
	ut32 exports_trie_size;
	RInterval lastrange;
	ut64 lastrange_pa;
};

typedef struct {
	RFixupEvent type;
	struct MACHO_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
	ut64 ordinal;
	ut64 addend;
	ut64 ptr_value;
	ut8 key;
	ut8 addr_div;
	ut16 diversity;
} RFixupEventDetails;

typedef bool (*RFixupCallback)(void * context, RFixupEventDetails * event_details);

void MACHO_(opts_set_default)(struct MACHO_(opts_t) *options, RBinFile *bf);
struct MACHO_(obj_t) *MACHO_(macho_new)(const char *file, struct MACHO_(opts_t) *options);
struct MACHO_(obj_t) *MACHO_(new_buf)(RBinFile *bf, RBuffer *buf, struct MACHO_(opts_t) *options);
void *MACHO_(macho_free)(struct MACHO_(obj_t) *bin);
const RVecSection *MACHO_(load_sections)(struct MACHO_(obj_t) *mo);
RList *MACHO_(get_segments)(RBinFile *bf, struct MACHO_(obj_t) *mo);
RVecSegment *MACHO_(get_segments_vec)(RBinFile *bf, struct MACHO_(obj_t) *mo);
const bool MACHO_(load_symbols)(struct MACHO_(obj_t) *mo);
void MACHO_(pull_symbols)(struct MACHO_(obj_t) *mo, RBinSymbolCallback cb, void *user);
RVecRBinImport *MACHO_(load_imports)(RBinFile* bf, struct MACHO_(obj_t) *bin);
const RSkipList *MACHO_(load_relocs)(struct MACHO_(obj_t) *bin);
struct addr_t *MACHO_(get_entrypoint)(struct MACHO_(obj_t) *bin);
const RVecMachoLib *MACHO_(load_libs)(struct MACHO_(obj_t) *bin);
ut64 MACHO_(get_baddr)(struct MACHO_(obj_t) *bin);
char *MACHO_(get_class)(struct MACHO_(obj_t) *bin);
int MACHO_(get_bits)(struct MACHO_(obj_t) *bin);
bool MACHO_(is_big_endian)(struct MACHO_(obj_t) *bin);
bool MACHO_(is_pie)(struct MACHO_(obj_t) *bin);
bool MACHO_(has_nx)(struct MACHO_(obj_t) *bin);
const char *MACHO_(get_intrp)(struct MACHO_(obj_t) *bin);
const char *MACHO_(get_os)(struct MACHO_(obj_t) *bin);
const char *MACHO_(get_cputype)(struct MACHO_(obj_t) *bin);
char *MACHO_(get_cpusubtype)(struct MACHO_(obj_t) *bin);
char *MACHO_(get_cpusubtype_from_hdr)(struct MACHO_(mach_header) *hdr);
char *MACHO_(get_filetype)(struct MACHO_(obj_t) *bin);
char *MACHO_(get_filetype_from_hdr)(struct MACHO_(mach_header) *hdr);
ut64 MACHO_(get_main)(struct MACHO_(obj_t) *mo);
const char *MACHO_(get_cputype_from_hdr)(struct MACHO_(mach_header) *hdr);
int MACHO_(get_bits_from_hdr)(struct MACHO_(mach_header) *hdr);
struct MACHO_(mach_header) *MACHO_(get_hdr)(RBuffer *buf);
char *MACHO_(mach_headerfields)(RBinFile *bf, int mode);
RList *MACHO_(mach_fields)(RBinFile *bf);
void MACHO_(iterate_chained_fixups)(struct MACHO_(obj_t) *obj, ut64 limit_start, ut64 limit_end, ut32 event_mask, RFixupCallback callback, void *context);
#endif
