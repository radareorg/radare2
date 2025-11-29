#include <r_bin.h>
#include <r_types.h>
#include <r_vector.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_MACH0_H_
#define _INCLUDE_R_BIN_MACH0_H_

#define R_BIN_MACH0_STRING_LENGTH 256


#define CSMAGIC_CODEDIRECTORY      0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1 /* multi-arch collection of embedded signatures */
#define CSMAGIC_ENTITLEMENTS       0xfade7171
#define CSMAGIC_REQUIREMENT        0xfade0c00 /* single Requirement blob */
#define CSMAGIC_REQUIREMENTS       0xfade0c01 /* Requirements vector (internal requirements) */

#define CS_PAGE_SIZE 4096

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
#define CSSLOT_CMS_SIGNATURE 0x10000

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
	char name[R_BIN_MACH0_STRING_LENGTH];
};

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
struct MACH0_(opts_t) {
	bool verbose;
	ut64 header_at;
	ut64 symbols_off;
	int maxsymlen;
	bool parse_start_symbols;
	RBinFile *bf;
};

static inline void r_bin_section_fini(RBinSection *bs) {
	if (bs) {
		free (bs->name);
		free (bs->format);
	}
}

R_VEC_TYPE_WITH_FINI(RVecSegment, RBinSection, r_bin_section_fini);

struct MACH0_(obj_t) {
	struct MACH0_(mach_header) hdr;
	struct MACH0_(segment_command) *segs;
	char *intrp;
	char *compiler;
	int nsegs;
	int segs_count;
	struct r_dyld_chained_starts_in_segment **chained_starts;
	struct dyld_chained_fixups_header fixups_header;
	ut64 fixups_offset;
	ut64 fixups_size;
	struct MACH0_(section) *sects;
	int nsects;
	struct MACH0_(nlist) *symtab;
	ut8 *symstr;
	ut8 *func_start; //buffer that hold the data from LC_FUNCTION_STARTS
	int symstrlen;
	int nsymtab;
	ut32 *indirectsyms;
	int nindirectsyms;
	int maxsymlen;

	RBinImport **imports_by_ord;
	size_t imports_by_ord_size;
	HtPP *imports_by_name;
	struct MACH0_(opts_t) options;

	struct dysymtab_command dysymtab;
	struct load_command main_cmd;
	struct dyld_info_command *dyld_info;
	struct dylib_table_of_contents *toc;
	int ntoc;
	struct MACH0_(dylib_module) *modtab;
	int nmodtab;
	struct thread_command thread;
	ut8 *signature;
	union {
		struct x86_thread_state32 x86_32;
		struct x86_thread_state64 x86_64;
		struct ppc_thread_state32 ppc_32;
		struct ppc_thread_state64 ppc_64;
		struct arm_thread_state32 arm_32;
		struct arm_thread_state64 arm_64;
	} thread_state;
	bool libs_loaded;
	RPVector libs_cache;
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
	RVector sections_cache;
	bool imports_loaded;
	RPVector imports_cache;
	bool relocs_loaded;
	RSkipList *relocs_cache;
	RList *reloc_fixups;
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
	struct MACH0_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
} RFixupEventDetails;

typedef struct {
	RFixupEvent type;
	struct MACH0_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
	ut64 ordinal;
	ut64 addend;
} RFixupBindEventDetails;

typedef struct {
	RFixupEvent type;
	struct MACH0_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
	ut32 ordinal;
	ut8 key;
	ut8 addr_div;
	ut16 diversity;
} RFixupBindAuthEventDetails;

typedef struct {
	RFixupEvent type;
	struct MACH0_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
	ut64 ptr_value;
} RFixupRebaseEventDetails;

typedef struct {
	RFixupEvent type;
	struct MACH0_(obj_t) *bin;
	ut64 offset;
	ut64 raw_ptr;
	ut64 ptr_size;
	ut64 ptr_value;
	ut8 key;
	ut8 addr_div;
	ut16 diversity;
} RFixupRebaseAuthEventDetails;

typedef bool (*RFixupCallback)(void * context, RFixupEventDetails * event_details);

void MACH0_(opts_set_default)(struct MACH0_(opts_t) *options, RBinFile *bf);
struct MACH0_(obj_t) *MACH0_(mach0_new)(const char *file, struct MACH0_(opts_t) *options);
struct MACH0_(obj_t) *MACH0_(new_buf)(RBinFile *bf, RBuffer *buf, struct MACH0_(opts_t) *options);
void *MACH0_(mach0_free)(struct MACH0_(obj_t) *bin);
const RVector *MACH0_(load_sections)(struct MACH0_(obj_t) *mo);
RList *MACH0_(get_segments)(RBinFile *bf, struct MACH0_(obj_t) *mo);
RVecSegment *MACH0_(get_segments_vec)(RBinFile *bf, struct MACH0_(obj_t) *mo);
const bool MACH0_(load_symbols)(struct MACH0_(obj_t) *mo);
void MACH0_(pull_symbols)(struct MACH0_(obj_t) *mo, RBinSymbolCallback cb, void *user);
const RPVector *MACH0_(load_imports)(RBinFile* bf, struct MACH0_(obj_t) *bin);
const RSkipList *MACH0_(load_relocs)(struct MACH0_(obj_t) *bin);
struct addr_t *MACH0_(get_entrypoint)(struct MACH0_(obj_t) *bin);
const RPVector *MACH0_(load_libs)(struct MACH0_(obj_t) *bin);
ut64 MACH0_(get_baddr)(struct MACH0_(obj_t) *bin);
char *MACH0_(get_class)(struct MACH0_(obj_t) *bin);
int MACH0_(get_bits)(struct MACH0_(obj_t) *bin);
bool MACH0_(is_big_endian)(struct MACH0_(obj_t) *bin);
bool MACH0_(is_pie)(struct MACH0_(obj_t) *bin);
bool MACH0_(has_nx)(struct MACH0_(obj_t) *bin);
const char *MACH0_(get_intrp)(struct MACH0_(obj_t) *bin);
const char *MACH0_(get_os)(struct MACH0_(obj_t) *bin);
const char *MACH0_(get_cputype)(struct MACH0_(obj_t) *bin);
char *MACH0_(get_cpusubtype)(struct MACH0_(obj_t) *bin);
char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) *hdr);
char *MACH0_(get_filetype)(struct MACH0_(obj_t) *bin);
char *MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) *hdr);
ut64 MACH0_(get_main)(struct MACH0_(obj_t) *mo);
const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) *hdr);
int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header) *hdr);
struct MACH0_(mach_header) *MACH0_(get_hdr)(RBuffer *buf);
void MACH0_(mach_headerfields)(RBinFile *bf);
RList *MACH0_(mach_fields)(RBinFile *bf);
void MACH0_(iterate_chained_fixups)(struct MACH0_(obj_t) *obj, ut64 limit_start, ut64 limit_end, ut32 event_mask, RFixupCallback callback, void *context);
#endif
