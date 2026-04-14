/* radare - LGPL - Copyright 2010-2026 - nibble, mrmacete, pancake */

#define R_LOG_ORIGIN "bin.macho"

#include "mach0.h"

// R2R db/formats/mach0/strip
// R2R db/formats/zip

#define MACHO_MAX_SECTIONS 4096
// Microsoft C++: 2048 characters; Intel C++: 2048 characters; g++: No limit
// see -e bin.maxsymlen (honor bin.limit too?)

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)

typedef struct {
	struct symbol_t *symbols;
	int j;
	int symbols_count;
	HtPP *hash;
} RSymCtx;

typedef void(*RExportsIterator)(struct MACH0_(obj_t) * mo, const char *name, ut64 flags, ut64 offset, void *ctx);

typedef struct {
	ut8 *node;
	char *label;
	int i;
	ut8 *next_child;
} RTrieState;

typedef struct {
	ut8 *imports;
	RSkipList *relocs;
} RWalkBindChainsContext;

struct symbol_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	int bits;
	int type;
	bool is_imported;
	char *name;
};

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
	ut8 spare1; /* unused (must be zero) */
	ut8 pageSize; /* log2 (page size in bytes); 0 => infinite */
	ut32 spare2; /* unused (must be zero) */
	/* followed by dynamic content as located by offset fields above */
} CodeDirectory;

// OMG; THIS SHOULD BE KILLED; this var exposes the local native endian, which is completely unnecessary
// USE THIS: int ws = bf->bo->info->big_endian;
#define mach0_endian 1

static void import_hash_free(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		r_bin_import_free (kv->value);
	}
}

static ut64 read_uleb128(ut8 **p, ut8 *end) {
	ut64 v;
	const char *error = NULL;
	const ut8 *next = r_uleb128 (*p, end - *p, &v, &error);
	if (error) {
		R_LOG_ERROR ("%s", error);
		return UT64_MAX;
	}
	*p = (ut8 *)next;
	return v;
}

static bool fits_in(ut64 file_size, ut64 offset, ut64 size) {
	ut64 end;
	if (!UT64_ADD (&end, offset, size)) {
		return false;
	}
	return offset <= file_size && end <= file_size;
}

static bool bind_fits(ut64 count, ut64 addr, ut64 segment_end_addr, ut64 stride) {
	if (!stride) {
		return count == 0;
	}
	const ut64 remaining = (addr < segment_end_addr)? segment_end_addr - addr: 0;
	return count <= (remaining / stride);
}

static bool segment_filebacked_size(struct MACH0_(obj_t) * mo, int seg_idx, R_OUT ut64 *size) {
	R_RETURN_VAL_IF_FAIL (mo && size, false);
	if (seg_idx < 0 || seg_idx >= mo->nsegs) {
		return false;
	}
	struct MACH0_(segment_command) *seg = &mo->segs[seg_idx];
	ut64 fileoff = seg->fileoff;
	ut64 filesize = seg->filesize;
	if (fileoff > mo->size) {
		return false;
	}
	ut64 max_filesize = mo->size - fileoff;
	ut64 filebacked_size = R_MIN (filesize, max_filesize);
	filebacked_size = R_MIN (filebacked_size, seg->vmsize);
	*size = filebacked_size;
	return true;
}

static inline bool safe_advance(ut64 *off, ut64 delta) {
	return UT64_ADD (off, *off, delta);
}

static inline bool safe_advance2(ut64 *off, ut64 a, ut64 b) {
	ut64 sum = 0;
	return UT64_ADD (&sum, a, b) && safe_advance (off, sum);
}

static bool magic_endian(ut32 magic, R_OUT bool *big_endian) {
	switch (magic) {
	case MH_MAGIC:
	case MH_MAGIC_64:
	case FAT_MAGIC:
		*big_endian = true;
		return true;
	case MH_CIGAM:
	case MH_CIGAM_64:
	case FAT_CIGAM:
		*big_endian = false;
		return true;
	default:
		return false;
	}
}

static ut64 entry_to_vaddr(struct MACH0_(obj_t) * bin) {
	switch (bin->main_cmd.cmd) {
	case LC_MAIN:
		return bin->entry + bin->baddr;
	case LC_UNIXTHREAD:
	case LC_THREAD:
		return bin->entry;
	default:
		return 0;
	}
}

static ut64 addr_to_offset(struct MACH0_(obj_t) * mo, ut64 addr) {
	if (mo->segs) {
		size_t i;
		for (i = 0; i < mo->nsegs; i++) {
			struct MACH0_(segment_command) *seg = &mo->segs[i];
			const ut64 segment_base = (ut64)seg->vmaddr;
			const ut64 segment_size = (ut64)seg->vmsize;
			if (addr >= segment_base && addr < segment_base + segment_size) {
				return seg->fileoff + (addr - segment_base);
			}
		}
	}
	return 0; // UT64_MAX?
}

static ut64 offset_to_vaddr(struct MACH0_(obj_t) * mo, ut64 offset) {
	if (mo->segs) {
		size_t i;
		for (i = 0; i < mo->nsegs; i++) {
			struct MACH0_(segment_command) *seg = &mo->segs[i];
			ut64 segment_base = (ut64)seg->fileoff;
			ut64 segment_size = (ut64)seg->filesize;
			if (offset >= segment_base && offset < segment_base + segment_size) {
				return seg->vmaddr + (offset - segment_base);
			}
		}
	}
	return 0; // UT64_MAX?
}

static ut64 pa2va(RBinFile *bf, ut64 offset) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, offset);
	RIO *io = bf->rbin->iob.io;
	if (!io || !io->va) {
		return offset;
	}
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	return mo? offset_to_vaddr (mo, offset): offset;
}

static void init_sdb_formats(struct MACH0_(obj_t) * mo) {
	Sdb *kv = mo->kv;
	/*
	 * These definitions are used by r2 -nn
	 * must be kept in sync with libr/bin/d/macho
	 */
	sdb_set (kv, "mach0_build_platform.cparse", "enum mach0_build_platform"
		"{MACOS=1, IOS=2, TVOS=3, WATCHOS=4, BRIDGEOS=5, IOSMAC=6, IOSSIMULATOR=7, TVOSSIMULATOR=8, WATCHOSSIMULATOR=9};",
		0);
	sdb_set (kv, "mach0_build_tool.cparse", "enum mach0_build_tool"
		"{CLANG=1, SWIFT=2, LD=3};",
		0);
	sdb_set (kv, "mach0_load_command_type.cparse", "enum mach0_load_command_type"
		"{ LC_SEGMENT=0x00000001ULL, LC_SYMTAB=0x00000002ULL, LC_SYMSEG=0x00000003ULL, LC_THREAD=0x00000004ULL, LC_UNIXTHREAD=0x00000005ULL, LC_LOADFVMLIB=0x00000006ULL, LC_IDFVMLIB=0x00000007ULL, LC_IDENT=0x00000008ULL, LC_FVMFILE=0x00000009ULL, LC_PREPAGE=0x0000000aULL, LC_DYSYMTAB=0x0000000bULL, LC_LOAD_DYLIB=0x0000000cULL, LC_ID_DYLIB=0x0000000dULL, LC_LOAD_DYLINKER=0x0000000eULL, LC_ID_DYLINKER=0x0000000fULL, LC_PREBOUND_DYLIB=0x00000010ULL, LC_ROUTINES=0x00000011ULL, LC_SUB_FRAMEWORK=0x00000012ULL, LC_SUB_UMBRELLA=0x00000013ULL, LC_SUB_CLIENT=0x00000014ULL, LC_SUB_LIBRARY=0x00000015ULL, LC_TWOLEVEL_HINTS=0x00000016ULL, LC_PREBIND_CKSUM=0x00000017ULL, LC_LOAD_WEAK_DYLIB=0x80000018ULL, LC_SEGMENT_64=0x00000019ULL, LC_ROUTINES_64=0x0000001aULL, LC_UUID=0x0000001bULL, LC_RPATH=0x8000001cULL, LC_CODE_SIGNATURE=0x0000001dULL, LC_SEGMENT_SPLIT_INFO=0x0000001eULL, LC_REEXPORT_DYLIB=0x8000001fULL, LC_LAZY_LOAD_DYLIB=0x00000020ULL, LC_ENCRYPTION_INFO=0x00000021ULL, LC_DYLD_INFO=0x00000022ULL, LC_DYLD_INFO_ONLY=0x80000022ULL, LC_LOAD_UPWARD_DYLIB=0x80000023ULL, LC_VERSION_MIN_MACOSX=0x00000024ULL, LC_VERSION_MIN_IPHONEOS=0x00000025ULL, LC_FUNCTION_STARTS=0x00000026ULL, LC_DYLD_ENVIRONMENT=0x00000027ULL, LC_MAIN=0x80000028ULL, LC_DATA_IN_CODE=0x00000029ULL, LC_SOURCE_VERSION=0x0000002aULL, LC_DYLIB_CODE_SIGN_DRS=0x0000002bULL, LC_ENCRYPTION_INFO_64=0x0000002cULL, LC_LINKER_OPTION=0x0000002dULL, LC_LINKER_OPTIMIZATION_HINT=0x0000002eULL, LC_VERSION_MIN_TVOS=0x0000002fULL, LC_VERSION_MIN_WATCHOS=0x00000030ULL, LC_NOTE=0x00000031ULL, LC_BUILD_VERSION=0x00000032ULL };",
		0);
	sdb_set (kv, "mach0_header_filetype.cparse", "enum mach0_header_filetype"
		"{MH_OBJECT=1, MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6, MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10, MH_KEXT_BUNDLE=11};",
		0);
	sdb_set (kv, "mach0_header_flags.cparse", "enum mach0_header_flags"
		"{MH_NOUNDEFS=1, MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10, MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80, MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400, MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000, MH_SUBSECTIONS_VIA_SYMBOLS=0x2000, MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000, MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000, MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000, MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000, MH_DEAD_STRIPPABLE_DYLIB=0x400000, MH_HAS_TLV_DESCRIPTORS=0x800000, MH_NO_HEAP_EXECUTION=0x1000000};",
		0);
	sdb_set (kv, "mach0_section_types.cparse", "enum mach0_section_types"
		"{S_REGULAR=0, S_ZEROFILL=1, S_CSTRING_LITERALS=2, S_4BYTE_LITERALS=3, S_8BYTE_LITERALS=4, S_LITERAL_POINTERS=5, S_NON_LAZY_SYMBOL_POINTERS=6, S_LAZY_SYMBOL_POINTERS=7, S_SYMBOL_STUBS=8, S_MOD_INIT_FUNC_POINTERS=9, S_MOD_TERM_FUNC_POINTERS=0xa, S_COALESCED=0xb, S_GB_ZEROFILL=0xc, S_INTERPOSING=0xd, S_16BYTE_LITERALS=0xe, S_DTRACE_DOF=0xf, S_LAZY_DYLIB_SYMBOL_POINTERS=0x10, S_THREAD_LOCAL_REGULAR=0x11, S_THREAD_LOCAL_ZEROFILL=0x12, S_THREAD_LOCAL_VARIABLES=0x13, S_THREAD_LOCAL_VARIABLE_POINTERS=0x14, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15, S_INIT_FUNC_OFFSETS=0x16};",
		0);
	sdb_set (kv, "mach0_section_attrs.cparse", "enum mach0_section_attrs"
		"{S_ATTR_PURE_INSTRUCTIONS=0x800000ULL, S_ATTR_NO_TOC=0x400000ULL, S_ATTR_STRIP_STATIC_SYMS=0x200000ULL, S_ATTR_NO_DEAD_STRIP=0x100000ULL, S_ATTR_LIVE_SUPPORT=0x080000ULL, S_ATTR_SELF_MODIFYING_CODE=0x040000ULL, S_ATTR_DEBUG=0x020000ULL, S_ATTR_SOME_INSTRUCTIONS=0x000004ULL, S_ATTR_EXT_RELOC=0x000002ULL, S_ATTR_LOC_RELOC=0x000001ULL};",
		0);
	sdb_set (kv, "mach0_header.format", "xxx[4]Edd[4]B "
		"magic cputype cpusubtype (mach0_header_filetype)filetype ncmds sizeofcmds (mach0_header_flags)flags",
		0);
	sdb_set (kv, "mach0_segment.format", "[4]Ed[16]zxxxxoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set (kv, "mach0_segment64.format", "[4]Ed[16]zqqqqoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set (kv, "mach0_symtab_command.format", "[4]Edxdxd "
		"(mach0_load_command_type)cmd cmdsize symoff nsyms stroff strsize",
		0);
	sdb_set (kv, "mach0_dysymtab_command.format", "[4]Edddddddddddxdxdxxxd "
		"(mach0_load_command_type)cmd cmdsize ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc moddtaboff nmodtab extrefsymoff nextrefsyms inddirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel",
		0);
	sdb_set (kv, "mach0_section.format", "[16]z[16]zxxxxxx[1]E[3]Bxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2",
		0);
	sdb_set (kv, "mach0_section64.format", "[16]z[16]zqqxxxx[1]E[3]Bxxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2 reserved3",
		0);
	sdb_set (kv, "mach0_dylib.format", "xxxxz "
		"name_offset timestamp current_version compatibility_version name",
		0);
	sdb_set (kv, "mach0_dylib_command.format", "[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set (kv, "mach0_id_dylib_command.format", "[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set (kv, "mach0_uuid_command.format", "[4]Ed[16]b "
		"(mach0_load_command_type)cmd cmdsize uuid",
		0);
	sdb_set (kv, "mach0_rpath_command.format", "[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize path_offset path",
		0);
	sdb_set (kv, "mach0_entry_point_command.format", "[4]Edqq "
		"(mach0_load_command_type)cmd cmdsize entryoff stacksize",
		0);
	sdb_set (kv, "mach0_encryption_info64_command.format", "[4]Edxddx "
		"(mach0_load_command_type)cmd cmdsize offset size id padding",
		0);
	sdb_set (kv, "mach0_encryption_info_command.format", "[4]Edxdd "
		"(mach0_load_command_type)cmd cmdsize offset size id",
		0);
	sdb_set (kv, "mach0_code_signature_command.format", "[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_dyld_info_only_command.format", "[4]Edxdxdxdxdxd "
		"(mach0_load_command_type)cmd cmdsize rebase_off rebase_size bind_off bind_size weak_bind_off weak_bind_size lazy_bind_off lazy_bind_size export_off export_size",
		0);
	sdb_set (kv, "mach0_load_dylinker_command.format", "[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set (kv, "mach0_id_dylinker_command.format", "[4]Edxzi "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set (kv, "mach0_build_version_command.format", "[4]Ed[4]Exxd "
		"(mach0_load_command_type)cmd cmdsize (mach0_build_platform)platform minos sdk ntools",
		0);
	sdb_set (kv, "mach0_build_version_tool.format", "[4]Ex "
		"(mach0_build_tool)tool version",
		0);
	sdb_set (kv, "mach0_source_version_command.format", "[4]Edq "
		"(mach0_load_command_type)cmd cmdsize version",
		0);
	sdb_set (kv, "mach0_function_starts_command.format", "[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_data_in_code_command.format", "[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_version_min_command.format", "[4]Edxx "
		"(mach0_load_command_type)cmd cmdsize version reserved",
		0);
	sdb_set (kv, "mach0_segment_split_info_command.format", "[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_unixthread_command.format", "[4]Eddd "
		"(mach0_load_command_type)cmd cmdsize flavor count",
		0);
	sdb_set (kv, "mach0_aot_metadata.format", "[4]Eddddddd "
		"(mach0_load_command_type)cmd cmdsize imagepathoffset imagepathlen field10 field14 x64code field1c",
		0);
}

static bool init_hdr(struct MACH0_(obj_t) * mo) {
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = { 0 };
	int len = r_buf_read_at (mo->b, mo->header_at, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof (machohdrbytes)) {
		R_LOG_WARN ("cannot read magic header");
		return false;
	}
	if (!magic_endian (r_read_be32 (machohdrbytes), &mo->big_endian)) {
		return false; // object files are magic == 0, but body is different :?
	}
	mo->hdr.magic = r_read_ble (&machohdrbytes[0], mo->big_endian, 32);
	mo->hdr.cputype = r_read_ble (&machohdrbytes[4], mo->big_endian, 32);
	mo->hdr.cpusubtype = r_read_ble (&machohdrbytes[8], mo->big_endian, 32);
	mo->hdr.filetype = r_read_ble (&machohdrbytes[12], mo->big_endian, 32);
	mo->hdr.ncmds = r_read_ble (&machohdrbytes[16], mo->big_endian, 32);
	mo->hdr.sizeofcmds = r_read_ble (&machohdrbytes[20], mo->big_endian, 32);
	mo->hdr.flags = r_read_ble (&machohdrbytes[24], mo->big_endian, 32);
#if R_BIN_MACH064
	mo->hdr.reserved = r_read_ble (&machohdrbytes[28], mo->big_endian, 32);
#endif
	init_sdb_formats (mo);
	sdb_num_set (mo->kv, "mach0_header.offset", 0, 0); // wat about fatmach0?
	return true;
}

static bool parse_segments(struct MACH0_(obj_t) * mo, ut64 off) {
	size_t i, j, k, sect, len;
	ut32 size_sects;
	ut8 segcom[sizeof (struct MACH0_(segment_command))] = { 0 };
	ut8 sec[sizeof (struct MACH0_(section))] = { 0 };
	char section_flagname[128];

	if (!UT32_MUL (&size_sects, mo->nsegs, sizeof (struct MACH0_(segment_command)))) {
		return false;
	}
	if (!size_sects || size_sects > mo->size) {
		return false;
	}
	if (off > mo->size || off + sizeof (struct MACH0_(segment_command)) > mo->size) {
		return false;
	}
	if (! (mo->segs = realloc (mo->segs, mo->nsegs * sizeof (struct MACH0_(segment_command))))) {
		r_sys_perror ("realloc (seg)");
		return false;
	}
	j = mo->nsegs - 1;
	len = r_buf_read_at (mo->b, off, segcom, sizeof (struct MACH0_(segment_command)));
	if (len != sizeof (struct MACH0_(segment_command))) {
		R_LOG_ERROR ("read (seg)");
		return false;
	}
	const ut8 *scp = (const ut8 *)&segcom;
	const bool be = mo->big_endian;
	struct MACH0_(segment_command) *seg = &mo->segs[j];
	seg->cmd = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->cmdsize = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	memcpy (&seg->segname, scp, 16);
	scp += 16;
#if R_BIN_MACH064
	seg->vmaddr = r_read_ble64 (scp, be);
	scp += sizeof (ut64);
	seg->vmsize = r_read_ble64 (scp, be);
	scp += sizeof (ut64);
	seg->fileoff = r_read_ble64 (scp, be);
	scp += sizeof (ut64);
	seg->filesize = r_read_ble64 (scp, be);
	scp += sizeof (ut64);
#else
	seg->vmaddr = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->vmsize = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->fileoff = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->filesize = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
#endif
	seg->maxprot = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->initprot = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->nsects = r_read_ble32 (scp, be);
	scp += sizeof (ut32);
	seg->flags = r_read_ble32 (scp, be);

	char *segment_flagname = NULL;
#if R_BIN_MACH064
	segment_flagname = r_str_newf ("mach0_segment64_%u.offset", (ut32)j);
#else
	segment_flagname = r_str_newf ("mach0_segment_%u.offset", (ut32)j);
#endif
	sdb_num_set (mo->kv, segment_flagname, off, 0);
	free (segment_flagname);
	sdb_num_set (mo->kv, "mach0_segments.count", 0, 0);

	if (seg->nsects > 0) {
		sect = mo->nsects;
		mo->nsects += seg->nsects;
		if (mo->nsects > MACHO_MAX_SECTIONS) {
			int new_nsects = mo->nsects & 0xf;
			R_LOG_WARN ("mach0 header contains too many sections (%d). Wrapping to %d",
				mo->nsects,
				new_nsects);
			mo->nsects = new_nsects;
		}
		if ((int)mo->nsects < 1) {
			R_LOG_WARN ("Invalid number of sections");
			mo->nsects = sect;
			return false;
		}
		if (!UT32_MUL (&size_sects, mo->nsects - sect, sizeof (struct MACH0_(section)))) {
			mo->nsects = sect;
			return false;
		}
		if (!size_sects || size_sects > mo->size) {
			mo->nsects = sect;
			return false;
		}
		if (seg->cmdsize != sizeof (struct MACH0_(segment_command)) + (sizeof (struct MACH0_(section)) * seg->nsects)) {
			mo->nsects = sect;
			return false;
		}

		if (off + sizeof (struct MACH0_(segment_command)) > mo->size ||
			off + sizeof (struct MACH0_(segment_command)) + size_sects > mo->size) {
			mo->nsects = sect;
			return false;
		}

		if (! (mo->sects = realloc (mo->sects, mo->nsects * sizeof (struct MACH0_(section))))) {
			r_sys_perror ("realloc (sects)");
			mo->nsects = sect;
			return false;
		}

		for (k = sect, j = 0; k < mo->nsects; k++, j++) {
			ut64 offset = off + sizeof (struct MACH0_(segment_command)) + j * sizeof (struct MACH0_(section));
			len = r_buf_read_at (mo->b, offset, sec, sizeof (struct MACH0_(section)));
			if (len != sizeof (struct MACH0_(section))) {
				R_LOG_ERROR ("read sects");
				mo->nsects = sect;
				return false;
			}

			struct MACH0_(section) *sk = &mo->sects[k];
			i = 0;
			memcpy (&sk->sectname, &sec[i], 16); // INFO: this string is not null terminated!
			i += 16;
			memcpy (&sk->segname, &sec[i], 16); // INFO: Remember: it's not null terminated!
			i += 16;
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.offset", sk->segname, sk->sectname);
			sdb_num_set (mo->kv, section_flagname, offset, 0);
#if R_BIN_MACH064
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.format", sk->segname, sk->sectname);
			sdb_set (mo->kv, section_flagname, "mach0_section64", 0);
#else
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.format", sk->segname, sk->sectname);
			sdb_set (mo->kv, section_flagname, "mach0_section", 0);
#endif

			const ut8 *scp = &sec[i];
			const bool be = mo->big_endian;
#if R_BIN_MACH064
			sk->addr = r_read_ble64 (scp, be);
			scp += sizeof (ut64);
			sk->size = r_read_ble64 (scp, be);
			scp += sizeof (ut64);
#else
			sk->addr = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->size = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
#endif
			sk->offset = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->align = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->reloff = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->nreloc = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->flags = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->reserved1 = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			sk->reserved2 = r_read_ble32 (scp, be);
#if R_BIN_MACH064
			scp += sizeof (ut32);
			sk->reserved3 = r_read_ble32 (scp, be);
#endif
		}
	}
	return true;
}

static void reset_symtab(struct MACH0_(obj_t) * mo) {
	R_FREE (mo->symtab);
	R_FREE (mo->symstr);
	mo->nsymtab = 0;
	mo->symstrlen = 0;
}

static bool defer_fail(struct MACH0_(obj_t) * mo, ut8 *symdata) {
	free (symdata);
	reset_symtab (mo);
	return false;
}

static bool parse_symtab(struct MACH0_(obj_t) * mo, ut64 off) {
	size_t i;
	ut8 *symdata = NULL;
	ut8 symt[sizeof (struct symtab_command)] = { 0 };
	const bool be = mo->big_endian;

	if (!fits_in (mo->size, off, sizeof (struct symtab_command))) {
		return false;
	}
	int len = r_buf_read_at (mo->b, off, symt, sizeof (struct symtab_command));
	if (len != sizeof (struct symtab_command)) {
		return false;
	}
	ut64 symoff = r_read_ble32 (symt + 8, be);
	const ut64 nsyms = r_read_ble32 (symt + 12, be);
	ut64 stroff = r_read_ble32 (symt + 16, be);
	const ut64 strsize = r_read_ble32 (symt + 20, be);
	if (!UT64_ADD (&symoff, symoff, mo->symbols_off)) {
		return false;
	}
	if (!UT64_ADD (&stroff, stroff, mo->symbols_off)) {
		return false;
	}

	reset_symtab (mo);
	if (strsize == 0 || strsize >= mo->size || nsyms == 0) {
		return true;
	}
	if (strsize > ST32_MAX || !fits_in (mo->size, stroff, strsize)) {
		return defer_fail (mo, symdata);
	}
	ut32 size_sym;
	if (!UT32_MUL (&size_sym, nsyms, sizeof (struct MACH0_(nlist))) || !size_sym || size_sym > ST32_MAX) {
		return defer_fail (mo, symdata);
	}
	if (!fits_in (mo->size, symoff, size_sym)) {
		return defer_fail (mo, symdata);
	}
	mo->symstr = calloc (1, strsize + 2);
	if (!mo->symstr) {
		return defer_fail (mo, symdata);
	}
	mo->symstrlen = strsize;
	len = r_buf_read_at (mo->b, stroff, (ut8 *)mo->symstr, strsize);
	if (len != strsize) {
		return defer_fail (mo, symdata);
	}
	const ut64 bsz = r_buf_size (mo->b);
	if (symoff > bsz) {
		return defer_fail (mo, symdata);
	}
	ut64 max_nsymtab = (bsz - symoff) / sizeof (struct MACH0_(nlist));
	if (nsyms > max_nsymtab) {
		return defer_fail (mo, symdata);
	}
	mo->symtab = calloc (nsyms, sizeof (struct MACH0_(nlist)));
	if (!mo->symtab) {
		return defer_fail (mo, symdata);
	}
	mo->nsymtab = nsyms;

	// Bulk read all symbol data at once instead of one-by-one
	symdata = malloc (size_sym);
	if (!symdata) {
		return defer_fail (mo, symdata);
	}
	len = r_buf_read_at (mo->b, symoff, symdata, size_sym);
	if (len != size_sym) {
		return defer_fail (mo, symdata);
	}
	const size_t nlist_size = sizeof (struct MACH0_(nlist));
	const size_t count = mo->nsymtab;
	if (be) {
		for (i = 0; i < count; i++) {
			const ut8 *nlst_ptr = symdata + (i * nlist_size);
			struct MACH0_(nlist) *sti = &mo->symtab[i];
			sti->n_strx = r_read_be32 (nlst_ptr);
			sti->n_type = r_read_be8 (nlst_ptr + 4);
			sti->n_sect = r_read_be8 (nlst_ptr + 5);
			sti->n_desc = r_read_be16 (nlst_ptr + 6);
#if R_BIN_MACH064
			sti->n_value = r_read_be64 (nlst_ptr + 8);
#else
			sti->n_value = r_read_be32 (nlst_ptr + 8);
#endif
		}
	} else {
#if R_SYS_ENDIAN
		for (i = 0; i < count; i++) {
			const ut8 *nlst_ptr = symdata + (i * nlist_size);
			struct MACH0_(nlist) *sti = &mo->symtab[i];
			sti->n_strx = r_read_le32 (nlst_ptr);
			sti->n_type = r_read_le8 (nlst_ptr + 4);
			sti->n_sect = r_read_le8 (nlst_ptr + 5);
			sti->n_desc = r_read_le16 (nlst_ptr + 6);
#if R_BIN_MACH064
			sti->n_value = r_read_le64 (nlst_ptr + 8);
#else
			sti->n_value = r_read_le32 (nlst_ptr + 8);
#endif
		}
#else
		memcpy (mo->symtab, symdata, size_sym);
#endif
	}
	free (symdata);
	return true;
}

static bool parse_aot_metadata(struct MACH0_(obj_t) * mo, ut64 off) {
	ut32 words[8];
	if (r_buf_fread_at (mo->b, off, (ut8 *)&words, "8i", 1) == -1) {
		return false;
	}
	// TODO: add flags for this or sthg
	R_LOG_INFO ("AOT: Image path offset: 0x%08x", words[2]);
	R_LOG_INFO ("AOT: Image path length: 0x%08x", words[3]);
	R_LOG_INFO ("AOT: X64- code section: 0x%08x", words[6]);
	return true;
}

static bool parse_dysymtab(struct MACH0_(obj_t) * mo, ut64 off) {
	size_t len, i;
	ut32 size_tab;
	ut8 dysym[sizeof (struct dysymtab_command)] = { 0 };
	ut8 dytoc[sizeof (struct dylib_table_of_contents)] = { 0 };
	ut8 dymod[sizeof (struct MACH0_(dylib_module))] = { 0 };
	ut8 idsyms[sizeof (ut32)] = { 0 };

	if (off > mo->size || off + sizeof (struct dysymtab_command) >= mo->size) {
		return false;
	}

	// free previous allocations in case of duplicate LC_DYSYMTAB
	R_FREE (mo->toc);
	R_FREE (mo->modtab);
	R_FREE (mo->indirectsyms);
	mo->ntoc = 0;
	mo->nmodtab = 0;
	mo->nindirectsyms = 0;

	len = r_buf_read_at (mo->b, off, dysym, sizeof (struct dysymtab_command));
	if (len != sizeof (struct dysymtab_command)) {
		R_LOG_ERROR ("read (dysymtab)");
		return false;
	}
	const bool be = mo->big_endian;
	struct dysymtab_command *ds = &mo->dysymtab;
	// use r_buf_fread instead of all this duck typing
	ds->cmd = r_read_ble32 (&dysym[0], be);
	ds->cmdsize = r_read_ble32 (&dysym[4], be);
	ds->ilocalsym = r_read_ble32 (&dysym[8], be);
	ds->nlocalsym = r_read_ble32 (&dysym[12], be);
	ds->iextdefsym = r_read_ble32 (&dysym[16], be);
	ds->nextdefsym = r_read_ble32 (&dysym[20], be);
	ds->iundefsym = r_read_ble32 (&dysym[24], be);
	ds->nundefsym = r_read_ble32 (&dysym[28], be);
	ds->tocoff = r_read_ble32 (&dysym[32], be);
	ds->ntoc = r_read_ble32 (&dysym[36], be);
	ds->modtaboff = r_read_ble32 (&dysym[40], be);
	ds->nmodtab = r_read_ble32 (&dysym[44], be);
	ds->extrefsymoff = r_read_ble32 (&dysym[48], be);
	ds->nextrefsyms = r_read_ble32 (&dysym[52], be);
	ds->indirectsymoff = r_read_ble32 (&dysym[56], be);
	ds->nindirectsyms = r_read_ble32 (&dysym[60], be);
	ds->extreloff = r_read_ble32 (&dysym[64], be);
	ds->nextrel = r_read_ble32 (&dysym[68], be);
	ds->locreloff = r_read_ble32 (&dysym[72], be);
	ds->nlocrel = r_read_ble32 (&dysym[76], be);

	mo->ntoc = ds->ntoc;
	if (mo->ntoc > 0) {
		if (!UT32_MUL (&size_tab, mo->ntoc, sizeof (struct dylib_table_of_contents))) {
			return false;
		}
		if (!size_tab) {
			return false;
		}
		if (ds->tocoff > mo->size || ds->tocoff + size_tab > mo->size) {
			return false;
		}
		if (! (mo->toc = calloc (mo->ntoc, sizeof (struct dylib_table_of_contents)))) {
			r_sys_perror ("calloc (toc)");
			return false;
		}
		for (i = 0; i < mo->ntoc; i++) {
			len = r_buf_read_at (mo->b, ds->tocoff + i * sizeof (struct dylib_table_of_contents), dytoc, sizeof (struct dylib_table_of_contents));
			if (len != sizeof (struct dylib_table_of_contents)) {
				R_LOG_ERROR ("read (toc)");
				R_FREE (mo->toc);
				return false;
			}
			mo->toc[i].symbol_index = r_read_ble32 (&dytoc[0], be);
			mo->toc[i].module_index = r_read_ble32 (&dytoc[4], be);
		}
	}
	mo->nmodtab = ds->nmodtab;
	ut64 max_nmodtab = (mo->size - ds->modtaboff) / sizeof (struct MACH0_(dylib_module));
	if (mo->nmodtab > 0 && mo->nmodtab <= max_nmodtab) {
		if (!UT32_MUL (&size_tab, mo->nmodtab, sizeof (struct MACH0_(dylib_module)))) {
			return false;
		}
		if (!size_tab) {
			return false;
		}
		if (ds->modtaboff > mo->size ||
			ds->modtaboff + size_tab > mo->size) {
			return false;
		}
		if (! (mo->modtab = calloc (mo->nmodtab, sizeof (struct MACH0_(dylib_module))))) {
			r_sys_perror ("calloc (modtab)");
			return false;
		}
		for (i = 0; i < mo->nmodtab; i++) {
			len = r_buf_read_at (mo->b, ds->modtaboff + i * sizeof (struct MACH0_(dylib_module)), dymod, sizeof (struct MACH0_(dylib_module)));
			if (len == -1) {
				R_LOG_ERROR ("read (modtab)");
				R_FREE (mo->modtab);
				return false;
			}
			struct MACH0_(dylib_module) *mt = &mo->modtab[i];
			mt->module_name = r_read_ble32 (&dymod[0], be);
			mt->iextdefsym = r_read_ble32 (&dymod[4], be);
			mt->nextdefsym = r_read_ble32 (&dymod[8], be);
			mt->irefsym = r_read_ble32 (&dymod[12], be);
			mt->nrefsym = r_read_ble32 (&dymod[16], be);
			mt->ilocalsym = r_read_ble32 (&dymod[20], be);
			mt->nlocalsym = r_read_ble32 (&dymod[24], be);
			mt->iextrel = r_read_ble32 (&dymod[28], be);
			mt->nextrel = r_read_ble32 (&dymod[32], be);
			mt->iinit_iterm = r_read_ble32 (&dymod[36], be);
			mt->ninit_nterm = r_read_ble32 (&dymod[40], be);
#if R_BIN_MACH064
			mt->objc_module_info_size = r_read_ble32 (&dymod[44], be);
			mt->objc_module_info_addr = r_read_ble64 (&dymod[48], be);
#else
			mt->objc_module_info_addr = r_read_ble32 (&dymod[44], be);
			mt->objc_module_info_size = r_read_ble32 (&dymod[48], be);
#endif
		}
	}
	mo->nindirectsyms = ds->nindirectsyms;
	if (mo->nindirectsyms > 0) {
		if (!UT32_MUL (&size_tab, mo->nindirectsyms, sizeof (ut32))) {
			mo->nindirectsyms = 0;
			return false;
		}
		if (!size_tab) {
			mo->nindirectsyms = 0;
			return false;
		}
		if (ds->indirectsymoff > mo->size ||
			ds->indirectsymoff + size_tab > mo->size) {
			mo->nindirectsyms = 0;
			return false;
		}
		if (! (mo->indirectsyms = calloc (mo->nindirectsyms, sizeof (ut32)))) {
			r_sys_perror ("calloc (indirectsyms)");
			mo->nindirectsyms = 0;
			return false;
		}
		for (i = 0; i < mo->nindirectsyms; i++) {
			len = r_buf_read_at (mo->b, ds->indirectsymoff + i * sizeof (ut32), idsyms, 4);
			if (len == -1) {
				R_LOG_ERROR ("read (indirect syms)");
				R_FREE (mo->indirectsyms);
				mo->nindirectsyms = 0;
				return false;
			}
			mo->indirectsyms[i] = r_read_ble32 (&idsyms[0], be);
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return true;
}

static char *readString(ut8 *p, int off, int len) {
	if (off < 0 || off >= len) {
		return NULL;
	}
	return r_str_ndup ((const char *)p + off, len - off);
}

static void parseCodeDirectory(RMutaBind *mb, RBuffer *b, int offset, int datasize) {
	ut64 off = offset;
	int psize = datasize;
	ut8 *p = calloc (1, psize);
	if (!p) {
		return;
	}
	R_LOG_INFO ("Offset: 0x%08" PFMT64x, off);
	r_buf_read_at (b, off, p, datasize);
	CS_CodeDirectory cscd = { 0 };
#define READFIELD(x) cscd.x = r_read_ble32(p + r_offsetof(CS_CodeDirectory, x), 1)
#define READFIELD8(x) cscd.x = p[r_offsetof(CS_CodeDirectory, x)]
	READFIELD (length);
	READFIELD (version);
	READFIELD (flags);
	READFIELD (hashOffset);
	READFIELD (identOffset);
	READFIELD (nSpecialSlots);
	READFIELD (nCodeSlots);
	READFIELD (hashSize);
	READFIELD (teamIDOffset);
	READFIELD8 (hashType);
	READFIELD (pageSize);
	READFIELD (codeLimit);
	eprintf ("Version: %x\n", cscd.version);
	eprintf ("Flags: %x\n", cscd.flags);
	eprintf ("Length: %d\n", cscd.length);
	eprintf ("PageSize: %d\n", cscd.pageSize);
	eprintf ("hashOffset: %d\n", cscd.hashOffset);
	eprintf ("codeLimit: %d\n", cscd.codeLimit);
	eprintf ("hashSize: %d\n", cscd.hashSize);
	eprintf ("hashType: %d\n", cscd.hashType);
	char *identity = readString (p, cscd.identOffset, psize);
	eprintf ("Identity: %s\n", identity);
	char *teamId = readString (p, cscd.teamIDOffset, psize);
	eprintf ("TeamID: %s\n", teamId);
	eprintf ("CodeSlots: %d\n", cscd.nCodeSlots);
	free (identity);
	free (teamId);

	int hashSize = 20; // SHA1 is default
	const char *hashName = "sha1";
	switch (cscd.hashType) {
	case 0: // SHA1 == 20 bytes
	case 1: // SHA1 == 20 bytes
		hashSize = 20;
		hashName = "sha1";
		break;
	case 2: // SHA256 == 32 bytes
		hashSize = 32;
		hashName = "sha256";
		break;
	}
	// computed cdhash
	int fofsz = cscd.length;
	if (fofsz > 0 && fofsz < (r_buf_size (b) - off)) {
		ut8 *fofbuf = calloc (fofsz, 1);
		if (fofbuf) {
			if (r_buf_read_at (b, off, fofbuf, fofsz) != fofsz) {
				R_LOG_WARN ("Invalid cdhash offset/length values");
			}
			int outlen = 0;
			ut8 *digest = mb->hash (mb, hashName, fofbuf, fofsz, &outlen);
			if (digest) {
				eprintf ("ph %s @ 0x%" PFMT64x "!%d\n", hashName, off, fofsz);
				eprintf ("ComputedCDHash: ");
				int i;
				for (i = 0; i < hashSize; i++) {
					eprintf ("%02x", digest[i]);
				}
				eprintf ("\n");
				free (digest);
			}
			free (fofbuf);
		}
	}
	// show and check the rest of hashes
	ut8 *hash = p + cscd.hashOffset;
	int j;
	eprintf ("Hashed region: 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", (ut64)0, (ut64)cscd.codeLimit);
	for (j = 0; j < cscd.nCodeSlots; j++) {
		int fof = 4096 * j;
		int idx = j * hashSize;
		eprintf ("0x%08" PFMT64x "  ", off + cscd.hashOffset + idx);
		int k;
		for (k = 0; k < hashSize; k++) {
			eprintf ("%02x", hash[idx + k]);
		}
		ut8 fofbuf[4096];
		int fofsz = R_MIN (sizeof (fofbuf), cscd.codeLimit - fof);
		r_buf_read_at (b, fof, fofbuf, sizeof (fofbuf));
		int outlen = 0;
		ut8 *digest = mb->hash (mb, hashName, fofbuf, fofsz, &outlen);
		if (digest) {
			if (memcmp (hash + idx, digest, hashSize)) {
				eprintf ("  wx ");
				int i;
				for (i = 0; i < hashSize; i++) {
					eprintf ("%02x", digest[i]);
				}
			} else {
				eprintf ("  OK");
			}
			free (digest);
		}
		eprintf ("\n");
	}
	free (p);
}

static void set_malformed_entitlement(struct MACH0_(obj_t) * mo) {
	free (mo->signature);
	mo->signature = (ut8 *)strdup ("Malformed entitlement");
}

// parse the Load Command
static bool parse_signature(struct MACH0_(obj_t) * mo, ut64 off) {
	int i, len;
	ut32 data;
	// free previous allocation in case of duplicate LC_CODE_SIGNATURE
	R_FREE (mo->signature);
	struct linkedit_data_command link = { 0 };
	ut8 lit[sizeof (struct linkedit_data_command)] = { 0 };
	struct blob_index_t idx = { 0 };
	struct super_blob_t super = { { 0 } };

	len = r_buf_read_at (mo->b, off, lit, sizeof (struct linkedit_data_command));
	if (len != sizeof (struct linkedit_data_command)) {
		R_LOG_ERROR ("Failed to get data while parsing LC_CODE_SIGNATURE command");
		return false;
	}
	link.cmd = r_read_ble32 (&lit[0], mo->big_endian);
	link.cmdsize = r_read_ble32 (&lit[4], mo->big_endian);
	link.dataoff = r_read_ble32 (&lit[8], mo->big_endian);
	link.datasize = r_read_ble32 (&lit[12], mo->big_endian);

	data = link.dataoff;
	if (link.datasize < sizeof (struct super_blob_t) || !fits_in (mo->size, data, link.datasize)) {
		set_malformed_entitlement (mo);
		return true;
	}
	super.blob.magic = r_buf_read_ble32_at (mo->b, data, mach0_endian);
	super.blob.length = r_buf_read_ble32_at (mo->b, data + 4, mach0_endian);
	super.count = r_buf_read_ble32_at (mo->b, data + 8, mach0_endian);
	if (super.blob.length < sizeof (struct super_blob_t) || super.blob.length > link.datasize) {
		set_malformed_entitlement (mo);
		return true;
	}
	ut64 max_slots = (super.blob.length - sizeof (struct super_blob_t)) / sizeof (struct blob_index_t);
	ut32 slots = (ut32)R_MIN ((ut64)super.count, max_slots);
	// XXX deprecate
	bool isVerbose = r_sys_getenv_asbool ("RABIN2_CODESIGN_VERBOSE");
	// to dump all certificates
	// [0x00053f75]> b 5K;/x 30800609;wtf @@ hit*
	// then do this:
	// $ openssl asn1parse -inform der -in a|less
	// $ openssl pkcs7 -inform DER -print_certs -text -in a
	// uhm we have pFa to parse der/asn1 we can do it inline
	ut64 index_off = data + sizeof (struct super_blob_t);
	for (i = 0; i < slots; i++, index_off += sizeof (struct blob_index_t)) {
		struct blob_index_t bi = { 0 };
		if (r_buf_read_at (mo->b, index_off, (ut8 *)&bi, sizeof (struct blob_index_t)) < sizeof (struct blob_index_t)) {
			set_malformed_entitlement (mo);
			break;
		}
		idx.type = r_read_ble32 (&bi.type, mach0_endian);
		idx.offset = r_read_ble32 (&bi.offset, mach0_endian);

		if (idx.offset > super.blob.length - sizeof (struct blob_t)) {
			if (mo->verbose) {
				R_LOG_DEBUG ("Invalid code signature slot offset %u", idx.offset);
			}
			continue;
		}
		ut64 slot_off = (ut64)data + idx.offset;

		if (idx.type == CSSLOT_CODEDIRECTORY || (idx.type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && idx.type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
			if (isVerbose) {
				RBinFile *bf = mo->options.bf;
				ut32 slot_size = r_buf_read_ble32_at (mo->b, slot_off + 4, mach0_endian);
				if (slot_size >= sizeof (struct blob_t) && slot_size <= super.blob.length && idx.offset <= super.blob.length - slot_size) {
					if (bf && bf->rbin && bf->rbin->mb.hash) {
						parseCodeDirectory (&bf->rbin->mb, mo->b, slot_off, slot_size);
					}
				} else if (mo->verbose) {
					R_LOG_DEBUG ("Invalid CodeDirectory slot size");
				}
			}
			continue;
		}

		switch (idx.type) {
		case CSSLOT_ENTITLEMENTS:
			{
				struct blob_t entitlements = { 0 };
				if (!fits_in (mo->size, slot_off, sizeof (struct blob_t))) {
					set_malformed_entitlement (mo);
					break;
				}
				entitlements.magic = r_buf_read_ble32_at (mo->b, slot_off, mach0_endian);
				entitlements.length = r_buf_read_ble32_at (mo->b, slot_off + 4, mach0_endian);
				if (entitlements.length <= sizeof (struct blob_t) || entitlements.length > super.blob.length || idx.offset > super.blob.length - entitlements.length) {
					set_malformed_entitlement (mo);
					break;
				}
				ut32 ent_size = entitlements.length - sizeof (struct blob_t);
				if (ent_size <= 1) {
					set_malformed_entitlement (mo);
					break;
				}
				if (!fits_in (mo->size, slot_off + sizeof (struct blob_t), ent_size)) {
					set_malformed_entitlement (mo);
					break;
				}
				free (mo->signature);
				mo->signature = calloc (1, ent_size + 1);
				if (!mo->signature) {
					break;
				}
				st64 got = r_buf_read_at (mo->b, slot_off + sizeof (struct blob_t), (ut8 *)mo->signature, ent_size);
				if (got < 0 || (ut64)got < ent_size) {
					set_malformed_entitlement (mo);
					break;
				}
				mo->signature[ent_size] = '\0';
			}
			break;
		case CSSLOT_SIGNATURESLOT: // ASN1/DER certificate
			if (isVerbose) {
				ut8 header[8] = { 0 };
				if (r_buf_read_at (mo->b, slot_off, header, sizeof (header)) < sizeof (header)) {
					break;
				}
				ut32 length = R_MIN (UT16_MAX, r_read_ble32 (header + 4, 1));
				if (!length || length > super.blob.length || idx.offset > super.blob.length - length) {
					break;
				}
				ut8 *p = calloc (length, 1);
				if (p) {
					if (r_buf_read_at (mo->b, slot_off, p, length) < (int)length) {
						free (p);
						break;
					}
					if (length >= sizeof (ut32)) {
						ut32 *words = (ut32 *)p;
						eprintf ("Magic: %x\n", words[0]);
					}
					eprintf ("wtf DUMP @%d!%d\n",
						(int)data + idx.offset + 8,
						(int)length);
					eprintf ("openssl pkcs7 -print_certs -text -inform der -in DUMP\n");
					eprintf ("openssl asn1parse -offset %d -length %d -inform der -in /mo/ls\n",
						(int)data + idx.offset + 8,
						(int)length);
					eprintf ("pFp@%d!%d\n",
						(int)data + idx.offset + 8,
						(int)length);
					free (p);
				}
			}
			break;
		case CSSLOT_REQUIREMENTS: // 2
		{
			ut8 p[256];
			const ut32 req_size = 16 + sizeof (p);
			if (req_size > super.blob.length || idx.offset > super.blob.length - req_size) {
				break;
			}
			ut64 req_off = slot_off + 16;
			if (r_buf_read_at (mo->b, req_off, p, sizeof (p)) < sizeof (p)) {
				break;
			}
			p[sizeof (p) - 1] = 0;
			ut32 ident_size = r_read_ble32 (p + 8, 1);
			if (!ident_size || ident_size > sizeof (p) - 28) {
				R_LOG_DEBUG ("Invalid code slot size");
				break;
			}
			char *ident = r_str_ndup ((const char *)p + 28, ident_size);
			if (ident) {
				sdb_set (mo->kv, "mach0.ident", ident, 0);
				free (ident);
			}
		}
		break;
		case CSSLOT_INFOSLOT: // 1
		case CSSLOT_RESOURCEDIR: // 3
		case CSSLOT_APPLICATION: // 4
		case CSSLOT_DER_ENTITLEMENTS:
		case CSSLOT_LAUNCH_CONSTRAINT_SELF:
		case CSSLOT_LAUNCH_CONSTRAINT_PARENT:
		case CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE:
		case CSSLOT_LIBRARY_CONSTRAINT:
		case CSSLOT_IDENTIFICATIONSLOT:
		case CSSLOT_TICKETSLOT:
			// TODO: parse those codesign slots
			if (mo->verbose) {
				R_LOG_TODO ("Some codesign slots are not yet supported");
			}
			break;
		default:
			if (mo->verbose) {
				R_LOG_WARN ("Unknown Code signature slot %u", idx.type);
			}
			break;
		}
	}
#if 0
	if (!mo->signature) {
		mo->signature = (ut8 *)strdup ("No entitlement found");
	}
#endif
	return true;
}

static int parse_thread(struct MACH0_(obj_t) * mo, struct load_command *lc, ut64 off, bool is_first_thread) {
	ut64 ptr_thread, pc = UT64_MAX, pc_offset = UT64_MAX;
	ut32 flavor, count;
	ut8 *arw_ptr = NULL;
	int arw_sz = 0;
	int len = 0;
	ut8 thc[sizeof (struct thread_command)] = { 0 };
	ut8 tmp[4];

	if (off > mo->size || off + sizeof (struct thread_command) > mo->size) {
		return false;
	}

	len = r_buf_read_at (mo->b, off, thc, 8);
	if (len < 1) {
		goto wrong_read;
	}
	const bool be = mo->big_endian;
	mo->thread.cmd = r_read_ble32 (&thc[0], be);
	mo->thread.cmdsize = r_read_ble32 (&thc[4], be);
	if (r_buf_read_at (mo->b, off + sizeof (struct thread_command), tmp, 4) < 4) {
		goto wrong_read;
	}
	flavor = r_read_ble32 (tmp, be);

	if (off + sizeof (struct thread_command) + sizeof (flavor) > mo->size ||
		off + sizeof (struct thread_command) + sizeof (flavor) + sizeof (ut32) > mo->size) {
		return false;
	}

	// TODO: use count for checks
	if (r_buf_read_at (mo->b, off + sizeof (struct thread_command) + sizeof (flavor), tmp, 4) < 4) {
		goto wrong_read;
	}
	count = r_read_ble32 (tmp, be);
	ptr_thread = off + sizeof (struct thread_command) + sizeof (flavor) + sizeof (count);

	if (ptr_thread > mo->size) {
		return false;
	}

	switch (mo->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		switch (flavor) {
		case X86_THREAD_STATE32:
			if (ptr_thread + sizeof (struct x86_thread_state32) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.x86_32, "16i", 1) == -1) {
				R_LOG_ERROR ("read (thread state x86_32)");
				return false;
			}
			pc = mo->thread_state.x86_32.eip;
			pc_offset = ptr_thread + r_offsetof (struct x86_thread_state32, eip);
			arw_ptr = (ut8 *)&mo->thread_state.x86_32;
			arw_sz = sizeof (struct x86_thread_state32);
			break;
		case X86_THREAD_STATE64:
			if (ptr_thread + sizeof (struct x86_thread_state64) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.x86_64, "32l", 1) == -1) {
				R_LOG_ERROR ("read (thread state x86_64)");
				return false;
			}
			pc = mo->thread_state.x86_64.rip;
			pc_offset = ptr_thread + r_offsetof (struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&mo->thread_state.x86_64;
			arw_sz = sizeof (struct x86_thread_state64);
			break;
			// default: bprintf ("Unknown type\n");
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (flavor == X86_THREAD_STATE32) {
			if (ptr_thread + sizeof (struct ppc_thread_state32) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.ppc_32, be? "40I": "40i", 1) == -1) {
				R_LOG_ERROR ("read (thread state ppc_32)");
				return false;
			}
			pc = mo->thread_state.ppc_32.srr0;
			pc_offset = ptr_thread + r_offsetof (struct ppc_thread_state32, srr0);
			arw_ptr = (ut8 *)&mo->thread_state.ppc_32;
			arw_sz = sizeof (struct ppc_thread_state32);
		} else if (flavor == X86_THREAD_STATE64) {
			if (ptr_thread + sizeof (struct ppc_thread_state64) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.ppc_64, be? "34LI3LI": "34li3li", 1) == -1) {
				R_LOG_ERROR ("read (thread state ppc_64)");
				return false;
			}
			pc = mo->thread_state.ppc_64.srr0;
			pc_offset = ptr_thread + r_offsetof (struct ppc_thread_state64, srr0);
			arw_ptr = (ut8 *)&mo->thread_state.ppc_64;
			arw_sz = sizeof (struct ppc_thread_state64);
		}
		break;
	case CPU_TYPE_ARM:
		if (ptr_thread + sizeof (struct arm_thread_state32) > mo->size) {
			return false;
		}
		if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.arm_32, be? "17I": "17i", 1) == -1) {
			R_LOG_ERROR ("read (thread state arm)");
			return false;
		}
		pc = mo->thread_state.arm_32.r15;
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state32, r15);
		arw_ptr = (ut8 *)&mo->thread_state.arm_32;
		arw_sz = sizeof (struct arm_thread_state32);
		break;
	case CPU_TYPE_ARM64:
		if (ptr_thread + sizeof (struct arm_thread_state64) > mo->size) {
			return false;
		}
		if (r_buf_fread_at (mo->b, ptr_thread, (ut8 *)&mo->thread_state.arm_64, be? "34LI1I": "34Li1i", 1) == -1) {
			R_LOG_ERROR ("read (thread state arm)");
			return false;
		}
		pc = r_read_be64 (&mo->thread_state.arm_64.pc);
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state64, pc);
		arw_ptr = (ut8 *)&mo->thread_state.arm_64;
		arw_sz = sizeof (struct arm_thread_state64);
		break;
	default:
		R_LOG_ERROR ("read (unknown thread state structure)");
		return false;
	}

	if (mo->verbose && arw_ptr && arw_sz > 0) {
		int i;
		ut8 *p = arw_ptr;
		eprintf ("arw ");
		for (i = 0; i < arw_sz; i++) {
			eprintf ("%02x", 0xff & p[i]);
		}
		eprintf ("\n");
	}

	if (is_first_thread) {
		mo->main_cmd = *lc;
		if (pc != UT64_MAX) {
			mo->entry = pc;
		}
		if (pc_offset != UT64_MAX) {
			sdb_num_set (mo->kv, "mach0.entry.offset", pc_offset, 0);
		}
	}
	return true;
wrong_read:
	R_LOG_ERROR ("read (thread)");
	return false;
}

static bool parse_function_starts(struct MACH0_(obj_t) * mo, ut64 off) {
	struct linkedit_data_command fc;
	ut8 sfc[sizeof (struct linkedit_data_command)] = { 0 };
	if (mo->nofuncstarts) {
		return false;
	}

	if (off > mo->size || off + sizeof (struct linkedit_data_command) > mo->size) {
		R_LOG_DEBUG ("Likely overflow while parsing LC_FUNCTION_STARTS command");
	}
	// free previous allocation in case of duplicate LC_FUNCTION_STARTS
	R_FREE (mo->func_start);
	mo->func_size = 0;
	int len = r_buf_read_at (mo->b, off, sfc, sizeof (struct linkedit_data_command));
	if (len < 1) {
		R_LOG_WARN ("Failed to get data while parsing LC_FUNCTION_STARTS command");
	}
	const bool be = mo->big_endian;
	fc.cmd = r_read_ble32 (&sfc[0], be);
	fc.cmdsize = r_read_ble32 (&sfc[4], be);
	fc.dataoff = r_read_ble32 (&sfc[8], be);
	fc.datasize = r_read_ble32 (&sfc[12], be);

	if ((int)fc.datasize > 0) {
		ut8 *buf = calloc (1, fc.datasize + 1);
		if (!buf) {
			return false;
		}
		mo->func_size = fc.datasize;
		if (fc.dataoff > mo->size || fc.dataoff + fc.datasize > mo->size) {
			free (buf);
			R_LOG_WARN ("Likely overflow while parsing LC_FUNCTION_STARTS command");
			return false;
		}
		len = r_buf_read_at (mo->b, fc.dataoff, buf, fc.datasize);
		if (len != fc.datasize) {
			free (buf);
			R_LOG_WARN ("Failed to get data while parsing LC_FUNCTION_STARTS");
			return false;
		}
		buf[fc.datasize] = 0; // null-terminated buffer
		mo->func_start = buf;
		return true;
	}
	mo->func_start = NULL;
	return false;
}

static int parse_dylib(struct MACH0_(obj_t) * mo, ut64 off) {
	ut8 sdl[sizeof (struct dylib_command)] = { 0 };

	if (off > mo->size || off + sizeof (struct dylib_command) > mo->size) {
		return false;
	}

	char lib[R_BIN_MACH0_STRING_LENGTH] = { 0 };
	int len = r_buf_read_at (mo->b, off, sdl, sizeof (struct dylib_command));
	if (len < 1) {
		R_LOG_ERROR ("read (dylib)");
		return false;
	}
	const bool be = mo->big_endian;
	struct dylib_command dl = {
		.cmd = r_read_ble32 (&sdl[0], be),
		.cmdsize = r_read_ble32 (&sdl[4], be),
		.dylib.name = r_read_ble32 (&sdl[8], be),
		.dylib.timestamp = r_read_ble32 (&sdl[12], be),
		.dylib.current_version = r_read_ble32 (&sdl[16], be),
		.dylib.compatibility_version = r_read_ble32 (&sdl[20], be),
	};

	ut64 offname = off + dl.dylib.name;
	if (offname + R_BIN_MACH0_STRING_LENGTH > mo->size) {
		return false;
	}

	len = r_buf_read_at (mo->b, off + dl.dylib.name, (ut8 *)lib, R_BIN_MACH0_STRING_LENGTH - 1);
	if (len < 1) {
		R_LOG_ERROR ("read (dylib str)");
		return false;
	}

	char *name = r_str_ndup (lib, R_BIN_MACH0_STRING_LENGTH);
	RVecMach0Lib_push_back (&mo->libs_cache, &name);
	return true;
}

static const char *cmd_tostring(ut32 cmd) {
	switch (cmd) {
	case LC_DATA_IN_CODE:
		return "LC_DATA_IN_CODE";
	case LC_CODE_SIGNATURE:
		return "LC_CODE_SIGNATURE";
	case LC_RPATH:
		return "LC_RPATH";
	case LC_TWOLEVEL_HINTS:
		return "LC_TWOLEVEL_HINTS";
	case LC_PREBIND_CKSUM:
		return "LC_PREBIND_CKSUM";
	case LC_SEGMENT:
		return "LC_SEGMENT";
	case LC_SEGMENT_64:
		return "LC_SEGMENT_64";
	case LC_SYMTAB:
		return "LC_SYMTAB";
	case LC_SYMSEG:
		return "LC_SYMSEG";
	case LC_DYSYMTAB:
		return "LC_DYSYMTAB";
	case LC_PREBOUND_DYLIB:
		return "LC_PREBOUND_DYLIB";
	case LC_ROUTINES:
		return "LC_ROUTINES";
	case LC_ROUTINES_64:
		return "LC_ROUTINES_64";
	case LC_SUB_FRAMEWORK:
		return "LC_SUB_FRAMEWORK";
	case LC_SUB_UMBRELLA:
		return "LC_SUB_UMBRELLA";
	case LC_SUB_CLIENT:
		return "LC_SUB_CLIENT";
	case LC_SUB_LIBRARY:
		return "LC_SUB_LIBRARY";
	case LC_FUNCTION_STARTS:
		return "LC_FUNCTION_STARTS";
	case LC_DYLIB_CODE_SIGN_DRS:
		return "LC_DYLIB_CODE_SIGN_DRS";
	case LC_NOTE:
		return "LC_NOTE";
	case LC_BUILD_VERSION:
		return "LC_BUILD_VERSION";
	case LC_VERSION_MIN_MACOSX:
		return "LC_VERSION_MIN_MACOSX";
	case LC_VERSION_MIN_IPHONEOS:
		return "LC_VERSION_MIN_IPHONEOS";
	case LC_VERSION_MIN_TVOS:
		return "LC_VERSION_MIN_TVOS";
	case LC_VERSION_MIN_WATCHOS:
		return "LC_VERSION_MIN_WATCHOS";
	case LC_DYLD_INFO:
		return "LC_DYLD_INFO";
	case LC_DYLD_INFO_ONLY:
		return "LC_DYLD_INFO_ONLY";
	case LC_DYLD_ENVIRONMENT:
		return "LC_DYLD_ENVIRONMENT";
	case LC_SOURCE_VERSION:
		return "LC_SOURCE_VERSION";
	case LC_MAIN:
		return "LC_MAIN";
	case LC_UUID:
		return "LC_UUID";
	case LC_ID_DYLIB:
		return "LC_ID_DYLIB";
	case LC_ID_DYLINKER:
		return "LC_ID_DYLINKER";
	case LC_LAZY_LOAD_DYLIB:
		return "LC_LAZY_LOAD_DYLIB";
	case LC_ENCRYPTION_INFO:
		return "LC_ENCRYPTION_INFO";
	case LC_ENCRYPTION_INFO_64:
		return "LC_ENCRYPTION_INFO_64";
	case LC_SEGMENT_SPLIT_INFO:
		return "LC_SEGMENT_SPLIT_INFO";
	case LC_REEXPORT_DYLIB:
		return "LC_REEXPORT_DYLIB";
	case LC_LINKER_OPTION:
		return "LC_LINKER_OPTION";
	case LC_LINKER_OPTIMIZATION_HINT:
		return "LC_LINKER_OPTIMIZATION_HINT";
	case LC_LOAD_DYLINKER:
		return "LC_LOAD_DYLINKER";
	case LC_LOAD_DYLIB:
		return "LC_LOAD_DYLIB";
	case LC_LOAD_WEAK_DYLIB:
		return "LC_LOAD_WEAK_DYLIB";
	case LC_THREAD:
		return "LC_THREAD";
	case LC_UNIXTHREAD:
		return "LC_UNIXTHREAD";
	case LC_LOADFVMLIB:
		return "LC_LOADFVMLIB";
	case LC_IDFVMLIB:
		return "LC_IDFVMLIB";
	case LC_IDENT:
		return "LC_IDENT";
	case LC_FVMFILE:
		return "LC_FVMFILE";
	case LC_PREPAGE:
		return "LC_PREPAGE";
	case LC_AOT_METADATA:
		return "LC_AOT_METADATA";
	}
	return "";
}

static const char *cmd_to_pf_definition(ut32 cmd) {
	switch (cmd) {
	case LC_BUILD_VERSION:
		return "mach0_build_version_command";
	case LC_CODE_SIGNATURE:
		return "mach0_code_signature_command";
	case LC_DATA_IN_CODE:
		return "mach0_data_in_code_command";
	case LC_DYLD_INFO:
	case LC_DYLD_INFO_ONLY:
		return "mach0_dyld_info_only_command";
	case LC_DYLD_ENVIRONMENT:
		return NULL;
	case LC_DYLIB_CODE_SIGN_DRS:
		return NULL;
	case LC_DYSYMTAB:
		return "mach0_dysymtab_command";
	case LC_ENCRYPTION_INFO:
		return "mach0_encryption_info_command";
	case LC_ENCRYPTION_INFO_64:
		return "mach0_encryption_info64_command";
	case LC_FUNCTION_STARTS:
		return "mach0_function_starts_command";
	case LC_FVMFILE:
		return NULL;
	case LC_ID_DYLIB:
		return "mach0_id_dylib_command";
	case LC_ID_DYLINKER:
		return "mach0_id_dylinker_command";
	case LC_IDENT:
		return NULL;
	case LC_IDFVMLIB:
		return NULL;
	case LC_LINKER_OPTION:
		return NULL;
	case LC_LINKER_OPTIMIZATION_HINT:
		return NULL;
	case LC_LOAD_DYLINKER:
		return "mach0_load_dylinker_command";
	case LC_LAZY_LOAD_DYLIB:
	case LC_LOAD_WEAK_DYLIB:
	case LC_LOAD_DYLIB:
		return "mach0_dylib_command";
	case LC_LOADFVMLIB:
		return NULL;
	case LC_MAIN:
		return "mach0_entry_point_command";
	case LC_NOTE:
		return NULL;
	case LC_PREBIND_CKSUM:
		return NULL;
	case LC_PREBOUND_DYLIB:
		return NULL;
	case LC_PREPAGE:
		return NULL;
	case LC_REEXPORT_DYLIB:
		return NULL;
	case LC_ROUTINES:
		return NULL;
	case LC_ROUTINES_64:
		return NULL;
	case LC_RPATH:
		return "mach0_rpath_command";
	case LC_SEGMENT:
		return "mach0_segment";
	case LC_SEGMENT_64:
		return "mach0_segment64";
	case LC_SEGMENT_SPLIT_INFO:
		return "mach0_segment_split_info_command";
	case LC_SOURCE_VERSION:
		return "mach0_source_version_command";
	case LC_SUB_FRAMEWORK:
		return NULL;
	case LC_SUB_UMBRELLA:
		return NULL;
	case LC_SUB_CLIENT:
		return NULL;
	case LC_SUB_LIBRARY:
		return NULL;
	case LC_SYMTAB:
		return "mach0_symtab_command";
	case LC_SYMSEG:
		return NULL;
	case LC_TWOLEVEL_HINTS:
		return NULL;
	case LC_UUID:
		return "mach0_uuid_command";
	case LC_VERSION_MIN_MACOSX:
	case LC_VERSION_MIN_IPHONEOS:
	case LC_VERSION_MIN_TVOS:
	case LC_VERSION_MIN_WATCHOS:
		return "mach0_version_min_command";
	case LC_THREAD:
		return NULL;
	case LC_UNIXTHREAD:
		return "mach0_unixthread_command";
	case LC_AOT_METADATA:
		return "mach0_aot_metadata";
	}
	return NULL;
}

static const char *build_version_platform_tostring(ut32 platform) {
	switch (platform) {
	case 1:
		return "macOS";
	case 2:
		return "iOS";
	case 3:
		return "tvOS";
	case 4:
		return "watchOS";
	case 5:
		return "bridgeOS";
	case 6:
		return "iOSmac";
	case 7:
		return "iOS Simulator";
	case 8:
		return "tvOS Simulator";
	case 9:
		return "watchOS Simulator";
	case 10:
		return "DriverKit";
	case 11:
		return "VisionOS";
	case 12:
		return "VisionOS Simulator";
	case 0xffffffff:
		return "any";
	default:
		return "unknown";
	}
}

static const char *build_version_tool_tostring(ut32 tool) {
	switch (tool) {
	case 1:
		return "clang";
	case 2:
		return "swift";
	case 3:
		return "ld";
	default:
		return "unknown";
	}
}

static size_t get_word_size(struct MACH0_(obj_t) * mo) {
	const size_t word_size = MACH0_(get_bits) (mo) / 8;
	return R_MAX (word_size, 4);
}

static void free_chained_starts(struct MACH0_(obj_t) * mo) {
	if (mo->chained_starts) {
		size_t i;
		size_t count = R_MIN (mo->nsegs, mo->segs_count);
		for (i = 0; i < count; i++) {
			if (mo->chained_starts[i]) {
				free (mo->chained_starts[i]->page_start);
				free (mo->chained_starts[i]);
			}
		}
		R_FREE (mo->chained_starts);
	}
	mo->segs_count = 0;
}

static bool parse_chained_fixups(struct MACH0_(obj_t) * mo, ut32 offset, ut32 size) {
	struct dyld_chained_fixups_header header;
	if (size < sizeof (header)) {
		return false;
	}
	if (r_buf_fread_at (mo->b, offset, (ut8 *)&header, "7i", 1) != sizeof (header)) {
		return false;
	}
	if (header.fixups_version > 0) {
		R_LOG_WARN ("Unsupported fixups version: %u", header.fixups_version);
		return false;
	}
	ut64 starts_at = offset + header.starts_offset;
	if (header.starts_offset > size) {
		return false;
	}
	ut32 segs_count = r_buf_read_le32_at (mo->b, starts_at);
	if (segs_count == UT32_MAX || segs_count == 0) {
		return false;
	}
	// free previous allocation in case of duplicate LC_DYLD_CHAINED_FIXUPS
	free_chained_starts (mo);
	mo->chained_starts = R_NEWS0 (struct r_dyld_chained_starts_in_segment *, segs_count);
	if (!mo->chained_starts) {
		return false;
	}
	mo->segs_count = segs_count;
	mo->fixups_header = header;
	mo->fixups_offset = offset;
	mo->fixups_size = size;
	ut32 segs_to_parse = segs_count;
	if (mo->nsegs < 1) {
		return true;
	}
	if ((ut32)mo->nsegs < segs_to_parse) {
		segs_to_parse = (ut32)mo->nsegs;
	}
	size_t i;
	ut64 cursor = starts_at + sizeof (ut32);
	ut64 bsize = r_buf_size (mo->b);
	for (i = 0; i < segs_to_parse && cursor + 4 < bsize; i++) {
		ut32 seg_off;
		if ((seg_off = r_buf_read_le32_at (mo->b, cursor)) == UT32_MAX || !seg_off) {
			cursor += sizeof (ut32);
			continue;
		}
		struct r_dyld_chained_starts_in_segment *cur_seg = R_NEW0 (struct r_dyld_chained_starts_in_segment);
		mo->chained_starts[i] = cur_seg;
		if (r_buf_fread_at (mo->b, starts_at + seg_off, (ut8 *)cur_seg, "isslis", 1) != 22) {
			return false;
		}
		if (cur_seg->page_count > 0) {
			ut16 *page_start = malloc (sizeof (ut16) * cur_seg->page_count);
			if (!page_start) {
				return false;
			}
			if (r_buf_fread_at (mo->b, starts_at + seg_off + 22, (ut8 *)page_start, "s", cur_seg->page_count) != cur_seg->page_count * 2) {
				return false;
			}
			cur_seg->page_start = page_start;
		}
		cursor += sizeof (ut32);
	}
	/* TODO: handle also imports, symbols and multiple starts (32-bit only) */
	return true;
}

static bool reconstruct_chained_fixup(struct MACH0_(obj_t) * mo) {
	R_LOG_DEBUG ("reconstructing chained fixups");
	if (!mo->dyld_info) {
		return false;
	}
	if (!mo->nsegs) {
		return false;
	}
	free_chained_starts (mo);
	mo->chained_starts = R_NEWS0 (struct r_dyld_chained_starts_in_segment *, mo->nsegs);
	if (!mo->chained_starts) {
		return false;
	}
	size_t wordsize = get_word_size (mo);
	ut8 *p = NULL;
	ut64 count, skip;
	int seg_idx = 0;
	ut64 seg_off = 0;
	ut64 segment_size = 0;
	struct dyld_info_command *di = mo->dyld_info;
	size_t bind_size = di->bind_size;
	if (!bind_size) {
		return false;
	}
	if (!fits_in (mo->size, di->bind_off, bind_size)) {
		return false;
	}
	ut8 *opcodes = calloc (1, bind_size + 1);
	if (!opcodes) {
		return false;
	}
	if (r_buf_read_at (mo->b, di->bind_off, opcodes, bind_size) != bind_size) {
		R_LOG_ERROR ("read (dyld_info bind) at 0x%08" PFMT64x, (ut64) (size_t)di->bind_off);
		R_FREE (opcodes);
		return false;
	}
	struct r_dyld_chained_starts_in_segment *cur_seg = NULL;
	size_t cur_seg_idx = 0;
	ut8 *end;
	bool done = false;
	if (!segment_filebacked_size (mo, seg_idx, &segment_size)) {
		R_FREE (opcodes);
		return false;
	}
	for (p = opcodes, end = opcodes + bind_size; !done && p < end;) {
		ut8 imm = *p & BIND_IMMEDIATE_MASK, op = *p & BIND_OPCODE_MASK;
		p++;
		switch (op) {
		case BIND_OPCODE_DONE:
			done = true;
			break;
		case BIND_OPCODE_THREADED:
			{
				switch (imm) {
				case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
					read_uleb128 (&p, end);
					break;
				case BIND_SUBOPCODE_THREADED_APPLY:
					{
						const size_t ps = 0x1000;
						if (!cur_seg || cur_seg_idx != seg_idx) {
							cur_seg_idx = seg_idx;
							cur_seg = mo->chained_starts[seg_idx];
							if (!cur_seg) {
								cur_seg = R_NEW0 (struct r_dyld_chained_starts_in_segment);
								if (!cur_seg) {
									break;
								}
								mo->chained_starts[seg_idx] = cur_seg;
								cur_seg->pointer_format = DYLD_CHAINED_PTR_ARM64E;
								cur_seg->page_size = ps;
								cur_seg->page_count = ((segment_size + (ps - 1)) & ~ (ps - 1)) / ps;
								if (cur_seg->page_count > 0) {
									cur_seg->page_start = R_NEWS0 (ut16, cur_seg->page_count);
									if (!cur_seg->page_start) {
										break;
									}
									memset (cur_seg->page_start, 0xff, sizeof (ut16) * cur_seg->page_count);
								}
							}
						}
						{
							ut32 page_index = (ut32) (seg_off / ps);
							if (page_index < cur_seg->page_count && cur_seg->page_start) {
								cur_seg->page_start[page_index] = seg_off & 0xfff;
							}
						}
						break;
					}
				default:
					R_LOG_ERROR ("Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x", imm);
					break;
				}
			}
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
		case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
		case BIND_OPCODE_SET_TYPE_IMM:
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
			read_uleb128 (&p, end);
			break;
		case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			while (*p++ && p < end) {
				/* empty loop */
			}
			break;
		case BIND_OPCODE_SET_ADDEND_SLEB:
			r_sleb128 ((const ut8 **)&p, end);
			break;
		case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			seg_idx = imm;
			if (seg_idx >= mo->nsegs) {
				R_LOG_ERROR ("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has unexistent segment %d", seg_idx);
				R_FREE (opcodes);
				return false;
			}
			seg_off = read_uleb128 (&p, end);
			if (!segment_filebacked_size (mo, seg_idx, &segment_size) || seg_off > segment_size) {
				R_LOG_ERROR ("Malformed bind opcode stream");
				R_FREE (opcodes);
				return false;
			}
			break;
		case BIND_OPCODE_ADD_ADDR_ULEB:
			if (!safe_advance (&seg_off, read_uleb128 (&p, end))) {
				R_FREE (opcodes);
				return false;
			}
			break;
		case BIND_OPCODE_DO_BIND:
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			if (!safe_advance2 (&seg_off, read_uleb128 (&p, end), wordsize)) {
				R_FREE (opcodes);
				return false;
			}
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			{
				ut64 scaled = 0;
				if (!UT64_MUL (&scaled, (ut64)imm, (ut64)wordsize) || !safe_advance2 (&seg_off, scaled, wordsize)) {
					R_FREE (opcodes);
					return false;
				}
			}
			break;
		case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			count = read_uleb128 (&p, end);
			skip = read_uleb128 (&p, end);
			{
				ut64 stride = 0;
				ut64 span = 0;
				if (!UT64_ADD (&stride, skip, wordsize) || !bind_fits (count, seg_off, segment_size, stride)) {
					R_LOG_ERROR ("Malformed bind opcode stream");
					R_FREE (opcodes);
					return false;
				}
				if (!UT64_MUL (&span, count, stride) || !safe_advance (&seg_off, span)) {
					R_FREE (opcodes);
					return false;
				}
			}
			break;
		default:
			R_LOG_ERROR ("unknown bind opcode 0x%02x in dyld_info", *p);
			R_FREE (opcodes);
			return false;
		}
	}
	R_FREE (opcodes);

	mo->segs_count = mo->nsegs;
	return true;
}

static int init_items(struct MACH0_(obj_t) * mo) {
	bool skip_chained_fixups = r_sys_getenv_asbool ("RABIN2_MACHO_SKIPFIXUPS");
	struct load_command lc = { 0, 0 };
	ut8 loadc[sizeof (struct load_command)] = { 0 };
	bool is_first_thread = true;
	ut64 cmds_begin = sizeof (struct MACH0_(mach_header)) + mo->header_at;
	ut64 cmds_end = 0;
	ut64 off = 0LL;
	int i, len;
	char cmd_flagname[128];

	mo->uuidn = 0;
	mo->os = 0;
	mo->has_crypto = false;
	mo->segments_vec = NULL;
	RVecMach0Lib_init (&mo->libs_cache);

	if (mo->hdr.sizeofcmds > 0 && fits_in (mo->size, cmds_begin, mo->hdr.sizeofcmds)) {
		cmds_end = cmds_begin + mo->hdr.sizeofcmds;
	} else {
		if (mo->hdr.ncmds > 0) {
			R_LOG_WARN ("chopping hdr.sizeofcmds because it's larger than the file size");
		}
		cmds_end = mo->size;
	}
	bool noFuncStarts = mo->nofuncstarts;
	// bprintf ("Commands: %d\n", mo->hdr.ncmds);
	for (i = 0, off = cmds_begin;
		i < mo->hdr.ncmds;
		i++, off += lc.cmdsize) {
		if (!fits_in (cmds_end, off, sizeof (struct load_command))) {
			R_LOG_WARN ("out of bounds macho command");
			break;
		}
		len = r_buf_read_at (mo->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			R_LOG_ERROR ("read (lc) at 0x%08" PFMT64x, off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], mo->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], mo->big_endian);

		if (lc.cmdsize < 1 || !fits_in (mo->size, off, lc.cmdsize)) {
			R_LOG_WARN ("mach0_header %d = cmdsize<1. (0x%" PFMT64x " vs 0x%" PFMT64x ")", i, off + lc.cmdsize, mo->size);
			break;
		}
		snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.offset", i);
		sdb_num_set (mo->kv, cmd_flagname, off, 0);
		const char *format_name = cmd_to_pf_definition (lc.cmd);
		snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.format", i);
		if (format_name) {
			sdb_set (mo->kv, cmd_flagname, format_name, 0);
		} else {
			sdb_set (mo->kv, cmd_flagname, "[4]Ed (mach_load_command_type)cmd size", 0);
		}

		snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.cmd", i);
		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set (mo->kv, cmd_flagname, "data_in_code", 0);
			break;
		case LC_RPATH:
			sdb_set (mo->kv, cmd_flagname, "rpath", 0);
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			sdb_set (mo->kv, cmd_flagname, "segment", 0);
			mo->nsegs++;
			if (!parse_segments (mo, off)) {
				R_LOG_ERROR ("parsing segment");
				mo->nsegs--;
				return false;
			}
			break;
		case LC_SYMTAB:
			sdb_set (mo->kv, cmd_flagname, "symtab", 0);
			if (!parse_symtab (mo, off)) {
				R_LOG_ERROR ("parsing symtab");
				return false;
			}
			break;
		case LC_DYSYMTAB:
			sdb_set (mo->kv, cmd_flagname, "dysymtab", 0);
			if (!parse_dysymtab (mo, off)) {
				R_LOG_ERROR ("parsing dysymtab");
				return false;
			}
			break;
		case LC_AOT_METADATA:
			sdb_set (mo->kv, cmd_flagname, "aot_metadata", 0);
			if (!parse_aot_metadata (mo, off)) {
				return false;
			}
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			sdb_set (mo->kv, cmd_flagname, "dylib_code_sign_drs", 0);
			R_LOG_DEBUG ("[mach0] code is signed");
			break;
		case LC_VERSION_MIN_MACOSX:
			sdb_set (mo->kv, cmd_flagname, "version_min_macosx", 0);
			mo->os = 1;
			// set OS = osx
			// bprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set (mo->kv, cmd_flagname, "version_min_iphoneos", 0);
			mo->os = 2;
			// set OS = ios
			// bprintf ("[mach0] Requires iOS >= x\n");
			break;
		case LC_VERSION_MIN_TVOS:
			sdb_set (mo->kv, cmd_flagname, "version_min_tvos", 0);
			mo->os = 4;
			break;
		case LC_VERSION_MIN_WATCHOS:
			sdb_set (mo->kv, cmd_flagname, "version_min_watchos", 0);
			mo->os = 3;
			break;
		case LC_UUID:
			sdb_set (mo->kv, cmd_flagname, "uuid", 0);
			{
				struct uuid_command uc = { 0 };
				if (off + sizeof (struct uuid_command) > mo->size) {
					R_LOG_DEBUG ("UUID out of bounds");
					return false;
				}
				if (r_buf_fread_at (mo->b, off, (ut8 *)&uc, "24c", 1) != -1) {
					char key[128];
					char val[128];
					snprintf (key, sizeof (key) - 1, "uuid.%d", mo->uuidn++);
					r_hex_bin2str ((ut8 *)&uc.uuid, 16, val);
					sdb_set (mo->kv, key, val, 0);
					// for (i=0;i<16; i++) bprintf ("%02x%c", uc.uuid[i], (i==15)? '\n': '-');
				}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set (mo->kv, cmd_flagname, "encryption_info", 0);
			{
				struct MACH0_(encryption_info_command) eic = { 0 };
				ut8 seic[sizeof (struct MACH0_(encryption_info_command))] = { 0 };
				if (off + sizeof (struct MACH0_(encryption_info_command)) > mo->size) {
					R_LOG_DEBUG ("encryption info out of bounds");
					return false;
				}
				if (r_buf_read_at (mo->b, off, seic, sizeof (struct MACH0_(encryption_info_command))) != -1) {
					eic.cmd = r_read_ble32 (&seic[0], mo->big_endian);
					eic.cmdsize = r_read_ble32 (&seic[4], mo->big_endian);
					eic.cryptoff = r_read_ble32 (&seic[8], mo->big_endian);
					eic.cryptsize = r_read_ble32 (&seic[12], mo->big_endian);
					eic.cryptid = r_read_ble32 (&seic[16], mo->big_endian);

					mo->has_crypto = eic.cryptid;
					sdb_set (mo->kv, "crypto", eic.cryptid? "true": "false", 0);
					sdb_num_set (mo->kv, "cryptid", eic.cryptid, 0);
					sdb_num_set (mo->kv, "cryptoff", eic.cryptoff, 0);
					sdb_num_set (mo->kv, "cryptsize", eic.cryptsize, 0);
					sdb_num_set (mo->kv, "cryptheader", off, 0);
				}
			}
			break;
		case LC_LOAD_DYLINKER:
			{
				sdb_set (mo->kv, cmd_flagname, "dylinker", 0);
				R_FREE (mo->intrp);
				R_LOG_DEBUG ("[mach0] load dynamic linker");
				struct dylinker_command dy = { 0 };
				ut8 sdy[sizeof (struct dylinker_command)] = { 0 };
				if (off + sizeof (struct dylinker_command) > mo->size) {
					R_LOG_DEBUG ("Cannot parse dylinker command");
					return false;
				}
				if (r_buf_read_at (mo->b, off, sdy, sizeof (struct dylinker_command)) == -1) {
					R_LOG_DEBUG ("Cannot read (LC_DYLD_INFO) at 0x%08" PFMT64x, off);
				} else {
					dy.cmd = r_read_ble32 (&sdy[0], mo->big_endian);
					dy.cmdsize = r_read_ble32 (&sdy[4], mo->big_endian);
					dy.name = r_read_ble32 (&sdy[8], mo->big_endian);

					ut32 len = dy.cmdsize;
					if (len < 1 || off + 0xc + len > mo->size) {
						break;
					}
					char *buf = malloc (len + 1);
					if (buf) {
						r_buf_read_at (mo->b, off + 0xc, (ut8 *)buf, len);
						buf[len] = 0;
						free (mo->intrp);
						mo->intrp = buf;
					}
				}
			}
			break;
		case LC_MAIN:
			{
				struct {
					ut64 eo;
					ut64 ss;
				} ep = { 0 };
				ut8 sep[2 * sizeof (ut64)] = { 0 };
				sdb_set (mo->kv, cmd_flagname, "main", 0);

				if (!is_first_thread) {
					R_LOG_DEBUG ("Error: LC_MAIN with other threads");
					return false;
				}
				if (off + 8 > mo->size || off + sizeof (ep) > mo->size) {
					R_LOG_DEBUG ("invalid command size for main");
					return false;
				}
				r_buf_read_at (mo->b, off + 8, sep, 2 * sizeof (ut64));
				ep.eo = r_read_ble64 (&sep[0], mo->big_endian);
				ep.ss = r_read_ble64 (&sep[8], mo->big_endian);

				mo->entry = ep.eo;
				mo->main_cmd = lc;

				sdb_num_set (mo->kv, "mach0.entry.offset", off + 8, 0);
				sdb_num_set (mo->kv, "stacksize", ep.ss, 0);

				is_first_thread = false;
			}
			break;
		case LC_UNIXTHREAD:
			sdb_set (mo->kv, cmd_flagname, "unixthread", 0);
			if (!is_first_thread) {
				R_LOG_DEBUG ("Error LC_UNIXTHREAD with other threads");
				return false;
			}
		case LC_THREAD:
			sdb_set (mo->kv, cmd_flagname, "thread", 0);
			if (!parse_thread (mo, &lc, off, is_first_thread)) {
				R_LOG_DEBUG ("Cannot parse thread");
				return false;
			}
			is_first_thread = false;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			sdb_set (mo->kv, cmd_flagname, "load_dylib", 0);
			mo->nlibs++;
			if (!parse_dylib (mo, off)) {
				R_LOG_DEBUG ("Cannot parse dylib command");
				mo->nlibs--;
				return false;
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
				ut8 dyldi[sizeof (struct dyld_info_command)] = { 0 };
				sdb_set (mo->kv, cmd_flagname, "dyld_info", 0);
				mo->dyld_info = calloc (1, sizeof (struct dyld_info_command));
				if (mo->dyld_info) {
					if (off + sizeof (struct dyld_info_command) > mo->size) {
						R_LOG_DEBUG ("Cannot parse dyldinfo");
						R_FREE (mo->dyld_info);
						return false;
					}
					if (r_buf_read_at (mo->b, off, dyldi, sizeof (struct dyld_info_command)) == -1) {
						R_FREE (mo->dyld_info);
						R_LOG_DEBUG ("read (LC_DYLD_INFO) at 0x%08" PFMT64x, off);
					} else {
						const bool be = mo->big_endian;
						struct dyld_info_command *di = mo->dyld_info;
						di->cmd = r_read_ble32 (&dyldi[0], be);
						di->cmdsize = r_read_ble32 (&dyldi[4], be);
						di->rebase_off = r_read_ble32 (&dyldi[8], be);
						di->rebase_size = r_read_ble32 (&dyldi[12], be);
						di->bind_off = r_read_ble32 (&dyldi[16], be);
						di->bind_size = r_read_ble32 (&dyldi[20], be);
						di->weak_bind_off = r_read_ble32 (&dyldi[24], be);
						di->weak_bind_size = r_read_ble32 (&dyldi[28], be);
						di->lazy_bind_off = r_read_ble32 (&dyldi[32], be);
						di->lazy_bind_size = r_read_ble32 (&dyldi[36], be);
						di->export_off = r_read_ble32 (&dyldi[40], be) + mo->symbols_off;
						di->export_size = r_read_ble32 (&dyldi[44], be);
					}
				}
			}
			break;
		case LC_CODE_SIGNATURE:
			parse_signature (mo, off);
			sdb_set (mo->kv, cmd_flagname, "signature", 0);
			/* ut32 dataoff
			// ut32 datasize */
			break;
		case LC_BUILD_VERSION:
			switch (r_buf_read_le32_at (mo->b, off + 8)) {
			case 1: // macos
			case 6: // iosmac
				mo->os = 1;
				break;
			case 2: // ios
			case 3: // tvos
			case 4: // watchos
			case 5: // bridgeos
			case 7: // ios-simulator
			case 8: // tvos-simulator
			case 9: // watchos-simulator
				mo->os = 2; // add enum for this, but 2=ios
				break;
			}
			R_LOG_DEBUG ("asm.os=%s", build_version_platform_tostring (r_buf_read_le32_at (mo->b, off + 8)));
			break;
		case LC_SOURCE_VERSION:
			sdb_set (mo->kv, cmd_flagname, "version", 0);
			/* uint64_t  version;  */
			/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
			// bprintf ("mach0: TODO: Show source version\n");
			break;
		case LC_SEGMENT_SPLIT_INFO:
			sdb_set (mo->kv, cmd_flagname, "split_info", 0);
			/* TODO */
			break;
		case LC_FUNCTION_STARTS:
			if (noFuncStarts) {
				// do nothing here
			} else {
				sdb_set (mo->kv, cmd_flagname, "function_starts", 0);
				if (!parse_function_starts (mo, off)) {
					R_LOG_DEBUG ("Unable to parse the LC_FUNCTION_STARTS");
				}
			}
			break;
		case LC_REEXPORT_DYLIB:
			sdb_set (mo->kv, cmd_flagname, "dylib", 0);
			/* TODO */
			break;
		case LC_ID_DYLIB:
			{
				ut64 addr = off;
				bool isBe = false;
				RBuffer *buf = mo->b;
				ut32 str_off = r_buf_read_ble32_at (buf, addr, isBe);
				char *s = r_str_newf ("%d.%d.%d",
					r_buf_read_le16_at (buf, addr + 10),
					r_buf_read8_at (buf, addr + 9),
					r_buf_read8_at (buf, addr + 8));
				sdb_set (mo->kv, "id.version", s, 0);
				free (s);
				s = r_str_newf ("%d.%d.%d",
					r_buf_read_le16_at (buf, addr + 14),
					r_buf_read8_at (buf, addr + 13),
					r_buf_read8_at (buf, addr + 12));
				sdb_set (mo->kv, "id.compat", s, 0);
				free (s);
				char *id = r_buf_get_string (buf, addr + str_off - 8);
				if (R_STR_ISNOTEMPTY (id)) {
					sdb_set (mo->kv, "id.name", id, 0);
					free (id);
				}
			}
			break;
		case LC_DYLD_EXPORTS_TRIE:
			break;
		case LC_DYLD_CHAINED_FIXUPS:
			break;
		default:
			R_LOG_DEBUG ("Unknown header %d command 0x%x at 0x%08" PFMT64x, i, lc.cmd, off);
			break;
		}
	}
	bool has_chained_fixups = false;
	for (i = 0, off = sizeof (struct MACH0_(mach_header)) + mo->header_at;
		i < mo->hdr.ncmds;
		i++, off += lc.cmdsize) {
		len = r_buf_read_at (mo->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			R_LOG_DEBUG ("read (lc) at 0x%08" PFMT64x, off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], mo->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], mo->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > mo->size) {
			R_LOG_DEBUG ("mach0_header %d = cmdsize<1. (0x%" PFMT64x " vs 0x%" PFMT64x ")", i, (ut64) (off + lc.cmdsize), (ut64) (mo->size));
			break;
		}
		snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.offset", i);
		sdb_num_set (mo->kv, cmd_flagname, off, 0);
		const char *format_name = cmd_to_pf_definition (lc.cmd);
		snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.format", i);
		if (format_name) {
			sdb_set (mo->kv, cmd_flagname, format_name, 0);
		} else {
			sdb_set (mo->kv, cmd_flagname, "[4]Ed (mach_load_command_type)cmd size", 0);
		}

		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			snprintf (cmd_flagname, sizeof (cmd_flagname), "mach0_cmd_%d.cmd", i);
			sdb_set (mo->kv, cmd_flagname, "data_in_code", 0);
			if (mo->verbose) {
				ut8 buf[8];
				r_buf_read_at (mo->b, off + 8, buf, sizeof (buf));
				ut32 dataoff = r_read_ble32 (buf, mo->big_endian);
				ut32 datasize = r_read_ble32 (buf + 4, mo->big_endian);
				R_LOG_INFO ("data-in-code at 0x%x size %d", dataoff, datasize);
				ut8 *db = (ut8 *)malloc (datasize);
				if (db) {
					r_buf_read_at (mo->b, dataoff, db, datasize);
					// TODO table of non-instructions regions in __text
					int j;
					for (j = 0; j < datasize; j += 8) {
						ut32 dw = r_read_ble32 (db + j, mo->big_endian);
						// int kind = r_read_ble16 (db + i + 4 + 2, mo->big_endian);
						int len = r_read_ble16 (db + j + 4, mo->big_endian);
						ut64 va = offset_to_vaddr (mo, dw);
						//	eprintf ("# 0x%x -> 0x%x\n", dw, va);
						//	eprintf ("0x%x kind %d len %d\n", dw, kind, len);
						eprintf ("Cd 8 %d @ 0x%" PFMT64x "\n", len / 8, va);
					}
				}
			}
			break;
		case LC_DYLD_EXPORTS_TRIE:
			{
				ut8 buf[8];
				r_buf_read_at (mo->b, off + 8, buf, sizeof (buf));
				mo->exports_trie_off = r_read_ble32 (buf, mo->big_endian) + mo->symbols_off;
				mo->exports_trie_size = r_read_ble32 (buf + 4, mo->big_endian);
				if (mo->verbose) {
					R_LOG_INFO ("exports trie at 0x%x size %d", mo->exports_trie_off, mo->exports_trie_size);
				}
			}
			break;
		case LC_DYLD_CHAINED_FIXUPS:
			if (!skip_chained_fixups) {
				ut8 buf[8];
				if (r_buf_read_at (mo->b, off + 8, buf, sizeof (buf)) == sizeof (buf)) {
					ut32 dataoff = r_read_ble32 (buf, mo->big_endian);
					ut32 datasize = r_read_ble32 (buf + 4, mo->big_endian);
					R_LOG_DEBUG ("chained fixups at 0x%08x with size %d", (ut64)dataoff, (int)datasize);
					has_chained_fixups = parse_chained_fixups (mo, dataoff, datasize);
				}
			}
			break;
		}
	}

	if (!has_chained_fixups && mo->hdr.cputype == CPU_TYPE_ARM64 && (mo->hdr.cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
		reconstruct_chained_fixup (mo);
	}
	return true;
}

static bool init(struct MACH0_(obj_t) * mo) {
	if (!init_hdr (mo)) {
		return false;
	}
	if (!init_items (mo)) {
		R_LOG_WARN ("Cannot initialize items");
	}
	mo->baddr = MACH0_(get_baddr) (mo);
	mo->libs_loaded = true;
	RVecMach0Lib_shrink_to_fit (&mo->libs_cache);
	return true;
}

void *MACH0_(mach0_free)(struct MACH0_(obj_t) * mo) {
	if (!mo) {
		return NULL;
	}

	free (mo->segs);
	free (mo->sects);
	free (mo->symtab);
	free (mo->symstr);
	free (mo->indirectsyms);
	if (mo->imports_by_name) {
		mo->imports_by_name->opt.freefn = import_hash_free;
		ht_pp_free (mo->imports_by_name);
	}
	free (mo->dyld_info);
	free (mo->toc);
	free (mo->modtab);
	if (mo->libs_loaded) {
		RVecMach0Lib_fini (&mo->libs_cache);
	}
	free (mo->func_start);
	free (mo->signature);
	free (mo->intrp);
	free (mo->compiler);
	if (mo->imports_loaded) {
		RVecRBinImport_fini (&mo->imports_cache);
	}
	if (mo->sections_loaded) {
		RVecSection_fini (&mo->sections_cache);
	}
	RVecSegment_free (mo->segments_vec);
	mo->segments_vec = NULL;
	if (mo->relocs_loaded) {
		r_skiplist_free (mo->relocs_cache);
	}
	free_chained_starts (mo);
	sdb_free (mo->kv);
	r_unref (mo->b);
	free (mo);
	return NULL;
}

void MACH0_(opts_set_default)(struct MACH0_(opts_t) * options, RBinFile *bf) {
	R_RETURN_IF_FAIL (options && bf && bf->rbin);
	options->bf = bf;
	options->header_at = 0;
	options->symbols_off = 0;
	options->verbose = bf->rbin->options.verbose;
	options->maxsymlen = bf->rbin->options.maxsymlen;
	options->parse_start_symbols = false;
}

struct MACH0_(obj_t) * MACH0_(new_buf)(RBinFile *bf, RBuffer *buf, struct MACH0_(opts_t) * options) {
	R_RETURN_VAL_IF_FAIL (buf && options->bf->bo, NULL);
	struct MACH0_(obj_t) *mo = R_NEW0 (struct MACH0_(obj_t));
	mo->b = r_ref (buf);
	mo->main_addr = UT64_MAX;
	mo->kv = sdb_new (NULL, "bin.mach0", 0);
	mo->imports_by_name = ht_pp_new0 ();
	// probably unnecessary indirection if we pass bf or bo to the apis instead of mo
	// RVecRBinSymbol_init (&options->bf->bo->symbols_vec);
	mo->symbols_vec = &(options->bf->bo->symbols_vec);
	mo->options = *options;
	mo->limit = options->bf->rbin->options.limit;
	// mo->nofuncstarts = options->nofuncstarts;
	// r_sys_getenv_asbool ("RABIN2_MACHO_NOFUNCSTARTS");
	ut64 sz = r_buf_size (buf);
	mo->verbose = options->verbose;
	mo->header_at = options->header_at;
	mo->maxsymlen = options->maxsymlen;
	mo->symbols_off = options->symbols_off;
	mo->parse_start_symbols = options->parse_start_symbols;
	mo->size = sz;
	if (!init (mo)) {
		return MACH0_(mach0_free) (mo);
	}
	return mo;
}

// prot: r = 1, w = 2, x = 4
// perm: r = 4, w = 2, x = 1
static int prot2perm(int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

static bool is_data_section(RBinSection *sect) {
	if (strstr (sect->name, "_cstring")) {
		return true;
	}
	if (strstr (sect->name, "_objc_methname")) {
		return true;
	}
	if (strstr (sect->name, "_objc_classname")) {
		return true;
	}
	if (strstr (sect->name, "_objc_methtype")) {
		return true;
	}
	return false;
}

static const char *macho_section_type_tostring(int flags) {
	switch (flags & UT8_MAX) {
	case S_REGULAR:
		return "REGULAR";
	case S_ZEROFILL:
		return "ZEROFILL";
	case S_CSTRING_LITERALS:
		return "CSTRINGS";
	case S_4BYTE_LITERALS:
		return "4BYTE";
	case S_8BYTE_LITERALS:
		return "8BYTE";
	case S_16BYTE_LITERALS:
		return "16BYTE";
	case S_SYMBOL_STUBS:
		return "SYMBOL_STUBS";
	case S_LITERAL_POINTERS:
		return "POINTERS";
	case S_NON_LAZY_SYMBOL_POINTERS:
		return "NONLAZY_POINTERS";
	case S_THREAD_LOCAL_REGULAR:
		return "TLS_REGULAR";
	case S_THREAD_LOCAL_ZEROFILL:
		return "TLS_ZEROFILL";
	case S_THREAD_LOCAL_VARIABLES:
		return "TLS_VARIABLES";
	case S_THREAD_LOCAL_VARIABLE_POINTERS:
		return "TLS_POINTERS";
	case S_GB_ZEROFILL:
		return "GB_ZEROFILL";
	case S_COALESCED:
		return "COALESCED";
	case S_DTRACE_DOF:
		return "DTRACE_DOF";
	case S_INTERPOSING: // 0x0du,
		return "INTERPOSING";
	case S_LAZY_SYMBOL_POINTERS: // 0x0du,
		return "LAZY_SYMBOL_POINTERS";
	case S_MOD_INIT_FUNC_POINTERS:
		return "MOD_INIT_FUNC_POINTERS";
	case S_MOD_TERM_FUNC_POINTERS:
		return "MOD_TERM_FUNC_POINTERS";
	case S_LAZY_DYLIB_SYMBOL_POINTERS:
		return "LAZY_DYLIB_SYMBOL_POINTERS";
	case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
		return "TLS_INIT_FUNCTIONS";
	case S_INIT_FUNC_OFFSETS:
		return "INIT_FUNC_OFFSETS";
#if 0
	S_ATTR_PURE_INSTRUCTIONS   = 0x80000000u,
	S_ATTR_NO_TOC              = 0x40000000u,
	S_ATTR_STRIP_STATIC_SYMS   = 0x20000000u,
	S_ATTR_NO_DEAD_STRIP       = 0x10000000u,
	S_ATTR_LIVE_SUPPORT        = 0x08000000u,
	S_ATTR_SELF_MODIFYING_CODE = 0x04000000u,
	S_ATTR_DEBUG               = 0x02000000u,
	S_ATTR_SOME_INSTRUCTIONS   = 0x00000400u,
	S_ATTR_EXT_RELOC           = 0x00000200u,
	S_ATTR_LOC_RELOC           = 0x00000100u,
	INDIRECT_SYMBOL_LOCAL = 0x80000000u,
	INDIRECT_SYMBOL_ABS   = 0x40000000u
#endif
	}
	R_LOG_WARN ("Unknown section flags 0x%x", flags);
	return "";
}

RVecSegment *MACH0_(get_segments_vec)(RBinFile *bf, struct MACH0_(obj_t) * mo) {
	if (mo->segments_vec) {
		return mo->segments_vec;
	}

	mo->segments_vec = RVecSegment_new ();

	/* for core files */
	if (mo->nsegs > 0) {
		if (RVecSegment_reserve (mo->segments_vec, mo->nsegs)) {
			size_t i;
			for (i = 0; i < mo->nsegs; i++) {
				struct MACH0_(segment_command) *seg = &mo->segs[i];
				if (!seg->initprot) {
					continue;
				}

				RBinSection *s = RVecSegment_emplace_back (mo->segments_vec);
				if (!s) {
					break;
				}
				memset (s, 0, sizeof (RBinSection)); // XXX redundant?

				s->vaddr = seg->vmaddr;
				s->vsize = seg->vmsize;
				s->size = seg->vmsize;
				s->paddr = seg->fileoff;
				s->paddr += bf->bo->boffset;
				// TODO s->flags = seg->flags;
				s->name = r_str_ndup (seg->segname, 16);
				s->is_segment = true;
				r_str_filter (s->name, -1);
				s->perm = prot2perm (seg->initprot);
				s->add = true;
			}
		}
	}

	const int ws = R_BIN_MACH0_WORD_SIZE;
	if (mo->nsects > 0) {
		const int last_section = R_MIN (mo->nsects, MACHO_MAX_SECTIONS);
		const ut64 total_size = RVecSegment_length (mo->segments_vec) + last_section;
		if (RVecSegment_reserve (mo->segments_vec, total_size)) {
			size_t i;
			for (i = 0; i < last_section; i++) {
				RBinSection *s = RVecSegment_emplace_back (mo->segments_vec);
				if (!s) {
					break;
				}
				memset (s, 0, sizeof (RBinSection)); // XXX redundant?

				struct MACH0_(section) *sect = &mo->sects[i];
				s->vaddr = (ut64)sect->addr;
				s->vsize = (ut64)sect->size;
				s->is_segment = false;
				s->size = (sect->flags == S_ZEROFILL)? 0: (ut64)sect->size;
				s->type = macho_section_type_tostring (sect->flags);
				s->paddr = (ut64)sect->offset;

				int segment_index = 0;
				size_t j;
				for (j = 0; j < mo->nsegs; j++) {
					struct MACH0_(segment_command) *seg = &mo->segs[j];
					if (s->vaddr >= seg->vmaddr &&
						s->vaddr < (seg->vmaddr + seg->vmsize)) {
						s->perm = prot2perm (seg->initprot);
						segment_index = j;
						break;
					}
				}

				char *section_name = r_str_ndup (sect->sectname, 16);
				char *segment_name = r_str_newf ("%u.%s", (ut32)i, mo->segs[segment_index].segname);
				s->name = r_str_newf ("%s.%s", segment_name, section_name);
				if (strstr (s->name, "__const")) {
					s->format = r_str_newf ("Cd %d %" PFMT64d, ws, s->size / ws);
				}

				s->is_data = is_data_section (s);
				if (strstr (section_name, "interpos") || strstr (section_name, "__mod_")) {
					free (s->format);
					s->format = r_str_newf ("Cd %d[%" PFMT64d "]", ws, s->vsize / ws);
				}
				// https://github.com/radareorg/ideas/issues/104
				// https://stackoverflow.com/questions/29665371/compiling-a-binary-immune-to-library-redirection-on-mac-os-x
				if (strstr (section_name, "restrict") || strstr (section_name, "RESTRICT")) {
					mo->has_libinjprot = true;
				}
				free (segment_name);
				free (section_name);
			}
		}
	}

	return mo->segments_vec;
}

RList *MACH0_(get_segments)(RBinFile *bf, struct MACH0_(obj_t) * macho) {
	RList *list = r_list_newf ((RListFree)r_bin_section_free);
	if (!list) {
		return NULL;
	}

	// R2_590 slow, should return vec directly
	RVecSegment *segments = MACH0_(get_segments_vec) (bf, macho);
	const int limit = macho->limit;
	int count = 0;
	RBinSection *s;
	R_VEC_FOREACH (segments, s) {
		if (limit > 0 && !s->is_segment && count >= limit) {
			break;
		}
		RBinSection *s_copy = r_bin_section_clone (s);
		if (!s_copy) {
			r_list_free (list);
			return NULL;
		}
		r_list_append (list, s_copy);
		if (!s->is_segment) {
			count++;
		}
	}

	return list;
}

const RVecSection *MACH0_(load_sections)(struct MACH0_(obj_t) * mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);
	if (mo->sections_loaded) {
		return &mo->sections_cache;
	}

	mo->sections_loaded = true;
	RVecSection_init (&mo->sections_cache);

	char sectname[64];
	char raw_segname[17];
	size_t i, j, to;
	struct MACH0_(segment_command) * seg;

	/* for core files */
	if (mo->nsects < 1 && mo->nsegs > 0) {
		if (!RVecSection_reserve (&mo->sections_cache, mo->nsegs)) {
			return NULL;
		}
		for (i = 0; i < mo->nsegs; i++) {
			struct section_t *section = RVecSection_emplace_back (&mo->sections_cache);
			seg = &mo->segs[i];
			section->vaddr = seg->vmaddr;
			section->paddr = seg->fileoff;
			section->size = seg->vmsize;
			section->vsize = seg->vmsize;
			section->align = 4096;
			section->flags = seg->flags;
			r_str_ncpy (sectname, seg->segname, 16);
			sectname[16] = 0;
			r_str_filter (sectname, -1);
			// hack to support multiple sections with same name
			section->perm = prot2perm (seg->initprot);
		}
		return &mo->sections_cache;
	}

	if (!mo->sects) {
		return NULL;
	}
	to = R_MIN (mo->nsects, MACHO_MAX_SECTIONS);
	if (to < 1) {
		return NULL;
	}
	if (!RVecSection_reserve (&mo->sections_cache, to)) {
		return NULL;
	}
	for (i = 0; i < to; i++) {
		struct section_t *section = RVecSection_emplace_back (&mo->sections_cache);
		struct MACH0_(section) *sect = &mo->sects[i];
		section->paddr = (ut64)sect->offset;
		section->vaddr = (ut64)sect->addr;
		section->size = (sect->flags == S_ZEROFILL)? 0: (ut64)sect->size;
		section->vsize = (ut64)sect->size;
		section->align = sect->align;
		section->flags = sect->flags;
		r_str_ncpy (sectname, sect->sectname, 17);
		r_str_filter (sectname, -1);
		r_str_ncpy (raw_segname, sect->segname, 17);
		r_str_filter (raw_segname, -1);
		for (j = 0; j < mo->nsegs; j++) {
			struct MACH0_(segment_command) *seg = &mo->segs[j];
			if (section->vaddr >= seg->vmaddr &&
				section->vaddr < (seg->vmaddr + seg->vmsize)) {
				section->perm = prot2perm (seg->initprot);
				break;
			}
		}
		snprintf (section->name, sizeof (section->name), "%d.%s.%s", (int)i, raw_segname, sectname);
	}
	return &mo->sections_cache;
}

static bool parse_import_stub(struct MACH0_(obj_t) * bin, struct symbol_t *symbol, int idx) {
	size_t i, j, nsyms, stridx;
	const char *symstr;
	if (idx < 0) {
		return false;
	}
	symbol->offset = 0LL;
	symbol->addr = 0LL;
	symbol->name = NULL;
	symbol->is_imported = true;

	if (!bin || !bin->sects) {
		return false;
	}
	if (!bin->indirectsyms || bin->nindirectsyms <= 0) {
		return false;
	}
	if (!bin->symtab || bin->nsymtab <= 0) {
		return false;
	}
	for (i = 0; i < bin->nsects; i++) {
		struct MACH0_(section) *sect = &bin->sects[i];
		if ((sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS && sect->reserved2 > 0) {
			ut64 sect_size = sect->size;
			ut32 sect_fragment = sect->reserved2;
			if (sect->offset > bin->size) {
				R_LOG_DEBUG ("section offset starts way beyond the end of the file");
				continue;
			}
			if (sect_size > bin->size) {
				R_LOG_DEBUG ("Invalid symbol table size");
				sect_size = bin->size - sect->offset;
			}
			nsyms = (int) (sect_size / sect_fragment);
			for (j = 0; j < nsyms; j++) {
				if ((ut64)sect->reserved1 + j >= (ut64)bin->nindirectsyms) {
					continue;
				}
				if (idx != bin->indirectsyms[sect->reserved1 + j]) {
					continue;
				}
				if (idx >= bin->nsymtab) {
					continue;
				}
				symbol->type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				int delta = j * sect->reserved2;
				if (delta < 0) {
					R_LOG_DEBUG ("corrupted reserved2 value leads to int overflow");
					continue;
				}
				symbol->offset = sect->offset + delta;
				symbol->addr = sect->addr + delta;
				symbol->size = 0;
				stridx = bin->symtab[idx].n_strx;
				if (stridx < bin->symstrlen) {
					symstr = (char *)bin->symstr + stridx;
				} else {
					symstr = "???";
				}
				// Remove the extra underscore that every import seems to have in Mach-O.
				if (*symstr == '_') {
					symstr++;
				}
				symbol->name = strdup (symstr);
				return true;
			}
		}
	}
	return false;
}

static int hash_find_or_insert(HtPP *hash, const char *name, ut64 addr) {
	bool found = false;
	char *key = r_str_newf ("%" PFMT64x ".%s", addr, name);
	ht_pp_find (hash, key, &found);
	if (found) {
		free (key);
		return true;
	}
	ht_pp_insert (hash, key, "1");
	free (key);
	return false;
}

static char *get_name(struct MACH0_(obj_t) * mo, ut32 stridx, bool filter) {
	size_t i = 0;
	if (!mo->symstr || stridx >= mo->symstrlen) {
		return NULL;
	}
	int len = mo->symstrlen - stridx;
	const char *symstr = (const char *)mo->symstr + stridx;
	for (i = 0; i < len; i++) {
		if ((ut8) (symstr[i] & 0xff) == 0xff || !symstr[i]) {
			len = i;
			break;
		}
	}
	if (mo->maxsymlen > 0 && len > mo->maxsymlen) {
		return NULL;
	}
	if (len > 0) {
		char *res = r_str_ndup (symstr, len);
		if (filter) {
			r_str_filter (res, -1);
		}
		return res;
	}
	return NULL;
}

static int walk_exports_trie(struct MACH0_(obj_t) * bin, ut64 trie_off, ut64 size, RExportsIterator iterator, void *ctx) {
	size_t count = 0;
	ut8 *p = NULL;
	if (!size || size >= SIZE_MAX) {
		return 0;
	}
	if (trie_off == UT64_MAX) {
		R_LOG_WARN ("dyld export trie is out of bounds");
		return 0;
	}
	if (bin->size != UT64_MAX) {
		if (trie_off >= bin->size) {
			R_LOG_WARN ("dyld export trie is out of bounds");
			return 0;
		}
		ut64 trie_left = bin->size - trie_off;
		if (size > trie_left) {
			R_LOG_WARN ("dyld export trie is out of bounds");
			size = trie_left;
		}
	}
	ut8 *trie = calloc ((size_t)size + 1, 1);
	if (!trie) {
		return 0;
	}
	ut8 *end = trie + (size_t)size;
	if (r_buf_read_at (bin->b, trie_off, trie, size) != size) {
		return 0;
	}

	RList *states = r_list_newf ((RListFree)free);
	if (!states) {
		goto beach;
	}

	RTrieState *root = R_NEW0 (RTrieState);
	root->node = trie;
	root->i = 0;
	root->label = NULL;
	r_list_push (states, root);

	do {
		RTrieState *state = r_list_last (states);
		p = state->node;
		ut64 len = read_uleb128 (&p, end);
		if (len == UT64_MAX) {
			break;
		}
		if (len) {
			ut64 flags = read_uleb128 (&p, end);
			if (flags == UT64_MAX) {
				break;
			}
			ut64 offset = read_uleb128 (&p, end);
			if (offset == UT64_MAX) {
				break;
			}
			ut64 resolver = 0;
			bool isReexport = flags & EXPORT_SYMBOL_FLAGS_REEXPORT;
			bool hasResolver = flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER;
			if (hasResolver) {
				ut64 res = read_uleb128 (&p, end);
				if (res == UT64_MAX) {
					break;
				}
				resolver = res + bin->header_at;
			} else if (isReexport) {
				p += strlen ((char *)p) + 1;
				// TODO: handle this
			}
			if (!isReexport) {
				offset += bin->header_at;
			}
			if (iterator && !isReexport) {
				char *name = NULL;
				RListIter *iter;
				RTrieState *s;
				r_list_foreach (states, iter, s) {
					if (!s->label) {
						continue;
					}
					name = r_str_append (name, s->label);
				}
				if (!name) {
					R_LOG_DEBUG ("malformed export trie3");
					goto beach;
				}
				if (hasResolver) {
					char *stub_name = r_str_newf ("stub.%s", name);
					iterator (bin, stub_name, flags, offset, ctx);
					iterator (bin, name, flags, resolver, ctx);
					R_FREE (stub_name);
				} else {
					iterator (bin, name, flags, offset, ctx);
				}
				R_FREE (name);
			}
			if (!isReexport) {
				if (hasResolver) {
					count++;
				}
				count++;
			}
		}
		ut64 child_count = read_uleb128 (&p, end);
		if (child_count == UT64_MAX) {
			goto beach;
		}
		if (state->i == child_count) {
			free (r_list_pop (states));
			continue;
		}
		if (state->next_child) {
			p = state->next_child;
		} else {
			state->next_child = p;
		}
		RTrieState *next = R_NEW0 (RTrieState);
		next->label = (char *)p;
		p += strlen (next->label) + 1;
		if (p >= end) {
			R_LOG_DEBUG ("malformed export trie");
			R_FREE (next);
			goto beach;
		}
		ut64 tr = read_uleb128 (&p, end);
		if (tr == UT64_MAX || tr >= size) {
			R_FREE (next);
			goto beach;
		}
		next->node = trie + (size_t)tr;
		if (next->node >= end) {
			R_LOG_DEBUG ("malformed export trie2");
			R_FREE (next);
			goto beach;
		}
		{
			// avoid loops
			RListIter *it;
			RTrieState *s;
			r_list_foreach (states, it, s) {
				if (s->node == next->node) {
					R_LOG_WARN ("malformed export trie %d", __LINE__);
					R_FREE (next);
					goto beach;
				}
			}
		}
		next->i = 0;
		state->i++;
		state->next_child = p;
		r_list_push (states, next);
	} while (r_list_length (states));

beach:
	r_list_free (states);
	R_FREE (trie);
	return count;
}

static int walk_exports(struct MACH0_(obj_t) * bin, RExportsIterator iterator, void *ctx) {
	R_RETURN_VAL_IF_FAIL (bin, 0);
	size_t count = 0;
	if (bin->dyld_info) {
		count += walk_exports_trie (bin, bin->dyld_info->export_off, bin->dyld_info->export_size, iterator, ctx);
	}
	if (bin->exports_trie_off && bin->exports_trie_size) {
		count += walk_exports_trie (bin, bin->exports_trie_off, bin->exports_trie_size, iterator, ctx);
	}
	return count;
}

static void _update_main_addr_if_needed(struct MACH0_(obj_t) * mo, const RBinSymbol *sym) {
	if (!mo->main_addr || mo->main_addr == UT64_MAX) {
		const char *name = r_bin_name_tostring2 (sym->name, 'o');
		if (!strcmp (name, "__Dmain")) {
			mo->main_addr = sym->vaddr;
		} else if (strstr (name, "4main") && !strstr (name, "STATIC")) {
			mo->main_addr = sym->vaddr;
		} else if (!strcmp (name, "_main")) {
			mo->main_addr = sym->vaddr;
		} else if (!strcmp (name, "main")) {
			mo->main_addr = sym->vaddr;
		}
	}
}

static void _handle_arm_thumb(RBinSymbol *sym) {
	if (sym->vaddr & 1) {
		sym->vaddr--;
		sym->bits = 16;
	}
	if (sym->paddr & 1) {
		sym->paddr--;
		sym->bits = 16;
	}
}

static void _enrich_symbol(RBinFile *bf, struct MACH0_(obj_t) * bin, HtPP *symcache, RBinSymbol *sym) {
	int wordsize = MACH0_(get_bits) (bin);

	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	if (oname) {
		bin->dbg_info = r_str_startswith (oname, "radr://");
		if (*oname == '_' && !sym->is_imported) {
			char *demangled = r_bin_demangle (bf, oname, oname, sym->vaddr, false);
			if (demangled) {
				r_bin_name_demangled (sym->name, demangled);
				// swift demangled names follow Module.Type.member pattern
				char *p = strchr (demangled, '.');
				if (p) {
					char *p2 = strchr (p + 1, '.');
					if (p2 && isupper (*demangled) && isupper (p[1])) {
						// Module.Class.method - use Module.Class
						sym->classname = r_str_ndup (demangled, p2 - demangled);
					} else if (isupper (*demangled)) {
						sym->classname = r_str_ndup (demangled, (p - demangled));
					} else if (isupper (p[1])) {
						sym->classname = strdup (p + 1);
						p = strchr (sym->classname, '.');
						if (p) {
							*p = 0;
						}
					}
				}
			}
		}
	}

	sym->forwarder = "NONE";
	sym->bind = sym->type && r_str_startswith (sym->type, "LOCAL")? R_BIN_BIND_LOCAL_STR: R_BIN_BIND_GLOBAL_STR;
	sym->type = R_BIN_TYPE_FUNC_STR;

	if (bin->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
		_handle_arm_thumb (sym);
	}

	r_strf_var (k, 32, "sym0x%" PFMT64x, sym->vaddr);
	ht_pp_insert (symcache, k, "found");
}

typedef struct fill_context_t {
	RBinFile *bf;
	HtPP *symcache;
	HtPP *hash;
	ut64 boffset;
	ut32 *ordinal;
} FillCtx;

static bool apple_symbol(const char *sym_name);

static const char *normalized_visibility_name(const char *name) {
	while (name && *name == '_') {
		name++;
	}
	return name;
}

static bool is_suspicious_library_export(const char *name) {
	name = normalized_visibility_name (name);
	return R_STR_ISNOTEMPTY (name) && (!strcmp (name, "main") ||
		r_str_casestr (name, "hidden") || r_str_casestr (name, "helper"));
}

static bool has_nonruntime_public_symbols(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, false);
	const bool executable_like = mo->hdr.filetype == MH_EXECUTE ||
		mo->hdr.filetype == MH_BUNDLE || mo->hdr.filetype == MH_KEXT_BUNDLE;
	const bool dylib_like = mo->hdr.filetype == MH_DYLIB;
	if (!executable_like && !dylib_like) {
		return false;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (mo->symbols_vec, sym) {
		const char *name = r_bin_name_tostring2 (sym->name, 'o');
		if (!name || !*name || sym->is_imported) {
			continue;
		}
		if (strcmp (sym->bind, R_BIN_BIND_GLOBAL_STR)) {
			continue;
		}
		if (executable_like && !apple_symbol (name)) {
			return true;
		}
		if (dylib_like && is_suspicious_library_export (name)) {
			return true;
		}
	}
	return false;
}

static void _fill_exports(struct MACH0_(obj_t) * mo, const char *name, ut64 flags, ut64 offset, void *ctx) {
	FillCtx *context = ctx;
	ut64 vaddr = offset_to_vaddr (mo, offset);
	if (hash_find_or_insert (context->hash, name, vaddr)) {
		return;
	}

	RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
	memset (sym, 0, sizeof (RBinSymbol));
	sym->vaddr = vaddr;
	sym->paddr = offset + context->boffset;
	sym->type = "EXT";
	sym->name = r_bin_name_new (name);
	sym->bind = R_BIN_BIND_GLOBAL_STR;
	sym->ordinal = (*context->ordinal)++;
	_enrich_symbol (context->bf, mo, context->symcache, sym);
}

static bool apple_symbol(const char *sym_name) {
	if (r_str_startswith (sym_name, "radr://")) {
		return true;
	}
	if (!strcmp (sym_name, "__mh_execute_header")) {
		return true;
	}
	if (!strcmp (sym_name, "start") || !strcmp (sym_name, "_NXArgc") ||
		!strcmp (sym_name, "_NXArgv") || !strcmp (sym_name, "___progname") ||
		!strcmp (sym_name, "_environ")) {
		return true;
	}
	return false;
}

#define WALK_THE_UNDEFINED 0
static bool dysym_bounds(struct MACH0_(obj_t) * mo, size_t s, ut64 *f, ut64 *t) {
	ut32 from = 0;
	ut32 to = 0;
	struct dysymtab_command *ds = &mo->dysymtab;
	switch (s) {
	case 0:
		from = ds->iextdefsym;
		to = from + ds->nextdefsym;
		break;
	case 1:
		from = ds->ilocalsym;
		to = from + ds->nlocalsym;
		break;
#if WALK_THE_UNDEFINED
	case 2:
		from = ds->iundefsym;
		to = from + ds->nundefsym;
		break;
#endif
	default:
		return false;
	}
	if (from >= to) {
		return false;
	}
	*f = R_MIN (from, (ut64)mo->nsymtab);
	*t = R_MIN (to, (ut64)mo->nsymtab);
	return *f < *t;
}

static inline bool exceeds_bin_limit(int limit, ut64 value) {
	return limit > 0 && value > (ut64)limit;
}

static int clamp_count(ut64 count, int limit) {
	if (count > ST32_MAX) {
		return 0;
	}
	if (exceeds_bin_limit (limit, count)) {
		return limit;
	}
	return (int)count;
}

static void parse_symbols(RBinFile *bf, struct MACH0_(obj_t) * mo, HtPP *symcache) {
	size_t i, j, s, symbols_size, symbols_count;
	ut64 to = UT64_MAX;
	ut64 from = UT64_MAX;
	ut32 ordinal = 0;

	RBinObject *obj = bf? bf->bo: NULL;
	if (!obj) {
		return;
	}

	HtPP *hash = ht_pp_new0 ();

	FillCtx fill_context = {
		.bf = bf,
		.symcache = symcache,
		.hash = hash,
		.boffset = obj->boffset,
		.ordinal = &ordinal,
	};
	walk_exports (mo, _fill_exports, &fill_context);

	if (!mo->symtab || !mo->symstr) {
		ht_pp_free (hash);
		return;
	}
	// Mach-O string tables are NUL-separated blobs, not a single C string.
	const bool has_redacted = mo->symstrlen > 0
		&& r_mem_mem (mo->symstr, mo->symstrlen, (const ut8 *)"<redacted>", sizeof ("<redacted>") - 1) != NULL;
	/* parse dynamic symbol table */
	struct dysymtab_command *ds = &mo->dysymtab;
	symbols_count = ds->nextdefsym + ds->nlocalsym + ds->nundefsym + mo->nsymtab;
	if (symbols_count == 0) {
		ht_pp_free (hash);
		return;
	}

	if (r_mul_overflow (symbols_count, 2 * sizeof (RBinSymbol), &symbols_size)) {
		ht_pp_free (hash);
		return;
	}
	j = 0; // symbol_idx
	mo->main_addr = UT64_MAX;
	int bits = MACH0_(get_bits_from_hdr) (&mo->hdr);
	bool is_stripped = true;
	const int limit = bf->rbin->options.limit;
	for (s = 0; s < 2; s++) {
		if (!dysym_bounds (mo, s, &from, &to)) {
			continue;
		}
		ut32 maxsymbols = symbols_size / sizeof (RBinSymbol);
		if (maxsymbols == 0 || symbols_count >= maxsymbols) {
			symbols_count = maxsymbols == 0 ? 0 : maxsymbols - 1;
			R_LOG_WARN ("Truncated symbol table");
		}

		for (i = from; i < to && j < symbols_count; i++) {
			struct MACH0_(nlist) *nl = &mo->symtab[i];
			ut64 vaddr = nl->n_value;
			if (vaddr < 100) {
				continue;
			}
			int stridx = nl->n_strx;
			char *sym_name = get_name (mo, stridx, false);
			if (!sym_name) {
				continue;
			}

			if ((has_redacted && strstr (sym_name, "<redacted>")) || hash_find_or_insert (hash, sym_name, vaddr)) {
				free (sym_name);
			} else {
				RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
				memset (sym, 0, sizeof (RBinSymbol));
				sym->vaddr = vaddr;
				sym->paddr = addr_to_offset (mo, sym->vaddr) + obj->boffset;
				sym->size = 0; /* TODO: Is it anywhere? */
				sym->bits = nl->n_desc & N_ARM_THUMB_DEF? 16: bits;
				sym->is_imported = false;
				sym->type = nl->n_type & N_EXT? "EXT": "LOCAL";
				sym->name = r_bin_name_new (sym_name);
				if (is_stripped && !apple_symbol (sym_name)) {
					is_stripped = false;
				}
				R_FREE (sym_name);
				sym->ordinal = ordinal++;
				_update_main_addr_if_needed (mo, sym);
				_enrich_symbol (bf, mo, symcache, sym);
				j++;
				if (exceeds_bin_limit (limit, ordinal)) {
					R_LOG_WARN ("symbols mo.limit reached");
					break;
				}
			}
		}
	}

	to = R_MIN ((ut32)mo->nsymtab, ds->iundefsym + ds->nundefsym);
	for (i = ds->iundefsym; i < to; i++) {
		struct symbol_t symbol;
		if (j > symbols_count) {
			R_LOG_WARN ("mach0-get-symbols: error");
			break;
		}

		if (parse_import_stub (mo, &symbol, i) && symbol.addr >= 100) {
			if (symbol.name && strstr (symbol.name, "<redacted>")) {
				free (symbol.name);
				continue;
			}
			j++;
			RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
			memset (sym, 0, sizeof (RBinSymbol));
			sym->lang = R_BIN_LANG_C;
			sym->vaddr = symbol.addr;
			sym->paddr = symbol.offset + obj->boffset;
			if (symbol.name) {
				// imports cant affect the strip state
				sym->name = r_bin_name_new (symbol.name);
			} else {
				char *name = r_str_newf ("entry%u", (ut32)i);
				sym->name = r_bin_name_new (name);
				free (name);
			}
			sym->type = symbol.type == R_BIN_MACH0_SYMBOL_TYPE_LOCAL? "LOCAL": "EXT";
			sym->is_imported = symbol.is_imported;
			sym->ordinal = ordinal++;
			_enrich_symbol (bf, mo, symcache, sym);
			free (symbol.name);
		}
	}

	for (i = 0; i < mo->nsymtab && i < symbols_count; i++) {
		struct MACH0_(nlist) *st = &mo->symtab[i];
		if (st->n_type & N_STAB) {
			continue;
		}
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
		int section = st->n_sect;
		if (section == 1 && j < symbols_count) { // text?? st->n_type == 1) maybe wrong
			ut64 vaddr = st->n_value;
			if (vaddr < 100) {
				continue;
			}
			char *sym_name = get_name (mo, st->n_strx, false);
			if (sym_name) {
				if (strstr (sym_name, "<redacted>")) {
					free (sym_name);
					continue;
				}
			} else {
				sym_name = r_str_newf ("entry%u", (ut32)i);
			}
			if (is_stripped && !apple_symbol (sym_name)) {
				is_stripped = false;
			}
			if (hash_find_or_insert (hash, sym_name, vaddr)) {
				free (sym_name);
				continue;
			}
			if (exceeds_bin_limit (limit, ordinal)) {
				R_LOG_WARN ("funcstart count reached bin.limit");
				free (sym_name);
				break;
			}
			RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
			if (R_UNLIKELY (!sym)) {
				free (sym_name);
				break;
			}
			memset (sym, 0, sizeof (RBinSymbol));
			sym->name = r_bin_name_new_from (sym_name);
			sym->vaddr = vaddr;
			sym->paddr = addr_to_offset (mo, vaddr) + obj->boffset;
			sym->type = (st->n_type & N_EXT)? "EXT": "LOCAL";
			sym->ordinal = ordinal++;

			_update_main_addr_if_needed (mo, sym);
			_enrich_symbol (bf, mo, symcache, sym);
			j++;
		}
	}
	if (is_stripped) {
		mo->dbg_info |= R_BIN_DBG_STRIPPED;
	}

	ht_pp_free (hash);
}

static bool parse_function_start_symbols(RBinFile *bf, struct MACH0_(obj_t) * mo, HtPP *symcache) {
	RBinObject *obj = bf? bf->bo: NULL;
	if (!obj) {
		return false;
	}
	if (mo->nofuncstarts) {
		return mo->dbg_info & R_BIN_DBG_STRIPPED;
	}

	int wordsize = MACH0_(get_bits) (mo);
	ut32 i = RVecRBinSymbol_length (mo->symbols_vec);

	// functions from LC_FUNCTION_STARTS
	bool is_stripped = false;
	if (!mo->func_start) {
		return true;
	}
	const int limit = bf->rbin->options.limit;
	char symstr[128];
	ut64 value = 0, address = 0;
	const ut8 *temp = mo->func_start;
	const ut8 *temp_end = mo->func_start + mo->func_size;
	strcpy (symstr, "sym0x");
	while (temp + 3 < temp_end && *temp) {
		temp = r_uleb128_decode (temp, NULL, &value);
		address += value;
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
		// probably not necessary if we fill all the fields below, just in case.. but maybe we can have another rvec method for this
		memset (sym, 0, sizeof (RBinSymbol));
		sym->vaddr = mo->baddr + address;
		sym->paddr = address + obj->boffset;
		sym->size = 0;
		char *n = r_str_newf ("func.%08" PFMT64x, sym->vaddr);
		sym->name = r_bin_name_new (n);
		free (n);
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->forwarder = "NONE";
		sym->bind = R_BIN_BIND_LOCAL_STR;
		sym->ordinal = i++;
		if (mo->hdr.cputype == CPU_TYPE_ARM && wordsize < 64) {
			_handle_arm_thumb (sym);
		}
		// if any func is not found in syms then we consider it to be stripped
		// XXX this is slow. we can check with addr ht/set
		if (!is_stripped) {
			snprintf (symstr + 5, sizeof (symstr) - 5, "%" PFMT64x, sym->vaddr);
			bool found = false;
			ht_pp_find (symcache, symstr, &found);
			if (!found) {
				is_stripped = true;
			}
		}
		if (exceeds_bin_limit (limit, sym->ordinal)) {
			R_LOG_WARN ("funcstart mo.limit reached");
			break;
		}
	}
	if (is_stripped) {
		mo->dbg_info |= R_BIN_DBG_STRIPPED;
	} else if (mo->dbg_info & R_BIN_DBG_STRIPPED) {
		mo->dbg_info &= ~R_BIN_DBG_STRIPPED;
		// R_BIT_UNSET (mo->dbg_info, R_BIN_DBG_STRIPPED);
	}
	return mo->dbg_info & ~R_BIN_DBG_STRIPPED;
}

#if 0
// R2_612
static inline bool is_debug_segment(const RBinSection *s, const void *user) {
	return strstr (s->name, "DWARF.__debug_line") != NULL;
}

static inline bool is_debug_build(RBinFile *bf, struct MACH0_(obj_t) *mo) {
	return RVecSegment_find (mo->segments_vec, NULL, is_debug_segment) != NULL;
}
#else
static bool is_debug_build(RBinFile *bf, struct MACH0_(obj_t) * mo) {
	RList *sections = MACH0_(get_segments) (bf, mo);
	if (!sections) {
		return false;
	}

	bool res = false;
	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (strstr (section->name, ".__debug_line")) {
			res = true;
			break;
		}
	}
	r_list_free (sections);
	return res;
}
#endif

const bool MACH0_(load_symbols)(struct MACH0_(obj_t) * mo) {
	R_RETURN_VAL_IF_FAIL (mo, false);
	if (mo->symbols_loaded) {
		return true;
	}
	// Skip symbol loading for companion debug files (dSYM)
	RBinFile *bf = mo->options.bf;
	if (bf && bf->rbin && bf->rbin->options.skip_symbols) {
		mo->symbols_loaded = true;
		return true;
	}

	mo->symbols_loaded = true;
	HtPP *symcache = ht_pp_new0 ();
	if (R_LIKELY (symcache)) {
		parse_symbols (bf, mo, symcache);
		if (mo->parse_start_symbols) {
			bool is_stripped = parse_function_start_symbols (bf, mo, symcache);
			if (is_stripped) {
				mo->dbg_info |= R_BIN_DBG_STRIPPED;
			}
		}
		ht_pp_free (symcache);
	}
	if (has_nonruntime_public_symbols (mo)) {
		mo->dbg_info |= R_BIN_DBG_UNCAPS;
	} else {
		mo->dbg_info &= ~R_BIN_DBG_UNCAPS;
	}

	if (is_debug_build (mo->options.bf, mo)) {
		mo->dbg_info |= R_BIN_DBG_LINENUMS;
		mo->dbg_info &= ~R_BIN_DBG_STRIPPED;
	}
	return !RVecRBinSymbol_empty (mo->symbols_vec);
}

static inline ut8 relfrom_wordsize(size_t ws) {
	if (ws == 1 || ws == 2 || ws == 4 || ws == 8) {
		return ws * 8;
	}
	return 0;
}

static struct reloc_t *parse_import_ptr(struct MACH0_(obj_t) * mo, int jota) {
	int idx = mo->dysymtab.iundefsym + jota;
	int i, j, sym;
	if (idx < 0 || idx >= mo->nsymtab) {
		return NULL;
	}
	const size_t wordsize = get_word_size (mo);
	const ut32 stype = ((mo->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY)
		? S_LAZY_SYMBOL_POINTERS
		: S_NON_LAZY_SYMBOL_POINTERS;

	int type = relfrom_wordsize (wordsize);
	if (!type) {
		return NULL;
	}
	struct reloc_t *reloc = R_NEW0 (struct reloc_t);
	reloc->addr = 0;
	reloc->type = type;
	reloc->offset = 0;
	reloc->addend = 0;
	reloc->ntype = stype;
	for (i = 0; i < mo->nsects; i++) {
		struct MACH0_(section) *sect = &mo->sects[i];
		if ((sect->flags & SECTION_TYPE) == stype) {
			for (j = 0, sym = -1; sect->reserved1 + j < mo->nindirectsyms; j++) {
				int indidx = sect->reserved1 + j;
				if (indidx < 0 || indidx >= mo->nindirectsyms) {
					break;
				}
				if (idx == mo->indirectsyms[indidx]) {
					sym = j;
					break;
				}
			}
			reloc->offset = sym == -1? 0: sect->offset + sym * wordsize;
			reloc->addr = sym == -1? 0: sect->addr + sym * wordsize;
			return reloc;
		}
	}
	free (reloc);
	return NULL;
}

static void fill_import(RBin *rbin, const char *orig_name, RBinImport *imp) {
	memset (imp, 0, sizeof (RBinImport));
	char *name = (char *)orig_name;
	const char _objc_class[] = "_OBJC_CLASS_$";
	const char _objc_metaclass[] = "_OBJC_METACLASS_$";
	const char *type;

	if (r_str_startswith (name, _objc_class)) {
		name += strlen (_objc_class);
		type = "OBJC_CLASS";
	} else if (r_str_startswith (name, _objc_metaclass)) {
		name += strlen (_objc_metaclass);
		type = "OBJC_METACLASS";
	} else {
		type = "FUNC";
	}

	// Remove the extra underscore that every import seems to have in Mach-O.
	if (*name == '_') {
		name++;
	}
	char *s = r_str_ndup (name, R_BIN_MACH0_STRING_LENGTH - 1);
	imp->name = r_bin_name_new (s);
	free (s);
	imp->bind = "NONE";
	imp->type = r_str_constpool_get (&rbin->constpool, type);
}

static void check_for_special_import_names(struct MACH0_(obj_t) * bin, RBinImport *import) {
	const char *name = r_bin_name_tostring (import->name);
	if (*name == '_') {
		if (name[1] == '_') {
			if (!strcmp (name, "__stack_chk_fail")) {
				bin->has_canary = true;
			} else if (!strcmp (name, "__asan_init") || !strcmp (name, "__tsan_init")) {
				bin->has_sanitizers = true;
			}
		} else if (!strcmp (name, "_NSConcreteGlobalBlock")) {
			bin->has_blocks_ext = true;
		}
	}
}

RVecRBinImport *MACH0_(load_imports)(RBinFile *bf, struct MACH0_(obj_t) * bin) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	if (bin->imports_loaded) {
		return &bin->imports_cache;
	}

	bin->imports_loaded = true;
	RVecRBinImport_init (&bin->imports_cache);

	ut32 nundefsym = bin->dysymtab.nundefsym;
	if (nundefsym < 1 || nundefsym > 0xfffff) {
		return NULL;
	}

	if (!bin->sects || !bin->symtab || !bin->symstr || !bin->indirectsyms) {
		return NULL;
	}

	const int limit = bf->rbin->options.limit;
	const int amount = clamp_count (nundefsym, limit);
	if (!RVecRBinImport_reserve (&bin->imports_cache, amount)) {
		return NULL;
	}
	bin->has_canary = false;
	bin->has_retguard = -1;
	bin->has_sanitizers = false;
	bin->has_blocks_ext = false;

	int i;
	for (i = 0; i < amount; i++) {
		int idx = bin->dysymtab.iundefsym + i;
		if (idx < 0 || idx >= bin->nsymtab) {
			R_LOG_WARN ("Imports index out of bounds. Ignoring relocs");
			return NULL;
		}

		int stridx = bin->symtab[idx].n_strx;
		char *imp_name = get_name (bin, stridx, false);
		if (!imp_name) {
			continue;
		}

		RBinImport *imp = RVecRBinImport_emplace_back (&bin->imports_cache);
		if (!imp) {
			free (imp_name);
			break;
		}
		fill_import (bf->rbin, imp_name, imp);
		imp->ordinal = i;
		check_for_special_import_names (bin, imp);
		free (imp_name);
	}

	return &bin->imports_cache;
}

static int reloc_comparator(struct reloc_t *a, struct reloc_t *b) {
	if (a->addr < b->addr) {
		return -1;
	}
	if (a->addr > b->addr) {
		return 1;
	}
	return 0;
}

static void parse_relocation_info(struct MACH0_(obj_t) * mo, RSkipList *relocs, ut32 offset, ut32 num) {
	if (!num || !offset || (st32)num < 0) {
		return;
	}

	ut64 total_size = (ut64)num * sizeof (struct relocation_info);
	if (offset > mo->size) {
		return;
	}
	if (total_size > mo->size) {
		total_size = mo->size - offset;
		num = total_size / sizeof (struct relocation_info);
	}
	const int amount = clamp_count (num, mo->limit);
	if (amount < 1) {
		return;
	}
	total_size = (ut64)amount * sizeof (struct relocation_info);
	struct relocation_info *info = calloc (amount, sizeof (struct relocation_info));
	if (!info) {
		return;
	}

	if (r_buf_read_at (mo->b, offset, (ut8 *)info, total_size) < total_size) {
		free (info);
		return;
	}

	size_t i;
	for (i = 0; i < amount; i++) {
		struct relocation_info a_info = info[i];
		ut32 sym_num = a_info.r_symbolnum;
		if (sym_num >= mo->nsymtab) {
			continue;
		}

		ut32 stridx = mo->symtab[sym_num].n_strx;
		char *sym_name = get_name (mo, stridx, false);
		if (!sym_name) {
			continue;
		}

		struct reloc_t *reloc = R_NEW0 (struct reloc_t);
		reloc->addr = offset_to_vaddr (mo, a_info.r_address);
		reloc->offset = a_info.r_address;
		reloc->ord = sym_num;
		reloc->type = a_info.r_type; // enum RelocationInfoType
		reloc->external = a_info.r_extern;
		reloc->pc_relative = a_info.r_pcrel;
		reloc->size = a_info.r_length;
		r_str_ncpy (reloc->name, sym_name, sizeof (reloc->name) - 1);
		r_skiplist_insert (relocs, reloc);
		free (sym_name);
	}
	free (info);
}

static bool walk_bind_chains_callback(void *context, RFixupEventDetails *ed) {
	RWalkBindChainsContext *ctx = context;
	ut8 *imports = ctx->imports;
	struct MACH0_(obj_t) *mo = ed->bin;
	struct dyld_chained_fixups_header *fh = &mo->fixups_header;
	ut32 imports_count = fh->imports_count;
	ut32 fixups_offset = mo->fixups_offset;
	ut32 fixups_size = mo->fixups_size;
	ut32 imports_format = fh->imports_format;
	ut32 import_index = ed->ordinal;
	ut64 addend = 0;
	if (ed->type != R_FIXUP_EVENT_BIND_AUTH) {
		addend = ed->addend;
	}
	const int limit = mo->limit;
	if (exceeds_bin_limit (limit, import_index)) {
		return false;
	}
	if (import_index < imports_count) {
		ut64 name_offset;
		switch (imports_format) {
		case DYLD_CHAINED_IMPORT:
			{
				struct dyld_chained_import *item = &((struct dyld_chained_import *)imports)[import_index];
				name_offset = item->name_offset;
				break;
			}
		case DYLD_CHAINED_IMPORT_ADDEND:
			{
				struct dyld_chained_import_addend *item = &((struct dyld_chained_import_addend *)imports)[import_index];
				name_offset = item->name_offset;
				addend += item->addend;
				break;
			}
		case DYLD_CHAINED_IMPORT_ADDEND64:
			{
				struct dyld_chained_import_addend64 *item = &((struct dyld_chained_import_addend64 *)imports)[import_index];
				name_offset = item->name_offset;
				addend += item->addend;
				break;
			}
		default:
			R_LOG_WARN ("Unsupported imports format");
			return false;
		}

		ut64 symbols_offset = fh->symbols_offset + fixups_offset;

		if (symbols_offset + name_offset + 1 < fixups_offset + fixups_size) {
			char *name = r_buf_get_string (mo->b, symbols_offset + name_offset);
			if (name) {
				struct reloc_t *reloc = R_NEW0 (struct reloc_t);
				reloc->addr = offset_to_vaddr (mo, ed->offset);
				reloc->offset = ed->offset;
				reloc->ord = import_index;
				reloc->type = R_BIN_RELOC_64;
				reloc->size = 8;
				reloc->addend = addend;
				r_str_ncpy (reloc->name, name, sizeof (reloc->name) - 1);
				r_skiplist_insert_autofree (ctx->relocs, reloc);
				free (name);
			} else if (mo->verbose) {
				R_LOG_WARN ("Malformed chained bind: failed to read name");
			}
		} else if (mo->verbose) {
			R_LOG_WARN ("Malformed chained bind: name_offset out of bounds");
		}
	} else if (mo->verbose) {
		R_LOG_WARN ("Malformed chained bind: import out of length");
	}

	return true;
}

static void walk_bind_chains(struct MACH0_(obj_t) * mo, RSkipList *relocs) {
	R_RETURN_IF_FAIL (mo && mo->fixups_offset);

	ut8 *imports = NULL;

	struct dyld_chained_fixups_header *fh = &mo->fixups_header;
	ut32 imports_count = fh->imports_count;
	ut32 fixups_offset = mo->fixups_offset;
	ut32 imports_offset = fh->imports_offset;
	if (!imports_count || !imports_offset) {
		return;
	}
	if (fh->symbols_format != 0) {
		R_LOG_INFO ("Compressed fixups symbols not supported yet, please file a bug with a sample attached");
		return;
	}

	ut32 imports_format = fh->imports_format;
	ut64 imports_size;
	switch (imports_format) {
	case DYLD_CHAINED_IMPORT:
		imports_size = sizeof (struct dyld_chained_import) * imports_count;
		break;
	case DYLD_CHAINED_IMPORT_ADDEND:
		imports_size = sizeof (struct dyld_chained_import_addend) * imports_count;
		break;
	case DYLD_CHAINED_IMPORT_ADDEND64:
		imports_size = sizeof (struct dyld_chained_import_addend64) * imports_count;
		break;
	default:
		R_LOG_WARN ("Unsupported chained imports format: %d", imports_format);
		goto beach;
	}

	imports = malloc (imports_size);
	if (!imports) {
		goto beach;
	}

	switch (imports_format) {
	case DYLD_CHAINED_IMPORT:
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset, imports, "i", imports_count) != imports_size) {
			goto beach;
		}
		break;
	case DYLD_CHAINED_IMPORT_ADDEND:
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset, imports, "ii", imports_count) != imports_size) {
			goto beach;
		}
		break;
	case DYLD_CHAINED_IMPORT_ADDEND64:
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset, imports, "il", imports_count) != imports_size) {
			goto beach;
		}
		break;
	}

	RWalkBindChainsContext ctx;
	ctx.imports = imports;
	ctx.relocs = relocs;

	MACH0_(iterate_chained_fixups) (mo, 0, UT64_MAX, R_FIXUP_EVENT_MASK_BIND_ALL, &walk_bind_chains_callback, &ctx);

beach:
	free (imports);
}

static bool is_valid_ordinal_table_size(ut64 size) {
	return size > 0 && size <= UT16_MAX;
}

static void mach0_reloc_ref_fini(struct reloc_t **reloc) {
	free (*reloc);
}

R_VEC_TYPE_WITH_FINI(RVecRelocRef, struct reloc_t *, mach0_reloc_ref_fini);

static RVecRelocRef *reloc_ref_vec_new_with_len(ut64 length) {
	RVecRelocRef *vec = RVecRelocRef_new ();
	if (!vec) {
		return NULL;
	}
	if (!RVecRelocRef_reserve (vec, length)) {
		RVecRelocRef_free (vec);
		return NULL;
	}
	struct reloc_t *empty = NULL;
	while (RVecRelocRef_length (vec) < length) {
		RVecRelocRef_push_back (vec, &empty);
	}
	return vec;
}

typedef struct {
	ut8 type;
	int lib_ord;
	int seg_idx;
	int sym_ord;
	char *sym_name;
	st64 addend;
	ut64 addr;
	ut64 segment_end_addr;
	bool done;
	bool stop;
} RBindOpState;

static HtPP *build_symbol_ordinal_cache(struct MACH0_(obj_t) * mo) {
	HtPP *cache = ht_pp_new0 ();
	struct dysymtab_command *ds = &mo->dysymtab;
	if (!mo->symtab || ds->nundefsym >= UT16_MAX) {
		return cache;
	}
	int iundefsym = ds->iundefsym;
	if (iundefsym < 0 || iundefsym >= mo->nsymtab) {
		return cache;
	}
	int j;
	for (j = 0; j < ds->nundefsym; j++) {
		int sidx = iundefsym + j;
		if (sidx < 0 || sidx >= mo->nsymtab) {
			continue;
		}
		size_t stridx = mo->symtab[sidx].n_strx;
		if (stridx >= mo->symstrlen) {
			continue;
		}
		const char *name = (const char *)mo->symstr + stridx;
		if (!ht_pp_find (cache, name, NULL)) {
			ht_pp_insert (cache, name, (void *) (size_t) (j + 1));
		}
	}
	return cache;
}

static bool stop_bind_parsing(RBindOpState *state) {
	state->done = true;
	state->stop = true;
	return true;
}

static void insert_bind_reloc(struct MACH0_(obj_t) * mo, RVecRelocRef *threaded_binds, RBindOpState *state, ut8 op, ut8 rel_type) {
	if (state->sym_ord < 0 && !state->sym_name) {
		return;
	}
	if (!threaded_binds) {
		if (state->seg_idx < 0) {
			return;
		}
		if (!state->addr) {
			return;
		}
	}
	struct reloc_t *reloc = R_NEW0 (struct reloc_t);
	reloc->addr = state->addr;
	if (state->seg_idx >= 0) {
		struct MACH0_(segment_command) *seg = &mo->segs[state->seg_idx];
		reloc->offset = state->addr - seg->vmaddr + seg->fileoff;
		reloc->addend = state->addend;
		if (state->type == BIND_TYPE_TEXT_PCREL32) {
			reloc->addend -= (mo->baddr + state->addr);
		}
	} else {
		reloc->addend = state->addend;
	}
	/* library ordinal??? */
	reloc->ntype = op;
	reloc->ord = state->sym_ord;
	reloc->type = rel_type;
	if (state->sym_name) {
		r_str_ncpy (reloc->name, state->sym_name, sizeof (reloc->name));
	}
	if (threaded_binds) {
		struct reloc_t **slot = RVecRelocRef_at (threaded_binds, state->sym_ord);
		if (slot) {
			free (*slot);
			*slot = reloc;
		} else {
			free (reloc);
		}
	} else {
		r_skiplist_insert_autofree (mo->relocs_cache, reloc);
	}
}

static void apply_threaded_bind(struct MACH0_(obj_t) * mo, RVecRelocRef *threaded_binds, RBindOpState *state, ut8 op, size_t wordsize) {
	if (!threaded_binds) {
		return;
	}
	int cur_seg_idx = (state->seg_idx != -1)? state->seg_idx: 0;
	struct MACH0_(segment_command) *cur_seg = &mo->segs[cur_seg_idx];
	ut64 n_threaded_binds = RVecRelocRef_length (threaded_binds);
	while (state->addr < state->segment_end_addr) {
		ut8 tmp[8];
		ut64 paddr = state->addr - cur_seg->vmaddr + cur_seg->fileoff;
		mo->rebasing_buffer = true;
		if (r_buf_read_at (mo->b, paddr, tmp, 8) != 8) {
			break;
		}
		mo->rebasing_buffer = false;
		ut64 raw_ptr = r_read_le64 (tmp);
		bool is_auth = (raw_ptr & (1ULL << 63)) != 0;
		bool is_bind = (raw_ptr & (1ULL << 62)) != 0;
		int ordinal = -1;
		int ptr_addend = -1;
		ut64 delta = 0;
		if (is_auth) {
			if (is_bind) {
				struct dyld_chained_ptr_arm64e_auth_bind *p =
					(struct dyld_chained_ptr_arm64e_auth_bind *)&raw_ptr;
				delta = p->next;
				ordinal = p->ordinal;
			} else {
				struct dyld_chained_ptr_arm64e_auth_rebase *p =
					(struct dyld_chained_ptr_arm64e_auth_rebase *)&raw_ptr;
				delta = p->next;
			}
		} else {
			if (is_bind) {
				struct dyld_chained_ptr_arm64e_bind *p =
					(struct dyld_chained_ptr_arm64e_bind *)&raw_ptr;
				delta = p->next;
				ordinal = p->ordinal;
				ptr_addend = p->addend;
			} else {
				struct dyld_chained_ptr_arm64e_rebase *p =
					(struct dyld_chained_ptr_arm64e_rebase *)&raw_ptr;
				delta = p->next;
			}
		}
		if (ordinal != -1) {
			if (ordinal >= n_threaded_binds) {
				R_LOG_DEBUG ("Malformed bind chain");
				break;
			}
			struct reloc_t **ref_slot = RVecRelocRef_at (threaded_binds, ordinal);
			struct reloc_t *ref = ref_slot? *ref_slot: NULL;
			if (!ref) {
				R_LOG_DEBUG ("Inconsistent bind opcodes");
				break;
			}
			struct reloc_t *reloc = R_NEW0 (struct reloc_t);
			*reloc = *ref;
			reloc->addr = state->addr;
			reloc->ntype = op;
			reloc->offset = paddr;
			if (ptr_addend != -1) {
				reloc->addend = ptr_addend;
			}
			r_skiplist_insert_autofree (mo->relocs_cache, reloc);
		}
		state->addr += delta * wordsize;
		if (!delta) {
			break;
		}
	}
}

static bool parse_bind_op_threaded(struct MACH0_(obj_t) * mo, RVecRelocRef **threaded_binds, RBindOpState *state, ut8 op, ut8 imm, size_t wordsize, ut8 **p, ut8 *end) {
	switch (imm) {
	case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
		{
			ut64 table_size = read_uleb128 (p, end);
			if (!is_valid_ordinal_table_size (table_size)) {
				R_LOG_DEBUG ("BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB size is wrong");
			} else {
				if (*threaded_binds) {
					RVecRelocRef_free (*threaded_binds);
				}
				*threaded_binds = reloc_ref_vec_new_with_len (table_size);
				if (*threaded_binds) {
					state->sym_ord = 0;
				}
			}
			return true;
		}
	case BIND_SUBOPCODE_THREADED_APPLY:
		apply_threaded_bind (mo, *threaded_binds, state, op, wordsize);
		return true;
	default:
		R_LOG_DEBUG ("Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x", imm);
		return true;
	}
}

static bool parse_bind_op_do_bind(struct MACH0_(obj_t) * mo, RVecRelocRef **threaded_binds, RBindOpState *state, ut8 op, ut8 imm, ut8 rel_type, size_t wordsize, ut8 **p, ut8 *end) {
	switch (op) {
	case BIND_OPCODE_DO_BIND:
		if (!*threaded_binds && state->addr >= state->segment_end_addr) {
			R_LOG_DEBUG ("Malformed DO bind opcode 0x%" PFMT64x, state->addr);
			return stop_bind_parsing (state);
		}
		insert_bind_reloc (mo, *threaded_binds, state, op, rel_type);
		if (!*threaded_binds) {
			state->addr += wordsize;
		} else {
			state->sym_ord++;
		}
		return true;
	case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
		if (state->addr >= state->segment_end_addr) {
			R_LOG_DEBUG ("Malformed ADDR ULEB bind opcode");
			return stop_bind_parsing (state);
		}
		insert_bind_reloc (mo, *threaded_binds, state, op, rel_type);
		state->addr += read_uleb128 (p, end) + wordsize;
		return true;
	case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
		if (state->addr >= state->segment_end_addr) {
			R_LOG_DEBUG ("Malformed IMM SCALED bind opcode");
			return stop_bind_parsing (state);
		}
		insert_bind_reloc (mo, *threaded_binds, state, op, rel_type);
		state->addr += (ut64)imm *(ut64)wordsize + wordsize;
		return true;
	case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
		{
			ut64 count = read_uleb128 (p, end);
			ut64 skip = read_uleb128 (p, end);
			ut64 increment;
			if (!UT64_ADD (&increment, skip, wordsize) || !bind_fits (count, state->addr, state->segment_end_addr, increment)) {
				R_LOG_DEBUG ("Count exceeds segment bounds");
				return stop_bind_parsing (state);
			}
			while (count--) {
				if (state->addr >= state->segment_end_addr) {
					R_LOG_DEBUG ("Malformed ULEB TIMES bind opcode");
					return stop_bind_parsing (state);
				}
				insert_bind_reloc (mo, *threaded_binds, state, op, rel_type);
				state->addr += skip + wordsize;
			}
			return true;
		}
	default:
		return false;
	}
}

static bool parse_bind_op(struct MACH0_(obj_t) * mo, RVecRelocRef **threaded_binds, HtPP *ord_cache, RBindOpState *state, ut8 rel_type, size_t wordsize, bool in_lazy_binds, ut8 **p, ut8 *end) {
	ut8 op = **p & BIND_OPCODE_MASK;
	ut8 imm = **p & BIND_IMMEDIATE_MASK;
	(*p)++;
	switch (op) {
	case BIND_OPCODE_DONE:
		if (!in_lazy_binds) {
			state->done = true;
		}
		return true;
	case BIND_OPCODE_THREADED:
		return parse_bind_op_threaded (mo, threaded_binds, state, op, imm, wordsize, p, end);
	case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
		state->lib_ord = imm;
		return true;
	case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
		state->lib_ord = read_uleb128 (p, end);
		return true;
	case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
		state->lib_ord = imm? (st8) (BIND_OPCODE_MASK | imm): 0;
		return true;
	case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
		state->sym_name = (char *)*p;
		while (*p < end && **p) {
			(*p)++;
		}
		if (*p < end) {
			(*p)++;
		}
		if (!*threaded_binds) {
			void *ord = ord_cache? ht_pp_find (ord_cache, state->sym_name, NULL): NULL;
			state->sym_ord = ord? (int) ((size_t)ord - 1): -1;
		}
		return true;
	case BIND_OPCODE_SET_TYPE_IMM:
		state->type = imm;
		return true;
	case BIND_OPCODE_SET_ADDEND_SLEB:
		state->addend = r_sleb128 ((const ut8 **)p, end);
		return true;
	case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
		state->seg_idx = imm;
		if (state->seg_idx >= mo->nsegs) {
			R_LOG_ERROR ("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has no segment %d", state->seg_idx);
			return false;
		}
		{
			struct MACH0_(segment_command) *seg = &mo->segs[state->seg_idx];
			state->addr = seg->vmaddr + read_uleb128 (p, end);
			state->segment_end_addr = seg->vmaddr + seg->vmsize;
		}
		return true;
	case BIND_OPCODE_ADD_ADDR_ULEB:
		state->addr += read_uleb128 (p, end);
		return true;
	case BIND_OPCODE_DO_BIND:
	case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
	case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
	case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
		return parse_bind_op_do_bind (mo, threaded_binds, state, op, imm, rel_type, wordsize, p, end);
	default:
		R_LOG_DEBUG ("unknown bind opcode 0x%02x in dyld_info", op);
		return false;
	}
}

static bool _load_relocations(struct MACH0_(obj_t) * mo) {
	RVecRelocRef *threaded_binds = NULL;
	ut8 *opcodes = NULL;
	size_t wordsize = get_word_size (mo);
	if (mo->dyld_info) {
		ut8 rel_type = relfrom_wordsize (wordsize);
		if (!rel_type) {
			return false;
		}
		struct dyld_info_command *di = mo->dyld_info;
		size_t bind_size = di->bind_size;
		size_t lazy_size = di->lazy_bind_size;
		size_t weak_size = di->weak_bind_size;
		ut64 bind_lazy_size = 0;

		if (!bind_size && !lazy_size) {
			return false;
		}
		if (!UT64_ADD (&bind_lazy_size, bind_size, lazy_size)) {
			return false;
		}
		if (!fits_in (mo->size, di->bind_off, bind_size)) {
			return false;
		}
		if (!fits_in (mo->size, di->lazy_bind_off, lazy_size)) {
			return false;
		}
		if (!fits_in (mo->size, di->bind_off, bind_lazy_size)) {
			return false;
		}
		if (!fits_in (mo->size, di->weak_bind_off, weak_size)) {
			return false;
		}
		ut64 amount = 0;
		if (!UT64_ADD (&amount, bind_lazy_size, weak_size) || amount == 0 || amount > UT32_MAX) {
			return false;
		}
		if (!mo->segs) {
			return false;
		}
		opcodes = calloc (1, amount + 1);
		if (!opcodes) {
			return false;
		}

		st64 len = r_buf_read_at (mo->b, di->bind_off, opcodes, bind_size);
		len += r_buf_read_at (mo->b, di->lazy_bind_off, opcodes + bind_size, lazy_size);
		len += r_buf_read_at (mo->b, di->weak_bind_off, opcodes + bind_size + lazy_size, weak_size);
		if (len < 0 || (ut64)len < amount) {
			R_LOG_ERROR ("read (dyld_info bind) at 0x%08" PFMT64x, (ut64) (size_t)di->bind_off);
			R_FREE (opcodes);
			return false;
		}
		HtPP *ord_cache = build_symbol_ordinal_cache (mo);

		size_t partition_sizes[] = { bind_size, lazy_size, weak_size };
		size_t pidx;
		size_t opcodes_offset = 0;
		for (pidx = 0; pidx < R_ARRAY_SIZE (partition_sizes); pidx++) {
			size_t partition_size = partition_sizes[pidx];
			if (partition_size > amount - opcodes_offset) {
				break;
			}

			RBindOpState state = { 0 };
			struct MACH0_(segment_command) *seg0 = &mo->segs[0];
			state.seg_idx = -1;
			state.sym_ord = -1;
			state.addr = seg0->vmaddr;
			state.segment_end_addr = seg0->vmaddr + seg0->vmsize;

			ut8 *p = opcodes + opcodes_offset;
			ut8 *end = p + partition_size;
			while (!state.done && p < end) {
				if (!parse_bind_op (mo, &threaded_binds, ord_cache, &state, rel_type, wordsize, pidx == 1, &p, end)) {
					R_FREE (opcodes);
					RVecRelocRef_free (threaded_binds);
					ht_pp_free (ord_cache);
					return false;
				}
			}
			if (state.stop) {
				break;
			}
			opcodes_offset += partition_size;
		}
		R_FREE (opcodes);
		RVecRelocRef_free (threaded_binds);
		ht_pp_free (ord_cache);
		threaded_binds = NULL;
	}

	struct dysymtab_command *ds = &mo->dysymtab;
	if (mo->symtab && mo->symstr && mo->sects && mo->indirectsyms) {
		int j, amount = clamp_count (ds->nundefsym, mo->limit);
		for (j = 0; j < amount; j++) {
			struct reloc_t *reloc = parse_import_ptr (mo, j);
			if (!reloc) {
				break;
			}
			reloc->ord = j;
			r_skiplist_insert_autofree (mo->relocs_cache, reloc);
		}
	}

	if (mo->symtab && ds->extreloff && ds->nextrel) {
		parse_relocation_info (mo, mo->relocs_cache, ds->extreloff, ds->nextrel);
	}

	if (!mo->dyld_info && mo->chained_starts && mo->nsegs && mo->fixups_offset) {
		walk_bind_chains (mo, mo->relocs_cache);
	}
	R_FREE (opcodes);
	RVecRelocRef_free (threaded_binds);
	return true;
}

const RSkipList *MACH0_(load_relocs)(struct MACH0_(obj_t) * mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);

	if (mo->relocs_loaded) {
		return mo->relocs_cache;
	}
	mo->relocs_loaded = true;
	mo->relocs_cache = r_skiplist_new ((RListFree)free, (RListComparator)reloc_comparator);
	if (!mo->relocs_cache) {
		return NULL;
	}
	if (_load_relocations (mo)) {
		return mo->relocs_cache;
	}
	return NULL;
}

struct addr_t *MACH0_(get_entrypoint)(struct MACH0_(obj_t) * mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);

	ut64 ea = entry_to_vaddr (mo);
	if (ea == 0 || ea == UT64_MAX) {
		return NULL;
	}
	struct addr_t *entry = R_NEW0 (struct addr_t);
	entry->addr = ea;
	entry->offset = addr_to_offset (mo, entry->addr);
	entry->haddr = sdb_num_get (mo->kv, "mach0.entry.offset", 0);
	sdb_num_set (mo->kv, "mach0.entry.vaddr", entry->addr, 0);
	sdb_num_set (mo->kv, "mach0.entry.paddr", mo->entry, 0);

	if (entry->offset == 0 && mo->sects) {
		int i;
		for (i = 0; i < mo->nsects; i++) {
			struct MACH0_(section) *sect = &mo->sects[i];
			// XXX: section name shoudnt matter .. just check for exec flags
			if (r_str_startswith (sect->sectname, "__text")) {
				entry->offset = (ut64)sect->offset;
				sdb_num_set (mo->kv, "mach0.entry", entry->offset, 0);
				entry->addr = (ut64)sect->addr;
				if (!entry->addr) { // workaround for object files
					R_LOG_INFO ("entrypoint is 0");
					// XXX (lowlyw) there's technically not really entrypoints
					// for .o files, so ignore this...
					// entry->addr = entry->offset;
				}
				break;
			}
		}
		mo->entry = entry->addr;
	}
	return entry;
}

void MACH0_(kv_loadlibs)(struct MACH0_(obj_t) * mo) {
	int i;
	char lib_flagname[128];
	for (i = 0; i < mo->nlibs; i++) {
		snprintf (lib_flagname, sizeof (lib_flagname), "libs.%d.name", i);
		char **lib = RVecMach0Lib_at (&mo->libs_cache, i);
		sdb_set (mo->kv, lib_flagname, lib? *lib: NULL, 0);
	}
}

const RVecMach0Lib *MACH0_(load_libs)(struct MACH0_(obj_t) * mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);
	if (!mo->nlibs) {
		return NULL;
	}
	if (mo->libs_loaded) {
		return &mo->libs_cache;
	}
	MACH0_(kv_loadlibs) (mo);
	return &mo->libs_cache;
}

ut64 MACH0_(get_baddr)(struct MACH0_(obj_t) * mo) {
	int i;

	if (mo->hdr.filetype != MH_EXECUTE && mo->hdr.filetype != MH_DYLINKER &&
		mo->hdr.filetype != MH_FILESET) {
		return 0;
	}
	for (i = 0; i < mo->nsegs; i++) {
		struct MACH0_(segment_command) *seg = &mo->segs[i];
		if (seg->fileoff == 0 && seg->filesize != 0) {
			return seg->vmaddr;
		}
	}
	return 0;
}

char *MACH0_(get_class)(struct MACH0_(obj_t) * mo) {
#if R_BIN_MACH064
	return strdup ("MACH064");
#else
	return strdup ("MACH0");
#endif
}

// XXX we are mixing up bits from cpu and opcodes
// since thumb use 16 bits opcode but run in 32 bits
// cpus  so here we should only return 32 or 64
int MACH0_(get_bits)(struct MACH0_(obj_t) * mo) {
	if (mo) {
		int bits = MACH0_(get_bits_from_hdr) (&mo->hdr);
		if (mo->hdr.cputype == CPU_TYPE_ARM && mo->entry & 1) {
			return 16;
		}
		return bits;
	}
	return 32;
}

int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header) * hdr) {
	if (hdr->magic == MH_MAGIC_64 || hdr->magic == MH_CIGAM_64) {
		return 64;
	}
	if (hdr->cputype == CPU_TYPE_ARM64_32) { // new apple watch aka arm64_32
		return 64;
	}
	if ((hdr->cpusubtype & CPU_SUBTYPE_MASK) == (CPU_SUBTYPE_ARM_V7K << 24)) {
		return 16;
	}
	return 32;
}

bool MACH0_(is_big_endian)(struct MACH0_(obj_t) * mo) {
	if (mo) {
		const int cpu = mo->hdr.cputype;
		return cpu == CPU_TYPE_POWERPC || cpu == CPU_TYPE_POWERPC64;
	}
	return false;
}

const char *MACH0_(get_intrp)(struct MACH0_(obj_t) * mo) {
	return mo? mo->intrp: NULL;
}

const char *MACH0_(get_os)(struct MACH0_(obj_t) * mo) {
	if (mo) {
		switch (mo->os) {
		case 1: return "macos";
		case 2: return "ios";
		case 3: return "watchos";
		case 4: return "tvos";
		}
	}
	return "darwin";
}

const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	const char *archstr = "unknown";
	switch (hdr->cputype) {
	case CPU_TYPE_VAX:
		archstr = "vax";
		break;
	case CPU_TYPE_MC680x0:
		archstr = "mc680x0";
		break;
	case CPU_TYPE_RISCV:
		return "riscv";
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		archstr = "x86";
		break;
	case CPU_TYPE_MC88000:
		archstr = "mc88000";
		break;
	case CPU_TYPE_MC98000:
		archstr = "mc98000";
		break;
	case CPU_TYPE_HPPA:
		archstr = "hppa";
		break;
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:
	case CPU_TYPE_ARM64_32:
		archstr = "arm";
		break;
	case CPU_TYPE_SPARC:
		archstr = "sparc";
		break;
	case CPU_TYPE_MIPS:
		archstr = "mips";
		break;
	case CPU_TYPE_I860:
		archstr = "i860";
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		archstr = "ppc";
		break;
	default:
		R_LOG_ERROR ("Unknown arch %d", hdr->cputype);
		break;
	}
	return archstr;
}

const char *MACH0_(get_cputype)(struct MACH0_(obj_t) * mo) {
	return mo? MACH0_(get_cputype_from_hdr) (&mo->hdr): "unknown";
}

static const char *cpusubtype_tostring(ut32 cputype, ut32 cpusubtype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		switch (cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL: return "all";
		case CPU_SUBTYPE_VAX780: return "vax780";
		case CPU_SUBTYPE_VAX785: return "vax785";
		case CPU_SUBTYPE_VAX750: return "vax750";
		case CPU_SUBTYPE_VAX730: return "vax730";
		case CPU_SUBTYPE_UVAXI: return "uvaxI";
		case CPU_SUBTYPE_UVAXII: return "uvaxII";
		case CPU_SUBTYPE_VAX8200: return "vax8200";
		case CPU_SUBTYPE_VAX8500: return "vax8500";
		case CPU_SUBTYPE_VAX8600: return "vax8600";
		case CPU_SUBTYPE_VAX8650: return "vax8650";
		case CPU_SUBTYPE_VAX8800: return "vax8800";
		case CPU_SUBTYPE_UVAXIII: return "uvaxIII";
		default: return "Unknown vax subtype";
		}
	case CPU_TYPE_MC680x0:
		switch (cpusubtype) {
		case CPU_SUBTYPE_MC68030: return "mc68030";
		case CPU_SUBTYPE_MC68040: return "mc68040";
		case CPU_SUBTYPE_MC68030_ONLY: return "mc68030 only";
		default: return "Unknown mc680x0 subtype";
		}
	case CPU_TYPE_RISCV:
		return "riscv";
	case CPU_TYPE_I386:
		switch (cpusubtype) {
		case CPU_SUBTYPE_386: return "386";
		case CPU_SUBTYPE_486: return "486";
		case CPU_SUBTYPE_486SX: return "486sx";
		case CPU_SUBTYPE_PENT: return "Pentium";
		case CPU_SUBTYPE_PENTPRO: return "Pentium Pro";
		case CPU_SUBTYPE_PENTII_M3: return "Pentium 3 M3";
		case CPU_SUBTYPE_PENTII_M5: return "Pentium 3 M5";
		case CPU_SUBTYPE_CELERON: return "Celeron";
		case CPU_SUBTYPE_CELERON_MOBILE: return "Celeron Mobile";
		case CPU_SUBTYPE_PENTIUM_3: return "Pentium 3";
		case CPU_SUBTYPE_PENTIUM_3_M: return "Pentium 3 M";
		case CPU_SUBTYPE_PENTIUM_3_XEON: return "Pentium 3 Xeon";
		case CPU_SUBTYPE_PENTIUM_M: return "Pentium Mobile";
		case CPU_SUBTYPE_PENTIUM_4: return "Pentium 4";
		case CPU_SUBTYPE_PENTIUM_4_M: return "Pentium 4 M";
		case CPU_SUBTYPE_ITANIUM: return "Itanium";
		case CPU_SUBTYPE_ITANIUM_2: return "Itanium 2";
		case CPU_SUBTYPE_XEON: return "Xeon";
		case CPU_SUBTYPE_XEON_MP: return "Xeon MP";
		default: return "Unknown i386 subtype";
		}
	case CPU_TYPE_X86_64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL: return "x86 64 all";
		case CPU_SUBTYPE_X86_ARCH1: return "x86 arch 1";
		default: return "Unknown x86 subtype";
		}
	case CPU_TYPE_MC88000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL: return "all";
		case CPU_SUBTYPE_MC88100: return "mc88100";
		case CPU_SUBTYPE_MC88110: return "mc88110";
		default: return "Unknown mc88000 subtype";
		}
	case CPU_TYPE_MC98000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL: return "all";
		case CPU_SUBTYPE_MC98601: return "mc98601";
		default: return "Unknown mc98000 subtype";
		}
	case CPU_TYPE_HPPA:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100: return "hppa7100";
		case CPU_SUBTYPE_HPPA_7100LC: return "hppa7100LC";
		default: return "Unknown hppa subtype";
		}
	case CPU_TYPE_ARM64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM64_ALL: return "all";
		case CPU_SUBTYPE_ARM64_V8: return "arm64v8";
		case CPU_SUBTYPE_ARM64E: return "arm64e";
		default: return "Unknown arm64 subtype";
		}
	case CPU_TYPE_ARM:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM_ALL:
			return "all";
		case CPU_SUBTYPE_ARM_V4T:
			return "v4t";
		case CPU_SUBTYPE_ARM_V5:
			return "v5";
		case CPU_SUBTYPE_ARM_V6:
			return "v6";
		case CPU_SUBTYPE_ARM_XSCALE:
			return "xscale";
		case CPU_SUBTYPE_ARM_V7:
			return "v7";
		case CPU_SUBTYPE_ARM_V7F:
			return "v7f";
		case CPU_SUBTYPE_ARM_V7S:
			return "v7s";
		case CPU_SUBTYPE_ARM_V7K:
			return "v7k";
		case CPU_SUBTYPE_ARM_V7M:
			return "v7m";
		case CPU_SUBTYPE_ARM_V7EM:
			return "v7em";
		default:
			R_LOG_WARN ("Unknown arm subtype %d", cpusubtype & 0xff);
			return "unknown arm subtype";
		}
	case CPU_TYPE_SPARC:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_SPARC_ALL: return "all";
		default: return "Unknown sparc subtype";
		}
	case CPU_TYPE_MIPS:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL: return "all";
		case CPU_SUBTYPE_MIPS_R2300: return "r2300";
		case CPU_SUBTYPE_MIPS_R2600: return "r2600";
		case CPU_SUBTYPE_MIPS_R2800: return "r2800";
		case CPU_SUBTYPE_MIPS_R2000a: return "r2000a";
		case CPU_SUBTYPE_MIPS_R2000: return "r2000";
		case CPU_SUBTYPE_MIPS_R3000a: return "r3000a";
		case CPU_SUBTYPE_MIPS_R3000: return "r3000";
		default: return "Unknown mips subtype";
		}
	case CPU_TYPE_I860:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL: return "all";
		case CPU_SUBTYPE_I860_860: return "860";
		default: return "Unknown i860 subtype";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL: return "all";
		case CPU_SUBTYPE_POWERPC_601: return "601";
		case CPU_SUBTYPE_POWERPC_602: return "602";
		case CPU_SUBTYPE_POWERPC_603: return "603";
		case CPU_SUBTYPE_POWERPC_603e: return "603e";
		case CPU_SUBTYPE_POWERPC_603ev: return "603ev";
		case CPU_SUBTYPE_POWERPC_604: return "604";
		case CPU_SUBTYPE_POWERPC_604e: return "604e";
		case CPU_SUBTYPE_POWERPC_620: return "620";
		case CPU_SUBTYPE_POWERPC_750: return "750";
		case CPU_SUBTYPE_POWERPC_7400: return "7400";
		case CPU_SUBTYPE_POWERPC_7450: return "7450";
		case CPU_SUBTYPE_POWERPC_970: return "970";
		default: return "Unknown ppc subtype";
		}
	}
	return "Unknown cputype";
}

char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	R_RETURN_VAL_IF_FAIL (hdr, NULL);
	return strdup (cpusubtype_tostring (hdr->cputype, hdr->cpusubtype));
}

char *MACH0_(get_cpusubtype)(struct MACH0_(obj_t) * mo) {
	return mo? MACH0_(get_cpusubtype_from_hdr) (&mo->hdr): strdup ("Unknown");
}

bool MACH0_(is_pie)(struct MACH0_(obj_t) * mo) {
	if (mo->hdr.filetype != MH_EXECUTE) {
		return true;
	}
	return (mo->hdr.flags & MH_PIE) != 0;
}

bool MACH0_(has_nx)(struct MACH0_(obj_t) * mo) {
	if (mo->hdr.flags & MH_NO_HEAP_EXECUTION) {
		return true;
	}
	return (mo->hdr.flags & MH_ALLOW_STACK_EXECUTION) == 0;
}

char *MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	const char *mhtype = "Unknown";
	switch (hdr->filetype) {
	case MH_OBJECT: mhtype = "Relocatable object"; break;
	case MH_EXECUTE: mhtype = "Executable file"; break;
	case MH_FVMLIB: mhtype = "Fixed VM shared library"; break;
	case MH_CORE: mhtype = "Core file"; break;
	case MH_PRELOAD: mhtype = "Preloaded executable file"; break;
	case MH_DYLIB: mhtype = "Dynamically bound shared library"; break;
	case MH_DYLINKER: mhtype = "Dynamic link editor"; break;
	case MH_BUNDLE: mhtype = "Dynamically bound bundle file"; break;
	case MH_DYLIB_STUB: mhtype = "Shared library stub for static linking (no sections)"; break;
	case MH_DSYM: mhtype = "Companion file with only debug sections"; break;
	case MH_KEXT_BUNDLE: mhtype = "Kernel extension bundle file"; break;
	case MH_FILESET: mhtype = "Kernel cache file"; break;
	}
	return strdup (mhtype);
}

char *MACH0_(get_filetype)(struct MACH0_(obj_t) * mo) {
	return mo? MACH0_(get_filetype_from_hdr) (&mo->hdr): strdup ("Unknown");
}

ut64 MACH0_(get_main)(struct MACH0_(obj_t) * mo) {
	ut64 addr = UT64_MAX;
	int i;

	// 0 = sscanned but no main found
	// -1 = not scanned, so no main
	// other = valid main addr
	if (mo->main_addr == UT64_MAX) {
		MACH0_(load_symbols) (mo);
	}
	if (mo->main_addr != 0 && mo->main_addr != UT64_MAX) {
		return mo->main_addr;
	}
	// dummy call to initialize things
	free (MACH0_(get_entrypoint) (mo));

	mo->main_addr = UT64_MAX;

	if (addr == UT64_MAX && mo->main_cmd.cmd == LC_MAIN) {
		addr = mo->entry + mo->baddr;
	}

	if (!addr) {
		ut8 b[128];
		ut64 entry = addr_to_offset (mo, mo->entry);
		// XXX: X86 only and hacky!
		if (entry > mo->size || entry + sizeof (b) > mo->size) {
			return UT64_MAX;
		}
		i = r_buf_read_at (mo->b, entry, b, sizeof (b));
		if (i < 80) {
			return UT64_MAX;
		}
		for (i = 0; i < 64; i++) {
			if (b[i] == 0xe8 && !b[i + 3] && !b[i + 4]) {
				int delta = b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24);
				addr = mo->entry + i + 5 + delta;
				break;
			}
		}
		if (!addr) {
			addr = entry;
		}
	}
	return mo->main_addr = addr;
}

typedef struct {
	ut32 magic;
	ut32 length;
	ut32 count;
} SuperBlob;

static char *walk_codesig(RBinFile *bf, ut32 addr, ut32 size) {
	ut32 magic;
	ut32 i;
	ut32 base_addr = addr;
	ut64 addr_end = addr + size;
	RStrBuf *sb = r_strbuf_new ("");
	struct MACH0_(obj_t) *bo = bf->bo->bin_obj;
	SuperBlob sblob = { 0 };
	if (r_buf_fread_at (bo->b, addr, (ut8 *)&sblob, "3I", 1) != -1) {
		r_strbuf_appendf (sb, "0x%08" PFMT64x " superblob.magic = 0x%08x\n", (ut64)addr, sblob.magic);
		r_strbuf_appendf (sb, "0x%08" PFMT64x " superblob.length = 0x%08x\n", (ut64)addr + 4, sblob.length);
		r_strbuf_appendf (sb, "0x%08" PFMT64x " superblob.count = 0x%08x\n", (ut64)addr + 8, sblob.count);
	}
	const ut32 maxcount = size > 12 ? ((size - 12) / 8) : 0;
	if (sblob.count > maxcount) {
		R_LOG_DEBUG ("invalid superblob count (%u > %u)", sblob.count, maxcount);
		sblob.count = maxcount;
	}
	ut32 *blob_offsets = R_NEWS0 (ut32, sblob.count);
	if (!blob_offsets) {
		return r_strbuf_drain (sb);
	}
	addr += (3 * 4); // skip superblob
	for (i = 0; i < sblob.count; i++) {
		// type : offset
		ut32 to[2];
		if (r_buf_fread_at (bo->b, addr, (ut8 *)&to, "2I", 1) == -1) {
			break;
		}
		r_strbuf_appendf (sb, "0x%08" PFMT64x " type 0x%08x off %d\n", (ut64)addr, to[0], to[1]);
		blob_offsets[i] = to[1];
		addr += 8;
	}
	for (i = 0; i < sblob.count; i++) {
		addr = base_addr + blob_offsets[i];
		if (addr >= addr_end) {
			break;
		}
		if (r_buf_fread_at (bo->b, addr, (ut8 *)&magic, "1I", 1) == -1) {
			R_LOG_DEBUG ("cannot read");
			break;
		}
		r_strbuf_appendf (sb, "0x%08" PFMT64x " blob %d magic 0x%08x:\n", (ut64)addr, i, magic);
		switch (magic) {
		case 0xfade0c02: // codedirectory
		{
			CodeDirectory cdbuf = { 0 }; // align pls
			if (r_buf_fread_at (bo->b, addr, (ut8 *)&cdbuf, "9I", 1) == -1) {
				R_LOG_WARN ("Cant read at 0x%" PFMT64x, (ut64)addr);
				// cant read the struct
			} else {
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.magic    0x%08x\n", (ut64)addr, cdbuf.magic);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.length   0x%08x\n", (ut64)addr + 4, cdbuf.length);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.version  0x%08x\n", (ut64)addr + 8, cdbuf.version);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.flags    0x%08x\n", (ut64)addr + 12, cdbuf.flags);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.hashoff  0x%08x\n", (ut64)addr + 16, cdbuf.hashOffset);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.identoff 0x%08x\n", (ut64)addr + 20, cdbuf.identOffset);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.nspecials  0x%08x\n", (ut64)addr + 24, cdbuf.nSpecialSlots);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.ncodes     0x%08x\n", (ut64)addr + 28, cdbuf.nCodeSlots);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.codelimit  0x%08x\n", (ut64)addr + 32, cdbuf.codeLimit);
				// ut8
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.hashsize   0x%02x\n", (ut64)addr + 36, cdbuf.hashSize);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.hashtype   0x%02x\n", (ut64)addr + 40, cdbuf.hashType);
				r_strbuf_appendf (sb, "0x%08" PFMT64x " code.dir.pagesize   0x%02x\n", (ut64)addr + 40, cdbuf.pageSize); // log2 () or 0
			}
		}
		break;
		case 0xfade0cc0: // embedded signature
			r_strbuf_appendf (sb, "0x%08" PFMT64x " magic embedded signature\n", (ut64)addr);
			break;
		case 0xfade0cc1: // detached signature
			r_strbuf_appendf (sb, "0x%08" PFMT64x " magic detached signature\n", (ut64)addr);
			break;
		case 0xfade0c01: // requirements
		case 0xfade0b01:
			r_strbuf_appendf (sb, "0x%08" PFMT64x " codesign requirements\n", (ut64)addr);
			break;
		case 0xfade7171:
			r_strbuf_appendf (sb, "0x%08" PFMT64x " codesign digest\n", (ut64)addr);
			// digest
			break;
		case 0:
			// nothing to do
			break;
		default:
			R_LOG_ERROR ("unknown codesign magic 0x%08x", magic);
			break;
		}
	}
	free (blob_offsets);
	return r_strbuf_drain (sb);
}

char *MACH0_(mach_headerfields)(RBinFile *bf, int mode) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	RStrBuf *sb = r_strbuf_new ("");
#define p(f, ...) r_strbuf_appendf(sb, f, ## __VA_ARGS__)
	RBuffer *buf = bf->buf;
	ut64 length = r_buf_size (buf);
	int n = 0;
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr) (buf);
	if (!mh) {
		r_strbuf_free (sb);
		return NULL;
	}
	ut64 pvaddr = pa2va (bf, 0);
	p ("pf.mach0_header @ 0x%08" PFMT64x "\n", pvaddr);
	p ("0x%08" PFMT64x "  Magic       0x%x\n", pvaddr, mh->magic);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  CpuType     0x%x\n", pvaddr, mh->cputype);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  CpuSubType  0x%x\n", pvaddr, mh->cpusubtype);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  FileType    0x%x\n", pvaddr, mh->filetype);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  nCmds       %d\n", pvaddr, mh->ncmds);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  sizeOfCmds  %d\n", pvaddr, mh->sizeofcmds);
	pvaddr += 4;
	p ("0x%08" PFMT64x "  Flags       0x%x\n", pvaddr, mh->flags);
	pvaddr += 4;
	bool is64 = mh->cputype >> 16;

	ut64 addr = 0x20 - 4;
	ut32 word = 0;
	ut8 wordbuf[sizeof (word)];
	bool isBe = false;
	switch (mh->cputype) {
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		isBe = true;
		break;
	}
#define READWORD() \
	if (r_buf_read_at (buf, addr, (ut8 *)wordbuf, 4) != 4) { \
		R_LOG_WARN ("Invalid address in buffer"); \
		break; \
	} \
	addr += 4; \
	pvaddr += 4; \
	word = isBe? r_read_be32 (wordbuf): r_read_le32 (wordbuf);
	if (is64) {
		addr += 4;
		pvaddr += 4;
	}
	init_sdb_formats (mo);
	for (n = 0; n < mh->ncmds && addr < length; n++) {
		READWORD ();
		ut32 lcType = word;
		const char *pf_definition = cmd_to_pf_definition (lcType);
		if (pf_definition) {
			p ("pf.%s @ 0x%08" PFMT64x "\n", pf_definition, pvaddr - 4);
		}
		p ("0x%08" PFMT64x "  cmd %7d 0x%x %s\n",
			pvaddr - 4,
			n,
			lcType,
			cmd_tostring (lcType));
		READWORD ();
		if (addr > length) {
			break;
		}
		int lcSize = word;
		word &= 0xFFFFFF;
		p ("0x%08" PFMT64x "  cmdsize     %d\n", pvaddr - 4, word);
		if (lcSize < 1) {
			R_LOG_WARN ("Invalid size for a load command");
			break;
		}
		switch (lcType) {
		case LC_BUILD_VERSION:
			{
				p ("0x%08" PFMT64x "  platform    %s\n",
					pvaddr,
					build_version_platform_tostring (r_buf_read_le32_at (buf, addr)));
				p ("0x%08" PFMT64x "  minos       %d.%d.%d\n",
					pvaddr + 4,
					r_buf_read_le16_at (buf, addr + 6),
					r_buf_read8_at (buf, addr + 5),
					r_buf_read8_at (buf, addr + 4));
				p ("0x%08" PFMT64x "  sdk         %d.%d.%d\n",
					pvaddr + 8,
					r_buf_read_le16_at (buf, addr + 10),
					r_buf_read8_at (buf, addr + 9),
					r_buf_read8_at (buf, addr + 8));
				ut32 ntools = r_buf_read_le32_at (buf, addr + 12);
				p ("0x%08" PFMT64x "  ntools      %d\n",
					pvaddr + 12,
					ntools);
				ut64 off = 16;
				while (off < (lcSize - 8) && ntools--) {
					p ("pf.mach0_build_version_tool @ 0x%08" PFMT64x "\n", pvaddr + off);
					p ("0x%08" PFMT64x "  tool        %s\n",
						pvaddr + off,
						build_version_tool_tostring (r_buf_read_le32_at (buf, addr + off)));
					off += 4;
					if (off >= (lcSize - 8)) {
						break;
					}
					p ("0x%08" PFMT64x "  version     %d.%d.%d\n",
						pvaddr + off,
						r_buf_read_le16_at (buf, addr + off + 2),
						r_buf_read8_at (buf, addr + off + 1),
						r_buf_read8_at (buf, addr + off));
					off += 4;
				}
				break;
			}
		case LC_MAIN:
			{
				ut8 data[64] = { 0 };
				r_buf_read_at (buf, addr, data, sizeof (data));
#if R_BIN_MACH064
				ut64 ep = r_read_ble64 (&data, false); //  bin->big_endian);
				p ("0x%08" PFMT64x "  entry0      0x%" PFMT64x "\n", pvaddr, ep);
				ut64 ss = r_read_ble64 (&data[8], false); //  bin->big_endian);
				p ("0x%08" PFMT64x "  stacksize   0x%" PFMT64x "\n", pvaddr + 8, ss);
#else
				ut32 ep = r_read_ble32 (&data, false); //  bin->big_endian);
				p ("0x%08" PFMT32x "  entry0      0x%" PFMT32x "\n", (ut32)pvaddr, ep);
				ut32 ss = r_read_ble32 (&data[4], false); //  bin->big_endian);
				p ("0x%08" PFMT32x "  stacksize   0x%" PFMT32x "\n", (ut32)pvaddr + 4, ss);
#endif
			}
			break;
		case LC_SYMTAB:
#if 0
			{
			char *id = r_buf_get_string (buf, addr + 20);
			p ("0x%08"PFMT64x"  id         0x%x\n", addr + 20, r_str_get (id));
			p ("0x%08"PFMT64x"  symooff    0x%x\n", addr + 20, r_str_get (id));
			p ("0x%08"PFMT64x"  nsyms      %d\n", addr + 20, r_str_get (id));
			p ("0x%08"PFMT64x"  stroff     0x%x\n", addr + 20, r_str_get (id));
			p ("0x%08"PFMT64x"  strsize    0x%x\n", addr + 20, r_str_get (id));
			free (id);
			}
#endif
			break;
		case LC_ID_DYLIB: // install_name_tool
		{
			ut32 str_off = r_buf_read_ble32_at (buf, addr, isBe);
			char *id = r_buf_get_string (buf, addr + str_off - 8);
			p ("0x%08" PFMT64x "  current     %d.%d.%d\n",
				pvaddr + 8,
				r_buf_read_le16_at (buf, addr + 10),
				r_buf_read8_at (buf, addr + 9),
				r_buf_read8_at (buf, addr + 8));
			p ("0x%08" PFMT64x "  compat      %d.%d.%d\n",
				pvaddr + 12,
				r_buf_read_le16_at (buf, addr + 14),
				r_buf_read8_at (buf, addr + 13),
				r_buf_read8_at (buf, addr + 12));
			p ("0x%08" PFMT64x "  id          %s\n",
				pvaddr + str_off - 8,
				r_str_get (id));
			free (id);
			break;
		}
		case LC_UUID:
			{
				ut8 i, uuid[16];
				r_buf_read_at (buf, addr, uuid, sizeof (uuid));
				p ("0x%08" PFMT64x "  uuid        ", pvaddr);
				for (i = 0; i < sizeof (uuid); i++) {
					p ("%02x", uuid[i]);
				}
				p ("\n");
			}
			break;
		case LC_SEGMENT:
		case LC_SEGMENT_64:
			{
				ut8 name[17] = { 0 };
				r_buf_read_at (buf, addr, name, sizeof (name) - 1);
				p ("0x%08" PFMT64x "  name        %s\n", pvaddr, name);
				ut32 nsects = r_buf_read_le32_at (buf, addr - 8 + (is64? 64: 48));
				ut64 off = is64? 72: 56;
				while (off < lcSize && nsects--) {
					if (is64) {
						p ("pf.mach0_section64 @ 0x%08" PFMT64x "\n", pvaddr - 8 + off);
						off += 80;
					} else {
						p ("pf.mach0_section @ 0x%08" PFMT64x "\n", pvaddr - 8 + off);
						off += 68;
					}
				}
			}
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			{
				ut32 str_off = r_buf_read_ble32_at (buf, addr, isBe);
				char *load_dylib = r_buf_get_string (buf, addr + str_off - 8);
				p ("0x%08" PFMT64x "  current     %d.%d.%d\n",
					pvaddr + 8,
					r_buf_read_le16_at (buf, addr + 10),
					r_buf_read8_at (buf, addr + 9),
					r_buf_read8_at (buf, addr + 8));
				p ("0x%08" PFMT64x "  compat      %d.%d.%d\n",
					pvaddr + 12,
					r_buf_read_le16_at (buf, addr + 14),
					r_buf_read8_at (buf, addr + 13),
					r_buf_read8_at (buf, addr + 12));
				p ("0x%08" PFMT64x "  load_dylib  %s\n",
					pvaddr + str_off - 8,
					r_str_get (load_dylib));
				if (load_dylib) {
					free (load_dylib);
				}
				break;
			}
		case LC_RPATH:
			{
				char *rpath = r_buf_get_string (buf, addr + 4);
				p ("0x%08" PFMT64x "  rpath       %s\n",
					pvaddr + 4,
					r_str_get (rpath));
				if (rpath) {
					free (rpath);
				}
				break;
			}
		case LC_ENCRYPTION_INFO:
		case LC_ENCRYPTION_INFO_64:
			{
				ut32 word = r_buf_read_le32_at (buf, addr);
				p ("0x%08" PFMT64x "  cryptoff   0x%08x\n", pvaddr, word);
				word = r_buf_read_le32_at (buf, addr + 4);
				p ("0x%08" PFMT64x "  cryptsize  %d\n", pvaddr + 4, word);
				word = r_buf_read_le32_at (buf, addr + 8);
				p ("0x%08" PFMT64x "  cryptid    %d\n", pvaddr + 8, word);
				break;
			}
		// https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c.auto.html
		case LC_CODE_SIGNATURE:
			{
				ut32 words[2];
				r_buf_read_at (buf, addr, (ut8 *)words, sizeof (words));
				p ("0x%08" PFMT64x "  codesig.dataoff     0x%08x\n", pvaddr, words[0]);
				p ("0x%08" PFMT64x "  codesig.datasize    %d\n", pvaddr + 4, words[1]);
				p ("# wtf mach0.sign %d @ 0x%x\n", words[1], words[0]);
				char *s = walk_codesig (bf, words[0], words[1]);
				p ("%s", s);
				free (s);
				break;
			}
		}
		addr += word - 8;
		pvaddr += word - 8;
	}
	free (mh);
#undef p
	return r_strbuf_drain (sb);
}

RList *MACH0_(mach_fields)(RBinFile *bf) {
	RBuffer *buf = bf->buf;
	ut64 length = r_buf_size (buf);
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr) (buf);
	if (!mh) {
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		free (mh);
		return NULL;
	}
	ret->free = free;
	ut64 addr = pa2va (bf, 0);
	ut64 paddr = 0;

	r_list_append (ret, r_bin_field_new (paddr, addr, -1, 1, "header", "mach0_header", "mach0_header", true));
	addr += 0x20 - 4;
	paddr += 0x20 - 4;
	bool is64 = mh->cputype >> 16;
	if (is64) {
		addr += 4;
		paddr += 4;
	}

	bool isBe = false;
	switch (mh->cputype) {
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		isBe = true;
		break;
	}

	int n;
	char load_command_flagname[128];
	for (n = 0; n < mh->ncmds && paddr < length; n++) {
		ut32 lcType = r_buf_read_ble32_at (buf, paddr, isBe);
		ut32 word = r_buf_read_ble32_at (buf, paddr + 4, isBe);
		if (paddr + 8 > length) {
			break;
		}
		ut32 lcSize = word;
		word &= 0xFFFFFF;
		if (lcSize < 1) {
			R_LOG_WARN ("Invalid size for a load command");
			break;
		}
		if (word == 0) {
			break;
		}
		const char *pf_definition = cmd_to_pf_definition (lcType);
		if (pf_definition) {
			snprintf (load_command_flagname, sizeof (load_command_flagname), "load_command_%d_%s", n, cmd_tostring (lcType));
			r_list_append (ret, r_bin_field_new (paddr, addr, 1, -1, load_command_flagname, pf_definition, pf_definition, true));
		}
		switch (lcType) {
		case LC_BUILD_VERSION:
			{
				ut32 ntools = r_buf_read_le32_at (buf, paddr + 20);
				ut64 off = 24;
				int j = 0;
				char tool_flagname[64];
				ut64 bsz = r_buf_size (buf);
				while (off < lcSize && ntools--) {
					ut64 at = paddr + off;
					if (at > bsz) {
						R_LOG_DEBUG ("prevented");
						break;
					}
					snprintf (tool_flagname, sizeof (tool_flagname), "tool_%d", j++);
					RBinField *f = r_bin_field_new (at, addr + off, 1, -1, tool_flagname, "mach0_build_version_tool", "mach0_build_version_tool", true);
					r_list_append (ret, f);
					off += 8;
				}
				break;
			}
		case LC_SEGMENT:
		case LC_SEGMENT_64:
			{
				ut32 nsects = r_buf_read_le32_at (buf, addr + (is64? 64: 48));
				ut64 off = is64? 72: 56;
				size_t i, j = 0;
				char section_flagname[128];
				for (i = 0; i < nsects && (addr + off) < length && off < lcSize; i++) {
					const char *sname = is64? "mach0_section64": "mach0_section";
					snprintf (section_flagname, sizeof (section_flagname), "section_%u", (ut32)j++);
					ut64 va = addr + off;
					ut64 pa = paddr + off;
					RBinField *f = r_bin_field_new (pa, va, -1, 1, section_flagname, sname, sname, true);
					r_list_append (ret, f);
					off += is64? 80: 68;
				}
				break;
		default:
				// TODO
				break;
			}
		}
		addr += word;
		paddr += word;
	}
	free (mh);
	return ret;
}

struct MACH0_(mach_header) * MACH0_(get_hdr)(RBuffer *buf) {
	ut8 hdr[sizeof (struct MACH0_(mach_header))] = { 0 };
	struct MACH0_(mach_header) *mh = R_NEW0 (struct MACH0_(mach_header));
	bool be = false;
	int len = r_buf_read_at (buf, 0, hdr, sizeof (hdr));
	if (len != sizeof (struct MACH0_(mach_header))) {
		free (mh);
		return NULL;
	}
	if (!magic_endian (r_read_be32 (hdr), &be)) {
		/* Keep parsing to support metadata extraction from non-mach0 slices. */
		be = false;
	}
	mh->magic = r_read_ble (&hdr[0], be, 32);
	mh->cputype = r_read_ble (&hdr[4], be, 32);
	mh->cpusubtype = r_read_ble (&hdr[8], be, 32);
	mh->filetype = r_read_ble (&hdr[12], be, 32);
	mh->ncmds = r_read_ble (&hdr[16], be, 32);
	mh->sizeofcmds = r_read_ble (&hdr[20], be, 32);
	mh->flags = r_read_ble (&hdr[24], be, 32);
#if R_BIN_MACH064
	mh->reserved = r_read_ble (&hdr[28], be, 32);
#endif
	return mh;
}

#define IS_FMT_32BIT(x) (x == DYLD_CHAINED_PTR_32 || x == DYLD_CHAINED_PTR_32_CACHE || x == DYLD_CHAINED_PTR_32_FIRMWARE)

void MACH0_(iterate_chained_fixups)(struct MACH0_(obj_t) * mo, ut64 limit_start, ut64 limit_end, ut32 event_mask, RFixupCallback callback, void *context) {
	int i;
	for (i = 0; i < mo->nsegs && i < mo->segs_count; i++) {
		struct r_dyld_chained_starts_in_segment *starts = mo->chained_starts[i];
		if (!starts || !starts->page_start || !starts->page_count) {
			continue;
		}
		int page_size = starts->page_size;
		if (page_size < 1) {
			page_size = 4096;
		}
		struct MACH0_(segment_command) *seg = &mo->segs[i];
		ut64 start = seg->fileoff;
		ut64 end = start + seg->filesize;
		if (end >= limit_start && start <= limit_end) {
			ut64 page_idx = (R_MAX (start, limit_start) - start) / page_size;
			ut64 page_end_idx = (R_MIN (limit_end, end) - start) / page_size;
			ut64 max_page_idx = starts->page_count - 1;
			page_end_idx = R_MIN (page_end_idx, max_page_idx);
			if (page_idx > page_end_idx) {
				continue;
			}
			for (; page_idx <= page_end_idx; page_idx++) {
				ut16 page_start = starts->page_start[page_idx];
				if (page_start == DYLD_CHAINED_PTR_START_NONE) {
					continue;
				}
				ut64 cursor = start + page_idx * page_size + page_start;
				while (cursor < limit_end && cursor < end) {
					ut8 tmp[8];
					bool previous_rebasing = mo->rebasing_buffer;
					mo->rebasing_buffer = true;
					if (r_buf_read_at (mo->b, cursor, tmp, 8) != 8) {
						mo->rebasing_buffer = previous_rebasing;
						break;
					}
					mo->rebasing_buffer = previous_rebasing;
					ut16 pointer_format = starts->pointer_format;
					ut64 raw_ptr = IS_FMT_32BIT (pointer_format)? r_read_le32 (tmp): r_read_le64 (tmp);
					ut64 ptr_value = raw_ptr;
					ut64 delta = 0, stride = 0, addend = 0;
					RFixupEvent event = R_FIXUP_EVENT_NONE;
					ut8 key = 0, addr_div = 0;
					ut16 diversity = 0;
					ut32 ordinal = UT32_MAX;
					ut8 ptr_size = 8;
					switch (pointer_format) {
					case DYLD_CHAINED_PTR_ARM64E:
						{
							stride = 8;
							bool is_auth = IS_PTR_AUTH (raw_ptr);
							bool is_bind = IS_PTR_BIND (raw_ptr);
							if (is_auth && is_bind) {
								struct dyld_chained_ptr_arm64e_auth_bind *p =
									(struct dyld_chained_ptr_arm64e_auth_bind *)&raw_ptr;
								event = R_FIXUP_EVENT_BIND_AUTH;
								delta = p->next;
								ordinal = p->ordinal;
								key = p->key;
								addr_div = p->addrDiv;
								diversity = p->diversity;
							} else if (!is_auth && is_bind) {
								struct dyld_chained_ptr_arm64e_bind *p =
									(struct dyld_chained_ptr_arm64e_bind *)&raw_ptr;
								event = R_FIXUP_EVENT_BIND;
								delta = p->next;
								ordinal = p->ordinal;
								addend = p->addend;
							} else if (is_auth && !is_bind) {
								struct dyld_chained_ptr_arm64e_auth_rebase *p =
									(struct dyld_chained_ptr_arm64e_auth_rebase *)&raw_ptr;
								event = R_FIXUP_EVENT_REBASE_AUTH;
								delta = p->next;
								ptr_value = p->target + mo->baddr;
								key = p->key;
								addr_div = p->addrDiv;
								diversity = p->diversity;
							} else {
								struct dyld_chained_ptr_arm64e_rebase *p =
									(struct dyld_chained_ptr_arm64e_rebase *)&raw_ptr;
								event = R_FIXUP_EVENT_REBASE;
								delta = p->next;
								ptr_value = ((ut64)p->high8 << 56) | p->target;
							}
						}
						break;
					case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
						{
							stride = 8;
							struct dyld_chained_ptr_arm64e_bind24 *bind =
								(struct dyld_chained_ptr_arm64e_bind24 *)&raw_ptr;
							if (bind->bind) {
								delta = bind->next;
								if (bind->auth) {
									struct dyld_chained_ptr_arm64e_auth_bind24 *p =
										(struct dyld_chained_ptr_arm64e_auth_bind24 *)&raw_ptr;
									event = R_FIXUP_EVENT_BIND_AUTH;
									ordinal = p->ordinal;
									key = p->key;
									addr_div = p->addrDiv;
									diversity = p->diversity;
								} else {
									event = R_FIXUP_EVENT_BIND;
									ordinal = bind->ordinal;
									addend = bind->addend;
								}
							} else {
								if (bind->auth) {
									struct dyld_chained_ptr_arm64e_auth_rebase *p =
										(struct dyld_chained_ptr_arm64e_auth_rebase *)&raw_ptr;
									event = R_FIXUP_EVENT_REBASE_AUTH;
									delta = p->next;
									ptr_value = p->target + mo->baddr;
									key = p->key;
									addr_div = p->addrDiv;
									diversity = p->diversity;
								} else {
									struct dyld_chained_ptr_arm64e_rebase *p =
										(struct dyld_chained_ptr_arm64e_rebase *)&raw_ptr;
									event = R_FIXUP_EVENT_REBASE;
									delta = p->next;
									ptr_value = mo->baddr + (((ut64)p->high8 << 56) | p->target);
								}
							}
						}
						break;
					case DYLD_CHAINED_PTR_64:
					case DYLD_CHAINED_PTR_64_OFFSET:
						{
							stride = 4;
							struct dyld_chained_ptr_64_bind *bind =
								(struct dyld_chained_ptr_64_bind *)&raw_ptr;
							if (bind->bind) {
								event = R_FIXUP_EVENT_BIND;
								delta = bind->next;
								ordinal = bind->ordinal;
								addend = bind->addend;
							} else {
								struct dyld_chained_ptr_64_rebase *p =
									(struct dyld_chained_ptr_64_rebase *)&raw_ptr;
								event = R_FIXUP_EVENT_REBASE;
								delta = p->next;
								ptr_value = ((ut64)p->high8 << 56) | p->target;
								if (pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
									ptr_value += mo->baddr;
								}
							}
						}
						break;
					case DYLD_CHAINED_PTR_32:
						{
							stride = 4;
							ptr_size = 4;
							struct dyld_chained_ptr_32_bind *bind =
								(struct dyld_chained_ptr_32_bind *)&raw_ptr;
							if (bind->bind) {
								event = R_FIXUP_EVENT_BIND;
								delta = bind->next;
								ordinal = bind->ordinal;
								addend = bind->addend;
							} else {
								struct dyld_chained_ptr_32_rebase *p =
									(struct dyld_chained_ptr_32_rebase *)&raw_ptr;
								event = R_FIXUP_EVENT_REBASE;
								delta = p->next;
								ptr_value = p->target;
							}
						}
						break;
					case DYLD_CHAINED_PTR_32_CACHE:
						{
							stride = 4;
							ptr_size = 4;
							struct dyld_chained_ptr_32_cache_rebase *p =
								(struct dyld_chained_ptr_32_cache_rebase *)&raw_ptr;
							event = R_FIXUP_EVENT_REBASE;
							delta = p->next;
							ptr_value = p->target;
						}
						break;
					case DYLD_CHAINED_PTR_32_FIRMWARE:
						{
							stride = 4;
							ptr_size = 4;
							struct dyld_chained_ptr_32_firmware_rebase *p =
								(struct dyld_chained_ptr_32_firmware_rebase *)&raw_ptr;
							event = R_FIXUP_EVENT_REBASE;
							delta = p->next;
							ptr_value = p->target;
						}
						break;
					default:
						R_LOG_WARN ("Unsupported chained pointer format %d", pointer_format);
						return;
					}
					if (cursor >= limit_start && cursor <= limit_end - 8 && (event & event_mask) != 0) {
						RFixupEventDetails ed = {
							.type = event,
							.bin = mo,
							.offset = cursor,
							.raw_ptr = raw_ptr,
							.ptr_size = ptr_size,
							.ordinal = ordinal,
							.addend = addend,
							.ptr_value = ptr_value,
							.key = key,
							.addr_div = addr_div,
							.diversity = diversity,
						};
						if (!callback (context, &ed)) {
							return;
						}
					}
					if (!delta) {
						break;
					}
					cursor += delta * stride;
				}
			}
		}
	}
}
