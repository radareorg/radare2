/* radare - LGPL - Copyright 2010-2026 - nibble, mrmacete, pancake */

#define R_LOG_ORIGIN "bin.macho"

#include <r_hash.h>
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

typedef void (*RExportsIterator)(struct MACH0_(obj_t) *mo, const char *name, ut64 flags, ut64 offset, void *ctx);

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
	ut32 magic;          /* magic number (CSMAGIC_CODEDIRECTORY) */
	ut32 length;         /* total length of CodeDirectory blob */
	ut32 version;        /* compatibility version */
	ut32 flags;          /* setup and mode flags */
	ut32 hashOffset;     /* offset of hash slot element at index zero */
	ut32 identOffset;    /* offset of identifier string */
	ut32 nSpecialSlots;  /* number of special hash slots */
	ut32 nCodeSlots;     /* number of ordinary (code) hash slots */
	ut32 codeLimit;      /* limit to main image signature range */
	ut8 hashSize;        /* size of each hash in bytes */
	ut8 hashType;        /* type of hash (cdHashType* constants) */
	ut8 spare1;          /* unused (must be zero) */
	ut8 pageSize;        /* log2(page size in bytes); 0 => infinite */
	ut32 spare2;         /* unused (must be zero) */
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
	const char *error = NULL;
	ut64 v;
	*p = (ut8 *)r_uleb128 (*p, end - *p, &v, &error);
	if (error) {
		R_LOG_ERROR ("%s", error);
		R_FREE (error);
		return UT64_MAX;
	}
	return v;
}

static ut64 entry_to_vaddr(struct MACH0_(obj_t) *bin) {
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

static ut64 addr_to_offset(struct MACH0_(obj_t) *mo, ut64 addr) {
	if (mo->segs) {
		size_t i;
		for (i = 0; i < mo->nsegs; i++) {
			const ut64 segment_base = (ut64)mo->segs[i].vmaddr;
			const ut64 segment_size = (ut64)mo->segs[i].vmsize;
			if (addr >= segment_base && addr < segment_base + segment_size) {
				return mo->segs[i].fileoff + (addr - segment_base);
			}
		}
	}
	return 0; // UT64_MAX?
}

static ut64 offset_to_vaddr(struct MACH0_(obj_t) *mo, ut64 offset) {
	if (mo->segs) {
		size_t i;
		for (i = 0; i < mo->nsegs; i++) {
			ut64 segment_base = (ut64)mo->segs[i].fileoff;
			ut64 segment_size = (ut64)mo->segs[i].filesize;
			if (offset >= segment_base && offset < segment_base + segment_size) {
				return mo->segs[i].vmaddr + (offset - segment_base);
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

static void init_sdb_formats(struct MACH0_(obj_t) *mo) {
	Sdb *kv = mo->kv;
	/*
	 * These definitions are used by r2 -nn
	 * must be kept in sync with libr/bin/d/macho
	 */
	sdb_set (kv, "mach0_build_platform.cparse",
		"enum mach0_build_platform" "{MACOS=1, IOS=2, TVOS=3, WATCHOS=4, BRIDGEOS=5, IOSMAC=6, IOSSIMULATOR=7, TVOSSIMULATOR=8, WATCHOSSIMULATOR=9};",
		0);
	sdb_set (kv, "mach0_build_tool.cparse",
		"enum mach0_build_tool" "{CLANG=1, SWIFT=2, LD=3};",
		0);
	sdb_set (kv, "mach0_load_command_type.cparse",
		"enum mach0_load_command_type" "{ LC_SEGMENT=0x00000001ULL, LC_SYMTAB=0x00000002ULL, LC_SYMSEG=0x00000003ULL, LC_THREAD=0x00000004ULL, LC_UNIXTHREAD=0x00000005ULL, LC_LOADFVMLIB=0x00000006ULL, LC_IDFVMLIB=0x00000007ULL, LC_IDENT=0x00000008ULL, LC_FVMFILE=0x00000009ULL, LC_PREPAGE=0x0000000aULL, LC_DYSYMTAB=0x0000000bULL, LC_LOAD_DYLIB=0x0000000cULL, LC_ID_DYLIB=0x0000000dULL, LC_LOAD_DYLINKER=0x0000000eULL, LC_ID_DYLINKER=0x0000000fULL, LC_PREBOUND_DYLIB=0x00000010ULL, LC_ROUTINES=0x00000011ULL, LC_SUB_FRAMEWORK=0x00000012ULL, LC_SUB_UMBRELLA=0x00000013ULL, LC_SUB_CLIENT=0x00000014ULL, LC_SUB_LIBRARY=0x00000015ULL, LC_TWOLEVEL_HINTS=0x00000016ULL, LC_PREBIND_CKSUM=0x00000017ULL, LC_LOAD_WEAK_DYLIB=0x80000018ULL, LC_SEGMENT_64=0x00000019ULL, LC_ROUTINES_64=0x0000001aULL, LC_UUID=0x0000001bULL, LC_RPATH=0x8000001cULL, LC_CODE_SIGNATURE=0x0000001dULL, LC_SEGMENT_SPLIT_INFO=0x0000001eULL, LC_REEXPORT_DYLIB=0x8000001fULL, LC_LAZY_LOAD_DYLIB=0x00000020ULL, LC_ENCRYPTION_INFO=0x00000021ULL, LC_DYLD_INFO=0x00000022ULL, LC_DYLD_INFO_ONLY=0x80000022ULL, LC_LOAD_UPWARD_DYLIB=0x80000023ULL, LC_VERSION_MIN_MACOSX=0x00000024ULL, LC_VERSION_MIN_IPHONEOS=0x00000025ULL, LC_FUNCTION_STARTS=0x00000026ULL, LC_DYLD_ENVIRONMENT=0x00000027ULL, LC_MAIN=0x80000028ULL, LC_DATA_IN_CODE=0x00000029ULL, LC_SOURCE_VERSION=0x0000002aULL, LC_DYLIB_CODE_SIGN_DRS=0x0000002bULL, LC_ENCRYPTION_INFO_64=0x0000002cULL, LC_LINKER_OPTION=0x0000002dULL, LC_LINKER_OPTIMIZATION_HINT=0x0000002eULL, LC_VERSION_MIN_TVOS=0x0000002fULL, LC_VERSION_MIN_WATCHOS=0x00000030ULL, LC_NOTE=0x00000031ULL, LC_BUILD_VERSION=0x00000032ULL };",
		0);
	sdb_set (kv, "mach0_header_filetype.cparse",
		"enum mach0_header_filetype" "{MH_OBJECT=1, MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6, MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10, MH_KEXT_BUNDLE=11};",
		0);
	sdb_set (kv, "mach0_header_flags.cparse",
		"enum mach0_header_flags" "{MH_NOUNDEFS=1, MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10, MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80, MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400, MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000, MH_SUBSECTIONS_VIA_SYMBOLS=0x2000, MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000, MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000, MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000, MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000, MH_DEAD_STRIPPABLE_DYLIB=0x400000, MH_HAS_TLV_DESCRIPTORS=0x800000, MH_NO_HEAP_EXECUTION=0x1000000};",
		0);
	sdb_set (kv, "mach0_section_types.cparse",
		"enum mach0_section_types" "{S_REGULAR=0, S_ZEROFILL=1, S_CSTRING_LITERALS=2, S_4BYTE_LITERALS=3, S_8BYTE_LITERALS=4, S_LITERAL_POINTERS=5, S_NON_LAZY_SYMBOL_POINTERS=6, S_LAZY_SYMBOL_POINTERS=7, S_SYMBOL_STUBS=8, S_MOD_INIT_FUNC_POINTERS=9, S_MOD_TERM_FUNC_POINTERS=0xa, S_COALESCED=0xb, S_GB_ZEROFILL=0xc, S_INTERPOSING=0xd, S_16BYTE_LITERALS=0xe, S_DTRACE_DOF=0xf, S_LAZY_DYLIB_SYMBOL_POINTERS=0x10, S_THREAD_LOCAL_REGULAR=0x11, S_THREAD_LOCAL_ZEROFILL=0x12, S_THREAD_LOCAL_VARIABLES=0x13, S_THREAD_LOCAL_VARIABLE_POINTERS=0x14, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15, S_INIT_FUNC_OFFSETS=0x16};",
		0);
	sdb_set (kv, "mach0_section_attrs.cparse",
		"enum mach0_section_attrs" "{S_ATTR_PURE_INSTRUCTIONS=0x800000ULL, S_ATTR_NO_TOC=0x400000ULL, S_ATTR_STRIP_STATIC_SYMS=0x200000ULL, S_ATTR_NO_DEAD_STRIP=0x100000ULL, S_ATTR_LIVE_SUPPORT=0x080000ULL, S_ATTR_SELF_MODIFYING_CODE=0x040000ULL, S_ATTR_DEBUG=0x020000ULL, S_ATTR_SOME_INSTRUCTIONS=0x000004ULL, S_ATTR_EXT_RELOC=0x000002ULL, S_ATTR_LOC_RELOC=0x000001ULL};",
		0);
	sdb_set (kv, "mach0_header.format",
		"xxx[4]Edd[4]B "
		"magic cputype cpusubtype (mach0_header_filetype)filetype ncmds sizeofcmds (mach0_header_flags)flags",
		0);
	sdb_set (kv, "mach0_segment.format",
		"[4]Ed[16]zxxxxoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set (kv, "mach0_segment64.format",
		"[4]Ed[16]zqqqqoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set (kv, "mach0_symtab_command.format",
		"[4]Edxdxd "
		"(mach0_load_command_type)cmd cmdsize symoff nsyms stroff strsize",
		0);
	sdb_set (kv, "mach0_dysymtab_command.format",
		"[4]Edddddddddddxdxdxxxd "
		"(mach0_load_command_type)cmd cmdsize ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc moddtaboff nmodtab extrefsymoff nextrefsyms inddirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel",
		0);
	sdb_set (kv, "mach0_section.format",
		"[16]z[16]zxxxxxx[1]E[3]Bxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2", 0);
	sdb_set (kv, "mach0_section64.format",
		"[16]z[16]zqqxxxx[1]E[3]Bxxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2 reserved3",
		0);
	sdb_set (kv, "mach0_dylib.format",
		"xxxxz "
		"name_offset timestamp current_version compatibility_version name",
		0);
	sdb_set (kv, "mach0_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set (kv, "mach0_id_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set (kv, "mach0_uuid_command.format",
		"[4]Ed[16]b "
		"(mach0_load_command_type)cmd cmdsize uuid",
		0);
	sdb_set (kv, "mach0_rpath_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize path_offset path",
		0);
	sdb_set (kv, "mach0_entry_point_command.format",
		"[4]Edqq "
		"(mach0_load_command_type)cmd cmdsize entryoff stacksize",
		0);
	sdb_set (kv, "mach0_encryption_info64_command.format",
		"[4]Edxddx "
		"(mach0_load_command_type)cmd cmdsize offset size id padding",
		0);
	sdb_set (kv, "mach0_encryption_info_command.format",
		"[4]Edxdd "
		"(mach0_load_command_type)cmd cmdsize offset size id",
		0);
	sdb_set (kv, "mach0_code_signature_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_dyld_info_only_command.format",
		"[4]Edxdxdxdxdxd "
		"(mach0_load_command_type)cmd cmdsize rebase_off rebase_size bind_off bind_size weak_bind_off weak_bind_size lazy_bind_off lazy_bind_size export_off export_size",
		0);
	sdb_set (kv, "mach0_load_dylinker_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set (kv, "mach0_id_dylinker_command.format",
		"[4]Edxzi "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set (kv, "mach0_build_version_command.format",
		"[4]Ed[4]Exxd "
		"(mach0_load_command_type)cmd cmdsize (mach0_build_platform)platform minos sdk ntools",
		0);
	sdb_set (kv, "mach0_build_version_tool.format",
		"[4]Ex "
		"(mach0_build_tool)tool version",
		0);
	sdb_set (kv, "mach0_source_version_command.format",
		"[4]Edq "
		"(mach0_load_command_type)cmd cmdsize version",
		0);
	sdb_set (kv, "mach0_function_starts_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_data_in_code_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_version_min_command.format",
		"[4]Edxx "
		"(mach0_load_command_type)cmd cmdsize version reserved",
		0);
	sdb_set (kv, "mach0_segment_split_info_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set (kv, "mach0_unixthread_command.format",
		"[4]Eddd "
		"(mach0_load_command_type)cmd cmdsize flavor count",
		0);
	sdb_set (kv, "mach0_aot_metadata.format",
		"[4]Eddddddd "
		"(mach0_load_command_type)cmd cmdsize imagepathoffset imagepathlen field10 field14 x64code field1c",
		0);
}

static bool init_hdr(struct MACH0_(obj_t) *mo) {
	ut8 magicbytes[4] = {0};
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = {0};

	if (r_buf_read_at (mo->b, 0 + mo->header_at, magicbytes, 4) < 1) {
		return false;
	}
	if (r_read_le32 (magicbytes) == 0xfeedface) {
		mo->big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedface) {
		mo->big_endian = true;
	} else if (r_read_le32 (magicbytes) == FAT_MAGIC) {
		mo->big_endian = false;
	} else if (r_read_be32 (magicbytes) == FAT_MAGIC) {
		mo->big_endian = true;
	} else if (r_read_le32 (magicbytes) == 0xfeedfacf) {
		mo->big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedfacf) {
		mo->big_endian = true;
	} else {
		return false; // object files are magic == 0, but body is different :?
	}
	int len = r_buf_read_at (mo->b, mo->header_at, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof (machohdrbytes)) {
		R_LOG_WARN ("cannot read magic header");
		return false;
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

static bool parse_segments(struct MACH0_(obj_t) *mo, ut64 off) {
	size_t i, j, k, sect, len;
	ut32 size_sects;
	ut8 segcom[sizeof (struct MACH0_(segment_command))] = {0};
	ut8 sec[sizeof (struct MACH0_(section))] = {0};
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
	if (!(mo->segs = realloc (mo->segs, mo->nsegs * sizeof (struct MACH0_(segment_command))))) {
		r_sys_perror ("realloc (seg)");
		return false;
	}
	j = mo->nsegs - 1;
	len = r_buf_read_at (mo->b, off, segcom, sizeof (struct MACH0_(segment_command)));
	if (len != sizeof (struct MACH0_(segment_command))) {
		R_LOG_ERROR ("read (seg)");
		return false;
	}
	const ut8 *scp = (const ut8*)&segcom;
	mo->segs[j].cmd = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].cmdsize = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	memcpy (&mo->segs[j].segname, scp, 16);
	scp += 16;
#if R_BIN_MACH064
	mo->segs[j].vmaddr = r_read_ble64 (scp, mo->big_endian);
	scp += sizeof (ut64);
	mo->segs[j].vmsize = r_read_ble64 (scp, mo->big_endian);
	scp += sizeof (ut64);
	mo->segs[j].fileoff = r_read_ble64 (scp, mo->big_endian);
	scp += sizeof (ut64);
	mo->segs[j].filesize = r_read_ble64 (scp, mo->big_endian);
	scp += sizeof (ut64);
#else
	mo->segs[j].vmaddr = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].vmsize = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].fileoff = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].filesize = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
#endif
	mo->segs[j].maxprot = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].initprot = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].nsects = r_read_ble32 (scp, mo->big_endian);
	scp += sizeof (ut32);
	mo->segs[j].flags = r_read_ble32 (scp, mo->big_endian);

	char *segment_flagname = NULL;
#if R_BIN_MACH064
	segment_flagname = r_str_newf ("mach0_segment64_%u.offset", (ut32)j);
#else
	segment_flagname = r_str_newf ("mach0_segment_%u.offset", (ut32)j);
#endif
	sdb_num_set (mo->kv, segment_flagname, off, 0);
	free (segment_flagname);
	sdb_num_set (mo->kv, "mach0_segments.count", 0, 0);

	if (mo->segs[j].nsects > 0) {
		sect = mo->nsects;
		mo->nsects += mo->segs[j].nsects;
		if (mo->nsects > MACHO_MAX_SECTIONS) {
			int new_nsects = mo->nsects & 0xf;
			R_LOG_WARN ("mach0 header contains too many sections (%d). Wrapping to %d",
				 mo->nsects, new_nsects);
			mo->nsects = new_nsects;
		}
		if ((int)mo->nsects < 1) {
			R_LOG_WARN ("Invalid number of sections");
			mo->nsects = sect;
			return false;
		}
		if (!UT32_MUL (&size_sects, mo->nsects-sect, sizeof (struct MACH0_(section)))) {
			mo->nsects = sect;
			return false;
		}
		if (!size_sects || size_sects > mo->size) {
			mo->nsects = sect;
			return false;
		}
		if (mo->segs[j].cmdsize != sizeof (struct MACH0_(segment_command)) \
				  + (sizeof (struct MACH0_(section))*mo->segs[j].nsects)) {
			mo->nsects = sect;
			return false;
		}

		if (off + sizeof (struct MACH0_(segment_command)) > mo->size ||\
				off + sizeof (struct MACH0_(segment_command)) + size_sects > mo->size) {
			mo->nsects = sect;
			return false;
		}

		if (!(mo->sects = realloc (mo->sects, mo->nsects * sizeof (struct MACH0_(section))))) {
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

			i = 0;
			memcpy (&mo->sects[k].sectname, &sec[i], 16); // INFO: this string is not null terminated!
			i += 16;
			memcpy (&mo->sects[k].segname, &sec[i], 16); // INFO: Remember: it's not null terminated!
			i += 16;
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.offset",
						mo->sects[k].segname, mo->sects[k].sectname);
			sdb_num_set (mo->kv, section_flagname, offset, 0);
#if R_BIN_MACH064
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.format",
						mo->sects[k].segname, mo->sects[k].sectname);
			sdb_set (mo->kv, section_flagname, "mach0_section64", 0);
#else
			snprintf (section_flagname, sizeof (section_flagname), "mach0_section_%.16s_%.16s.format",
						mo->sects[k].segname, mo->sects[k].sectname);
			sdb_set (mo->kv, section_flagname, "mach0_section", 0);
#endif

			const ut8 *scp = &sec[i];
			const bool be = mo->big_endian;
#if R_BIN_MACH064
			mo->sects[k].addr = r_read_ble64 (scp, be);
			scp += sizeof (ut64);
			mo->sects[k].size = r_read_ble64 (scp, be);
			scp += sizeof (ut64);
#else
			mo->sects[k].addr = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].size = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
#endif
			mo->sects[k].offset = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].align = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].reloff = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].nreloc = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].flags = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].reserved1 = r_read_ble32 (scp, be);
			scp += sizeof (ut32);
			mo->sects[k].reserved2 = r_read_ble32 (scp, be);
#if R_BIN_MACH064
			scp += sizeof (ut32);
			mo->sects[k].reserved3 = r_read_ble32 (scp, be);
#endif
		}
	}
	return true;
}

#define Error(x) error_message = x; goto error;
static bool parse_symtab(struct MACH0_(obj_t) *mo, ut64 off) {
	struct symtab_command st;
	ut32 size_sym;
	size_t i;
	const char *error_message = "";
	ut8 symt[sizeof (struct symtab_command)] = {0};
	ut8 nlst[sizeof (struct MACH0_(nlist))] = {0};
	const bool be = mo->big_endian;

	if (off > (ut64)mo->size || off + sizeof (struct symtab_command) > (ut64)mo->size) {
		return false;
	}
	int len = r_buf_read_at (mo->b, off, symt, sizeof (struct symtab_command));
	if (len != sizeof (struct symtab_command)) {
		R_LOG_ERROR ("read (symtab)");
		return false;
	}
	st.cmd = r_read_ble32 (symt, be);
	st.cmdsize = r_read_ble32 (symt + 4, be);
	st.symoff = r_read_ble32 (symt + 8, be) + mo->symbols_off;
	st.nsyms = r_read_ble32 (symt + 12, be);
	st.stroff = r_read_ble32 (symt + 16, be) + mo->symbols_off;
	st.strsize = r_read_ble32 (symt + 20, be);

	mo->symtab = NULL;
	mo->nsymtab = 0;
	if (st.strsize > 0 && st.strsize < mo->size && st.nsyms > 0) {
		mo->nsymtab = st.nsyms;
		if (st.stroff > mo->size || st.stroff + st.strsize > mo->size) {
			Error ("fail");
		}
		if (!UT32_MUL (&size_sym, mo->nsymtab, sizeof (struct MACH0_(nlist)))) {
			Error ("fail2");
		}
		if (!size_sym) {
			Error ("symbol size is zero");
		}
		if (st.symoff > mo->size || st.symoff + size_sym > mo->size) {
			Error ("symoff is out of bounds");
		}
		if (!(mo->symstr = calloc (1, st.strsize + 2))) {
			Error ("symoff is out of bounds");
		}
		mo->symstrlen = st.strsize;
		len = r_buf_read_at (mo->b, st.stroff, (ut8*)mo->symstr, st.strsize);
		if (len != st.strsize) {
			Error ("Error: read (symstr)");
		}
		ut64 max_nsymtab = (r_buf_size (mo->b) - st.symoff) / sizeof (struct MACH0_(nlist));
		if (mo->nsymtab > max_nsymtab || !(mo->symtab = calloc (mo->nsymtab, sizeof (struct MACH0_(nlist))))) {
			goto error;
		}
		for (i = 0; i < mo->nsymtab; i++) {
			ut64 at = st.symoff + (i * sizeof (struct MACH0_(nlist)));
			len = r_buf_read_at (mo->b, at, nlst, sizeof (struct MACH0_(nlist)));
			if (len != sizeof (struct MACH0_(nlist))) {
				Error ("read (nlist)");
			}
			struct MACH0_(nlist) *sti = &mo->symtab[i];
			//XXX not very safe what if is n_un.n_name instead?
			sti->n_strx = r_read_ble32 (nlst, be);
			sti->n_type = r_read_ble8 (nlst + 4);
			sti->n_sect = r_read_ble8 (nlst + 5);
			sti->n_desc = r_read_ble16 (nlst + 6, be);
#if R_BIN_MACH064
			sti->n_value = r_read_ble64 (&nlst[8], be);
#else
			sti->n_value = r_read_ble32 (&nlst[8], be);
#endif
		}
	}
	return true;
error:
	R_FREE (mo->symstr);
	R_FREE (mo->symtab);
	R_LOG_ERROR ("parse.symtab: %s", error_message);
	return false;
}

static bool parse_aot_metadata(struct MACH0_(obj_t) *mo, ut64 off) {
	ut32 words[8];
	if (r_buf_fread_at (mo->b, off, (ut8*)&words, "8i", 1) == -1) {
		return false;
	}
	// TODO: add flags for this or sthg
	R_LOG_INFO ("AOT: Image path offset: 0x%08x", words[2]);
	R_LOG_INFO ("AOT: Image path length: 0x%08x", words[3]);
	R_LOG_INFO ("AOT: X64- code section: 0x%08x", words[6]);
	return true;
}

static bool parse_dysymtab(struct MACH0_(obj_t) *mo, ut64 off) {
	size_t len, i;
	ut32 size_tab;
	ut8 dysym[sizeof (struct dysymtab_command)] = {0};
	ut8 dytoc[sizeof (struct dylib_table_of_contents)] = {0};
	ut8 dymod[sizeof (struct MACH0_(dylib_module))] = {0};
	ut8 idsyms[sizeof (ut32)] = {0};

	if (off > mo->size || off + sizeof (struct dysymtab_command) >= mo->size) {
		return false;
	}

	len = r_buf_read_at (mo->b, off, dysym, sizeof (struct dysymtab_command));
	if (len != sizeof (struct dysymtab_command)) {
		R_LOG_ERROR ("read (dysymtab)");
		return false;
	}
	// use r_buf_fread instead of all this duck typing
	mo->dysymtab.cmd = r_read_ble32 (&dysym[0], mo->big_endian);
	mo->dysymtab.cmdsize = r_read_ble32 (&dysym[4], mo->big_endian);
	mo->dysymtab.ilocalsym = r_read_ble32 (&dysym[8], mo->big_endian);
	mo->dysymtab.nlocalsym = r_read_ble32 (&dysym[12], mo->big_endian);
	mo->dysymtab.iextdefsym = r_read_ble32 (&dysym[16], mo->big_endian);
	mo->dysymtab.nextdefsym = r_read_ble32 (&dysym[20], mo->big_endian);
	mo->dysymtab.iundefsym = r_read_ble32 (&dysym[24], mo->big_endian);
	mo->dysymtab.nundefsym = r_read_ble32 (&dysym[28], mo->big_endian);
	mo->dysymtab.tocoff = r_read_ble32 (&dysym[32], mo->big_endian);
	mo->dysymtab.ntoc = r_read_ble32 (&dysym[36], mo->big_endian);
	mo->dysymtab.modtaboff = r_read_ble32 (&dysym[40], mo->big_endian);
	mo->dysymtab.nmodtab = r_read_ble32 (&dysym[44], mo->big_endian);
	mo->dysymtab.extrefsymoff = r_read_ble32 (&dysym[48], mo->big_endian);
	mo->dysymtab.nextrefsyms = r_read_ble32 (&dysym[52], mo->big_endian);
	mo->dysymtab.indirectsymoff = r_read_ble32 (&dysym[56], mo->big_endian);
	mo->dysymtab.nindirectsyms = r_read_ble32 (&dysym[60], mo->big_endian);
	mo->dysymtab.extreloff = r_read_ble32 (&dysym[64], mo->big_endian);
	mo->dysymtab.nextrel = r_read_ble32 (&dysym[68], mo->big_endian);
	mo->dysymtab.locreloff = r_read_ble32 (&dysym[72], mo->big_endian);
	mo->dysymtab.nlocrel = r_read_ble32 (&dysym[76], mo->big_endian);

	mo->ntoc = mo->dysymtab.ntoc;
	if (mo->ntoc > 0) {
		if (!(mo->toc = calloc (mo->ntoc, sizeof (struct dylib_table_of_contents)))) {
			r_sys_perror ("calloc (toc)");
			return false;
		}
		if (!UT32_MUL (&size_tab, mo->ntoc, sizeof (struct dylib_table_of_contents))) {
			R_FREE (mo->toc);
			return false;
		}
		if (!size_tab) {
			R_FREE (mo->toc);
			return false;
		}
		if (mo->dysymtab.tocoff > mo->size || mo->dysymtab.tocoff + size_tab > mo->size) {
			R_FREE (mo->toc);
			return false;
		}
		for (i = 0; i < mo->ntoc; i++) {
			len = r_buf_read_at (mo->b, mo->dysymtab.tocoff +
				i * sizeof (struct dylib_table_of_contents),
				dytoc, sizeof (struct dylib_table_of_contents));
			if (len != sizeof (struct dylib_table_of_contents)) {
				R_LOG_ERROR ("read (toc)");
				R_FREE (mo->toc);
				return false;
			}
			mo->toc[i].symbol_index = r_read_ble32 (&dytoc[0], mo->big_endian);
			mo->toc[i].module_index = r_read_ble32 (&dytoc[4], mo->big_endian);
		}
	}
	mo->nmodtab = mo->dysymtab.nmodtab;
	ut64 max_nmodtab = (mo->size - mo->dysymtab.modtaboff) / sizeof (struct MACH0_(dylib_module));
	if (mo->nmodtab > 0 && mo->nmodtab <= max_nmodtab) {
		if (!(mo->modtab = calloc (mo->nmodtab, sizeof (struct MACH0_(dylib_module))))) {
			r_sys_perror ("calloc (modtab)");
			return false;
		}
		if (!UT32_MUL (&size_tab, mo->nmodtab, sizeof (struct MACH0_(dylib_module)))) {
			R_FREE (mo->modtab);
			return false;
		}
		if (!size_tab) {
			R_FREE (mo->modtab);
			return false;
		}
		if (mo->dysymtab.modtaboff > mo->size || \
		  mo->dysymtab.modtaboff + size_tab > mo->size) {
			R_FREE (mo->modtab);
			return false;
		}
		for (i = 0; i < mo->nmodtab; i++) {
			len = r_buf_read_at (mo->b, mo->dysymtab.modtaboff +
				i * sizeof (struct MACH0_(dylib_module)),
				dymod, sizeof (struct MACH0_(dylib_module)));
			if (len == -1) {
				R_LOG_ERROR ("read (modtab)");
				R_FREE (mo->modtab);
				return false;
			}
			// TODO: reduce dereferences
			mo->modtab[i].module_name = r_read_ble32 (&dymod[0], mo->big_endian);
			mo->modtab[i].iextdefsym = r_read_ble32 (&dymod[4], mo->big_endian);
			mo->modtab[i].nextdefsym = r_read_ble32 (&dymod[8], mo->big_endian);
			mo->modtab[i].irefsym = r_read_ble32 (&dymod[12], mo->big_endian);
			mo->modtab[i].nrefsym = r_read_ble32 (&dymod[16], mo->big_endian);
			mo->modtab[i].ilocalsym = r_read_ble32 (&dymod[20], mo->big_endian);
			mo->modtab[i].nlocalsym = r_read_ble32 (&dymod[24], mo->big_endian);
			mo->modtab[i].iextrel = r_read_ble32 (&dymod[28], mo->big_endian);
			mo->modtab[i].nextrel = r_read_ble32 (&dymod[32], mo->big_endian);
			mo->modtab[i].iinit_iterm = r_read_ble32 (&dymod[36], mo->big_endian);
			mo->modtab[i].ninit_nterm = r_read_ble32 (&dymod[40], mo->big_endian);
#if R_BIN_MACH064
			mo->modtab[i].objc_module_info_size = r_read_ble32 (&dymod[44], mo->big_endian);
			mo->modtab[i].objc_module_info_addr = r_read_ble64 (&dymod[48], mo->big_endian);
#else
			mo->modtab[i].objc_module_info_addr = r_read_ble32 (&dymod[44], mo->big_endian);
			mo->modtab[i].objc_module_info_size = r_read_ble32 (&dymod[48], mo->big_endian);
#endif
		}
	}
	mo->nindirectsyms = mo->dysymtab.nindirectsyms;
	if (mo->nindirectsyms > 0) {
		if (!(mo->indirectsyms = calloc (mo->nindirectsyms, sizeof (ut32)))) {
			r_sys_perror ("calloc (indirectsyms)");
			return false;
		}
		if (!UT32_MUL (&size_tab, mo->nindirectsyms, sizeof (ut32))) {
			R_FREE (mo->indirectsyms);
			return false;
		}
		if (!size_tab) {
			R_FREE (mo->indirectsyms);
			return false;
		}
		if (mo->dysymtab.indirectsymoff > mo->size || \
				mo->dysymtab.indirectsymoff + size_tab > mo->size) {
			R_FREE (mo->indirectsyms);
			return false;
		}
		for (i = 0; i < mo->nindirectsyms; i++) {
			len = r_buf_read_at (mo->b, mo->dysymtab.indirectsymoff + i * sizeof (ut32), idsyms, 4);
			if (len == -1) {
				R_LOG_ERROR ("read (indirect syms)");
				R_FREE (mo->indirectsyms);
				return false;
			}
			mo->indirectsyms[i] = r_read_ble32 (&idsyms[0], mo->big_endian);
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

static void parseCodeDirectory(RBuffer *b, int offset, int datasize) {
	typedef struct __CodeDirectory {
		uint32_t magic;		/* magic number (CSMAGIC_CODEDIRECTORY) */
		uint32_t length;	/* total length of CodeDirectory blob */
		uint32_t version;	/* compatibility version */
		uint32_t flags;		/* setup and mode flags */
		uint32_t hashOffset;	/* offset of hash slot element at index zero */
		uint32_t identOffset;	/* offset of identifier string */
		uint32_t nSpecialSlots;	/* number of special hash slots */
		uint32_t nCodeSlots;	/* number of ordinary (code) hash slots */
		uint32_t codeLimit;	/* limit to main image signature range */
		uint8_t hashSize;	/* size of each hash in bytes */
		uint8_t hashType;	/* type of hash (cdHashType* constants) */
		uint8_t platform;	/* unused (must be zero) */
		uint8_t	pageSize;	/* log2(page size in bytes); 0 => infinite */
		uint32_t spare2;	/* unused (must be zero) */
		/* followed by dynamic content as located by offset fields above */
		uint32_t scatterOffset;
		uint32_t teamIDOffset;
		uint32_t spare3;
		ut64 codeLimit64;
		ut64 execSegBase;
		ut64 execSegLimit;
		ut64 execSegFlags;
	} CS_CodeDirectory;
	ut64 off = offset;
	int psize = datasize;
	ut8 *p = calloc (1, psize);
	if (!p) {
		return;
	}
	R_LOG_INFO ("Offset: 0x%08"PFMT64x, off);
	r_buf_read_at (b, off, p, datasize);
	CS_CodeDirectory cscd = {0};
	#define READFIELD(x) cscd.x = r_read_ble32 (p + r_offsetof (CS_CodeDirectory, x), 1)
	#define READFIELD8(x) cscd.x = p[r_offsetof (CS_CodeDirectory, x)]
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
	int algoType = R_HASH_SHA1;
	const char *hashName = "sha1";
	switch (cscd.hashType) {
	case 0: // SHA1 == 20 bytes
	case 1: // SHA1 == 20 bytes
		hashSize = 20;
		hashName = "sha1";
		algoType = R_HASH_SHA1;
		break;
	case 2: // SHA256 == 32 bytes
		hashSize = 32;
		algoType = R_HASH_SHA256;
		hashName = "sha256";
		break;
	}
	// computed cdhash
	RHash *ctx = r_hash_new (true, algoType);
	int fofsz = cscd.length;
	if (fofsz > 0 && fofsz < (r_buf_size (b) - off)) {
		ut8 *fofbuf = calloc (fofsz, 1);
		if (fofbuf) {
			int i;
			if (r_buf_read_at (b, off, fofbuf, fofsz) != fofsz) {
				R_LOG_WARN ("Invalid cdhash offset/length values");
			}
			r_hash_do_begin (ctx, algoType);
			if (algoType == R_HASH_SHA1) {
				r_hash_do_sha1 (ctx, fofbuf, fofsz);
			} else {
				r_hash_do_sha256 (ctx, fofbuf, fofsz);
			}
			r_hash_do_end (ctx, algoType);
			eprintf ("ph %s @ 0x%"PFMT64x"!%d\n", hashName, off, fofsz);
			eprintf ("ComputedCDHash: ");
			for (i = 0; i < hashSize;i++) {
				eprintf ("%02x", ctx->digest[i]);
			}
			eprintf ("\n");
			free (fofbuf);
		}
	}
	// show and check the rest of hashes
	ut8 *hash = p + cscd.hashOffset;
	int j = 0;
	int k = 0;
	eprintf ("Hashed region: 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", (ut64)0, (ut64)cscd.codeLimit);
	for (j = 0; j < cscd.nCodeSlots; j++) {
		int fof = 4096 * j;
		int idx = j * hashSize;
		eprintf ("0x%08"PFMT64x"  ", off + cscd.hashOffset + idx);
		for (k = 0; k < hashSize; k++) {
			eprintf ("%02x", hash[idx + k]);
		}
		ut8 fofbuf[4096];
		int fofsz = R_MIN (sizeof (fofbuf), cscd.codeLimit - fof);
		r_buf_read_at (b, fof, fofbuf, sizeof (fofbuf));
		r_hash_do_begin (ctx, algoType);
		if (algoType == R_HASH_SHA1) {
			r_hash_do_sha1 (ctx, fofbuf, fofsz);
		} else {
			r_hash_do_sha256 (ctx, fofbuf, fofsz);
		}
		r_hash_do_end (ctx, algoType);
		if (memcmp (hash + idx, ctx->digest, hashSize)) {
			eprintf ("  wx ");
			int i;
			for (i = 0; i < hashSize;i++) {
				eprintf ("%02x", ctx->digest[i]);
			}
		} else {
			eprintf ("  OK");
		}
		eprintf ("\n");
	}
	r_hash_free (ctx);
	free (p);
}

// parse the Load Command
static bool parse_signature(struct MACH0_(obj_t) *mo, ut64 off) {
	int i,len;
	ut32 data;
	mo->signature = NULL;
	struct linkedit_data_command link = {0};
	ut8 lit[sizeof (struct linkedit_data_command)] = {0};
	struct blob_index_t idx = {0};
	struct super_blob_t super = {{0}};

	if (off > mo->size || off + sizeof (struct linkedit_data_command) > mo->size) {
		return false;
	}
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
	if (data > mo->size || data + sizeof (struct super_blob_t) > mo->size) {
		mo->signature = (ut8 *)strdup ("Malformed entitlement");
		return true;
	}
	super.blob.magic = r_buf_read_ble32_at (mo->b, data, mach0_endian);
	super.blob.length = r_buf_read_ble32_at (mo->b, data + 4, mach0_endian);
	super.count = r_buf_read_ble32_at (mo->b, data + 8, mach0_endian);
	// XXX deprecate
	bool isVerbose = r_sys_getenv_asbool ("RABIN2_CODESIGN_VERBOSE");
	// to dump all certificates
	// [0x00053f75]> b 5K;/x 30800609;wtf @@ hit*
	// then do this:
	// $ openssl asn1parse -inform der -in a|less
	// $ openssl pkcs7 -inform DER -print_certs -text -in a
	// uhm we have pFa to parse der/asn1 we can do it inline
	for (i = 0; i < super.count; i++) {
		if (data + i > mo->size) {
			mo->signature = (ut8 *)strdup ("Malformed entitlement");
			break;
		}
		struct blob_index_t bi = { 0 };
		if (r_buf_read_at (mo->b, data + 12 + (i * sizeof (struct blob_index_t)),
			(ut8*)&bi, sizeof (struct blob_index_t)) < sizeof (struct blob_index_t)) {
			break;
		}
		if (i > 32 && idx.type == 0 && idx.offset == 0) {
			break;
		}
		idx.type = r_read_ble32 (&bi.type, mach0_endian);
		idx.offset = r_read_ble32 (&bi.offset, mach0_endian);
		switch (idx.type) {
		case CSSLOT_ENTITLEMENTS:
			if (true || isVerbose) {
				ut64 off = data + idx.offset;
				if (off > mo->size || off + sizeof (struct blob_t) > mo->size) {
					mo->signature = (ut8 *)strdup ("Malformed entitlement");
					break;
				}
				struct blob_t entitlements = {0};
				entitlements.magic = r_buf_read_ble32_at (mo->b, off, mach0_endian);
				entitlements.length = r_buf_read_ble32_at (mo->b, off + 4, mach0_endian);
				len = entitlements.length - sizeof (struct blob_t);
				if (len <= mo->size && len > 1) {
					mo->signature = calloc (1, len + 1);
					if (!mo->signature) {
						break;
					}
					if (off + sizeof (struct blob_t) + len < r_buf_size (mo->b)) {
						r_buf_read_at (mo->b, off + sizeof (struct blob_t), (ut8 *)mo->signature, len);
						if (len >= 0) {
							mo->signature[len] = '\0';
						}
					} else {
						mo->signature = (ut8 *)strdup ("Malformed entitlement");
					}
				} else {
					mo->signature = (ut8 *)strdup ("Malformed entitlement");
				}
			}
			break;
		case CSSLOT_CODEDIRECTORY:
			if (isVerbose) {
				parseCodeDirectory (mo->b, data + idx.offset, link.datasize);
			}
			break;
		case 0x1000:
			// unknown
			break;
		case CSSLOT_CMS_SIGNATURE: // ASN1/DER certificate
			if (isVerbose) {
				ut8 header[8] = {0};
				r_buf_read_at (mo->b, data + idx.offset, header, sizeof (header));
				ut32 length = R_MIN (UT16_MAX, r_read_ble32 (header + 4, 1));
				ut8 *p = calloc (length, 1);
				if (p) {
					r_buf_read_at (mo->b, data + idx.offset + 0, p, length);
					ut32 *words = (ut32*)p;
					eprintf ("Magic: %x\n", words[0]);
					eprintf ("wtf DUMP @%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf ("openssl pkcs7 -print_certs -text -inform der -in DUMP\n");
					eprintf ("openssl asn1parse -offset %d -length %d -inform der -in /mo/ls\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf ("pFp@%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					free (p);
				}
			}
			break;
		case CSSLOT_REQUIREMENTS: // 2
			{
				ut8 p[256];
				r_buf_read_at (mo->b, data + idx.offset + 16, p, sizeof (p));
				p[sizeof (p) - 1] = 0;
				ut32 slot_size = r_read_ble32 (p + 8, 1);
				if (slot_size < sizeof (p)) {
					ut32 ident_size = r_read_ble32 (p + 8, 1);
					if (!ident_size || ident_size > sizeof (p) - 28) {
						break;
					}
					char *ident = r_str_ndup ((const char *)p + 28, ident_size);
					if (ident) {
						sdb_set (mo->kv, "mach0.ident", ident, 0);
						free (ident);
					}
				} else {
					R_LOG_DEBUG ("Invalid code slot size");
				}
			}
			break;
		case CSSLOT_INFOSLOT: // 1;
		case CSSLOT_RESOURCEDIR: // 3;
		case CSSLOT_APPLICATION: // 4;
			// TODO: parse those codesign slots
			if (mo->verbose) {
				R_LOG_TODO ("Some codesign slots are not yet supported");
			}
			break;
		default:
			if (mo->verbose) {
				R_LOG_WARN ("Unknown Code signature slot %d", idx.type);
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

static int parse_thread(struct MACH0_(obj_t) *mo, struct load_command *lc, ut64 off, bool is_first_thread) {
	ut64 ptr_thread, pc = UT64_MAX, pc_offset = UT64_MAX;
	ut32 flavor, count;
	ut8 *arw_ptr = NULL;
	int arw_sz = 0;
	int len = 0;
	ut8 thc[sizeof (struct thread_command)] = {0};
	ut8 tmp[4];

	if (off > mo->size || off + sizeof (struct thread_command) > mo->size) {
		return false;
	}

	len = r_buf_read_at (mo->b, off, thc, 8);
	if (len < 1) {
		goto wrong_read;
	}
	mo->thread.cmd = r_read_ble32 (&thc[0], mo->big_endian);
	mo->thread.cmdsize = r_read_ble32 (&thc[4], mo->big_endian);
	if (r_buf_read_at (mo->b, off + sizeof (struct thread_command), tmp, 4) < 4) {
		goto wrong_read;
	}
	flavor = r_read_ble32 (tmp, mo->big_endian);

	if (off + sizeof (struct thread_command) + sizeof (flavor) > mo->size ||
		off + sizeof (struct thread_command) + sizeof (flavor) + sizeof (ut32) > mo->size) {
		return false;
	}

	// TODO: use count for checks
	if (r_buf_read_at (mo->b, off + sizeof (struct thread_command) + sizeof (flavor), tmp, 4) < 4) {
		goto wrong_read;
	}
	count = r_read_ble32 (tmp, mo->big_endian);
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
			if (r_buf_fread_at (mo->b, ptr_thread,
				(ut8*)&mo->thread_state.x86_32, "16i", 1) == -1) {
				R_LOG_ERROR ("read (thread state x86_32)");
				return false;
			}
			pc = mo->thread_state.x86_32.eip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state32, eip);
			arw_ptr = (ut8 *)&mo->thread_state.x86_32;
			arw_sz = sizeof (struct x86_thread_state32);
			break;
		case X86_THREAD_STATE64:
			if (ptr_thread + sizeof (struct x86_thread_state64) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread,
				(ut8*)&mo->thread_state.x86_64, "32l", 1) == -1) {
				R_LOG_ERROR ("read (thread state x86_64)");
				return false;
			}
			pc = mo->thread_state.x86_64.rip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&mo->thread_state.x86_64;
			arw_sz = sizeof (struct x86_thread_state64);
			break;
		//default: bprintf ("Unknown type\n");
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (flavor == X86_THREAD_STATE32) {
			if (ptr_thread + sizeof (struct ppc_thread_state32) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread,
				(ut8*)&mo->thread_state.ppc_32, mo->big_endian ? "40I" : "40i", 1) == -1) {
				R_LOG_ERROR ("read (thread state ppc_32)");
				return false;
			}
			pc = mo->thread_state.ppc_32.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state32, srr0);
			arw_ptr = (ut8 *)&mo->thread_state.ppc_32;
			arw_sz = sizeof (struct ppc_thread_state32);
		} else if (flavor == X86_THREAD_STATE64) {
			if (ptr_thread + sizeof (struct ppc_thread_state64) > mo->size) {
				return false;
			}
			if (r_buf_fread_at (mo->b, ptr_thread,
				(ut8*)&mo->thread_state.ppc_64, mo->big_endian ? "34LI3LI" : "34li3li", 1) == -1) {
				R_LOG_ERROR ("read (thread state ppc_64)");
				return false;
			}
			pc = mo->thread_state.ppc_64.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state64, srr0);
			arw_ptr = (ut8 *)&mo->thread_state.ppc_64;
			arw_sz = sizeof (struct ppc_thread_state64);
		}
		break;
	case CPU_TYPE_ARM:
		if (ptr_thread + sizeof (struct arm_thread_state32) > mo->size) {
			return false;
		}
		if (r_buf_fread_at (mo->b, ptr_thread,
			(ut8*)&mo->thread_state.arm_32, mo->big_endian ? "17I" : "17i", 1) == -1) {
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
		if (r_buf_fread_at (mo->b, ptr_thread,
			(ut8*)&mo->thread_state.arm_64, mo->big_endian ? "34LI1I" : "34Li1i", 1) == -1) {
			R_LOG_ERROR ("read (thread state arm)");
			return false;
		}
		pc = r_read_be64 (&mo->thread_state.arm_64.pc);
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state64, pc);
		arw_ptr = (ut8*)&mo->thread_state.arm_64;
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

static bool parse_function_starts(struct MACH0_(obj_t) *mo, ut64 off) {
	struct linkedit_data_command fc;
	ut8 sfc[sizeof (struct linkedit_data_command)] = {0};
	if (mo->nofuncstarts) {
		return false;
	}

	if (off > mo->size || off + sizeof (struct linkedit_data_command) > mo->size) {
		R_LOG_DEBUG ("Likely overflow while parsing LC_FUNCTION_STARTS command");
	}
	mo->func_start = NULL;
	int len = r_buf_read_at (mo->b, off, sfc, sizeof (struct linkedit_data_command));
	if (len < 1) {
		R_LOG_WARN ("Failed to get data while parsing LC_FUNCTION_STARTS command");
	}
	fc.cmd = r_read_ble32 (&sfc[0], mo->big_endian);
	fc.cmdsize = r_read_ble32 (&sfc[4], mo->big_endian);
	fc.dataoff = r_read_ble32 (&sfc[8], mo->big_endian);
	fc.datasize = r_read_ble32 (&sfc[12], mo->big_endian);

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

static int parse_dylib(struct MACH0_(obj_t) *mo, ut64 off) {
	ut8 sdl[sizeof (struct dylib_command)] = {0};

	if (off > mo->size || off + sizeof (struct dylib_command) > mo->size) {
		return false;
	}

	char lib[R_BIN_MACH0_STRING_LENGTH] = {0};
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

	len = r_buf_read_at (mo->b, off + dl.dylib.name,
		(ut8*) lib, R_BIN_MACH0_STRING_LENGTH - 1);
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

static size_t get_word_size(struct MACH0_(obj_t) *mo) {
	const size_t word_size = MACH0_(get_bits)(mo) / 8;
	return R_MAX (word_size, 4);
}

static bool parse_chained_fixups(struct MACH0_(obj_t) *mo, ut32 offset, ut32 size) {
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
	mo->chained_starts = R_NEWS0 (struct r_dyld_chained_starts_in_segment *, segs_count);
	if (!mo->chained_starts) {
		return false;
	}
	mo->segs_count = segs_count;
	mo->fixups_header = header;
	mo->fixups_offset = offset;
	mo->fixups_size = size;
	size_t i;
	ut64 cursor = starts_at + sizeof (ut32);
	ut64 bsize = r_buf_size (mo->b);
	for (i = 0; i < segs_count && cursor + 4 < bsize; i++) {
		ut32 seg_off;
		if ((seg_off = r_buf_read_le32_at (mo->b, cursor)) == UT32_MAX || !seg_off) {
			cursor += sizeof (ut32);
			continue;
		}
		if (i >= mo->nsegs) {
			break;
		}
		struct r_dyld_chained_starts_in_segment *cur_seg = R_NEW0 (struct r_dyld_chained_starts_in_segment);
		if (!cur_seg) {
			return false;
		}
		mo->chained_starts[i] = cur_seg;
		if (r_buf_fread_at (mo->b, starts_at + seg_off, (ut8 *)cur_seg, "isslis", 1) != 22) {
			return false;
		}
		if (cur_seg->page_count > 0) {
			ut16 *page_start = malloc (sizeof (ut16) * cur_seg->page_count);
			if (!page_start) {
				return false;
			}
			if (r_buf_fread_at (mo->b, starts_at + seg_off + 22, (ut8 *)page_start, "s", cur_seg->page_count)
					!= cur_seg->page_count * 2) {
				return false;
			}
			cur_seg->page_start = page_start;
		}
		cursor += sizeof (ut32);
	}
	/* TODO: handle also imports, symbols and multiple starts (32-bit only) */
	return true;
}

static bool reconstruct_chained_fixup(struct MACH0_(obj_t) *mo) {
	R_LOG_DEBUG ("reconstructing chained fixups");
	if (!mo->dyld_info) {
		return false;
	}
	if (!mo->nsegs) {
		return false;
	}
	mo->chained_starts = R_NEWS0 (struct r_dyld_chained_starts_in_segment *, mo->nsegs);
	if (!mo->chained_starts) {
		return false;
	}
	size_t wordsize = get_word_size (mo);
	ut8 *p = NULL;
	size_t j, count, skip;
	int seg_idx = 0;
	ut64 seg_off = 0;
	size_t bind_size = mo->dyld_info->bind_size;
	if (!bind_size || bind_size < 1) {
		return false;
	}
	if (mo->dyld_info->bind_off > mo->size) {
		return false;
	}
	if (mo->dyld_info->bind_off + bind_size > mo->size) {
		return false;
	}
	ut8 *opcodes = calloc (1, bind_size + 1);
	if (!opcodes) {
		return false;
	}
	if (r_buf_read_at (mo->b, mo->dyld_info->bind_off, opcodes, bind_size) != bind_size) {
		R_LOG_ERROR ("read (dyld_info bind) at 0x%08"PFMT64x, (ut64)(size_t)mo->dyld_info->bind_off);
		R_FREE (opcodes);
		return false;
	}
	struct r_dyld_chained_starts_in_segment *cur_seg = NULL;
	size_t cur_seg_idx = 0;
	ut8 *end;
	bool done = false;
	for (p = opcodes, end = opcodes + bind_size; !done && p < end;) {
		ut8 imm = *p & BIND_IMMEDIATE_MASK, op = *p & BIND_OPCODE_MASK;
		p++;
		switch (op) {
		case BIND_OPCODE_DONE:
			done = true;
			break;
		case BIND_OPCODE_THREADED: {
			switch (imm) {
			case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
				read_uleb128 (&p, end);
				break;
			}
			case BIND_SUBOPCODE_THREADED_APPLY: {
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
						cur_seg->page_count = ((mo->segs[seg_idx].vmsize + (ps - 1)) & ~(ps - 1)) / ps;
						if (cur_seg->page_count > 0) {
							cur_seg->page_start = R_NEWS0 (ut16, cur_seg->page_count);
							if (!cur_seg->page_start) {
								break;
							}
							memset (cur_seg->page_start, 0xff, sizeof (ut16) * cur_seg->page_count);
						}
					}
				}
				if (cur_seg) {
					ut32 page_index = (ut32)(seg_off / ps);
					if (page_index < cur_seg->page_count && cur_seg->page_start) {
						cur_seg->page_start[page_index] = seg_off & 0xfff;
					}
				}
				break;
			}
			default:
				R_LOG_ERROR ("Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x", imm);
			}
			break;
		}
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
			} else {
				seg_off = read_uleb128 (&p, end);
			}
			break;
		case BIND_OPCODE_ADD_ADDR_ULEB:
			seg_off += read_uleb128 (&p, end);
			break;
		case BIND_OPCODE_DO_BIND:
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			seg_off += read_uleb128 (&p, end) + wordsize;
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			seg_off += (ut64)imm * (ut64)wordsize + wordsize;
			break;
		case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			count = read_uleb128 (&p, end);
			skip = read_uleb128 (&p, end);
			for (j = 0; j < count; j++) {
				seg_off += skip + wordsize;
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

static int init_items(struct MACH0_(obj_t) *mo) {
	bool skip_chained_fixups = r_sys_getenv_asbool ("RABIN2_MACHO_SKIPFIXUPS");
	struct load_command lc = {0, 0};
	ut8 loadc[sizeof (struct load_command)] = {0};
	bool is_first_thread = true;
	ut64 off = 0LL;
	int i, len;
	char cmd_flagname[128];

	mo->uuidn = 0;
	mo->os = 0;
	mo->has_crypto = false;
	mo->segments_vec = NULL;
	RVecMach0Lib_init (&mo->libs_cache);

	if (mo->hdr.sizeofcmds > mo->size) {
		R_LOG_WARN ("chopping hdr.sizeofcmds because it's larger than the file size");
		mo->hdr.sizeofcmds = mo->size - 128;
		// return false;
	}
	bool noFuncStarts = mo->nofuncstarts;
	//bprintf ("Commands: %d\n", mo->hdr.ncmds);
	for (i = 0, off = sizeof (struct MACH0_(mach_header)) + mo->header_at; \
			i < mo->hdr.ncmds; i++, off += lc.cmdsize) {
		if (off > mo->size || off + sizeof (struct load_command) > mo->size) {
			R_LOG_WARN ("out of bounds macho command");
			return false;
		}
		len = r_buf_read_at (mo->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			R_LOG_ERROR ("read (lc) at 0x%08"PFMT64x, off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], mo->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], mo->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > mo->size) {
			R_LOG_WARN ("mach0_header %d = cmdsize<1. (0x%"PFMT64x" vs 0x%"PFMT64x")", i,
				(ut64)(off + lc.cmdsize), (ut64)(mo->size));
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
			//bprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set (mo->kv, cmd_flagname, "version_min_iphoneos", 0);
			mo->os = 2;
			// set OS = ios
			//bprintf ("[mach0] Requires iOS >= x\n");
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
			struct uuid_command uc = {0};
			if (off + sizeof (struct uuid_command) > mo->size) {
				R_LOG_DEBUG ("UUID out of bounds");
				return false;
			}
			if (r_buf_fread_at (mo->b, off, (ut8*)&uc, "24c", 1) != -1) {
				char key[128];
				char val[128];
				snprintf (key, sizeof (key)-1, "uuid.%d", mo->uuidn++);
				r_hex_bin2str ((ut8*)&uc.uuid, 16, val);
				sdb_set (mo->kv, key, val, 0);
				// for (i=0;i<16; i++) bprintf ("%02x%c", uc.uuid[i], (i==15)?'\n':'-');
			}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set (mo->kv, cmd_flagname, "encryption_info", 0);
			{
			struct MACH0_(encryption_info_command) eic = {0};
			ut8 seic[sizeof (struct MACH0_(encryption_info_command))] = {0};
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
				sdb_set (mo->kv, "crypto", eic.cryptid ? "true" : "false", 0);
				sdb_num_set (mo->kv, "cryptid", eic.cryptid, 0);
				sdb_num_set (mo->kv, "cryptoff", eic.cryptoff, 0);
				sdb_num_set (mo->kv, "cryptsize", eic.cryptsize, 0);
				sdb_num_set (mo->kv, "cryptheader", off, 0);
			} }
			break;
		case LC_LOAD_DYLINKER:
			{
				sdb_set (mo->kv, cmd_flagname, "dylinker", 0);
				R_FREE (mo->intrp);
				R_LOG_DEBUG ("[mach0] load dynamic linker");
				struct dylinker_command dy = {0};
				ut8 sdy[sizeof (struct dylinker_command)] = {0};
				if (off + sizeof (struct dylinker_command) > mo->size) {
					R_LOG_DEBUG ("Cannot parse dylinker command");
					return false;
				}
				if (r_buf_read_at (mo->b, off, sdy, sizeof (struct dylinker_command)) == -1) {
					R_LOG_DEBUG ("Cannot read (LC_DYLD_INFO) at 0x%08"PFMT64x, off);
				} else {
					dy.cmd = r_read_ble32 (&sdy[0], mo->big_endian);
					dy.cmdsize = r_read_ble32 (&sdy[4], mo->big_endian);
					dy.name = r_read_ble32 (&sdy[8], mo->big_endian);

					int len = dy.cmdsize;
					char *buf = malloc (len+1);
					if (buf) {
						// wtf @ off + 0xc ?
						r_buf_read_at (mo->b, off + 0xc, (ut8*)buf, len);
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
			} ep = {0};
			ut8 sep[2 * sizeof (ut64)] = {0};
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
			ut8 dyldi[sizeof (struct dyld_info_command)] = {0};
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
					R_LOG_DEBUG ("read (LC_DYLD_INFO) at 0x%08"PFMT64x, off);
				} else {
					mo->dyld_info->cmd = r_read_ble32 (&dyldi[0], mo->big_endian);
					mo->dyld_info->cmdsize = r_read_ble32 (&dyldi[4], mo->big_endian);
					mo->dyld_info->rebase_off = r_read_ble32 (&dyldi[8], mo->big_endian);
					mo->dyld_info->rebase_size = r_read_ble32 (&dyldi[12], mo->big_endian);
					mo->dyld_info->bind_off = r_read_ble32 (&dyldi[16], mo->big_endian);
					mo->dyld_info->bind_size = r_read_ble32 (&dyldi[20], mo->big_endian);
					mo->dyld_info->weak_bind_off = r_read_ble32 (&dyldi[24], mo->big_endian);
					mo->dyld_info->weak_bind_size = r_read_ble32 (&dyldi[28], mo->big_endian);
					mo->dyld_info->lazy_bind_off = r_read_ble32 (&dyldi[32], mo->big_endian);
					mo->dyld_info->lazy_bind_size = r_read_ble32 (&dyldi[36], mo->big_endian);
					mo->dyld_info->export_off = r_read_ble32 (&dyldi[40], mo->big_endian) + mo->symbols_off;
					mo->dyld_info->export_size = r_read_ble32 (&dyldi[44], mo->big_endian);
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
			//bprintf ("mach0: TODO: Show source version\n");
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
			R_LOG_DEBUG ("Unknown header %d command 0x%x at 0x%08"PFMT64x, i, lc.cmd, off);
			break;
		}
	}
	bool has_chained_fixups = false;
	for (i = 0, off = sizeof (struct MACH0_(mach_header)) + mo->header_at; \
			i < mo->hdr.ncmds; i++, off += lc.cmdsize) {
		len = r_buf_read_at (mo->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			R_LOG_DEBUG ("read (lc) at 0x%08"PFMT64x, off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], mo->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], mo->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > mo->size) {
			R_LOG_DEBUG ("mach0_header %d = cmdsize<1. (0x%"PFMT64x" vs 0x%"PFMT64x")", i,
				(ut64)(off + lc.cmdsize), (ut64)(mo->size));
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
				ut8 *db = (ut8*)malloc (datasize);
				if (db) {
					r_buf_read_at (mo->b, dataoff, db, datasize);
					// TODO table of non-instructions regions in __text
					int j;
					for (j = 0; j < datasize; j += 8) {
						ut32 dw = r_read_ble32 (db + j, mo->big_endian);
						// int kind = r_read_ble16 (db + i + 4 + 2, mo->big_endian);
						int len = r_read_ble16 (db + j + 4, mo->big_endian);
						ut64 va = offset_to_vaddr(mo, dw);
					//	eprintf ("# 0x%x -> 0x%x\n", dw, va);
					//	eprintf ("0x%x kind %d len %d\n", dw, kind, len);
						eprintf ("Cd 8 %d @ 0x%"PFMT64x"\n", len / 8, va);
					}
				}
			}
			break;
		case LC_DYLD_EXPORTS_TRIE: {
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

static bool init(struct MACH0_(obj_t) *mo) {
	if (!init_hdr (mo)) {
		return false;
	}
	if (!init_items (mo)) {
		R_LOG_WARN ("Cannot initialize items");
	}
	mo->baddr = MACH0_(get_baddr)(mo);
	mo->libs_loaded = true;
	RVecMach0Lib_shrink_to_fit (&mo->libs_cache);
	return true;
}

void *MACH0_(mach0_free)(struct MACH0_(obj_t) *mo) {
	if (!mo) {
		return NULL;
	}

	size_t i;
	free (mo->segs);
	free (mo->sects);
	free (mo->symtab);
	free (mo->symstr);
	free (mo->indirectsyms);
	free (mo->imports_by_ord);
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
#if R2_590
#else
	if (mo->imports_loaded) {
		RVecMach0Import_fini (&mo->imports_cache);
	}
#endif
	if (mo->sections_loaded) {
		RVecSection_fini (&mo->sections_cache);
	}
	RVecSegment_free (mo->segments_vec);
	mo->segments_vec = NULL;
	if (mo->relocs_loaded) {
		r_skiplist_free (mo->relocs_cache);
	}
	if (mo->chained_starts) {
		for (i = 0; i < mo->nsegs && i < mo->segs_count; i++) {
			if (mo->chained_starts[i]) {
				free (mo->chained_starts[i]->page_start);
				free (mo->chained_starts[i]);
			}
		}
		free (mo->chained_starts);
	}
	r_buf_free (mo->b);
	free (mo);
	return NULL;
}

void MACH0_(opts_set_default)(struct MACH0_(opts_t) *options, RBinFile *bf) {
	R_RETURN_IF_FAIL (options && bf && bf->rbin);
	options->bf = bf;
	options->header_at = 0;
	options->symbols_off = 0;
	options->verbose = bf->rbin->options.verbose;
	options->maxsymlen = bf->rbin->options.maxsymlen;
	options->parse_start_symbols = false;
}

struct MACH0_(obj_t) *MACH0_(new_buf)(RBinFile *bf, RBuffer *buf, struct MACH0_(opts_t) *options) {
	R_RETURN_VAL_IF_FAIL (buf && options->bf->bo, NULL);
	struct MACH0_(obj_t) *mo = R_NEW0 (struct MACH0_(obj_t));
	if (mo) {
		mo->b = r_buf_ref (buf);
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
		if (options) {
#if 0
			if (options->bf->loadaddr == UT64_MAX - sz) {
				// handle the negative binsize problem when source io returns -1 as size. assume its 2MB
				// sz = 4 * 1024 * 1024;
			}
#endif
			mo->verbose = options->verbose;
			mo->header_at = options->header_at;
			mo->maxsymlen = options->maxsymlen;
			mo->symbols_off = options->symbols_off;
			mo->parse_start_symbols = options->parse_start_symbols;
		}
		mo->size = sz;
		if (!init (mo)) {
			return MACH0_(mach0_free)(mo);
		}
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

RVecSegment *MACH0_(get_segments_vec)(RBinFile *bf, struct MACH0_(obj_t) *mo) {
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
				//TODO s->flags = seg->flags;
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

				s->vaddr = (ut64)mo->sects[i].addr;
				s->vsize = (ut64)mo->sects[i].size;
				s->is_segment = false;
				s->size = (mo->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)mo->sects[i].size;
				s->type = macho_section_type_tostring (mo->sects[i].flags);
				s->paddr = (ut64)mo->sects[i].offset;

				int segment_index = 0;
				size_t j;
				for (j = 0; j < mo->nsegs; j++) {
					if (s->vaddr >= mo->segs[j].vmaddr &&
							s->vaddr < (mo->segs[j].vmaddr + mo->segs[j].vmsize)) {
						s->perm = prot2perm (mo->segs[j].initprot);
						segment_index = j;
						break;
					}
				}

				char *section_name = r_str_ndup (mo->sects[i].sectname, 16);
				char *segment_name = r_str_newf ("%u.%s", (ut32)i, mo->segs[segment_index].segname);
				s->name = r_str_newf ("%s.%s", segment_name, section_name);
				if (strstr (s->name, "__const")) {
					s->format = r_str_newf ("Cd %d %"PFMT64d, ws, s->size / ws);
				}

				s->is_data = is_data_section (s);
				if (strstr (section_name, "interpos") || strstr (section_name, "__mod_")) {
					free (s->format);
					s->format = r_str_newf ("Cd %d[%"PFMT64d"]", ws, s->vsize / ws);
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

RList *MACH0_(get_segments)(RBinFile *bf, struct MACH0_(obj_t) *macho) {
	RList *list = r_list_newf ((RListFree)r_bin_section_free);
	if (!list) {
		return NULL;
	}

	// R2_590 slow, should return vec directly
	RVecSegment *segments = MACH0_(get_segments_vec)(bf, macho);
	RBinSection *s;
	R_VEC_FOREACH (segments, s) {
		RBinSection *s_copy = r_bin_section_clone (s);
		if (!s_copy) {
			r_list_free (list);
			return NULL;
		}
		r_list_append (list, s_copy);
	}

	return list;
}

const RVecSection *MACH0_(load_sections)(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);
	if (mo->sections_loaded) {
		return &mo->sections_cache;
	}

	mo->sections_loaded = true;
	RVecSection_init (&mo->sections_cache);

	char sectname[64];
	char raw_segname[17];
	size_t i, j, to;
	struct MACH0_(segment_command) *seg;

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
		section->paddr = (ut64)mo->sects[i].offset;
		section->vaddr = (ut64)mo->sects[i].addr;
		section->size = (mo->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)mo->sects[i].size;
		section->vsize = (ut64)mo->sects[i].size;
		section->align = mo->sects[i].align;
		section->flags = mo->sects[i].flags;
		r_str_ncpy (sectname, mo->sects[i].sectname, 17);
		r_str_filter (sectname, -1);
		r_str_ncpy (raw_segname, mo->sects[i].segname, 17);
		r_str_filter (raw_segname, -1);
		for (j = 0; j < mo->nsegs; j++) {
			if (section->vaddr >= mo->segs[j].vmaddr &&
				section->vaddr < (mo->segs[j].vmaddr + mo->segs[j].vmsize)) {
				section->perm = prot2perm (mo->segs[j].initprot);
				break;
			}
		}
		snprintf (section->name, sizeof (section->name),
			"%d.%s.%s", (int)i, raw_segname, sectname);
	}
	return &mo->sections_cache;
}

static bool parse_import_stub(struct MACH0_(obj_t) *bin, struct symbol_t *symbol, int idx) {
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
	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS && bin->sects[i].reserved2 > 0) {
			ut64 sect_size = bin->sects[i].size;
			ut32 sect_fragment = bin->sects[i].reserved2;
			if (bin->sects[i].offset > bin->size) {
				R_LOG_DEBUG ("section offset starts way beyond the end of the file");
				continue;
			}
			if (sect_size > bin->size) {
				R_LOG_DEBUG ("Invalid symbol table size");
				sect_size = bin->size - bin->sects[i].offset;
			}
			nsyms = (int)(sect_size / sect_fragment);
			for (j = 0; j < nsyms; j++) {
				if (bin->sects) {
					if (bin->nindirectsyms < 0 || bin->sects[i].reserved1 + j >= bin->nindirectsyms) {
						continue;
					}
				}
				if (bin->indirectsyms) {
					if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j]) {
						continue;
					}
				}
				if (idx > bin->nsymtab) {
					continue;
				}
				symbol->type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				int delta = j * bin->sects[i].reserved2;
				if (delta < 0) {
					R_LOG_DEBUG ("corrupted reserved2 value leads to int overflow");
					continue;
				}
				symbol->offset = bin->sects[i].offset + delta;
				symbol->addr = bin->sects[i].addr + delta;
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
	char *key = r_str_newf ("%"PFMT64x".%s", addr, name);
	ht_pp_find (hash, key, &found);
	if (found) {
		free (key);
		return true;
	}
	ht_pp_insert (hash, key, "1");
	free (key);
	return false;
}

static char *get_name(struct MACH0_(obj_t) *mo, ut32 stridx, bool filter) {
	size_t i = 0;
	if (!mo->symstr || stridx >= mo->symstrlen) {
		return NULL;
	}
	int len = mo->symstrlen - stridx;
	const char *symstr = (const char*)mo->symstr + stridx;
	for (i = 0; i < len; i++) {
		if ((ut8)(symstr[i] & 0xff) == 0xff || !symstr[i]) {
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

static int walk_exports_trie(struct MACH0_(obj_t) *bin, ut64 trie_off, ut64 size, RExportsIterator iterator, void *ctx) {
	size_t count = 0;
	ut8 *p = NULL;
	if (!size || size >= SIZE_MAX) {
		return 0;
	}
	ut8 *trie = calloc (size + 1, 1);
	if (!trie) {
		return 0;
	}
	ut8 *end = trie + size;
	if (r_buf_read_at (bin->b, trie_off, trie, size) != size) {
		return 0;
	}

	RList *states = r_list_newf ((RListFree)free);
	if (!states) {
		goto beach;
	}

	RTrieState *root = R_NEW0 (RTrieState);
	if (!root) {
		goto beach;
	}
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
				p += strlen ((char*) p) + 1;
				// TODO: handle this
			}
			if (!isReexport) {
				offset += bin->header_at;
			}
			if (iterator && !isReexport) {
				char * name = NULL;
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
					char * stub_name = r_str_newf ("stub.%s", name);
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
		if (!state->next_child) {
			state->next_child = p;
		} else {
			p = state->next_child;
		}
		RTrieState * next = R_NEW0 (RTrieState);
		if (!next) {
			goto beach;
		}
		next->label = (char *) p;
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

static int walk_exports(struct MACH0_(obj_t) *bin, RExportsIterator iterator, void *ctx) {
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

static void _update_main_addr_if_needed(struct MACH0_(obj_t) *mo, const RBinSymbol *sym) {
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
	if (sym->paddr & 1) {
		sym->paddr--;
		sym->vaddr--;
		sym->bits = 16;
	}
}

static void _enrich_symbol(RBinFile *bf, struct MACH0_(obj_t) *bin, HtPP *symcache, RBinSymbol *sym) {
	int wordsize = MACH0_(get_bits) (bin);

	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	if (oname) {
		bin->dbg_info = r_str_startswith (oname, "radr://");
	       	if (*oname == '_' && !sym->is_imported) {
			char *demangled = r_bin_demangle (bf, oname, oname, sym->vaddr, false);
			if (demangled) {
				r_bin_name_demangled (sym->name, demangled);
				char *p = strchr (demangled, '.');
				if (p) {
					if (isupper (*demangled)) {
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

	r_strf_var (k, 32, "sym0x%"PFMT64x, sym->vaddr);
	ht_pp_insert (symcache, k, "found");
}

typedef struct fill_context_t {
	RBinFile *bf;
	HtPP *symcache;
	HtPP *hash;
	ut64 boffset;
	ut32 *ordinal;
} FillCtx;

static void _fill_exports(struct MACH0_(obj_t) *mo, const char *name, ut64 flags, ut64 offset, void *ctx) {
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
#if 0
	if (r_str_startswith (sym_name, "__")) {
		return true;
	}
#endif
	if (r_str_startswith (sym_name, "radr://")) {
		return true;
	}
	if (!strcmp (sym_name, "__mh_execute_header")) {
		return true;
	}
	return false;
}

static void parse_symbols(RBinFile *bf, struct MACH0_(obj_t) *mo, HtPP *symcache) {
	size_t i, j, s, symbols_size, symbols_count;
	ut32 to = UT32_MAX;
	ut32 from = UT32_MAX;
	ut32 ordinal = 0;

	RBinObject *obj = bf? bf->bo: NULL;
	if (!obj) {
		return;
	}

	HtPP *hash = ht_pp_new0 ();
	if (!hash) {
		return;
	}

	FillCtx fill_context = { .bf = bf, .symcache = symcache, .hash = hash, .boffset = obj->boffset, .ordinal = &ordinal };
	walk_exports (mo, _fill_exports, &fill_context);

	if (!mo->symtab || !mo->symstr) {
		ht_pp_free (hash);
		return;
	}
	/* parse dynamic symbol table */
	symbols_count = mo->dysymtab.nextdefsym + mo->dysymtab.nlocalsym + mo->dysymtab.nundefsym + mo->nsymtab;
	if (symbols_count == 0) {
		ht_pp_free (hash);
		return;
	}

	if (SZT_MUL_OVFCHK (symbols_count, 2 * sizeof (RBinSymbol))) {
		// overflow may happen here
		ht_pp_free (hash);
		return;
	}

	symbols_size = symbols_count * 2 * sizeof (RBinSymbol);
	j = 0; // symbol_idx
	mo->main_addr = UT64_MAX;
	int bits = MACH0_(get_bits_from_hdr) (&mo->hdr);
	bool is_stripped = true;
	const int limit = bf->rbin->options.limit;
	for (s = 0; s < 2; s++) {
		switch (s) {
		case 0:
			from = mo->dysymtab.iextdefsym;
			to = from + mo->dysymtab.nextdefsym;
			break;
		case 1:
			from = mo->dysymtab.ilocalsym;
			to = from + mo->dysymtab.nlocalsym;
			break;
#if NOT_USED
		case 2:
			from = mo->dysymtab.iundefsym;
			to = from + mo->dysymtab.nundefsym;
			break;
#endif
		}
		if (from == to) {
			continue;
		}

		from = R_MIN (from, symbols_size / sizeof (RBinSymbol));
		to = R_MIN (R_MIN (to, mo->nsymtab), symbols_size / sizeof (RBinSymbol));
		ut32 maxsymbols = symbols_size / sizeof (RBinSymbol);
		if (symbols_count >= maxsymbols) {
			symbols_count = maxsymbols - 1;
			R_LOG_WARN ("Truncated symbol table");
		}

		for (i = from; i < to && j < symbols_count; i++, j++) {
			ut64 vaddr = mo->symtab[i].n_value;
			if (vaddr < 100) {
				j--;
				continue;
			}

			int stridx = mo->symtab[i].n_strx;
			char *sym_name = get_name (mo, stridx, false);
			if (!sym_name) {
				j--;
				continue;
			}

			if (strstr (sym_name, "<redacted>") || hash_find_or_insert (hash, sym_name, vaddr)) {
				free (sym_name);
				j--;
			} else {
				RBinSymbol *sym = RVecRBinSymbol_emplace_back (mo->symbols_vec);
				memset (sym, 0, sizeof (RBinSymbol));
				sym->vaddr = vaddr;
				sym->paddr = addr_to_offset (mo, sym->vaddr) + obj->boffset;
				sym->size = 0; /* TODO: Is it anywhere? */
				sym->bits = mo->symtab[i].n_desc & N_ARM_THUMB_DEF ? 16 : bits;
				sym->is_imported = false;
				sym->type = mo->symtab[i].n_type & N_EXT ? "EXT" : "LOCAL";
				sym->name = r_bin_name_new (sym_name);
				if (is_stripped && !apple_symbol (sym_name)) {
					is_stripped = false;
				}
				R_FREE (sym_name);
				sym->ordinal = ordinal++;
				_update_main_addr_if_needed (mo, sym);
				_enrich_symbol (bf, mo, symcache, sym);
				if (limit > 0 && ordinal > limit) {
					R_LOG_WARN ("symbols mo.limit reached");
					break;
				}
			}
		}
	}

	to = R_MIN ((ut32)mo->nsymtab, mo->dysymtab.iundefsym + mo->dysymtab.nundefsym);
	for (i = mo->dysymtab.iundefsym; i < to; i++) {
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
		if (section == 1 && j < symbols_count) { // text ??st->n_type == 1) maybe wrong
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
			if (limit > 0 && ordinal > limit) {
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

static bool parse_function_start_symbols(RBinFile *bf, struct MACH0_(obj_t) *mo, HtPP *symcache) {
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
		char *n = r_str_newf ("func.%08"PFMT64x, sym->vaddr);
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
			snprintf (symstr + 5, sizeof (symstr) - 5 , "%" PFMT64x, sym->vaddr);
			bool found = false;
			ht_pp_find (symcache, symstr, &found);
			if (!found) {
				is_stripped = true;
			}
		}
		if (limit > 0 && sym->ordinal > limit) {
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
// R2_590
static inline bool is_debug_segment(const RBinSection *s, const void *user) {
	return strstr (s->name, "DWARF.__debug_line") != NULL;
}

static inline bool is_debug_build(RBinFile *bf, struct MACH0_(obj_t) *mo) {
	return RVecSegment_find (mo->segments_vec, NULL, is_debug_segment) != NULL;
}
#else
static bool is_debug_build(RBinFile *bf, struct MACH0_(obj_t) *mo) {
	RList *sections = MACH0_(get_segments) (bf, mo);
	if (!sections) {
		return false;
	}

	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (strstr (section->name, ".__debug_line")) {
			return true;
		}
	}
	r_list_free (sections);
	return false;
}
#endif

const bool MACH0_(load_symbols)(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, false);
	if (mo->symbols_loaded) {
		return true;
	}

	mo->symbols_loaded = true;
	HtPP *symcache = ht_pp_new0 ();
	if (R_LIKELY (symcache)) {
		RBinFile *bf = mo->options.bf;
		parse_symbols (bf, mo, symcache);
		if (mo->parse_start_symbols) {
			bool is_stripped = parse_function_start_symbols (bf, mo, symcache);
			if (is_stripped) {
				mo->dbg_info |= R_BIN_DBG_STRIPPED;
			}
		}
		ht_pp_free (symcache);
	}

	if (is_debug_build (mo->options.bf, mo)) {
		mo->dbg_info |= R_BIN_DBG_LINENUMS;
		mo->dbg_info &= ~R_BIN_DBG_STRIPPED;
	}
	return !RVecRBinSymbol_empty (mo->symbols_vec);
}

static struct reloc_t *parse_import_ptr(struct MACH0_(obj_t) *mo, int jota) {
	int idx = mo->dysymtab.iundefsym + jota;
	int i, j, sym;
	if (idx < 0 || idx >= mo->nsymtab) {
		return NULL;
	}
	const size_t wordsize = get_word_size (mo);
	const ut32 stype = ((mo->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY)
		? S_LAZY_SYMBOL_POINTERS: S_NON_LAZY_SYMBOL_POINTERS;

	int type = 0;
#define CASE(T) case ((T) / 8): type = R_BIN_RELOC_ ## T; break
	switch (wordsize) {
	CASE(8);
	CASE(16);
	CASE(32);
	CASE(64);
	default: return NULL;
	}
#undef CASE

	struct reloc_t *reloc = R_NEW0 (struct reloc_t);
	reloc->addr = 0;
	reloc->type = type;
	reloc->offset = 0;
	reloc->addend = 0;
	reloc->ntype = stype;
	for (i = 0; i < mo->nsects; i++) {
		if ((mo->sects[i].flags & SECTION_TYPE) == stype) {
			for (j = 0, sym = -1; mo->sects[i].reserved1 + j < mo->nindirectsyms; j++) {
				int indidx = mo->sects[i].reserved1 + j;
				if (indidx < 0 || indidx >= mo->nindirectsyms) {
					break;
				}
				if (idx == mo->indirectsyms[indidx]) {
					sym = j;
					break;
				}
			}
			reloc->offset = sym == -1 ? 0 : mo->sects[i].offset + sym * wordsize;
			reloc->addr = sym == -1 ? 0 : mo->sects[i].addr + sym * wordsize;
			return reloc;
		}
	}
	free (reloc);
	return NULL;
}

static RBinImport *import_from_name(RBin *rbin, const char *orig_name) {
	RBinImport *ptr = R_NEW0 (RBinImport);
	if (R_UNLIKELY (!ptr)) {
		return NULL;
	}

	char *name = (char*) orig_name;
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
	ptr->name = r_bin_name_new (s);
	free (s);
	ptr->bind = "NONE";
	ptr->type = r_str_constpool_get (&rbin->constpool, type);
	return ptr;
}

static void check_for_special_import_names(struct MACH0_(obj_t) *bin, RBinImport *import) {
	const char *name = r_bin_name_tostring (import->name);
	if (*name == '_') {
		if (name[1] == '_') {
			if (!strcmp (name, "__stack_chk_fail") ) {
				bin->has_canary = true;
			} else if (!strcmp (name, "__asan_init") || !strcmp (name, "__tsan_init")) {
				bin->has_sanitizers = true;
			}
		} else if (!strcmp (name, "_NSConcreteGlobalBlock")) {
			bin->has_blocks_ext = true;
		}
	}
}

const RVecMach0Import *MACH0_(load_imports)(RBinFile *bf, struct MACH0_(obj_t) *bin) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	if (bin->imports_loaded) {
		return &bin->imports_cache;
	}

	bin->imports_loaded = true;
	RVecMach0Import_init (&bin->imports_cache);

	ut32 nundefsym = bin->dysymtab.nundefsym;
	if (nundefsym < 1 || nundefsym > 0xfffff) {
		return NULL;
	}

	RVecMach0Import_reserve (&bin->imports_cache, nundefsym);

	if (!bin->sects || !bin->symtab || !bin->symstr || !bin->indirectsyms) {
		return NULL;
	}

	int i, num_imports;
	const int limit = bf->rbin->options.limit;
	bin->has_canary = false;
	bin->has_retguard = -1;
	bin->has_sanitizers = false;
	bin->has_blocks_ext = false;

	for (i = num_imports = 0; i < nundefsym; i++) {
		int idx = bin->dysymtab.iundefsym + i;
		if (idx < 0 || idx >= bin->nsymtab) {
			R_LOG_WARN ("Imports index out of bounds. Ignoring relocs");
			return NULL;
		}
		if (limit > 0 && i > limit) {
			R_LOG_WARN ("imports mo.limit reached");
			break;
		}

		int stridx = bin->symtab[idx].n_strx;
		char *imp_name = get_name (bin, stridx, false);
		if (!imp_name) {
			continue;
		}

		RBinImport *import = import_from_name (bf->rbin, imp_name);
		if (!import) {
			free (imp_name);
			break;
		}

		import->ordinal = i;
		RVecMach0Import_push_back (&bin->imports_cache, &import);
		num_imports++;
		check_for_special_import_names (bin, import);
		free (imp_name);
	}

	if (num_imports > 0) {
		bin->imports_by_ord_size = num_imports;
		bin->imports_by_ord = (RBinImport**)calloc (num_imports, sizeof (RBinImport*));
		if (!bin->imports_by_ord) {
			return NULL;
		}

		RBinImport **it;
		R_VEC_FOREACH (&bin->imports_cache, it) {
			RBinImport *import = *it;
			if (import->ordinal < bin->imports_by_ord_size) {
				bin->imports_by_ord[import->ordinal] = import;
			}
		}
	} else {
		bin->imports_by_ord_size = 0;
		bin->imports_by_ord = NULL;
	}

	return &bin->imports_cache;
}

static bool check_bind_count(ut64 count, ut64 addr, ut64 segment_end_addr, ut64 skip, ut64 wordsize) {
	ut64 increment = skip + wordsize;
	if (!increment) {
		return count == 0;
	}
	ut64 remaining = (addr < segment_end_addr) ? segment_end_addr - addr : 0;
	ut64 max_count = remaining / increment;
	return count <= max_count;
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

static void parse_relocation_info(struct MACH0_(obj_t) *mo, RSkipList *relocs, ut32 offset, ut32 num) {
	if (!num || !offset || (st32)num < 0) {
		return;
	}

	ut64 total_size = num * sizeof (struct relocation_info);
	if (offset > mo->size) {
		return;
	}
	if (total_size > mo->size) {
		total_size = mo->size - offset;
		num = total_size /= sizeof (struct relocation_info);
	}
	struct relocation_info *info = calloc (num, sizeof (struct relocation_info));
	if (!info) {
		return;
	}

	if (r_buf_read_at (mo->b, offset, (ut8 *) info, total_size) < total_size) {
		free (info);
		return;
	}

	const int limit = mo->limit;
	size_t i;
	for (i = 0; i < num; i++) {
		struct relocation_info a_info = info[i];
		ut32 sym_num = a_info.r_symbolnum;
		if (sym_num >= mo->nsymtab) {
			continue;
		}
		if (limit > 0 && i > limit) {
			R_LOG_WARN ("relocs mo.limit reached");
			break;
		}

		ut32 stridx = mo->symtab[sym_num].n_strx;
		char *sym_name = get_name (mo, stridx, false);
		if (!sym_name) {
			continue;
		}

		struct reloc_t *reloc = R_NEW0 (struct reloc_t);
		if (!reloc) {
			free (info);
			free (sym_name);
			return;
		}

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

static bool walk_bind_chains_callback(void * context, RFixupEventDetails * event_details) {
	R_RETURN_VAL_IF_FAIL (event_details->type == R_FIXUP_EVENT_BIND || event_details->type == R_FIXUP_EVENT_BIND_AUTH, false);
	RWalkBindChainsContext *ctx = context;
	ut8 *imports = ctx->imports;
	struct MACH0_(obj_t) *mo = event_details->bin;
	ut32 imports_count = mo->fixups_header.imports_count;
	ut32 fixups_offset = mo->fixups_offset;
	ut32 fixups_size = mo->fixups_size;
	ut32 imports_format = mo->fixups_header.imports_format;
	ut32 import_index = ((RFixupBindEventDetails *) event_details)->ordinal;
	ut64 addend = 0;
	if (event_details->type != R_FIXUP_EVENT_BIND_AUTH) {
		addend = ((RFixupBindEventDetails *) event_details)->addend;
	}
	const int limit = mo->limit;
	if (limit > 0 && import_index > limit) {
		return false;
	}
	if (import_index < imports_count) {
		ut64 name_offset;
		switch (imports_format) {
			case DYLD_CHAINED_IMPORT: {
				struct dyld_chained_import * item = &((struct dyld_chained_import *) imports)[import_index];
				name_offset = item->name_offset;
				break;
			}
			case DYLD_CHAINED_IMPORT_ADDEND: {
				struct dyld_chained_import_addend * item = &((struct dyld_chained_import_addend *) imports)[import_index];
				name_offset = item->name_offset;
				addend += item->addend;
				break;
			}
			case DYLD_CHAINED_IMPORT_ADDEND64: {
				struct dyld_chained_import_addend64 * item = &((struct dyld_chained_import_addend64 *) imports)[import_index];
				name_offset = item->name_offset;
				addend += item->addend;
				break;
			}
			default:
				R_LOG_WARN ("Unsupported imports format");
				return false;
		}

		ut64 symbols_offset = mo->fixups_header.symbols_offset + fixups_offset;

		if (symbols_offset + name_offset + 1 < fixups_offset + fixups_size) {
			char *name = r_buf_get_string (mo->b, symbols_offset + name_offset);
			if (name) {
				struct reloc_t *reloc = R_NEW0 (struct reloc_t);
				if (!reloc) {
					free (name);
					return false;
				}
				reloc->addr = offset_to_vaddr (mo, event_details->offset);
				reloc->offset = event_details->offset;
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

static void walk_bind_chains(struct MACH0_(obj_t) *mo, RSkipList *relocs) {
	R_RETURN_IF_FAIL (mo && mo->fixups_offset);

	ut8 *imports = NULL;

	ut32 imports_count = mo->fixups_header.imports_count;
	ut32 fixups_offset = mo->fixups_offset;
	ut32 imports_offset = mo->fixups_header.imports_offset;
	if (!imports_count || !imports_offset) {
		return;
	}
	if (mo->fixups_header.symbols_format != 0) {
		R_LOG_INFO ("Compressed fixups symbols not supported yet, please file a bug with a sample attached");
		return;
	}

	ut32 imports_format = mo->fixups_header.imports_format;
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
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset,
				imports, "i", imports_count) != imports_size) {
			goto beach;
		}
		break;
	case DYLD_CHAINED_IMPORT_ADDEND:
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset,
				imports, "ii", imports_count) != imports_size) {
			goto beach;
		}
		break;
	case DYLD_CHAINED_IMPORT_ADDEND64:
		if (r_buf_fread_at (mo->b, fixups_offset + imports_offset,
				imports, "il", imports_count) != imports_size) {
			goto beach;
		}
		break;
	}

	RWalkBindChainsContext ctx;
	ctx.imports = imports;
	ctx.relocs = relocs;

	MACH0_(iterate_chained_fixups) (mo, 0, UT64_MAX,
		R_FIXUP_EVENT_MASK_BIND_ALL, &walk_bind_chains_callback, &ctx);

beach:
	free (imports);
}

static bool is_valid_ordinal_table_size(ut64 size) {
	return size > 0 && size <= UT16_MAX;
}

static void mach0_reloc_ref_fini (struct reloc_t **reloc) {
	free (*reloc);
}

R_VEC_TYPE_WITH_FINI (RVecRelocRef, struct reloc_t *, mach0_reloc_ref_fini);

static RVecRelocRef *reloc_ref_vec_new_with_len (ut64 length) {
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

static bool _load_relocations(struct MACH0_(obj_t) *mo) {
	RVecRelocRef *threaded_binds = NULL;
	ut8 *opcodes = NULL;
	size_t wordsize = get_word_size (mo);
	if (mo->dyld_info) {
		ut8 rel_type = 0;
		size_t bind_size, lazy_size, weak_size;

#define CASE(T) case ((T) / 8): rel_type = R_BIN_RELOC_ ## T; break
		switch (wordsize) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
		default: return false;
		}
#undef CASE
		bind_size = mo->dyld_info->bind_size;
		lazy_size = mo->dyld_info->lazy_bind_size;
		weak_size = mo->dyld_info->weak_bind_size;

		if (!bind_size && !lazy_size) {
			return false;
		}

		if ((bind_size + lazy_size) < 1) {
			return false;
		}
		if (mo->dyld_info->bind_off > mo->size || mo->dyld_info->bind_off + bind_size > mo->size) {
			return false;
		}
		if (mo->dyld_info->lazy_bind_off > mo->size || \
			mo->dyld_info->lazy_bind_off + lazy_size > mo->size) {
			return false;
		}
		if (mo->dyld_info->bind_off + bind_size + lazy_size > mo->size) {
			return false;
		}
		if (mo->dyld_info->weak_bind_off + weak_size > mo->size) {
			return false;
		}
		ut64 amount = bind_size + lazy_size + weak_size;
		if (amount == 0 || amount > UT32_MAX) {
			return false;
		}
		if (!mo->segs) {
			return false;
		}
		opcodes = calloc (1, amount + 1);
		if (!opcodes) {
			return false;
		}

		int len = r_buf_read_at (mo->b, mo->dyld_info->bind_off, opcodes, bind_size);
		len += r_buf_read_at (mo->b, mo->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size);
		len += r_buf_read_at (mo->b, mo->dyld_info->weak_bind_off, opcodes + bind_size + lazy_size, weak_size);
		if (len < amount) {
			R_LOG_ERROR ("read (dyld_info bind) at 0x%08"PFMT64x, (ut64)(size_t)mo->dyld_info->bind_off);
			R_FREE (opcodes);
			return false;
		}

		size_t partition_sizes[] = {bind_size, lazy_size, weak_size};
		size_t pidx;
		int opcodes_offset = 0;
		for (pidx = 0; pidx < R_ARRAY_SIZE (partition_sizes); pidx++) {
			size_t partition_size = partition_sizes[pidx];

			ut8 type = 0;
			int lib_ord = 0, seg_idx = -1, sym_ord = -1;
			char *sym_name = NULL;
			size_t j, count, skip;
			st64 addend = 0;
			ut64 addr = mo->segs[0].vmaddr;
			ut64 segment_size = mo->segs[0].filesize;
			if (mo->segs[0].filesize != mo->segs[0].vmsize) {
				// is probably invalid and we should warn the user
			}
			if (segment_size > mo->size) {
				// is probably invalid and we should warn the user
				segment_size = mo->size;
			}
			ut64 segment_end_addr = addr + segment_size;

			ut8 *p = opcodes + opcodes_offset;
			ut8 *end = p + partition_size;
			bool done = false;
			while (!done && p < end) {
				ut8 imm = *p & BIND_IMMEDIATE_MASK;
				ut8 op = *p & BIND_OPCODE_MASK;
				p++;
				switch (op) {
				case BIND_OPCODE_DONE: {
					bool in_lazy_binds = pidx == 1;
					if (!in_lazy_binds) {
						done = true;
					}
					break;
				}
				case BIND_OPCODE_THREADED: {
					switch (imm) {
					case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
						ut64 table_size = read_uleb128 (&p, end);
						if (!is_valid_ordinal_table_size (table_size)) {
							R_LOG_DEBUG ("BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB size is wrong");
							break;
						}
						if (threaded_binds) {
							RVecRelocRef_free (threaded_binds);
						}
						threaded_binds = reloc_ref_vec_new_with_len (table_size);
						if (threaded_binds) {
							sym_ord = 0;
						}
						break;
					}
					case BIND_SUBOPCODE_THREADED_APPLY:
						if (threaded_binds) {
							int cur_seg_idx = (seg_idx != -1)? seg_idx: 0;
							ut64 n_threaded_binds = RVecRelocRef_length (threaded_binds);
							while (addr < segment_end_addr) {
								ut8 tmp[8];
								ut64 paddr = addr - mo->segs[cur_seg_idx].vmaddr + mo->segs[cur_seg_idx].fileoff;
								mo->rebasing_buffer = true;
								if (r_buf_read_at (mo->b, paddr, tmp, 8) != 8) {
									break;
								}
								mo->rebasing_buffer = false;
								ut64 raw_ptr = r_read_le64 (tmp);
								bool is_auth = (raw_ptr & (1ULL << 63)) != 0;
								bool is_bind = (raw_ptr & (1ULL << 62)) != 0;
								int ordinal = -1;
								int addend = -1;
								ut64 delta;
								if (is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_auth_bind *p =
											(struct dyld_chained_ptr_arm64e_auth_bind *) &raw_ptr;
									delta = p->next;
									ordinal = p->ordinal;
								} else if (!is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_bind *p =
											(struct dyld_chained_ptr_arm64e_bind *) &raw_ptr;
									delta = p->next;
									ordinal = p->ordinal;
									addend = p->addend;
								} else if (is_auth && !is_bind) {
									struct dyld_chained_ptr_arm64e_auth_rebase *p =
											(struct dyld_chained_ptr_arm64e_auth_rebase *) &raw_ptr;
									delta = p->next;
								} else {
									struct dyld_chained_ptr_arm64e_rebase *p =
											(struct dyld_chained_ptr_arm64e_rebase *) &raw_ptr;
									delta = p->next;
								}
								if (ordinal != -1) {
									if (ordinal >= n_threaded_binds) {
										R_LOG_DEBUG ("Malformed bind chain");
										break;
									}
									struct reloc_t **ref_slot = RVecRelocRef_at (threaded_binds, ordinal);
									struct reloc_t *ref = ref_slot ? *ref_slot : NULL;
									if (!ref) {
										R_LOG_DEBUG ("Inconsistent bind opcodes");
										break;
									}
									struct reloc_t *reloc = R_NEW0 (struct reloc_t);
									if (!reloc) {
										break;
									}
									*reloc = *ref;
									reloc->addr = addr;
									reloc->ntype = op;
									reloc->offset = paddr;
									if (addend != -1) {
										reloc->addend = addend;
									}
									r_skiplist_insert (mo->relocs_cache, reloc);
								}
								addr += delta * wordsize;
								if (!delta) {
									break;
								}
							}
						}
						break;
					default:
						R_LOG_DEBUG ("Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x", imm);
					}
					break;
				}
				case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
					lib_ord = imm;
					break;
				case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
					lib_ord = read_uleb128 (&p, end);
					break;
				case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
					lib_ord = imm? (st8)(BIND_OPCODE_MASK | imm) : 0;
					break;
				case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
					sym_name = (char*)p;
					while (*p++ && p < end) {
						/* empty loop */
					}
					if (threaded_binds) {
						break;
					}
					sym_ord = -1;
					if (mo->symtab && mo->dysymtab.nundefsym < UT16_MAX) {
						for (j = 0; j < mo->dysymtab.nundefsym; j++) {
							size_t stridx = 0;
							bool found = false;
							int iundefsym = mo->dysymtab.iundefsym;
							if (iundefsym >= 0 && iundefsym < mo->nsymtab) {
								int sidx = iundefsym + j;
								if (sidx < 0 || sidx >= mo->nsymtab) {
									continue;
								}
								stridx = mo->symtab[sidx].n_strx;
								if (stridx >= mo->symstrlen) {
									continue;
								}
								found = true;
							}
							if (found && !strcmp ((const char *)mo->symstr + stridx, sym_name)) {
								sym_ord = j;
								break;
							}
						}
					}
					break;
				}
				case BIND_OPCODE_SET_TYPE_IMM:
					type = imm;
					break;
				case BIND_OPCODE_SET_ADDEND_SLEB:
					addend = r_sleb128 ((const ut8 **)&p, end);
					break;
				case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					seg_idx = imm;
					if (seg_idx >= mo->nsegs) {
						R_LOG_ERROR ("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has no segment %d", seg_idx);
						free (opcodes);
						RVecRelocRef_free (threaded_binds);
						return false; // early exit to avoid future mayhem
					}
					addr = mo->segs[seg_idx].vmaddr + read_uleb128 (&p, end);
					segment_end_addr = mo->segs[seg_idx].vmaddr \
							+ mo->segs[seg_idx].vmsize;
					break;
				case BIND_OPCODE_ADD_ADDR_ULEB:
					addr += read_uleb128 (&p, end);
					break;
#define DO_BIND() do {\
	if (sym_ord < 0 && !sym_name) break;\
	if (!threaded_binds) {\
		if (seg_idx < 0 ) break;\
		if (!addr) break;\
	}\
	struct reloc_t *reloc = R_NEW0 (struct reloc_t);\
	reloc->addr = addr;\
	if (seg_idx >= 0) {\
		reloc->offset = addr - mo->segs[seg_idx].vmaddr + mo->segs[seg_idx].fileoff;\
		reloc->addend = addend;\
		if (type == BIND_TYPE_TEXT_PCREL32) {\
			reloc->addend -= (mo->baddr + addr);\
		}\
	} else {\
		reloc->addend = addend;\
	}\
	/* library ordinal ??? */ \
	reloc->ntype = op; \
	reloc->ord = lib_ord;\
	reloc->ord = sym_ord;\
	reloc->type = rel_type;\
	if (sym_name) {\
		r_str_ncpy (reloc->name, sym_name, 256);\
	}\
	if (threaded_binds) {\
		struct reloc_t **slot = RVecRelocRef_at (threaded_binds, sym_ord);\
		if (slot) {\
			*slot = reloc;\
		} else {\
			free (reloc);\
		}\
	} else {\
		r_skiplist_insert (mo->relocs_cache, reloc);\
	}\
} while (0)
				case BIND_OPCODE_DO_BIND:
					if (!threaded_binds && addr >= segment_end_addr) {
						R_LOG_DEBUG ("Malformed DO bind opcode 0x%"PFMT64x, addr);
						goto beach;
					}
					DO_BIND ();
					if (!threaded_binds) {
						addr += wordsize;
					} else {
						sym_ord++;
					}
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
					if (addr >= segment_end_addr) {
						R_LOG_DEBUG ("Malformed ADDR ULEB bind opcode");
						goto beach;
					}
					DO_BIND ();
					addr += read_uleb128 (&p, end) + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
					if (addr >= segment_end_addr) {
						R_LOG_DEBUG ("Malformed IMM SCALED bind opcode");
						goto beach;
					}
					DO_BIND ();
					addr += (ut64)imm * (ut64)wordsize + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
					count = read_uleb128 (&p, end);
					skip = read_uleb128 (&p, end);
					if (!check_bind_count (count, addr, segment_end_addr, skip, wordsize)) {
						R_LOG_DEBUG ("Count exceeds segment bounds");
						goto beach;
					}
					for (j = 0; j < count; j++) {
						if (addr >= segment_end_addr) {
							R_LOG_DEBUG ("Malformed ULEB TIMES bind opcode");
							goto beach;
						}
						DO_BIND ();
						addr += skip + wordsize;
					}
					break;
#undef DO_BIND
				default:
					R_LOG_DEBUG ("unknown bind opcode 0x%02x in dyld_info", *p);
					R_FREE (opcodes);
					RVecRelocRef_free (threaded_binds);
					return false;
				}
			}
			opcodes_offset += partition_size;
		}
		R_FREE (opcodes);
		RVecRelocRef_free (threaded_binds);
		threaded_binds = NULL;
	}

	if (mo->symtab && mo->symstr && mo->sects && mo->indirectsyms) {
		int j;
		int amount = mo->dysymtab.nundefsym;
		if (amount < 0) {
			amount = 0;
		}
		const int bin_limit = mo->limit;
		if (bin_limit > 0 && amount > bin_limit) {
			amount = bin_limit;
		}
		for (j = 0; j < amount; j++) {
			struct reloc_t *reloc = parse_import_ptr (mo, j);
			if (!reloc) {
				break;
			}
			reloc->ord = j;
			r_skiplist_insert_autofree (mo->relocs_cache, reloc);
		}
	}

	if (mo->symtab && mo->dysymtab.extreloff && mo->dysymtab.nextrel) {
		parse_relocation_info (mo, mo->relocs_cache, mo->dysymtab.extreloff, mo->dysymtab.nextrel);
	}

	if (!mo->dyld_info && mo->chained_starts && mo->nsegs && mo->fixups_offset) {
		walk_bind_chains (mo, mo->relocs_cache);
	}
beach:
	R_FREE (opcodes);
	RVecRelocRef_free (threaded_binds);
	return true;
}

const RSkipList *MACH0_(load_relocs)(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);

	if (mo->relocs_loaded) {
		return mo->relocs_cache;
	}
	mo->relocs_loaded = true;
	mo->relocs_cache = r_skiplist_new ((RListFree) free, (RListComparator) reloc_comparator);
	if (!mo->relocs_cache) {
		return NULL;
	}
	if (_load_relocations (mo)) {
		return mo->relocs_cache;
	}
	return NULL;
}

struct addr_t *MACH0_(get_entrypoint)(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);

	ut64 ea = entry_to_vaddr (mo);
	if (ea == 0 || ea == UT64_MAX) {
		return NULL;
	}
	struct addr_t *entry = R_NEW0 (struct addr_t);
	if (!entry) {
		return NULL;
	}
	entry->addr = ea;
	entry->offset = addr_to_offset (mo, entry->addr);
	entry->haddr = sdb_num_get (mo->kv, "mach0.entry.offset", 0);
	sdb_num_set (mo->kv, "mach0.entry.vaddr", entry->addr, 0);
	sdb_num_set (mo->kv, "mach0.entry.paddr", mo->entry, 0);

	if (entry->offset == 0 && !mo->sects) {
		int i;
		for (i = 0; i < mo->nsects; i++) {
			// XXX: section name shoudnt matter .. just check for exec flags
			if (r_str_startswith (mo->sects[i].sectname, "__text")) {
				entry->offset = (ut64)mo->sects[i].offset;
				sdb_num_set (mo->kv, "mach0.entry", entry->offset, 0);
				entry->addr = (ut64)mo->sects[i].addr;
				if (!entry->addr) { // workaround for object files
					R_LOG_INFO ("entrypoint is 0");
					// XXX(lowlyw) there's technically not really entrypoints
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

void MACH0_(kv_loadlibs)(struct MACH0_(obj_t) *mo) {
	int i;
	char lib_flagname[128];
	for (i = 0; i < mo->nlibs; i++) {
		snprintf (lib_flagname, sizeof (lib_flagname), "libs.%d.name", i);
		char **lib = RVecMach0Lib_at (&mo->libs_cache, i);
		sdb_set (mo->kv, lib_flagname, lib? *lib: NULL, 0);
	}
}

const RVecMach0Lib *MACH0_(load_libs)(struct MACH0_(obj_t) *mo) {
	R_RETURN_VAL_IF_FAIL (mo, NULL);
	if (!mo->nlibs) {
		return NULL;
	}
	if (mo->libs_loaded) {
		return &mo->libs_cache;
	}
	MACH0_(kv_loadlibs)(mo);
	return &mo->libs_cache;
}

ut64 MACH0_(get_baddr)(struct MACH0_(obj_t) *mo) {
	int i;

	if (mo->hdr.filetype != MH_EXECUTE && mo->hdr.filetype != MH_DYLINKER &&
			mo->hdr.filetype != MH_FILESET) {
		return 0;
	}
	for (i = 0; i < mo->nsegs; i++) {
		if (mo->segs[i].fileoff == 0 && mo->segs[i].filesize != 0) {
			return mo->segs[i].vmaddr;
		}
	}
	return 0;
}

char *MACH0_(get_class)(struct MACH0_(obj_t) *mo) {
#if R_BIN_MACH064
	return strdup ("MACH064");
#else
	return strdup ("MACH0");
#endif
}

//XXX we are mixing up bits from cpu and opcodes
//since thumb use 16 bits opcode but run in 32 bits
//cpus  so here we should only return 32 or 64
int MACH0_(get_bits)(struct MACH0_(obj_t) *mo) {
	if (mo) {
		int bits = MACH0_(get_bits_from_hdr) (&mo->hdr);
		if (mo->hdr.cputype == CPU_TYPE_ARM && mo->entry & 1) {
			return 16;
		}
		return bits;
	}
	return 32;
}

int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header) *hdr) {
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

bool MACH0_(is_big_endian)(struct MACH0_(obj_t) *mo) {
	if (mo) {
		const int cpu = mo->hdr.cputype;
		return cpu == CPU_TYPE_POWERPC || cpu == CPU_TYPE_POWERPC64;
	}
	return false;
}

const char *MACH0_(get_intrp)(struct MACH0_(obj_t) *mo) {
	return mo? mo->intrp: NULL;
}

const char *MACH0_(get_os)(struct MACH0_(obj_t) *mo) {
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

const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) *hdr) {
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

const char *MACH0_(get_cputype)(struct MACH0_(obj_t) *mo) {
	return mo? MACH0_(get_cputype_from_hdr) (&mo->hdr): "unknown";
}

static const char *cpusubtype_tostring(ut32 cputype, ut32 cpusubtype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		switch (cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL:	return "all";
		case CPU_SUBTYPE_VAX780:	return "vax780";
		case CPU_SUBTYPE_VAX785:	return "vax785";
		case CPU_SUBTYPE_VAX750:	return "vax750";
		case CPU_SUBTYPE_VAX730:	return "vax730";
		case CPU_SUBTYPE_UVAXI:		return "uvaxI";
		case CPU_SUBTYPE_UVAXII:	return "uvaxII";
		case CPU_SUBTYPE_VAX8200:	return "vax8200";
		case CPU_SUBTYPE_VAX8500:	return "vax8500";
		case CPU_SUBTYPE_VAX8600:	return "vax8600";
		case CPU_SUBTYPE_VAX8650:	return "vax8650";
		case CPU_SUBTYPE_VAX8800:	return "vax8800";
		case CPU_SUBTYPE_UVAXIII:	return "uvaxIII";
		default:			return "Unknown vax subtype";
		}
	case CPU_TYPE_MC680x0:
		switch (cpusubtype) {
		case CPU_SUBTYPE_MC68030:	return "mc68030";
		case CPU_SUBTYPE_MC68040:	return "mc68040";
		case CPU_SUBTYPE_MC68030_ONLY:	return "mc68030 only";
		default:			return "Unknown mc680x0 subtype";
		}
	case CPU_TYPE_RISCV:
		return "riscv";
	case CPU_TYPE_I386:
		switch (cpusubtype) {
		case CPU_SUBTYPE_386: 			return "386";
		case CPU_SUBTYPE_486: 			return "486";
		case CPU_SUBTYPE_486SX: 		return "486sx";
		case CPU_SUBTYPE_PENT: 			return "Pentium";
		case CPU_SUBTYPE_PENTPRO: 		return "Pentium Pro";
		case CPU_SUBTYPE_PENTII_M3: 		return "Pentium 3 M3";
		case CPU_SUBTYPE_PENTII_M5: 		return "Pentium 3 M5";
		case CPU_SUBTYPE_CELERON: 		return "Celeron";
		case CPU_SUBTYPE_CELERON_MOBILE:	return "Celeron Mobile";
		case CPU_SUBTYPE_PENTIUM_3:		return "Pentium 3";
		case CPU_SUBTYPE_PENTIUM_3_M:		return "Pentium 3 M";
		case CPU_SUBTYPE_PENTIUM_3_XEON:	return "Pentium 3 Xeon";
		case CPU_SUBTYPE_PENTIUM_M:		return "Pentium Mobile";
		case CPU_SUBTYPE_PENTIUM_4:		return "Pentium 4";
		case CPU_SUBTYPE_PENTIUM_4_M:		return "Pentium 4 M";
		case CPU_SUBTYPE_ITANIUM:		return "Itanium";
		case CPU_SUBTYPE_ITANIUM_2:		return "Itanium 2";
		case CPU_SUBTYPE_XEON:			return "Xeon";
		case CPU_SUBTYPE_XEON_MP:		return "Xeon MP";
		default:				return "Unknown i386 subtype";
		}
	case CPU_TYPE_X86_64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL:	return "x86 64 all";
		case CPU_SUBTYPE_X86_ARCH1:	return "x86 arch 1";
		default:			return "Unknown x86 subtype";
		}
	case CPU_TYPE_MC88000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL:	return "all";
		case CPU_SUBTYPE_MC88100:	return "mc88100";
		case CPU_SUBTYPE_MC88110:	return "mc88110";
		default:			return "Unknown mc88000 subtype";
		}
	case CPU_TYPE_MC98000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL:	return "all";
		case CPU_SUBTYPE_MC98601:	return "mc98601";
		default:			return "Unknown mc98000 subtype";
		}
	case CPU_TYPE_HPPA:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100:	return "hppa7100";
		case CPU_SUBTYPE_HPPA_7100LC:	return "hppa7100LC";
		default:			return "Unknown hppa subtype";
		}
	case CPU_TYPE_ARM64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM64_ALL:	return "all";
		case CPU_SUBTYPE_ARM64_V8:	return "arm64v8";
		case CPU_SUBTYPE_ARM64E:	return "arm64e";
		default:			return "Unknown arm64 subtype";
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
		case CPU_SUBTYPE_SPARC_ALL:	return "all";
		default:			return "Unknown sparc subtype";
		}
	case CPU_TYPE_MIPS:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL:	return "all";
		case CPU_SUBTYPE_MIPS_R2300:	return "r2300";
		case CPU_SUBTYPE_MIPS_R2600:	return "r2600";
		case CPU_SUBTYPE_MIPS_R2800:	return "r2800";
		case CPU_SUBTYPE_MIPS_R2000a:	return "r2000a";
		case CPU_SUBTYPE_MIPS_R2000:	return "r2000";
		case CPU_SUBTYPE_MIPS_R3000a:	return "r3000a";
		case CPU_SUBTYPE_MIPS_R3000:	return "r3000";
		default:			return "Unknown mips subtype";
		}
	case CPU_TYPE_I860:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL:	return "all";
		case CPU_SUBTYPE_I860_860:	return "860";
		default:			return "Unknown i860 subtype";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL:	return "all";
		case CPU_SUBTYPE_POWERPC_601:	return "601";
		case CPU_SUBTYPE_POWERPC_602:	return "602";
		case CPU_SUBTYPE_POWERPC_603:	return "603";
		case CPU_SUBTYPE_POWERPC_603e:	return "603e";
		case CPU_SUBTYPE_POWERPC_603ev:	return "603ev";
		case CPU_SUBTYPE_POWERPC_604:	return "604";
		case CPU_SUBTYPE_POWERPC_604e:	return "604e";
		case CPU_SUBTYPE_POWERPC_620:	return "620";
		case CPU_SUBTYPE_POWERPC_750:	return "750";
		case CPU_SUBTYPE_POWERPC_7400:	return "7400";
		case CPU_SUBTYPE_POWERPC_7450:	return "7450";
		case CPU_SUBTYPE_POWERPC_970:	return "970";
		default:			return "Unknown ppc subtype";
		}
	}
	return "Unknown cputype";
}

char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	R_RETURN_VAL_IF_FAIL (hdr, NULL);
	return strdup (cpusubtype_tostring (hdr->cputype, hdr->cpusubtype));
}

char *MACH0_(get_cpusubtype)(struct MACH0_(obj_t) *mo) {
	return mo? MACH0_(get_cpusubtype_from_hdr) (&mo->hdr): strdup ("Unknown");
}

bool MACH0_(is_pie)(struct MACH0_(obj_t) *mo) {
	return (mo && mo->hdr.filetype == MH_EXECUTE && mo->hdr.flags & MH_PIE);
}

bool MACH0_(has_nx)(struct MACH0_(obj_t) *mo) {
	return (mo && mo->hdr.filetype == MH_EXECUTE &&
		mo->hdr.flags & MH_NO_HEAP_EXECUTION);
}

char *MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	const char *mhtype = "Unknown";
	switch (hdr->filetype) {
	case MH_OBJECT:     mhtype = "Relocatable object"; break;
	case MH_EXECUTE:    mhtype = "Executable file"; break;
	case MH_FVMLIB:     mhtype = "Fixed VM shared library"; break;
	case MH_CORE:       mhtype = "Core file"; break;
	case MH_PRELOAD:    mhtype = "Preloaded executable file"; break;
	case MH_DYLIB:      mhtype = "Dynamically bound shared library"; break;
	case MH_DYLINKER:   mhtype = "Dynamic link editor"; break;
	case MH_BUNDLE:     mhtype = "Dynamically bound bundle file"; break;
	case MH_DYLIB_STUB: mhtype = "Shared library stub for static linking (no sections)"; break;
	case MH_DSYM:       mhtype = "Companion file with only debug sections"; break;
	case MH_KEXT_BUNDLE: mhtype = "Kernel extension bundle file"; break;
	case MH_FILESET:    mhtype = "Kernel cache file"; break;
	}
	return strdup (mhtype);
}

char *MACH0_(get_filetype)(struct MACH0_(obj_t) *mo) {
	return mo? MACH0_(get_filetype_from_hdr) (&mo->hdr): strdup ("Unknown");
}

ut64 MACH0_(get_main)(struct MACH0_(obj_t) *mo) {
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
	free (MACH0_(get_entrypoint)(mo));

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
	ut64 addr_end = addr + size;
	RStrBuf *sb = r_strbuf_new ("");
	struct MACH0_(obj_t) *bo = bf->bo->bin_obj;
	SuperBlob sblob = {0};
	if (r_buf_fread_at (bo->b, addr, (ut8*)&sblob, "3I", 1) != -1) {
		r_strbuf_appendf (sb, "0x%08"PFMT64x" superblob.magic = 0x%08x\n", (ut64)addr, sblob.magic);
		r_strbuf_appendf (sb, "0x%08"PFMT64x" superblob.length = 0x%08x\n", (ut64)addr + 4, sblob.length);
		r_strbuf_appendf (sb, "0x%08"PFMT64x" superblob.count = 0x%08x\n", (ut64)addr + 8, sblob.count);
	}
	addr += (3 * 4); // skip superblob
	for (i = 0; i < sblob.count; i++) {
		// type : offset
		ut32 to[2];
		if (r_buf_fread_at (bo->b, addr, (ut8*)&to, "2I", 1) == -1) {
			break;
		}
		r_strbuf_appendf (sb, "0x%08"PFMT64x" type 0x%08x off %d\n", (ut64)addr, to[0], to[1]);
		addr += 8;
	}
	for (i = 0; i < sblob.count; i++) {
		if (addr >= addr_end) {
			break;
		}
		if (r_buf_fread_at (bo->b, addr, (ut8*)&magic, "1I", 1) == -1) {
			R_LOG_DEBUG ("cannot read");
			break;
		}
		r_strbuf_appendf (sb, "0x%08"PFMT64x" blob %d magic 0x%08x:\n", (ut64)addr, i, magic);
		switch (magic) {
		case 0xfade0c02: // codedirectory
			{
				CodeDirectory cdbuf = {0}; // align pls
				if (r_buf_fread_at (bo->b, addr, (ut8*)&cdbuf, "9I", 1) == -1) {
					R_LOG_WARN ("Cant read at 0x%"PFMT64x, (ut64)addr);
					// cant read the struct
				} else {
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.magic    0x%08x\n", (ut64)addr, cdbuf.magic);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.length   0x%08x\n", (ut64)addr+4, cdbuf.length);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.version  0x%08x\n", (ut64)addr + 8, cdbuf.version);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.flags    0x%08x\n", (ut64)addr+12, cdbuf.flags);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.hashoff  0x%08x\n", (ut64)addr+16, cdbuf.hashOffset);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.identoff 0x%08x\n", (ut64)addr+20, cdbuf.identOffset);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.nspecials  0x%08x\n", (ut64)addr+24, cdbuf.nSpecialSlots);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.ncodes     0x%08x\n", (ut64)addr+28, cdbuf.nCodeSlots);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.codelimit  0x%08x\n", (ut64)addr+32, cdbuf.codeLimit);
					// ut8
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.hashsize   0x%02x\n", (ut64)addr+36, cdbuf.hashSize);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.hashtype   0x%02x\n", (ut64)addr+40, cdbuf.hashType);
					r_strbuf_appendf (sb, "0x%08"PFMT64x" code.dir.pagesize   0x%02x\n", (ut64)addr+40, cdbuf.pageSize); // log2() or 0
				}
				addr += sizeof (CodeDirectory) - 4;
			}
			break;
		case 0xfade0cc0: // embedded signature
			r_strbuf_appendf (sb, "0x%08"PFMT64x" magic embedded signature\n", (ut64)addr);
			break;
		case 0xfade0cc1: // detached signature
			r_strbuf_appendf (sb, "0x%08"PFMT64x" magic detached signature\n", (ut64)addr);
			break;
		case 0xfade0c01: // requirements
		case 0xfade0b01:
			r_strbuf_appendf (sb, "0x%08"PFMT64x" codesign requirements\n", (ut64)addr);
			break;
		case 0xfade7171:
			r_strbuf_appendf (sb, "0x%08"PFMT64x" codesign digest\n", (ut64)addr);
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
	return r_strbuf_drain (sb);
}

void MACH0_(mach_headerfields)(RBinFile *bf) {
	struct MACH0_(obj_t) *mo = bf->bo->bin_obj;
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	if (!cb_printf) {
		cb_printf = printf;
	}
	RBuffer *buf = bf->buf;
	ut64 length = r_buf_size (buf);
	int n = 0;
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr)(buf);
	if (!mh) {
		return;
	}
	ut64 pvaddr = pa2va (bf, 0);
	cb_printf ("pf.mach0_header @ 0x%08"PFMT64x"\n", pvaddr);
	cb_printf ("0x%08"PFMT64x"  Magic       0x%x\n", pvaddr, mh->magic);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  CpuType     0x%x\n", pvaddr, mh->cputype);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  CpuSubType  0x%x\n", pvaddr, mh->cpusubtype);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  FileType    0x%x\n", pvaddr, mh->filetype);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  nCmds       %d\n", pvaddr, mh->ncmds);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  sizeOfCmds  %d\n", pvaddr, mh->sizeofcmds);
	pvaddr += 4;
	cb_printf ("0x%08"PFMT64x"  Flags       0x%x\n", pvaddr, mh->flags);
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
		if (r_buf_read_at (buf, addr, (ut8*)wordbuf, 4) != 4) { \
			R_LOG_WARN ("Invalid address in buffer"); \
			break; \
		} \
		addr += 4; \
		pvaddr += 4;\
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
			cb_printf ("pf.%s @ 0x%08"PFMT64x"\n", pf_definition, pvaddr - 4);
		}
		cb_printf ("0x%08"PFMT64x"  cmd %7d 0x%x %s\n",
			pvaddr - 4, n, lcType, cmd_tostring (lcType));
		READWORD ();
		if (addr > length) {
			break;
		}
		int lcSize = word;
		word &= 0xFFFFFF;
		cb_printf ("0x%08"PFMT64x"  cmdsize     %d\n", pvaddr - 4, word);
		if (lcSize < 1) {
			R_LOG_WARN ("Invalid size for a load command");
			break;
		}
		switch (lcType) {
		case LC_BUILD_VERSION: {
			cb_printf ("0x%08"PFMT64x"  platform    %s\n",
				pvaddr, build_version_platform_tostring (r_buf_read_le32_at (buf, addr)));
			cb_printf ("0x%08"PFMT64x"  minos       %d.%d.%d\n",
				pvaddr + 4, r_buf_read_le16_at (buf, addr + 6), r_buf_read8_at (buf, addr + 5),
				r_buf_read8_at (buf, addr + 4));
			cb_printf ("0x%08"PFMT64x"  sdk         %d.%d.%d\n",
				pvaddr + 8, r_buf_read_le16_at (buf, addr + 10), r_buf_read8_at (buf, addr + 9),
				r_buf_read8_at (buf, addr + 8));
			ut32 ntools = r_buf_read_le32_at (buf, addr + 12);
			cb_printf ("0x%08"PFMT64x"  ntools      %d\n",
				pvaddr + 12, ntools);
			ut64 off = 16;
			while (off < (lcSize - 8) && ntools--) {
				cb_printf ("pf.mach0_build_version_tool @ 0x%08"PFMT64x"\n", pvaddr + off);
				cb_printf ("0x%08"PFMT64x"  tool        %s\n",
					pvaddr + off, build_version_tool_tostring (r_buf_read_le32_at (buf, addr + off)));
				off += 4;
				if (off >= (lcSize - 8)) {
					break;
				}
				cb_printf ("0x%08"PFMT64x"  version     %d.%d.%d\n",
					pvaddr + off, r_buf_read_le16_at (buf, addr + off + 2), r_buf_read8_at (buf, addr + off + 1),
					r_buf_read8_at (buf, addr + off));
				off += 4;
			}
			break;
		}
		case LC_MAIN:
			{
				ut8 data[64] = {0};
				r_buf_read_at (buf, addr, data, sizeof (data));
#if R_BIN_MACH064
				ut64 ep = r_read_ble64 (&data, false); //  bin->big_endian);
				cb_printf ("0x%08"PFMT64x"  entry0      0x%" PFMT64x "\n", pvaddr, ep);
				ut64 ss = r_read_ble64 (&data[8], false); //  bin->big_endian);
				cb_printf ("0x%08"PFMT64x"  stacksize   0x%" PFMT64x "\n", pvaddr +  8, ss);
#else
				ut32 ep = r_read_ble32 (&data, false); //  bin->big_endian);
				cb_printf ("0x%08"PFMT32x"  entry0      0x%" PFMT32x "\n", (ut32)pvaddr, ep);
				ut32 ss = r_read_ble32 (&data[4], false); //  bin->big_endian);
				cb_printf ("0x%08"PFMT32x"  stacksize   0x%" PFMT32x "\n", (ut32)pvaddr +  4, ss);
#endif
			}
			break;
		case LC_SYMTAB:
#if 0
			{
			char *id = r_buf_get_string (buf, addr + 20);
			cb_printf ("0x%08"PFMT64x"  id         0x%x\n", addr + 20, r_str_get (id));
			cb_printf ("0x%08"PFMT64x"  symooff    0x%x\n", addr + 20, r_str_get (id));
			cb_printf ("0x%08"PFMT64x"  nsyms      %d\n", addr + 20, r_str_get (id));
			cb_printf ("0x%08"PFMT64x"  stroff     0x%x\n", addr + 20, r_str_get (id));
			cb_printf ("0x%08"PFMT64x"  strsize    0x%x\n", addr + 20, r_str_get (id));
			free (id);
			}
#endif
			break;
		case LC_ID_DYLIB: { // install_name_tool
			ut32 str_off = r_buf_read_ble32_at (buf, addr, isBe);
			char *id = r_buf_get_string (buf, addr + str_off - 8);
			cb_printf ("0x%08"PFMT64x"  current     %d.%d.%d\n",
				pvaddr + 8, r_buf_read_le16_at (buf, addr + 10), r_buf_read8_at (buf, addr + 9),
				r_buf_read8_at (buf, addr + 8));
			cb_printf ("0x%08"PFMT64x"  compat      %d.%d.%d\n",
				pvaddr + 12, r_buf_read_le16_at (buf, addr + 14), r_buf_read8_at (buf, addr + 13),
				r_buf_read8_at (buf, addr + 12));
			cb_printf ("0x%08"PFMT64x"  id          %s\n",
				pvaddr + str_off - 8, r_str_get (id));
			free (id);
			break;
		}
		case LC_UUID:
			{
				ut8 i, uuid[16];
				r_buf_read_at (buf, addr, uuid, sizeof (uuid));
				cb_printf ("0x%08"PFMT64x"  uuid        ", pvaddr);
				for (i = 0; i < sizeof (uuid); i++) {
					cb_printf ("%02x", uuid[i]);
				}
				cb_printf ("\n");
			}
			break;
		case LC_SEGMENT:
		case LC_SEGMENT_64:
			{
				ut8 name[17] = {0};
				r_buf_read_at (buf, addr, name, sizeof (name) - 1);
				cb_printf ("0x%08"PFMT64x"  name        %s\n", pvaddr, name);
				ut32 nsects = r_buf_read_le32_at (buf, addr - 8 + (is64 ? 64 : 48));
				ut64 off = is64 ? 72 : 56;
				while (off < lcSize && nsects--) {
					if (is64) {
						cb_printf ("pf.mach0_section64 @ 0x%08"PFMT64x"\n", pvaddr - 8 + off);
						off += 80;
					} else {
						cb_printf ("pf.mach0_section @ 0x%08"PFMT64x"\n", pvaddr - 8 + off);
						off += 68;
					}
				}
			}
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB: {
			ut32 str_off = r_buf_read_ble32_at (buf, addr, isBe);
			char *load_dylib = r_buf_get_string (buf, addr + str_off - 8);
			cb_printf ("0x%08"PFMT64x"  current     %d.%d.%d\n",
				pvaddr + 8, r_buf_read_le16_at (buf, addr + 10), r_buf_read8_at (buf, addr + 9),
				r_buf_read8_at (buf, addr + 8));
			cb_printf ("0x%08"PFMT64x"  compat      %d.%d.%d\n",
				pvaddr + 12, r_buf_read_le16_at (buf, addr + 14), r_buf_read8_at (buf, addr + 13),
				r_buf_read8_at (buf, addr + 12));
			cb_printf ("0x%08"PFMT64x"  load_dylib  %s\n",
				pvaddr + str_off - 8, r_str_get (load_dylib));
			if (load_dylib) {
				free (load_dylib);
			}
			break;
		}
		case LC_RPATH: {
			char *rpath = r_buf_get_string (buf, addr + 4);
			cb_printf ("0x%08" PFMT64x "  rpath       %s\n",
				pvaddr + 4, r_str_get (rpath));
			if (rpath) {
				free (rpath);
			}
			break;
		}
		case LC_ENCRYPTION_INFO:
		case LC_ENCRYPTION_INFO_64: {
			ut32 word = r_buf_read_le32_at (buf, addr);
			cb_printf ("0x%08"PFMT64x"  cryptoff   0x%08x\n", pvaddr, word);
			word = r_buf_read_le32_at (buf, addr + 4);
			cb_printf ("0x%08"PFMT64x"  cryptsize  %d\n", pvaddr + 4, word);
			word = r_buf_read_le32_at (buf, addr + 8);
			cb_printf ("0x%08"PFMT64x"  cryptid    %d\n", pvaddr + 8, word);
			break;
		}
		// https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c.auto.html
		case LC_CODE_SIGNATURE: {
			ut32 words[2];
			r_buf_read_at (buf, addr, (ut8 *)words, sizeof (words));
			cb_printf ("0x%08"PFMT64x"  codesig.dataoff     0x%08x\n", pvaddr, words[0]);
			cb_printf ("0x%08"PFMT64x"  codesig.datasize    %d\n", pvaddr + 4, words[1]);
			cb_printf ("# wtf mach0.sign %d @ 0x%x\n", words[1], words[0]);
			char *s = walk_codesig (bf, words[0], words[1]);
			cb_printf ("%s", s);
			free (s);
			break;
		}
		}
		addr += word - 8;
		pvaddr += word - 8;
	}
	free (mh);
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
		case LC_BUILD_VERSION: {
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
				RBinField *f = r_bin_field_new (at, addr + off, 1, -1,
					tool_flagname, "mach0_build_version_tool", "mach0_build_version_tool", true);
				r_list_append (ret, f);
				off += 8;
			}
			break;
		}
		case LC_SEGMENT:
		case LC_SEGMENT_64: {
			ut32 nsects = r_buf_read_le32_at (buf, addr + (is64 ? 64 : 48));
			ut64 off = is64 ? 72 : 56;
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

struct MACH0_(mach_header) *MACH0_(get_hdr)(RBuffer *buf) {
	ut8 magicbytes[sizeof (ut32)] = {0};
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = {0};
	int len;
	struct MACH0_(mach_header) *macho_hdr = R_NEW0 (struct MACH0_(mach_header));
	bool big_endian = false;
	if (!macho_hdr) {
		return NULL;
	}
	if (r_buf_read_at (buf, 0, magicbytes, 4) < 1) {
		free (macho_hdr);
		return false;
	}
	const ut32 lemagic = r_read_le32 (magicbytes);
	const ut32 bemagic = r_read_be32 (magicbytes);
	// TODO: simplify this
	if (lemagic == 0xfeedface) {
		big_endian = false;
	} else if (bemagic == 0xfeedface) {
		big_endian = true;
	} else if (lemagic == FAT_MAGIC) {
		big_endian = false;
	} else if (bemagic == FAT_MAGIC) {
		big_endian = true;
	} else if (lemagic == 0xfeedfacf) {
		big_endian = false;
	} else if (bemagic == 0xfeedfacf) {
		big_endian = true;
	} else {
		/* also extract non-mach0s */
#if 0
		free (macho_hdr);
		return NULL;
#endif
	}
	len = r_buf_read_at (buf, 0, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof (struct MACH0_(mach_header))) {
		free (macho_hdr);
		return NULL;
	}
	macho_hdr->magic = r_read_ble (&machohdrbytes[0], big_endian, 32);
	macho_hdr->cputype = r_read_ble (&machohdrbytes[4], big_endian, 32);
	macho_hdr->cpusubtype = r_read_ble (&machohdrbytes[8], big_endian, 32);
	macho_hdr->filetype = r_read_ble (&machohdrbytes[12], big_endian, 32);
	macho_hdr->ncmds = r_read_ble (&machohdrbytes[16], big_endian, 32);
	macho_hdr->sizeofcmds = r_read_ble (&machohdrbytes[20], big_endian, 32);
	macho_hdr->flags = r_read_ble (&machohdrbytes[24], big_endian, 32);
#if R_BIN_MACH064
	macho_hdr->reserved = r_read_ble (&machohdrbytes[28], big_endian, 32);
#endif
	return macho_hdr;
}

#define IS_FMT_32BIT(x) (x == DYLD_CHAINED_PTR_32 || x == DYLD_CHAINED_PTR_32_CACHE || x == DYLD_CHAINED_PTR_32_FIRMWARE)

void MACH0_(iterate_chained_fixups)(struct MACH0_(obj_t) *mo, ut64 limit_start, ut64 limit_end, ut32 event_mask, RFixupCallback callback, void * context) {
	int i;
	for (i = 0; i < mo->nsegs && i < mo->segs_count; i++) {
		if (!mo->chained_starts[i]) {
			continue;
		}
		int page_size = mo->chained_starts[i]->page_size;
		if (page_size < 1) {
			page_size = 4096;
		}
		ut64 start = mo->segs[i].fileoff;
		ut64 end = start + mo->segs[i].filesize;
		if (end >= limit_start && start <= limit_end) {
			ut64 page_idx = (R_MAX (start, limit_start) - start) / page_size;
			ut64 page_end_idx = (R_MIN (limit_end, end) - start) / page_size;
			for (; page_idx <= page_end_idx; page_idx++) {
				if (page_idx >= mo->chained_starts[i]->page_count) {
					break;
				}
				if (!mo->chained_starts[i]->page_start) {
					break;
				}
				ut16 page_start = mo->chained_starts[i]->page_start[page_idx];
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
					ut16 pointer_format = mo->chained_starts[i]->pointer_format;
					ut64 raw_ptr = IS_FMT_32BIT (pointer_format)? r_read_le32 (tmp) : r_read_le64 (tmp);
					ut64 ptr_value = raw_ptr;
					ut64 delta, stride, addend;
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
									(struct dyld_chained_ptr_arm64e_auth_bind *) &raw_ptr;
							event = R_FIXUP_EVENT_BIND_AUTH;
							delta = p->next;
							ordinal = p->ordinal;
							key = p->key;
							addr_div = p->addrDiv;
							diversity = p->diversity;
						} else if (!is_auth && is_bind) {
							struct dyld_chained_ptr_arm64e_bind *p =
									(struct dyld_chained_ptr_arm64e_bind *) &raw_ptr;
							event = R_FIXUP_EVENT_BIND;
							delta = p->next;
							ordinal = p->ordinal;
							addend = p->addend;
						} else if (is_auth && !is_bind) {
							struct dyld_chained_ptr_arm64e_auth_rebase *p =
									(struct dyld_chained_ptr_arm64e_auth_rebase *) &raw_ptr;
							event = R_FIXUP_EVENT_REBASE_AUTH;
							delta = p->next;
							ptr_value = p->target + mo->baddr;
							key = p->key;
							addr_div = p->addrDiv;
							diversity = p->diversity;
						} else {
							struct dyld_chained_ptr_arm64e_rebase *p =
									(struct dyld_chained_ptr_arm64e_rebase *) &raw_ptr;
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
								(struct dyld_chained_ptr_arm64e_bind24 *) &raw_ptr;
						if (bind->bind) {
							delta = bind->next;
							if (bind->auth) {
								struct dyld_chained_ptr_arm64e_auth_bind24 *p =
										(struct dyld_chained_ptr_arm64e_auth_bind24 *) &raw_ptr;
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
										(struct dyld_chained_ptr_arm64e_auth_rebase *) &raw_ptr;
								event = R_FIXUP_EVENT_REBASE_AUTH;
								delta = p->next;
								ptr_value = p->target + mo->baddr;
								key = p->key;
								addr_div = p->addrDiv;
								diversity = p->diversity;
							} else {
								struct dyld_chained_ptr_arm64e_rebase *p =
									(struct dyld_chained_ptr_arm64e_rebase *) &raw_ptr;
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
								(struct dyld_chained_ptr_64_bind *) &raw_ptr;
						if (bind->bind) {
							event = R_FIXUP_EVENT_BIND;
							delta = bind->next;
							ordinal = bind->ordinal;
							addend = bind->addend;
						} else {
							struct dyld_chained_ptr_64_rebase *p =
								(struct dyld_chained_ptr_64_rebase *) &raw_ptr;
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
								(struct dyld_chained_ptr_32_bind *) &raw_ptr;
						if (bind->bind) {
							event = R_FIXUP_EVENT_BIND;
							delta = bind->next;
							ordinal = bind->ordinal;
							addend = bind->addend;
						} else {
							struct dyld_chained_ptr_32_rebase *p =
								(struct dyld_chained_ptr_32_rebase *) &raw_ptr;
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
							(struct dyld_chained_ptr_32_cache_rebase *) &raw_ptr;
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
							(struct dyld_chained_ptr_32_firmware_rebase *) &raw_ptr;
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
						bool carry_on;
						switch (event) {
						case R_FIXUP_EVENT_BIND: {
							RFixupBindEventDetails event_details = {
								.type = event,
								.bin = mo,
								.offset = cursor,
								.raw_ptr = raw_ptr,
								.ptr_size = ptr_size,
								.ordinal = ordinal,
								.addend = addend,
							};
							carry_on = callback (context, (RFixupEventDetails *) &event_details);
							break;
						}
						case R_FIXUP_EVENT_BIND_AUTH: {
							RFixupBindAuthEventDetails event_details = {
								.type = event,
								.bin = mo,
								.offset = cursor,
								.raw_ptr = raw_ptr,
								.ptr_size = ptr_size,
								.ordinal = ordinal,
								.key = key,
								.addr_div = addr_div,
								.diversity = diversity,
							};
							carry_on = callback (context, (RFixupEventDetails *) &event_details);
							break;
						}
						case R_FIXUP_EVENT_REBASE: {
							RFixupRebaseEventDetails event_details = {
								.type = event,
								.bin = mo,
								.offset = cursor,
								.raw_ptr = raw_ptr,
								.ptr_size = ptr_size,
								.ptr_value = ptr_value,
							};
							carry_on = callback (context, (RFixupEventDetails *) &event_details);
							break;
						}
						case R_FIXUP_EVENT_REBASE_AUTH: {
							RFixupRebaseAuthEventDetails event_details = {
								.type = event,
								.bin = mo,
								.offset = cursor,
								.raw_ptr = raw_ptr,
								.ptr_size = ptr_size,
								.ptr_value = ptr_value,
								.key = key,
								.addr_div = addr_div,
								.diversity = diversity,
							};
							carry_on = callback (context, (RFixupEventDetails *) &event_details);
							break;
						}
						default:
							R_LOG_WARN ("Unexpected event while iterating chained fixups");
							carry_on = false;
							break;
						}
						if (!carry_on) {
							return;
						}
					}
					cursor += delta * stride;
					if (!delta) {
						break;
					}
				}
			}
		}
	}
}
