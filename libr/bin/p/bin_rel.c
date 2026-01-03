/* radare - LGPL - 2022-2026 - terorie */

#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>

#define MAX_SECTION_COUNT 128
#define MAX_IMP_COUNT 128
#define MAX_RELOC_COUNT (1 << 26)

R_PACKED(typedef struct {
	ut32 module_id;
	ut32 next_module_vaddr;
	ut32 prev_module_vaddr;
	ut32 num_sections;
	ut32 section_table_paddr;
	ut32 module_name_paddr;
	ut32 module_name_length;
	ut32 module_version;
	ut32 bss_size;
	ut32 reloc_table_offset;
	ut32 imp_table_paddr;
	ut32 imp_table_size;
	ut8 prolog_section;
	ut8 epilog_section;
	ut8 unresolved_section;
	ut8 bss_section;
	ut32 prolog_offset;
	ut32 epilog_offset;
	ut32 unresolved_offset;
})
RelHeader;

R_PACKED(typedef struct {
	ut32 align;
	ut32 bss_align;
	ut32 bss_size;
})
RelV3Ext;

R_PACKED(typedef struct {
	ut32 offset_packed;
	ut32 size;
})
RelSection;

// Imp/Reloc handling
//
// Wii REL libs always depend on a "main.dol" (Wii's base ROM), provided by the bin.dol plugin.
// They can also dynamically link against other REL libs.
//
// The libs to reloc against are identified by a 32-bit module ID.
// Each lib then gets a RelImp which points to a RelReloc table.
// This plugin behaves a bit differently depending on each lib:
//
//  - 0:      Relocs to main.dol
//            main.dol is not relocatable, thus uses absolute addresses as addends (S = 0)
//            Used for fixing up relative references (e.g. branches).
//            Patched on load without emitting a symbol/reloc.
//
//  - <self>: If imp module ID equals ID from REL header, these are relocs between PIC.
//            Basically everything that needs absolute addresses, such as
//              - xrefs from to data sections
//              - switch tables, vtables
//            Patched on load without emitting a symbol/reloc.
//
//  - <i>:    Relocs to other RELs (unsupported for now)
//            Emits an import and a reloc.

R_PACKED(typedef struct {
	ut32 module; // target lib (0 = main.dol, N = other REL)
	ut32 relocs_paddr;
})
RelImp;

R_PACKED(typedef struct {
	ut16 offset;
	ut8 type;
	ut8 section;
	ut32 addend;
})
RelReloc;

#define REL_MODULE_MAIN_DOL 0

#define R_PPC_NONE 0
#define R_PPC_ADDR32 1
#define R_PPC_ADDR24 2
#define R_PPC_ADDR16 3
#define R_PPC_ADDR16_LO 4
#define R_PPC_ADDR16_HI 5
#define R_PPC_ADDR16_HA 6
#define R_PPC_ADDR14 7
#define R_PPC_ADDR14_BRTAKEN 8
#define R_PPC_ADDR14_BRNTAKEN 9
#define R_PPC_REL24 10
#define R_PPC_REL14 11
#define R_PPC_REL14_BRTAKEN 12
#define R_PPC_REL14_BRNTAKEN 13
#define R_RVL_NONE 201
#define R_RVL_SECT 202
#define R_RVL_STOP 203

#if DEBUG
// TODO: we need a way to stringify the RBinReloc->ntype when listing it from cbin, for now just comment as its debug only
static const char *reloc_str(int reloc) {
	switch (reloc) {
	case R_PPC_NONE: return "R_PPC_NONE";
	case R_PPC_ADDR32: return "R_PPC_ADDR32";
	case R_PPC_ADDR24: return "R_PPC_ADDR24";
	case R_PPC_ADDR16: return "R_PPC_ADDR16";
	case R_PPC_ADDR16_LO: return "R_PPC_ADDR16_LO";
	case R_PPC_ADDR16_HI: return "R_PPC_ADDR16_HI";
	case R_PPC_ADDR16_HA: return "R_PPC_ADDR16_HA";
	case R_PPC_ADDR14: return "R_PPC_ADDR14";
	case R_PPC_ADDR14_BRTAKEN: return "R_PPC_ADDR14_BRTAKEN";
	case R_PPC_ADDR14_BRNTAKEN: return "R_PPC_ADDR14_BRNTAKEN";
	case R_PPC_REL24: return "R_PPC_REL24";
	case R_PPC_REL14: return "R_PPC_REL14";
	case R_PPC_REL14_BRTAKEN: return "R_PPC_REL14_BRTAKEN";
	case R_PPC_REL14_BRNTAKEN: return "R_PPC_REL14_BRNTAKEN";
	case R_RVL_NONE: return "R_RVL_NONE";
	case R_RVL_SECT: return "R_RVL_SECT";
	case R_RVL_STOP: return "R_RVL_STOP";
	default: return "";
	}
}
#endif

typedef struct {
	RelHeader hdr;
	RelV3Ext v3;
	const RelSection *sections;
	ut32 *section_vaddrs;
	int num_imps;
	const RelImp *imps;
	const int *reloc_counts; // LUT imp idx => reloc count
	const RelReloc *const *relocs;
	const char *libname; // owned by RBinInfo
} LoadedRel;

static ut32 rel_section_paddr(const RelSection *rel) {
	return rel->offset_packed & 0xFFFFFFFC;
}

static bool rel_section_is_executable(const RelSection *rel) {
	return rel->offset_packed & 1;
}

static int load_reloc_table(RelReloc *out, RBuffer *buf, ut64 addr) {
	r_buf_seek (buf, addr, R_BUF_SET);
	int i;
	for (i = 0; i < MAX_RELOC_COUNT; i++) {
		RelReloc reloc = { 0 };
		if (r_buf_fread (buf, (void *)&reloc, "SccI", 1) == -1) {
			break;
		}
		if (reloc.type == R_RVL_STOP) {
			break;
		}
		if (out) {
			*out = reloc;
			out++;
		}
	}
	if (i == MAX_RELOC_COUNT) {
		R_LOG_ERROR ("Too many relocs, stopped at index %d", i);
	}
	return i;
}

static bool vread_at_be32(RBin *b, ut32 vaddr, ut32 *out) {
	ut8 buf[4] = { 0 };
	if (!b->iob.read_at (b->iob.io, vaddr, (void *)&buf, sizeof (buf))) {
		return false;
	}
	*out = r_read_be32 (&buf);
	return true;
}

static bool vwriten_at_be32(RBin *b, ut32 vaddr, ut32 val, ut32 size) {
	R_RETURN_VAL_IF_FAIL (size <= 4, false);
	ut8 buf[4];
	r_write_be32 (&buf, val);
	return b->iob.overlay_write_at (b->iob.io, vaddr, (void *)&buf, size);
}

static bool file_has_rel_ext(RBinFile *bf) {
	if (R_LIKELY (bf && bf->file)) {
		char *lowername = strdup (bf->file);
		r_str_case (lowername, 0);
		char *ext = strstr (lowername, ".rel");
		bool ret = ext && ext[4] == '\0';
		free (lowername);
		return ret;
	}
	return false;
}

static LoadedRel *load_rel_header(RBinFile *bf) {
	if (r_buf_size (bf->buf) < sizeof (RelHeader)) {
		return NULL;
	}
	LoadedRel *rel = R_NEW0 (LoadedRel);
	if (r_buf_fread_at (bf->buf, 0, (void *)&rel->hdr, "12I4c3I", 1) == -1) {
		free (rel);
		return NULL;
	}
	return rel;
}

static bool check(RBinFile *bf, RBuffer *buf) {
	if (!file_has_rel_ext (bf)) {
		return false;
	}

	const LoadedRel *rel = load_rel_header (bf);
	if (!rel) {
		return false;
	}

	bool ret = rel->hdr.num_sections > 0 && rel->hdr.module_version <= 3;
	free ((void *)rel);
	return ret;
}

// RBinPlugin method setting up sections and fixing up PIC.
static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	RelSection *sections = NULL;
	int i;
	int num_imps;
	RelImp *imps = NULL;
	int *reloc_counts = NULL;
	RelReloc **relocs = NULL;

	LoadedRel *rel = load_rel_header (bf);
	if (!rel) {
		return false;
	}
	R_LOG_INFO ("REL module ID %08x", rel->hdr.module_id);
	R_LOG_INFO ("REL version %u", rel->hdr.module_version);
	if (rel->hdr.module_version == 3) {
		if (r_buf_fread_at (bf->buf, 0x40, (void *)&rel->v3, "3I", 1) == -1) {
			free (rel);
			return false;
		}
	}

	// Load section table
	if (rel->hdr.num_sections > MAX_SECTION_COUNT) {
		R_LOG_WARN ("Too many sections (%u), limiting to %u", rel->hdr.num_sections, MAX_SECTION_COUNT);
		rel->hdr.num_sections = MAX_SECTION_COUNT;
	}
	sections = R_NEWS0 (RelSection, rel->hdr.num_sections);
	if (!sections) {
		goto beach;
	}
	if (r_buf_fread_at (bf->buf, rel->hdr.section_table_paddr, (void *)sections, "2I", rel->hdr.num_sections) == -1) {
		goto beach;
	}
	rel->sections = sections;
	rel->section_vaddrs = R_NEWS0 (ut32, rel->hdr.num_sections);

	// Load imports table
	// Name is misleading; an import entry just points to a reloc table + module ID.
	// So it does not directly relate to r2's imports and relocs.
	num_imps = rel->hdr.imp_table_size / sizeof (RelImp);
	if (num_imps > MAX_IMP_COUNT) {
		R_LOG_WARN ("Too many imps (%u), limiting to %u", num_imps, MAX_IMP_COUNT);
		num_imps = MAX_IMP_COUNT;
	}
	imps = R_NEWS0 (RelImp, num_imps);
	reloc_counts = R_NEWS0 (int, num_imps);
	relocs = R_NEWS0 (RelReloc *, num_imps);
	if (!imps || !reloc_counts || !relocs) {
		goto beach;
	}
	r_buf_fread_at (bf->buf, rel->hdr.imp_table_paddr, (void *)imps, "II", num_imps);
	for (i = 0; i < num_imps; i++) {
		if (imps[i].relocs_paddr == 0) {
			continue;
		}
		// Load reloc subtable
		int num_relocs = load_reloc_table (NULL, bf->buf, imps[i].relocs_paddr);
		R_LOG_DEBUG ("imp %d: %d relocs", i, num_relocs);
		reloc_counts[i] = num_relocs;
		relocs[i] = R_NEWS0 (RelReloc, num_relocs);
		load_reloc_table (relocs[i], bf->buf, imps[i].relocs_paddr);
	}
	rel->num_imps = num_imps;
	rel->imps = imps;
	rel->reloc_counts = reloc_counts;
	rel->relocs = (const RelReloc *const *)relocs;
	const char *file_name = bf->file;
	if (file_name) {
		rel->libname = r_file_basename (file_name);
	}
	if (!rel->libname) {
		rel->libname = "";
	}

	bf->bo->bin_obj = rel;
	return true;

beach:
	free (imps);
	free (reloc_counts);
	free (relocs);
	free (sections);
	free (rel);
	return false;
}

static void destroy(RBinFile *bf) {
	int i;
	const LoadedRel *rel = bf->bo->bin_obj;
	if (!rel) {
		return;
	}
	free ((void *)rel->imps);
	free ((void *)rel->reloc_counts);
	for (i = 0; i < rel->num_imps; i++) {
		free ((void *)rel->relocs[i]);
	}
	free ((void *)rel->relocs);
	free ((void *)rel->sections);
	free ((void *)rel->section_vaddrs);
	free ((void *)rel);
}

static ut64 baddr(RBinFile *bf) {
	return bf->bo->baddr;
}

static RList *sections(RBinFile *bf) {
	int i;
	const RelSection *rel_s;
	RBinSection *s;
	const LoadedRel *rel = bf->bo->bin_obj;
	RList *ret = r_list_new ();

	bool has_bss = false;
	for (i = 0; i < rel->hdr.num_sections; i++) {
		rel_s = &rel->sections[i];
		if (rel_s->size == 0) {
			continue;
		}
		bool executable = rel_section_is_executable (&rel->sections[i]);
		s = R_NEW0 (RBinSection);
		if (!s) {
			break;
		}
		s->paddr = rel_section_paddr (rel_s);
		s->vaddr = bf->bo->baddr + s->paddr;
		s->size = s->vsize = rel_s->size;
		s->add = true;
		if (s->paddr == 0) {
			if (has_bss) {
				R_LOG_ERROR ("Ignoring duplicate bss section (%d)", i);
				free (s);
				continue;
			}
			has_bss = true;
			s->name = strdup ("bss");
			// Place after end of REL file
			s->vaddr = bf->bo->baddr + bf->size + 0x3c;
		} else if (executable) {
			s->name = r_str_newf ("text_%d", i);
		} else {
			s->name = r_str_newf ("data_%d", i);
		}
		if (executable) {
			// s->perm = r_str_rwx ("r-x");
			s->perm = r_str_rwx ("rwx"); // XXX
		} else {
			s->perm = r_str_rwx ("rw-");
		}
		rel->section_vaddrs[i] = s->vaddr;
		r_list_append (ret, s);
	}

	return ret;
}

static void register_header_symbol(RBinFile *bf, RList *syms, const char *name, ut8 section, ut32 offset) {
	const LoadedRel *rel = bf->bo->bin_obj;
	if (section == 0 || section >= rel->hdr.num_sections) {
		return;
	}
	RBinSymbol *ret = R_NEW0 (RBinSymbol);
	ret->type = R_BIN_TYPE_FUNC_STR;
	ret->libname = strdup (rel->libname);
	ret->name = r_bin_name_new (name);
	ret->paddr = rel_section_paddr (&rel->sections[section]) + offset;
	ret->vaddr = bf->bo->baddr + ret->paddr;
	r_list_append (syms, ret);
}

static RList *symbols(RBinFile *bf) {
	RList *syms = r_list_new ();
	const LoadedRel *rel = bf->bo->bin_obj;
	register_header_symbol (bf, syms, "prolog", rel->hdr.prolog_section, rel->hdr.prolog_offset);
	register_header_symbol (bf, syms, "epilog", rel->hdr.epilog_section, rel->hdr.epilog_offset);
	register_header_symbol (bf, syms, "unresolved", rel->hdr.unresolved_section, rel->hdr.unresolved_offset);

	return syms;
}

static ut32 get_section_vaddr(const LoadedRel *rel, ut8 section_idx) {
	if (section_idx >= rel->hdr.num_sections) {
		return 0;
	}
	return rel->section_vaddrs[section_idx];
}

// Updates the reloc source site; return false if reloc table walk should abort.
//
// Walking the reloc table is a stateful process (comparable to DWARF line number program).
// The addresses at which relocs are applied are monotonically increasing while walking the table.
// Each table entry can increase the offset or reset it to the beginning of a section.
static bool reloc_step_vaddr(const LoadedRel *rel, const RelReloc *reloc, ut32 *P) {
	if (R_UNLIKELY (reloc->type == R_RVL_SECT)) {
		ut32 section_vaddr = get_section_vaddr (rel, reloc->section);
		if (!section_vaddr) {
			// fucks up the entire reloc table, should probably abort
			R_LOG_ERROR ("reloc->section out of bounds (%d >= %d)", reloc->section, rel->hdr.num_sections);
			return false;
		}
		*P = section_vaddr;
	} else if (R_UNLIKELY (reloc->type == R_RVL_STOP)) {
		return false;
	} else {
		*P += reloc->offset;
	}
	return true;
}

#define set_masked(v, mask, expr) ((v) &(~ ((ut32) (mask)))) | ((expr) &(mask))

#define set_low24(v, expr) set_masked(v, 0x03FFFFFC,(expr) << 2)
#define set_half16(v, expr) set_masked(v, 0xFFFF0000,(expr) << 16)

#define lo(x) ((x) & 0xffff)
#define hi(x) (((x) >> 16) & 0xffff)
#define ha(x) ((((x) >> 16) + (((x) & 0x8000)? 1: 0)) & 0xffff)

static bool _overlay_write_at_hack(RIO *io, ut64 addr, const ut8 *buf, int len) {
	return true;
}

// Applies a relocation on the current program.
// Does not generate RBinReloc/RBinImport entries.
static RBinReloc *patch_reloc(RBin *b, const LoadedRel *rel, const RelReloc *reloc, ut32 module, ut32 P) {
	ut32 value_old, value; // (*P)
	ut32 S; // Section vaddr of symbol
	ut32 A = reloc->addend; // sym vaddr = S + A

	if (module == 0) {
		S = 0;
	} else {
		// note: This assumes that this is an internal reloc
		// Relocs against other RELs are not yet handled.
		S = get_section_vaddr (rel, reloc->section);
		if (!S) {
			R_LOG_ERROR ("Invalid reloc against section %d with unknown virtual addr", reloc->section);
			return NULL;
		}
	}

	// Load original slot
	// if (r_buf_fread_at (buf, paddr, (void *)&V, "I", 1) == -1) {
	if (!vread_at_be32 (b, P, &value)) {
		R_LOG_ERROR ("REL: Cannot read reloc target at %#08x", P);
		return NULL;
	}
	value_old = value;
	int size = 0;

	// clang-format off
	switch (reloc->type) {
	case R_RVL_NONE:
	case R_RVL_SECT:
		return NULL;
	case R_PPC_ADDR32:     size = 4; value = S + A;                              break;
	case R_PPC_ADDR24:     size = 4; value = set_low24 (value, (S + A) >> 2);     break;
	case R_PPC_REL24:      size = 4; value = set_low24 (value, (S + A - P) >> 2); break;
	case R_PPC_ADDR16_LO:  size = 2; value = set_half16 (value, lo (S + A));       break;
	case R_PPC_ADDR16_HI:  size = 2; value = set_half16 (value, hi (S + A));       break;
	case R_PPC_ADDR16_HA:  size = 2; value = set_half16 (value, ha (S + A));       break;
	default:
		if (b->iob.overlay_write_at != _overlay_write_at_hack) {
			R_LOG_ERROR ("REL: Unsupported reloc type %d", reloc->type);
		}
		return NULL;
	}
	// clang-format on

	if (r_log_match (R_LOG_LEVEL_DEBUG, R_LOG_ORIGIN) && b->iob.overlay_write_at != _overlay_write_at_hack) {
		assert (size > 0 && size <= 8);
		char value_old_hex[9], value_new_hex[9];
		char fmt[] = "%08x";
		fmt[2] = '0' + (2 * size);
		snprintf (value_old_hex, sizeof (value_old_hex), fmt, value_old >> ((4 - size) * 8));
		snprintf (value_new_hex, sizeof (value_new_hex), fmt, value >> ((4 - size) * 8));
#if DEBUG
		R_LOG_DEBUG ("REL: Reloc %-21s @%#08x: %s => %s", reloc_str (reloc->type), P, &value_old_hex, &value_new_hex);
#endif
	}

	// Perform relocation
	// if (r_buf_fwrite_at (buf, paddr, (void *)&V, "I", 1) == -1) {
	if (!vwriten_at_be32 (b, P, value, size)) {
		R_LOG_ERROR ("REL: Cannot write reloc target at %#08x", P);
		return NULL;
	}

	RBinReloc *ret = R_NEW0 (RBinReloc);
	switch (size) {
	// UNREACHABLE case 1: ret->type = R_BIN_RELOC_8; break;
	case 2: ret->type = R_BIN_RELOC_16; break;
	// UNREACHABLE case 3: ret->type = R_BIN_RELOC_24; break;
	case 4: ret->type = R_BIN_RELOC_32; break;
	default:
		R_LOG_DEBUG ("Cannot convert reloc of size %d to RBinReloc", size);
		free (ret);
		return NULL;
	}
	ret->ntype = reloc->type;
	ret->addend = A;
	ret->vaddr = P;
	RBinSection *s = r_bin_get_section_at (b->cur->bo, P, true);
	if (s && s->paddr != 0) {
		ret->paddr = P - b->cur->bo->baddr;
	}
	return ret;
}

static RList *patch_relocs(RBinFile *bf) {
	int i, j;
	RBin *b = bf->rbin;
	const LoadedRel *rel = b->cur->bo->bin_obj;

	RList *ret = r_list_new ();
	for (i = 0; i < rel->num_imps; i++) {
		const RelImp *imp = &rel->imps[i];
		if (imp->module != 0 && imp->module != rel->hdr.module_id) {
			if (b->iob.overlay_write_at != _overlay_write_at_hack) {
				R_LOG_ERROR ("Imports from other REL (%08x) not yet implemented", imp->module);
			}
			continue;
		}

		ut32 P = 0; // virtual addr where reloc is filled in
		ut32 num_relocs = rel->reloc_counts[i];

		for (j = 0; j < num_relocs; j++) {
			const RelReloc *reloc = &rel->relocs[i][j];
			if (!reloc_step_vaddr (rel, reloc, &P)) {
				break;
			}
			RBinReloc *r_reloc = patch_reloc (b, rel, reloc, imp->module, P);
			if (ret && r_reloc) {
				r_list_append (ret, r_reloc);
			}
		}
	}
	return ret;
}

static RList *relocs(RBinFile *bf) {
	if (!bf || !bf->rbin) {
		return NULL;
	}
	RBin *b = bf->rbin;
	void *tmp = b->iob.overlay_write_at;
	b->iob.overlay_write_at = _overlay_write_at_hack;
	RList *ret = patch_relocs (bf);
	b->iob.overlay_write_at = tmp;
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->buf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->big_endian = true;
	ret->type = strdup ("Relocatable File");
	ret->machine = strdup ("Nintendo Wii");
	ret->os = strdup ("wii-ios");
	ret->arch = strdup ("ppc");
	ret->has_va = true;
	ret->bits = 32;
	ret->cpu = strdup ("ps");
	ret->file = bf->file? strdup (bf->file): NULL;
	return ret;
}

RBinPlugin r_bin_plugin_rel = {
	.meta = {
		.name = "rel",
		.desc = "Nintendo Wii Relocatable",
		.license = "LGPL-3.0-only",
		.author = "terorie",
	},
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.baddr = &baddr,
	.sections = &sections,
	.symbols = &symbols,
	.relocs = &relocs,
	.info = &info,
	.patch_relocs = &patch_relocs
};

// clang-format off
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_rel,
	.version = R2_VERSION
};
#endif
