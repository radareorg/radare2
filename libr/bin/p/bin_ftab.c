/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

#define FTAB_HEADER_SIZE 0x30
#define FTAB_MAGIC_OFFSET 0x20
#define FTAB_ENTRY_COUNT_OFFSET 0x28
#define FTAB_ENTRY_OFFSET 0x30
#define FTAB_ENTRY_SIZE 16
#define FTAB_MAX_ENTRIES 4096

#define GNS1_SEGMENT_ENTRY_SIZE 12
#define GNS1_MIN_FILE_SIZE 64
#define GNS1_REGION1_BASE 0x12000000
#define GNS1_REGION2_BASE 0x15000000
#define GNS1_REGION2_END 0x16000000
#define GNS1_INTERNAL_BASE 0x10000000
#define GNS1_ADDRMASK 0xFFFFFF
#define GNS1_MAX_VALID_SEGMENTS 1000

typedef enum {
	GNS1_SEG_TEXT,
	GNS1_SEG_DATA
} Gns1SegType;

typedef enum {
	GNS1_REGION_UNKNOWN,
	GNS1_REGION_A,
	GNS1_REGION_B
} Gns1Region;

typedef struct ftab_entry_t {
	char tag[5];
	ut32 offset;
	ut32 size;
	ut32 zero;
} FtabEntry;

typedef struct gns1_segment_entry {
	ut32 size;
	ut32 paddr;
	ut32 offset;
	Gns1SegType type;
	Gns1Region region;
} Gns1SegmentEntry;

R_VEC_TYPE(RVecFtabEntry, FtabEntry);
R_VEC_TYPE(RVecGns1Segment, Gns1SegmentEntry);

typedef struct ftab_obj_t {
	RVecFtabEntry entries;
	RVecGns1Segment gns1_segments;
	ut64 gns1_offset;
	ut64 gns1_size;
	ut64 gns1_table_size;
	bool has_gns1;
} FtabObj;

typedef struct ftab_section_hint_t {
	const char *arch;
	int bits;
	ut32 perm;
	bool add;
} FtabSectionHint;

static inline ut32 region_type(ut32 pa) {
	if (pa >= GNS1_REGION1_BASE && pa < GNS1_REGION2_BASE) {
		return GNS1_REGION_A;
	}
	if (pa >= GNS1_REGION2_BASE && pa < GNS1_REGION2_END) {
		return GNS1_REGION_B;
	}
	return GNS1_REGION_UNKNOWN;
}

static ut64 translate_vaddr(ut32 paddr) {
	ut32 addr = paddr & 0xFF000000;
	if (region_type (addr) == GNS1_REGION_A) {
		return GNS1_INTERNAL_BASE + (paddr & GNS1_ADDRMASK);
	}
	return paddr;
}

static bool is_erased_segment(const Gns1SegmentEntry *e) {
	return e->size == UT32_MAX && e->paddr == UT32_MAX && e->offset == UT32_MAX;
}

static bool is_first_segment(const Gns1SegmentEntry *e) {
	return !is_erased_segment (e) && e->type == GNS1_SEG_TEXT && e->region != GNS1_REGION_UNKNOWN;
}

static bool is_valid_segment(const Gns1SegmentEntry *e, ut64 file_size, ut64 min_offset) {
	if (e->size == 0 || is_erased_segment (e) || e->region == GNS1_REGION_UNKNOWN) {
		return false;
	}
	ut64 seg_size = e->size;
	ut64 seg_off = e->offset;
	return seg_size <= file_size && seg_off >= min_offset && seg_off < file_size && seg_off <= file_size - seg_size;
}

static bool parse_segment(RBuffer *b, ut64 base, ut64 *off, Gns1SegmentEntry *e) {
	ut8 buf[GNS1_SEGMENT_ENTRY_SIZE];
	if (*off > UT64_MAX - base) {
		return false;
	}
	if (r_buf_read_at (b, base + *off, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	e->size = r_read_le32 (buf);
	e->paddr = r_read_le32 (buf + 4);
	e->offset = r_read_le32 (buf + 8);
	*off += GNS1_SEGMENT_ENTRY_SIZE;
	e->type = (e->paddr & GNS1_ADDRMASK) == 0? GNS1_SEG_TEXT: GNS1_SEG_DATA;
	e->region = region_type (e->paddr);
	return true;
}

static bool is_zero_filled(RBuffer *b, ut64 base, ut64 off, ut64 end) {
	ut8 buf[64];
	while (off < end) {
		int len = (int)R_MIN ((ut64)sizeof (buf), end - off);
		if (off > UT64_MAX - base || r_buf_read_at (b, base + off, buf, len) != len) {
			return false;
		}
		int i;
		for (i = 0; i < len; i++) {
			if (buf[i]) {
				return false;
			}
		}
		off += len;
	}
	return true;
}

static bool parse_gns1_segment_table(RBuffer *b, RVecGns1Segment *segments, ut64 base, ut64 image_size, ut64 *table_size) {
	if (!b || image_size < GNS1_MIN_FILE_SIZE) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	if (base > buf_size || image_size > buf_size - base) {
		return false;
	}
	ut64 off = 0;
	Gns1SegmentEntry entry;
	if (!parse_segment (b, base, &off, &entry) || !is_first_segment (&entry)) {
		return false;
	}
	const ut64 data_start = entry.offset;
	if (data_start < 0x64 || !is_valid_segment (&entry, image_size, data_start)) {
		return false;
	}
	off = 0;
	size_t n_segments = 0;
	bool terminated = false;
	while (off < data_start) {
		if (n_segments > GNS1_MAX_VALID_SEGMENTS) {
			return false;
		}
		if (data_start - off < GNS1_SEGMENT_ENTRY_SIZE) {
			terminated = is_zero_filled (b, base, off, data_start);
			off = data_start;
			break;
		}
		if (!parse_segment (b, base, &off, &entry) || off > data_start) {
			return false;
		}
		if (is_erased_segment (&entry)) {
			terminated = true;
			break;
		}
		if (entry.size == 0) {
			if (entry.paddr || entry.offset) {
				return false;
			}
			terminated = true;
			break;
		}
		if (!is_valid_segment (&entry, image_size, data_start)) {
			return false;
		}
		if (segments) {
			RVecGns1Segment_push_back (segments, &entry);
		}
		n_segments++;
	}
	if (!terminated || n_segments == 0 || !is_zero_filled (b, base, off, data_start)) {
		return false;
	}
	if (table_size) {
		*table_size = data_start;
	}
	return true;
}

static bool is_tag_char(ut8 ch) {
	return ch >= 0x20 && ch <= 0x7e;
}

static bool ftab_check_buffer(RBuffer *b) {
	ut8 buf[8];
	return b && r_buf_size (b) >= FTAB_HEADER_SIZE &&
		r_buf_read_at (b, FTAB_MAGIC_OFFSET, buf, sizeof (buf)) == sizeof (buf) &&
		!memcmp (buf, "rkosftab", 8);
}

static bool parse_ftab_entries(RBuffer *b, RVecFtabEntry *entries) {
	if (!ftab_check_buffer (b)) {
		return false;
	}
	ut8 buf[FTAB_ENTRY_SIZE];
	if (r_buf_read_at (b, FTAB_ENTRY_COUNT_OFFSET, buf, 8) != 8) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	const ut32 n_entries = r_read_le32 (buf);
	const ut32 zero = r_read_le32 (buf + 4);
	if (!n_entries || n_entries > FTAB_MAX_ENTRIES || zero) {
		return false;
	}
	const ut64 table_size = (ut64)n_entries * FTAB_ENTRY_SIZE;
	if (table_size > buf_size - FTAB_ENTRY_OFFSET) {
		return false;
	}
	ut64 off = FTAB_ENTRY_OFFSET;
	ut32 i;
	for (i = 0; i < n_entries; i++, off += FTAB_ENTRY_SIZE) {
		if (r_buf_read_at (b, off, buf, sizeof (buf)) != sizeof (buf)) {
			return false;
		}
		if (!is_tag_char (buf[0]) || !is_tag_char (buf[1]) || !is_tag_char (buf[2]) || !is_tag_char (buf[3])) {
			return false;
		}
		FtabEntry entry = {0};
		memcpy (entry.tag, buf, 4);
		entry.offset = r_read_le32 (buf + 4);
		entry.size = r_read_le32 (buf + 8);
		entry.zero = r_read_le32 (buf + 12);
		if (entry.zero || entry.offset > buf_size || entry.size > buf_size - entry.offset) {
			return false;
		}
		if (entries) {
			RVecFtabEntry_push_back (entries, &entry);
		}
	}
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	return parse_ftab_entries (b, NULL);
}

static FtabObj *load_buffer(RBuffer *b) {
	FtabObj *obj = R_NEW0 (FtabObj);
	RVecFtabEntry_init (&obj->entries);
	RVecGns1Segment_init (&obj->gns1_segments);
	if (!parse_ftab_entries (b, &obj->entries)) {
		RVecFtabEntry_fini (&obj->entries);
		RVecGns1Segment_fini (&obj->gns1_segments);
		free (obj);
		return NULL;
	}
	FtabEntry *entry;
	R_VEC_FOREACH (&obj->entries, entry) {
		if (strcmp (entry->tag, "GNS1")) {
			continue;
		}
		ut64 table_size = 0;
		if (parse_gns1_segment_table (b, &obj->gns1_segments, entry->offset, entry->size, &table_size)) {
			obj->gns1_offset = entry->offset;
			obj->gns1_size = entry->size;
			obj->gns1_table_size = table_size;
			obj->has_gns1 = true;
		}
		break;
	}
	return obj;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	FtabObj *obj = load_buffer (buf);
	if (obj) {
		bf->bo->bin_obj = obj;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->bin_obj);
	FtabObj *obj = bf->bo->bin_obj;
	RVecFtabEntry_fini (&obj->entries);
	RVecGns1Segment_fini (&obj->gns1_segments);
	R_FREE (bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool tag_is(const FtabEntry *fe, const char *tag) {
	return !strncmp (fe->tag, tag, 4);
}

static FtabSectionHint section_hint(const FtabEntry *fe) {
	FtabSectionHint hint = { NULL, 0, R_PERM_R, false };
	if (tag_is (fe, "illb") || tag_is (fe, "rkos") || tag_is (fe, "rkol") ||
			tag_is (fe, "l1cs") || tag_is (fe, "cdpd") || tag_is (fe, "cdpu") ||
			tag_is (fe, "sbd1")) {
		hint.arch = "arm";
		hint.bits = 64;
		hint.perm = R_PERM_RX;
		hint.add = true;
	} else if (tag_is (fe, "cdph") || tag_is (fe, "pmfw") || tag_is (fe, "apmu")) {
		hint.arch = "arm";
		hint.bits = 32;
		hint.perm = R_PERM_RX;
		hint.add = true;
	}
	return hint;
}

static RBinSection *add_section(RBinFile *bf, const char *name, ut64 paddr, ut64 size, ut64 vaddr, ut32 perm, const char *type, const char *format) {
	RBinSection *sec = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	sec->name = strdup (name);
	sec->paddr = paddr;
	sec->vaddr = vaddr;
	sec->size = sec->vsize = size;
	sec->perm = perm;
	sec->type = type;
	sec->format = format? strdup (format): NULL;
	return sec;
}

static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	FtabObj *obj = bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);
	const ut64 n_entries = RVecFtabEntry_length (&obj->entries);
	add_section (bf, "ftab_header", 0, FTAB_HEADER_SIZE, 0, R_PERM_R, "FTAB",
		"8x magic[8] entries zero");
	add_section (bf, "ftab_entries", FTAB_ENTRY_OFFSET, n_entries * FTAB_ENTRY_SIZE,
		FTAB_ENTRY_OFFSET, R_PERM_R, "FTAB", "4cxxx tag offset size zero");
	FtabEntry *fe;
	ut32 idx = 0;
	R_VEC_FOREACH (&obj->entries, fe) {
		char name[32];
		snprintf (name, sizeof (name), "ftab_%s_%u", fe->tag, idx);
		FtabSectionHint hint = section_hint (fe);
		RBinSection *sec = add_section (bf, name, fe->offset, fe->size, fe->offset, hint.perm, "FTAB", NULL);
		sec->arch = hint.arch;
		sec->bits = hint.bits;
		sec->add = hint.add;
		idx++;
	}
	if (!obj->has_gns1) {
		return true;
	}
	add_section (bf, "gns1_segments", obj->gns1_offset, obj->gns1_table_size, obj->gns1_offset, R_PERM_R,
		"GNS1", "xxx size paddr offset");
	Gns1SegmentEntry *e;
	idx = 0;
	R_VEC_FOREACH (&obj->gns1_segments, e) {
		RBinSection *sec = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		sec->paddr = obj->gns1_offset + e->offset;
		sec->size = sec->vsize = e->size;
		sec->vaddr = translate_vaddr (e->paddr);
		sec->perm = e->type == GNS1_SEG_TEXT? R_PERM_RX: R_PERM_RW;
		sec->add = true;
		sec->arch = "arc";
		sec->bits = 16;
		const char *seg_type = e->type == GNS1_SEG_TEXT? "text": "data";
		const char *region = e->region == GNS1_REGION_A? "region_a": (e->region == GNS1_REGION_B? "region_b": NULL);
		sec->name = region? r_str_newf ("gns1_%s_%s_%u", region, seg_type, idx)
				: r_str_newf ("gns1_%s_%u", seg_type, idx);
		idx++;
	}
	return true;
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	FtabObj *obj = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!obj->has_gns1) {
		return ret;
	}
	Gns1SegmentEntry *ra_text = NULL, *rb_text = NULL, *e;
	R_VEC_FOREACH (&obj->gns1_segments, e) {
		if (e->type != GNS1_SEG_TEXT) {
			continue;
		}
		if (e->region == GNS1_REGION_A) {
			if (!ra_text || e->paddr < ra_text->paddr) {
				ra_text = e;
			}
		} else if (e->region == GNS1_REGION_B) {
			if (!rb_text || e->paddr < rb_text->paddr) {
				rb_text = e;
			}
		}
	}
	if (ra_text) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		entry->paddr = obj->gns1_offset + ra_text->offset;
		entry->vaddr = translate_vaddr (ra_text->paddr);
		r_list_append (ret, entry);
	}
	if (rb_text) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		entry->paddr = obj->gns1_offset + rb_text->offset;
		entry->vaddr = translate_vaddr (rb_text->paddr);
		r_list_append (ret, entry);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	FtabObj *obj = bf->bo->bin_obj;
	RBinInfo *info = R_NEW0 (RBinInfo);
	info->file = bf->file? strdup (bf->file): NULL;
	info->type = strdup ("FTAB");
	info->bclass = strdup ("firmware");
	info->machine = strdup ("Apple C4000");
	info->rclass = strdup ("firmware");
	info->subsystem = strdup ("baseband");
	info->bits = obj->has_gns1? 16: 0;
	info->has_va = obj->has_gns1;
	info->big_endian = false;
	info->flags = obj->has_gns1?
		r_str_newf ("entries=%u,gns1.offset=0x%08"PFMT64x",gns1.size=0x%08"PFMT64x,
			(ut32)RVecFtabEntry_length (&obj->entries), obj->gns1_offset, obj->gns1_size):
		r_str_newf ("entries=%u", (ut32)RVecFtabEntry_length (&obj->entries));
	if (obj->has_gns1) {
		info->arch = strdup ("arc");
		info->cpu = strdup ("hs");
	} else {
		FtabEntry *fe;
		R_VEC_FOREACH (&obj->entries, fe) {
			FtabSectionHint hint = section_hint (fe);
			if (hint.arch) {
				info->arch = strdup (hint.arch);
				info->bits = hint.bits;
				info->cpu = strdup (hint.bits == 64? "v8": "v7");
				break;
			}
		}
	}
	return info;
}

RBinPlugin r_bin_plugin_ftab = {
	.meta = {
		.name = "ftab",
		.desc = "Apple C4000 FTAB firmware container",
		.license = "LGPL3",
		.author = "pancake",
	},
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.baddr = &baddr,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.info = &info,
	.minstrlen = 4,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ftab,
	.version = R2_VERSION
};
#endif
