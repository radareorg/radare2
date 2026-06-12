/* radare2 - LGPL - Copyright 2026 - Zapper9982, pancake */
// inspired by the bin.gns1 plugin from rizin written by Zapper9982

#include <r_bin.h>

#define GNS1_SEGMENT_ENTRY_SIZE 12
#define GNS1_MIN_FILE_SIZE 64
#define GNS1_FTAB_HEADER_SIZE 0x30
#define GNS1_FTAB_MAGIC_OFFSET 0x20
#define GNS1_FTAB_ENTRY_COUNT_OFFSET 0x28
#define GNS1_FTAB_ENTRY_OFFSET 0x30
#define GNS1_FTAB_ENTRY_SIZE 16
#define GNS1_FTAB_MAX_ENTRIES 4096
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

typedef struct gns1_segment_entry {
	ut32 size;
	ut32 paddr;
	ut32 offset;
	Gns1SegType type;
	Gns1Region region;
} Gns1SegmentEntry;

typedef struct gns1_ftab_entry {
	char tag[5];
	ut32 offset;
	ut32 size;
	ut32 zero;
} Gns1FtabEntry;

R_VEC_TYPE(RVecGns1Segment, Gns1SegmentEntry);
R_VEC_TYPE(RVecGns1FtabEntry, Gns1FtabEntry);

typedef struct gns1_obj {
	RVecGns1Segment segments;
	RVecGns1FtabEntry ftab_entries;
	ut64 base_offset;
	ut64 image_size;
	ut64 table_size;
	ut32 n_ftab_entries;
	bool is_ftab;
} Gns1Obj;

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
	ut8 buf[12];
	if (*off > UT64_MAX - base) {
		return false;
	}
	if (r_buf_read_at (b, base + *off, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	e->size = r_read_le32 (buf);
	e->paddr = r_read_le32 (buf + 4);
	e->offset = r_read_le32 (buf + 8);
	*off += 12;
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

static bool parse_segment_table(RBuffer *b, RVecGns1Segment *segments, ut64 base, ut64 image_size, ut64 *table_size) {
	if (!b || image_size < GNS1_MIN_FILE_SIZE) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	if (base > buf_size || image_size > buf_size - base) {
		return false;
	}
	ut64 off = 0;
	Gns1SegmentEntry entry;
	if (!parse_segment (b, base, &off, &entry)) {
		return false;
	}
	if (!is_first_segment (&entry)) {
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

static bool parse_ftab(RBuffer *b, RVecGns1FtabEntry *entries, ut64 *base, ut64 *image_size, ut32 *n_entries_out) {
	if (!b || r_buf_size (b) < GNS1_FTAB_ENTRY_OFFSET + GNS1_FTAB_ENTRY_SIZE) {
		return false;
	}
	ut8 buf[GNS1_FTAB_ENTRY_SIZE];
	if (r_buf_read_at (b, GNS1_FTAB_MAGIC_OFFSET, buf, 8) != 8 || memcmp (buf, "rkosftab", 8)) {
		return false;
	}
	if (r_buf_read_at (b, GNS1_FTAB_ENTRY_COUNT_OFFSET, buf, 8) != 8) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	const ut32 n_entries = r_read_le32 (buf);
	const ut32 zero = r_read_le32 (buf + 4);
	if (!n_entries || n_entries > GNS1_FTAB_MAX_ENTRIES || zero) {
		return false;
	}
	ut64 table_size = (ut64)n_entries * GNS1_FTAB_ENTRY_SIZE;
	if (table_size > buf_size - GNS1_FTAB_ENTRY_OFFSET) {
		return false;
	}
	ut64 off = GNS1_FTAB_ENTRY_OFFSET;
	ut32 i;
	for (i = 0; i < n_entries; i++, off += GNS1_FTAB_ENTRY_SIZE) {
		if (r_buf_read_at (b, off, buf, sizeof (buf)) != sizeof (buf)) {
			return false;
		}
		const ut32 entry_off = r_read_le32 (buf + 4);
		const ut32 entry_size = r_read_le32 (buf + 8);
		const ut32 entry_zero = r_read_le32 (buf + 12);
		if (entry_off > buf_size || entry_size > buf_size - entry_off) {
			return false;
		}
		if (entries) {
			Gns1FtabEntry entry = {0};
			memcpy (entry.tag, buf, 4);
			entry.offset = entry_off;
			entry.size = entry_size;
			entry.zero = entry_zero;
			RVecGns1FtabEntry_push_back (entries, &entry);
		}
		if (!memcmp (buf, "GNS1", 4)) {
			if (!entry_size) {
				return false;
			}
			*base = entry_off;
			*image_size = entry_size;
		}
	}
	if (n_entries_out) {
		*n_entries_out = n_entries;
	}
	return image_size && *image_size > 0;
}

static bool parse_gns1(RBuffer *b, RVecGns1Segment *segments, Gns1Obj *obj) {
	if (!b) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	ut64 table_size = 0;
	if (parse_segment_table (b, NULL, 0, buf_size, &table_size)) {
		if (segments && !parse_segment_table (b, segments, 0, buf_size, &table_size)) {
			return false;
		}
		if (obj) {
			obj->base_offset = 0;
			obj->image_size = buf_size;
			obj->table_size = table_size;
			obj->is_ftab = false;
		}
		return true;
	}
	ut64 base = 0;
	ut64 image_size = 0;
	ut32 n_entries = 0;
	RVecGns1FtabEntry *ftab_entries = obj? &obj->ftab_entries: NULL;
	if (parse_ftab (b, ftab_entries, &base, &image_size, &n_entries) && parse_segment_table (b, NULL, base, image_size, &table_size)) {
		if (segments && !parse_segment_table (b, segments, base, image_size, &table_size)) {
			return false;
		}
		if (obj) {
			obj->base_offset = base;
			obj->image_size = image_size;
			obj->table_size = table_size;
			obj->n_ftab_entries = n_entries;
			obj->is_ftab = true;
		}
		return true;
	}
	return false;
}

static bool check_buffer(RBuffer *b) {
	if (!b) {
		return false;
	}
	ut64 table_size = 0;
	return parse_segment_table (b, NULL, 0, r_buf_size (b), &table_size);
}

static Gns1Obj *load_buffer(RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, NULL);
	Gns1Obj *gns1 = R_NEW0 (Gns1Obj);
	RVecGns1Segment_init (&gns1->segments);
	RVecGns1FtabEntry_init (&gns1->ftab_entries);
	if (!parse_gns1 (b, &gns1->segments, gns1) || RVecGns1Segment_empty (&gns1->segments)) {
		R_LOG_ERROR ("GNS1: invalid segment table");
		RVecGns1Segment_fini (&gns1->segments);
		RVecGns1FtabEntry_fini (&gns1->ftab_entries);
		free (gns1);
		return NULL;
	}
	return gns1;
}

static void obj_free(Gns1Obj *gns1) {
	if (gns1) {
		RVecGns1Segment_fini (&gns1->segments);
		RVecGns1FtabEntry_fini (&gns1->ftab_entries);
		R_FREE (gns1);
	}
}

static bool gns1_check(RBinFile *bf, RBuffer *b) {
	return b && check_buffer (b);
}

static bool gns1_load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	Gns1Obj *obj = load_buffer (buf);
	if (obj) {
		bf->bo->bin_obj = obj;
		return true;
	}
	return false;
}

static void gns1_destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL (bf && bf->bo && bf->bo->bin_obj);
	obj_free (bf->bo->bin_obj);
	bf->bo->bin_obj = NULL;
}

static ut64 gns1_baddr(RBinFile *bf) {
	return GNS1_INTERNAL_BASE;
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

static bool gns1_sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	Gns1Obj *obj = bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);
	if (obj->is_ftab) {
		add_section (bf, "ftab_header", 0, GNS1_FTAB_HEADER_SIZE, 0, R_PERM_R, "FTAB",
			"8x magic[8] entries zero");
		add_section (bf, "ftab_entries", GNS1_FTAB_ENTRY_OFFSET, (ut64)obj->n_ftab_entries * GNS1_FTAB_ENTRY_SIZE,
			GNS1_FTAB_ENTRY_OFFSET, R_PERM_R, "FTAB", "4cxxx tag offset size zero");
		Gns1FtabEntry *fe;
		R_VEC_FOREACH (&obj->ftab_entries, fe) {
			char name[32];
			snprintf (name, sizeof (name), "ftab_%s", fe->tag);
			add_section (bf, name, fe->offset, fe->size, fe->offset, R_PERM_R, "FTAB", NULL);
		}
	}
	add_section (bf, "gns1_segments", obj->base_offset, obj->table_size, obj->base_offset, R_PERM_R,
		"GNS1", "xxx size paddr offset");
	Gns1SegmentEntry *e;
	ut32 idx = 0;
	R_VEC_FOREACH (&obj->segments, e) {
		RBinSection *sec = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		sec->paddr = obj->base_offset + e->offset;
		sec->size = sec->vsize = e->size;
		sec->vaddr = translate_vaddr (e->paddr);
		sec->perm = ((e->paddr & GNS1_ADDRMASK) == 0)? R_PERM_RX: R_PERM_RW;
		sec->add = true;
		sec->arch = "arc";
		sec->bits = 16;
		const char *seg_type = e->type == GNS1_SEG_TEXT? "text": "data";
		const char *region = e->region == GNS1_REGION_A? "region_a": (e->region == GNS1_REGION_B? "region_b": NULL);
		sec->name = region? r_str_newf ("%s_%s_%u", region, seg_type, idx)
				: r_str_newf ("%s_%u", seg_type, idx);
		idx++;
	}
	return true;
}

static RList *gns1_entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	Gns1Obj *obj = bf->bo->bin_obj;
	if (RVecGns1Segment_empty (&obj->segments)) {
		return r_list_newf (free);
	}
	RList *ret = r_list_newf (free);
	Gns1SegmentEntry *ra_text = NULL, *rb_text = NULL, *e;
	R_VEC_FOREACH (&obj->segments, e) {
		if (e->type != GNS1_SEG_TEXT) {
			continue;
		}
		const Gns1Region region = e->region;
		if (region == GNS1_REGION_A) {
			if (!ra_text || e->paddr < ra_text->paddr) {
				ra_text = e;
			}
		} else if (region == GNS1_REGION_B) {
			if (!rb_text || e->paddr < rb_text->paddr) {
				rb_text = e;
			}
		}
	}
	if (ra_text) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		entry->paddr = obj->base_offset + ra_text->offset;
		entry->vaddr = translate_vaddr (ra_text->paddr);
		r_list_append (ret, entry);
	}
	if (rb_text) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		entry->paddr = obj->base_offset + rb_text->offset;
		entry->vaddr = translate_vaddr (rb_text->paddr);
		r_list_append (ret, entry);
	}
	return ret;
}

static RBinInfo *gns1_info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	Gns1Obj *obj = bf->bo->bin_obj;
	RBinInfo *info = R_NEW0 (RBinInfo);
	info->file = bf->file? strdup (bf->file): NULL;
	info->type = strdup (obj->is_ftab? "FTAB/GNS1": "GNS1");
	info->bclass = strdup (obj->is_ftab? "ftab": "raw");
	info->machine = strdup ("Apple C4000 Baseband");
	info->arch = strdup ("arc");
	info->rclass = strdup ("firmware");
	info->subsystem = strdup ("baseband");
	info->cpu = strdup ("hs");
	info->flags = r_str_newf ("gns1.offset=0x%08"PFMT64x",gns1.size=0x%08"PFMT64x,
		obj->base_offset, obj->image_size);
	info->has_va = true;
	info->bits = 16;
	info->big_endian = false;
	return info;
}

RBinPlugin r_bin_plugin_gns1 = {
	.meta = {
		.name = "gns1",
		.desc = "Apple C4000 baseband firmware (FTAB/GNS1.bin)",
		.license = "LGPL3",
		.author = "Zapper9982",
	},
	.check = &gns1_check,
	.load = &gns1_load,
	.destroy = &gns1_destroy,
	.baddr = &gns1_baddr,
	.entries = &gns1_entries,
	.sections_vec = &gns1_sections_vec,
	.info = &gns1_info,
	.minstrlen = 4,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_gns1,
	.version = R2_VERSION
};
#endif
