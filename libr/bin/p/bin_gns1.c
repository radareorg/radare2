/* radare2 - LGPL - Copyright 2026 - Zapper9982, pancake */
// inspired by the bin.gns1 plugin from rizin written by Zapper9982

#include <r_bin.h>

#define GNS1_SEGMENT_ENTRY_SIZE 12
#define GNS1_MIN_FILE_SIZE 64
#define GNS1_REGION1_BASE 0x12000000
#define GNS1_REGION2_BASE 0x15000000
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

R_VEC_TYPE(RVecGns1Segment, Gns1SegmentEntry);

typedef struct gns1_obj {
	RVecGns1Segment segments;
} Gns1Obj;

static inline ut32 region_type(ut32 pa) {
	if (pa >= GNS1_REGION1_BASE && pa < GNS1_REGION2_BASE) {
		return GNS1_REGION_A;
	}
	if (pa >= GNS1_REGION2_BASE) {
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

static bool parse_segment(RBuffer *b, ut64 *off, Gns1SegmentEntry *e) {
	ut8 buf[12];
	if (r_buf_read_at (b, *off, buf, sizeof (buf)) != sizeof (buf)) {
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

static bool check_buffer(RBuffer *b) {
	if (!b || r_buf_size (b) < GNS1_MIN_FILE_SIZE) {
		return false;
	}
	ut64 off = 0;
	Gns1SegmentEntry entry;
	if (!parse_segment (b, &off, &entry)) {
		return false;
	}
	ut64 buf_size = r_buf_size (b);
	if (entry.size == 0 || entry.size > buf_size ||
		entry.offset < 0x64 || entry.offset >= buf_size ||
		entry.offset + entry.size > buf_size) {
		return false;
	}
	return r_buf_read_le32_at (b, entry.offset - 4) == 0;
}

static Gns1Obj *load_buffer(RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, NULL);
	Gns1Obj *gns1 = R_NEW0 (Gns1Obj);
	RVecGns1Segment_init (&gns1->segments);
	ut64 off = 0;
	Gns1SegmentEntry entry;
	ut64 file_size = r_buf_size (b);
	int invalid = 0;
	while (parse_segment (b, &off, &entry)) {
		if (entry.size == 0) {
			break;
		}
		if (entry.offset >= file_size || entry.offset + entry.size > file_size) {
			if (invalid++ > 3) {
				R_LOG_ERROR ("GNS1: Too many invalid segments found");
				break;
			}
			continue;
		}
		RVecGns1Segment_push_back (&gns1->segments, &entry);
		if (RVecGns1Segment_length (&gns1->segments) > GNS1_MAX_VALID_SEGMENTS) {
			R_LOG_ERROR ("GNS1: too many segments");
			break;
		}
	}
	if (RVecGns1Segment_empty (&gns1->segments)) {
		R_LOG_ERROR ("GNS1: no valid segments found");
		RVecGns1Segment_fini (&gns1->segments);
		free (gns1);
		return NULL;
	}
	return gns1;
}

static void obj_free(Gns1Obj *gns1) {
	if (gns1) {
		RVecGns1Segment_fini (&gns1->segments);
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

static RList *gns1_sections(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	Gns1Obj *obj = bf->bo->bin_obj;
	RList *secs = r_list_newf (free);
	Gns1SegmentEntry *e;
	ut32 idx = 0;
	R_VEC_FOREACH (&obj->segments, e) {
		RBinSection *sec = R_NEW0 (RBinSection);
		sec->paddr = e->offset;
		sec->size = sec->vsize = e->size;
		sec->vaddr = translate_vaddr (e->paddr);
		sec->perm = ((e->paddr & GNS1_ADDRMASK) == 0)? R_PERM_RX: R_PERM_RW;
		const char *seg_type = e->type == GNS1_SEG_TEXT? "text": "data";
		const char *region = e->region == GNS1_REGION_A? "region_a": (e->region == GNS1_REGION_B? "region_b": NULL);
		sec->name = region? r_str_newf ("%s_%s_%u", region, seg_type, idx)
				: r_str_newf ("%s_%u", seg_type, idx);
		r_list_append (secs, sec);
		idx++;
	}
	return secs;
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
		entry->paddr = ra_text->offset;
		entry->vaddr = translate_vaddr (ra_text->paddr);
		r_list_append (ret, entry);
	}
	if (rb_text) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		entry->paddr = rb_text->offset;
		entry->vaddr = translate_vaddr (rb_text->paddr);
		r_list_append (ret, entry);
	}
	return ret;
}

static RBinInfo *gns1_info(RBinFile *bf) {
	RBinInfo *info = R_NEW0 (RBinInfo);
	info->file = bf->file? strdup (bf->file): NULL;
	info->type = strdup ("GNS1");
	info->machine = strdup ("Apple C4000 Baseband");
	info->arch = strdup ("arc");
	info->rclass = strdup ("firmware");
	info->subsystem = strdup ("baseband");
	info->cpu = strdup ("ARC700");
	info->has_va = true;
	info->bits = 16;
	info->big_endian = false;
	return info;
}

RBinPlugin r_bin_plugin_gns1 = {
	.meta = {
		.name = "gns1",
		.desc = "Apple C4000 baseband firmware (GNS1.bin)",
		.license = "LGPL3",
		.author = "Zapper9982",
	},
	.check = &gns1_check,
	.load = &gns1_load,
	.destroy = &gns1_destroy,
	.baddr = &gns1_baddr,
	.entries = &gns1_entries,
	.sections = &gns1_sections,
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
