/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_bin.h>

#ifdef _MSC_VER
typedef struct art_header_t {
#else
typedef struct __packed art_header_t {
#endif
	ut8 magic[4];
	ut8 version[4];
	ut32 image_base;
	ut32 image_size;
	ut32 bitmap_offset;
	ut32 bitmap_size;
	ut32 checksum; /* adler32 */
	ut32 oat_file_begin; // oat_file_begin
	ut32 oat_data_begin;
	ut32 oat_data_end;
	ut32 oat_file_end;
	/* patch_delta is the amount of the base address the image is relocated */
	st32 patch_delta;
	/* image_roots: address of an array of objects needed to initialize */
	ut32 image_roots;
	ut32 compile_pic;
} ARTHeader;

typedef struct {
	Sdb *kv;
	ARTHeader art;
	RBuffer *buf;
} ArtObj;

static int art_header_load(ArtObj *ao, Sdb *db) {
	/* TODO: handle read errors here */
	if (r_buf_size (ao->buf) < sizeof (ARTHeader)) {
		return false;
	}
	ARTHeader *art = &ao->art;
	r_strf_buffer (64);
	(void) r_buf_fread_at (ao->buf, 0, (ut8 *) art, "IIiiiiiiiiiiii", 1);
	sdb_set (db, "img.base", r_strf ("0x%x", art->image_base), 0);
	sdb_set (db, "img.size", r_strf ("0x%x", art->image_size), 0);
	sdb_set (db, "art.checksum", r_strf ("0x%x", art->checksum), 0);
	sdb_set (db, "art.version", r_strf ("%c%c%c",
			art->version[0], art->version[1], art->version[2]), 0);
	sdb_set (db, "oat.begin", r_strf ("0x%x", art->oat_file_begin), 0);
	sdb_set (db, "oat.end", r_strf ("0x%x", art->oat_file_end), 0);
	sdb_set (db, "oat_data.begin", r_strf ("0x%x", art->oat_data_begin), 0);
	sdb_set (db, "oat_data.end", r_strf ("0x%x", art->oat_data_end), 0);
	sdb_set (db, "patch_delta", r_strf ("0x%x", art->patch_delta), 0);
	sdb_set (db, "image_roots", r_strf ("0x%x", art->image_roots), 0);
	sdb_set (db, "compile_pic", r_strf ("0x%x", art->compile_pic), 0);
	return true;
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->bo;
	if (!o) {
		return NULL;
	}
	ArtObj *ao = o->bin_obj;
	return ao? ao->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	ArtObj *ao = R_NEW0 (ArtObj);
	if (ao) {
		ao->kv = sdb_new0 ();
		if (!ao->kv) {
			free (ao);
			return false;
		}
		ao->buf = r_buf_ref (buf);
		art_header_load (ao, ao->kv);
		sdb_ns_set (bf->sdb, "info", ao->kv);
		bf->bo->bin_obj = ao;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	ArtObj *obj = bf->bo->bin_obj;
	r_buf_free (obj->buf);
	free (obj);
}

static ut64 baddr(RBinFile *bf) {
	ArtObj *ao = bf->bo->bin_obj;
	return ao? ao->art.image_base: 0;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ArtObj *ao = bf->bo->bin_obj;
	ret->lang = NULL;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("ART");

	ret->bclass = malloc (5);
	memcpy (ret->bclass, &ao->art.version, 4);
	ret->bclass[3] = 0;

	ret->rclass = strdup ("program");
	ret->os = strdup ("android");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("arm");
	ret->arch = strdup ("arm");
	ret->has_va = 1;
	ret->has_lit = true;
	ret->has_pi = ao->art.compile_pic;
	ret->bits = 16; // 32? 64?
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool check(RBinFile *bf, RBuffer *buf) {
	char tmp[4];
	int r = r_buf_read_at (buf, 0, (ut8 *)tmp, sizeof (tmp));
	return r == 4 && !strncmp (tmp, "art\n", 4);
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (ret) {
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		if (ptr) {
			ptr->paddr = ptr->vaddr = 0;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	ArtObj *ao = bf->bo->bin_obj;
	if (!ao) {
		return NULL;
	}
	ARTHeader art = ao->art;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinSection *ptr = R_NEW0 (RBinSection);
	if (R_LIKELY (ptr)) {
		ptr->name = strdup ("load");
		ptr->size = r_buf_size (bf->buf);
		ptr->vsize = art.image_size; // TODO: align?
		ptr->paddr = 0;
		ptr->vaddr = art.image_base;
		ptr->perm = R_PERM_R;
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	ptr = R_NEW0 (RBinSection);
	if (R_LIKELY (ptr)) {
		ptr->name = strdup ("bitmap");
		ptr->size = art.bitmap_size;
		ptr->vsize = art.bitmap_size;
		ptr->paddr = art.bitmap_offset;
		ptr->vaddr = art.image_base + art.bitmap_offset;
		ptr->perm = R_PERM_RX; // r-x
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	ptr = R_NEW0 (RBinSection);
	if (R_LIKELY (ptr)) {
		ptr->name = strdup ("oat");
		ptr->paddr = art.bitmap_offset;
		ptr->vaddr = art.oat_file_begin;
		ptr->size = art.oat_file_end - art.oat_file_begin;
		ptr->vsize = ptr->size;
		ptr->perm = R_PERM_RX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	ptr = R_NEW0 (RBinSection);
	if (R_LIKELY (ptr)) {
		ptr->name = strdup ("oat_data");
		ptr->paddr = art.bitmap_offset;
		ptr->vaddr = art.oat_data_begin;
		ptr->size = art.oat_data_end - art.oat_data_begin;
		ptr->vsize = ptr->size;
		ptr->perm = R_PERM_R;
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	return ret;
}

RBinPlugin r_bin_plugin_art = {
	.meta = {
		.name = "art",
		.author = "pancake",
		.desc = "Android Runtime",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.sections = &sections,
	.entries = entries,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_art,
	.version = R2_VERSION
};
#endif
