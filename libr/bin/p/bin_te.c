/* radare - LGPL - Copyright 2013-2024 - xvilka */

#include <r_bin.h>
#include "te/te_specs.h"
#include "te/te.h"

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->bo;
	if (!o) {
		return NULL;
	}
	struct r_bin_te_obj_t *bin = (struct r_bin_te_obj_t *) o->bin_obj;
	return bin? bin->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && b, false);
	ut64 sz = r_buf_size (b);
	if (sz == 0 || sz == UT64_MAX) {
		return false;
	}
	struct r_bin_te_obj_t *res = r_bin_te_new_buf (b);
	if (res) {
		sdb_ns_set (bf->sdb, "info", res->kv);
	}
	bf->bo->bin_obj = res;
	return true;
}

static void destroy(RBinFile *bf) {
	r_bin_te_free ((struct r_bin_te_obj_t *) bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return r_bin_te_get_image_base (bf->bo->bin_obj);
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	RBinAddr *ret = NULL;
	switch (type) {
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW (RBinAddr))) {
			return NULL;
		}
		ret->paddr = ret->vaddr = r_bin_te_get_main_paddr (bf->bo->bin_obj);
		break;
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (ret) {
		RBinAddr *entry = r_bin_te_get_entrypoint (bf->bo->bin_obj);
		if (entry) {
			RBinAddr *ptr = R_NEW0 (RBinAddr);
			if (ptr) {
				ptr->paddr = entry->paddr;
				ptr->vaddr = entry->vaddr;
				r_list_append (ret, ptr);
			}
			free (entry);
		}
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_te_section_t *sections = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(sections = r_bin_te_get_sections (bf->bo->bin_obj))) {
		free (ret);
		return NULL;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		ptr->name = strdup ((char*)sections[i].name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr;
		ptr->perm = 0;
		ptr->add = true;
		if (R_BIN_TE_SCN_IS_EXECUTABLE (sections[i].flags)) {
			ptr->perm |= R_PERM_X;
		}
		if (R_BIN_TE_SCN_IS_WRITABLE (sections[i].flags)) {
			ptr->perm |= R_PERM_W;
		}
		if (R_BIN_TE_SCN_IS_READABLE (sections[i].flags)) {
			ptr->perm |= R_PERM_R;
		}
		if (R_BIN_TE_SCN_IS_SHAREABLE (sections[i].flags)) {
			ptr->perm |= R_PERM_SHAR;
		}
		/* All TE files have _TEXT_RE section, which is 16-bit, because of
		 * CPU start in this mode */
		if (!strncmp (ptr->name, "_TEXT_RE", 8)) {
			ptr->bits = R_SYS_BITS_PACK (16);
		}
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("TE");
	ret->rclass = strdup ("te");
	if (bf->bo->bin_obj) {
		ret->os = r_bin_te_get_os (bf->bo->bin_obj);
		const char *arch = r_bin_te_get_arch (bf->bo->bin_obj);
		ret->arch = arch? strdup (arch): NULL;
		ret->machine = r_bin_te_get_machine (bf->bo->bin_obj);
		ret->subsystem = r_bin_te_get_subsystem (bf->bo->bin_obj);
		ret->type = strdup ("EXEC (Executable file)");
		ret->bits = r_bin_te_get_bits (bf->bo->bin_obj);
	}
	ret->big_endian = true;
	ret->dbg_info = 0;
	ret->has_va = true;
	sdb_num_set (bf->sdb, "te.bits", ret->bits, 0);
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 buf[2];
	if (r_buf_read_at (b, 0, buf, 2) == 2) {
		return !memcmp (buf, "\x56\x5a", 2);
	}
	return false;
}

RBinPlugin r_bin_plugin_te = {
	.meta = {
		.name = "te",
		.author = "xvilka",
		.desc = "Terse Executable (based on PE/COFF for PE32/+)",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.minstrlen = 4,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_te,
	.version = R2_VERSION
};
#endif
