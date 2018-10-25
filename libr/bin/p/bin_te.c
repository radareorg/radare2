/* radare - LGPL - Copyright 2013-2015 - xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "te/te_specs.h"
#include "te/te.h"

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct r_bin_te_obj_t *bin = (struct r_bin_te_obj_t *) o->bin_obj;
	return bin? bin->kv: NULL;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct r_bin_te_obj_t *res = NULL;
	RBuffer *tbuf = NULL;

	if (!buf || sz == 0 || sz == UT64_MAX) {
		return false;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_te_new_buf (tbuf);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	*bin_obj = res;
	return true;
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf? r_buf_buffer (bf->buf): NULL;
	ut64 sz = bf? r_buf_size (bf->buf): 0;

	if (!bf || !bf->o) {
		return false;
	}
	load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
	return bf->o->bin_obj? true: false;
}

static int destroy(RBinFile *bf) {
	r_bin_te_free ((struct r_bin_te_obj_t *) bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return r_bin_te_get_image_base (bf->o->bin_obj);
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	RBinAddr *ret = NULL;
	switch (type) {
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW (RBinAddr))) {
			return NULL;
		}
		ret->paddr = ret->vaddr = r_bin_te_get_main_paddr (bf->o->bin_obj);
		break;
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBinAddr *entry = NULL;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(entry = r_bin_te_get_entrypoint (bf->o->bin_obj))) {
		return ret;
	}
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->paddr = entry->paddr;
		ptr->vaddr = entry->vaddr;
		r_list_append (ret, ptr);
	}
	free (entry);
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
	if (!(sections = r_bin_te_get_sections (bf->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		if (sections[i].name[sizeof (sections[i].name) - 1]) {
			memcpy (ptr->name, sections[i].name,
				sizeof (sections[i].name));
			ptr->name[sizeof (sections[i].name)] = 0;
		} else {
			strncpy (ptr->name, (char *) sections[i].name,
				R_BIN_SIZEOF_STRINGS);
		}
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
			ptr->bits = 16;
		}
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("TE");
	ret->rclass = strdup ("te");
	ret->os = r_bin_te_get_os (bf->o->bin_obj);
	ret->arch = r_bin_te_get_arch (bf->o->bin_obj);
	ret->machine = r_bin_te_get_machine (bf->o->bin_obj);
	ret->subsystem = r_bin_te_get_subsystem (bf->o->bin_obj);
	ret->type = strdup ("EXEC (Executable file)");
	ret->bits = r_bin_te_get_bits (bf->o->bin_obj);
	ret->big_endian = 1;
	ret->dbg_info = 0;
	ret->has_va = true;

	sdb_num_set (bf->sdb, "te.bits", ret->bits, 0);

	return ret;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	return (buf && length > 2 && !memcmp (buf, "\x56\x5a", 2));
}

RBinPlugin r_bin_plugin_te = {
	.name = "te",
	.desc = "TE bin plugin", // Terse Executable format
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.minstrlen = 4,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_te,
	.version = R2_VERSION
};
#endif
