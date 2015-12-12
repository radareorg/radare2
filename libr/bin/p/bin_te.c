/* radare - LGPL - Copyright 2013-2015 - xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "te/te_specs.h"
#include "te/te.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	struct r_bin_te_obj_t *bin = (struct r_bin_te_obj_t *) o->bin_obj;
	if (bin && bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct r_bin_te_obj_t *res = NULL;
	RBuffer *tbuf = NULL;

	if (!buf || sz == 0 || sz == UT64_MAX) return NULL;
	tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_te_new_buf (tbuf);
	if (res)
		sdb_ns_set (sdb, "info", res->kv);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	if (!arch || !arch->o) return false;
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true: false;
}

static int destroy(RBinFile *arch) {
	r_bin_te_free ((struct r_bin_te_obj_t*)arch->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return r_bin_te_get_image_base (arch->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	RBinAddr *ret = NULL;
	switch (type) {
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW (RBinAddr)))
			return NULL;
		ret->paddr = ret->vaddr = r_bin_te_get_main_paddr (arch->o->bin_obj);
		break;
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;
	RBinAddr *entry = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(entry = r_bin_te_get_entrypoint (arch->o->bin_obj)))
		return ret;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->paddr = entry->paddr;
		ptr->vaddr = entry->vaddr;
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_te_section_t *sections = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(sections = r_bin_te_get_sections(arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection)))
			break;
		if (sections[i].name[sizeof (sections[i].name)-1]) {
			memcpy (ptr->name, sections[i].name,
				sizeof (sections[i].name));
			ptr->name[sizeof (sections[i].name)] = 0;
		} else strncpy (ptr->name, (char*)sections[i].name,
			R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr;
		ptr->srwx = R_BIN_SCN_MAP;
		ptr->add = true;
		if (R_BIN_TE_SCN_IS_EXECUTABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_EXECUTABLE;
		if (R_BIN_TE_SCN_IS_WRITABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_WRITABLE;
		if (R_BIN_TE_SCN_IS_READABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_SHAREABLE;
		if (R_BIN_TE_SCN_IS_SHAREABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_SHAREABLE;
		/* All TE files have _TEXT_RE section, which is 16-bit, because of
		 * CPU start in this mode */
		if (!strncmp(ptr->name, "_TEXT_RE", 8))
			ptr->bits = 16;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("TE");
	ret->rclass = strdup ("te");
	ret->os = r_bin_te_get_os (arch->o->bin_obj);
	ret->arch = r_bin_te_get_arch (arch->o->bin_obj);
	ret->machine = r_bin_te_get_machine (arch->o->bin_obj);
	ret->subsystem = r_bin_te_get_subsystem (arch->o->bin_obj);
	ret->type = strdup ("EXEC (Executable file)");
	ret->bits = r_bin_te_get_bits (arch->o->bin_obj);
	ret->big_endian = 1;
	ret->dbg_info = 0;
	ret->has_va = true;

	sdb_num_set (arch->sdb, "te.bits", ret->bits, 0);

	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 2)
		if (!memcmp (buf, "\x56\x5a", 2))
			return true;
	return false;
}

RBinPlugin r_bin_plugin_te = {
	.name = "te",
	.desc = "TE bin plugin", // Terse Executable format
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.minstrlen = 4,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_te,
	.version = R2_VERSION
};
#endif
