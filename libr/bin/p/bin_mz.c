/* radare - LGPL - Copyright 2015-2017 nodepad */

#include <r_types.h>
#include <r_bin.h>
#include "mz/mz.h"

static Sdb * get_sdb(RBinFile *bf) {
	const struct r_bin_mz_obj_t *bin;
	if (bf && bf->o && bf->o->bin_obj) {
		bin = (struct r_bin_mz_obj_t *) bf->o->bin_obj;
		if (bin && bin->kv) {
			return bin->kv;
		}
	}
	return NULL;
}

static bool checkEntrypoint(const ut8 *buf, ut64 length) {
	st16 cs = r_read_ble16 (buf + 0x16, false);
	ut16 ip = r_read_ble16 (buf + 0x14, false);
	ut32 pa = ((r_read_ble16 (buf + 8 , false) + cs) << 4) + ip;

	/* A minimal MZ header is 0x1B bytes.  Header length is measured in
	 * 16-byte paragraphs so the minimum header must occupy 2 paragraphs.
	 * This means that the entrypoint should be at least 0x20 unless someone
	 * cleverly fit a few instructions inside the header.
	 */
//	if (pa >= 0x20 && pa + 1 < length) {
	pa &= 0xffff;
	if (pa > 0x20 && pa + 1 < length) {
		ut16 pe = r_read_ble16 (buf + 0x3c, false);
		if (pe < length && length > 0x104 && !memcmp (buf + pe, "PE", 2)) {
			return false;
		}
		return true;
	}
	return false;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	unsigned int exth_offset;
	int ret = false;
	if (!buf || length <= 0x3d) {
		return false;
	}
	if (!memcmp (buf, "MZ", 2) || !memcmp (buf, "ZM", 2)) {
		ret = true;
		exth_offset = (buf[0x3c] | (buf[0x3d]<<8));
		if (length > exth_offset + 2) {
			//check for PE
			if (length > exth_offset + 0x20) {
				if (!memcmp (buf, "MZ", 2) &&
				    !memcmp (buf + exth_offset, "PE", 2) &&
				    !memcmp (buf + exth_offset + 0x18,
					     "\x0b\x01", 2)) {
					return false;
					}
			}
			if (!memcmp (buf + exth_offset, "NE", 2) ||
			    !memcmp (buf + exth_offset, "LE", 2) ||
			    !memcmp (buf + exth_offset, "LX", 2) ) {
				if (!checkEntrypoint (buf, length)) {
					ret = false;
				}
			} else {
				if (checkEntrypoint (buf, length)) {
					/* raw plain MZ executable (watcom) */
				} else {
					ret = false;
				}
			}
		}
	}
	return ret;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz,
		ut64 loadaddr, Sdb *sdb) {
	const struct r_bin_mz_obj_t *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_mz_new_buf (tbuf);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	return (void *)res;
}

static bool load(RBinFile *arch) {
	if (!arch || !arch->o) {
		return false;
	}
	const ut8 *bytes = r_buf_buffer (arch->buf);
	ut64 sz = r_buf_size (arch->buf);
	const void *res = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	arch->o->bin_obj = (void *)res;
	return res != NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_mz_free ((struct r_bin_mz_obj_t*)arch->o->bin_obj);
	return true;
}

static RList * entries(RBinFile *arch) {
	RBinAddr *ptr = NULL;
	RList *res = NULL;
	if (!(res = r_list_newf (free))) {
		return NULL;
	}
	int entry = r_bin_mz_get_entrypoint (arch->o->bin_obj);
	if (entry >= 0) {
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = (ut64) entry;
			ptr->vaddr = (ut64) entry;
			r_list_append (res, ptr);
		}
	}
	return res;
}

static RList * sections(RBinFile *arch) {
	const struct r_bin_mz_segment_t *segments = NULL;
	RBinSection *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(segments = r_bin_mz_get_segments (arch->o->bin_obj))){
		r_list_free (ret);
		return NULL;
	}
	for (i = 0; !segments[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			free ((void *)segments);
			r_list_free (ret);
			return NULL;
		}
		sprintf ((char*)ptr->name, "seg_%03d", i);
		ptr->size = segments[i].size;
		ptr->vsize = segments[i].size;
		ptr->paddr = segments[i].paddr;
		ptr->vaddr = segments[i].paddr;
		ptr->srwx = r_str_rwx ("mrwx");
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	free ((void *)segments);
	return ret;
}

static RBinInfo * info(RBinFile *arch) {
	RBinInfo * const ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("MZ");
	ret->rclass = strdup ("mz");
	ret->os = strdup ("DOS");
	ret->arch = strdup ("x86");
	ret->machine = strdup ("i386");
	ret->type = strdup ("EXEC (Executable file)");
	ret->subsystem = strdup ("DOS");
	ret->bits = 16;
	ret->dbg_info = 0;
	ret->big_endian = false;
	ret->has_crypto = false;
	ret->has_canary = false;
	ret->has_nx = false;
	ret->has_pi = false;
	ret->has_va = false;
	return ret;
}

static RList * relocs(RBinFile *arch) {
	RList *ret = NULL;
	RBinReloc *rel = NULL;
	const struct r_bin_mz_reloc_t *relocs = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(relocs = r_bin_mz_get_relocs (arch->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !relocs[i].last; i++) {
		if (!(rel = R_NEW0 (RBinReloc))) {
			free ((void *)relocs);
			r_list_free (ret);
			return NULL;
		}
		rel->type = R_BIN_RELOC_16;
		rel->vaddr = relocs[i].paddr;
		rel->paddr = relocs[i].paddr;
		r_list_append (ret, rel);
	}
	free ((void *)relocs);
	return ret;
}

RBinPlugin r_bin_plugin_mz = {
	.name = "mz",
	.desc = "MZ bin plugin",
	.license = "MIT",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.relocs = &relocs,
	.minstrlen = 4,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mz,
	.version = R2_VERSION
};
#endif
