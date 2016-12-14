#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>

#include "bflt/bflt.h"

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loaddr, Sdb *sdb) {
	struct r_bin_bflt_obj *res;
	RBuffer *tbuf = NULL;

	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = r_bin_bflt_new_buf (tbuf);
	r_buf_free (tbuf);
	return res ? res : NULL;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = r_buf_buffer (arch->buf);
	ut64 sz = r_buf_size (arch->buf);

	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true : false;
}

static RList *entries(RBinFile *arch) {
	struct r_bin_bflt_obj *obj = (struct r_bin_bflt_obj*)arch->o->bin_obj;
	RList *ret;
	RBinAddr *ptr;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	ptr = r_bflt_get_entry (obj);
	if (!ptr) {
		return NULL;
	}
	r_list_append (ret, ptr);
	return ret;
}

static void __patch_reloc (RBuffer *r_buf, struct bflt_relocation_t *reloc) {
	char s[32];
	int len, ret;
	ut8 *buf;
	ut32 val;

	val = reloc->data;
	snprintf (s, sizeof (s), "%08x", val);
	buf = calloc (strlen (s), 1);

	if (!buf) {
		return;
	}
	len = r_hex_str2bin (s, buf);
	ret = r_buf_write_at (r_buf, reloc->addr_to_patch, buf, len);
	if (ret == -1) {
		eprintf ("Error\n");
	}
	free (buf);
}

static RList *patch_relocs(RBin *b) {
	struct r_bin_bflt_obj *bin;
	struct bflt_relocation_t *reloc_table;
	RList *list;
	RBinReloc *reloc;
	RBinObject *obj;
	int i;
	
	obj = r_bin_cur_object (b);
	if (!obj) {
		return NULL;
	}
	bin = obj->bin_obj;
	reloc_table = bin->bflt_reloc_table;
	list = r_list_new ();
	if (!list) {
		return NULL;
	}
	
	for (i = 0; i < bin->hdr->reloc_count; i++) {
		__patch_reloc (bin->b, &reloc_table[i]);
		RBinReloc *reloc = R_NEW0 (RBinReloc);
		reloc->type = R_BIN_RELOC_32;
		reloc->paddr = reloc_table[i].addr_to_patch;
		reloc->vaddr = reloc->paddr;
		r_list_append (list, reloc);	
	}
	
	free (reloc_table);
	return list;
}

static int get_ngot_entries(struct r_bin_bflt_obj *obj) {
	int i, len;

	for (i = 0 ;; i++) {
		ut32 entry;
		len = r_buf_read_at (obj->b, obj->hdr->data_start + (i * 4), (ut8 *)&entry, sizeof (ut32));
		if (len != sizeof (ut32)) {
			return 0;
		}
		entry = r_swap_ut32 (entry);
		if (!VALID_GOT_ENTRY (entry)) {
			break;
		}
	}
	return i;
}

static RList *relocs(RBinFile *arch) {
	struct r_bin_bflt_obj *obj = (struct r_bin_bflt_obj*)arch->o->bin_obj;
	struct bflt_relocation_t *bflt_reloc_table = NULL;
	RList *list = r_list_new ();
	int i, len, n_got = 0, n_reloc = obj->hdr->reloc_count;
	
	if (!list || !obj) {
		r_list_free (list);
		return NULL;
	}
	if (obj->hdr->flags & FLAT_FLAG_GOTPIC) {
		n_got = get_ngot_entries (obj);
		n_reloc += n_got;
	}
	bflt_reloc_table = calloc (1, n_reloc * sizeof (struct bflt_relocation_t));
	if (!bflt_reloc_table) {
		return list;
	}
	if (obj->hdr->flags & FLAT_FLAG_GOTPIC) {
		ut32 offset;
		for (offset = 0, i = 0; i < n_got; i++, offset += 4) {
			ut32 got_entry;
			len = r_buf_read_at (obj->b, obj->hdr->data_start + offset, (ut8 *)&got_entry, sizeof (ut32));
			got_entry = r_swap_ut32 (got_entry);
			if (!VALID_GOT_ENTRY (got_entry)) {
				break;
			} else {
				bflt_reloc_table[i].addr_to_patch = got_entry;
				bflt_reloc_table[i].data = got_entry + BFLT_HDR_SIZE;
			}
		}
	}

	for (i = 0; i < obj->hdr->reloc_count; i++) {
		ut32 reloc_pointer;

		len = r_buf_read_at (obj->b, obj->hdr->reloc_start + (i * 4), (ut8 *)&reloc_pointer, 4);
		if (len != 4) {
			return list;
		}

		reloc_pointer = r_swap_ut32 (reloc_pointer);
		ut32 reloc_offset = reloc_pointer + BFLT_HDR_SIZE;

		if (reloc_offset < obj->hdr->bss_end) {
			ut32 reloc_fixed;
			ut32 reloc_data_offset;

			len = r_buf_read_at (obj->b, reloc_offset, (ut8 *)&reloc_fixed, 4);
			reloc_data_offset = reloc_fixed + BFLT_HDR_SIZE;

			bflt_reloc_table[n_got + i].addr_to_patch = reloc_offset;
			bflt_reloc_table[n_got + i].data = reloc_data_offset;

			RBinReloc *reloc = R_NEW0 (RBinReloc);
			reloc->type = R_BIN_RELOC_32;
			reloc->paddr = bflt_reloc_table[n_got + i].addr_to_patch;
			reloc->vaddr = reloc->paddr;
			r_list_append (list, reloc);			
		}

	}
	obj->bflt_reloc_table = bflt_reloc_table;
	return list;
}

static RBinInfo *info(RBinFile *arch) {
	struct r_bin_bflt_obj *obj = (struct r_bin_bflt_obj*)arch->o->bin_obj;
	RBinInfo *info = R_NEW0(RBinInfo);

	if (!info) {
		return NULL;
	}
	info->file = arch->file ? strdup (arch->file) : NULL;
	info->rclass = strdup ("bflt");
	info->bclass = strdup ("bflt" );
	info->type = strdup ("bFLT (Executable file)");
	info->os = strdup ("Linux");
	info->subsystem = strdup ("Linux");
	info->arch = strdup ("arm");
	info->big_endian = obj->endian;
	info->bits = 32;
	info->has_va = false;
	info->dbg_info = 0;
	info->machine = strdup ("unknown");

	return info;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return true;
}

static int check(RBinFile *arch) {
	/*const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0; */
	return true;
}

static Sdb* get_sdb(RBinObject *o) {
	if (!o) {
		return NULL;
	}
	struct r_bin_bflt_obj *bin = (struct r_bin_bflt_obj *) o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}

	return NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_bflt_free ((struct r_bin_bflt_obj*)arch->o->bin_obj);
	return true;
}

RBinPlugin r_bin_plugin_bflt = {
	.name = "bflt",
	.desc = "bFLT format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = NULL,
	.binsym = NULL,
	.entries = &entries,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.info = &info,
	.fields = NULL,
	.size = NULL,
	.libs = NULL,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.write = NULL,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bflt,
	.version = R2_VERSION
};
#endif
