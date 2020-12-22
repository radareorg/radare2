/* radare - LGPL - Copyright 2008-2019 pancake, inisider */

#include <r_util.h>

#include "coff.h"

#define bprintf if(obj->verbose)eprintf

bool r_coff_supported_arch(const ut8 *buf) {
	ut16 arch = *(ut16*)buf;
	switch (arch) {
	case COFF_FILE_MACHINE_AMD64:
	case COFF_FILE_MACHINE_I386:
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_TI_COFF:
	case COFF_FILE_MACHINE_R4000:
	case COFF_FILE_MACHINE_AMD29KBE:
	case COFF_FILE_MACHINE_AMD29KLE:
	case COFF_FILE_MACHINE_ARM64:
	case COFF_FILE_MACHINE_ARMNT:
		return true;
	default:
		return false;
	}
}

char *r_coff_symbol_name(struct r_bin_coff_obj *obj, void *ptr) {
	char n[256] = {0};
	int len = 0, offset = 0;
	union {
		char name[8];
		struct {
			ut32 zero;
			ut32 offset;
		};
	} *p = ptr;
	if (!ptr) {
		return NULL;
	}
	if (p->zero) {
		return r_str_ndup (p->name, 8);
	}
	offset = obj->hdr.f_symptr + obj->hdr.f_nsyms * sizeof (struct coff_symbol) + p->offset;
	if (offset > obj->size) {
		return NULL;
	}
	len = r_buf_read_at (obj->b, offset, (ut8*)n, sizeof (n));
	if (len < 1) {
		return NULL;
	}
	/* ensure null terminated string */
	n[sizeof (n) - 1] = 0;
	return strdup (n);
}

static int r_coff_rebase_sym(struct r_bin_coff_obj *obj, RBinAddr *addr, struct coff_symbol *sym) {
	if (sym->n_scnum < 1 || sym->n_scnum > obj->hdr.f_nscns) {
		return 0;
	}
	addr->paddr = obj->scn_hdrs[sym->n_scnum - 1].s_scnptr + sym->n_value;
	return 1;
}

/* Try to get a valid entrypoint using the methods outlined in
 * http://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
RBinAddr *r_coff_get_entry(struct r_bin_coff_obj *obj) {
	RBinAddr *addr = R_NEW0 (RBinAddr);
	int i;
	if (!addr) {
		return NULL;
	}
	/* Simplest case, the header provides the entrypoint address */
	if (obj->hdr.f_opthdr) {
		addr->paddr = obj->opt_hdr.entry;
		return addr;
	}
	/* No help from the header eh? Use the address of the symbols '_start'
	 * or 'main' if present */
	if (obj->symbols) {
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp (obj->symbols[i].n_name, "_start") ||
				    !strcmp (obj->symbols[i].n_name, "start")) &&
				r_coff_rebase_sym (obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp (obj->symbols[i].n_name, "_main") ||
				    !strcmp (obj->symbols[i].n_name, "main")) &&
				r_coff_rebase_sym (obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
	}
#if 0
	/* Still clueless ? Let's just use the address of .text */
	if (obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			// avoid doing string matching and use x bit from the section
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_EXECUTE) {
				addr->paddr = obj->scn_hdrs[i].s_scnptr;
				return addr;
			}
		}
	}
#else
	free (addr);
	return NULL;
#endif
	return addr;
}

static bool r_bin_coff_init_hdr(struct r_bin_coff_obj *obj) {
	ut16 magic = r_buf_read_ble16_at (obj->b, 0, COFF_IS_LITTLE_ENDIAN);
	switch (magic) {
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_MACHINE_AMD29KBE:
		obj->endian = COFF_IS_BIG_ENDIAN;
		break;
	default:
		obj->endian = COFF_IS_LITTLE_ENDIAN;
	}
	int ret = 0;
	ret = r_buf_fread_at (obj->b, 0, (ut8 *)&obj->hdr, obj->endian? "2S3I2S": "2s3i2s", 1);
	if (ret != sizeof (struct coff_hdr)) {
		return false;
	}
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		ret = r_buf_fread (obj->b, (ut8 *)&obj->target_id, obj->endian? "S": "s", 1);
		if (ret != sizeof (ut16)) {
			return false;
		}
	}
	return true;
}

static bool r_bin_coff_init_opt_hdr(struct r_bin_coff_obj *obj) {
	int ret;
	if (!obj->hdr.f_opthdr) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, sizeof (struct coff_hdr),
						 (ut8 *)&obj->opt_hdr, obj->endian? "2S6I": "2s6i", 1);
	if (ret != sizeof (struct coff_opt_hdr)) {
		return false;
	}
	return true;
}

static bool r_bin_coff_init_scn_hdr(struct r_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = sizeof (struct coff_hdr) + (obj->hdr.f_opthdr ? sizeof (struct coff_opt_hdr) : 0);
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		offset += 2;
	}
	size = obj->hdr.f_nscns * sizeof (struct coff_scn_hdr);
	if (offset > obj->size || offset + size > obj->size || size < 0) {
		return false;
	}
	obj->scn_hdrs = calloc (1, size + sizeof (struct coff_scn_hdr));
	if (!obj->scn_hdrs) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->scn_hdrs, obj->endian? "8c6I2S1I": "8c6i2s1i", obj->hdr.f_nscns);
	if (ret != size) {
		R_FREE (obj->scn_hdrs);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_symtable(struct r_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (obj->hdr.f_nsyms >= 0xffff || !obj->hdr.f_nsyms) { // too much symbols, probably not allocatable
		return false;
	}
	size = obj->hdr.f_nsyms * sizeof (struct coff_symbol);
	if (size < 0 ||
		size > obj->size ||
		offset > obj->size ||
		offset + size > obj->size) {
		return false;
	}
	obj->symbols = calloc (1, size + sizeof (struct coff_symbol));
	if (!obj->symbols) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->symbols, obj->endian? "8c1I2S2c": "8c1i2s2c", obj->hdr.f_nsyms);
	if (ret != size) {
		R_FREE (obj->symbols);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_scn_va(struct r_bin_coff_obj *obj) {
	obj->scn_va = R_NEWS (ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	int i;
	ut64 va = 0;
	for (i = 0; i < obj->hdr.f_nscns; i++) {
		obj->scn_va[i] = va;
		va += obj->scn_hdrs[i].s_size;
		va = R_ROUND (va, 16ULL);
	}
	return true;
}

static int r_bin_coff_init(struct r_bin_coff_obj *obj, RBuffer *buf, bool verbose) {
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new0 ();
	obj->imp_ht = ht_up_new0 ();
	if (!r_bin_coff_init_hdr (obj)) {
		bprintf ("Warning: failed to init hdr\n");
		return false;
	}
	r_bin_coff_init_opt_hdr (obj);
	if (!r_bin_coff_init_scn_hdr (obj)) {
		bprintf ("Warning: failed to init section header\n");
		return false;
	}
	if (!r_bin_coff_init_scn_va (obj)) {
		bprintf ("Warning: failed to init section VA table\n");
		return false;
	}
	if (!r_bin_coff_init_symtable (obj)) {
		bprintf ("Warning: failed to init symtable\n");
		return false;
	}
	return true;
}

void r_bin_coff_free(struct r_bin_coff_obj *obj) {
	ht_up_free (obj->sym_ht);
	ht_up_free (obj->imp_ht);
	free (obj->scn_va);
	free (obj->scn_hdrs);
	free (obj->symbols);
	r_buf_free (obj->b);
	free (obj);
}

struct r_bin_coff_obj* r_bin_coff_new_buf(RBuffer *buf, bool verbose) {
	struct r_bin_coff_obj* bin = R_NEW0 (struct r_bin_coff_obj);
	r_bin_coff_init (bin, buf, verbose);
	return bin;
}
