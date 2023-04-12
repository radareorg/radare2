/* radare - LGPL - Copyright 2023 terorie */

#include <r_util.h>
#include "xcoff64.h"

R_IPI bool r_xcoff64_supported_arch(const ut8 *buf) {
	ut16 arch = r_read_be16 (buf);
	switch (arch) {
	case XCOFF64_FILE_MACHINE_U803TOC:
	case XCOFF64_FILE_MACHINE_U803XTOC:
	case XCOFF64_FILE_MACHINE_U64:
		return true;
	default:
		return false;
	}
}

R_IPI char *r_xcoff64_symbol_name(RBinXCoff64Obj *obj, ut32 offset) {
	char n[1024] = {0};
	int len = 0;
	ut64 paddr = obj->nametbl_off + offset;
	if (paddr > obj->size) {
		return NULL;
	}
	len = r_buf_read_at (obj->b, paddr, (ut8*)n, sizeof (n));
	if (len < 1) {
		return NULL;
	}
	/* ensure null terminated string */
	n[sizeof (n) - 1] = 0;
	return strdup (n);
}

R_IPI RBinAddr *r_xcoff64_get_entry(RBinXCoff64Obj *obj) {
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		return NULL;
	}
	/* XXX Are XCOFF64 without auxiliary header valid? */
	if (!obj->hdr.f_opthdr) {
		return NULL;
	}
	addr->hpaddr = sizeof (struct xcoff64_hdr) + r_offsetof (struct xcoff64_opt_hdr, entry);
	addr->vaddr = obj->opt_hdr.entry;
	if (addr->vaddr >= obj->opt_hdr.text_start) {
		addr->paddr = addr->vaddr - obj->opt_hdr.text_start;
	}
	return addr;
}

static bool r_bin_xcoff64_init_hdr(RBinXCoff64Obj *obj) {
	ut16 magic = r_buf_read_be16_at (obj->b, 0);
	switch (magic) {
	case XCOFF64_FILE_MACHINE_U803TOC:
	case XCOFF64_FILE_MACHINE_U803XTOC:
	case XCOFF64_FILE_MACHINE_U64:
		obj->endian = COFF_IS_BIG_ENDIAN;
		break;
	default:
		R_LOG_ERROR ("unsupported xcoff64 magic: %#x", magic);
		return false;
	}
	int ret = 0;
	ret = r_buf_fread_at (obj->b, 0, (ut8 *)&obj->hdr, obj->endian? "2S1I1L2S1I": "2s1i1l2s1i", 1);
	if (ret != sizeof (struct xcoff64_hdr)) {
		return false;
	}
	obj->nametbl_off = obj->hdr.f_symptr + (obj->hdr.f_nsyms * sizeof (struct xcoff64_symbol));
	return true;
}

static bool r_bin_xcoff64_init_opt_hdr(RBinXCoff64Obj *obj) {
	int ret;
	if (obj->hdr.f_opthdr != 0x78) {
		R_LOG_ERROR ("unexpected auxiliary header size in xcoff64: %#x", obj->hdr.f_opthdr);
		return false;
	}
	ret = r_buf_fread_at (obj->b, sizeof (struct xcoff64_hdr),
						 (ut8 *)&obj->opt_hdr, obj->endian? "2S1I3L8S8c6L4S3I": "2s1i3l8s8c6l4s3i", 1);
	if (ret != sizeof (struct coff_opt_hdr)) {
		return false;
	}
	return true;
}

static bool r_bin_xcoff64_init_scn_hdr(RBinXCoff64Obj *obj) {
	int ret, size;
	ut64 offset = sizeof (struct xcoff64_hdr) + obj->hdr.f_opthdr;
	size = obj->hdr.f_nscns * sizeof (struct xcoff64_scn_hdr);
	if (offset > obj->size || offset + size > obj->size || size < 0) {
		obj->hdr.f_nscns = 0;
		obj->scn_hdrs = NULL;
		return false;
	}
	obj->scn_hdrs = calloc (1, size + sizeof (struct xcoff64_scn_hdr));
	if (!obj->scn_hdrs) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->scn_hdrs, obj->endian? "8c6L3I4c": "8c6l3i4c", obj->hdr.f_nscns);
	if (ret != size) {
		R_FREE (obj->scn_hdrs);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_symtable(RBinXCoff64Obj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (obj->hdr.f_nsyms >= 0xffffff || !obj->hdr.f_nsyms) { // too much symbols, probably not allocatable
		return false;
	}
	size = obj->hdr.f_nsyms * sizeof (struct xcoff64_symbol);
	if (size < 0 ||
		size > obj->size ||
		offset > obj->size ||
		offset + size > obj->size) {
		return false;
	}
	obj->symbols = calloc (1, size + sizeof (struct xcoff64_symbol));
	if (!obj->symbols) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->symbols, obj->endian? "1L1I2S2c": "1l1i2s2c", obj->hdr.f_nsyms);
	if (ret != size) {
		R_FREE (obj->symbols);
		return false;
	}
	return true;
}

static bool r_bin_xcoff64_init_scn_va(RBinXCoff64Obj *obj) {
	int i;
	ut64 va = 0;

	obj->scn_va = R_NEWS0 (ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}

	/* Use predefined virtual addresses */
	if (obj->hdr.f_opthdr) {
		if (obj->opt_hdr.o_sntext < obj->hdr.f_nscns) {
			obj->scn_va[obj->opt_hdr.o_sntext] = obj->opt_hdr.text_start;
			va = R_MAX (va, obj->opt_hdr.text_start + obj->opt_hdr.tsize);
		}
		if (obj->opt_hdr.o_sndata < obj->hdr.f_nscns) {
			obj->scn_va[obj->opt_hdr.o_sndata] = obj->opt_hdr.data_start;
			va = R_MAX (va, obj->opt_hdr.data_start + obj->opt_hdr.dsize);
		}
	}
	va = R_ROUND (va, 0x100ULL);

	/* Place other sections after predefined */
	for (i = 0; i < obj->hdr.f_nscns; i++) {
		if (obj->scn_va[i]) {
			continue;
		}
		ut64 sz = obj->scn_hdrs[i].s_size;
		if (sz < 16) {
			sz = 16;
		}
		obj->scn_va[i] = va;
		va += sz;
		va = R_ROUND (va, 16ULL);
	}
	return true;
}

static bool r_bin_xcoff64_init(RBinXCoff64Obj *obj, RBuffer *buf, bool verbose) {
	if (!obj || !buf) {
		return false;
	}
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new0 ();
	obj->imp_ht = ht_up_new0 ();
	if (!r_bin_xcoff64_init_hdr (obj)) {
		R_LOG_ERROR ("failed to init xcoff64 header");
		return false;
	}
	r_bin_xcoff64_init_opt_hdr (obj);
	if (!r_bin_xcoff64_init_scn_hdr (obj)) {
	    R_LOG_WARN ("failed to init section header");
	    return false;
	}
	if (!r_bin_xcoff64_init_scn_va (obj)) {
		R_LOG_WARN ("failed to init section VA table");
		return false;
	}
	if (!r_bin_coff_init_symtable (obj)) {
		R_LOG_WARN ("failed to init symtable");
		return false;
	}
	return true;
}

R_IPI void r_bin_xcoff64_free(RBinXCoff64Obj *obj) {
	if (obj) {
		ht_up_free (obj->sym_ht);
		ht_up_free (obj->imp_ht);
		free (obj->scn_va);
		free (obj->scn_hdrs);
		free (obj->symbols);
		r_buf_free (obj->b);
		free (obj);
	}
}

R_IPI RBinXCoff64Obj *r_bin_xcoff64_new_buf(RBuffer *buf, bool verbose) {
	RBinXCoff64Obj* bin = R_NEW0 (RBinXCoff64Obj);
	r_bin_xcoff64_init (bin, buf, verbose);
	return bin;
}
