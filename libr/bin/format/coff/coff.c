/* radare - LGPL - Copyright 2008-2022 pancake, inisider */

#include <r_util.h>
#include "coff.h"

static bool r_coff_supported_arch_be(const ut8 *buf) {
	ut16 arch = r_read_be16 (buf);
	switch (arch) {
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_MACHINE_AMD29K:
	case XCOFF32_FILE_MACHINE_U800WR:
	case XCOFF32_FILE_MACHINE_U800RO:
	case XCOFF32_FILE_MACHINE_U800TOC:
	case XCOFF32_FILE_MACHINE_U802WR:
	case XCOFF32_FILE_MACHINE_U802RO:
	case XCOFF32_FILE_MACHINE_U802TOC:
		return true;
	default:
		return false;
	}
}

static bool r_coff_supported_arch_le(const ut8 *buf) {
	ut16 arch = r_read_le16 (buf);
	switch (arch) {
	case COFF_FILE_MACHINE_MIPS16:
 	case COFF_FILE_MACHINE_MIPSFPU:
 	case COFF_FILE_MACHINE_MIPSFPU16:
	case COFF_FILE_MACHINE_AMD64:
	case COFF_FILE_MACHINE_I386:
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_TI_COFF:
	case COFF_FILE_MACHINE_R4000:
	case COFF_FILE_MACHINE_AMD29K:
	case COFF_FILE_MACHINE_SH3:
 	case COFF_FILE_MACHINE_SH3DSP:
 	case COFF_FILE_MACHINE_SH4:
 	case COFF_FILE_MACHINE_SH5:
 	case COFF_FILE_MACHINE_THUMB:
 	case COFF_FILE_MACHINE_ARM:
	case COFF_FILE_MACHINE_ARM64:
	case COFF_FILE_MACHINE_ARMNT:
	case COFF_FILE_MACHINE_POWERPC:
	case COFF_FILE_MACHINE_ALPHA:
		return true;
	default:
		return false;
	}
}

R_IPI bool r_coff_supported_arch(const ut8 *buf) {
	return r_coff_supported_arch_le (buf) || r_coff_supported_arch_be (buf);
}

R_IPI char *r_coff_symbol_name(RBinCoffObj *obj, void *ptr) {
	char n[256] = {0};
	int len = 0;
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
	ut64 offset = obj->hdr.f_symptr + (obj->hdr.f_nsyms * sizeof (struct coff_symbol) + p->offset);
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

static int r_coff_rebase_sym(RBinCoffObj *obj, RBinAddr *addr, struct coff_symbol *sym) {
	if (sym->n_scnum < 1 || sym->n_scnum > obj->hdr.f_nscns) {
		return 0;
	}
	addr->paddr = obj->scn_hdrs[sym->n_scnum - 1].s_scnptr + sym->n_value;
	return 1;
}

/* In XCOFF32, the entrypoint seems to be indirect.
	At the entrypoint address, we find a pointer in .data,
	that resolves to the actual entrypoint. */

static RBinAddr *r_xcoff_get_entry(RBinCoffObj *obj) {
	/* Scan XCOFF loader symbol table */
	int ptr_scnum = 0;
	ut64 ptr_vaddr;
	if (obj->x_ldsyms) {
		int i;
		for (i = 0; i < obj->x_ldhdr.l_nsyms; i++) {
			if (!strcmp (obj->x_ldsyms[i].l_name, "__start")) {
				ptr_scnum = obj->x_ldsyms[i].l_scnum;
				ptr_vaddr = obj->x_ldsyms[i].l_value;
				break;
			}
		}
	}
	if (!ptr_scnum) {
		return NULL;
	}
	/* Translate the pointer to a file offset */
	if (ptr_scnum < 1 || ptr_scnum > obj->hdr.f_nscns) {
		R_LOG_WARN ("__start l_scnum invalid (%d)", ptr_scnum);
		return NULL;
	}
	ut64 ptr_offset = obj->scn_hdrs[ptr_scnum - 1].s_scnptr + ptr_vaddr - obj->scn_hdrs[ptr_scnum - 1].s_vaddr;

	/* Read the actual entrypoint */
	ut32 entry_vaddr = r_buf_read_be32_at (obj->b, ptr_offset);
	if (entry_vaddr == UT32_MAX) {
		R_LOG_WARN ("__start vaddr invalid (vaddr=%#x off=%#x)", ptr_vaddr, ptr_offset);
		return NULL;
	}

	/* Double check that the entrypoint is in .text */
	int sntext = obj->x_opt_hdr.o_sntext;
	if (sntext < 1 || sntext > obj->hdr.f_nscns) {
		R_LOG_WARN ("o_sntext invalid (%d)", sntext);
		return NULL;
	}
	ut32 text_vaddr = obj->scn_hdrs[sntext - 1].s_vaddr;
	ut32 text_size = obj->scn_hdrs[sntext - 1].s_size;
	if (entry_vaddr < text_vaddr || entry_vaddr >= text_vaddr + text_size) {
		R_LOG_WARN ("*__start OOB (vaddr=%#lx text=%#lx..%#lx)", entry_vaddr, text_vaddr, text_vaddr + text_size);
		return NULL;
	}

	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		return NULL;
	}
	addr->vaddr = entry_vaddr;
	return addr;
}

/* Try to get a valid entrypoint using the methods outlined in
 * http://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
R_IPI RBinAddr *r_coff_get_entry(RBinCoffObj *obj) {
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		return NULL;
	}
	/* Special case for XCOFF */
	if (obj->xcoff) {
		return r_xcoff_get_entry (obj);
	}
	/* Simplest case, the header provides the entrypoint address */
	if (obj->hdr.f_opthdr) {
		addr->paddr = obj->opt_hdr.entry;
		return addr;
	}
	/* No help from the header eh? Use the address of the symbols '_start'
	 * or 'main' if present */
	if (obj->symbols) {
		int i;
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

static bool r_bin_coff_init_hdr(RBinCoffObj *obj) {
	ut16 magic = r_buf_read_le16_at (obj->b, 0);
	switch (r_swap_ut16 (magic)) {
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_MACHINE_AMD29K:
	case XCOFF32_FILE_MACHINE_U800WR:
	case XCOFF32_FILE_MACHINE_U800RO:
	case XCOFF32_FILE_MACHINE_U800TOC:
	case XCOFF32_FILE_MACHINE_U802WR:
	case XCOFF32_FILE_MACHINE_U802RO:
	case XCOFF32_FILE_MACHINE_U802TOC:
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
	obj->xcoff = obj->hdr.f_opthdr == sizeof (struct coff_opt_hdr) + sizeof (struct xcoff32_opt_hdr);
	return true;
}

static bool r_bin_coff_init_opt_hdr(RBinCoffObj *obj) {
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

static bool r_bin_xcoff_init_opt_hdr(RBinCoffObj *obj) {
	int ret;
	ret = r_buf_fread_at (obj->b, sizeof (struct coff_hdr) + sizeof (struct coff_opt_hdr),
				(ut8 *)&obj->x_opt_hdr, "1I8S4c3I4c2S", 1);
	if (ret != sizeof (struct xcoff32_opt_hdr)) {
		return false;
	}
	return true;
}

static bool r_bin_coff_init_scn_hdr(RBinCoffObj *obj) {
	int ret, size;
	ut64 offset = sizeof (struct coff_hdr) + obj->hdr.f_opthdr;
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

/* init_ldhdr reads the XCOFF32 loader header, which is at the beginning of the .loader section */

static bool r_bin_xcoff_init_ldhdr(RBinCoffObj *obj) {
	int ret;
	ut16 loader_idx = obj->x_opt_hdr.o_snloader;
	if (!loader_idx) {
		return true;
	}
	if (loader_idx > obj->hdr.f_nscns) {
		R_LOG_WARN ("invalid loader section number (%d > %d)", loader_idx, obj->hdr.f_nscns);
		return false;
	}
	ut64 offset = obj->scn_hdrs[loader_idx-1].s_scnptr;  // section numbers start at 1
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)&obj->x_ldhdr, "8I", 1);
	if (ret != sizeof (struct xcoff32_ldhdr)) {
		R_LOG_WARN ("failed to read loader header");
		return false;
	}
	if (obj->x_ldhdr.l_version != 1) {
		R_LOG_WARN ("unsupported loader version (%u)", obj->x_ldhdr.l_version);
		return false;
	}
	return true;
}

static bool r_bin_xcoff_init_ldsyms(RBinCoffObj *obj) {
	int ret;
	size_t size;
	ut64 offset = obj->scn_hdrs[obj->x_opt_hdr.o_snloader-1].s_scnptr + sizeof (struct xcoff32_ldhdr);
	if (!obj->x_ldhdr.l_nsyms) {
		return true;
	}
	if (obj->x_ldhdr.l_nsyms >= 0xffff) { // too much symbols, probably not allocatable
		R_LOG_DEBUG ("too many loader symbols (%u)", obj->x_ldhdr.l_nsyms);
		return false;
	}
	// USHORT_MAX * 24UL cannot overflow size_t
	size = obj->x_ldhdr.l_nsyms * sizeof (struct xcoff32_ldsym);
	obj->x_ldsyms = calloc (1, size);
	if (!obj->x_ldsyms) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->x_ldsyms, "8cIS2c2I", obj->x_ldhdr.l_nsyms);
	if (ret != size) {
		R_LOG_DEBUG ("failed to read loader symbol table (%lu, %lu)", ret, size);
		R_FREE (obj->x_ldsyms);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_symtable(RBinCoffObj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (!obj->hdr.f_nsyms) {
		return true;
	}
	if (obj->hdr.f_nsyms >= 0xffff) { // too much symbols, probably not allocatable
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

static bool r_bin_coff_init_scn_va(RBinCoffObj *obj) {
	obj->scn_va = R_NEWS (ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	int i;
	ut64 va = 0;
	for (i = 0; i < obj->hdr.f_nscns; i++) {
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

static bool r_bin_coff_init(RBinCoffObj *obj, RBuffer *buf, bool verbose) {
	if (!obj || !buf) {
		return false;
	}
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new0 ();
	obj->imp_ht = ht_up_new0 ();
	if (!r_bin_coff_init_hdr (obj)) {
		R_LOG_ERROR ("failed to init coff header");
		return false;
	}
	r_bin_coff_init_opt_hdr (obj);
	if (obj->xcoff) {
		r_bin_xcoff_init_opt_hdr (obj);
	}
	if (!r_bin_coff_init_scn_hdr (obj)) {
		R_LOG_WARN ("failed to init section header");
		return false;
	}
	if (!obj->xcoff) {
		if (!r_bin_coff_init_scn_va (obj)) {
			R_LOG_WARN ("failed to init section VA table");
			return false;
		}
	} else {
		if (!r_bin_xcoff_init_ldhdr (obj)) {
			R_LOG_WARN ("failed to init xcoff loader header");
			return false;
		}
		if (!r_bin_xcoff_init_ldsyms (obj)) {
			R_LOG_WARN ("failed to init xcoff loader symbol table");
			return false;
		}
	}
	if (!r_bin_coff_init_symtable (obj)) {
		R_LOG_WARN ("failed to init symtable");
		return false;
	}
	return true;
}

R_IPI void r_bin_coff_free(RBinCoffObj *obj) {
	if (obj) {
		ht_up_free (obj->sym_ht);
		ht_up_free (obj->imp_ht);
		free (obj->scn_va);
		free (obj->scn_hdrs);
		free (obj->x_ldsyms);
		free (obj->symbols);
		r_buf_free (obj->b);
		free (obj);
	}
}

R_IPI RBinCoffObj *r_bin_coff_new_buf(RBuffer *buf, bool verbose) {
	RBinCoffObj* bin = R_NEW0 (RBinCoffObj);
	r_bin_coff_init (bin, buf, verbose);
	return bin;
}
