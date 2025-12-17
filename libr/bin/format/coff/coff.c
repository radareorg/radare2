/* radare - LGPL - Copyright 2008-2025 pancake, inisider */

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

// copied from bfd
static bool r_coff_decode_base64(const char *str, ut32 len, ut32 *res) {
	ut32 i;
	ut32 val;

	val = 0;
	for (i = 0; i < len; i++) {
		char c = str[i];
		ut32 d;
		if (c >= 'A' && c <= 'Z') {
			d = c - 'A';
		} else if (c >= 'a' && c <= 'z') {
			d = c - 'a' + 26;
		} else if (c >= '0' && c <= '9') {
			d = c - '0' + 52;
		} else if (c == '+') {
			d = 62;
		} else if (c == '/') {
			d = 63;
		} else {
			return false;
		}

		/* Check for overflow */
		if ((val >> 26) != 0) {
			return false;
		}

		val = (val << 6) + d;
	}

	*res = val;
	return true;
}

R_IPI char *r_coff_symbol_name(RBinCoffObj *obj, void *ptr) {
	char n[256] = {0};
	int len = 0;
	ut32 offset = 0; // offset into the string table.

	typedef union {
		char name[9];
		struct {
			ut32 zero;
			ut32 offset;
		};
	} NameOff;
	NameOff no;
	memcpy (&no, ptr, sizeof (no));
	NameOff *p = &no;
	if (!ptr) {
		return NULL;
	}

	if (p->zero && *p->name != '/') {
		return r_str_ndup (p->name, 8);
	}
	if (*p->name == '/') {
		char *offset_str = (p->name + 1);
		no.name[8] = 0;
		if (*offset_str == '/') {
			r_coff_decode_base64 (p->name + 2, 6, &offset);
		} else {
			// ensure null termination
			offset = atoi (offset_str);
		}
	} else {
		offset = p->offset;
	}

	// Calculate the actual pointer to the symbol/section name we're interested in.
	st64 name_ptr;
	if (obj->type == COFF_TYPE_BIGOBJ) {
		ut32 f_nsyms = obj->bigobj_hdr.f_nsyms;
		if (f_nsyms < 1 || f_nsyms > UT24_MAX) {
		//	R_LOG_WARN ("Invalid amount of big fsyms %d", f_nsyms);
		//	f_nsyms &= 0xff;
		//	return NULL;
		}
		name_ptr = obj->bigobj_hdr.f_symptr + (f_nsyms * sizeof (struct coff_bigobj_symbol) + offset);
	} else {
		ut32 f_nsyms = obj->hdr.f_nsyms;
		if (f_nsyms < 1 || f_nsyms > UT24_MAX) {
		//	R_LOG_WARN ("Invalid amount of fsyms %d", f_nsyms);
		//	f_nsyms &= 0xff;
		//	return NULL;
		}
		name_ptr = obj->hdr.f_symptr + (f_nsyms * sizeof (struct coff_symbol) + offset);
	}
#if 0
	if (name_ptr < 0 || name_ptr >= obj->size) {
		return NULL;
	}
#endif
	len = r_buf_read_at (obj->b, name_ptr, (ut8 *)n, sizeof (n));
	if (len < 1) {
		return NULL;
	}
	/* ensure null terminated string */
	n[sizeof (n) - 1] = 0;
	return strdup (n);
}

static int r_coff_rebase_sym(RBinCoffObj *obj, RBinAddr *addr, int symbol_index) {
	ut32 n_scnum = 0;
	ut32 n_value = 0;
	ut32 f_nscns = 0;
	if (obj->type == COFF_TYPE_BIGOBJ) {
		n_scnum = obj->bigobj_symbols[symbol_index].n_scnum;
		n_value = obj->bigobj_symbols[symbol_index].n_value;
		f_nscns = obj->bigobj_hdr.f_nscns;
	} else {
		n_scnum = obj->symbols[symbol_index].n_scnum;
		n_value = obj->symbols[symbol_index].n_value;
		f_nscns = obj->hdr.f_nscns;
	}
#if 0
	if (n_scnum < 1 || n_scnum > UT16_MAX) {
		return 0;
	}
#endif
	if (n_scnum < 1 || n_scnum > f_nscns) {
		return 0;
	}
	addr->paddr = obj->scn_hdrs[n_scnum - 1].s_scnptr + n_value;
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
	addr->vaddr = entry_vaddr;
	return addr;
}

static bool r_coff_get_entry_helper(RBinCoffObj *obj, RBinAddr *address) {
	void *symbols = NULL;
	size_t symbol_size;
	size_t symbol_count;
	if (obj->type == COFF_TYPE_BIGOBJ) {
		symbols = (void *)obj->bigobj_symbols;
		symbol_size = sizeof (struct coff_bigobj_symbol);
		symbol_count = obj->bigobj_hdr.f_nsyms;
	} else {
		symbols = (void *)obj->symbols;
		symbol_size = sizeof (struct coff_symbol);
		symbol_count = obj->hdr.f_nsyms;
	}

	int i;
#if 0
	if (symbol_count < 1 || symbol_count > UT16_MAX) {
		return false;
	}
#endif
	if (symbols) {
		for (i = 0; i < symbol_count; i++) {
			const char *name = (const char *)symbols + (i * symbol_size);
			// can be non null terminated
			if ((!strncmp (name, "_start", symbol_size) || !strncmp (name, "start", symbol_size)) &&
					r_coff_rebase_sym (obj, address, i)) {
				return true;
			}
		}
		for (i = 0; i < symbol_count; i++) {
			const char *name = (const char *)symbols + (i * symbol_size);
			if ((!strncmp (name, "_main", symbol_size) || !strncmp (name, "main", symbol_size)) &&
					r_coff_rebase_sym (obj, address, i)) {
				return true;
			}
		}
	}
	return false;
}

/* Try to get a valid entrypoint using the methods outlined in
 * https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
R_IPI RBinAddr *r_coff_get_entry(RBinCoffObj *obj) {
	/* Special case for XCOFF */
	if (obj->type == COFF_TYPE_XCOFF) {
		return r_xcoff_get_entry (obj);
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	/* Simplest case, the header provides the entrypoint address */
	if (obj->type == COFF_TYPE_REGULAR && obj->hdr.f_opthdr) {
		addr->paddr = obj->opt_hdr.entry;
		return addr;
	}

	/* No help from the header eh? Use the address of the symbols '_start'
	 * or 'main' if present */
	if ((obj->type == COFF_TYPE_BIGOBJ && obj->bigobj_symbols) || obj->symbols) {
		if (r_coff_get_entry_helper (obj, addr)) {
			return addr;
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
	ut8 buf[16];
	int result = r_buf_read_at (obj->b, 12, buf, sizeof (buf));
	if (result >= sizeof (buf) && memcmp (coff_bigobj_magic, buf, 16) == 0) {
		obj->type = COFF_TYPE_BIGOBJ;
	}

	ut64 offset = obj->type == COFF_TYPE_BIGOBJ? 6: 0;
	ut16 magic = r_buf_read_le16_at (obj->b, offset);

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
	int expected = obj->type == COFF_TYPE_BIGOBJ? sizeof (struct coff_bigobj_hdr): sizeof (struct coff_hdr);

	if (obj->type == COFF_TYPE_BIGOBJ) {
		ret = r_buf_fread_at (obj->b, 0, (ut8 *)&obj->bigobj_hdr, obj->endian? "4S12I": "4s12i", 1);
	} else {
		ret = r_buf_fread_at (obj->b, 0, (ut8 *)&obj->hdr, obj->endian? "2S3I2S": "2s3i2s", 1);
	}
	if (ret != expected) {
		return false;
	}

	if (magic == COFF_FILE_TI_COFF) {
		ret = r_buf_fread (obj->b, (ut8 *)&obj->target_id, obj->endian? "S": "s", 1);
		if (ret != sizeof (ut16)) {
			return false;
		}
	}

	if (obj->type != COFF_TYPE_BIGOBJ &&
		obj->hdr.f_opthdr == sizeof (struct coff_opt_hdr) + sizeof (struct xcoff32_opt_hdr)) {
		obj->type = COFF_TYPE_XCOFF;
	}
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

#ifndef R_BIN_COFF_BIGOBJ
static bool r_bin_xcoff_init_opt_hdr(RBinCoffObj *obj) {
	int ret;
	ret = r_buf_fread_at (obj->b, sizeof (struct coff_hdr) + sizeof (struct coff_opt_hdr),
				(ut8 *)&obj->x_opt_hdr, "1I8S4c3I4c2S", 1);
	if (ret != sizeof (struct xcoff32_opt_hdr)) {
		return false;
	}
	return true;
}
#endif

static bool r_bin_coff_init_scn_hdr(RBinCoffObj *obj) {
	int ret, size;
	ut32 f_nscns;

	ut64 offset = 0;
	ut16 f_magic;
	if (obj->type == COFF_TYPE_BIGOBJ) {
		offset = sizeof (struct coff_bigobj_hdr);
		f_nscns = obj->bigobj_hdr.f_nscns;
		f_magic = obj->bigobj_hdr.f_magic;
	} else {
		offset = sizeof (struct coff_hdr) + obj->hdr.f_opthdr;
		f_nscns = obj->hdr.f_nscns;
		f_magic = obj->hdr.f_magic;
	}
	if (ST32_MUL_OVFCHK (sizeof (struct coff_scn_hdr), f_nscns)) {
	// if ((st32)f_nscns < 1 || f_nscns > UT16_MAX)
		R_LOG_WARN ("Dimming f_nscns count because is poluted or too large");
		f_nscns &= 0xff;
		if (obj->type == COFF_TYPE_BIGOBJ) {
			obj->bigobj_hdr.f_nscns = f_nscns;
		} else {
			obj->hdr.f_nscns = f_nscns;
		}
	}

	if (f_magic == COFF_FILE_TI_COFF) {
		offset += 2;
	}
	size = f_nscns * sizeof (struct coff_scn_hdr);
	if (offset > obj->size || offset + size > obj->size || size < 0) {
		return false;
	}
	obj->scn_hdrs = calloc (1, size + sizeof (struct coff_scn_hdr));
	if (!obj->scn_hdrs) {
		return false;
	}
	ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->scn_hdrs,
			obj->endian? "8c6I2S1I": "8c6i2s1i", f_nscns);
	// 8 + (6*4) + (2*2) + (4) = 40
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
	ut64 offset;
	if (!obj->x_ldhdr.l_nsyms) {
		return true;
	}
	offset = obj->scn_hdrs[obj->x_opt_hdr.o_snloader-1].s_scnptr + sizeof (struct xcoff32_ldhdr);
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
	int ret;
	ut32 f_symptr, f_nsyms;
	ut32 symbol_size;
	if (obj->type == COFF_TYPE_BIGOBJ) {
		symbol_size = sizeof (struct coff_bigobj_symbol);
		f_symptr = obj->bigobj_hdr.f_symptr;
		f_nsyms = obj->bigobj_hdr.f_nsyms;
	} else {
		symbol_size = sizeof (struct coff_symbol);
		f_symptr = obj->hdr.f_symptr;
		f_nsyms = obj->hdr.f_nsyms;
		if (f_nsyms >= 0xffff) {
			// R_FREE (obj->bigobj_symbols);
			// R_FREE (obj->symbols);
			// too much symbols, probably not allocatable
			return false;
		}
	}
	ut64 offset = f_symptr;
	if (!f_nsyms) {
		return true;
	}
	if (ST32_MUL_OVFCHK (symbol_size, f_nsyms)) {
		R_LOG_WARN ("Dimming f_nsyms count because is poluted or too large");
		f_nsyms = 1;
		if (obj->type == COFF_TYPE_BIGOBJ) {
			obj->bigobj_hdr.f_nsyms = f_nsyms;
		} else {
			obj->hdr.f_nsyms = f_nsyms;
		}
	}
	int size = f_nsyms * symbol_size;
	if (size < 0 || size > obj->size || offset > obj->size || offset + size > obj->size) {
		R_FREE (obj->bigobj_symbols);
		R_FREE (obj->symbols);
		return false;
	}
	void *symbols = calloc (1, size + symbol_size);
	if (!symbols) {
		R_FREE (obj->bigobj_symbols);
		R_FREE (obj->symbols);
		return false;
	}
	// XXX RBuf.readAt() is unsafe, so we need to trim down the f_nsyms
	if (obj->type == COFF_TYPE_BIGOBJ) {
		obj->bigobj_symbols = symbols;
		const char *fmt = obj->endian? "8c2I1S2c": "8c2i1s2c";
		ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->bigobj_symbols, fmt, f_nsyms);
	} else {
		obj->symbols = symbols;
		const char *fmt = obj->endian? "8c1I2S2c": "8c1i2s2c";
		ret = r_buf_fread_at (obj->b, offset, (ut8 *)obj->symbols, fmt, f_nsyms);
	}
	if (ret != size) {
		R_FREE (obj->bigobj_symbols);
		R_FREE (obj->symbols);
		return false;
	}
	return true;
}

static bool r_bin_coff_init_scn_va(RBinCoffObj *obj) {
	int f_nscns = obj->type == COFF_TYPE_BIGOBJ? obj->bigobj_hdr.f_nscns: obj->hdr.f_nscns;
#if 0
	if (f_nscns < 1) {
		R_LOG_WARN ("Invalid amount of f_nscns %d", f_nscns);
		return true;
	}
	if (f_nscns > UT16_MAX) {
		R_LOG_WARN ("Invalid amount of f_nscns %d", f_nscns);
		return true;
	}
	if (ST32_MUL_OVFCHK (sizeof (struct coff_scn_hdr), f_nscns)) {
		R_LOG_WARN ("Dimming f_nscns count because is poluted or too large");
		f_nscns &= 0xff;
		return false;
	}
#endif
	obj->scn_va = R_NEWS (ut64, f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	int i;
	ut64 va = 0;
	for (i = 0; i < f_nscns; i++) {
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
	R_RETURN_VAL_IF_FAIL (obj && buf, false);
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new0 ();
	obj->imp_ht = ht_up_new0 ();

	// Assume we're dealing with regular coff
	// The init functions will change the type if necessary.
	obj->type = COFF_TYPE_REGULAR;
	if (!r_bin_coff_init_hdr (obj)) {
		R_LOG_ERROR ("failed to init coff header");
		return false;
	}

	if (obj->type != COFF_TYPE_BIGOBJ) {
		r_bin_coff_init_opt_hdr (obj);
		if (obj->type == COFF_TYPE_XCOFF) {
			r_bin_xcoff_init_opt_hdr (obj);
		}
	}

	if (!r_bin_coff_init_scn_hdr (obj)) {
		R_LOG_WARN ("failed to init section header");
		return false;
	}
	if (obj->type != COFF_TYPE_XCOFF) {
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
		if (obj->type == COFF_TYPE_BIGOBJ) {
			free (obj->bigobj_symbols);
		} else {
			free (obj->symbols);
		}
		r_buf_free (obj->b);
		free (obj);
	}
}

R_IPI RBinCoffObj *r_bin_coff_new_buf(RBuffer *buf, bool verbose) {
	RBinCoffObj* bin = R_NEW0 (RBinCoffObj);
	r_bin_coff_init (bin, buf, verbose);
	return bin;
}
