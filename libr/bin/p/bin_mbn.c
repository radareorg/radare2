/* radare2 - LGPL - Copyright 2015-2025 - pancake */

#include <r_bin.h>

typedef struct sbl_header {
	ut32 load_index;
	ut32 version; // (flash_partition_version) 3 = nand
	ut32 paddr; // This + 40 is the start of the code in the file
	ut32 vaddr; // Where it's loaded in memory
	ut32 psize; // code_size + signature_size + cert_chain_size
	ut32 code_pa; // Only what's loaded to memory
	ut32 sign_va;
	ut32 sign_sz;
	ut32 cert_va; // Max of 3 certs?
	ut32 cert_sz;
} SblHeader;

/* Per-file SblHeader stored in bf->bo->bin_obj. Helper to fetch it. */
static SblHeader *sbl_from_bf(RBinFile *bf) {
	return (bf && bf->bo && bf->bo->bin_obj) ? (SblHeader *)bf->bo->bin_obj : NULL;
}

static void sbl_destroy(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return;
	}
	if (bf->bo->bin_obj) {
		R_FREE (bf->bo->bin_obj);
		bf->bo->bin_obj = NULL;
	}
}

static bool parse_sbl(RBuffer *b, SblHeader *h) {
	if (!b || !h) {
		return false;
	}
	int ret = r_buf_fread_at (b, 0, (ut8 *)h, "10i", 1);
	if (!ret) {
		return false;
	}
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (bf && b, false);
	ut64 bufsz = r_buf_size (b);
	SblHeader h = { 0 };
	if (!parse_sbl (b, &h)) {
		return false;
	}
	if (sizeof(SblHeader) < bufsz) {
		if (h.version != 3) { // NAND
			return false;
		}
		if (h.paddr + sizeof (SblHeader) > bufsz) { // NAND
			return false;
		}
		if (h.vaddr < 0x100 || h.psize > bufsz) { // NAND
			return false;
		}
		if (h.cert_va < h.vaddr) {
			return false;
		}
		if (h.cert_sz >= 0xf0000) {
			return false;
		}
		if (h.sign_va < h.vaddr) {
			return false;
		}
		if (h.sign_sz >= 0xf0000) {
			return false;
		}
		if (h.load_index < 1 || h.load_index > 0x40) {
			return false; // should be 0x19 ?
		}
		// TODO: Add more checks here
		return true;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	if (!bf || !bf->bo) {
		return false;
	}
	SblHeader *hdr = R_NEW0 (SblHeader);
	if (!parse_sbl (b, hdr)) {
		R_FREE (hdr);
		return false;
	}
	bf->bo->bin_obj = hdr;
	return true;
}

static ut64 baddr(RBinFile *bf) {
	SblHeader *sbl = sbl_from_bf (bf);
	return sbl ? sbl->vaddr : 0; // XXX
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	SblHeader *sbl = sbl_from_bf (bf);
	if (!sbl) {
		// try to read header directly from buffer as a fallback
		SblHeader h = { 0 };
		if (!parse_sbl (bf->buf, &h)) {
			r_list_free(ret);
			return NULL;
		}
		ptr->paddr = 40 + h.code_pa;
		ptr->vaddr = 40 + h.code_pa + h.vaddr;
	} else {
		ptr->paddr = 40 + sbl->code_pa;
		ptr->vaddr = 40 + sbl->code_pa + sbl->vaddr;
	}
	r_list_append (ret, ptr);
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	SblHeader *sbl = sbl_from_bf (bf);
	SblHeader h_local;
	SblHeader *h = sbl;
	if (!h) {
		int rc = r_buf_fread_at (bf->buf, 0, (ut8 *)&h_local, "10i", 1);
		if (!rc) {
			r_list_free (ret);
			return false;
		}
		h = &h_local;
	}

	// add text segment
	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup("text");
	ptr->size = h->psize;
	ptr->vsize = h->psize;
	ptr->paddr = h->paddr + 40;
	ptr->vaddr = h->vaddr;
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	ptr->has_strings = true;
	r_list_append (ret, ptr);

	ptr = R_NEW0 (RBinSection);
	ptr->name = strdup("sign");
	ptr->size = h->sign_sz;
	ptr->vsize = h->sign_sz;
	ptr->paddr = h->sign_va - h->vaddr;
	ptr->vaddr = h->sign_va;
	ptr->perm = R_PERM_R; // r--
	ptr->has_strings = true;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (h->cert_sz && h->cert_va > h->vaddr) {
		ptr = R_NEW0 (RBinSection);
		ptr->name = strdup ("cert");
		ptr->size = h->cert_sz;
		ptr->vsize = h->cert_sz;
		ptr->paddr = h->cert_va - h->vaddr;
		ptr->vaddr = h->cert_va;
		ptr->perm = R_PERM_R; // r--
		ptr->has_strings = true;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("bootloader");
	ret->rclass = strdup ("mbn");
	ret->os = strdup ("MBN");
	ret->arch = strdup ("arm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("mbn");
	ret->type = strdup ("sbl"); // secondary boot loader
	ret->bits = 16;
	ret->has_va = true;
	ret->has_crypto = true; // must be false if there' no sign or cert sections
	ret->has_pi = false;
	ret->has_nx = false;
	ret->big_endian = false;
	ret->dbg_info = false;
	return ret;
}

static ut64 size(RBinFile *bf) {
	SblHeader *sbl = sbl_from_bf (bf);
	if (sbl) {
		return sizeof (SblHeader) + sbl->psize;
	}
	// fallback: try reading header directly
	SblHeader h = { 0 };
	if (parse_sbl (bf->buf, &h)) {
		return sizeof (SblHeader) + h.psize;
	}
	return 0;
}

RBinPlugin r_bin_plugin_mbn = {
	.meta = {
		.name = "mbn",
		.desc = "MBN/SBL Qualcomm modems baseband firmwares",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.minstrlen = 10,
	.load = &load,
	.size = &size,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.destroy = &sbl_destroy,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mbn,
	.version = R2_VERSION
};
#endif
