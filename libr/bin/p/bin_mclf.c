/* radare2 - LGPL - Copyright 2025 - pancake */

// MCLF (MobiCore Load Format) loader based on public resources:
// * https://gist.github.com/Stolas/e3ecaebaa7369b2d8d6c539b9ac2908e
// * https://github.com/quarkslab/sboot-binwalk/blob/master/plugins/mclf.py
// * https://github.com/NeatMonster/mclf-ghidra-loader
// * https://github.com/ghassani/mclf-ghidra-loader
// * https://github.com/ghassani/mclf-ida-loader/blob/master/mclf_loader.py
// * https://github.com/v-rzh/mclf-binja-loader
// * https://android.googlesource.com/platform/hardware/samsung_slsi/exynos5/+/jb-mr1-dev/mobicore/common/MobiCore/inc/mcLoadFormat.h
// * https://blog.quarkslab.com/a-deep-dive-into-samsungs-trustzone-part-2.html and
// * https://github.com/quarkslab/samsung-trustzone-research to complete the implementation

#include <r_bin.h>

typedef struct {
	bool be;
	ut32 version;
	ut32 flags;
	ut32 memType;
	ut32 serviceType;
	ut32 numInstances;
	ut8 uuid[16];
	ut32 driverId;
	ut32 numThreads;
	ut32 text_va;
	ut32 text_len;
	ut32 data_va;
	ut32 data_len;
	ut32 bss_len;
	ut32 entry;
	ut32 serviceVersion; // optional in older samples, present in >= v2.0.1
	// text header (descriptor) fields
	ut32 text_hdr_version;
	ut32 text_hdr_len;
	ut32 requiredFeat;
	ut32 mcLibEntry; // entry point to mcLib trampoline
	ut32 tlApiVers;
	ut32 drApiVers;
} MclfHeader;

/* Per-file MclfHeader stored in bf->bo->bin_obj. Helper to fetch it. */
static MclfHeader *mclf_from_bf(RBinFile *bf) {
	return (bf && bf->bo && bf->bo->bin_obj) ? (MclfHeader *)bf->bo->bin_obj : NULL;
}

static void mclf_destroy(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return;
	}
	if (bf->bo->bin_obj) {
		R_FREE (bf->bo->bin_obj);
		bf->bo->bin_obj = NULL;
	}
}

static bool parse_header(RBuffer *b, MclfHeader *h) {
	ut8 buf[512];
	int r = r_buf_read_at (b, 0, buf, sizeof (buf));
	/* Single read: require at least the fixed header through entry (0x48)
	 * so we can parse mandatory fields. Other fields are optional and
	 * will be read only if present in the buffer. */
	if (r <= 0 || (size_t)r < 0x48) {
		return false;
	}

	h->be = false;
	if (!memcmp (buf, "MCLF", 4)) {
		h->be = false;
	} else if (!memcmp (buf, "FLCM", 4)) {
		h->be = true;
	} else {
		return false;
	}

/* Helper to read 32-bit values from the local buffer honoring endianness */
#define READ32(off) (h->be ? r_read_be32 (buf + (off)) : r_read_le32 (buf + (off)))

	h->version = READ32 (0x4);
	h->flags = READ32 (0x8);
	h->memType = READ32 (0xC);
	h->serviceType = READ32 (0x10);
	h->numInstances = READ32 (0x14);
	memcpy (h->uuid, buf + 0x18, sizeof (h->uuid));
	h->driverId = READ32 (0x28);
	h->numThreads = READ32 (0x2C);
	h->text_va = READ32 (0x30);
	h->text_len = READ32 (0x34);
	h->data_va = READ32 (0x38);
	h->data_len = READ32 (0x3C);
	h->bss_len = READ32 (0x40);
	h->entry = READ32 (0x44);

	/* serviceVersion may be missing in some early samples; only read if present */
	if ( (size_t)r >= 0x48 + 4) {
		h->serviceVersion = READ32 (0x48);
	} else {
		h->serviceVersion = 0;
	}

	/* Parse Text Header at paddr 0x80 if available */
	if ( (size_t)r >= 0x80 + 4) {
		h->text_hdr_version = READ32 (0x80);
		if ( (size_t)r >= 0x84 + 4) {
			h->text_hdr_len = READ32 (0x84);
		} else {
			h->text_hdr_len = 0;
		}
		if ( (size_t)r >= 0x88 + 4) {
			h->requiredFeat = READ32 (0x88);
		} else {
			h->requiredFeat = 0;
		}
		if ( (size_t)r >= 0x8C + 4) {
			h->mcLibEntry = READ32 (0x8C);
		} else {
			h->mcLibEntry = 0;
		}
		/* tlApi/drApi versions are placed after mcIMD; read if present */
		if ( (size_t)r >= 0x9C + 4) {
			h->tlApiVers = READ32 (0x9C);
		} else {
			h->tlApiVers = 0;
		}
		if ( (size_t)r >= 0xA0 + 4) {
			h->drApiVers = READ32 (0xA0);
		} else {
			h->drApiVers = 0;
		}
	} else {
		h->text_hdr_version = 0;
		h->text_hdr_len = 0;
		h->requiredFeat = 0;
		h->mcLibEntry = 0;
		h->tlApiVers = 0;
		h->drApiVers = 0;
	}

#undef READ32
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	MclfHeader h = { 0 };
	if (!parse_header (b, &h)) {
		return false;
	}
	// Basic sanity checks based on public loaders
	const ut64 fsz = r_buf_size (b);
	if (h.text_len == 0 || h.data_len > fsz || h.text_len > fsz) {
		return false;
	}
	if ( (ut64)h.text_len + (ut64)h.data_len > fsz) {
		// Some files may include only text (drivers). Allow equal or larger file
		// but never smaller than declared sizes.
		return false;
	}
	if (h.text_va == 0 || h.entry == 0) {
		// Many trustlets map at non-zero VA and have valid entry
		return false;
	}
	// Versions seen in docs: 0x20001.. >= 0x20005
	if (h.version < 0x20001) {
		return false;
	}
	return true;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	if (!bf || !bf->bo) {
		return false;
	}
	MclfHeader *hdr = R_NEW0 (MclfHeader);
	if (!parse_header (b, hdr)) {
		R_FREE (hdr);
		return false;
	}
	bf->bo->bin_obj = hdr;
	return true;
}

static ut64 baddr(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	return hdr ? hdr->text_va : 0;
}

typedef struct {
	ut32 ord;
	const char *name;
} McApiEnt;

static const McApiEnt mc_api_list[] = {
	{ 0x80000000, "mcLib_init" },
	{ 0, "tlApiNOP" },
	{ 1, "tlApiGetVersion" },
	{ 2, "tlApiGetMobicoreVersion" },
	{ 3, "tlApiGetPlatformInfo" },
	{ 4, "tlApiExit" },
	{ 5, "tlApiLogvPrintf" },
	{ 6, "tlApiWaitNotification" },
	{ 7, "tlApiNotify" },
	{ 8, "tlApi_callDriver" },
	{ 9, "tlApiWrapObjectExt" },
	{ 10, "tlApiUnwrapObjectExt" },
	{ 11, "tlApiGetSuid" },
	{ 12, "tlApiSecSPICmd" },
	{ 13, "tlApiCrAbort" },
	{ 14, "tlApiRandomGenerateData" },
	{ 15, "tlApiGenerateKeyPair" },
	{ 16, "tlApiCipherInitWithData" },
	{ 17, "tlApiCipherUpdate" },
	{ 18, "tlApiCipherDoFinal" },
	{ 19, "tlApiSignatureInitWithData" },
	{ 20, "tlApiSignatureUpdate" },
	{ 21, "tlApiSignatureSign" },
	{ 22, "tlApiSignatureVerify" },
	{ 23, "tpiApiMessageDigestInitWithData" },
	{ 24, "tlApiMessageDigestUpdate" },
	{ 25, "tlApiMessageDigestDoFinal" },
	{ 26, "tlApiGetVirtMemType" },
	{ 27, "tlApiDeriveKey" },
	{ 28, "tlApiMalloc" },
	{ 29, "tlApiRealloc" },
	{ 30, "tlApiFree" },
	{ 43, "tlApiGetIDs" },
	{ 83, "tlApiRandomGenerateData_wrap" },
	{ 84, "tlApiCrash" },
	{ 85, "tlApiEndorse" },
	{ 86, "tlApiTuiGetScreenInfo" },
	{ 87, "tlApiTuiOpenSession" },
	{ 88, "tlApiTuiCloseSession" },
	{ 89, "tlApiTuiSetImage" },
	{ 90, "tlApiTuiGetTouchEvent" },
	{ 91, "tlApiTuiGetTouchEventsLoop" },
	{ 92, "tlApiDrmProcessContent" },
	{ 93, "tlApiDrmOpenSession" },
	{ 94, "tlApiDrmCloseSession" },
	{ 95, "tlApiDrmCheckLink" },
	{ 96, "tlApiDeriveKey_wrapper" },
	{ 97, "tlApiUnwrapObjectExt_wrapper" },
	{ 98, "tlApiGetSecureTimestamp" },
	{ 0x1000 + 0, "drApiGetVersion" },
	{ 0x1000 + 1, "drApiExit" },
	{ 0x1000 + 2, "drApiMapPhys" },
	{ 0x1000 + 3, "drApiUnmap" },
	{ 0x1000 + 4, "drApiMapPhysPage4KBWithHardware" },
	{ 0x1000 + 5, "drApiMapClient" },
	{ 0x1000 + 6, "drApiMapClientAndParams" },
	{ 0x1000 + 7, "drApiAddrTranslateAndCheck" },
	{ 0x1000 + 8, "drApiGetTaskid" },
	{ 0x1000 + 9, "drApiTaskidGetThreadid" },
	{ 0x1000 + 10, "drApiGetLocalThreadId" },
	{ 0x1000 + 11, "drApiStartThread" },
	{ 0x1000 + 12, "drApiStopThread" },
	{ 0x1000 + 13, "drApiResumeThread" },
	{ 0x1000 + 14, "drApiThreadSleep" },
	{ 0x1000 + 15, "drApiSetThreadPriority" },
	{ 0x1000 + 16, "drApiIntrAttach" },
	{ 0x1000 + 17, "drApiIntrDetach" },
	{ 0x1000 + 18, "drApiWaitForIntr" },
	{ 0x1000 + 19, "drApiTriggerIntr" },
	{ 0x1000 + 20, "drApiIpcWaitForMessage" },
	{ 0x1000 + 21, "drApiIpcCallToIPCH" },
	{ 0x1000 + 22, "drApiIpcSignal" },
	{ 0x1000 + 23, "drApiIpcSigWait" },
	{ 0x1000 + 24, "drApiNotify" },
	{ 0x1000 + 25, "drApiSystemCtrl" },
	{ 0x1000 + 27, "drApiVirt2Phys" },
	{ 0x1000 + 28, "drApiCacheDataClean" },
	{ 0x1000 + 29, "drApiCacheDataCleanAndInvalidate" },
	{ 0x1000 + 30, "drApiNotifyClient" },
	{ 0x1000 + 31, "drApiThreadExRegs" },
	{ 0x1000 + 32, "drApiInstallFc" },
	{ 0x1000 + 33, "drApiIpcUnknownMessage" },
	{ 0x1000 + 34, "drApiIpcUnknownException" },
	{ 0x1000 + 35, "drApiGetPhysMemType" },
	{ 0x1000 + 36, "drApiGetClientRootAndSpId" },
	{ 0x1000 + 37, "drApiCacheDataCleanRange" },
	{ 0x1000 + 38, "drApiCacheDataCleanAndInvalidateRange" },
	{ 0x1000 + 39, "drApiMapPhys64" },
	{ 0x1000 + 40, "drApiMapPhys64_2" },
	{ 0x1000 + 41, "drApiVirt2Phys64" },
	{ 0x1000 + 42, "drApiGetPhysMemType64" },
	{ 0x1000 + 43, "drApiUpdateNotificationThread" },
	{ 0x1000 + 44, "drApiRestartThread" },
	{ 0x1000 + 45, "drApiGetSecureTimestamp" },
	{ 0x1000 + 46, "drApiFastCall" },
	{ 0x1000 + 47, "drApiGetClientUuid" },
	{ 0x1000 + 49, "drApiMapVirtBuf" },
	{ 0x1000 + 50, "drApiUnmapPhys2" },
	{ 0x1000 + 51, "drApiMapPhys2" },
	{ 0x1000 + 52, "drApiUnmapVirtBuf2" },
};

static const size_t mc_api_list_count = sizeof(mc_api_list) / sizeof(mc_api_list[0]);

static const char *mc_api_libname(ut32 ord) {
	if (ord == 0x80000000) {
		return "mclib";
	}
	if (ord >= 0x1000) {
		return "drApi";
	}
	return "tlApi";
}

static RList *entries(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	if (!hdr) {
		return NULL;
	}
	RList *res = r_list_newf (free);
	if (!res) {
		return NULL;
	}
	RBinAddr *ea = R_NEW0 (RBinAddr);
	if (!ea) {
		r_list_free (res);
		return NULL;
	}
	ut64 entry = hdr->entry;
	// If Thumb bit is set, clear it; analysis will detect Thumb automatically later
	if (entry & 1) {
		entry--;
	}
	ea->vaddr = entry;
	ea->paddr = (entry >= hdr->text_va) ? (entry - hdr->text_va) : 0;
	r_list_append (res, ea);
	return res;
}

static RList *sections(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	if (!hdr) {
		return NULL;
	}
	RList *ret = r_list_newf (free);

	// .text
	RBinSection *s = R_NEW0 (RBinSection);
	s->name = strdup (".text");
	s->paddr = 0;
	s->vaddr = hdr->text_va;
	s->size = hdr->text_len;
	s->vsize = hdr->text_len;
	s->perm = R_PERM_RX;
	s->add = true;
	s->has_strings = true;
	r_list_append (ret, s);

	// .data
	s = R_NEW0 (RBinSection);
	s->name = strdup (".data");
	s->paddr = hdr->text_len;
	s->vaddr = hdr->data_va;
	s->size = hdr->data_len;
	s->vsize = hdr->data_len;
	s->perm = R_PERM_R;
	if (hdr->data_len) {
		s->perm |= R_PERM_W;
	}
	s->add = true;
	s->has_strings = true;
	r_list_append (ret, s);

	// .bss (no bytes in file)
	if (hdr->bss_len) {
		s = R_NEW0 (RBinSection);
		s->name = strdup (".bss");
		s->paddr = 0;
		s->vaddr = (ut64)hdr->data_va + (ut64)hdr->data_len;
		s->size = 0;
		s->vsize = hdr->bss_len;
		s->perm = R_PERM_RW;
		s->add = true;
		r_list_append (ret, s);
	}

	return ret;
}

static RList *symbols(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	if (!hdr) {
		return NULL;
	}
	RList *ret = r_list_newf (free);
	RBinSymbol *s = NULL;
	// _start
	s = R_NEW0 (RBinSymbol);
	s->name = r_bin_name_new ("_start");
	s->vaddr = (hdr->entry & 1) ? (hdr->entry - 1) : hdr->entry;
	s->paddr = (s->vaddr >= hdr->text_va) ? (s->vaddr - hdr->text_va) : 0;
	s->type = "FUNC";
	r_list_append (ret, s);
	// header and text descriptor anchors
	s = R_NEW0 (RBinSymbol);
	s->name = r_bin_name_new ("__mclf_header");
	s->vaddr = hdr->text_va;
	s->paddr = 0;
	s->type = "OBJ";
	r_list_append (ret, s);
	s = R_NEW0 (RBinSymbol);
	s->name = r_bin_name_new ("__mclf_text_descriptor");
	s->vaddr = hdr->text_va + 0x80;
	s->paddr = 0x80;
	s->type = "OBJ";
	r_list_append (ret, s);
	// mcLibEntry (if present)
	if (hdr->mcLibEntry) {
		s = R_NEW0 (RBinSymbol);
		s->name = r_bin_name_new ("mcLibEntry");
		s->vaddr = hdr->mcLibEntry & (ut32)~1;
		if (s->vaddr >= hdr->text_va && s->vaddr < hdr->text_va + hdr->text_len) {
			s->paddr = s->vaddr - hdr->text_va;
		} else if (s->vaddr >= hdr->data_va && s->vaddr < hdr->data_va + hdr->data_len) {
			s->paddr = hdr->text_len + (s->vaddr - hdr->data_va);
		} else {
			s->paddr = UT64_MAX;
		}
		s->type = "FUNC";
		r_list_append (ret, s);
	}
	return ret;
}

static RList *imports(RBinFile *bf) {
	RList *ret = r_list_newf ( (RListFree)r_bin_import_free);
	size_t i;
	for (i = 0; i < mc_api_list_count; i++) {
		const McApiEnt *e = &mc_api_list[i];
		RBinImport *imp = R_NEW0 (RBinImport);
		imp->name = r_bin_name_new (e->name);
		imp->libname = strdup (mc_api_libname (e->ord));
		imp->type = "FUNC";
		imp->bind = "GLOBAL";
		imp->ordinal = e->ord;
		r_list_append (ret, imp);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file ? strdup (bf->file) : NULL;
	ret->bclass = strdup ("firmware");
	ret->rclass = strdup ("mclf");
	ret->os = strdup ("MobiCore");
	ret->arch = strdup ("arm");
	ret->machine = strdup ("arm");
	ret->subsystem = strdup ("trustzone");
	ret->type = strdup ("MCLF trustlet/driver");
	ret->bits = 32;
	ret->has_va = true;
	ret->has_pi = false;
	ret->has_nx = false;
	ret->big_endian = hdr ? hdr->be : false;
	ret->dbg_info = false;
	return ret;
}

static ut64 size(RBinFile *bf) {
	MclfHeader *hdr = mclf_from_bf (bf);
	if (!hdr) {
		return 0;
	}
	// The file contains the full .text and .data
	return (ut64)hdr->text_len + (ut64)hdr->data_len;
}

RBinPlugin r_bin_plugin_mclf = {
	.meta = {
		.name = "mclf",
		.desc = "MCLF (MobiCore Load Format) trustlets/drivers",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.minstrlen = 4,
	.load = &load,
	.size = &size,
	.destroy = &mclf_destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.symbols = &symbols,
	.imports = &imports,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mclf,
	.version = R2_VERSION
};
#endif
