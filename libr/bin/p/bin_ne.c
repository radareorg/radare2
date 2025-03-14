/* radare - LGPL - Copyright 2009-2019 - GustavoLCR, nibble, pancake, alvarofe */

#include <r_bin.h>
#include "../i/private.h"
#include "../format/ne/ne.h"

static bool check(RBinFile *bf, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= 0x3d) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if ((ut64)idx + 26 < length) {
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
			if (!memcmp (buf, "NE", 2)) {
				return true;
			}
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	r_bin_ne_obj_t *res = r_bin_ne_new_buf (buf, bf->rbin->options.verbose);
	if (res) {
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_ne_free (bf->bo->bin_obj);
}

static void header(RBinFile *bf) {
	struct r_bin_t *rbin = bf->rbin;
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	rbin->cb_printf ("Signature: NE\n");
	rbin->cb_printf ("MajLinkerVersion: %d\n", ne->ne_header->MajLinkerVersion);
	rbin->cb_printf ("MinLinkerVersion: %d\n", ne->ne_header->MinLinkerVersion);
	rbin->cb_printf ("EntryTableOffset: 0x%04x\n", ne->ne_header->EntryTableOffset);
	rbin->cb_printf ("EntryTableLength: %d\n", ne->ne_header->EntryTableLength);
	rbin->cb_printf ("FileLoadCRC: %08x\n", ne->ne_header->FileLoadCRC);
	rbin->cb_printf ("ProgFlags: %d\n", ne->ne_header->ProgFlags);
	rbin->cb_printf ("ApplFlags: %d\n", ne->ne_header->ApplFlags);
	rbin->cb_printf ("AutoDataSegIndex: %d\n", ne->ne_header->AutoDataSegIndex);
	rbin->cb_printf ("InitHeapSize: %d\n", ne->ne_header->InitHeapSize);
	rbin->cb_printf ("InitStackSize: %d\n", ne->ne_header->InitStackSize);
	rbin->cb_printf ("EntryPointCSIndex: %d\n", ne->ne_header->csEntryPoint);
	rbin->cb_printf ("EntryPointIPOff: 0x%04x\n", ne->ne_header->ipEntryPoint);
	rbin->cb_printf ("InitStack: %d\n", ne->ne_header->InitStack);
	rbin->cb_printf ("SegCount: %d\n", ne->ne_header->SegCount);
	rbin->cb_printf ("ModuleRefsCount: %d\n", ne->ne_header->ModRefs);
	rbin->cb_printf ("NonResNamesTblSiz: 0x%x\n", ne->ne_header->NoResNamesTabSiz);
	rbin->cb_printf ("SegTableOffset: 0x%x\n", ne->ne_header->SegTableOffset);
	rbin->cb_printf ("ResourceTblOff: 0x%x\n", ne->ne_header->ResTableOffset);
	rbin->cb_printf ("ResidentNameTblOff: 0x%x\n", ne->ne_header->ResidNamTable);
	rbin->cb_printf ("ModuleRefTblOff: 0x%x\n", ne->ne_header->ModRefTable);
	rbin->cb_printf ("ImportNameTblOff: 0x%x\n", ne->ne_header->ImportNameTable);
	rbin->cb_printf ("OffStartNonResTab: %d\n", ne->ne_header->OffStartNonResTab);
	rbin->cb_printf ("MovEntryCount: %d\n", ne->ne_header->MovEntryCount);
	rbin->cb_printf ("FileAlnSzShftCnt: %d\n", ne->ne_header->FileAlnSzShftCnt);
	rbin->cb_printf ("nResTabEntries: %d\n", ne->ne_header->nResTabEntries);
	rbin->cb_printf ("OS: %s\n", ne->os);
	rbin->cb_printf ("OS2EXEFlags: %x\n", ne->ne_header->OS2EXEFlags);
	rbin->cb_printf ("retThunkOffset: %d\n", ne->ne_header->retThunkOffset);
	rbin->cb_printf ("segRefThunksOff: %d\n", ne->ne_header->segrefthunksoff);
	rbin->cb_printf ("mincodeswap: %d\n", ne->ne_header->mincodeswap);
	rbin->cb_printf ("winver: %d.%d\n", ne->ne_header->expctwinver[1], ne->ne_header->expctwinver[0]);
}

static RBinInfo *info(RBinFile *bf) {
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	RBinInfo *i = R_NEW0 (RBinInfo);
	if (i) {
		i->bits = 16;
		i->arch = strdup ("x86");
		i->os = strdup (ne->os);
		i->claimed_checksum = r_str_newf ("%08x", ne->ne_header->FileLoadCRC);
	}
	return i;
}

static RList *entries(RBinFile *bf) {
	return r_bin_ne_get_entrypoints (bf->bo->bin_obj);
}

static RList *symbols(RBinFile *bf) {
	return r_bin_ne_get_symbols (bf->bo->bin_obj);
}

static RList *imports(RBinFile *bf) {
	return r_bin_ne_get_imports (bf->bo->bin_obj);
}

static RList *sections(RBinFile *bf) {
	return r_bin_ne_get_segments (bf->bo->bin_obj);
}

static RList *relocs(RBinFile *bf) {
	return r_bin_ne_get_relocs (bf->bo->bin_obj);
}

RBinPlugin r_bin_plugin_ne = {
	.meta = {
		.name = "ne",
		.desc = "NE format r2 plugin",
		.author = "GustavoLCR",
		.license = "LGPL-3.0-only",
	},
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.header = &header,
	.info = &info,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.relocs = &relocs,
	.minstrlen = 4
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ne,
	.version = R2_VERSION
};
#endif
