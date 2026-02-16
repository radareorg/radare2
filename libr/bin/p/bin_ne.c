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

static char *header(RBinFile *bf, int mode) {
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	p ("Signature: NE\n");
	p ("MajLinkerVersion: %d\n", ne->ne_header->MajLinkerVersion);
	p ("MinLinkerVersion: %d\n", ne->ne_header->MinLinkerVersion);
	p ("EntryTableOffset: 0x%04x\n", ne->ne_header->EntryTableOffset);
	p ("EntryTableLength: %d\n", ne->ne_header->EntryTableLength);
	p ("FileLoadCRC: %08x\n", ne->ne_header->FileLoadCRC);
	p ("ProgFlags: %d\n", ne->ne_header->ProgFlags);
	p ("ApplFlags: %d\n", ne->ne_header->ApplFlags);
	p ("AutoDataSegIndex: %d\n", ne->ne_header->AutoDataSegIndex);
	p ("InitHeapSize: %d\n", ne->ne_header->InitHeapSize);
	p ("InitStackSize: %d\n", ne->ne_header->InitStackSize);
	p ("EntryPointCSIndex: %d\n", ne->ne_header->csEntryPoint);
	p ("EntryPointIPOff: 0x%04x\n", ne->ne_header->ipEntryPoint);
	p ("InitStack: %d\n", ne->ne_header->InitStack);
	p ("SegCount: %d\n", ne->ne_header->SegCount);
	p ("ModuleRefsCount: %d\n", ne->ne_header->ModRefs);
	p ("NonResNamesTblSiz: 0x%x\n", ne->ne_header->NoResNamesTabSiz);
	p ("SegTableOffset: 0x%x\n", ne->ne_header->SegTableOffset);
	p ("ResourceTblOff: 0x%x\n", ne->ne_header->ResTableOffset);
	p ("ResidentNameTblOff: 0x%x\n", ne->ne_header->ResidNamTable);
	p ("ModuleRefTblOff: 0x%x\n", ne->ne_header->ModRefTable);
	p ("ImportNameTblOff: 0x%x\n", ne->ne_header->ImportNameTable);
	p ("OffStartNonResTab: %d\n", ne->ne_header->OffStartNonResTab);
	p ("MovEntryCount: %d\n", ne->ne_header->MovEntryCount);
	p ("FileAlnSzShftCnt: %d\n", ne->ne_header->FileAlnSzShftCnt);
	p ("nResTabEntries: %d\n", ne->ne_header->nResTabEntries);
	p ("OS: %s\n", ne->os);
	p ("OS2EXEFlags: %x\n", ne->ne_header->OS2EXEFlags);
	p ("retThunkOffset: %d\n", ne->ne_header->retThunkOffset);
	p ("segRefThunksOff: %d\n", ne->ne_header->segrefthunksoff);
	p ("mincodeswap: %d\n", ne->ne_header->mincodeswap);
	p ("winver: %d.%d\n", ne->ne_header->expctwinver[1], ne->ne_header->expctwinver[0]);
#undef p
	return r_strbuf_drain (sb);
}

static RBinInfo *info(RBinFile *bf) {
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	RBinInfo *i = R_NEW0 (RBinInfo);
	i->bits = 16;
	i->arch = strdup ("x86");
	i->os = strdup (ne->os? ne->os: "os2");
	if (ne->ne_header) {
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
		.desc = "New Executables for 16bit Windows",
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
