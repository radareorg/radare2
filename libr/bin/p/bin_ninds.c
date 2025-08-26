/* radare - LGPL - 2015-2025 - a0rtega */

#include <r_bin.h>
#include "../format/nin/nds.h"

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 ninlogohead[6];
	if (r_buf_read_at (b, 0xc0, ninlogohead, sizeof (ninlogohead)) == 6) {
		/* begin of nintendo logo =    \x24\xff\xae\x51\x69\x9a */
		if (!memcmp (ninlogohead, "\x24\xff\xae\x51\x69\x9a", 6)) {
			return true;
		}
		/* begin of Homebrew magic */
		if (!memcmp (ninlogohead, "\xC8\x60\x4F\xE2\x01\x70", 6)) {
			return true;
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	struct nds_hdr *loaded_header = R_NEW0 (struct nds_hdr);
	if (r_buf_read_at (b, 0, (ut8 *)loaded_header, sizeof (*loaded_header)) == sizeof (*loaded_header)) {
		bf->bo->bin_obj = loaded_header;
		return true;
	}
	free (loaded_header);
	bf->bo->bin_obj = NULL;
	return false;
}

static ut64 baddr(RBinFile *bf) {
	struct nds_hdr *loaded_header = (void *)bf->bo->bin_obj;
	if (!loaded_header) {
		return 0;
	}
	return (ut64)loaded_header->arm9_ram_address;
}

static RList *sections(RBinFile *bf) {
	RList *ret = r_list_new ();
	struct nds_hdr *loaded_header = (void *)bf->bo->bin_obj;
	if (!loaded_header) {
		return ret;
	}
	RBinSection *ptr9 = R_NEW0 (RBinSection);

	ptr9->name = strdup ("arm9");
	ptr9->size = loaded_header->arm9_size;
	ptr9->vsize = loaded_header->arm9_size;
	ptr9->paddr = loaded_header->arm9_rom_offset;
	ptr9->vaddr = loaded_header->arm9_ram_address;
	ptr9->perm = r_str_rwx ("rwx");
	ptr9->add = true;
	r_list_append (ret, ptr9);

	RBinSection *ptr7 = R_NEW0 (RBinSection);
	ptr7->name = strdup ("arm7");
	ptr7->size = loaded_header->arm7_size;
	ptr7->vsize = loaded_header->arm7_size;
	ptr7->paddr = loaded_header->arm7_rom_offset;
	ptr7->vaddr = loaded_header->arm7_ram_address;
	ptr7->perm = r_str_rwx ("rwx");
	ptr7->add = true;
	r_list_append (ret, ptr7);

	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	struct nds_hdr *loaded_header = (void *)bf->bo->bin_obj;
	if (bf && bf->buf && loaded_header) {
		ret->free = free;

		/* ARM9 entry point */
		RBinAddr *ptr9 = R_NEW0 (RBinAddr);
		ptr9->vaddr = loaded_header->arm9_entry_address;
		// ptr9->paddr = loaded_header.arm9_entry_address;
		r_list_append (ret, ptr9);

		/* ARM7 entry point */
		RBinAddr *ptr7 = R_NEW0 (RBinAddr);
		ptr7->vaddr = loaded_header->arm7_entry_address;
		// ptr7->paddr = loaded_header.arm7_entry_address;
		r_list_append (ret, ptr7);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->buf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	struct nds_hdr *loaded_header = (void *)bf->bo->bin_obj;
	char *filepath = r_str_newf ("%.12s - %.4s",
		loaded_header ? loaded_header->title : "", loaded_header ? loaded_header->gamecode : "");
	ret->file = filepath;
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Nintendo DS");
	ret->os = strdup ("nds");
	ret->arch = strdup ("arm");
	ret->has_va = true;
	ret->bits = 32;
	return ret;
}

RBinPlugin r_bin_plugin_ninds = {
	.meta = {
		.name = "ninds",
		.author = "a0rtega",
		.desc = "Nintendo DS ROM loader",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ninds,
	.version = R2_VERSION
};
#endif
