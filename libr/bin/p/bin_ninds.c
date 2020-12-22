/* radare - LGPL - 2015-2019 - a0rtega */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>

#include "../format/nin/nds.h"

static struct nds_hdr loaded_header;

static bool check_buffer(RBuffer *b) {
	ut8 ninlogohead[6];
	if (r_buf_read_at (b, 0xc0, ninlogohead, sizeof (ninlogohead)) == 6) {
		/* begin of nintendo logo =    \x24\xff\xae\x51\x69\x9a */
		if (!memcmp (ninlogohead, "\x24\xff\xae\x51\x69\x9a", 6)) {
			return true;
		}
		/* begin of Homebrew magic */
		if (!memcmp (ninlogohead, "\xC8\x60\x4F\xE2\x01\x70", 6)){
			return true;
		}
	}
	return false;
}

static bool load_buffer (RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	r_buf_read_at (b, 0, (ut8*)&loaded_header, sizeof (loaded_header));
	*bin_obj = &loaded_header;
	return (*bin_obj != NULL);
}

static ut64 baddr(RBinFile *bf) {
	return (ut64) loaded_header.arm9_ram_address;
}

static ut64 boffset(RBinFile *bf) {
	return 0LL;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr9 = NULL, *ptr7 = NULL;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr9 = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}
	if (!(ptr7 = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		free (ptr9);
		return NULL;
	}

	ptr9->name = strdup ("arm9");
	ptr9->size = loaded_header.arm9_size;
	ptr9->vsize = loaded_header.arm9_size;
	ptr9->paddr = loaded_header.arm9_rom_offset;
	ptr9->vaddr = loaded_header.arm9_ram_address;
	ptr9->perm = r_str_rwx ("rwx");
	ptr9->add = true;
	r_list_append (ret, ptr9);

	ptr7->name = strdup ("arm7");
	ptr7->size = loaded_header.arm7_size;
	ptr7->vsize = loaded_header.arm7_size;
	ptr7->paddr = loaded_header.arm7_rom_offset;
	ptr7->vaddr = loaded_header.arm7_ram_address;
	ptr7->perm = r_str_rwx ("rwx");
	ptr7->add = true;
	r_list_append (ret, ptr7);

	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	RBinAddr *ptr9 = NULL, *ptr7 = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr9 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			return NULL;
		}
		if (!(ptr7 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			free (ptr9);
			return NULL;
		}

		/* ARM9 entry point */
		ptr9->vaddr = loaded_header.arm9_entry_address;
		// ptr9->paddr = loaded_header.arm9_entry_address;
		r_list_append (ret, ptr9);

		/* ARM7 entry point */
		ptr7->vaddr = loaded_header.arm7_entry_address;
		// ptr7->paddr = loaded_header.arm7_entry_address;
		r_list_append (ret, ptr7);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->buf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		char *filepath = r_str_newf ("%.12s - %.4s",
			loaded_header.title, loaded_header.gamecode);
		ret->file = filepath;
		ret->type = strdup ("ROM");
		ret->machine = strdup ("Nintendo DS");
		ret->os = strdup ("nds");
		ret->arch = strdup ("arm");
		ret->has_va = true;
		ret->bits = 32;
	}
	return ret;
}

RBinPlugin r_bin_plugin_ninds = {
	.name = "ninds",
	.desc = "Nintendo DS format r_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.boffset = &boffset,
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
