/* radare - LGPL3 - 2021 - murphy */

#include <r_bin.h>
#include <r_lib.h>
#include "wad/wad.h"

static WAD_Hdr loaded_header;

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);
	ut8 sig[4];
	if (r_buf_read_at (b, 0, sig, sizeof (sig)) != 4) {
		return false;
	}
	if (memcmp (sig, "IWAD", 4) && memcmp (sig, "PWAD", 4)) {
		return false;
	}
	return true;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	if (r_buf_read_at (b, 0, (ut8*)&loaded_header, sizeof (loaded_header)) == sizeof (loaded_header)) {
		*bin_obj = &loaded_header;
		return true;
	}
	return false;
}

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail(bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("WAD");
	ret->machine = strdup ("DOOM Engine");
	ret->os = strdup ("DOOM Engine");
	ret->arch = strdup ("any");
	ret->bits = 32;
	ret->has_va = false;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	WAD_DIR_Entry dir;
	size_t i = 0;
	while (i < loaded_header.numlumps) {
		memset (&dir, 0, sizeof (dir));
		r_buf_read_at (bf->buf, loaded_header.diroffset + (i * 16), (ut8*)&dir, sizeof (dir));
		addsym (ret, strndup(dir.name, 8), dir.filepos, dir.size);
		i++;
	}
	return ret;
}

RBinPlugin r_bin_plugin_wad = {
	.name = "wad",
	.desc = "DOOM WAD format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = NULL,
	.entries = NULL,
	.sections = NULL,
	.symbols = &symbols,
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
	.baddr = &baddr,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wad,
	.version = R2_VERSION
};
#endif
