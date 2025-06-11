/* radare - MIT - 2021-2024 - pancake */

#include <r_bin.h>

#if 0
https://es.wikipedia.org/wiki/Amiga_Hunk
http://amiga-dev.wikidot.com/file-format:hunk
https://retro-commodore.eu/files/downloads/amigamanuals-xiik.net/eBooks/AmigaDOS%20Technical%20Reference%20Manual%20-%20eBook-ENG.pdf
#endif

#define HUNK_HEADER "\x00\x00\x03\xf3"
#define HUNK_CODE "\x00\x00\x03\xe9"

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		return (!memcmp (buf, HUNK_HEADER, sizeof (buf)));
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return check (bf, buf);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("Hunk (Executable file)");
	ret->machine = strdup ("Amiga");
	ret->os = strdup ("AmigaOS");
	ret->arch = strdup ("m68k");
	ret->bits = 32;
	ret->has_va = 1;
	ret->big_endian = true;
	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = r_list_new ();
	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("HUNK_HEADER");
	ptr->paddr = 0;
	ptr->size = r_buf_size (bf->buf);
	ptr->vaddr = 0;
	ptr->vsize = ptr->size;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *bf) {
	RList *ret;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	RBinAddr *ptr = NULL;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	int addr;
	ut8 b[1024];
	int last = r_buf_read_at (bf->buf, 0, b, sizeof (b)) - 4;
	for (addr = 0x18; addr <= last; addr += 4) {
		if (!memcmp (b + addr, HUNK_CODE, 4)) {
			ptr->paddr = addr + 8;
			ptr->vaddr = addr + 8;
			r_list_append (ret, ptr);
			return ret;
		}
	}
	R_LOG_ERROR ("Cannot determine entrypoint, cannot find HUNK_CODE");
	return ret;
}

RBinPlugin r_bin_plugin_hunk = {
	.meta = {
		.name = "hunk",
		.version = "1.0",
		.author = "pancake",
		.desc = "AmigaOS Hunk Executable",
		.license = "MIT",
	},
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections = sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_hunk,
	.version = R2_VERSION
};
#endif
