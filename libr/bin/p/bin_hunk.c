/* radare - MIT - 2021 - pancake */

#include <r_bin.h>
#include <r_lib.h>

#if 0
https://es.wikipedia.org/wiki/Amiga_Hunk
https://amiga-dev.wikidot.com/file-format:hunk
#endif

#define HUNK_MAGIC "\x00\x00\x03\xf3"

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		return (!memcmp (buf, HUNK_MAGIC, sizeof (buf)));
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (bf, buf);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Amiga");
	ret->os = strdup ("Workbench");
	ret->arch = strdup ("m68k");
	ret->cpu = strdup ("68040");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

#if 0
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
#endif

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
#if 0
	addsym (ret, "NMI_VECTOR_START_ADDRESS", NMI_VECTOR_START_ADDRESS,2);
#endif
	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("hunk");
	ptr->paddr = 0;
	ptr->size = r_buf_size (bf->buf);
	ptr->vaddr = 0;
	ptr->vsize = ptr->size;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *bf) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = 0x24;
	ptr->vaddr = 0x24;
	r_list_append (ret, ptr);
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	// having this we make r2 -B work, otherwise it doesnt works :??
	return 0;
}

RBinPlugin r_bin_plugin_hunk = {
	.name = "hunk",
	.desc = "AmigaOS Hunk executable binary",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.baddr = &baddr,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_hunk,
	.version = R2_VERSION
};
#endif
