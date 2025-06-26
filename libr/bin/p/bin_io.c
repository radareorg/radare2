/* radare - MIT - 2024-2025 - pancake */

// the info loaded here is never updated maybe we should have a way to refresh it
#include <r_bin.h>
#include <r_core.h>
#include <r_io.h>

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return true;
}

static char *iocmd(RBinFile *bf, const char *s) {
	RIO *io = R_UNWRAP3 (bf, rbin, iob.io);
	if (!io) {
		R_LOG_ERROR ("NO IO");
		return NULL;
	}
	char *res = r_io_system (io, s);
	if (!res) {
		RCore *core = io->coreb.core;
		RCons *cons = core->cons;
		const char *buffer = r_cons_get_buffer (cons, NULL);
		if (buffer != NULL) {
			res = strdup (buffer);
		}
	}
	return res;
}

static RBinInfo *info(RBinFile *bf) {
	free (iocmd (bf, "i"));
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("IO");
	ret->machine = strdup ("IO");
	ut8 tmp[32];
	r_buf_read_at (bf->buf, 0x100, tmp, sizeof (tmp));
	ret->bclass = r_str_ndup ((char *)tmp, 32);
	ret->os = strdup ("io");
	ret->arch = strdup ("arm");
	ret->bits = 64;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

#if 0
static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (R_LIKELY (ptr)) {
		ptr->name = r_bin_name_new (r_str_get (name));
		ptr->paddr = ptr->vaddr = addr;
		ptr->size = 0;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
}
#endif

static RList *symbols(RBinFile *bf) {
	free (iocmd (bf, "is"));
	RList *ret = r_list_newf (free);
#if 0
	addsym (ret, "rom_start", r_read_be32 (&hdr.RomStart));
#endif
	return ret;
}

static RList *sections(RBinFile *bf) {
	free (iocmd (bf, "iS"));
	RList *ret = r_list_new ();
#if 0
	RBinSection *ptr;
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("vtable");
	ptr->paddr = ptr->vaddr = 0;
	ptr->size = ptr->vsize = 0x100;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("header");
	ptr->paddr = ptr->vaddr = 0x100;
	ptr->size = ptr->vsize = sizeof (SMD_Header);
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->paddr = ptr->vaddr = 0x100 + sizeof (SMD_Header);
	{
		SMD_Header hdr = {{0}};
		r_buf_read_at (bf->buf, 0x100, (ut8*)&hdr, sizeof (hdr));
		ut64 baddr = r_read_be32 (&hdr.RomStart);
		ptr->vaddr += baddr;
	}
	ptr->size = ptr->vsize = r_buf_size (bf->buf) - ptr->paddr;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
#endif
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	char *res = iocmd (bf, "ie");
	if (res) {
		ut64 entry0 = r_num_get (NULL, res);
		free (res);
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		ptr->paddr = ptr->vaddr = entry0;
		r_list_append (ret, ptr);
	}
	return ret;
}

RBinPlugin r_bin_plugin_io = {
	.meta = {
		.name = "io",
		.author = "pancake",
		.desc = "Use IO plugins for RBin",
		.license = "MIT",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.minstrlen = 10,
	.strfilter = 'U'
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_io,
	.version = R2_VERSION
};
#endif

