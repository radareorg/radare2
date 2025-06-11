/* radare - LGPL - 2015-2022 - pancake */

#include <r_bin.h>

#if 0
Start	End	Length	Description
0x0	0x3	4	File offset to start of Text0
0x04	0x1b	24	File offsets for Text1..6
0x1c	0x47	44	File offsets for Data0..10
0x48	0x4B	4	Loading address for Text0
0x4C	0x8F	68	Loading addresses for Text1..6, Data0..10
0x90	0xD7	72	Section sizes for Text0..6, Data0..10
0xD8	0xDB	4	BSS address
0xDC	0xDF	4	BSS size
0xE0	0xE3	4	Entry point
0xE4	0xFF		padding
#endif

#define N_TEXT 7
#define N_DATA 11

R_PACKED (
typedef struct {
	ut32 text_paddr[N_TEXT];
	ut32 data_paddr[N_DATA];
	ut32 text_vaddr[N_TEXT];
	ut32 data_vaddr[N_DATA];
	ut32 text_size[N_TEXT];
	ut32 data_size[N_DATA];
	ut32 bss_addr;
	ut32 bss_size;
	ut32 entrypoint;
	ut32 padding[10];
	// 0x100 -- start of data section
}) DolHeader;

static bool check(RBinFile *bf, RBuffer *buf) {
	ut8 tmp[6];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	bool one = r == sizeof (tmp) && !memcmp (tmp, "\x00\x00\x01\x00\x00\x00", sizeof (tmp));
	if (one) {
		int r = r_buf_read_at (buf, 6, tmp, sizeof (tmp));
		if (r != 6) {
			return false;
		}
		return sizeof (tmp) && !memcmp (tmp, "\x00\x00\x00\x00\x00\x00", sizeof (tmp));
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	if (r_buf_size (buf) < sizeof (DolHeader)) {
		return false;
	}
	DolHeader *dol = R_NEW0 (DolHeader);
	char *lowername = strdup (bf->file);
	if (!lowername) {
		goto dol_err;
	}
	r_str_case (lowername, 0);
	char *ext = strstr (lowername, ".dol");
	if (!ext || ext[4] != 0) {
		goto lowername_err;
	}
	free (lowername);
	if (r_buf_fread_at (bf->buf, 0, (void *) dol, "67I", 1) < 1) {
		free (dol);
		return false;
	}
	bf->bo->bin_obj = dol;
	return true;

lowername_err:
	free (lowername);
dol_err:
	free (dol);
	return false;
}

static RList *sections(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	int i;
	RList *ret;
	RBinSection *s;
	DolHeader *dol = bf->bo->bin_obj;
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	/* text sections */
	for (i = 0; i < N_TEXT; i++) {
		if (!dol->text_paddr[i] || !dol->text_vaddr[i]) {
			continue;
		}
		s = R_NEW0 (RBinSection);
		s->name = r_str_newf ("text_%d", i);
		s->paddr = dol->text_paddr[i];
		s->vaddr = dol->text_vaddr[i];
		s->size = dol->text_size[i];
		s->vsize = s->size;
		s->perm = r_str_rwx ("r-x");
		s->add = true;
		r_list_append (ret, s);
	}
	/* data sections */
	for (i = 0; i < N_DATA; i++) {
		if (!dol->data_paddr[i] || !dol->data_vaddr[i]) {
			continue;
		}
		s = R_NEW0 (RBinSection);
		s->name = r_str_newf ("data_%d", i);
		s->paddr = dol->data_paddr[i];
		s->vaddr = dol->data_vaddr[i];
		s->size = dol->data_size[i];
		s->vsize = s->size;
		s->perm = r_str_rwx ("r--");
		s->add = true;
		r_list_append (ret, s);
	}
	/* bss section */
	s = R_NEW0 (RBinSection);
	s->name = strdup ("bss");
	s->paddr = 0;
	s->vaddr = dol->bss_addr;
	s->size = dol->bss_size;
	s->vsize = s->size;
	s->perm = r_str_rwx ("rw-");
	s->add = true;
	r_list_append (ret, s);

	return ret;
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RList *ret = r_list_new ();
	RBinAddr *addr = R_NEW0 (RBinAddr);
	DolHeader *dol = bf->bo->bin_obj;
	addr->vaddr = (ut64) dol->entrypoint;
	addr->paddr = addr->vaddr & 0xFFFF;
	r_list_append (ret, addr);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->buf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->big_endian = true;
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Nintendo Wii");
	ret->os = strdup ("wii-ios");
	ret->arch = strdup ("ppc");
	ret->has_va = true;
	ret->bits = 32;
	ret->cpu = strdup ("ps");

	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0x80b00000; // XXX
}

RBinPlugin r_bin_plugin_dol = {
	.meta = {
		.name = "dol",
		.author = "pancake",
		.desc = "Nintendo Dolphin Wii executables",
		.license = "BSD-3-Clause",
	},
	.weak_guess = true,
	.load = &load,
	.baddr = &baddr,
	.check = &check,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dol,
	.version = R2_VERSION
};
#endif
