/* radare - LGPL - Copyright 2013-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static void destroy(RBinFile *bf) {
	r_buf_free (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("brainfuck");
	ret->bclass = strdup ("1.0");
	ret->rclass = strdup ("program");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("brainfuck");
	ret->arch = strdup ("bf");
	ret->has_va = 1;
	ret->bits = 32; // 16?
	ret->big_endian = 0;
	ret->dbg_info = 0;
	/* TODO: move this somewhere else */
	eprintf ("f input 128 0x3000\n");
	eprintf ("o malloc://128 0x3000\n");
	eprintf ("f screen 80*25 0x4000\n");
	eprintf ("o malloc://80*25 0x4000\n");
	eprintf ("f stack 0x200 0x5000\n");
	eprintf ("o malloc://0x200 0x5000\n");
	eprintf ("f data 0x1000 0x6000\n");
	eprintf ("o malloc://0x1000 0x6000\n");
	eprintf ("ar\n"); // hack to init
	eprintf ("ar brk=stack\n");
	eprintf ("ar scr=screen\n");
	eprintf ("ar kbd=input\n");
	eprintf ("ar ptr=data\n");
	eprintf ("\"e cmd.vprompt=pxa 32@stack;pxa 32@screen;pxa 32@data\"\n");
	eprintf ("s 0\n");
	eprintf ("e asm.bits=32\n");
	eprintf ("dL bf\n");
	return ret;
}

static bool check_buffer(RBuffer *buf) {
	r_return_val_if_fail (buf, false);

	ut8 tmp[16];
	int read_length = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	if (read_length <= 0) {
		return false;
	}

	const ut8 *p = (const ut8 *)tmp;
	int i;
	for (i = 0; i < read_length; i++) {
		switch (p[i]) {
		case '+':
		case '-':
		case '>':
		case '<':
		case '[':
		case ']':
		case ',':
		case '.':
		case ' ':
		case '\n':
		case '\r':
			break;
		default:
			return false;
		}
	}
	return true;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = ptr->vaddr = 0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bf,
	.version = R2_VERSION
};
#endif
