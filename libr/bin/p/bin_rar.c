/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define RARVMHDR "\x52\x61\x72\x21\x1a\x07\x00\xf9\x4e\x73\x00\x00\x0e\x00\x00\x00"

static int check(RBinFile *arch) {
	if (arch && arch->buf && arch->buf->buf)
		if (!memcmp (arch->buf->buf, RARVMHDR, 16))
			return R_TRUE;
	return R_FALSE;
}

static int load(RBinFile *arch) {
	return check (arch);
}

static int destroy (RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RList* entries(RBinFile *arch) {
	RList* ret = r_list_new ();;
	RBinAddr *ptr = NULL;
	if (!ret) return NULL;
	ret->free = free;
	if (!memcmp (arch->buf+0x30, "\x00\x00\x00\x00\x20\x73\x74\x64\x6f\x75\x74\x20\x21\x55\x0c\xcd", 16)) {
		if ((ptr = R_NEW (RBinAddr))) {
			ptr->rva = ptr->offset = 0x9a;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	// TODO: return NULL here?
	if (memcmp (arch->buf+0x30,
	"\x00\x00\x00\x00\x20\x73\x74\x64\x6f\x75\x74\x20\x21\x55\x0c\xcd", 16))
		return ret;

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "header", R_BIN_SIZEOF_STRINGS);
	ptr->size =
	ptr->vsize = 0x9a;
	ptr->offset = 0;
	ptr->rva = ptr->offset;
	ptr->srwx = 4; // r--
	r_list_append (ret, ptr);

	/* rarvm code */
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "rarvm", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = ptr->size = arch->buf->length - 0x9a;
	ptr->rva = ptr->offset = 0x9a;
	ptr->srwx = 5; // rw-
	r_list_append (ret, ptr);
	return ret;
}

static RList* symbols(RBinFile *arch) {
	return NULL;
}

static RList* imports(RBinFile *arch) {
	return NULL;
}

static RList* libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	const char *archstr;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	int bits = 32;

	if (!ret) return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "rar", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "rar", R_BIN_SIZEOF_STRINGS);
	archstr = "rar";
	strncpy (ret->arch, archstr, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, archstr, R_BIN_SIZEOF_STRINGS);
	if (!memcmp (arch->buf+0x30, "\x00\x00\x00\x00\x20\x73\x74\x64\x6f\x75\x74\x20\x21\x55\x0c\xcd", 16)) {
		strncpy (ret->subsystem, "rarvm", R_BIN_SIZEOF_STRINGS);
		strncpy (ret->bclass, "program", R_BIN_SIZEOF_STRINGS);
		strncpy (ret->type, "EXEC (Compressed executable)", R_BIN_SIZEOF_STRINGS);
	} else {
		strncpy (ret->subsystem, "archive", R_BIN_SIZEOF_STRINGS);
		strncpy (ret->bclass, "archive", R_BIN_SIZEOF_STRINGS);
		strncpy (ret->type, "ARCHIVE (Compressed archive)", R_BIN_SIZEOF_STRINGS);
	}
// TODO: specify if its compressed or executable
	ret->bits = bits;
	ret->has_va = R_TRUE;
	ret->big_endian = R_TRUE;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static int size(RBinFile *arch) {
	// TODO: walk rar structures and guess size here...
	return 0x9a+128; // XXX
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBuffer *buf = r_buf_new ();
	return buf;
}

RBinPlugin r_bin_plugin_rar = {
	.name = "rar",
	.desc = "rarvm bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.size = &size,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = NULL,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = NULL,
	.dbginfo = NULL,
	.write = NULL,
	.create = &create,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
