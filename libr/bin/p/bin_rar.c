/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define RAR_CONST "\x00\x00\x00\x00\x20\x73\x74\x64\x6f\x75\x74\x20\x21\x55\x0c\xcd"
#define RARVMHDR "\x52\x61\x72\x21\x1a\x07\x00\xf9\x4e\x73\x00\x00\x0e\x00\x00\x00"

typedef struct r_bin_obj_rar_t {
	RBuffer *buf;
	ut64 loadaddr;
	Sdb *kv;
} RRarBinObj;

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 16)
		if (!memcmp (buf, RARVMHDR, 16))
			return R_TRUE;
	return R_FALSE;
}

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	struct r_bin_obj_rar_t *bin = (struct r_bin_obj_rar_t *) o->bin_obj;
	if (bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	RBuffer *tbuf = NULL;
	RRarBinObj *res = NULL;

	if (!buf || sz == 0 || sz == UT64_MAX) return NULL;

	res = R_NEW0 (RRarBinObj);
	tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	res->buf = tbuf;
	res->kv = sdb;
	res->loadaddr = loadaddr;
	return res;
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
	RRarBinObj *bin_obj = arch && arch->o ? arch->o->bin_obj : NULL;
	const ut8 *buf = bin_obj ? r_buf_buffer (bin_obj->buf) : NULL;
	ut64 sz = arch && bin_obj ? r_buf_size (bin_obj->buf) : 0;

	if (!ret) return NULL;
	ret->free = free;
	if (bin_obj && sz > 0x30 && !memcmp (buf+0x30, RAR_CONST, 16)) {
		if ((ptr = R_NEW (RBinAddr))) {
			ptr->vaddr = ptr->paddr = 0x9a;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RRarBinObj *bin_obj = arch && arch->o ? arch->o->bin_obj : NULL;
	const ut8 *buf = bin_obj ? r_buf_buffer (bin_obj->buf) : NULL;
	ut64 sz = 0;
	if (bin_obj)
		sz = r_buf_size (bin_obj->buf);

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	// TODO: return NULL here?
	if (!buf || sz < 0x30 || memcmp (buf+0x30, RAR_CONST, 16))
		return ret;

	// add text segment
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "header", R_BIN_SIZEOF_STRINGS);
	ptr->size = ptr->vsize = 0x9a;
	ptr->paddr = 0;
	ptr->vaddr = ptr->paddr;
	ptr->srwx = 4; // r--
	r_list_append (ret, ptr);

	/* rarvm code */
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "rarvm", R_BIN_SIZEOF_STRINGS);
	ptr->vsize = ptr->size = sz - 0x9a;
	ptr->vaddr = ptr->paddr = 0x9a;
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
	RRarBinObj *bin_obj = arch && arch->o ? arch->o->bin_obj : NULL;
	const ut8 *buf = bin_obj ? r_buf_buffer (bin_obj->buf) : NULL;
	ut64 sz = arch && bin_obj ? r_buf_size (bin_obj->buf): 0;

	int bits = 32; // Default value

	if (!ret || !buf || sz < 0x30) return NULL;

	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "rar", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "rar", R_BIN_SIZEOF_STRINGS);
	archstr = "rar";
	strncpy (ret->arch, archstr, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, archstr, R_BIN_SIZEOF_STRINGS);
	if (!memcmp (buf+0x30, RAR_CONST, 16)) {
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
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.size = &size,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
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
