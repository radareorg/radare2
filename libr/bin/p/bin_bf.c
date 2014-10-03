/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return R_NOTNULL;
}

static int load(RBinFile *arch) {
	return R_TRUE;
#if 0
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_bytes (bytes, sz);
#endif
}

static int destroy(RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RList *strings(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS-1);
	strncpy (ret->type, "brainfuck", sizeof (ret->type)-1); // asm.arch
	strncpy (ret->bclass, "1.0", sizeof (ret->bclass)-1);
	strncpy (ret->rclass, "program", sizeof (ret->rclass)-1); // file.type
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strncpy (ret->subsystem, "unknown", sizeof (ret->subsystem)-1);
	strncpy (ret->machine, "brainfuck", sizeof (ret->machine)-1);
	strcpy (ret->arch, "bf");
	ret->has_va = 1;
	ret->bits = 32; // 16?
	ret->big_endian = 0;
	ret->dbg_info = 0;
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
	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	int i, is_bf = 0;
	if (buf && length > 0) {
		int max = R_MIN (16, length);
		const char *p = (const char *)buf;
		is_bf = 1;
		for (i=0; i<max; i++) {
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
				is_bf = 0;
			}
		}
	}
	return is_bf;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = ptr->vaddr = 0;
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = entries,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = &strings,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.dbginfo = NULL,
	.write = NULL,
	.demangle_type = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bf
};
#endif
