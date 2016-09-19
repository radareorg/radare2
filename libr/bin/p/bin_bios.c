/* radare - LGPL - Copyright 2013-2016 - pancake */

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

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	if (!check_bytes (buf, sz)) {
		return NULL;
	}
	return R_NOTNULL;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	//r_bin_bios_free ((struct r_bin_bios_obj_t*)arch->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = NULL;
	ret->file = arch->file? strdup (arch->file): NULL;
	ret->type = strdup ("bios");
	ret->bclass = strdup ("1.0");
	ret->rclass = strdup ("bios");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("pc");
	ret->arch = strdup ("x86");
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 0xffff && buf[0] != 0xcf) {
		const ut32 ep = length - 0x10000 + 0xfff0; /* F000:FFF0 address */
		/* hacky check to avoid detecting multidex bins as bios */
		/* need better fix for this */
		if (!memcmp (buf, "dex", 3)) {
			return 0;
		}
		/* Check if this a 'jmp' opcode */
		if ((buf[ep] == 0xea) || (buf[ep] == 0xe9)) {
			return 1;
		}
	}
	return 0;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	// program headers is another section
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "bootblk");
	ptr->vsize = ptr->size = 0x10000;
//printf ("SIZE %d\n", ptr->size);
	ptr->paddr = arch->buf->length - ptr->size;
	ptr->vaddr = 0xf0000;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE |
		R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = 0; //0x70000;
	ptr->vaddr = 0xffff0;
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_bios = {
	.name = "bios",
	.desc = "BIOS bin plugin",
	.license = "LGPL",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bios,
	.version = R2_VERSION
};
#endif
