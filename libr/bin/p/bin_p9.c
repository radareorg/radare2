/* radare2 - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/p9/p9bin.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 4)
		return (r_bin_p9_get_arch (buf, NULL, NULL));
	return R_FALSE;
}

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void*)(size_t)check_bytes (buf, sz);
}

static int load(RBinFile *arch) {
	return check(arch);
}

static int destroy (RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0x1000000; // XXX
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static RList* entries(RBinFile *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->paddr = 8*4;
		ptr->vaddr = 8*4;// + baddr (arch);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ut64 textsize, datasize, symssize, spszsize, pcszsize;
	int big_endian = arch->o->info->big_endian;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	// add text segment
	textsize = r_mem_get_num (arch->buf->buf+4, 4, big_endian);
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "text", R_BIN_SIZEOF_STRINGS);
	ptr->size = textsize;
	ptr->vsize = textsize + (textsize%4096);
	ptr->paddr = 8*4;
	ptr->vaddr = ptr->paddr;
	ptr->srwx = 5; // r-x
	r_list_append (ret, ptr);
	// add data segment
	datasize = r_mem_get_num (arch->buf->buf+8, 4, big_endian);
	if (datasize>0) {
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "data", R_BIN_SIZEOF_STRINGS);
		ptr->size = datasize;
		ptr->vsize = datasize + (datasize%4096);
		ptr->paddr = textsize+(8*4);
		ptr->vaddr = ptr->paddr;
		ptr->srwx = 6; // rw-
		r_list_append (ret, ptr);
	}
	// ignore bss or what
	// add syms segment
	symssize = r_mem_get_num (arch->buf->buf+16, 4, big_endian);
	if (symssize) {
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "syms", R_BIN_SIZEOF_STRINGS);
		ptr->size = symssize;
		ptr->vsize = symssize + (symssize%4096);
		ptr->paddr = datasize+textsize+(8*4);
		ptr->vaddr = ptr->paddr;
		ptr->srwx = 4; // r--
		r_list_append (ret, ptr);
	}
	// add spsz segment
	spszsize = r_mem_get_num (arch->buf->buf+24, 4, big_endian);
	if (spszsize) {
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "spsz", R_BIN_SIZEOF_STRINGS);
		ptr->size = spszsize;
		ptr->vsize = spszsize + (spszsize%4096);
		ptr->paddr = symssize+datasize+textsize+(8*4);
		ptr->vaddr = ptr->paddr;
		ptr->srwx = 4; // r--
		r_list_append (ret, ptr);
	}
	// add pcsz segment
	pcszsize = r_mem_get_num (arch->buf->buf+24, 4, big_endian);
	if (pcszsize) {
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "pcsz", R_BIN_SIZEOF_STRINGS);
		ptr->size = pcszsize;
		ptr->vsize = pcszsize + (pcszsize%4096);
		ptr->paddr = spszsize+symssize+datasize+textsize+(8*4);
		ptr->vaddr = ptr->paddr;
		ptr->srwx = 4; // r--
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* symbols(RBinFile *arch) {
	// TODO: parse symbol table
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
	RBinInfo *ret = NULL;
	int big_endian = 0;
	int bits = 32;
	int bina;

	if (!(bina = r_bin_p9_get_arch (arch->buf->buf, &bits, &big_endian)))
		return NULL;
	if ((ret = R_NEW0 (RBinInfo)) == NULL)
		return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "program", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "p9", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "plan9", R_BIN_SIZEOF_STRINGS);
	archstr = r_sys_arch_str (bina);
	strncpy (ret->arch, archstr, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, archstr, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "plan9", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->bits = bits;
	ret->has_va = R_TRUE;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static int size(RBinFile *arch) {
	ut64 text, data, syms, spsz;
	int big_endian;
	if (!arch->o->info)
		arch->o->info = info (arch);
	big_endian = arch->o->info->big_endian;
	// TODO: reuse section list
	text = r_mem_get_num (arch->buf->buf+4, 4, big_endian);
	data = r_mem_get_num (arch->buf->buf+8, 4, big_endian);
	syms = r_mem_get_num (arch->buf->buf+16, 4, big_endian);
	spsz = r_mem_get_num (arch->buf->buf+24, 4, big_endian);
	return text+data+syms+spsz+(6*4);
}

#if !R_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBuffer *buf = r_buf_new ();
#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
	D (I_MAGIC); // i386 only atm
	D (codelen);
	D (datalen);
	D (4096); // bss
	D (0); // syms
	D (8*4); // entry
	D (4096); // spsz
	D (4096); // pcsz
	B (code, codelen);
	if (datalen>0)
		B (data, datalen);
	return buf;
}

struct r_bin_plugin_t r_bin_plugin_p9 = {
	.name = "p9",
	.desc = "Plan9 bin plugin",
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
	.binsym = &binsym,
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
#endif
