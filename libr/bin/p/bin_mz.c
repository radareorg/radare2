/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#if 0
- header
- relocs
- code
#endif

struct EXE {
	unsigned short signature; /* == 0x5a4D */
	unsigned short bytes_in_last_block;
	unsigned short blocks_in_file;
	unsigned short num_relocs;
	unsigned short header_paragraphs;
	unsigned short min_extra_paragraphs;
	unsigned short max_extra_paragraphs;
	unsigned short ss;
	unsigned short sp;
	unsigned short checksum;
	unsigned short ip;
	unsigned short cs;
	unsigned short reloc_table_offset;
	unsigned short overlay_number;
};

#if 0
// begin
exe_data_start = exe.header_paragraphs * 16L;
// end
extra_data_start = exe.blocks_in_file * 512L;
if (exe.bytes_in_last_block)
	extra_data_start -= (512 - exe.bytes_in_last_block);
#endif

struct EXE_RELOC {
	unsigned short offset;
	unsigned short segment;
};


static int load(RBinArch *arch) {
	// parse stuff 
	return R_TRUE;
}

static int destroy (RBinArch *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return 0; // XXX
}

static RBinAddr* binsym(RBinArch *arch, int type) {
	return NULL;
}

static RList* entries(RBinArch *arch) {
	ut64 off = 0LL;
	RList* ret;
	RBinAddr *ptr = NULL;
	struct EXE *exe = (struct EXE*) arch->buf->buf;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	off = exe->header_paragraphs * 16L;
	off += exe->ip; // XXX
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->offset = off;
		ptr->rva = off;
		r_list_append (ret, ptr);
	}
	
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct EXE *exe = (struct EXE*) arch->buf->buf;
	
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free; // r_bin-section_free

	ptr = R_NEW0 (RBinSection);
	strncpy (ptr->name, ".text", R_BIN_SIZEOF_STRINGS);
	ptr->offset = exe->header_paragraphs * 16L;
	ptr->size = arch->buf->length - ptr->offset;
	ptr->vsize = ptr->size;
	ptr->rva = exe->header_paragraphs * 16L;
	ptr->srwx = r_str_rwx ("rwx");
	if (ptr->size <1) {
		eprintf ("Invalid section size\n");
	} else r_list_append (ret, ptr);
#if 0
	//--
	ptr = R_NEW (RBinSection);
	strncpy (ptr->name, ".text", R_BIN_SIZEOF_STRINGS);
	ptr->size = 100;
	ptr->vsize = 100;
	ptr->offset = 100;
	ptr->rva = 0;
	ptr->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr);
	//--
	ptr = R_NEW (RBinSection);
	strncpy (ptr->name, ".data", R_BIN_SIZEOF_STRINGS);
	ptr->size = 100;
	ptr->vsize = 100;
	ptr->offset = exe->header_paragraphs * 16L;
	ptr->rva = 0;
	ptr->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr);
#endif
	return ret;
}

static RList* symbols(RBinArch *arch) {
	return NULL;
}

static RList* imports(RBinArch *arch) {
	return NULL;
}

static RBinInfo* info(RBinArch *arch) {
	struct EXE *exe = (struct EXE*) arch->buf->buf;
	RBinInfo *ret = NULL;

	// TODO: remove those strings
	eprintf ("SS : %x\n", exe->ss);
	eprintf ("SP : %x\n", exe->sp);
	eprintf ("IP : %x\n", exe->ip);
	eprintf ("CS : %x\n", exe->cs);
	eprintf ("NRELOCS: %x\n", exe->num_relocs);
	eprintf ("RELOC  : %x\n", exe->reloc_table_offset);
	eprintf ("CHKSUM : %x\n", exe->checksum);
	if ((ret = R_NEW0 (RBinInfo)) == NULL)
		return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "mz", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "DOS", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "pc", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "DOS", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->has_va = R_TRUE;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinArch *arch) {
	int idx, ret = R_TRUE;
	const ut8 *b;
	if (!arch || !arch->buf || !arch->buf->buf)
		return R_FALSE;
	b = arch->buf->buf;
	if (b[0]=='M' && b[1]=='Z' && arch->buf->length>0x3d) {
		idx = (b[0x3c]|(b[0x3d]<<8));
		if (arch->buf->length>idx)
			if (!memcmp (b+idx, "\x50\x45", 2))
				ret = R_FALSE;
	} else ret = R_FALSE;
	return ret;
}

RBinPlugin r_bin_plugin_mz = {
	.name = "mz",
	.desc = "MZ bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
	.create = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mz
};
#endif
