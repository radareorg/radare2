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
	unsigned short reloc_table_paddr;
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
	unsigned short paddr;
	unsigned short segment;
};

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int load(RBinFile *arch) {
	// parse stuff
	return R_TRUE;
}

static int destroy (RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0; // XXX
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	return NULL;
}

static RList* entries(RBinFile *arch) {
	ut64 off = 0LL;
	RList* ret;
	RBinAddr *ptr = NULL;
	struct EXE *exe = (struct EXE*) arch->buf->buf;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	off = (exe->cs << 4) + exe->ip;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->paddr = off;
		ptr->vaddr = off;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct EXE *exe = (struct EXE*) arch->buf->buf;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free; // r_bin-section_free

	ptr = R_NEW0 (RBinSection);
	strncpy (ptr->name, ".text", R_BIN_SIZEOF_STRINGS);
	ptr->paddr = exe->header_paragraphs * 16L;
	ptr->size = arch->buf->length - ptr->paddr;
	ptr->vsize = ptr->size;
	ptr->vaddr = exe->header_paragraphs * 16L;
	ptr->srwx = r_str_rwx ("rwx");
	if (ptr->size <1) {
		eprintf ("Invalid section size\n");
		free (ptr);
	} else r_list_append (ret, ptr);
#if 0
	//--
	ptr = R_NEW (RBinSection);
	strncpy (ptr->name, ".text", R_BIN_SIZEOF_STRINGS);
	ptr->size = 100;
	ptr->vsize = 100;
	ptr->paddr = 100;
	ptr->vaddr = 0;
	ptr->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr);
	//--
	ptr = R_NEW (RBinSection);
	strncpy (ptr->name, ".data", R_BIN_SIZEOF_STRINGS);
	ptr->size = 100;
	ptr->vsize = 100;
	ptr->paddr = exe->header_paragraphs * 16L;
	ptr->vaddr = 0;
	ptr->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr);
#endif
	return ret;
}

static RList* symbols(RBinFile *arch) {
	return NULL;
}

static RList* imports(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	struct EXE *exe = (struct EXE*) arch->buf->buf;
	RBinInfo *ret = NULL;

	sdb_num_set (arch->sdb, "ss", exe->ss, 0);
	sdb_num_set (arch->sdb, "sp", exe->sp, 0);
	sdb_num_set (arch->sdb, "ip", exe->ip, 0);
	sdb_num_set (arch->sdb, "cs", exe->cs, 0);
	sdb_num_set (arch->sdb, "mz.relocs.count", exe->num_relocs, 0);
	sdb_num_set (arch->sdb, "mz.relocs.paddr", exe->reloc_table_paddr, 0);
	sdb_num_set (arch->sdb, "mz.checksum", exe->checksum, 0);

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

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

/*
	- MZ at paddr 0
	- no PE at paddr stored at 0x3C
*/
static int check_bytes(const ut8 *buf, ut64 length) {
	int idx;
	if (!buf)
		return R_FALSE;

	if (length <= 0x3d || buf[0] != 'M' || buf[1] != 'Z')
		return R_FALSE;

	idx = (buf[0x3c] | (buf[0x3d] << 8));
	if (length > idx && buf[idx] == 'P' && buf[idx+1] == 'E')
		return R_FALSE;

	return R_TRUE;
}

RBinPlugin r_bin_plugin_mz = {
	.name = "mz",
	.desc = "MZ bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = NULL,
	.load = &load,	//.load_bytes = &load_bytes,
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
	.libs = NULL,
	.relocs = NULL,
	.dbginfo = NULL,
	.write = NULL,
	.create = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mz
};
#endif
