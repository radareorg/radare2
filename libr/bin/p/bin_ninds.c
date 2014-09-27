/* radare - LGPL - 2014 - a0rtega */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>

#include "../format/nin/nds.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static struct nds_hdr loaded_header;

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	ut8 ninlogohead[6];
	if (!buf || length < sizeof(struct nds_hdr)) /* header size */
		return R_FALSE;
	memcpy(ninlogohead, buf+0xc0, 6);
	/* begin of nintendo logo =    \x24\xff\xae\x51\x69\x9a */
	return (!memcmp (ninlogohead, "\x24\xff\xae\x51\x69\x9a", 6))? R_TRUE : R_FALSE;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return memcpy (&loaded_header, buf, sizeof(struct nds_hdr));
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o)
		return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return (ut64) loaded_header.arm9_ram_address;
}

static ut64 boffset(RBinFile *arch) {
	return 0LL;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr9 = NULL, *ptr7 = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	if (!(ptr9 = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}
	if (!(ptr7 = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		free (ptr9);
		return NULL;
	}

	strncpy (ptr9->name, "arm9", 4);
	ptr9->size = loaded_header.arm9_size;
	ptr9->vsize = loaded_header.arm9_size;
	ptr9->paddr = loaded_header.arm9_rom_offset;
	ptr9->vaddr = loaded_header.arm9_ram_address;
	ptr9->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr9);

	strncpy (ptr7->name, "arm7", 4);
	ptr7->size = loaded_header.arm7_size;
	ptr7->vsize = loaded_header.arm7_size;
	ptr7->paddr = loaded_header.arm7_rom_offset;
	ptr7->vaddr = loaded_header.arm7_ram_address;
	ptr7->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr7);

	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret = r_list_new ();
	RBinAddr *ptr9 = NULL, *ptr7 = NULL;

	if (arch && arch->buf) {
		if (!ret)
			return NULL;
		ret->free = free;
		if (!(ptr9 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			return NULL;
		}
		if (!(ptr7 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			free (ptr9);
			return NULL;
		}

		/* ARM9 entry point */
		ptr9->vaddr = loaded_header.arm9_entry_address;
		//ptr9->paddr = loaded_header.arm9_entry_address;
		r_list_append (ret, ptr9);

		/* ARM7 entry point */
		ptr7->vaddr = loaded_header.arm7_entry_address;
		//ptr7->paddr = loaded_header.arm7_entry_address;
		r_list_append (ret, ptr7);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {

	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	strncpy(ret->file, (char *) loaded_header.title, 0xC);
	strncat(ret->file, " - ", 3);
	strncat(ret->file, (char *) loaded_header.gamecode, 0x4);
	strncpy (ret->type, "ROM", sizeof (ret->type)-1);
	strncpy (ret->machine, "Nintendo DS", sizeof (ret->machine)-1);
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strcpy (ret->arch, "arm");
	ret->has_va = R_TRUE;
	ret->bits = 32;

	return ret;
}

struct r_bin_plugin_t r_bin_plugin_ninds = {
	.name = "ninds",
	.desc = "Nintendo DS format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = NULL,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = NULL,
	.entries = &entries,
	.sections = &sections,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ninds
};
#endif

