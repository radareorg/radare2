/* radare - GPL - 2013 - condret@runas-racer.com */


#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static int check(RBinArch *arch);

static int load(RBinArch *arch) {
	if(check(arch)) return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinArch *arch) {
	if (arch->buf) r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return 0LL;
}

static RList* entries(RBinArch *arch) {
	RList *ret = r_list_new ();
	RBinAddr *ptr = NULL;
	ut8 init_jmp[4];

	if (arch && arch->buf == NULL){
		r_buf_read_at(arch->buf,0x100,init_jmp,4);

			if (!ret) return NULL;

			ret->free = free;
			if (!(ptr = R_NEW (RBinAddr)))
				return ret;

			memset (ptr, '\0', sizeof (RBinAddr));
			if (!init_jmp[1]==0xc3){						/* Function for this? */
				ptr->offset = ptr->rva = 0x100;
			} else {
				ptr->offset = ptr->rva = init_jmp[3]*0x100+init_jmp[2];
			}

		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinArch *arch){
	ut8 banks;
	RList *ret = r_list_new();
	RBinSection *rombank0 = NULL;

	if (!ret ) return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	} 

	ret->free = free;

	rombank0 = R_NEW0 (RBinSection);
	strncpy (rombank0->name, "rombank0", R_BIN_SIZEOF_STRINGS);

	r_buf_read_at (arch->buf,0x147,&banks,1);

	rombank0->offset = 0;
	rombank0->size = 0x4000;
	rombank0->vsize = 0x4000;
	rombank0->rva = 0;
	rombank0->srwx = r_str_rwx("rx");

	r_list_append(ret,rombank0);

	if(banks==GB_ROM){						/* TODO(for condret): Function + switch + Ram Banks + Moar Banks!!! */
		RBinSection *rombank1 = NULL;
		rombank1 = R_NEW0 (RBinSection);
		strncpy(rombank1->name, "rombank1", R_BIN_SIZEOF_STRINGS);
		rombank1->offset = 0x4000;
		rombank1->size = 0x4000;
		rombank1->vsize = 0x4000;
		rombank1->rva = 0x4000;
		rombank1->srwx = r_str_rwx("rx");
		r_list_append(ret,rombank1);
	}
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	ut8 rom_header[76];
	RBinInfo *ret = R_NEW (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	memset (ret, '\0', sizeof (RBinInfo));
	ret->lang = NULL;
	r_buf_read_at (arch->buf,0x104,rom_header,76);
	strncpy (ret->file, &rom_header[48], 16);
	gb_get_gbtype (ret->type,rom_header[66],rom_header[63]);
	gb_add_cardtype (ret->type,rom_header[67]);			// XXX
	strncpy (ret->machine, "Gameboy", sizeof (ret->machine)-1);
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strcpy (ret->arch, "gb");
	ret->has_va = 1;
	ret->bits = 8;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static int check(RBinArch *arch) {
	ut8 lict[48];

	if (!arch || !arch->buf)
		return 0;

	r_buf_read_at (arch->buf,0x104,lict,48);

	if ( !memcmp (lict,lic,48))
		return 1;

	return 0;
}



struct r_bin_plugin_t r_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Gameboy format r_bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
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
	.meta = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningb
};
#endif
