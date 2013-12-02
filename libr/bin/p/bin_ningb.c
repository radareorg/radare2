/* radare - GPL - 2013 - condret@runas-racer.com */


#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static int check(RBinArch *arch) {
	ut8 lict[48];
	if (!arch || !arch->buf)
		return 0;
	r_buf_read_at (arch->buf, 0x104, lict,48);
	return (!memcmp (lict, lic, 48))? 1: 0;
}

static int load(RBinArch *arch) {
	if (check (arch)) return R_TRUE;
	return R_FALSE;
}

static int destroy(RBinArch *arch) {
	r_buf_free (arch->buf);
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

	if (arch && arch->buf != NULL) {
		r_buf_read_at (arch->buf, 0x100, init_jmp,4);
		if (!ret) {
			return NULL;
		}

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
	ut8 bank;
	int i;
	RList *ret = r_list_new();
	RBinSection *ram = NULL, *vram = NULL, *fram = NULL, *oam = NULL;					//Array for this

	r_buf_read_at(arch->buf,0x148,&bank,1);
	bank=gb_get_rombanks(bank);
	RBinSection *rombank[bank];

	if (!ret ) return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	ret->free = free;

	rombank[0] = R_NEW0 (RBinSection);
	rombank[1] = R_NEW0 (RBinSection);					//for(i=0;...)
	ram = R_NEW0 (RBinSection);
	vram = R_NEW0 (RBinSection);
	fram = R_NEW0 (RBinSection);
	oam = R_NEW0 (RBinSection);
	strncpy (rombank[0]->name, "rombank0", R_BIN_SIZEOF_STRINGS);
	strncpy (rombank[1]->name, "rombank1", R_BIN_SIZEOF_STRINGS);
	strncpy (vram->name, "vram", R_BIN_SIZEOF_STRINGS);
	strncpy (ram->name, "ram", R_BIN_SIZEOF_STRINGS);
	strncpy (oam->name, "oam", R_BIN_SIZEOF_STRINGS);
	strncpy (fram->name, "fram", R_BIN_SIZEOF_STRINGS);

	rombank[0]->offset = 0;
	rombank[0]->size = 0x4000;
	rombank[0]->vsize = 0x4000;
	rombank[0]->rva = 0;
	rombank[0]->srwx = r_str_rwx("rx");

	rombank[1]->offset = 0x4000;
	rombank[1]->size = 0x4000;
	rombank[1]->vsize = 0x4000;
	rombank[1]->rva = 0x4000;
	rombank[1]->srwx = r_str_rwx("rx");

	vram->offset = 0x8000;
	vram->size = 0x2000;
	vram->vsize = 0x2000;
	vram->rva = 0x8000;
	vram->srwx = r_str_rwx("rwx");

	ram->offset = 0xc000;
	ram->size = 0x2000;
	ram->vsize = 0x2000;
	ram->rva = 0xc000;
	ram->srwx = r_str_rwx("rwx");

	oam->offset = 0xFE00;
	oam->size = 0xA0;
	oam->vsize = 0xA0;
	oam->rva = 0xFE00;
	oam->srwx = r_str_rwx("rwx");

	fram->offset = 0xff80;
	fram->size = 0x80;
	fram->vsize = 0x80;
	fram->rva = 0xff80;
	fram->srwx = r_str_rwx("rwx");

	r_list_append(ret,rombank[0]);
	r_list_append(ret,rombank[1]);
	r_list_append(ret,vram);
	r_list_append(ret,ram);
	r_list_append(ret,oam);
	r_list_append(ret,fram);

	for (i=2;i<bank;i++) {
		rombank[i] = R_NEW0 (RBinSection);
		sprintf(rombank[i]->name,"rombank%i",i);
		rombank[i]->offset = rombank[i]->rva = 0x8000+i*0x4000;
		rombank[i]->size = rombank[i]->vsize = 0x4000;
		rombank[i]->srwx=r_str_rwx("rx");
		r_list_append(ret,rombank[i]);
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
