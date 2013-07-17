/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static int load(RBinArch *arch) {
	if(!(arch->bin_obj = PE_(r_bin_pe_new_buf) (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	PE_(r_bin_pe_free) ((struct PE_(r_bin_pe_obj_t)*)arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return PE_(r_bin_pe_get_image_base) (arch->bin_obj);
}

static RBinAddr* binsym(RBinArch *arch, int type) {
	RBinAddr *ret = NULL;
	switch (type) {
	case R_BIN_SYM_MAIN:
		if (!(ret = R_NEW (RBinAddr)))
			return NULL;
		memset (ret, '\0', sizeof (RBinAddr));
		ret->offset = ret->rva = PE_(r_bin_pe_get_main_offset) (arch->bin_obj);
		break;
	}
	return ret;
}

static RList* entries(RBinArch *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;
	struct r_bin_pe_addr_t *entry = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(entry = PE_(r_bin_pe_get_entrypoint) (arch->bin_obj)))
		return ret;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->offset = entry->offset;
		ptr->rva = entry->rva;
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_pe_section_t *sections = NULL;
	int i;
	
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(sections = PE_(r_bin_pe_get_sections)(arch->bin_obj)))
		return NULL;
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection)))
			break;
		strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->offset = sections[i].offset;
		ptr->rva = sections[i].rva;
		ptr->srwx = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].flags))
			ptr->srwx |= 0x1;
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].flags))
			ptr->srwx |= 0x2;
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].flags))
			ptr->srwx |= 0x4;
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].flags))
			ptr->srwx |= 0x8;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(symbols = PE_(r_bin_pe_get_exports)(arch->bin_obj)))
		return ret;
	for (i = 0; !symbols[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, (char*)symbols[i].forwarder, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS); //XXX Get the right type 
		ptr->size = 0;
		ptr->rva = symbols[i].rva;
		ptr->offset = symbols[i].offset;
		ptr->ordinal = symbols[i].ordinal;
		r_list_append (ret, ptr);
	}
	free (symbols);
	return ret;
}

static RList* imports(RBinArch *arch) {
	RList *ret = NULL, *relocs = NULL;
	RBinImport *ptr = NULL;
	RBinReloc *rel = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!(ret = r_list_new ()) || !(relocs = r_list_new ()))
		return NULL;

	ret->free = free;
	relocs->free = free;

	((struct PE_(r_bin_pe_obj_t)*)arch->bin_obj)->relocs = relocs;

	if (!(imports = PE_(r_bin_pe_get_imports)(arch->bin_obj)))
		return ret;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;

		strncpy (ptr->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->ordinal = imports[i].ordinal;
		// NOTE(eddyb) a PE hint is just an optional possible DLL export table
		// index for the import. There is no point in exposing it.
		//ptr->hint = imports[i].hint;
		r_list_append (ret, ptr);

		if (!(rel = R_NEW (RBinReloc)))
			break;
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		rel->rva = imports[i].rva;
		rel->offset = imports[i].offset;
		r_list_append (relocs, rel);
	}
	free (imports);

	return ret;
}

static RList* relocs(RBinArch *arch) {
	return ((struct PE_(r_bin_pe_obj_t)*)arch->bin_obj)->relocs;
}

static RList* libs(RBinArch *arch) {
	RList *ret = NULL;
	char *ptr = NULL;
	struct r_bin_pe_lib_t *libs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = PE_(r_bin_pe_get_libs)(arch->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	char *str;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_class) (arch->bin_obj))) {
		strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy (ret->rclass, "pe", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_os) (arch->bin_obj))) {
		strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_arch) (arch->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_machine) (arch->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_subsystem) (arch->bin_obj))) {
		strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if (PE_(r_bin_pe_is_dll) (arch->bin_obj))
		strncpy (ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_STRINGS);
	else strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->bits = PE_(r_bin_pe_get_bits) (arch->bin_obj);
	ret->big_endian = PE_(r_bin_pe_is_big_endian) (arch->bin_obj);
	ret->dbg_info = 0;
	ret->has_va = R_TRUE;
	if (!PE_(r_bin_pe_is_stripped_debug) (arch->bin_obj))
		ret->dbg_info |= 0x01;
	if (PE_(r_bin_pe_is_stripped_line_nums) (arch->bin_obj))
		ret->dbg_info |= 0x04;
	if (PE_(r_bin_pe_is_stripped_local_syms) (arch->bin_obj))
		ret->dbg_info |= 0x08;
	if (PE_(r_bin_pe_is_stripped_relocs) (arch->bin_obj))
		ret->dbg_info |= 0x10;
	return ret;
}

#if !R_BIN_PE64
static int check(RBinArch *arch) {
	int idx, ret = R_FALSE;
	if (!arch || !arch->buf || !arch->buf->buf)
		return R_FALSE;
	idx = (arch->buf->buf[0x3c]|(arch->buf->buf[0x3d]<<8));
	if (arch->buf->length>idx)
		if (!memcmp (arch->buf->buf, "\x4d\x5a", 2) &&
			!memcmp (arch->buf->buf+idx, "\x50\x45", 2) && 
			!memcmp (arch->buf->buf+idx+0x18, "\x0b\x01", 2))
			ret = R_TRUE;
	return ret;
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 hdrsize, p_start, p_opthdr, p_sections, p_lsrlc, n;
	ut32 baddr = 0x400000;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	B ("MZ\x00\x00", 4);
	B ("PE\x00\x00", 4);
	H (0x14c);
	H (1);
	D (0); // nothing
	p_start = 97; // HACK this is filesize

	D (0);
	D (0);
	p_lsrlc = buf->length;
	H (-1); // sections-opthdr
	H (0x103);
	// opthdr:
	p_opthdr = buf->length;
	H (0x10b);
	B ("\x08\x00", 2);
	p_sections = buf->length;
	n = p_sections-p_opthdr;
	W (p_lsrlc, &n, 4);
	// sections:
	D (R_ROUND (codelen, 4));
	D (0);
	D (codelen); // codesize
	D (p_start);
	D (codelen);
	D (p_start);
	D (baddr);
	D (4); // sect align
	D (4); // file align
	H (4);
	H (0);
	H (0);
	H (0);
	H (4);
	H (0);
	D (0);
	hdrsize = 100;
	D (R_ROUND (hdrsize, 4)+R_ROUND (codelen, 4));
	D (R_ROUND (hdrsize, 4));
	D (0);
	B ("\x02", 1);
	//hdrsize = filesize; // 97
	//printf ("FILESIZE = %d\n", buf->length);
	B (code, codelen);

	if (data && datalen>0) {
		//ut32 data_section = buf->length;
		eprintf ("Warning: DATA section not support for PE yet\n");
		B (data, datalen);
	}
	return buf;
}

struct r_bin_plugin_t r_bin_plugin_pe = {
	.name = "pe",
	.desc = "PE bin plugin",
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
	.libs = &libs,
	.relocs = &relocs,
	.meta = NULL,
	.write = NULL,
	.minstrlen = 4,
	.create = &create,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
#endif
