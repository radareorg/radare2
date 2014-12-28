/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	struct PE_(r_bin_pe_obj_t) *bin;
	if (!o || !o->bin_obj) return NULL;
	bin = (struct PE_(r_bin_pe_obj_t) *) o->bin_obj;
	if (bin && bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct PE_(r_bin_pe_obj_t) *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || sz == 0 || sz == UT64_MAX) return NULL;
	tbuf = r_buf_new();
	r_buf_set_bytes (tbuf, buf, sz);
	res = PE_(r_bin_pe_new_buf) (tbuf);
	if (res)
		sdb_ns_set (sdb, "info", res->kv);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	void *res;
	const ut8 *bytes;
	ut64 sz;

	if (!arch || !arch->o)
		return R_FALSE;

	bytes = r_buf_buffer (arch->buf);
	sz = r_buf_size (arch->buf);
	res = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);
 	arch->o->bin_obj = res;
	return res? R_TRUE: R_FALSE;
}

static int destroy(RBinFile *arch) {
	PE_(r_bin_pe_free) ((struct PE_(r_bin_pe_obj_t)*)arch->o->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return PE_(r_bin_pe_get_image_base) (arch->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	struct r_bin_pe_addr_t *peaddr = NULL;
	RBinAddr *ret = NULL;
	if (arch && arch->o && arch->o->bin_obj)
	switch (type) {
	case R_BIN_SYM_MAIN:
		peaddr = PE_(r_bin_pe_get_main_vaddr) (arch->o->bin_obj);
		break;
	}
	if (peaddr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = peaddr->paddr;
		ret->vaddr = peaddr->vaddr;
	}
	free (peaddr);
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList* ret;
	RBinAddr *ptr = NULL;
	struct r_bin_pe_addr_t *entry = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(entry = PE_(r_bin_pe_get_entrypoint) (arch->o->bin_obj)))
		return ret;
	if ((ptr = R_NEW (RBinAddr))) {
		ptr->paddr = entry->paddr;
		ptr->vaddr = entry->vaddr;
		r_list_append (ret, ptr);
	}
	free (entry);
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_pe_section_t *sections = NULL;
	ut64 ba = baddr (arch);
	int i;
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(sections = PE_(r_bin_pe_get_sections)(arch->o->bin_obj))){
		r_list_free (ret);
		return NULL;
	}
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection)))
			break;
		if (sections[i].name[0])
			strncpy (ptr->name, (char*)sections[i].name,
				R_BIN_SIZEOF_STRINGS);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr + ba;
		ptr->srwx = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_EXECUTABLE;
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_WRITABLE;
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_READABLE;
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].flags))
			ptr->srwx |= R_BIN_SCN_SHAREABLE;
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static RList* symbols(RBinFile *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((symbols = PE_(r_bin_pe_get_exports)(arch->o->bin_obj))) {
        for (i = 0; !symbols[i].last; i++) {
            if (!(ptr = R_NEW0 (RBinSymbol)))
                break;
            //strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
            snprintf (ptr->name, R_BIN_SIZEOF_STRINGS-1, "%s", symbols[i].name);
            strncpy (ptr->forwarder, (char*)symbols[i].forwarder, R_BIN_SIZEOF_STRINGS);
            strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
            strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS); //XXX Get the right type
            ptr->size = 0;
            ptr->vaddr = symbols[i].vaddr;
            ptr->paddr = symbols[i].paddr;
            ptr->ordinal = symbols[i].ordinal;
            r_list_append (ret, ptr);
        }
        free (symbols);
	}

	if ((imports = PE_(r_bin_pe_get_imports)(arch->o->bin_obj))) {
        for (i = 0; !imports[i].last; i++) {
            if (!(ptr = R_NEW0 (RBinSymbol)))
                break;
            //strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
            snprintf (ptr->name, R_BIN_SIZEOF_STRINGS-1, "imp.%s", imports[i].name);
            //strncpy (ptr->forwarder, (char*)imports[i].forwarder, R_BIN_SIZEOF_STRINGS);
            strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
            strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS); //XXX Get the right type
            ptr->size = 0;
            ptr->vaddr = imports[i].vaddr;
            ptr->paddr = imports[i].paddr;
            ptr->ordinal = imports[i].ordinal;
            r_list_append (ret, ptr);
        }
        free (imports);
	}
	return ret;
}

static void filter_import(ut8 *n) {
	int I;
	for (I=0; n[I]; I++) {
		if (n[I]<30 || n[I]>=0x7f) {
			n[I] = 0;
			break;
		}
	}
}

static RList* imports(RBinFile *arch) {
	RList *ret = NULL, *relocs = NULL;
	RBinImport *ptr = NULL;
	RBinReloc *rel = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	if (!(ret = r_list_new ()) || !(relocs = r_list_new ()))
		return NULL;

	ret->free = free;
	relocs->free = free;

	((struct PE_(r_bin_pe_obj_t)*)arch->o->bin_obj)->relocs = relocs;

	if (!(imports = PE_(r_bin_pe_get_imports)(arch->o->bin_obj)))
		return ret;
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport)))
			break;
		filter_import (imports[i].name);
		strncpy (ptr->name, (char*)imports[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, "FUNC", R_BIN_SIZEOF_STRINGS);
		ptr->ordinal = imports[i].ordinal;
		// NOTE(eddyb) a PE hint is just an optional possible DLL export table
		// index for the import. There is no point in exposing it.
		//ptr->hint = imports[i].hint;
		r_list_append (ret, ptr);

		if (!(rel = R_NEW0 (RBinReloc)))
			break;
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		rel->vaddr = imports[i].vaddr + baddr (arch);
		rel->paddr = imports[i].paddr;
		r_list_append (relocs, rel);
	}
	free (imports);
	return ret;
}

static RList* relocs(RBinFile *arch) {
	struct PE_(r_bin_pe_obj_t)* obj= arch->o->bin_obj;
	if (obj) return obj->relocs;
	return NULL;
}

static RList* libs(RBinFile *arch) {
	struct r_bin_pe_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = PE_(r_bin_pe_get_libs)(arch->o->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static int is_dot_net(RBinFile *arch) {
	struct r_bin_pe_lib_t *libs = NULL;
	int i;
	if (!(libs = PE_(r_bin_pe_get_libs)(arch->o->bin_obj)))
		return R_FALSE;
	for (i = 0; !libs[i].last; i++) {
		if (!strcmp (libs[i].name, "mscoree.dll")) {
			free (libs);
			return R_TRUE;
		}
	}
	free (libs);
	return R_FALSE;
}

static int has_canary(RBinFile *arch) {
	const RList* imports_list = imports (arch);
	RListIter *iter;
	RBinImport *import;
	// TODO: use O(1) when imports sdbized
	if (imports_list) {
		r_list_foreach (imports_list, iter, import)
			if (!strcmp (import->name, "__security_init_cookie")) {
				//r_list_free (imports_list);
				return 1;
			}
		// DO NOT FREE IT! r_list_free (imports_list);
	}
	return 0;
}

static int haschr(const RBinFile* arch, ut16 dllCharacteristic) {
	const ut8 *buf;
	unsigned int idx;
	ut64 sz;
	if (!arch) return R_FALSE;
	buf = r_buf_buffer (arch->buf);
	if (!buf) return R_FALSE;
	sz = r_buf_size (arch->buf);
	idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (sz < idx + 0x5E)
		return R_FALSE;
	return ((*(ut16*)(buf + idx + 0x5E)) & \
		dllCharacteristic);
}

static RBinInfo* info(RBinFile *arch) {
	SDebugInfo di = {0};
	int len = 0;
	char *str;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;
	if (arch->file)
		strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	else *ret->file = 0;
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_class) (arch->o->bin_obj))) {
		strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	strncpy (ret->rclass, "pe", R_BIN_SIZEOF_STRINGS);
	if ((str = PE_(r_bin_pe_get_os) (arch->o->bin_obj))) {
		strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_arch) (arch->o->bin_obj))) {
		strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_machine) (arch->o->bin_obj))) {
		strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if ((str = PE_(r_bin_pe_get_subsystem) (arch->o->bin_obj))) {
		strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	}
	if (is_dot_net (arch)) {
		ret->lang = "msil";
	}
	if (PE_(r_bin_pe_is_dll) (arch->o->bin_obj))
		strncpy (ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_STRINGS);
	else strncpy (ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_STRINGS);
	ret->bits = PE_(r_bin_pe_get_bits) (arch->o->bin_obj);
	ret->big_endian = PE_(r_bin_pe_is_big_endian) (arch->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_canary = has_canary (arch);
	ret->has_nx = haschr (arch, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
	ret->has_pi = haschr (arch, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);

	sdb_bool_set (arch->sdb, "pe.canary", has_canary(arch), 0);
	sdb_bool_set (arch->sdb, "pe.highva", haschr(arch, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA), 0);
	sdb_bool_set (arch->sdb, "pe.aslr", haschr(arch, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE), 0);
	sdb_bool_set (arch->sdb, "pe.forceintegrity", haschr(arch, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (arch->sdb, "pe.nx", haschr(arch, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT), 0);
	sdb_bool_set (arch->sdb, "pe.isolation", !haschr(arch, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (arch->sdb, "pe.seh", !haschr(arch, IMAGE_DLLCHARACTERISTICS_NO_SEH), 0);
	sdb_bool_set (arch->sdb, "pe.bind", !haschr(arch, IMAGE_DLLCHARACTERISTICS_NO_BIND), 0);
	sdb_bool_set (arch->sdb, "pe.appcontainer", haschr(arch, IMAGE_DLLCHARACTERISTICS_APPCONTAINER), 0);
	sdb_bool_set (arch->sdb, "pe.wdmdriver", haschr(arch, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER), 0);
	sdb_bool_set (arch->sdb, "pe.guardcf", haschr(arch, IMAGE_DLLCHARACTERISTICS_GUARD_CF), 0);
	sdb_bool_set (arch->sdb, "pe.terminalserveraware", haschr(arch, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE), 0);
	sdb_num_set (arch->sdb, "pe.bits", ret->bits, 0);

	ret->has_va = R_TRUE;
	if (!PE_(r_bin_pe_is_stripped_debug) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	if (PE_(r_bin_pe_is_stripped_line_nums) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_LINENUMS;
	if (PE_(r_bin_pe_is_stripped_local_syms) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_SYMS;
	if (PE_(r_bin_pe_is_stripped_relocs) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_RELOCS;

	if (PE_(r_bin_pe_get_debug_data)(arch->o->bin_obj, &di)) {
		len = R_BIN_SIZEOF_STRINGS;
		if (R_BIN_SIZEOF_STRINGS >= GUIDSTR_LEN) {
			len = GUIDSTR_LEN;
		} else {
			eprintf("warning: guid is bigger than R_BIN_SIZEOF_STRINGS\n");
		}
		strncpy(ret->guid, (char *)di.guidstr, len);

		if (R_BIN_SIZEOF_STRINGS >= DBG_FILE_NAME_LEN) {
			len = DBG_FILE_NAME_LEN;
		} else {
			eprintf("waring: debug file name len os bigger then R_BIN_SIZEOF_STRINGS\n");
		}
		strncpy(ret->debug_file_name, (char *)di.file_name, len);
	}

	return ret;
}

static ut64 get_vaddr (RBinFile *arch, ut64 baddr, ut64 paddr, ut64 vaddr) {
	if (!baddr) return vaddr;
	return baddr + vaddr;
}

#if !R_BIN_PE64
static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	unsigned int idx;
	int ret = R_FALSE;
	if (!buf)
		return R_FALSE;
	if (length <= 0x3d)
		return R_FALSE;
	idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (length > idx+0x18+2)
		if (!memcmp (buf, "MZ", 2) &&
			!memcmp (buf+idx, "PE", 2) &&
			!memcmp (buf+idx+0x18, "\x0b\x01", 2))
			ret = R_TRUE;
	return ret;
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 hdrsize, p_start, p_opthdr, p_sections, p_lsrlc, n;
	ut32 baddr = 0x400000;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define H(x) r_buf_append_ut16(buf,x)
#define D(x) r_buf_append_ut32(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	B ("MZ\x00\x00", 4); // MZ Header
	B ("PE\x00\x00", 4); // PE Signature
	H (0x14c); // Machine
	H (1); // Number of sections
	D (0); // Timestamp (Unused)
	D (0); // PointerToSymbolTable (Unused)
	D (0); // NumberOfSymbols (Unused)
	p_lsrlc = buf->length;
	H (-1); // SizeOfOptionalHeader
	H (0x103); // Characteristics

	/* Optional Header */
	p_opthdr = buf->length;
	H (0x10b); // Magic
	B ("\x08\x00", 2); // (Major/Minor)LinkerVersion (Unused)

	p_sections = buf->length;
	n = p_sections-p_opthdr;
	W (p_lsrlc, &n, 2); // Fix SizeOfOptionalHeader

	/* Sections */
	p_start = 0x7c; //HACK: Headersize
	hdrsize = 0x7c;

	D (R_ROUND (codelen, 4)); // SizeOfCode (Unused)
	D (0); // SizeOfInitializedData (Unused)
	D (codelen); // codesize
	D (p_start);
	D (codelen);
	D (p_start);
	D (baddr); // ImageBase
	D (4); // SectionAlignment
	D (4); // FileAlignment
	H (4); // MajorOperatingSystemVersion (Unused)
	H (0); // MinorOperatingSystemVersion (Unused)
	H (0); // MajorImageVersion (Unused)
	H (0); // MinorImageVersion (Unused)
	H (4); // MajorSubsystemVersion
	H (0); // MinorSubsystemVersion (Unused)
	D (0); // Win32VersionValue (Unused)
	D ((R_ROUND (hdrsize, 4)) + (R_ROUND (codelen, 4))); // SizeOfImage
	D (R_ROUND (hdrsize, 4)); // SizeOfHeaders
	D (0); // CheckSum (Unused)
	H (2); // Subsystem (Win32 GUI)
	H (0x400); // DllCharacteristics (Unused)
	D (0x100000); // SizeOfStackReserve (Unused)
	D (0x1000); // SizeOfStackCommit
	D (0x100000); // SizeOfHeapReserve
	D (0x1000); // SizeOfHeapCommit (Unused)
	D (0); // LoaderFlags (Unused)
	D (0); // NumberOfRvaAndSizes (Unused)
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
	.dbginfo = NULL,
	.write = NULL,
	.minstrlen = 4,
	.create = &create,
	.get_vaddr = &get_vaddr
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe
};
#endif
#endif
