/* radare - LGPL - Copyright 2009-2018 - nibble, pancake, alvarofe */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pe.h"

static Sdb* get_sdb (RBinFile *bf) {
	RBinObject *o = bf->o;
	struct PE_(r_bin_pe_obj_t) *bin;
	if (!o || !o->bin_obj) {
		return NULL;
	}
	bin = (struct PE_(r_bin_pe_obj_t) *) o->bin_obj;
	return bin? bin->kv: NULL;
}

static void * load_bytes(RBinFile *bf, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	struct PE_(r_bin_pe_obj_t) *res = NULL;
	RBuffer *tbuf = NULL;
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = PE_(r_bin_pe_new_buf) (tbuf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	return res;
}

static void * load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	struct PE_(r_bin_pe_obj_t) *res;
	if (!buf) {
		return NULL;
	}
	res = PE_(r_bin_pe_new_buf) (buf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	return res;
}

static bool load(RBinFile *bf) {
	void *res;
	const ut8 *bytes;
	ut64 sz;

	if (!bf || !bf->o) {
		return false;
	}
	bytes = r_buf_buffer (bf->buf);
	sz = r_buf_size (bf->buf);
	res = load_bytes (bf, bytes, sz, bf->o->loadaddr, bf->sdb);
 	bf->o->bin_obj = res;
	return res? true: false;
}

static int destroy(RBinFile *bf) {
	PE_(r_bin_pe_free) ((struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return PE_(r_bin_pe_get_image_base) (bf->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	struct r_bin_pe_addr_t *peaddr = NULL;
	RBinAddr *ret = NULL;
	if (bf && bf->o && bf->o->bin_obj) {
		switch (type) {
		case R_BIN_SYM_MAIN:
				peaddr = PE_(r_bin_pe_get_main_vaddr) (bf->o->bin_obj);
				break;
		}
	}
	if (peaddr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = peaddr->paddr;
		ret->vaddr = peaddr->vaddr;
	}
	free (peaddr);
	return ret;
}

static void add_tls_callbacks(RBinFile *bf, RList* list) {
	PE_DWord paddr, vaddr, haddr;
	int count = 0;
	RBinAddr *ptr = NULL;
	struct PE_(r_bin_pe_obj_t) *bin = (struct PE_(r_bin_pe_obj_t) *) (bf->o->bin_obj);
	char *key;

	do {
		key =  sdb_fmt ("pe.tls_callback%d_paddr", count);
		paddr = sdb_num_get (bin->kv, key, 0);
		if (!paddr) {
			break;
		}

		key =  sdb_fmt ("pe.tls_callback%d_vaddr", count);
		vaddr = sdb_num_get (bin->kv, key, 0);
		if (!vaddr) {
			break;
		}

		key =  sdb_fmt ("pe.tls_callback%d_haddr", count);
		haddr = sdb_num_get (bin->kv, key, 0);
		if (!haddr) {
			break;
		}
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->haddr = haddr;
			ptr->type  = R_BIN_ENTRY_TYPE_TLS;
			r_list_append (list, ptr);
		}
		count++;
	} while (vaddr);
}

static RList* entries(RBinFile *bf) {
	struct r_bin_pe_addr_t *entry = NULL;
	RBinAddr *ptr = NULL;
	RList* ret;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(entry = PE_(r_bin_pe_get_entrypoint) (bf->o->bin_obj))) {
		return ret;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = entry->paddr;
		ptr->vaddr = entry->vaddr;
		ptr->haddr = entry->haddr;
		ptr->type  = R_BIN_ENTRY_TYPE_PROGRAM;
		r_list_append (ret, ptr);
	}
	free (entry);
	// get TLS callback addresses
	add_tls_callbacks (bf, ret);

	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_pe_section_t *sections = NULL;
	struct PE_(r_bin_pe_obj_t) *bin = (struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj;
	ut64 ba = baddr (bf);
	int i;
	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(sections = PE_(r_bin_pe_get_sections) (bin))){
		r_list_free (ret);
		return NULL;
	}
	PE_(r_bin_pe_check_sections) (bin, &sections);
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		if (sections[i].name[0]) {
			strncpy (ptr->name, (char*)sections[i].name, R_BIN_SIZEOF_STRINGS);
		}
		ptr->size = sections[i].size;
		if (ptr->size > bin->size) {
			if (sections[i].vsize < bin->size) {
				ptr->size = sections[i].vsize;
			} else {
				//hack give it page size
				ptr->size = 4096;
			}
		}
		ptr->vsize = sections[i].vsize;
		if (!ptr->vsize && ptr->size) {
			ptr->vsize = ptr->size;
		}
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr + ba;
		ptr->add = true;
		ptr->srwx = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].flags)) {
			ptr->srwx |= R_BIN_SCN_EXECUTABLE;
		}
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].flags)) {
			ptr->srwx |= R_BIN_SCN_WRITABLE;
		}
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].flags)) {
			ptr->srwx |= R_BIN_SCN_READABLE;
		} else {
			//fix those sections that could have been fucked up
			//if the section does have -x- but not -r- add it
			if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].flags)) {
				ptr->srwx |= R_BIN_SCN_READABLE;
			}
		}
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].flags)) {
			ptr->srwx |= R_BIN_SCN_SHAREABLE;
		}
#define X 1
#define ROW (4 | 2)
		if (ptr->srwx & ROW && !(ptr->srwx & X) && ptr->size > 0) {
			if (!strcmp (ptr->name, ".rsrc") ||
			  	!strcmp (ptr->name, ".data") ||
				!strcmp (ptr->name, ".rdata")) {
					ptr->is_data = true;
				}
		}
		r_list_append (ret, ptr);
	}
	free (sections);
	return ret;
}

static void find_pe_overlay(RBinFile *bf) {
	ut64 pe_overlay_size;
	ut64 pe_overlay_offset = PE_(bin_pe_get_overlay) (bf->o->bin_obj, &pe_overlay_size);
	if (pe_overlay_offset) {
		sdb_num_set (bf->sdb, "pe_overlay.offset", pe_overlay_offset, 0);
		sdb_num_set (bf->sdb, "pe_overlay.size", pe_overlay_size, 0);
	}
}

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	struct r_bin_pe_export_t *symbols = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if ((symbols = PE_(r_bin_pe_get_exports)(bf->o->bin_obj))) {
		for (i = 0; !symbols[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			ptr->name = strdup ((char *)symbols[i].name);
			ptr->forwarder = r_str_const ((char *)symbols[i].forwarder);
			//strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
			ptr->bind = r_str_const ("GLOBAL");
			ptr->type = r_str_const ("FUNC");
			ptr->size = 0;
			ptr->vaddr = symbols[i].vaddr;
			ptr->paddr = symbols[i].paddr;
			ptr->ordinal = symbols[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (symbols);
	}


	if ((imports = PE_(r_bin_pe_get_imports)(bf->o->bin_obj))) {
		for (i = 0; !imports[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				break;
			}
			//strncpy (ptr->name, (char*)symbols[i].name, R_BIN_SIZEOF_STRINGS);
			ptr->name = r_str_newf ("imp.%s", imports[i].name);
			//strncpy (ptr->forwarder, (char*)imports[i].forwarder, R_BIN_SIZEOF_STRINGS);
			ptr->bind = r_str_const ("NONE");
			ptr->type = r_str_const ("FUNC");
			ptr->size = 0;
			ptr->vaddr = imports[i].vaddr;
			ptr->paddr = imports[i].paddr;
			ptr->ordinal = imports[i].ordinal;
			r_list_append (ret, ptr);
		}
		free (imports);
	}
	find_pe_overlay(bf);
	return ret;
}

static void filter_import(ut8 *n) {
	int I;
	for (I = 0; n[I]; I++) {
		if (n[I] < 30 || n[I] >= 0x7f) {
			n[I] = 0;
			break;
		}
	}
}

static RList* imports(RBinFile *bf) {
	RList *ret = NULL, *relocs = NULL;
	RBinImport *ptr = NULL;
	RBinReloc *rel = NULL;
	struct r_bin_pe_import_t *imports = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}

	// XXX: has_canary is causing problems! thus we need to check and clean here until it is fixed!
	if (((struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj)->relocs) {
		r_list_free (((struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj)->relocs);
	}

	if (!(relocs = r_list_newf (free))) {
		free (ret);
		return NULL;
	}
	((struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj)->relocs = relocs;

	if (!(imports = PE_(r_bin_pe_get_imports)(bf->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			break;
		}
		filter_import (imports[i].name);
		ptr->name = strdup ((char*)imports[i].name);
		ptr->bind = r_str_const ("NONE");
		ptr->type = r_str_const ("FUNC");
		ptr->ordinal = imports[i].ordinal;
		// NOTE(eddyb) a PE hint is just an optional possible DLL export table
		// index for the import. There is no point in exposing it.
		//ptr->hint = imports[i].hint;
		r_list_append (ret, ptr);

		if (!(rel = R_NEW0 (RBinReloc))) {
			break;
		}
#ifdef R_BIN_PE64
		rel->type = R_BIN_RELOC_64;
#else
		rel->type = R_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		{
			ut8 addr[4];
			r_buf_read_at (bf->buf, imports[i].paddr, addr, 4);
			ut64 newaddr = (ut64) r_read_le32 (&addr);
			rel->vaddr = newaddr;
		}
		rel->paddr = imports[i].paddr;
		r_list_append (relocs, rel);
	}
	free (imports);
	return ret;
}

static RList* relocs(RBinFile *bf) {
	struct PE_(r_bin_pe_obj_t)* obj= bf->o->bin_obj;
	if (obj) {
		return obj->relocs;
	}
	return NULL;
}

static RList* libs(RBinFile *bf) {
	struct r_bin_pe_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(libs = PE_(r_bin_pe_get_libs)(bf->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static int is_dot_net(RBinFile *bf) {
	struct r_bin_pe_lib_t *libs = NULL;
	int i;
	if (!(libs = PE_(r_bin_pe_get_libs)(bf->o->bin_obj))) {
		return false;
	}
	for (i = 0; !libs[i].last; i++) {
		if (!strcmp (libs[i].name, "mscoree.dll")) {
			free (libs);
			return true;
		}
	}
	free (libs);
	return false;
}

static int is_vb6(RBinFile *bf) {
	struct r_bin_pe_lib_t *libs = NULL;
	int i;
	if (!(libs = PE_(r_bin_pe_get_libs)(bf->o->bin_obj))) {
		return false;
	}
	for (i = 0; !libs[i].last; i++) {
		if (!strcmp (libs[i].name, "msvbvm60.dll")) {
			free (libs);
			return true;
		}
	}
	free (libs);
	return false;
}

static int has_canary(RBinFile *bf) {
	// XXX: We only need imports here but this causes leaks, we need to wait for the below. This is a horrible solution!
	// TODO: use O(1) when imports sdbized
	RListIter *iter;
	struct PE_ (r_bin_pe_obj_t) *bin = bf->o->bin_obj;
	if (bin) {
		const RList* relocs_list = bin->relocs;
		RBinReloc *rel;
		if (relocs_list) {
			r_list_foreach (relocs_list, iter, rel) {
				if (!strcmp (rel->import->name, "__security_init_cookie")) {
					return true;
				}
			}
		}
	} else {  // rabin2 needs this as it will not initialise bin
		const RList* imports_list = imports (bf);
		RBinImport *imp;
		if (imports_list) {
			r_list_foreach (imports_list, iter, imp) {
				if (!strcmp (imp->name, "__security_init_cookie")) {
					return true;
				}
			}
		}
	}
	return false;
}

static int haschr(const RBinFile* bf, ut16 dllCharacteristic) {
	const ut8 *buf;
	unsigned int idx;
	ut64 sz;
	if (!bf) {
		return false;
	}
	buf = r_buf_buffer (bf->buf);
	if (!buf) {
		return false;
	}
	sz = r_buf_size (bf->buf);
	idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (idx + 0x5E + 1 >= sz ) {
		return false;
	}
	//it's funny here idx+0x5E can be 158 and sz 159 but with
	//the cast it reads two bytes until 160
	return ((*(ut16*)(buf + idx + 0x5E)) & dllCharacteristic);
}

static RBinInfo* info(RBinFile *bf) {
	struct PE_ (r_bin_pe_obj_t) *bin;
	SDebugInfo di = {{0}};
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ut32 claimed_checksum, actual_checksum, pe_overlay;

	if (!ret) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	bf->file = strdup (bf->file);
	ret->bclass = PE_(r_bin_pe_get_class) (bf->o->bin_obj);
	ret->rclass = strdup ("pe");
	ret->os = PE_(r_bin_pe_get_os) (bf->o->bin_obj);
	ret->arch = PE_(r_bin_pe_get_arch) (bf->o->bin_obj);
	ret->machine = PE_(r_bin_pe_get_machine) (bf->o->bin_obj);
	ret->subsystem = PE_(r_bin_pe_get_subsystem) (bf->o->bin_obj);
	if (is_dot_net (bf)) {
		ret->lang = "cil";
	}
	if (is_vb6 (bf)) {
		ret->lang = "vb";
	}
	if (PE_(r_bin_pe_is_dll) (bf->o->bin_obj)) {
		ret->type = strdup ("DLL (Dynamic Link Library)");
	} else {
		ret->type = strdup ("EXEC (Executable file)");
	}
	claimed_checksum = PE_(bin_pe_get_claimed_checksum) (bf->o->bin_obj);
	actual_checksum  = PE_(bin_pe_get_actual_checksum) (bf->o->bin_obj);
	pe_overlay = sdb_num_get (bf->sdb, "pe_overlay.size", 0);
	ret->bits = PE_(r_bin_pe_get_bits) (bf->o->bin_obj);
	ret->big_endian = PE_(r_bin_pe_is_big_endian) (bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_lit = true;
	ret->has_canary = has_canary (bf);
	ret->has_nx = haschr (bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
	ret->has_pi = haschr (bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
	ret->claimed_checksum = strdup (sdb_fmt ("0x%08x", claimed_checksum));
	ret->actual_checksum  = strdup (sdb_fmt ("0x%08x", actual_checksum));
	ret->pe_overlay = pe_overlay > 0;
	ret->signature = bin ? bin->is_signed : false;

	sdb_bool_set (bf->sdb, "pe.canary", has_canary(bf), 0);
	sdb_bool_set (bf->sdb, "pe.highva", haschr(bf, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA), 0);
	sdb_bool_set (bf->sdb, "pe.aslr", haschr(bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE), 0);
	sdb_bool_set (bf->sdb, "pe.forceintegrity", haschr(bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (bf->sdb, "pe.nx", haschr(bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT), 0);
	sdb_bool_set (bf->sdb, "pe.isolation", !haschr(bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (bf->sdb, "pe.seh", !haschr(bf, IMAGE_DLLCHARACTERISTICS_NO_SEH), 0);
	sdb_bool_set (bf->sdb, "pe.bind", !haschr(bf, IMAGE_DLLCHARACTERISTICS_NO_BIND), 0);
	sdb_bool_set (bf->sdb, "pe.appcontainer", haschr(bf, IMAGE_DLLCHARACTERISTICS_APPCONTAINER), 0);
	sdb_bool_set (bf->sdb, "pe.wdmdriver", haschr(bf, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER), 0);
	sdb_bool_set (bf->sdb, "pe.guardcf", haschr(bf, IMAGE_DLLCHARACTERISTICS_GUARD_CF), 0);
	sdb_bool_set (bf->sdb, "pe.terminalserveraware", haschr(bf, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE), 0);
	sdb_num_set (bf->sdb, "pe.bits", ret->bits, 0);
	sdb_set (bf->sdb, "pe.claimed_checksum", ret->claimed_checksum, 0);
	sdb_set (bf->sdb, "pe.actual_checksum", ret->actual_checksum, 0);

	ret->has_va = true;

	if (!PE_(r_bin_pe_is_stripped_debug) (bf->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	if (PE_(r_bin_pe_is_stripped_line_nums) (bf->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS;
	}
	if (PE_(r_bin_pe_is_stripped_local_syms) (bf->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_SYMS;
	}
	if (PE_(r_bin_pe_is_stripped_relocs) (bf->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_RELOCS;
	}
	if (PE_(r_bin_pe_get_debug_data)(bf->o->bin_obj, &di)) {
		ret->guid = r_str_ndup (di.guidstr, GUIDSTR_LEN);
		if (ret->guid) {
			ret->debug_file_name = r_str_ndup (di.file_name, DBG_FILE_NAME_LEN);
			if (!ret->debug_file_name) {
				R_FREE (ret->guid);
			}
		}
	}

	return ret;
}

static ut64 get_vaddr (RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return baddr + vaddr;
}

#if !R_BIN_PE64
static bool check_bytes(const ut8 *buf, ut64 length) {
	unsigned int idx;
	if (!buf) {
		return false;
	}
	if (length <= 0x3d) {
		return false;
	}
	idx = (buf[0x3c] | (buf[0x3d]<<8));
	if (length > idx + 0x18 + 2) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		if (!memcmp (buf, "MZ", 2)) {
			if (!memcmp (buf+idx, "PE", 2) &&
				!memcmp (buf+idx+0x18, "\x0b\x01", 2)) {
				return true;
			}
			// TODO: Add one more indicator, to prevent false positives
			if (!memcmp (buf+idx, "PL", 2)) {
				return true;
			}
		}
	}
	return false;
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

static char *signature (RBinFile *bf, bool json) {
	char* c = NULL;
	struct PE_ (r_bin_pe_obj_t) * bin;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return c;
	}
	bin = bf->o->bin_obj;
	if (json) {
		RJSVar *json = r_pkcs7_cms_json (bin->cms);
		c = r_json_stringify (json, false);
		r_json_var_free (json);
	} else {
		c = r_pkcs7_cms_dump (bin->cms);
	}
	return c;
}

static RList *fields(RBinFile *bf) {
	RList *ret = NULL;
	const ut8 *buf = NULL;

	buf = bf ? r_buf_buffer (bf->buf) : NULL;
	ret  = r_list_new ();

	if (!buf || !ret) {
		return NULL;
	}

	#define ROWL(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, siz, nam, sdb_fmt ("0x%08x", val), fmt));
	ut64 addr = 128;

	struct PE_(r_bin_pe_obj_t) * bin = bf->o->bin_obj;
	ROWL ("Signature", 4, bin->nt_headers->Signature, "x"); addr += 4;
	ROWL ("Machine", 2, bin->nt_headers->file_header.Machine, "x"); addr += 2;
	ROWL ("NumberOfSections", 2, bin->nt_headers->file_header.NumberOfSections, "x"); addr += 2;
	ROWL ("TimeDateStamp", 4, bin->nt_headers->file_header.TimeDateStamp, "x"); addr += 4;
	ROWL ("PointerToSymbolTable", 4, bin->nt_headers->file_header.PointerToSymbolTable, "x"); addr += 4;
	ROWL ("NumberOfSymbols ", 4, bin->nt_headers->file_header.NumberOfSymbols, "x"); addr += 4;
	ROWL ("SizeOfOptionalHeader", 2, bin->nt_headers->file_header.SizeOfOptionalHeader, "x"); addr += 2;
	ROWL ("Characteristics", 2, bin->nt_headers->file_header.Characteristics, "x"); addr += 2;
	ROWL ("Magic", 2, bin->nt_headers->optional_header.Magic, "x"); addr += 2;
	ROWL ("MajorLinkerVersion", 1, bin->nt_headers->optional_header.MajorLinkerVersion, "x"); addr += 1;
	ROWL ("MinorLinkerVersion", 1, bin->nt_headers->optional_header.MinorLinkerVersion, "x"); addr += 1;
	ROWL ("SizeOfCode", 4, bin->nt_headers->optional_header.SizeOfCode, "x"); addr += 4;
	ROWL ("SizeOfInitializedData", 4, bin->nt_headers->optional_header.SizeOfInitializedData, "x"); addr += 4;
	ROWL ("SizeOfUninitializedData", 4, bin->nt_headers->optional_header.SizeOfUninitializedData, "x"); addr += 4;
	ROWL ("AddressOfEntryPoint", 4, bin->nt_headers->optional_header.AddressOfEntryPoint, "x"); addr += 4;
	ROWL ("BaseOfCode", 4, bin->nt_headers->optional_header.BaseOfCode, "x"); addr += 4;
	ROWL ("BaseOfData", 4, bin->nt_headers->optional_header.BaseOfData, "x"); addr += 4;
	ROWL ("ImageBase", 4, bin->nt_headers->optional_header.ImageBase, "x"); addr += 4;
	ROWL ("SectionAlignment", 4, bin->nt_headers->optional_header.SectionAlignment, "x"); addr += 4;
	ROWL ("FileAlignment", 4, bin->nt_headers->optional_header.FileAlignment, "x"); addr += 4;
	ROWL ("MajorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MajorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MinorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MinorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MajorImageVersion", 2, bin->nt_headers->optional_header.MajorImageVersion, "x"); addr += 2;
	ROWL ("MinorImageVersion", 2, bin->nt_headers->optional_header.MinorImageVersion, "x"); addr += 2;
	ROWL ("MajorSubsystemVersion", 2, bin->nt_headers->optional_header.MajorSubsystemVersion, "x"); addr += 2;
	ROWL ("MinorSubsystemVersion", 2, bin->nt_headers->optional_header.MinorSubsystemVersion, "x"); addr += 2;
	ROWL ("Win32VersionValue", 4, bin->nt_headers->optional_header.Win32VersionValue, "x"); addr += 4;
	ROWL ("SizeOfImage", 4, bin->nt_headers->optional_header.SizeOfImage, "x"); addr += 4;
	ROWL ("SizeOfHeaders", 4, bin->nt_headers->optional_header.SizeOfHeaders, "x"); addr += 4;
	ROWL ("CheckSum", 4, bin->nt_headers->optional_header.CheckSum, "x"); addr += 4;
	ROWL ("Subsystem",24, bin->nt_headers->optional_header.Subsystem, "x"); addr += 2;
	ROWL ("DllCharacteristics", 2, bin->nt_headers->optional_header.DllCharacteristics, "x"); addr += 2;
	ROWL ("SizeOfStackReserve", 4, bin->nt_headers->optional_header.SizeOfStackReserve, "x"); addr += 4;
	ROWL ("SizeOfStackCommit", 4, bin->nt_headers->optional_header.SizeOfStackCommit, "x"); addr += 4;
	ROWL ("SizeOfHeapReserve", 4, bin->nt_headers->optional_header.SizeOfHeapReserve, "x"); addr += 4;
	ROWL ("SizeOfHeapCommit", 4, bin->nt_headers->optional_header.SizeOfHeapCommit, "x"); addr += 4;
	ROWL ("LoaderFlags", 4, bin->nt_headers->optional_header.LoaderFlags, "x"); addr += 4;
	ROWL ("NumberOfRvaAndSizes", 4, bin->nt_headers->optional_header.NumberOfRvaAndSizes, "x"); addr += 4;

	int i;
	ut64 tmp = addr;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			addr = tmp + i*8;
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ROWL ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				ROWL ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				ROWL ("IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			}
		}
	}

	return ret;
}

static void header(RBinFile *bf) {
	struct PE_(r_bin_pe_obj_t) * bin = bf->o->bin_obj;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("PE file header:\n");
	rbin->cb_printf ("IMAGE_NT_HEADERS\n");
	rbin->cb_printf ("\tSignature : 0x%x\n", bin->nt_headers->Signature);
	rbin->cb_printf ("IMAGE_FILE_HEADERS\n");
	rbin->cb_printf ("\tMachine : 0x%x\n", bin->nt_headers->file_header.Machine);
	rbin->cb_printf ("\tNumberOfSections : 0x%x\n", bin->nt_headers->file_header.NumberOfSections);
	rbin->cb_printf ("\tTimeDateStamp : 0x%x\n", bin->nt_headers->file_header.TimeDateStamp);
	rbin->cb_printf ("\tPointerToSymbolTable : 0x%x\n", bin->nt_headers->file_header.PointerToSymbolTable);
	rbin->cb_printf ("\tNumberOfSymbols : 0x%x\n", bin->nt_headers->file_header.NumberOfSymbols);
	rbin->cb_printf ("\tSizeOfOptionalHeader : 0x%x\n", bin->nt_headers->file_header.SizeOfOptionalHeader);
	rbin->cb_printf ("\tCharacteristics : 0x%x\n", bin->nt_headers->file_header.Characteristics);
	rbin->cb_printf ("IMAGE_OPTIONAL_HEADERS\n");
	rbin->cb_printf ("\tMagic : 0x%x\n", bin->nt_headers->optional_header.Magic);
	rbin->cb_printf ("\tMajorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MajorLinkerVersion);
	rbin->cb_printf ("\tMinorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MinorLinkerVersion);
	rbin->cb_printf ("\tSizeOfCode : 0x%x\n", bin->nt_headers->optional_header.SizeOfCode);
	rbin->cb_printf ("\tSizeOfInitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfInitializedData);
	rbin->cb_printf ("\tSizeOfUninitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfUninitializedData);
	rbin->cb_printf ("\tAddressOfEntryPoint : 0x%x\n", bin->nt_headers->optional_header.AddressOfEntryPoint);
	rbin->cb_printf ("\tBaseOfCode : 0x%x\n", bin->nt_headers->optional_header.BaseOfCode);
	rbin->cb_printf ("\tBaseOfData : 0x%x\n", bin->nt_headers->optional_header.BaseOfData);
	rbin->cb_printf ("\tImageBase : 0x%x\n", bin->nt_headers->optional_header.ImageBase);
	rbin->cb_printf ("\tSectionAlignment : 0x%x\n", bin->nt_headers->optional_header.SectionAlignment);
	rbin->cb_printf ("\tFileAlignment : 0x%x\n", bin->nt_headers->optional_header.FileAlignment);
	rbin->cb_printf ("\tMajorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorOperatingSystemVersion);
	rbin->cb_printf ("\tMinorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorOperatingSystemVersion);
	rbin->cb_printf ("\tMajorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MajorImageVersion);
	rbin->cb_printf ("\tMinorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MinorImageVersion);
	rbin->cb_printf ("\tMajorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorSubsystemVersion);
	rbin->cb_printf ("\tMinorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorSubsystemVersion);
	rbin->cb_printf ("\tWin32VersionValue : 0x%x\n", bin->nt_headers->optional_header.Win32VersionValue);
	rbin->cb_printf ("\tSizeOfImage : 0x%x\n", bin->nt_headers->optional_header.SizeOfImage);
	rbin->cb_printf ("\tSizeOfHeaders : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeaders);
	rbin->cb_printf ("\tCheckSum : 0x%x\n", bin->nt_headers->optional_header.CheckSum);
	rbin->cb_printf ("\tSubsystem : 0x%x\n", bin->nt_headers->optional_header.Subsystem);
	rbin->cb_printf ("\tDllCharacteristics : 0x%x\n", bin->nt_headers->optional_header.DllCharacteristics);
	rbin->cb_printf ("\tSizeOfStackReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackReserve);
	rbin->cb_printf ("\tSizeOfStackCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackCommit);
	rbin->cb_printf ("\tSizeOfHeapReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapReserve);
	rbin->cb_printf ("\tSizeOfHeapCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapCommit);
	rbin->cb_printf ("\tLoaderFlags : 0x%x\n", bin->nt_headers->optional_header.LoaderFlags);
	rbin->cb_printf ("\tNumberOfRvaAndSizes : 0x%x\n", bin->nt_headers->optional_header.NumberOfRvaAndSizes);
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			rbin->cb_printf ("\tVirtualAddress : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			rbin->cb_printf ("\tSize : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
}

extern struct r_bin_write_t r_bin_write_pe;

RBinPlugin r_bin_plugin_pe = {
	.name = "pe",
	.desc = "PE bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_buffer = &load_buffer,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.signature = &signature,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.header = &header,
	.fields = &fields,
	.libs = &libs,
	.relocs = &relocs,
	.minstrlen = 4,
	.create = &create,
	.get_vaddr = &get_vaddr,
	.write = &r_bin_write_pe
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe,
	.version = R2_VERSION
};
#endif
#endif
