/* radare - LGPL - Copyright 2009-2019 - nibble, pancake, alvarofe */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"
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

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && bin_obj && buf, false);
	struct PE_(r_bin_pe_obj_t) *res = PE_(r_bin_pe_new_buf) (buf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
		*bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	PE_(r_bin_pe_free) ((struct PE_(r_bin_pe_obj_t)*)bf->o->bin_obj);
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
			ptr->paddr  = paddr;
			ptr->vaddr  = vaddr;
			ptr->hpaddr = haddr;
			ptr->type   = R_BIN_ENTRY_TYPE_TLS;
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
		ptr->paddr  = entry->paddr;
		ptr->vaddr  = entry->vaddr;
		ptr->hpaddr = entry->haddr;
		ptr->type   = R_BIN_ENTRY_TYPE_PROGRAM;
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
	if (!(ret = r_list_newf ((RListFree)r_bin_section_free))) {
		return NULL;
	}
	if (!bin || !(sections = bin->sections)){
		r_list_free (ret);
		return NULL;
	}
	PE_(r_bin_pe_check_sections) (bin, &sections);
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		if (sections[i].name[0]) {
			ptr->name = strdup ((char*)sections[i].name);
		} else {
			ptr->name = strdup ("");
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
		ptr->perm = 0;
		if (R_BIN_PE_SCN_IS_EXECUTABLE (sections[i].perm)) {
			ptr->perm |= R_PERM_X;
			ptr->perm |= R_PERM_R; // implicit
		}
		if (R_BIN_PE_SCN_IS_WRITABLE (sections[i].perm)) {
			ptr->perm |= R_PERM_W;
		}
		if (R_BIN_PE_SCN_IS_READABLE (sections[i].perm)) {
			ptr->perm |= R_PERM_R;
		}
		// this is causing may tests to fail because rx != srx
		if (R_BIN_PE_SCN_IS_SHAREABLE (sections[i].perm)) {
			ptr->perm |= R_PERM_SHAR;
		}
		if ((ptr->perm & R_PERM_RW) && !(ptr->perm & R_PERM_X) && ptr->size > 0) {
			if (!strcmp (ptr->name, ".rsrc") ||
			  	!strcmp (ptr->name, ".data") ||
				!strcmp (ptr->name, ".rdata")) {
					ptr->is_data = true;
				}
		}
		r_list_append (ret, ptr);
	}
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
			ptr->libname = *symbols[i].libname ? strdup ((char *)symbols[i].libname) : NULL;
			ptr->forwarder = r_str_constpool_get (&bf->rbin->constpool, (char *)symbols[i].forwarder);
			//strncpy (ptr->bind, "NONE", R_BIN_SIZEOF_STRINGS);
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
			ptr->type = R_BIN_TYPE_FUNC_STR;
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
			ptr->name = strdup ((const char *)imports[i].name);
			ptr->libname = strdup ((const char *)imports[i].libname);
			ptr->is_imported = true;
			//strncpy (ptr->forwarder, (char*)imports[i].forwarder, R_BIN_SIZEOF_STRINGS);
			ptr->bind = "NONE";
			ptr->type = R_BIN_TYPE_FUNC_STR;
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
		ptr->libname = strdup ((char*)imports[i].libname);
		ptr->bind = "NONE";
		ptr->type = "FUNC";
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
	buf = r_buf_data (bf->buf, &sz);
	if (!buf) {
		return false;
	}
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
	ret->file = strdup (bf->file);
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
	Sdb *db = sdb_ns (bf->sdb, "pe", true);
	sdb_bool_set (db, "canary", has_canary (bf), 0);
	sdb_bool_set (db, "highva", haschr (bf, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA), 0);
	sdb_bool_set (db, "aslr", haschr (bf, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE), 0);
	sdb_bool_set (db, "forceintegrity", haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "nx", haschr (bf, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT), 0);
	sdb_bool_set (db, "isolation", !haschr (bf, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY), 0);
	sdb_bool_set (db, "seh", !haschr (bf, IMAGE_DLLCHARACTERISTICS_NO_SEH), 0);
	sdb_bool_set (db, "bind", !haschr (bf, IMAGE_DLLCHARACTERISTICS_NO_BIND), 0);
	sdb_bool_set (db, "appcontainer", haschr (bf, IMAGE_DLLCHARACTERISTICS_APPCONTAINER), 0);
	sdb_bool_set (db, "wdmdriver", haschr (bf, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER), 0);
	sdb_bool_set (db, "guardcf", haschr (bf, IMAGE_DLLCHARACTERISTICS_GUARD_CF), 0);
	sdb_bool_set (db, "terminalserveraware", haschr (bf, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE), 0);
	sdb_num_set (db, "bits", ret->bits, 0);
	sdb_set (db, "claimed_checksum", ret->claimed_checksum, 0);
	sdb_set (db, "actual_checksum", ret->actual_checksum, 0);

	ret->has_va = true;

	if (PE_(r_bin_pe_is_stripped_debug) (bf->o->bin_obj)) {
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
