/* radare2 - LGPL - Copyright 2017 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "wasm/wasm.h"

static bool check_bytes(const ut8 *buf, ut64 length) {
	return (buf && length >= 4 && !memcmp (buf, R_BIN_WASM_MAGIC_BYTES, 4));
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	if (!check_bytes(buf, sz)) {
		return NULL;
	}
	return r_bin_wasm_init (arch);
}

static bool load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) {
		return false;
	}
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj != NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_wasm_destroy (arch);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RBinAddr *binsym(RBinFile *arch, int type) {
	return NULL; // TODO
}

static RList *sections(RBinFile *arch);

static RList *entries(RBinFile *arch) {
	RBinWasmObj *bin = arch && arch->o ? arch->o->bin_obj : NULL;
	// TODO
	RList *ret;
	RBinAddr *ptr = NULL;
	ut64 addr = 0x0;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(addr = (ut64) r_bin_wasm_get_entrypoint (bin))) {
		r_list_free (ret);
		return NULL;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = addr;
		ptr->vaddr = addr;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *sections(RBinFile *arch) {
	RBinWasmObj *bin = arch && arch->o ? arch->o->bin_obj : NULL;
	RList *ret = NULL;
	RList *secs = NULL;
	RBinSection *ptr = NULL;
	RBinWasmSection *sec;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(secs = r_bin_wasm_get_sections (bin))) {
		r_list_free (ret);
		return NULL;
	}
	RListIter *iter;
	r_list_foreach (secs, iter, sec) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			r_list_free (secs);
			r_list_free (ret);
			return NULL;
		}
		strncpy (ptr->name, (char*)sec->name, R_BIN_SIZEOF_STRINGS);
		if (sec->id == R_BIN_WASM_SECTION_DATA || sec->id == R_BIN_WASM_SECTION_MEMORY) {
			ptr->is_data = true;
		}
		ptr->size = sec->payload_len;
		ptr->vsize = sec->payload_len;
		ptr->vaddr = sec->offset;
		ptr->paddr = sec->offset;
		ptr->add = true;
		// TODO permissions
		ptr->srwx = 0;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *symbols(RBinFile *arch) {
	RBinWasmObj *bin = NULL;
	RList *ret = NULL, *codes = NULL, *imports = NULL;
	RBinSymbol *ptr = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = arch->o->bin_obj;
	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(codes = r_bin_wasm_get_codes (bin))) {
		goto bad_alloc;
	}
	if (!(imports = r_bin_wasm_get_imports (bin))) {
		goto bad_alloc;
	}
	
	ut32 i = 0;
	RBinWasmImportEntry *imp;
	RListIter *iter;
	r_list_foreach (imports, iter, imp) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			goto bad_alloc;
		}
		char tmp[R_BIN_SIZEOF_STRINGS];
		snprintf (tmp, R_BIN_SIZEOF_STRINGS, "imp.%s.%s", imp->module_str, imp->field_str);
		ptr->name = strdup(tmp);
		ptr->forwarder = r_str_const ("NONE");
		ptr->bind = r_str_const ("NONE");
		switch (imp->kind) {
		case 0: ptr->type = r_str_const ("FUNC"); break;
		case 1: ptr->type = r_str_const ("TABLE"); break;
		case 2: ptr->type = r_str_const ("MEMORY"); break;
		case 3: ptr->type = r_str_const ("GLOBAL"); break;
		}
		ptr->size = 0;
		ptr->vaddr = 0;
		ptr->paddr = 0;
		ptr->ordinal = i;
		i += 1;
		r_list_append (ret, ptr);
	}
	
	RBinWasmCodeEntry *func;
	r_list_foreach (codes, iter, func) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			goto bad_alloc;
		}
		char tmp[R_BIN_SIZEOF_STRINGS];
		snprintf (tmp, R_BIN_SIZEOF_STRINGS, "fnc.%d", i);
		ptr->name = strdup(tmp);
		ptr->forwarder = r_str_const ("NONE");
		ptr->bind = r_str_const ("NONE");
		ptr->type = r_str_const ("FUNC");
		ptr->size = func->len;
		ptr->vaddr = (ut64)func->code;
		ptr->paddr = (ut64)func->code;
		ptr->ordinal = i;
		i += 1;
		r_list_append (ret, ptr);
	}

	// TODO: use custom section "name" if present
	// TODO: exports, globals, tables and memories
	return ret;
bad_alloc:
	// not so sure if imports should be freed.
	r_list_free (codes);
	r_list_free (ret);
	return NULL;
}

static RList *imports(RBinFile *arch) {
	RBinWasmObj *bin = NULL;
	RList *imports = NULL;
	RBinImport *ptr = NULL;
	RList *ret = NULL;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = arch->o->bin_obj;
	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}
	if (!(imports = r_bin_wasm_get_imports (bin))) {
		goto bad_alloc;
	}

	RBinWasmImportEntry *import = NULL;
	ut32 i = 0;
	RListIter *iter;
	r_list_foreach (imports, iter, import) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			goto bad_alloc;
		}
		ptr->name = strdup (import->field_str);
		ptr->classname = strdup (import->module_str);
		ptr->ordinal = i;
		ptr->bind = r_str_const ("NONE");
		switch(import->kind) {
		case R_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = r_str_const ("FUNC");
			break;
		case R_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = r_str_const ("TABLE");
			break;
		case R_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = r_str_const ("MEM");
			break;
		case R_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = r_str_const ("GLOBAL");
			break;
		}
		r_list_append (ret, ptr);
	}
	return ret;
bad_alloc:
	r_list_free (imports);
	r_list_free (ret);
	return NULL;
}

static RList *libs(RBinFile *arch) {
	return NULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("module");
	ret->rclass = strdup ("wasm");
	ret->os = strdup ("Wasm");
	ret->arch = strdup ("wasm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("wasm");
	ret->type = strdup ("EXEC");
	ret->bits = 32;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RBinFile *arch) {
	if (!arch->o->info) {
		arch->o->info = info (arch);
	}
	if (!arch->o->info) {
		return 0;
	}
	return arch->buf->length;
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBuffer *buf = r_buf_new ();
#define B(x, y) r_buf_append_bytes (buf, (const ut8 *) x, y)
#define D(x) r_buf_append_ut32 (buf, x)
	B ("\x00" "asm", 4);
	B ("\x01\x00\x00\x00", 4);
	return buf;
}

RBinPlugin r_bin_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly bin plugin",
	.license = "MIT",
	.load = &load,
	.load_bytes = &load_bytes,
	.size = &size,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.create = &create,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wasm,
	.version = R2_VERSION
};
#endif
