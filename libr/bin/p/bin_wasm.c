/* radare2 - LGPL - Copyright 2017-2021 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "wasm/wasm.h"
#include "../format/wasm/wasm.h"

static bool check_buffer(RBinFile *bf, RBuffer *rbuf) {
	ut8 buf[4] = {0};
	return rbuf && r_buf_read_at (rbuf, 0, buf, 4) == 4 && !memcmp (buf, R_BIN_WASM_MAGIC_BYTES, 4);
}

struct search_fields {
	ut8 kind;
	ut32 index;
};

static int _export_finder(const void *_exp, const void *_needle) {
	const RBinWasmExportEntry *exp = _exp;
	const struct search_fields *needle = _needle;
	st64 diff = (st64)exp->kind - needle->kind;
	if (!diff) {
		diff = (st64)exp->index - needle->index;
		if (!diff) {
			return 0;
		}
	}
	return diff > 0? 1: -1;
}

static int _export_sorter(const void *_a, const void *_b) {
	const RBinWasmExportEntry *a = _a;
	const RBinWasmExportEntry *b = _b;
	st64 diff = (st64)a->kind - b->kind;
	if (!diff) {
		diff = (st64)a->index - b->index;
		if (!diff) { // index collision shouldn't happen
			diff = (st64)a->sec_i - b->sec_i;
		}
	}
	return diff > 0? 1: -1;
}

static inline RBinWasmExportEntry *find_export(RPVector *exports, ut8 kind, ut32 index) {
	if (!exports) {
		return NULL;
	}
	struct search_fields sf = { .kind = kind, .index = index };
	int n = r_pvector_bsearch (exports, (void *)&sf, _export_finder);
	return n >= 0? r_pvector_at (exports, n): NULL;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && buf && r_buf_size (buf) != UT64_MAX, false);

	if (check_buffer (bf, buf)) {
		*bin_obj = r_bin_wasm_init (bf, buf);
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_wasm_destroy (bf);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL; // TODO
}

static RList *entries(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinWasmObj *bin = (RBinWasmObj *)bf->o->bin_obj;
	// TODO
	ut64 addr = (ut64)r_bin_wasm_get_entrypoint (bin);
	if (!addr) {
		RPVector *codes = r_bin_wasm_get_codes (bin);
		if (codes) {
			RBinWasmCodeEntry *func = r_pvector_at (codes, 0);
			if (func) {
				addr = func->code;
			}
		}
		if (!addr) {
			return NULL;
		}
	}

	RList *ret = r_list_newf ((RListFree)free);
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (!ptr || !ret || !r_list_append (ret, ptr)) {
		r_list_free (ret);
		R_FREE (ptr);
	}
	ptr->paddr = addr;
	ptr->vaddr = addr;
	return ret;
}

static RList *sections(RBinFile *bf) {
	RBinWasmObj *bin = bf && bf->o? bf->o->bin_obj: NULL;
	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	RList *secs = r_bin_wasm_get_sections (bin);
	if (!ret || !secs) {
		goto alloc_err;
	}

	RBinSection *ptr = NULL;
	RBinWasmSection *sec;

	RListIter *iter;
	r_list_foreach (secs, iter, sec) {
		ptr = R_NEW0 (RBinSection);
		if (!ptr) {
			goto alloc_err;
		}
		ptr->name = strdup ((char *)sec->name);
		if (sec->id == R_BIN_WASM_SECTION_DATA || sec->id == R_BIN_WASM_SECTION_MEMORY) {
			ptr->is_data = true;
		}
		ptr->size = sec->payload_len;
		ptr->vsize = sec->payload_len;
		ptr->vaddr = sec->offset;
		ptr->paddr = sec->offset;
		ptr->add = true;
		// TODO permissions
		ptr->perm = 0;
		r_list_append (ret, ptr);
	}
	return ret;

alloc_err:
	r_list_free (secs);
	r_list_free (ret);
	return NULL;
}

static RList *symbols(RBinFile *bf) {
	RBinSymbol *ptr = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	RBinWasmObj *bin = bf->o->bin_obj;
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		goto bad_alloc;
	}

	ut32 fcn_idx = 0;
	ut32 table_idx = 0;
	ut32 mem_idx = 0;
	ut32 global_idx = 0;

	void **p;
	RPVector *imports = r_bin_wasm_get_imports (bin);
	if (imports) {
		r_pvector_foreach (imports, p) {
			RBinWasmImportEntry *imp = *p;
			if (!(ptr = R_NEW0 (RBinSymbol))) {
				goto bad_alloc;
			}
			ptr->name = strdup (imp->field_str);
			ptr->libname = strdup (imp->module_str);
			ptr->is_imported = true;
			ptr->forwarder = "NONE";
			ptr->bind = "NONE";
			switch (imp->kind) {
			case R_BIN_WASM_EXTERNALKIND_Function:
				ptr->type = R_BIN_TYPE_FUNC_STR;
				ptr->ordinal = fcn_idx++;
				break;
			case R_BIN_WASM_EXTERNALKIND_Table:
				ptr->type = "TABLE";
				ptr->ordinal = table_idx++;
				break;
			case R_BIN_WASM_EXTERNALKIND_Memory:
				ptr->type = "MEMORY";
				ptr->ordinal = mem_idx++;
				break;
			case R_BIN_WASM_EXTERNALKIND_Global:
				ptr->type = R_BIN_BIND_GLOBAL_STR;
				ptr->ordinal = global_idx++;
				break;
			}
			ptr->size = 0;
			ptr->vaddr = -1;
			ptr->paddr = -1;
			r_list_append (ret, ptr);
		}
	}

	RPVector *codes = r_bin_wasm_get_codes (bin);
	if (!codes) {
		return ret;
	}
	RPVector *exports = r_bin_wasm_get_exports (bin);
	if (exports) {
		r_pvector_sort (exports, _export_sorter);
	}

	RBinWasmExportEntry *exp;
	r_pvector_foreach (codes, p) {
		RBinWasmCodeEntry *func = *p;
		ptr = R_NEW0 (RBinSymbol);
		if (!ptr) {
			goto bad_alloc;
		}
		exp = find_export (exports, R_BIN_WASM_EXTERNALKIND_Function, fcn_idx);
		if (exp) {
			ptr->name = strdup (exp->field_str);
			ptr->bind = R_BIN_BIND_GLOBAL_STR;
		} else {
			ptr->bind = "NONE";
			const char *name = r_bin_wasm_get_function_name (bin, fcn_idx);
			ptr->name = name? strdup (name): r_str_newf ("fcn.%d", fcn_idx);
		}
		ptr->forwarder = "NONE";
		ptr->type = R_BIN_TYPE_FUNC_STR;
		ptr->size = func->len;
		ptr->vaddr = (ut64)func->code;
		ptr->paddr = (ut64)func->code;
		ptr->ordinal = fcn_idx++;
		r_list_append (ret, ptr);
	}

	// TODO: globals, tables and memories
	return ret;
bad_alloc:
	r_list_free (ret);
	return NULL;
}

static RList *get_imports(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinWasmObj *bin = bf->o->bin_obj;
	RPVector *imports = r_bin_wasm_get_imports (bin);
	RList *ret = r_list_newf ((RListFree)r_bin_import_free);

	if (!ret || !imports) {
		goto bad_alloc;
	}

	ut32 fcn_idx = 0;
	ut32 table_idx = 0;
	ut32 mem_idx = 0;
	ut32 global_idx = 0;
	void **p;
	r_pvector_foreach (imports, p) {
		RBinWasmImportEntry *import = *p;
		RBinImport *ptr = R_NEW0 (RBinImport);
		if (!ptr) {
			goto bad_alloc;
		}
		ptr->name = strdup (import->field_str);
		ptr->classname = strdup (import->module_str);
		ptr->bind = "NONE";
		switch (import->kind) {
		case R_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = "FUNC";
			ptr->ordinal = fcn_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = "TABLE";
			ptr->ordinal = table_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = "MEM";
			ptr->ordinal = mem_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = "GLOBAL";
			ptr->ordinal = global_idx++;
			break;
		}
		r_list_append (ret, ptr);
	}
	return ret;
bad_alloc:
	r_list_free (ret);
	return NULL;
}

static RList *libs(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("module");
	ret->rclass = strdup ("wasm");
	ret->os = strdup ("WebAssembly");
	ret->arch = strdup ("wasm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("wasm");
	ret->type = strdup ("EXEC");
	ret->bits = 32;
	ret->has_va = 0;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RBinFile *bf) {
	if (!bf || !bf->buf) {
		return 0;
	}
	return r_buf_size (bf->buf);
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	RBuffer *buf = r_buf_new ();
#define B(x, y) r_buf_append_bytes (buf, (const ut8 *)(x), y)
#define D(x) r_buf_append_ut32 (buf, x)
	B ("\x00" "asm", 4);
	B ("\x01\x00\x00\x00", 4);
	return buf;
}

static int get_fcn_offset_from_id(RBinFile *bf, int fcn_idx) {
	// XXX shouldn't the number of functions in imports be considered?
	RBinWasmObj *bin = bf->o->bin_obj;
	RPVector *codes = r_bin_wasm_get_codes (bin);
	if (codes) {
		RBinWasmCodeEntry *func = r_pvector_at (codes, fcn_idx);
		if (func) {
			return func->code;
		}
	}
	return -1;
}

static int getoffset(RBinFile *bf, int type, int idx) {
	switch (type) {
	case 'f': // fcnid -> fcnaddr
		return get_fcn_offset_from_id (bf, idx);
	}
	return -1;
}

static const char *getname(RBinFile *bf, int type, int idx, bool sd) {
	RBinWasmObj *bin = bf->o->bin_obj;
	switch (type) {
	case 'f': // fcnidx
		{
			const char *r = r_bin_wasm_get_function_name (bin, idx);
			return r? strdup (r): NULL;
		}
	}
	return NULL;
}

RBinPlugin r_bin_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly bin plugin",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.size = &size,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &get_imports,
	.info = &info,
	.libs = &libs,
	.get_offset = &getoffset,
	.get_name = &getname,
	.create = &create,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wasm,
	.version = R2_VERSION
};
#endif
