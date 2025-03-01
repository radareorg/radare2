/* radare2 - LGPL - Copyright 2017-2024 - pancake, cgvwzq, Dennis Goodlett */

#define R_LOG_ORIGIN "bin.wasm"

#include <r_lib.h>
#include <r_bin.h>
#include "wasm.h"

typedef size_t (*ConsumeFcn) (const ut8 *p, const ut8 *bound, ut32 *out_value);
typedef void *(*ParseEntryFcn) (RBinWasmObj *bin, ut64 bound, ut32 index);

// RBuffer consume functions
static ut32 consume_r(RBuffer *b, ut64 bound, size_t *n_out, ConsumeFcn consume_fcn) {
	R_RETURN_VAL_IF_FAIL (b && n_out && consume_fcn, 0);

	ut32 tmp;
	ut64 cur = r_buf_tell (b);
	if (bound >= r_buf_size (b) || cur > bound) {
		return 0;
	}
	// 16 bytes are enough to store 128bits values
	ut8 *buf = R_NEWS (ut8, 16);
	if (!buf) {
		return 0;
	}
	r_buf_read (b, buf, 16);
	size_t n = consume_fcn (buf, buf + bound + 1, &tmp);
	if (!n) {
		free (buf);
		return 0;
	}
	r_buf_seek (b, cur + n, R_BUF_SET);
	*n_out = n;
	free (buf);
	return tmp;
}

static size_t consume_u32_r(RBuffer *b, ut64 bound, ut32 *out) {
	size_t n = 0;
	ut32 tmp = consume_r (b, bound, &n, read_u32_leb128);
	if (out) {
		*out = tmp;
	}
	return n;
}

static size_t consume_u7_r(RBuffer *b, ut64 bound, ut8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r (b, bound, &n, read_u32_leb128);
	if (out) {
		*out = (ut8) (tmp & 0x7f);
	}
	return n;
}

static size_t consume_s7_r(RBuffer *b, ut64 bound, st8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r (b, bound, &n, (ConsumeFcn)read_i32_leb128);
	if (out) {
		*out = (st8) (((tmp & 0x10000000) << 7) | (tmp & 0x7f));
	}
	return n;
}

static size_t consume_u1_r(RBuffer *b, ut64 bound, ut8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r (b, bound, &n, read_u32_leb128);
	if (out) {
		*out = (ut8) (tmp & 0x1);
	}
	return n;
}

static bool consume_str_r(RBuffer *b, ut64 bound, size_t len, char *out) {
	R_RETURN_VAL_IF_FAIL (b && bound > 0 && bound < r_buf_size (b), 0);
	*out = 0;

	if (r_buf_tell (b) + len <= bound + 1) {
		if (r_buf_read (b, (ut8 *)out, len) == len) {
			out[len] = 0;
			return true;
		}
	}
	return false;
}

static inline bool consume_str_new(RBuffer *b, ut64 bound, ut32 *len_out, char **str_out) {
	R_RETURN_VAL_IF_FAIL (str_out, false);
	*str_out = NULL;
	if (len_out) {
		*len_out = 0;
	}

	ut32 len = 0;
	// module_str
	if (consume_u32_r (b, bound, &len)) {
		if (len > 0xffff) {
			// avoid large allocations can be caused by fuzzed bins
			return false;
		}
		char *str = (char *)malloc (len + 1);
		if (str && consume_str_r (b, bound, len, str)) {
			if (len_out) {
				*len_out = len;
			}
			*str_out = str;
			return true;
		}
		free (str);
	}
	return false;
}

/*
 * Wasm Names are utf-8 character strings. This means '7\x00' is a valid name 2
 * byte name. R2 uses tcc to do C like function declarations, so we encode
 * these functions in a way that can be decoded 1 to 1. Encoding is for char
 * '\xXX' that is not allowed, we encode it as "_XX_" Where XX is [0-9A-Z] (no
 * lower). Should the original function have a substring of the form "_XX_" we
 * encode it as "_5F_XX_".
 */
#define WASM_isdigit(c) (c >= '0' && c <= '9')
#define WASM_IS_ENC_HEX(c) (WASM_isdigit (c) || (c >= 'A' && c <= 'F'))
#define WASM_AFTER_U_NOT_HEX(str, i) (!WASM_IS_ENC_HEX (str[i + 1]) || !WASM_IS_ENC_HEX (str[i + 2]))
#define WASM_AFTER_UNDERSCORE_OK(str, i) (WASM_AFTER_U_NOT_HEX (str, i) || str[i + 3] != '_')
#define WASM_IS_ALPH(c) ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
#define WASM_IS_OK_EXCEPT__(loc, c) (WASM_IS_ALPH (c) || (loc != 0 && WASM_isdigit (c))) // C functions can't start with [0-9]
#define WASM_UNDERSCORE_OK(str, i, max) (str[i] == '_' && (max - i < 4 || WASM_AFTER_UNDERSCORE_OK (str, i)))
#define WASM_IS_OK(str, i, max) (WASM_IS_OK_EXCEPT__ (i, str[i]) || WASM_UNDERSCORE_OK (str, i, max))
static bool consume_encoded_name_new(RBuffer *b, ut64 bound, ut32 *len_out, char **str_out) {
	ut32 len;
	char *orig = NULL;
	if (!consume_str_new (b, bound, &len, &orig)) {
		return false;
	}

	// room for even every character getting encoded
	size_t maxsize = (len * 4) + 2;
	char *sout = malloc (maxsize);
	if (!sout) {
		free (orig);
		return false;
	}

	size_t i, oi = 0;
	for (i = 0; i < len && oi + 6 < maxsize; i++) {
		if (WASM_IS_OK (orig, i, len)) {
			sout[oi++] = orig[i];
		} else {
			int res = snprintf (sout + oi, maxsize - oi, "_%02x_", orig[i]);
			oi += res;
		}
	}
	if (oi >= maxsize) {
		sout[maxsize - 1] = '\0';
	} else {
		sout[oi++] = '\0';
	}
	free (orig);

	char *tmp = realloc (sout, oi);
	if (!tmp) {
		free (sout);
		free (tmp);
		return false;
	}
	*str_out = tmp;
	if (len_out) {
		*len_out = len;
	}
	return true;
}

static size_t consume_init_expr_r(RBuffer *b, ut64 bound, ut8 eoc, void *out) {
	if (!b || bound >= r_buf_size (b) || r_buf_tell (b) > bound) {
		return 0;
	}
	size_t res = 0;
	ut8 cur = r_buf_read8 (b);
	while (r_buf_tell (b) <= bound && cur != eoc) {
		cur = r_buf_read8 (b);
		res++;
	}
	if (cur != eoc) {
		return 0;
	}
	return res + 1;
}

static size_t consume_locals_r(RBuffer *b, ut64 bound, RBinWasmCodeEntry *out) {
	R_RETURN_VAL_IF_FAIL (out, 0);
	ut32 count = out->local_count;
	if ((st32)count < 1 || count > ST16_MAX) {
		return 0;
	}
	out->locals = R_NEWS0 (struct r_bin_wasm_local_entry_t, count);
	if (!out->locals) {
		return 0;
	}

	ut32 i = 0;
	for (i = 0; i < count; i++) {
		struct r_bin_wasm_local_entry_t *local = &out->locals[i];
		if (!consume_u32_r (b, bound, &local->count)) {
			return 0;
		}
		if (!consume_s7_r (b, bound, &local->type)) {
			return 0;
		}
	}
	return i;
}

static size_t consume_limits_r(RBuffer *b, ut64 bound, struct r_bin_wasm_resizable_limits_t *out) {
	R_RETURN_VAL_IF_FAIL (b && out, 0);
	if (bound >= r_buf_size (b) || r_buf_tell (b) > bound || !out) {
		return 0;
	}
	ut32 i = r_buf_tell (b);
	if (!consume_u7_r (b, bound, &out->flags)) {
		return 0;
	}
	if (!consume_u32_r (b, bound, &out->initial)) {
		return 0;
	}
	if (out->flags && !consume_u32_r (b, bound, &out->maximum)) {
		return 0;
	}
	int delta = r_buf_tell (b) - i;
	return (delta > 0)? delta: 0;
}

// Utils
#define CUST_NAME_START "\x04name"
#define CUST_NAME_START_LEN sizeof CUST_NAME_START - 1
static inline RBinWasmSection *sections_first_custom_name(RBinWasmObj *bin) {
	RBuffer *buf = bin->buf;
	RListIter *iter;
	RBinWasmSection *sec;
	r_list_foreach (bin->g_sections, iter, sec) {
		if (sec->id == R_BIN_WASM_SECTION_CUSTOM && sec->size > 6) {
			ut8 _tmp[CUST_NAME_START_LEN] = {0};
			if (r_buf_read_at (buf, sec->offset, _tmp, CUST_NAME_START_LEN) > 0) {
				if (!memcmp (CUST_NAME_START, _tmp, CUST_NAME_START_LEN)) {
					return sec;
				}
			}
		}
	}
	return NULL;
}
#undef CUST_NAME_START
#undef CUST_NAME_START_LEN

static inline RBinWasmSection *section_first_with_id(RList *sections, ut8 id) {
	RBinWasmSection *sec;
	RListIter *iter;
	r_list_foreach (sections, iter, sec) {
		if (sec->id == id) {
			return sec;
		}
	}
	return NULL;
}

const char *r_bin_wasm_valuetype_tostring(r_bin_wasm_value_type_t type) {
	switch (type) {
	case R_BIN_WASM_VALUETYPE_i32:
		return "i32";
	case R_BIN_WASM_VALUETYPE_i64:
		return "i62";
	case R_BIN_WASM_VALUETYPE_f32:
		return "f32";
	case R_BIN_WASM_VALUETYPE_f64:
		return "f64";
	case R_BIN_WASM_VALUETYPE_REFTYPE:
		return "ANYFUNC";
	case R_BIN_WASM_VALUETYPE_FUNC:
		return "FUNC";
	default:
		return "<?>";
	}
}

static inline bool strbuf_append_type_vec(RStrBuf *sb, RBinWasmTypeVec *vec) {
	if (!r_strbuf_append (sb, "(")) {
		return false;
	}
	ut32 i;
	for (i = 0; i < vec->count; i++) {
		if (i > 0 && !r_strbuf_append (sb, ", ")) {
			return false;
		}
		const char *s = r_bin_wasm_valuetype_tostring (vec->types[i]);
		if (!s || !r_strbuf_append (sb, s)) {
			return false;
		}
	}

	if (!r_strbuf_append (sb, ")")) {
		return false;
	}
	return true;
}

static bool append_rets(RStrBuf *sb, RBinWasmTypeVec *rets) {
	bool ret = true;
	if (!rets->count) {
		ret &= r_strbuf_append (sb, "nil");
	} else if (rets->count == 1) {
		ret &= r_strbuf_append (sb, r_bin_wasm_valuetype_tostring (rets->types[0]));
	} else {
		ret &= strbuf_append_type_vec (sb, rets);
	}
	return ret;
}

static const char *r_bin_wasm_type_entry_tostring(RBinWasmTypeEntry *type) {
	R_RETURN_VAL_IF_FAIL (type, NULL);
	if (type->to_str) {
		return type->to_str;
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_reserve (sb, (type->args->count + type->rets->count) * 8);

	bool appended = strbuf_append_type_vec (sb, type->args);
	appended &= r_strbuf_append (sb, " -> ");
	appended &= append_rets (sb, type->rets);
	if (appended) {
		type->to_str = r_strbuf_drain (sb);
	} else {
		r_strbuf_free (sb);
	}
	return type->to_str;
}

// Free
static void free_type_vec(RBinWasmTypeVec *vec) {
	if (vec) {
		free (vec->types);
		free (vec);
	}
}

static void free_type_entry(RBinWasmTypeEntry *ptr) {
	if (ptr) {
		free_type_vec (ptr->args);
		free_type_vec (ptr->rets);
		free (ptr->to_str);
		free (ptr);
	}
}

static void free_import_entry(RBinWasmImportEntry *entry) {
	if (entry) {
		free (entry->module_str);
		free (entry->field_str);
		free (entry);
	}
}

static inline void free_all_imports(RBinWasmObj *bin) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (bin->g_imports_arr); i++) {
		r_pvector_free (bin->g_imports_arr[i]);
	}
	memset (bin->g_imports_arr, 0, sizeof (bin->g_imports_arr));
}

static void free_export_entry(RBinWasmExportEntry *entry) {
	if (entry) {
		free (entry->field_str);
		free (entry);
	}
}

static void free_code_entry(RBinWasmCodeEntry *ptr) {
	if (ptr) {
		free (ptr->locals);
		free (ptr);
	}
}

static void wasm_sec_free(RBinWasmSection *sec) {
	if (sec) {
		free (sec->name);
		free (sec);
	}
}

bool _store_free_cb(void *user, void *data, ut32 id) {
	free (data);
	return true;
}

static inline void storage_deep_free(RIDStorage *store) {
	if (store) {
		r_id_storage_foreach (store, (RIDStorageForeachCb)_store_free_cb, NULL);
		r_id_storage_free (store);
	}
}

static bool _2d_store_free_cb(void *user, void *data, ut32 id) {
	RIDStorage *store = (RIDStorage *)data;
	storage_deep_free (store);
	return true;
}

static inline void free_custom_names(RBinWasmCustomNames *names) {
	if (names) {
		free (names->mod.name);
		storage_deep_free (names->funcs.store);
		if (names->locals.store) {
			r_id_storage_foreach (names->locals.store, (RIDStorageForeachCb)_2d_store_free_cb, NULL);
		}
		free (names);
	}
}

// Parsing
static inline RPVector *parse_vec(RBinWasmObj *bin, ut64 bound, ParseEntryFcn parse_entry, RPVectorFree free_entry) {
	RBuffer *buf = bin->buf;

	ut32 count;
	if (!consume_u32_r (buf, bound, &count)) {
		return NULL;
	}
	if (count > r_buf_size (buf)) {
		count = r_buf_size (buf) - r_buf_tell (buf);
	}
	if ((st32)count < 1) {
		return NULL;
	}

	RPVector *vec = r_pvector_new (free_entry);
	if (vec) {
		if (!r_pvector_reserve (vec, count)) {
			return NULL;
		}
		ut32 i;
		for (i = 0; i < count; i++) {
			ut64 start = r_buf_tell (buf);
			void *e = parse_entry (bin, bound, i);
			if (!e || !r_pvector_push (vec, e)) {
				R_LOG_ERROR ("Failed to parse entry %u/%u of vec at 0x%" PFMT64x, i, count, start);
				free_entry (e);
				break;
			}
		}
	}
	return vec;
}

static inline RBinWasmTypeVec *parse_type_vector(RBuffer *b, ut64 bound) {
	RBinWasmTypeVec *vec = R_NEW0 (RBinWasmTypeVec);
	// types are all ut8, so leb128 shouldn't be needed, we can reuse consume_str_new
	if (vec && !consume_str_new (b, bound, &vec->count, (char **)&vec->types)) {
		free_type_vec (vec);
		return NULL;
	}
	return vec;
}

static RBinWasmTypeEntry *parse_type_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmTypeEntry *type = R_NEW0 (RBinWasmTypeEntry);
	if (!type) {
		return NULL;
	}
	type->sec_i = index;
	type->file_offset = r_buf_tell (b);
	if (!consume_u7_r (b, bound, &type->form)) {
		goto beach;
	}
	if (type->form != R_BIN_WASM_VALUETYPE_FUNC) {
		R_LOG_WARN ("Halting types section parsing at invalid type 0x%02x at offset: 0x%" PFMTSZx, type->form, type->file_offset);
		goto beach;
	}

	type->args = parse_type_vector (b, bound);
	if (!type->args) {
		goto beach;
	}

	type->rets = parse_type_vector (b, bound);
	if (!type->rets) {
		goto beach;
	}
	r_bin_wasm_type_entry_tostring (type);

	return type;

beach:
	free_type_entry (type);
	return NULL;
}

static RBinWasmImportEntry *parse_import_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmImportEntry *ptr = R_NEW0 (RBinWasmImportEntry);
	if (!ptr) {
		return NULL;
	}
	ptr->sec_i = index;
	ptr->file_offset = r_buf_tell (b);

	if (!consume_encoded_name_new (b, bound, &ptr->module_len, &ptr->module_str)) {
		goto beach;
	}

	if (!consume_encoded_name_new (b, bound, &ptr->field_len, &ptr->field_str)) {
		goto beach;
	}

	if (!consume_u7_r (b, bound, &ptr->kind)) {
		goto beach;
	}
	switch (ptr->kind) {
	case R_BIN_WASM_EXTERNALKIND_Function:
		if (!consume_u32_r (b, bound, &ptr->type_f)) {
			goto beach;
		}
		break;
	case R_BIN_WASM_EXTERNALKIND_Table:
		if (!consume_s7_r (b, bound, (st8 *)&ptr->type_t.elem_type)) {
			goto beach;
		}
		if (!consume_limits_r (b, bound, &ptr->type_t.limits)) {
			goto beach;
		}
		break;
	case R_BIN_WASM_EXTERNALKIND_Memory:
		if (!consume_limits_r (b, bound, &ptr->type_m.limits)) {
			goto beach;
		}
		break;
	case R_BIN_WASM_EXTERNALKIND_Global:
		if (!consume_s7_r (b, bound, (st8 *)&ptr->type_g.content_type)) {
			goto beach;
		}
		if (!consume_u1_r (b, bound, (ut8 *)&ptr->type_g.mutability)) {
			goto beach;
		}
		break;
	default:
		goto beach;
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static RBinWasmFunctionEntry *parse_function_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmFunctionEntry *func = R_NEW0 (RBinWasmFunctionEntry);
	if (func && consume_u32_r (b, bound, &func->typeindex)) {
		func->sec_i = index;
		func->file_offset = r_buf_tell (b);
		return func;
	}
	free (func);
	return NULL;
}

static RBinWasmExportEntry *parse_export_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmExportEntry *export = R_NEW0 (RBinWasmExportEntry);
	if (export) {
		export->sec_i = index;
		export->file_offset = r_buf_tell (b);
		if (!consume_encoded_name_new (b, bound, &export->field_len, &export->field_str)) {
			goto beach;
		}
		if (!consume_u7_r (b, bound, &export->kind)) {
			goto beach;
		}
		if (!consume_u32_r (b, bound, &export->index)) {
			goto beach;
		}
	}
	return export;
beach:
	free_export_entry (export);
	return NULL;
}

static RBinWasmCodeEntry *parse_code_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmCodeEntry *ptr = R_NEW0 (RBinWasmCodeEntry);
	if (!ptr) {
		return NULL;
	}
	ptr->sec_i = index;
	ptr->file_offset = r_buf_tell (b);
	if (!consume_u32_r (b, bound, &ptr->body_size)) {
		goto beach;
	}
	ut32 j = r_buf_tell (b);
	if (r_buf_tell (b) + ptr->body_size - 1 > bound) {
		goto beach;
	}
	if (!consume_u32_r (b, bound, &ptr->local_count)) {
		goto beach;
	}
	if (consume_locals_r (b, bound, ptr) < ptr->local_count) {
		goto beach;
	}
	ptr->code = r_buf_tell (b);
	ptr->len = ptr->body_size - ptr->code + j;
	r_buf_seek (b, ptr->len - 1, R_BUF_CUR); // consume bytecode
	ut8 end;
	r_buf_read (b, &end, 1);
	if (end != R_BIN_WASM_END_OF_CODE) {
		ut32 where = r_buf_tell (b) - 1;
		R_LOG_WARN ("Wasm code entry at starting at 0x%x has ending byte 0x%x at 0x%x, should be 0x%x",
			(ut32)ptr->file_offset, end, where, R_BIN_WASM_END_OF_CODE);
		goto beach;
	}
	return ptr;

beach:
	free_code_entry (ptr);
	return NULL;
}

static RBinWasmDataEntry *parse_data_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmDataEntry *ptr = R_NEW0 (RBinWasmDataEntry);
	if (!ptr) {
		return NULL;
	}
	ptr->sec_i = index;
	ptr->file_offset = r_buf_tell (b);
	if (!consume_u32_r (b, bound, &ptr->index)) {
		goto beach;
	}
	if (!(ptr->offset.len = consume_init_expr_r (b, bound, R_BIN_WASM_END_OF_CODE, NULL))) {
		goto beach;
	}
	if (!consume_u32_r (b, bound, &ptr->size)) {
		goto beach;
	}
	ptr->data = r_buf_tell (b);
	r_buf_seek (b, ptr->size, R_BUF_CUR);
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static RIDStorage *parse_namemap(RBuffer *b, ut64 bound) {
	RIDStorage *store = r_id_storage_new (0, UT32_MAX);
	ut32 i, count;
	if (store && consume_u32_r (b, bound, &count)) {
		for (i = 0; i < count; i++) {
			ut32 idx;
			if (!consume_u32_r (b, bound, &idx)) {
				break;
			}

			char *name = NULL;
			if (!consume_encoded_name_new (b, bound, NULL, &name)) {
				R_FREE (name);
				break;
			}

			if (!r_id_storage_add (store, name, &idx)) {
				R_FREE (name);
				break;
			};
		}
	}
	return store;
}

static inline RIDStorage *parse_custom_names_local(RBuffer *b, ut64 bound) {
	RIDStorage *store = r_id_storage_new (0, UT32_MAX);
	ut32 i, count;
	if (store && consume_u32_r (b, bound, &count)) {
		for (i = 0; i < count; i++) {
			ut32 idx;
			if (!consume_u32_r (b, bound, &idx)) {
				break;
			}
			RIDStorage *funcstore = parse_namemap (b, bound);
			if (!funcstore || !r_id_storage_add (store, funcstore, &idx)) {
				storage_deep_free (funcstore);
				break;
			}
		}
	}
	return store;
}

static inline bool parse_custom_name_section(RBinWasmObj *bin, ut64 bound) {
	RBinWasmCustomNames *names = bin->names;
	RBuffer *b = bin->buf;
	ut64 start = r_buf_tell (b);
	ut8 type;
	if (!consume_u7_r (b, bound, &type)) {
		return false;
	};

	ut32 size;
	if (!consume_u32_r (b, bound, &size)) {
		return false;
	}

	ut64 new_bound = start + size - 1;
	if (new_bound > bound) {
		R_LOG_WARN ("custom name subection at 0x%" PFMT64x " extends beyond the custom section", start);
		new_bound = bound;
	}

	switch (type) {
	case R_BIN_WASM_NAMETYPE_Module:
		if (names->mod.name) {
			eprintf ("[wasm] Multiple module names in custom name section! first: 0x%" PFMT64x ", this: 0x%" PFMT64x "\n", names->mod.file_offset, start);
		} else if (!consume_encoded_name_new (b, bound, NULL, &names->mod.name)) {
			eprintf ("[wasm] Custom Name section corrupt module name at 0x%" PFMT64x "\n", start);
		} else {
			names->mod.file_offset = start;
		}
		break;
	case R_BIN_WASM_NAMETYPE_Function:
		if (names->funcs.store) {
			eprintf ("[wasm] Multiple function susbections in custom name section! first: 0x%" PFMT64x ", this: 0x%" PFMT64x "\n", names->funcs.file_offset, start);
		} else {
			names->funcs.file_offset = start;
			names->funcs.store = parse_namemap (b, bound);
		}
		break;
	case R_BIN_WASM_NAMETYPE_Local:
		if (names->locals.store) {
			eprintf ("[wasm] Multiple locals susbections in custom name section! first: 0x%" PFMT64x ", this: 0x%" PFMT64x "\n", names->locals.file_offset, start);
		} else {
			names->funcs.file_offset = start;
			names->locals.store = parse_custom_names_local (b, bound);
		}
		break;
	default:
		R_LOG_WARN ("Unknown custom name subsection with id: %d", type);
		break;
	}

	// even if a custom section fails to parse, as long as we have length we can try to parse the next one
	r_buf_seek (b, bound + 1, R_BUF_SET);
	return true;
}

static RBinWasmMemoryEntry *parse_memory_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmMemoryEntry *ptr = R_NEW0 (RBinWasmMemoryEntry);
	if (ptr) {
		ptr->sec_i = index;
		ptr->file_offset = r_buf_tell (b);
		if (!consume_limits_r (b, bound, &ptr->limits)) {
			free (ptr);
			return NULL;
		}
	}
	return ptr;
}

static RBinWasmTableEntry *parse_table_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmTableEntry *table = R_NEW0 (RBinWasmTableEntry);
	if (table) {
		table->sec_i = index;
		table->file_offset = r_buf_tell (b);
		if (!consume_s7_r (b, bound, (st8 *)&table->element_type)) {
			goto beach;
		}
		if (!consume_limits_r (b, bound, &table->limits)) {
			goto beach;
		}
	}
	return table;

beach:
	free (table);
	return NULL;
}

static RBinWasmGlobalEntry *parse_global_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmGlobalEntry *ptr = R_NEW0 (RBinWasmGlobalEntry);
	if (ptr) {
		ptr->sec_i = index;
		ptr->file_offset = r_buf_tell (b);
		if (!consume_u7_r (b, bound, (ut8 *)&ptr->content_type)) {
			goto beach;
		}
		if (!consume_u1_r (b, bound, &ptr->mutability)) {
			goto beach;
		}
		if (!consume_init_expr_r (b, bound, R_BIN_WASM_END_OF_CODE, NULL)) {
			goto beach;
		}
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static RBinWasmElementEntry *parse_element_entry(RBinWasmObj *bin, ut64 bound, ut32 index) {
	RBuffer *b = bin->buf;
	RBinWasmElementEntry *elem = R_NEW0 (RBinWasmElementEntry);
	if (elem) {
		elem->sec_i = index;
		elem->file_offset = r_buf_tell (b);
		if (!consume_u32_r (b, bound, &elem->index)) {
			goto beach;
		}
		if (!consume_init_expr_r (b, bound, R_BIN_WASM_END_OF_CODE, NULL)) {
			goto beach;
		}
		if (!consume_u32_r (b, bound, &elem->num_elem)) {
			goto beach;
		}
		ut32 j = 0;
		while (r_buf_tell (b) <= bound && j < elem->num_elem) {
			// TODO: allocate space and fill entry
			if (!consume_u32_r (b, bound, NULL)) {
				goto beach;
			}
		}
	}
	return elem;

beach:
	free (elem);
	return NULL;
}

static ut32 r_bin_wasm_get_start(RBinWasmObj *bin) {
	if (bin->g_start == UT32_MAX) {
		RBinWasmSection *sec = section_first_with_id (bin->g_sections, R_BIN_WASM_SECTION_START);
		if (sec) {
			RBuffer *b = bin->buf;
			r_buf_seek (b, sec->payload_data, R_BUF_SET);
			ut64 bound = r_buf_tell (b) + sec->payload_len - 1;
			if (!consume_u32_r (b, bound, &bin->g_start)) {
				bin->g_start = UT32_MAX;
			}
		}
	}
	return bin->g_start;
}

static inline bool r_bin_wasm_get_custom_name_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	RBuffer *buf = bin->buf;
	r_buf_seek (buf, sec->payload_data, R_BUF_SET);
	ut64 bound = sec->payload_data + sec->payload_len - 1;

	R_RETURN_VAL_IF_FAIL (bound <= r_buf_size (buf), false); // should be checked in section parsing
	if (!bin->names) {
		bin->names = R_NEW0 (RBinWasmCustomNames);
		if (!bin->names) {
			return false;
		}
	}

	while (r_buf_tell (buf) < bound) {
		if (!parse_custom_name_section (bin, bound)) {
			break;
		}
	}

	return bin->names != NULL;
}

static bool parse_import_sec(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, false);
	// each import type has seperate index space, so we parse them into 4 vecs
	free_all_imports (bin); // ensure all are empty

	int i;
	for (i = 0; i < R_ARRAY_SIZE (bin->g_imports_arr); i++) {
		bin->g_imports_arr[i] = r_pvector_new ((RPVectorFree)free_import_entry);
		if (!bin->g_imports_arr[i]) {
			return false;
		}
	}

	RBinWasmSection *sec = section_first_with_id (bin->g_sections, R_BIN_WASM_SECTION_IMPORT);
	if (!sec) {
		return true; // not an error, empty import section
	}

	RBuffer *buf = bin->buf;
	ut64 offset = sec->payload_data;
	ut64 len = sec->payload_len;
	ut64 bound = offset + len - 1;

	if (r_buf_seek (buf, offset, R_BUF_SET) != offset) {
		return false;
	}

	ut32 count;
	if (!consume_u32_r (buf, bound, &count)) {
		return false;
	}
	if (count > 0xfffff) {
		return false;
	}

	// over estimate size, shrink later
	for (i = 0; i < R_ARRAY_SIZE (bin->g_imports_arr); i++) {
		if (!r_pvector_reserve (bin->g_imports_arr[i], count)) {
			R_LOG_ERROR ("Unable to allocate %d in import array", count);
			return false;
		}
	}

	for (i = 0; i < count; i++) {
		ut64 start = r_buf_tell (buf);
		RBinWasmImportEntry *imp = parse_import_entry (bin, bound, i);
		if (imp && imp->kind < R_ARRAY_SIZE (bin->g_imports_arr)) {
			r_pvector_push (bin->g_imports_arr[imp->kind], imp);
		} else {
			R_LOG_ERROR ("Failed to parse import entry %u/%u of vec at 0x%" PFMT64x, i, count, start);
			free_import_entry (imp);
			break;
		}
	}

	ut32 seen = 0;
	for (i = 0; i < R_ARRAY_SIZE (bin->g_imports_arr); i++) {
		r_pvector_shrink (bin->g_imports_arr[i]);
		seen += r_pvector_length (bin->g_imports_arr[i]);
	}
	return seen == count? true: false;
}

// Public functions
RBinWasmObj *r_bin_wasm_init(RBinFile *bf, RBuffer *buf) {
	RBinWasmObj *bin = R_NEW0 (RBinWasmObj);
	if (bin) {
		bin->g_start = UT32_MAX;
		bin->buf = r_buf_ref (buf);
		bin->size = (ut32)r_buf_size (bf->buf);
		bin->g_sections = r_bin_wasm_get_sections (bin);
		// TODO: recursive invocation more natural with streamed parsing
		// but dependency problems when sections are disordered (against spec)

		bin->g_types = r_bin_wasm_get_types (bin);
		parse_import_sec (bin);
		bin->g_funcs = r_bin_wasm_get_functions (bin);
		bin->g_tables = r_bin_wasm_get_tables (bin);
		bin->g_memories = r_bin_wasm_get_memories (bin);
		bin->g_globals = r_bin_wasm_get_globals (bin);
		bin->g_exports = r_bin_wasm_get_exports (bin);
		bin->g_codes = r_bin_wasm_get_codes (bin);
		bin->g_datas = r_bin_wasm_get_datas (bin);

		r_bin_wasm_get_custom_names (bin);

		// entrypoint from Start section
		bin->entrypoint = r_bin_wasm_get_entrypoint (bin);
	}
	return bin;
}

void wasm_obj_free(RBinWasmObj *bin) {
	if (bin) {
		r_buf_free (bin->buf);
		r_list_free (bin->g_sections);
		r_pvector_free (bin->g_types);
		free_all_imports (bin);
		r_pvector_free (bin->g_funcs);
		r_pvector_free (bin->g_tables);
		r_pvector_free (bin->g_memories);
		r_pvector_free (bin->g_globals);
		r_pvector_free (bin->g_exports);
		r_pvector_free (bin->g_elements);
		r_pvector_free (bin->g_codes);
		r_pvector_free (bin->g_datas);
		free_custom_names (bin->names);
		free (bin);
	}
}

void r_bin_wasm_destroy(RBinFile *bf) {
	if (bf && bf->bo) {
		wasm_obj_free (bf->bo->bin_obj);
		bf->bo->bin_obj = NULL;
	}
}

RList *r_bin_wasm_get_sections(RBinWasmObj *bin) {
	RList *ret = NULL;
	RBinWasmSection *ptr = NULL;

	if (!bin) {
		return NULL;
	}
	if (bin->g_sections) {
		return bin->g_sections;
	}
	if (!(ret = r_list_newf ((RListFree)wasm_sec_free))) {
		return NULL;
	}
	RBuffer *b = bin->buf;
	ut64 bound = r_buf_size (b) - 1;
	r_buf_seek (b, 8, R_BUF_SET);
	while (r_buf_tell (b) <= bound) {
		if (!(ptr = R_NEW0 (RBinWasmSection))) {
			return ret;
		}
		if (!consume_u7_r (b, bound, &ptr->id)) {
			goto beach;
		}
		if (!consume_u32_r (b, bound, &ptr->size)) {
			goto beach;
		}
		// against spec. TODO: choose criteria for parsing
		if (ptr->size < 1) {
			goto beach;
			// free (ptr);
			// continue;
		}
		ptr->offset = r_buf_tell (b);
		switch (ptr->id) {
		case R_BIN_WASM_SECTION_CUSTOM:
			// eprintf("custom section: 0x%x, ", (ut32)b->cur);
			if (!consume_encoded_name_new (b, bound, &ptr->name_len, &ptr->name)) {
				goto beach;
			}
			break;
		case R_BIN_WASM_SECTION_TYPE:
			// eprintf("section type: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("type");
			ptr->name_len = 4;
			break;
		case R_BIN_WASM_SECTION_IMPORT:
			// eprintf("section import: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("import");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_FUNCTION:
			// eprintf("section function: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("function");
			ptr->name_len = 8;
			break;
		case R_BIN_WASM_SECTION_TABLE:
			// eprintf("section table: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("table");
			ptr->name_len = 5;
			break;
		case R_BIN_WASM_SECTION_MEMORY:
			// eprintf("section memory: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("memory");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_GLOBAL:
			// eprintf("section global: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("global");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_EXPORT:
			// eprintf("section export: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("export");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_START:
			// eprintf("section start: 0x%x\n", (ut32)b->cur);
			ptr->name = strdup ("start");
			ptr->name_len = 5;
			break;
		case R_BIN_WASM_SECTION_ELEMENT:
			// eprintf("section element: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("element");
			ptr->name_len = 7;
			break;
		case R_BIN_WASM_SECTION_CODE:
			// eprintf("section code: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("code");
			ptr->name_len = 4;
			break;
		case R_BIN_WASM_SECTION_DATA:
			// eprintf("section data: 0x%x, ", (ut32)b->cur);
			ptr->name = strdup ("data");
			ptr->name_len = 4;
			break;
		default:
			R_LOG_ERROR ("unknown section id: %d", ptr->id);
			r_buf_seek (b, ptr->size - 1, R_BUF_CUR);
			continue;
		}
		if (ptr->offset + (ut64)ptr->size - 1 > bound) {
			// TODO: Better error handling here
			ut32 diff = ptr->size - (bound + 1 - ptr->offset);
			R_LOG_INFO ("Artificially reducing size of section %s by 0x%x bytes so it fits in the file", ptr->name, diff);
			ptr->size -= diff;
		}
		ptr->payload_data = r_buf_tell (b);
		ptr->payload_len = ptr->size - (ptr->payload_data - ptr->offset);
		if (ptr->payload_len > ptr->size) {
			goto beach;
		}
		r_buf_seek (b, ptr->payload_len, R_BUF_CUR);
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
	}
	bin->g_sections = ret;
	return ret;
beach:
	R_LOG_ERROR ("beach sections");
	free (ptr);
	return ret;
}

ut32 r_bin_wasm_get_entrypoint(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, 0);

	if (bin->entrypoint) {
		return bin->entrypoint;
	}
	ut32 start = r_bin_wasm_get_start (bin);
	RPVector *code = r_bin_wasm_get_codes (bin);
	// FIX: entrypoint can be also an import
	if (code && start != UT32_MAX) {
		RBinWasmCodeEntry *func = r_pvector_at (code, start);
		return func? func->code: 0;
	}
	return 0;
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

static RPVector *parse_sub_section_vec(RBinWasmObj *bin, RBinWasmSection *sec) {
	RPVectorComparator sorter = NULL;
	RPVector **cache = NULL;
	RPVectorFree pfree = (RPVectorFree)free;
	ParseEntryFcn parser;
	switch (sec->id) {
	case R_BIN_WASM_SECTION_TYPE:
		parser = (ParseEntryFcn)parse_type_entry;
		pfree = (RPVectorFree)free_type_entry;
		cache = &bin->g_types;
		break;
	case R_BIN_WASM_SECTION_FUNCTION:
		parser = (ParseEntryFcn)parse_function_entry;
		cache = &bin->g_funcs;
		break;
	case R_BIN_WASM_SECTION_TABLE:
		parser = (ParseEntryFcn)parse_table_entry;
		cache = &bin->g_tables;
		break;
	case R_BIN_WASM_SECTION_MEMORY:
		parser = (ParseEntryFcn)parse_memory_entry;
		cache = &bin->g_memories;
		break;
	case R_BIN_WASM_SECTION_GLOBAL:
		parser = (ParseEntryFcn)parse_global_entry;
		cache = &bin->g_globals;
		break;
	case R_BIN_WASM_SECTION_EXPORT:
		parser = (ParseEntryFcn)parse_export_entry;
		pfree = (RPVectorFree)free_export_entry;
		cache = &bin->g_exports;
		sorter = (RPVectorComparator)_export_sorter;
		break;
	case R_BIN_WASM_SECTION_ELEMENT:
		parser = (ParseEntryFcn)parse_element_entry;
		cache = &bin->g_elements;
		break;
	case R_BIN_WASM_SECTION_CODE:
		parser = (ParseEntryFcn)parse_code_entry;
		pfree = (RPVectorFree)free_code_entry;
		cache = &bin->g_codes;
		break;
	case R_BIN_WASM_SECTION_DATA:
		parser = (ParseEntryFcn)parse_data_entry;
		cache = &bin->g_datas;
		break;
	default:
		return NULL;
	}

	RBuffer *buf = bin->buf;
	ut64 offset = sec->payload_data;
	ut64 len = sec->payload_len;
	ut64 bound = offset + len - 1;

	if (bound >= r_buf_size (buf)) {
		R_WARN_IF_REACHED (); // section parsing should prevent this
		eprintf ("[wasm] End of %s section data is beyond file end\n", sec->name);
		return NULL;
	}
	if (r_buf_seek (buf, offset, R_BUF_SET) != offset) {
		return NULL;
	}

	*cache = parse_vec (bin, bound, parser, pfree);
	if (sorter) {
		r_pvector_sort (*cache, sorter);
	}
	return *cache;
}

// warns if there are two sections of this type
static inline RPVector *parse_unique_subsec_vec_by_id(RBinWasmObj *bin, ut8 id) {
	RBinWasmSection *sec = section_first_with_id (bin->g_sections, id);
	if (sec) {
		return parse_sub_section_vec (bin, sec);
	}
	return false;
}

RPVector *r_bin_wasm_get_types(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_types? bin->g_types: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_TYPE);
}

RPVector *r_bin_wasm_get_imports_kind(RBinWasmObj *bin, ut32 kind) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections && kind < R_ARRAY_SIZE (bin->g_imports_arr), NULL);
	RPVector **vec = &bin->g_imports_arr[kind];
	if (!*vec) {
		parse_import_sec (bin);
	}
	return *vec;
}

RPVector *r_bin_wasm_get_functions(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_funcs? bin->g_funcs: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_FUNCTION);
}

RPVector *r_bin_wasm_get_tables(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_tables? bin->g_tables: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_TABLE);
}

RPVector *r_bin_wasm_get_memories(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_memories? bin->g_memories: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_MEMORY);
}

RPVector *r_bin_wasm_get_globals(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_globals? bin->g_globals: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_GLOBAL);
}

RPVector *r_bin_wasm_get_exports(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_exports? bin->g_exports: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_EXPORT);
}

RPVector *r_bin_wasm_get_elements(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_elements? bin->g_elements: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_ELEMENT);
}

RPVector *r_bin_wasm_get_codes(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_codes? bin->g_codes: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_CODE);
}

RPVector *r_bin_wasm_get_datas(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	return bin->g_datas? bin->g_datas: parse_unique_subsec_vec_by_id (bin, R_BIN_WASM_SECTION_DATA);
}

RBinWasmCustomNames *r_bin_wasm_get_custom_names(RBinWasmObj *bin) {
	R_RETURN_VAL_IF_FAIL (bin && bin->g_sections, NULL);
	if (bin->names) {
		return bin->names;
	}

	// support for multiple "name" sections against spec
	RBinWasmSection *sec = sections_first_custom_name (bin);
	if (sec) {
		r_bin_wasm_get_custom_name_entries (bin, sec);
	}
	return bin->names;
}

const char *r_bin_wasm_get_function_name(RBinWasmObj *bin, ut32 idx) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);

	if (bin->names && bin->names->funcs.store) {
		return r_id_storage_get (bin->names->funcs.store, idx);
	}
	return NULL;
}
