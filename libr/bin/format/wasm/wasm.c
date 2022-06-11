/* radare2 - LGPL - Copyright 2017-2022 - pancake, cgvwzq, Dennis Goodlett */

#include <r_lib.h>
#include <r_bin.h>
#include "wasm.h"

typedef size_t (*ConsumeFcn) (const ut8 *p, const ut8 *bound, ut32 *out_value);
typedef void *(*ParseEntryFcn) (RBuffer *b, ut64 bound);

// RBuffer consume functions
static ut32 consume_r(RBuffer *b, ut64 bound, size_t *n_out, ConsumeFcn consume_fcn) {
	r_return_val_if_fail (b && n_out && consume_fcn, 0);

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
	r_return_val_if_fail (b && bound > 0 && bound < r_buf_size (b), 0);
	*out = 0;

	if (r_buf_tell (b) + len <= bound + 1) {
		if (r_buf_read (b, (ut8 *)out, len) == len) {
			out[len] = 0;
			return true;
		}
	}
	return false;
}

static bool inline consume_str_new(RBuffer *b, ut64 bound, ut32 *len_out, char **str_out) {
	r_return_val_if_fail (str_out, false);
	*str_out = NULL;
	if (len_out) {
		*len_out = 0;
	}

	ut32 len = 0;
	// module_str
	if (consume_u32_r (b, bound, &len)) {
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
#define WASM_IS_DIGIT(c) (c >= '0' && c <= '9')
#define WASM_IS_ENC_HEX(c) (WASM_IS_DIGIT (c) || (c >= 'A' && c <= 'F'))
#define WASM_AFTER_U_NOT_HEX(str, i) (!WASM_IS_ENC_HEX (str[i + 1]) || !WASM_IS_ENC_HEX (str[i + 2]))
#define WASM_AFTER_UNDERSCORE_OK(str, i) (WASM_AFTER_U_NOT_HEX (str, i) || str[i + 3] != '_')
#define WASM_IS_ALPH(c) ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
#define WASM_IS_OK_EXCEPT__(loc, c) (WASM_IS_ALPH (c) || (loc != 0 && WASM_IS_DIGIT (c))) // C functions can't start with [0-9]
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
	for (i = 0; i < len && oi + 4 < maxsize; i++) {
		if (WASM_IS_OK (orig, i, len)) {
			sout[oi++] = orig[i];
		} else {
			oi += snprintf (sout + oi, maxsize - oi, "_%02x_", orig[i]);
		}
	}
	sout[oi++] = '\0';
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
	ut64 cur = r_buf_tell (b);
	if (!b || bound >= r_buf_size (b) || cur > bound) {
		return 0;
	}
	ut32 count = out? out->local_count: 0;
	if (count > 0) {
		if (!(out->locals = R_NEWS0 (struct r_bin_wasm_local_entry_t, count))) {
			return 0;
		}
	}
	ut32 j = 0;
	while (r_buf_tell (b) <= bound && j < count) {
		ut32 *_tmp = out? &out->locals[j].count: NULL;
		if (!consume_u32_r (b, bound, _tmp)) {
			goto beach;
		}
		st8 *_tmp2 = out? (st8 *)&out->locals[j].type: NULL;
		if (!consume_s7_r (b, bound, _tmp2)) {
			goto beach;
		}
		j++;
	}
	if (j != count) {
		goto beach;
	}
	return j;
beach:
	R_FREE (out->locals);
	return 0;
}

static size_t consume_limits_r(RBuffer *b, ut64 bound, struct r_bin_wasm_resizable_limits_t *out) {
	r_return_val_if_fail (b && out, 0);
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
static RList *r_bin_wasm_get_sections_by_id(RList *sections, ut8 id) {
	RList *ret = r_list_newf (NULL);
	if (ret) {
		RBinWasmSection *sec;
		RListIter *iter;
		r_list_foreach (sections, iter, sec) {
			if (sec->id == id) {
				r_list_append (ret, sec);
			}
		}
	}
	return ret;
}

const char *r_bin_wasm_valuetype_to_string (r_bin_wasm_value_type_t type) {
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
		const char *s = r_bin_wasm_valuetype_to_string (vec->types[i]);
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
		ret &= r_strbuf_append (sb, r_bin_wasm_valuetype_to_string (rets->types[0]));
	} else {
		ret &= strbuf_append_type_vec (sb, rets);
	}
	return ret;
}

static const char *r_bin_wasm_type_entry_to_string(RBinWasmTypeEntry *type) {
	r_return_val_if_fail (type, NULL);
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

static void r_bin_wasm_free_codes(RBinWasmCodeEntry *ptr) {
	if (ptr) {
		free (ptr->locals);
		free (ptr->name);
		free (ptr);
	}
}

static void import_entry_free(RBinWasmImportEntry *entry) {
	if (entry) {
		free (entry->module_str);
		free (entry->field_str);
		free (entry);
	}
}

static void export_entry_free(RBinWasmExportEntry *entry) {
	if (entry) {
		free (entry->field_str);
		free (entry);
	}
}

static void wasm_sec_free(RBinWasmSection *sec) {
	if (sec) {
		free (sec->name);
		free (sec);
	}
}

static void wasm_custom_name_local_free(RBinWasmCustomNameLocalName *name) {
	if (name) {
		r_id_storage_free (name->names);
		R_FREE (name);
	}
}

static inline void wasm_custom_local_names_free(RBinWasmCustomNameLocalNames *local) {
	if (local) {
		r_list_free (local->locals);
		R_FREE (local);
	}
}

static void wasm_custom_name_free(RBinWasmCustomNameEntry *cust) {
	if (cust) {
		switch (cust->type) {
		case R_BIN_WASM_NAMETYPE_Module:
			R_FREE (cust->mod_name);
			break;
		case R_BIN_WASM_NAMETYPE_Function:
			if (cust->func) {
				r_id_storage_free (cust->func->names);
				R_FREE (cust->func);
			}
			break;
		case R_BIN_WASM_NAMETYPE_Local:
			wasm_custom_local_names_free (cust->local);
			break;
		case R_BIN_WASM_NAMETYPE_None:
			break;
		default:
			eprintf ("Unkown type: 0x%x\n", cust->type);
			r_warn_if_reached ();
		}
		R_FREE (cust);
	}
}

// Parsing
static RList *get_entries_from_section(RBinWasmObj *bin, RBinWasmSection *sec, ParseEntryFcn parse_entry, RListFree free_entry) {
	r_return_val_if_fail (sec && bin, NULL);

	RList *ret = r_list_newf (free_entry);
	if (!ret) {
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_BUF_SET);
	ut32 r = 0;
	ut64 bound = r_buf_tell (b) + sec->payload_len - 1;
	if (bound >= r_buf_size (b)) {
		goto beach;
	}

	ut32 count;
	if (!consume_u32_r (b, bound, &count)) {
		return NULL;
	}
	while (r_buf_tell (b) <= bound && r < count) {
		void *entry = parse_entry (b, bound);
		if (!entry) {
			goto beach;
		}

		if (!r_list_append (ret, entry)) {
			free_entry (entry);
			// should this jump to beach?
		}
		r++;
	}
	return ret;
beach:
	eprintf ("[wasm] error: beach reading entries for section %s\n", sec->name);
	return ret;
}

static inline ut8 *buf_read_new(RBuffer *b, ut64 len) {
	ut8 *buf = malloc (len);
	if (buf && r_buf_read (b, buf, len) < len) {
		free (buf);
		buf = NULL;
	}
	return buf;
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

static RBinWasmTypeEntry *parse_type_entry(RBuffer *b, ut64 bound, ut32 index) {
	RBinWasmTypeEntry *type = R_NEW0 (RBinWasmTypeEntry);
	if (!type) {
		return NULL;
	}
	type->index = index;
	type->file_offset = r_buf_tell (b);
	if (!consume_u7_r (b, bound, &type->form)) {
		goto beach;
	}
	if (type->form != R_BIN_WASM_VALUETYPE_FUNC) {
		R_LOG_WARN ("Halting types section parsing at invalid type 0x%02x at offset: 0x%" PFMTSZx "\n", type->form, type->file_offset);
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
	r_bin_wasm_type_entry_to_string (type);

	return type;

beach:
	free_type_entry (type);
	return NULL;
}

static void *parse_import_entry(RBuffer *b, ut64 bound) {
	RBinWasmImportEntry *ptr = R_NEW0 (RBinWasmImportEntry);
	if (!ptr) {
		return NULL;
	}

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
	case 0: // Function
		if (!consume_u32_r (b, bound, &ptr->type_f)) {
			goto beach;
		}
		break;
	case 1: // Table
		if (!consume_s7_r (b, bound, (st8 *)&ptr->type_t.elem_type)) {
			goto beach;
		}
		if (!consume_limits_r (b, bound, &ptr->type_t.limits)) {
			goto beach;
		}
		break;
	case 2: // Memory
		if (!consume_limits_r (b, bound, &ptr->type_m.limits)) {
			goto beach;
		}
		break;
	case 3: // Global
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

static void *parse_export_entry(RBuffer *b, ut64 bound) {
	RBinWasmExportEntry *ptr = R_NEW0 (RBinWasmExportEntry);
	if (!ptr) {
		return NULL;
	}
	if (!consume_encoded_name_new (b, bound, &ptr->field_len, &ptr->field_str)) {
		goto beach;
	}
	if (!consume_u7_r (b, bound, &ptr->kind)) {
		goto beach;
	}
	if (!consume_u32_r (b, bound, &ptr->index)) {
		goto beach;
	}
	return ptr;
beach:
	free (ptr);
	return NULL;
}

static void *parse_code_entry(RBuffer *b, ut64 bound) {
	RBinWasmCodeEntry *ptr = R_NEW0 (RBinWasmCodeEntry);
	if (!ptr) {
		return NULL;
	}
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
	r_buf_read (b, &ptr->byte, 1);
	if (ptr->byte != R_BIN_WASM_END_OF_CODE) {
		goto beach;
	}
	return ptr;

beach:
	r_bin_wasm_free_codes (ptr);
	return NULL;
}

static void *parse_data_entry(RBuffer *b, ut64 bound) {
	RBinWasmDataEntry *ptr = R_NEW0 (RBinWasmDataEntry);
	if (!ptr) {
		return NULL;
	}
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

static bool parse_namemap(RBuffer *b, ut64 bound, RIDStorage *map, ut32 *count) {
	size_t i;
	if (!consume_u32_r (b, bound, count)) {
		return false;
	}

	for (i = 0; i < *count; i++) {
		ut32 idx;
		if (!consume_u32_r (b, bound, &idx)) {
			return false;
		}

		char *name = NULL;
		if (!consume_encoded_name_new (b, bound, NULL, &name)) {
			R_FREE (name);
			return false;
		}

		if (!r_id_storage_add (map, name, &idx)) {
			R_FREE (name);
			return false;
		};
	}

	return true;
}

static inline RBinWasmCustomNameLocalName *parse_local_name(RBuffer *b, ut64 bound) {
	RBinWasmCustomNameLocalName *local_name = R_NEW0 (RBinWasmCustomNameLocalName);
	if (local_name) {
		if (!consume_u32_r (b, bound, &local_name->index)) {
			goto beach;
		}

		local_name->names = r_id_storage_new (0, UT32_MAX);
		if (!local_name->names) {
			goto beach;
		}

		if (!parse_namemap (b, bound, local_name->names, &local_name->names_count)) {
			goto beach;
		}

		return local_name;
	}
beach:
	wasm_custom_name_local_free (local_name);
	return NULL;
}

static inline RBinWasmCustomNameLocalNames *parse_custom_names_local(RBuffer *b, ut64 bound) {
	RBinWasmCustomNameLocalNames *local = R_NEW0 (RBinWasmCustomNameLocalNames);
	if (!local) {
		return NULL;
	}
	if (!consume_u32_r (b, bound, &local->count)) {
		goto beach;
	}

	local->locals = r_list_newf ((RListFree)wasm_custom_name_local_free);
	if (local->locals) {
		size_t i;
		for (i = 0; i < local->count; i++) {
			RBinWasmCustomNameLocalName *local_name = parse_local_name (b, bound);
			if (!local_name || !r_list_append (local->locals, local_name)) {
				wasm_custom_name_local_free (local_name);
				goto beach;
			}
		}
		return local;
	}

beach:
	wasm_custom_local_names_free (local);
	return NULL;
}

static RBinWasmCustomNameEntry *parse_custom_name_entry(RBuffer *b, ut64 bound) {
	RBinWasmCustomNameEntry *cust = R_NEW0 (RBinWasmCustomNameEntry);
	if (!cust) {
		return NULL;
	}
	cust->type = R_BIN_WASM_NAMETYPE_None;

	size_t start = r_buf_tell (b);
	if (!consume_u7_r (b, bound, &cust->type)) {
		goto beach;
	};

	if (!consume_u32_r (b, bound, &cust->size)) {
		goto beach;
	};

	switch (cust->type) {
	case R_BIN_WASM_NAMETYPE_Module:
		if (!consume_encoded_name_new (b, bound, NULL, &cust->mod_name)) {
			goto beach;
		}
		break;
	case R_BIN_WASM_NAMETYPE_Function:
		cust->func = R_NEW0 (RBinWasmCustomNameFunctionNames);
		if (!cust->func) {
			goto beach;
		}
		cust->func->names = r_id_storage_new (0, UT32_MAX);
		if (!cust->func->names) {
			goto beach;
		}

		if (!parse_namemap (b, bound, cust->func->names, &cust->func->count)) {
			goto beach;
		}
		break;
	case R_BIN_WASM_NAMETYPE_Local:
		cust->local = parse_custom_names_local (b, bound);
		if (!cust->local) {
			goto beach;
		}
		break;
	default:
		R_LOG_WARN ("[wasm] Halting custom name section parsing at unknown type 0x%x offset 0x%" PFMTSZx "\n", cust->type, start);
		cust->type = R_BIN_WASM_NAMETYPE_None;
		goto beach;
	}

	return cust;
beach:
	wasm_custom_name_free (cust);
	return NULL;
}

static void *parse_memory_entry(RBuffer *b, ut64 bound) {
	RBinWasmMemoryEntry *ptr = R_NEW0 (RBinWasmMemoryEntry);
	if (!ptr) {
		return NULL;
	}
	if (!consume_limits_r (b, bound, &ptr->limits)) {
		goto beach;
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static void *parse_table_entry(RBuffer *b, ut64 bound) {
	RBinWasmTableEntry *ptr = R_NEW0 (RBinWasmTableEntry);
	if (!ptr) {
		return NULL;
	}
	if (!consume_s7_r (b, bound, (st8 *)&ptr->element_type)) {
		goto beach;
	}
	if (!consume_limits_r (b, bound, &ptr->limits)) {
		goto beach;
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static void *parse_global_entry(RBuffer *b, ut64 bound) {
	RBinWasmGlobalEntry *ptr = R_NEW0 (RBinWasmGlobalEntry);
	if (!ptr) {
		return NULL;
	}
	if (!consume_u7_r (b, bound, (ut8 *)&ptr->content_type)) {
		goto beach;
	}
	if (!consume_u1_r (b, bound, &ptr->mutability)) {
		goto beach;
	}
	if (!consume_init_expr_r (b, bound, R_BIN_WASM_END_OF_CODE, NULL)) {
		goto beach;
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static void *parse_element_entry(RBuffer *b, ut64 bound) {
	RBinWasmElementEntry *ptr = R_NEW0 (RBinWasmElementEntry);
	if (!ptr) {
		return NULL;
	}
	if (!consume_u32_r (b, bound, &ptr->index)) {
		goto beach;
	}
	if (!consume_init_expr_r (b, bound, R_BIN_WASM_END_OF_CODE, NULL)) {
		goto beach;
	}
	if (!consume_u32_r (b, bound, &ptr->num_elem)) {
		goto beach;
	}
	ut32 j = 0;
	while (r_buf_tell (b) <= bound && j < ptr->num_elem) {
		// TODO: allocate space and fill entry
		if (!consume_u32_r (b, bound, NULL)) {
			goto beach;
		}
	}
	return ptr;

beach:
	free (ptr);
	return NULL;
}

static RPVector *r_bin_wasm_get_type_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	r_return_val_if_fail (sec && bin, NULL);

	RBuffer *b = bin->buf;
	ut32 data_off = sec->payload_data;
	r_buf_seek (b, data_off, R_BUF_SET);
	ut64 bound = data_off + sec->payload_len - 1;
	if (r_buf_seek (b, data_off, R_BUF_SET) != data_off) {
		return NULL;
	}
	if (bound >= r_buf_size (b)) {
		eprintf ("[wasm] error: beach reading entries for section %s\n", sec->name);
		return NULL;
	}

	ut32 count;
	if (!consume_u32_r (b, bound, &count)) {
		return NULL;
	}

	RPVector *ret = r_pvector_new ((RPVectorFree)free_type_entry);
	if (!ret) {
		return NULL;
	}
	r_pvector_reserve (ret, count);

	ut32 i;
	for (i = 0; i < sec->count; i++) {
		RBinWasmTypeEntry *entry = parse_type_entry (b, bound, i);
		if (!entry || !r_pvector_push (ret, entry)) {
			break;
		}
	}
	return ret;
}

static RList *r_bin_wasm_get_import_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_import_entry, (RListFree)import_entry_free);
}

static RList *r_bin_wasm_get_export_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_export_entry, (RListFree)export_entry_free);
}

static RList *r_bin_wasm_get_code_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_code_entry, (RListFree)r_bin_wasm_free_codes);
}

static RList *r_bin_wasm_get_data_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_data_entry, (RListFree)free);
}

static RBinWasmStartEntry *r_bin_wasm_get_start(RBinWasmObj *bin, RBinWasmSection *sec) {
	RBinWasmStartEntry *ptr;

	if (!(ptr = R_NEW0 (RBinWasmStartEntry))) {
		return NULL;
	}

	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_BUF_SET);
	ut64 bound = r_buf_tell (b) + sec->payload_len - 1;
	if (bound < r_buf_size (b) && consume_u32_r (b, bound, &ptr->index)) {
		return ptr;
	}
	eprintf ("[wasm] header parsing error.\n");
	free (ptr);
	return NULL;
}

static RList *r_bin_wasm_get_memory_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_memory_entry, (RListFree)free);
}

static RList *r_bin_wasm_get_table_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_table_entry, (RListFree)free);
}

static RList *r_bin_wasm_get_global_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_global_entry, (RListFree)free);
}

static RList *r_bin_wasm_get_element_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	return get_entries_from_section (bin, sec, parse_element_entry, (RListFree)free);
}

static RList *r_bin_wasm_get_custom_name_entries(RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = r_list_newf ((RListFree)wasm_custom_name_free);

	RBuffer *buf = bin->buf;

	r_buf_seek (buf, sec->payload_data, R_BUF_SET);
	ut64 bound = sec->payload_data + sec->payload_len - 1;

	if (bound > r_buf_size (buf)) {
		goto beach;
	}

	while (r_buf_tell (buf) < bound) {
		RBinWasmCustomNameEntry *nam = parse_custom_name_entry (buf, bound);

		if (!nam) {
			break; // allow partial parsing of section
		}

		if (!r_list_append (ret, nam)) {
			goto beach;
		}
	}

	return ret;
beach:
	r_list_free (ret);
	return NULL;
}

// Public functions
RBinWasmObj *r_bin_wasm_init(RBinFile *bf, RBuffer *buf) {
	RBinWasmObj *bin = R_NEW0 (RBinWasmObj);
	if (!bin) {
		return NULL;
	}
	bin->buf = r_buf_ref (buf);
	bin->size = (ut32)r_buf_size (bf->buf);
	bin->g_sections = r_bin_wasm_get_sections (bin);
	// TODO: recursive invocation more natural with streamed parsing
	// but dependency problems when sections are disordered (against spec)

	bin->g_types = r_bin_wasm_get_types (bin);
	bin->g_imports = r_bin_wasm_get_imports (bin);
	bin->g_exports = r_bin_wasm_get_exports (bin);
	bin->g_tables = r_bin_wasm_get_tables (bin);
	bin->g_memories = r_bin_wasm_get_memories (bin);
	bin->g_globals = r_bin_wasm_get_globals (bin);
	bin->g_codes = r_bin_wasm_get_codes (bin);
	bin->g_datas = r_bin_wasm_get_datas (bin);

	bin->g_names = r_bin_wasm_get_custom_names (bin);

	// entrypoint from Start section
	bin->entrypoint = r_bin_wasm_get_entrypoint (bin);

	return bin;
}

void wasm_obj_free(RBinWasmObj *bin) {
	if (bin) {
		r_buf_free (bin->buf);
		r_list_free (bin->g_sections);
		r_pvector_free (bin->g_types);
		r_list_free (bin->g_imports);
		r_list_free (bin->g_exports);
		r_list_free (bin->g_tables);
		r_list_free (bin->g_memories);
		r_list_free (bin->g_globals);
		r_list_free (bin->g_codes);
		r_list_free (bin->g_datas);
		r_list_free (bin->g_names);
		free (bin->g_start);
		free (bin);
	}
}

void r_bin_wasm_destroy(RBinFile *bf) {
	if (bf && bf->o) {
		wasm_obj_free (bf->o->bin_obj);
		bf->o->bin_obj = NULL;
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
		if (r_buf_tell (b) + (ut64)ptr->size - 1 > bound) {
			goto beach;
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
			eprintf ("[wasm] error: unkown section id: %d\n", ptr->id);
			r_buf_seek (b, ptr->size - 1, R_BUF_CUR);
			continue;
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
	eprintf ("[wasm] error: beach sections\n");
	free (ptr);
	return ret;
}

ut32 r_bin_wasm_get_entrypoint(RBinWasmObj *bin) {
	RList *secs = NULL;
	RBinWasmStartEntry *start = NULL;
	RBinWasmSection *sec = NULL;
	RBinWasmCodeEntry *func = NULL;

	if (!bin || !bin->g_sections) {
		return 0;
	}
	if (bin->entrypoint) {
		return bin->entrypoint;
	}
	if (bin->g_start) {
		start = bin->g_start;
	} else if (!(secs = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_START))) {
		return 0;
	} else if (!(sec = (RBinWasmSection *)r_list_first (secs))) {
		r_list_free (secs);
		return 0;
	} else {
		start = r_bin_wasm_get_start (bin, sec);
		bin->g_start = start;
	}
	if (!start) {
		r_list_free (secs);
		return 0;
	}
	// FIX: entrypoint can be also an import
	if (!bin->g_codes) {
		r_list_free (secs);
		return 0;
	}
	func = r_list_get_n (bin->g_codes, start->index);
	r_list_free (secs);
	return (ut32) (func ? func->code : 0);
}

RList *r_bin_wasm_get_imports(RBinWasmObj *bin) {
	RBinWasmSection *import = NULL;
	RList *imports = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_imports) {
		return bin->g_imports;
	}
	if (!(imports = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_IMPORT))) {
		return r_list_new ();
	}
	// support for multiple import sections against spec
	if (!(import = (RBinWasmSection *)r_list_first (imports))) {
		r_list_free (imports);
		return r_list_new ();
	}
	bin->g_imports = r_bin_wasm_get_import_entries (bin, import);
	r_list_free (imports);
	return bin->g_imports;
}

RList *r_bin_wasm_get_exports(RBinWasmObj *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinWasmSection *export = NULL;
	RList *exports = NULL;

	if (!bin->g_sections) {
		return NULL;
	}
	if (bin->g_exports) {
		return bin->g_exports;
	}
	if (!(exports = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_EXPORT))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(export = (RBinWasmSection *)r_list_first (exports))) {
		r_list_free (exports);
		return r_list_new ();
	}
	bin->g_exports = r_bin_wasm_get_export_entries (bin, export);
	r_list_free (exports);
	return bin->g_exports;
}

RPVector *r_bin_wasm_get_types(RBinWasmObj *bin) {
	RBinWasmSection *type = NULL;
	RList *types = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_types) {
		return bin->g_types;
	}
	if (!(types = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_TYPE))) {
		return r_pvector_new ((RPVectorFree)free_type_entry);
	}
	// support for multiple export sections against spec
	if (!(type = (RBinWasmSection *)r_list_first (types))) {
		r_list_free (types);
		return r_pvector_new ((RPVectorFree)free_type_entry);
	}
	bin->g_types = r_bin_wasm_get_type_entries (bin, type);
	r_list_free (types);
	return bin->g_types;
}

RList *r_bin_wasm_get_tables(RBinWasmObj *bin) {
	RBinWasmSection *table = NULL;
	RList *tables = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_tables) {
		return bin->g_tables;
	}
	if (!(tables = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_TABLE))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(table = (RBinWasmSection *)r_list_first (tables))) {
		r_list_free (tables);
		return r_list_new ();
	}
	bin->g_tables = r_bin_wasm_get_table_entries (bin, table);
	r_list_free (tables);
	return bin->g_tables;
}

RList *r_bin_wasm_get_memories(RBinWasmObj *bin) {
	RBinWasmSection *memory;
	RList *memories;

	if (!bin || !bin->g_sections) {
		return NULL;
	}

	if (bin->g_memories) {
		return bin->g_memories;
	}

	if (!(memories = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_MEMORY))) {
		return r_list_new ();
	}

	// support for multiple export sections against spec
	if (!(memory = (RBinWasmSection *)r_list_first (memories))) {
		r_list_free (memories);
		return r_list_new ();
	}

	bin->g_memories = r_bin_wasm_get_memory_entries (bin, memory);
	r_list_free (memories);
	return bin->g_memories;
}

RList *r_bin_wasm_get_globals(RBinWasmObj *bin) {
	RBinWasmSection *global = NULL;
	RList *globals = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_globals) {
		return bin->g_globals;
	}
	if (!(globals = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_GLOBAL))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(global = (RBinWasmSection *)r_list_first (globals))) {
		r_list_free (globals);
		return r_list_new ();
	}
	bin->g_globals = r_bin_wasm_get_global_entries (bin, global);
	r_list_free (globals);
	return bin->g_globals;
}

RList *r_bin_wasm_get_elements(RBinWasmObj *bin) {
	RBinWasmSection *element = NULL;
	RList *elements = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_elements) {
		return bin->g_elements;
	}
	if (!(elements = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_ELEMENT))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(element = (RBinWasmSection *)r_list_first (elements))) {
		r_list_free (elements);
		return r_list_new ();
	}
	bin->g_elements = r_bin_wasm_get_element_entries (bin, element);
	r_list_free (elements);
	return bin->g_elements;
}

RList *r_bin_wasm_get_codes(RBinWasmObj *bin) {
	RBinWasmSection *code = NULL;
	RList *codes = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_codes) {
		return bin->g_codes;
	}
	if (!(codes = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_CODE))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(code = (RBinWasmSection *)r_list_first (codes))) {
		r_list_free (codes);
		return r_list_new ();
	}
	bin->g_codes = r_bin_wasm_get_code_entries (bin, code);
	r_list_free (codes);
	return bin->g_codes;
}

RList *r_bin_wasm_get_datas(RBinWasmObj *bin) {
	RBinWasmSection *data = NULL;
	RList *datas = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_datas) {
		return bin->g_datas;
	}
	if (!(datas = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_DATA))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(data = (RBinWasmSection *)r_list_first (datas))) {
		r_list_free (datas);
		return r_list_new ();
	}
	bin->g_datas = r_bin_wasm_get_data_entries (bin, data);
	r_list_free (datas);
	return bin->g_datas;
}

RList *r_bin_wasm_get_custom_names(RBinWasmObj *bin) {
	RList *customs = NULL;

	r_return_val_if_fail (bin && bin->g_sections, NULL);

	if (bin->g_names) {
		return bin->g_names;
	}
	if (!(customs = r_bin_wasm_get_sections_by_id (bin->g_sections, R_BIN_WASM_SECTION_CUSTOM))) {
		return r_list_new ();
	}
	// support for multiple "name" sections against spec
	RBinWasmSection *cust = (RBinWasmSection *)r_list_first (customs);
	if (!cust || !cust->name) {
		r_list_free (customs);
		return r_list_new ();
	}
	if (strcmp (cust->name, "name")) {
		r_list_free (customs);
		return r_list_new ();
	}
	bin->g_names = r_bin_wasm_get_custom_name_entries (bin, cust);
	r_list_free (customs);
	return bin->g_names;
}

const char *r_bin_wasm_get_function_name(RBinWasmObj *bin, ut32 idx) {
	if (!(bin && bin->g_names)) {
		return NULL;
	};

	RListIter *iter;
	RBinWasmCustomNameEntry *nam;
	r_list_foreach (bin->g_names, iter, nam) {
		if (nam->type == R_BIN_WASM_NAMETYPE_Function) {
			const char *n = r_id_storage_get (nam->func->names, idx);
			if (n) {
				return n;
			}
		}
	}

	return NULL;
}
