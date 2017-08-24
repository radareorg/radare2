/* radare2 - LGPL - Copyright 2017 - pancake, cgvwzq */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "wasm.h"

// RBuffer consume functions
static size_t consume_u32_r (RBuffer *b, ut64 max, ut32 *out) {
	size_t n;
	ut32 tmp;
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(n = read_u32_leb128 (&b->buf[b->cur], &b->buf[max + 1], &tmp))) {
		return 0;
	}
	r_buf_seek (b, n, R_IO_SEEK_CUR);
	if (out) {
		*out = tmp;
	}
	return n;
}

#if 0
static size_t consume_s32_r (RBuffer *b, ut64 max, st32 *out) {
	size_t n;
	st32 tmp;
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(n = read_i32_leb128 (&b->buf[b->cur], &b->buf[max + 1], &tmp))) {
		return 0;
	}
	r_buf_seek (b, n, R_IO_SEEK_CUR);
	if (out) {
		*out = tmp;
	}
	return n;
}
#endif

static size_t consume_u7_r (RBuffer *b, ut64 max, ut8 *out) {
	size_t n;
	ut32 tmp;
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(n = read_u32_leb128 (&b->buf[b->cur], &b->buf[max + 1], &tmp))) {
		return 0;
	}
	r_buf_seek (b, n, R_IO_SEEK_CUR);
	if (out) {
		*out = (ut8)(tmp & 0x7f);
	}
	return n;
}

static size_t consume_s7_r (RBuffer *b, ut64 max, st8 *out) {
	size_t n;
	ut32 tmp = 0;
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(n = read_i32_leb128 (&b->buf[b->cur], (ut8*)&b->buf[max + 1], (int*)&tmp)) || n > 2) {
		return 0;
	}
	r_buf_seek (b, n, R_IO_SEEK_CUR);
	if (out) {
		*out = (st8)(((tmp & 0x10000000) << 7) | (tmp & 0x7f));
	}
	return n;
}

static size_t consume_u1_r (RBuffer *b, ut64 max, ut8 *out) {
	size_t n;
	ut32 tmp;
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(n = read_u32_leb128 (&b->buf[b->cur], &b->buf[max + 1], &tmp)) || n > 1) {
		return 0;
	}
	r_buf_seek (b, n, R_IO_SEEK_CUR);
	if (out) {
		*out = (ut8)(tmp & 0x1);
	}
	return n;
}

static size_t consume_str_r (RBuffer *b, ut64 max, size_t sz, char *out) {
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	if (!(b->cur + sz - 1 <= max)) {
		return 0;
	}
	if (sz > 0) {
		strncpy (out, (char*)&b->buf[b->cur], R_MIN (R_BIN_WASM_STRING_LENGTH - 1, sz));
	} else {
		*out = 0;
	}
	r_buf_seek (b, sz, R_IO_SEEK_CUR);
	return sz;
}

static size_t consume_init_expr_r (RBuffer *b, ut64 max, ut8 eoc, void *out) {
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	ut32 i = 0;
	while (b->cur + i <= max && b->buf[b->cur + i] != eoc) {
		// TODO: calc the expresion with the bytcode (ESIL?)
		i++;
	}
	if (*(ut8*)(&b->buf[b->cur + i]) != eoc) {
		return 0;
	}
	r_buf_seek (b, i + 1, R_IO_SEEK_CUR);
	return i + 1;
}

static size_t consume_locals_r (RBuffer *b, ut64 max, RBinWasmCodeEntry *out) {
	if (!b || !b->buf || max >= b->length || b->cur > max) {
		return 0;
	}
	ut32 count = out ? out->local_count : 0;
	if (!(b->cur + (count * 7) <= max)) { // worst case 7 bytes
		return 0;
	}
	if (count > 0) {
		if (!(out->locals = R_NEWS0 (struct r_bin_wasm_local_entry_t, count))) {
			return 0;
		}
	}
	ut32 j = 0;
	while (b->cur <= max && j < count) {
		if (!(consume_u32_r (b, max, (out? &out->locals[j].count: NULL)))) {
			goto beach;
		}
		if (!(consume_s7_r (b, max, (out? (st8*)&out->locals[j].type: NULL)))) {
			goto beach;
		}
		j++;
	}
	if (j != count) goto beach;
	return j;
beach:
	free (out->locals);
	out->locals = NULL;
	return 0;
}

static size_t consume_limits_r (RBuffer *b, ut64 max, struct r_bin_wasm_resizable_limits_t *out) {
	if (!b || !b->buf || max >= b->length || b->cur > max || !out) {
		return 0;
	}
	ut32 i = b->cur;
	if (!(consume_u7_r (b, max, &out->flags))) {
		return 0;
	}
	if (!(consume_u32_r (b, max, &out->initial))) {
		return 0;
	}
	if (out->flags && (!(consume_u32_r (b, max, &out->maximum)))) {
		return 0;
	}
	return (size_t)R_ABS (b->cur - i);
}

// Utils
static RList *r_bin_wasm_get_sections_by_id (RList *sections, ut8 id) {
	RBinWasmSection *sec = NULL;
	RList *ret = r_list_newf (NULL);
	if (!ret) {
		return NULL;
	}
	RListIter *iter;
	r_list_foreach (sections, iter, sec) {
		if (sec->id == id) {
			r_list_append(ret, sec);
		}
	}
	return ret;
}

#if 0
static const char *r_bin_wasm_valuetype_to_string (r_bin_wasm_value_type_t type) {
	switch (type) {
	case R_BIN_WASM_VALUETYPE_i32:
		return r_str_const ("i32");
	case R_BIN_WASM_VALUETYPE_i64:
		return r_str_const ("i62");
	case R_BIN_WASM_VALUETYPE_f32:
		return r_str_const ("f32");
	case R_BIN_WASM_VALUETYPE_f64:
		return r_str_const ("f64");
	default:
		return r_str_const ("?");
	}
}

static char *r_bin_wasm_type_entry_to_string (RBinWasmTypeEntry *ptr) {
	if (!ptr) {
		return NULL;
	}
	char *buf = (char*)calloc (ptr->param_count, 5);
	if (!buf) {
		return NULL;
	}
	int p;
	for (p = 0; p < ptr->param_count; p++) {
		strcat (buf, r_bin_wasm_valuetype_to_string (ptr->param_types[p]));
		if (p < ptr->param_count - 1) {
			strcat (buf, ", ");
		}
	}
	snprintf (ptr->to_str, R_BIN_WASM_STRING_LENGTH, "(%s) -> (%s)",
		(ptr->param_count > 0? buf: ""),
		(ptr->return_count == 1? r_bin_wasm_valuetype_to_string (ptr->return_type): ""));
	free (buf);
	return ptr->to_str;
}
#endif

// Free
static void r_bin_wasm_free_types (RBinWasmTypeEntry *ptr) {
	if (ptr) {
		free (ptr->param_types);
	}
	free (ptr);
}

static void r_bin_wasm_free_codes (RBinWasmCodeEntry *ptr) {
	if (ptr) {
		free (ptr->locals);
	}
	free (ptr);
}

// Parsing
static RList *r_bin_wasm_get_type_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmTypeEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)r_bin_wasm_free_types))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut32 r = 0;
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmTypeEntry))) {
			return ret;
		}
		if (!(consume_u7_r (b, max, &ptr->form))) {
			goto beach;
		}
		// check valid type?
		if (!(consume_u32_r (b, max, &ptr->param_count))) {
			goto beach;
		}
		ut32 count = ptr ? ptr->param_count : 0;
		if (!(b->cur + (count * 3) <= max)) { // worst case 3 bytes
			goto beach;
		}
		if (count > 0) {
			if (!(ptr->param_types = R_NEWS0 (r_bin_wasm_value_type_t, count))) {
				goto beach;
			}
		}
		int j;
		for (j = 0; j < count; j++) {
			if (!(consume_s7_r (b, max, (st8*)&ptr->param_types[j]))) {
				goto beach;
			}
		}
		if (!(consume_u1_r (b, max, (ut8*)&ptr->return_count))) {
			goto beach;
		}
		if (ptr->return_count > 1) {
			goto beach;
		}
		if (ptr->return_count == 1) {
			if (!(consume_s7_r (b, max, (st8*)&ptr->return_type))) {
				goto beach;
			}
		}
		// r_bin_wasm_type_entry_to_string (ptr);
		if (!r_list_append (ret, ptr)) {
			r_bin_wasm_free_types (ptr);
			// should this jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf ("err: beach type entries\n");
	r_bin_wasm_free_types (ptr);
	return ret;
}

static RList *r_bin_wasm_get_import_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmImportEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1; 
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmImportEntry))) {
			return ret;
		}
		if (!(consume_u32_r (b, max, &ptr->module_len))) {
			goto beach;
		}
		if (consume_str_r (b, max, ptr->module_len, ptr->module_str) < ptr->module_len) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->field_len))) {
			goto beach;
		}
		if (consume_str_r (b, max, ptr->field_len, ptr->field_str) < ptr->field_len) {
			goto beach;
		} 
		if (!(consume_u7_r (b, max, &ptr->kind))) {
			goto beach;
		}
		switch (ptr->kind) {
		case 0: // Function
			if (!(consume_u32_r (b, max, &ptr->type_f))) {
				goto beach;
			}
			break;
		case 1: // Table
			if (!(consume_s7_r (b, max, (st8*)&ptr->type_t.elem_type))) {
				goto beach;
			}
			if (!(consume_limits_r (b, max, &ptr->type_t.limits))) {
				goto beach;
			}
			break;
		case 2: // Memory
			if (!(consume_limits_r (b, max, &ptr->type_m.limits))) {
				goto beach;
			}
			break;
		case 3: // Global
			if (!(consume_s7_r (b, max, (st8*)&ptr->type_g.content_type))) {
				goto beach;
			}
			if (!(consume_u1_r (b, max, (ut8*)&ptr->type_g.mutability))) {
				goto beach;
			}
			break;
		default:
			goto beach;
		}
		r_list_append (ret, ptr);
		r++;
	}
	return ret;
beach:
	eprintf("err: beach import entries\n");
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_export_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmExportEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmExportEntry))) {
			return ret;
		}
		if (!(consume_u32_r (b, max, &ptr->field_len))) {
			goto beach;
		}
		if (consume_str_r (b, max, ptr->field_len, ptr->field_str) < ptr->field_len) {
			goto beach;
		}
		if (!(consume_u7_r (b, max, &ptr->kind))) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->index))) {
			goto beach;
		}
		r_list_append (ret, ptr);
		r++;
	}
	return ret;
beach:
	eprintf("err: beach export entries\n");
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_code_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmCodeEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)r_bin_wasm_free_codes))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmCodeEntry))) {
			return ret;
		}
		if (!(consume_u32_r (b, max, &ptr->body_size))) {
			goto beach;
		}
		ut32 j = b->cur;
		if (!(b->cur + ptr->body_size - 1 <= max)) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->local_count))) {
			goto beach;
		}
		if (consume_locals_r (b, max, ptr) < ptr->local_count) {
			goto beach;
		}
		ptr->code = b->cur;
		ptr->len = ptr->body_size - ptr->code + j;
		r_buf_seek(b, ptr->len - 1, R_IO_SEEK_CUR); // consume bytecode
		r_buf_read (b, &ptr->byte, 1);
		if (ptr->byte != R_BIN_WASM_END_OF_CODE) {
			goto beach;
		}
		// search 'r' in function_space, if present get signature from types
		// if export get name
		if (!r_list_append (ret, ptr)) {
			r_bin_wasm_free_codes (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach code entries\n");
	r_bin_wasm_free_codes (ptr);
	return ret;
}

static RList *r_bin_wasm_get_data_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmDataEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmDataEntry))) {
			return ret;
		}
		if (!(consume_u32_r (b, max, &ptr->index))) {
			goto beach;
		}
		if (!(ptr->offset.len = consume_init_expr_r (b, max, R_BIN_WASM_END_OF_CODE, NULL))) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->size))) {	
			goto beach;
		}
		ptr->data = b->cur;
		r_buf_seek (b, ptr->size, R_IO_SEEK_CUR);
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach data entries\n");
	free (ptr);
	return ret;
}

static RBinWasmStartEntry *r_bin_wasm_get_start (RBinWasmObj *bin, RBinWasmSection *sec) {
	RBinWasmStartEntry *ptr;	

	if (!(ptr = R_NEW0 (RBinWasmStartEntry))) {
		return NULL;
	}

	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	if (!(consume_u32_r (b, max, &ptr->index))) {
		goto beach;
	}
	return ptr;
beach:
	eprintf("err: beach start\n");
	free (ptr);
	return NULL;
}

static RList *r_bin_wasm_get_memory_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmMemoryEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max =  b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmMemoryEntry))) {
			return ret;
		}
		if (!(consume_limits_r (b, max, &ptr->limits))) {
			goto beach;
		}
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach memory entries\n");
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_table_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmTableEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmTableEntry))) {
			return ret;
		}
		if (!(consume_s7_r (b, max, (st8*)&ptr->element_type))) {
			goto beach;
		}
		if (!(consume_limits_r (b, max, &ptr->limits))) {
			goto beach;
		}
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach table entries\n");
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_global_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmGlobalEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmGlobalEntry))) {
			return ret;
		}
		if (!(consume_u7_r (b, max, (ut8*)&ptr->content_type))) {
			goto beach;
		}
		if (!(consume_u1_r (b, max, &ptr->mutability))) {
			goto beach;
		}
		if (!(consume_init_expr_r (b, max, R_BIN_WASM_END_OF_CODE, NULL))) {
			goto beach;
		}
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach global entries\n");
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_element_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmElementEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!sec) {
		r_list_free (ret);
		return NULL;
	}
	RBuffer *b = bin->buf;
	r_buf_seek (b, sec->payload_data, R_IO_SEEK_SET);
	ut64 max = b->cur + sec->payload_len - 1;
	if (!(max < b->length)) {
		goto beach;
	}
	ut32 r = 0;
	while (b->cur <= max && r < sec->count) {
		if (!(ptr = R_NEW0 (RBinWasmElementEntry))) {
			return ret;
		}
		if (!(consume_u32_r (b, max, &ptr->index))) {
			goto beach;
		}
		if (!(consume_init_expr_r (b, max, R_BIN_WASM_END_OF_CODE, NULL))) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->num_elem))) {
			goto beach;
		}
		ut32 j = 0;
		while (b->cur <= max && j < ptr->num_elem) {
			// TODO: allocate space and fill entry
			if (!(consume_u32_r (b, max, NULL))) {
				goto beach;
			}
		}
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
		r++;
	}
	return ret;
beach:
	eprintf("err: beach element entries\n");
	free (ptr);
	return ret;
}

// Public functions
RBinWasmObj *r_bin_wasm_init (RBinFile *arch) {
	RBinWasmObj *bin = R_NEW0 (RBinWasmObj);
	if (!bin) {
		return NULL;
	}
	if (!(bin->buf = r_buf_new ())) {
		free (bin);
		return NULL;
	}
	bin->size = (ut32)arch->buf->length;
	if (!r_buf_set_bytes (bin->buf, arch->buf->buf, bin->size)) {
		r_bin_wasm_destroy (arch);
		free (bin);
		return NULL;
	}

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

	// entrypoint from Start section
	bin->entrypoint = r_bin_wasm_get_entrypoint (bin);

	return bin;
}

void r_bin_wasm_destroy (RBinFile *arch) {
	RBinWasmObj *bin;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return;
	}

	bin = arch->o->bin_obj;
	r_buf_free (bin->buf);

	r_list_free (bin->g_sections);
	r_list_free (bin->g_types);

	r_list_free (bin->g_imports);
	r_list_free (bin->g_exports);
	r_list_free (bin->g_tables);
	r_list_free (bin->g_memories);
	r_list_free (bin->g_globals);
	r_list_free (bin->g_codes);
	r_list_free (bin->g_datas);

	free (bin->g_start);
	free (bin);
	arch->o->bin_obj = NULL;
}

RList *r_bin_wasm_get_sections (RBinWasmObj *bin) {
	RList *ret = NULL;
	RBinWasmSection *ptr = NULL;

	if (!bin) {
		return NULL;
	}
	if (bin->g_sections) {
		return bin->g_sections;
	}
	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	RBuffer *b = bin->buf;
	ut64 max = b->length - 1;
	r_buf_seek (b, 8, R_IO_SEEK_SET);
	while (b->cur <= max) {
		if (!(ptr = R_NEW0 (RBinWasmSection))) {
			return ret;
		}
		if (!(consume_u7_r (b, max, &ptr->id))) {
			goto beach;
		}
		if (!(consume_u32_r (b, max, &ptr->size))) {
			goto beach;
		}
		// against spec. TODO: choose criteria for parsing
		if (ptr->size < 1) {
			goto beach;
			// free (ptr);
			// continue;
		}
		if (!(b->cur + (ut64)ptr->size - 1 <= max)) {
			goto beach;
		}
		ptr->count = 0;
		ptr->offset = b->cur;
		switch (ptr->id) {
		case R_BIN_WASM_SECTION_CUSTOM:
			eprintf("custom section: 0x%x, ", (ut32)b->cur);
			if (!(consume_u32_r (b, max, &ptr->name_len))) {
				goto beach;
			}
			if (consume_str_r (b, max, ptr->name_len, ptr->name) < ptr->name_len) {
				goto beach;
			}
			eprintf("name: %s\n", ptr->name);
			break;
		case R_BIN_WASM_SECTION_TYPE:
			eprintf("section type: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "type");
			ptr->name_len = 4;
			break;
		case R_BIN_WASM_SECTION_IMPORT:
			eprintf("section import: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "import");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_FUNCTION:
			eprintf("section function: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "function");
			ptr->name_len = 8;
			break;
		case R_BIN_WASM_SECTION_TABLE:
			eprintf("section table: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "table");
			ptr->name_len = 5;
			break;
		case R_BIN_WASM_SECTION_MEMORY:
			eprintf("section memory: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "memory");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_GLOBAL:
			eprintf("section global: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "global");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_EXPORT:
			eprintf("section export: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "export");
			ptr->name_len = 6;
			break;
		case R_BIN_WASM_SECTION_START:
			eprintf("section start: 0x%x\n", (ut32)b->cur);
			strcpy (ptr->name, "start");
			ptr->name_len = 5;
			break;
		case R_BIN_WASM_SECTION_ELEMENT:
			eprintf("section element: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "element");
			ptr->name_len = 7;
			break;
		case R_BIN_WASM_SECTION_CODE:
			eprintf("section code: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "code");
			ptr->name_len = 4;
			break;
		case R_BIN_WASM_SECTION_DATA:
			eprintf("section data: 0x%x, ", (ut32)b->cur);
			strcpy (ptr->name, "data");
			ptr->name_len = 4;
			break;
		default:
			eprintf("unkown section id: %d\n", ptr->id);
			r_buf_seek (b, ptr->size - 1, R_IO_SEEK_CUR);
			continue;
		}
		if (ptr->id != R_BIN_WASM_SECTION_START
				&& ptr->id != R_BIN_WASM_SECTION_CUSTOM) {
			if (!(consume_u32_r (b, max, &ptr->count))) {
				goto beach;
			}
			eprintf("count %d\n", ptr->count);
		}
		ptr->payload_data = b->cur;
		ptr->payload_len = ptr->size - (ptr->payload_data - ptr->offset);
		if (ptr->payload_len > ptr->size) {
			goto beach;
		}
		r_buf_seek (b, ptr->payload_len, R_IO_SEEK_CUR);
		if (!r_list_append (ret, ptr)) {
			free (ptr);
			// should it jump to beach?
		}
		ptr = NULL;
	}
	bin->g_sections = ret;
	return ret;
beach:
	eprintf("err: beach sections\n");
	free (ptr);
	return ret;
}

ut32 r_bin_wasm_get_entrypoint (RBinWasmObj *bin) {
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
	} else if (!(sec = (RBinWasmSection*) r_list_first (secs))) {
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
	return (ut32)(func? func->code: 0);
}

RList *r_bin_wasm_get_imports (RBinWasmObj *bin) {
	RBinWasmSection *import = NULL;
	RList *imports = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_imports) {
		return bin->g_imports;
	}
	if (!(imports = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_IMPORT))) {
		return r_list_new();
	}
	// support for multiple import sections against spec
	if (!(import = (RBinWasmSection*) r_list_first (imports))) {
		r_list_free (imports);
		return r_list_new();
	}
	bin->g_imports = r_bin_wasm_get_import_entries (bin, import);
	r_list_free (imports);
	return bin->g_imports;
}

RList *r_bin_wasm_get_exports (RBinWasmObj *bin) {
	RBinWasmSection *export = NULL;
	RList *exports = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_exports) {
		return bin->g_exports;
	}
	if (!(exports= r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_EXPORT))) {
		return r_list_new();
	}
	// support for multiple export sections against spec
	if (!(export = (RBinWasmSection*) r_list_first (exports))) {
		r_list_free (exports);
		return r_list_new();
	}
	bin->g_exports = r_bin_wasm_get_export_entries (bin, export);
	r_list_free (exports);
	return bin->g_exports;
}

RList *r_bin_wasm_get_types (RBinWasmObj *bin) {
	RBinWasmSection *type = NULL;
	RList *types = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_types) {
		return bin->g_types;
	}
	if (!(types = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_TYPE))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(type = (RBinWasmSection*) r_list_first (types))) {
		r_list_free (types);
		return r_list_new();
	}
	bin->g_types = r_bin_wasm_get_type_entries (bin, type);
	r_list_free (types);
	return bin->g_types;
}

RList *r_bin_wasm_get_tables (RBinWasmObj *bin) {
	RBinWasmSection *table = NULL;
	RList *tables = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_tables) {
		return bin->g_tables;
	}
	if (!(tables = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_TABLE))) {
		return r_list_new();
	}
	// support for multiple export sections against spec
	if (!(table = (RBinWasmSection*) r_list_first (tables))) {
		r_list_free (tables);
		return r_list_new();
	}
	bin->g_tables = r_bin_wasm_get_table_entries (bin, table);
	r_list_free (tables);
	return bin->g_tables;
}

RList *r_bin_wasm_get_memories (RBinWasmObj *bin) {
	RBinWasmSection *memory;
	RList *memories;

	if (!bin || !bin->g_sections) {
		return NULL;
	}

	if (bin->g_memories) {
		return bin->g_memories;
	}

	if (!(memories = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_MEMORY))) {
		return r_list_new();
	}

	// support for multiple export sections against spec
	if (!(memory = (RBinWasmSection*) r_list_first (memories))) {
		r_list_free (memories);
		return r_list_new();
	}

	bin->g_memories = r_bin_wasm_get_memory_entries (bin, memory);
	r_list_free (memories);
	return bin->g_memories;
}

RList *r_bin_wasm_get_globals (RBinWasmObj *bin) {
	RBinWasmSection *global = NULL;
	RList *globals = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_globals) {
		return bin->g_globals;
	}
	if (!(globals = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_GLOBAL))) {
		return r_list_new();
	}
	// support for multiple export sections against spec
	if (!(global = (RBinWasmSection*) r_list_first (globals))) {
		r_list_free (globals);
		return r_list_new();
	}
	bin->g_globals = r_bin_wasm_get_global_entries (bin, global);
	r_list_free (globals);
	return bin->g_globals;
}

RList *r_bin_wasm_get_elements (RBinWasmObj *bin) {
	RBinWasmSection *element = NULL;
	RList *elements = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_elements) {
		return bin->g_elements;
	}
	if (!(elements = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_ELEMENT))) {
		return r_list_new();
	}
	// support for multiple export sections against spec
	if (!(element = (RBinWasmSection*) r_list_first (elements))) {
		r_list_free (elements);
		return r_list_new();
	}
	bin->g_elements = r_bin_wasm_get_element_entries (bin, element);
	r_list_free (elements);
	return bin->g_elements;
}

RList *r_bin_wasm_get_codes (RBinWasmObj *bin) {
	RBinWasmSection *code = NULL;;
	RList *codes = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_codes) {
		return bin->g_codes;
	}
	if (!(codes = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_CODE))) {
		return r_list_new ();
	}
	// support for multiple export sections against spec
	if (!(code = (RBinWasmSection*) r_list_first (codes))) {
		r_list_free (codes);
		return r_list_new();
	}
	bin->g_codes = r_bin_wasm_get_code_entries (bin, code);
	r_list_free (codes);
	return bin->g_codes;
}

RList *r_bin_wasm_get_datas (RBinWasmObj *bin) {
	RBinWasmSection *data = NULL;
	RList *datas = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_datas) {
		return bin->g_datas;
	}
	if (!(datas = r_bin_wasm_get_sections_by_id (bin->g_sections,
						R_BIN_WASM_SECTION_DATA))) {
		return r_list_new();
	}
	// support for multiple export sections against spec
	if (!(data = (RBinWasmSection*) r_list_first (datas))) {
		r_list_free (datas);
		return r_list_new();
	}
	bin->g_datas = r_bin_wasm_get_data_entries (bin, data);
	r_list_free (datas);
	return bin->g_datas;
}
