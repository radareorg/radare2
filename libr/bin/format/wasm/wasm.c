/* radare2 - LGPL - Copyright 2017 - pancake, cgvwzq */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "wasm.h"

// Consume functions
static size_t consume_u32 (ut8 *buf, ut8 *max, ut32 *out, ut32 *offset) {
	size_t n;
	if (!buf || !max || !out) {
		return 0;
	}
	if (!(n = read_u32_leb128 (buf, max, out)) || n > 5) {
		return 0;
	}
	if (offset) {
		*offset += n;
	}
	return n;
}

static size_t consume_s32 (ut8 *buf, ut8 *max, st32 *out, ut32 *offset) {
	size_t n;
	if (!buf || !max || !out) {
		return 0;
	}
	if (!(n = read_i32_leb128 (buf, max, out)) || n > 5) {
		return 0;
	}
	if (offset) {
		*offset += n;
	}
	return n;
}

static size_t consume_u8 (ut8 *buf, ut8 *max, ut8 *out, ut32 *offset) {
	size_t n;
	ut32 tmp;
	if (!(n = consume_u32 (buf, max, &tmp, offset)) || n > 1) {
		return 0;
	}
	*out = tmp & 0x7f;
	return 1;	
}

static size_t consume_s8 (ut8 *buf, ut8 *max, st8 *out, ut32 *offset) {
	size_t n;
	ut32 tmp;
	if (!(n = consume_u32 (buf, max, &tmp, offset)) || n > 1) {
		return 0;
	}
	*out = (st8)(tmp & 0x7f);
	return 1;	
}

static size_t consume_str (ut8 *buf, ut8 *max, size_t sz, char *out, ut32 *offset) {
	if (!buf || !max || !out || !sz) {
		return 0;
	}
	if (!(buf + sz < max)) {
		return 0;
	}
	strncpy ((char*)out, (char*)buf, R_MIN (R_BIN_WASM_STRING_LENGTH-1, sz));
	if (offset) *offset += sz;
	return sz;
}
static size_t consume_init_expr (ut8 *buf, ut8 *max, ut8 eoc, void *out, ut32 *offset) {
	ut32 i = 0;
	while (buf + i < max && buf[i] != eoc) {
		// TODO: calc the expresion with the bytcode (ESIL?)
		i += 1;
	}
	if (buf[i] != eoc) {
		return 0;
	}
	if (offset) {
		*offset += i + 1;
	}
	return i + 1;
}

static size_t consume_locals (ut8 *buf, ut8 *max, ut32 count, RBinWasmCodeEntry *out, ut32 *offset) {
	ut32 i = 0, j = 0;
	if (count < 1) return 0;
	// memory leak
	if (!(out->locals = (struct r_bin_wasm_local_entry_t*) malloc (sizeof(struct r_bin_wasm_local_entry_t) * count))) {
		return 0;
	}
	while (buf + i < max && j < count) {
		if (!(consume_u32 (buf + i, max, &out->locals[j].count, &i))) {
			free (out->locals);
			return 0;	
		}

		if (!(consume_s8 (buf + i, max, (st8*)&out->locals[j].type, &i))) {
			free (out->locals);
			return 0;
		}
		j += 1;
	}
	if (offset) *offset += i;
	return j;
}

static size_t consume_limits (ut8 *buf, ut8 *max, struct r_bin_wasm_resizable_limits_t *out, ut32 *offset) {
	ut32 i = 0;
	if (!(consume_u8 (buf + i, max, &out->flags, &i))) return 0;
	if (!(consume_u32 (buf + i, max, &out->initial, &i))) return 0;
	if (out->flags && (!(consume_u32 (buf + i, max, &out->maximum, &i)))) return 0;
	if (offset) *offset += i;
	return i;
}

// Utils
static RList *r_bin_wasm_get_sections_by_id (RList *sections, ut8 id) {
	RBinWasmSection *sec = NULL;
	RList *ret = NULL;	
	RListIter *iter = NULL;

	// memory leak
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	r_list_foreach (sections, iter, sec) {
		if (sec->id == id) {
			r_list_append(ret, sec);
		}
	}
	return ret;
}

#define R_BIN_WASM_VALUETYPETOSTRING(p, type, i) {\
	switch(type) {\
	case R_BIN_WASM_VALUETYPE_i32:\
		strcpy(p, "i32");\
		break;\
	case R_BIN_WASM_VALUETYPE_i64:\
		strcpy(p, "i64");\
		break;\
	case R_BIN_WASM_VALUETYPE_f32:\
		strcpy(p, "f32");\
		break;\
	case R_BIN_WASM_VALUETYPE_f64:\
		strcpy(p, "f64");\
		break;\
	}\
	i+= 3;\
}

static char *r_bin_wasm_type_entry_to_string (RBinWasmTypeEntry *ptr) {
	if (!ptr || ptr->to_str) {
		return NULL;
	}

	char *ret;

	int p, i = 0, sz;

	sz = (ptr->param_count + ptr->return_count) * 5 + 9;

	// memory leak
	if (!(ret = (char*) malloc (sz * sizeof(char)))) {
		return NULL;
	}

	strcpy (ret + i, "(");
	i++;

	for (p = 0; p < ptr->param_count; p++ ) {
		R_BIN_WASM_VALUETYPETOSTRING (ret+i, ptr->param_types[p], i); // i+=3
		if (p < ptr->param_count - 1) {
			strcpy (ret+i, ", ");
			i += 2;
		}
	}		

	strcpy (ret + i, ") -> (");
	i += 6;

	if (ptr->return_count == 1) {
		R_BIN_WASM_VALUETYPETOSTRING (ret + i, ptr->return_type, i);
	}

	strcpy (ret + i, ")");

	return ret;
}

// Parsing
static RList *r_bin_wasm_get_type_entries (RBinWasmObj *bin, RBinWasmSection *sec) {

	RList *ret = NULL;
	RBinWasmTypeEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {
		if (!(ptr = R_NEW0 (RBinWasmTypeEntry))) {
			return ret;
		}

		if (!(consume_u8 (buf + i, buf + len, &ptr->form, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->param_count, &i))) {
			free (ptr);
			return ret;
		}

		if (!(i + ptr->param_count < len)) {
			free (ptr);
			return ret;
		}

		int j;
		for (j = 0; j < ptr->param_count; j++) {
			if (!(consume_s8 (buf + i, buf + len, (st8*)&ptr->param_types[j], &i))) {
				free (ptr);
				return ret;
			}
		}

		if (!(consume_s8 (buf + i, buf + len, &ptr->return_count, &i))) {
			free (ptr);
			return ret;
		}

		if (ptr->return_count > 1) {
			free(ptr);
			return ret;
		}

		if (ptr->return_count == 1) {
			if (!(consume_s8 (buf + i, buf + len, (st8*)&ptr->return_type, &i))) {
				free(ptr);
				return ret;
			}
		}

		ptr->to_str = r_bin_wasm_type_entry_to_string (ptr);

		r_list_append (ret, ptr);

		r += 1;

	}

	return ret;

}

static RList *r_bin_wasm_get_import_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmImportEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {
		if (!(ptr = R_NEW0 (RBinWasmImportEntry))) {
			return ret;
		}
		if (!(consume_u32 (buf + i, buf + len, &ptr->module_len, &i))) {
			goto culvert;
		}
		if (!(consume_str (buf + i, buf + len, ptr->module_len, ptr->module_str, &i))) {
			goto culvert;
		}
		if (!(consume_u32 (buf + i, buf + len, &ptr->field_len, &i))) {
			goto culvert;
		}
		if (!(consume_str (buf + i, buf + len, ptr->field_len, ptr->field_str, &i))) {
			goto culvert;
		} 
		if (!(consume_u8 (buf + i, buf + len, &ptr->kind, &i))) {
			goto culvert;
		}
		switch (ptr->kind) {
		case 0: // Function
			if (!(consume_u32 (buf + i, buf + len, &ptr->type_f, &i))) {
				goto sewer;
			}
			break;
		case 1: // Table
			if (!(consume_u8 (buf + i, buf + len, (ut8*)&ptr->type_t.elem_type, &i))) {
				goto sewer; // varint7
			}
			if (!(consume_limits (buf + i, buf + len, &ptr->type_t.limits, &i))) {
				goto sewer;
			}
			break;
		case 2: // Memory
			if (!(consume_limits (buf + i, buf + len, &ptr->type_m.limits, &i))) {
				goto sewer;
			}
			break;
		case 3: // Global
			if (!(consume_u8 (buf + i, buf + len, (ut8*)&ptr->type_g.content_type, &i))) {
				goto sewer; // varint7
			}
			if (!(consume_u8 (buf + i, buf + len, (ut8*)&ptr->type_g.mutability, &i))) {
				goto sewer; // varuint1
			}
			break;
		default:
			goto sewer;
		}
		r_list_append (ret, ptr);
		r++;
	}
	return ret;
sewer:
	ret = NULL;
culvert:
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_export_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmExportEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {
		if (!(ptr = R_NEW0 (RBinWasmExportEntry))) {
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->field_len, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_str (buf + i, buf + len, ptr->field_len, ptr->field_str, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_u8 (buf + i, buf + len, &ptr->kind, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
			free (ptr);
			return ret;
		}

		r_list_append (ret, ptr);
		r++;
	}
	return ret;
}

static RList *r_bin_wasm_get_code_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmCodeEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, j = 0, r = 0;
	size_t n = 0;

	while (i < len && r < count) {

		if (!(ptr = R_NEW0 (RBinWasmCodeEntry))) {
			return ret;
		}

		if (!(n = consume_u32 (buf + i, buf + len, &ptr->body_size, &i))) {
			free (ptr);
			return ret;
		}

		if (!(i + ptr->body_size - 1 < len)) {
			free (ptr);
			return ret;
		}

		j = i;

		if (!(n = consume_u32 (buf + i, buf + len, &ptr->local_count, &i))) {
			free (ptr);
			return ret;
		}

		if ((n = consume_locals (buf + i, buf + len, ptr->local_count,ptr, &i)) < ptr->local_count) {
			free (ptr);
			return ret;
		}

		ptr->code = sec->payload_data + i;
		ptr->len = ptr->body_size - (i - j);

		i += ptr->len - 1; // consume bytecode

		if (!(consume_u8 (buf + i, buf + len, &ptr->byte, &i))) {
			free (ptr);
			return ret;
		}

		if (ptr->byte != R_BIN_WASM_END_OF_CODE) {
			free (ptr);
			return ret;
		}

		// search 'r' in function_space, if present get signature from types
		// if export get name

		r_list_append (ret, ptr);

		r += 1;

	}

	return ret;
}

static RList *r_bin_wasm_get_data_entries (RBinWasmObj *bin, RBinWasmSection *sec) {

	RList *ret = NULL;
	RBinWasmDataEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;
	size_t n = 0;

	while (i < len && r < count) {

		if (!(ptr = R_NEW0 (RBinWasmDataEntry))) {
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
			free (ptr);
			return ret;
		}

		if (!(n = consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
			free (ptr);
			return ret;
		}

		ptr->offset.len = n;

		if (!(consume_u32 (buf + i, buf + len, &ptr->size, &i))) {	
			free (ptr);
			return ret;
		}

		ptr->data = sec->payload_data + i;

		r_list_append (ret, ptr);

		r += 1;

	}

	return ret;
}

static RBinWasmStartEntry *r_bin_wasm_get_start (RBinWasmObj *bin, RBinWasmSection *sec) {

	RBinWasmStartEntry *ptr;	

	if (!(ptr = R_NEW0 (RBinWasmStartEntry))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 i = 0;

	if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
		free (ptr);
		return NULL;
	}

	return ptr;

}

static RList *r_bin_wasm_get_memory_entries (RBinWasmObj *bin, RBinWasmSection *sec) {

	RList *ret = NULL;
	RBinWasmMemoryEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {

		if (!(ptr = R_NEW0 (RBinWasmMemoryEntry))) {
			return ret;
		}

		if (!(consume_limits (buf + i, buf + len, &ptr->limits, &i))) {
			free (ptr);
			return ret;
		}

		r_list_append (ret, ptr);

		r += 1;

	}

	return ret;
}

static RList *r_bin_wasm_get_table_entries (RBinWasmObj *bin, RBinWasmSection *sec) {

	RList *ret = NULL;
	RBinWasmTableEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {

		if (!(ptr = R_NEW0 (RBinWasmTableEntry))) {
			return ret;
		}

		if (!(consume_u8 (buf + i, buf + len, &ptr->element_type, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_limits (buf + i, buf + len, &ptr->limits, &i))) {
			free (ptr);
			return ret;
		}

		r_list_append (ret, ptr);

		r += 1;

	}

	return ret;
}

static RList *r_bin_wasm_get_global_entries (RBinWasmObj *bin, RBinWasmSection *sec) {
	RList *ret = NULL;
	RBinWasmGlobalEntry *ptr = NULL;
	int buflen = bin->buf->length;
	if (sec->payload_data + 32 > buflen) {
		return NULL;
	}

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && len < buflen && r < count) {
		if (!(ptr = R_NEW0 (RBinWasmGlobalEntry))) {
			return ret;
		}

		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, (ut8*)&ptr->content_type, &i))) {
			goto beach;
		}
		if (len + 8 > buflen || !(consume_u8 (buf + i, buf + len, &ptr->mutability, &i))) {
			goto beach;
		}
		if (len + 8 > buflen || !(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
			goto beach;
		}
		r_list_append (ret, ptr);
		r++;
	}
	return ret;
beach:
	free (ptr);
	return ret;
}

static RList *r_bin_wasm_get_element_entries (RBinWasmObj *bin, RBinWasmSection *sec) {

	RList *ret = NULL;
	RBinWasmElementEntry *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	ut8* buf = bin->buf->buf + (ut32)sec->payload_data;
	ut32 len =  sec->payload_len;
	ut32 count = sec->count;
	ut32 i = 0, r = 0;

	while (i < len && r < count) {

		if (!(ptr = R_NEW0 (RBinWasmElementEntry))) {
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->index, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_init_expr (buf + i, buf + len, R_BIN_WASM_END_OF_CODE, NULL, &i))) {
			free (ptr);
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->num_elem, &i))) {
			free (ptr);
			return ret;
		}

		ut32 j = 0;
		while (i < len && j < ptr->num_elem	) {
			// TODO: allocate space and fill entry
			ut32 e;
			if (!(consume_u32 (buf + i, buf + len, &e, &i))) {
				free (ptr);
				return ret;
			}
		}

		r_list_append (ret, ptr);

		r += 1;

	}

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

	ut8* buf = bin->buf->buf;
	ut32 len = bin->size, i = 8; // skip magic bytes + version

	while (i < len) {

		//r_buf_read_* api but it makes sense going through the array directly
		if (!(ptr = R_NEW0 (RBinWasmSection))) {
			return ret;
		}

		if (!(consume_u8 (buf + i, buf + len, &ptr->id, &i))) {
			return ret;
		}

		if (!(consume_u32 (buf + i, buf + len, &ptr->size, &i))) {
			free(ptr);
			return NULL;
		}	

		ptr->count = 0;
		ptr->offset = i;

		switch (ptr->id) {

		case R_BIN_WASM_SECTION_CUSTOM:
			//eprintf("custom section: 0x%x, ", i);
			if (!(consume_u32 (buf + i, buf + len, &ptr->name_len, &i))) {
				free(ptr);
				return ret;
			}
			if (!(consume_str (buf + i, buf + len, ptr->name_len,
					ptr->name, &i))) {
				free(ptr);
				return ret;
			}
			//eprintf("%s\n", ptr->name);
			break;

		case R_BIN_WASM_SECTION_TYPE:
			//eprintf("section type: 0x%x, ", i);
			strcpy (ptr->name, "type");
			ptr->name_len = 4;
			break;

		case R_BIN_WASM_SECTION_IMPORT:
			//eprintf("section import: 0x%x, ", i);
			strcpy (ptr->name, "import");
			ptr->name_len = 6;
			break;

		case R_BIN_WASM_SECTION_FUNCTION:
			//eprintf("section function: 0x%x, ", i);
			strcpy (ptr->name, "function");
			ptr->name_len = 8;
			break;

		case R_BIN_WASM_SECTION_TABLE:
			//eprintf("section table: 0x%x, ", i);
			strcpy (ptr->name, "table");
			ptr->name_len = 5;
			break;

		case R_BIN_WASM_SECTION_MEMORY:
			//eprintf("section memory: 0x%x, ", i);
			strcpy (ptr->name, "memory");
			ptr->name_len = 6;
			break;

		case R_BIN_WASM_SECTION_GLOBAL:
			//eprintf("section global: 0x%x, ", i);
			strcpy (ptr->name, "global");
			ptr->name_len = 6;
			break;

		case R_BIN_WASM_SECTION_EXPORT:
			//eprintf("section export: 0x%x, ", i);
			strcpy (ptr->name, "export");
			ptr->name_len = 6;
			break;

		case R_BIN_WASM_SECTION_START:
			//eprintf("section start: 0x%x\n", i);
			strcpy (ptr->name, "start");
			ptr->name_len = 5;
			break;

		case R_BIN_WASM_SECTION_ELEMENT:
			//eprintf("section element: 0x%x, ", i);
			strncpy (ptr->name, "element", R_BIN_WASM_STRING_LENGTH);
			ptr->name_len = 7;
			break;

		case R_BIN_WASM_SECTION_CODE:
			//eprintf("section code: 0x%x, ", i);
			strncpy (ptr->name, "code", R_BIN_WASM_STRING_LENGTH);
			ptr->name_len = 4;
			break;

		case R_BIN_WASM_SECTION_DATA:
			//eprintf("section data: 0x%x, ", i);
			strncpy (ptr->name, "data", R_BIN_WASM_STRING_LENGTH);
			ptr->name_len = 4;
			break;

		default:
			eprintf("unkown section id: %d\n", ptr->id);
			i += ptr->size - 1; // next
			continue;

		}

		if (ptr->id != R_BIN_WASM_SECTION_START
				&& ptr->id != R_BIN_WASM_SECTION_CUSTOM) {
			if (!(consume_u32 (buf + i, buf + len, &ptr->count, &i))) {
				free (ptr);
				return ret;
			}
			//eprintf("count %d\n", ptr->count);
		}

		ptr->payload_data = i;
		ptr->payload_len = ptr->size - (i - ptr->offset);

		r_list_append (ret, ptr);

		i += ptr->payload_len; // next

	}

	bin->g_sections = ret;

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
		return 0;
	} else {
		start = r_bin_wasm_get_start (bin, sec);
		bin->g_start = start;
	}

	if (!start) {
		return 0;
	}

	// FIX: entrypoint can be also an import
	func = r_list_get_n (r_bin_wasm_get_codes (bin), start->index);
	return (ut32)func? func->code: 0;

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
		return r_list_new();
	}
	return bin->g_imports = r_bin_wasm_get_import_entries (bin, import);
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
		return r_list_new();
	}

	bin->g_exports = r_bin_wasm_get_export_entries (bin, export);

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
		return r_list_new();
	}

	// support for multiple export sections against spec
	if (!(type = (RBinWasmSection*) r_list_first (types))) {
		return r_list_new();
	}

	bin->g_types = r_bin_wasm_get_type_entries (bin, type);

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
		return r_list_new();
	}

	bin->g_memories = r_bin_wasm_get_memory_entries (bin, memory);

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
		return r_list_new();
	}

	bin->g_globals = r_bin_wasm_get_global_entries (bin, global);

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
		return r_list_new();
	}

	bin->g_elements = r_bin_wasm_get_element_entries (bin, element);

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
		return r_list_new();
	}

	// support for multiple export sections against spec
	if (!(code = (RBinWasmSection*) r_list_first (codes))) {
		return r_list_new();
	}

	bin->g_codes = r_bin_wasm_get_code_entries (bin, code);

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
		return r_list_new();
	}

	bin->g_datas = r_bin_wasm_get_data_entries (bin, data);

	return bin->g_datas;
}
