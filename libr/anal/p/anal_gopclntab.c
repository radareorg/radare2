/* radare - MIT - Copyright 2026 - AsherDLL */
// vibetranspiled from the original Python code from AsherDLL
// -> https://github.com/AsherDLL/r2gopclntabParser

#define R_LOG_ORIGIN "anal.gopclntab"

#include <r_core.h>
#include <r_util/r_json.h>

#define GO_MAGIC_120 0xfffffff1U
#define GO_MAGIC_118 0xfffffff0U
#define GO_MAGIC_116 0xfffffffaU
#define GO_MAGIC_12  0xfffffffbU

#define GO_SCAN_CHUNK (16ULL * 1024ULL * 1024ULL)
#define GO_SCAN_STEP (GO_SCAN_CHUNK - 8)
#define GO_MAX_SECTION_READ (128ULL * 1024ULL * 1024ULL)

typedef enum {
	GO_PCLN_UNKNOWN = 0,
	GO_PCLN_12,
	GO_PCLN_116,
	GO_PCLN_118,
	GO_PCLN_120,
} GoPclnVersion;

typedef struct {
	ut32 magic;
	ut8 min_lc;
	ut8 ptr_size;
	GoPclnVersion version;
	ut64 nfunc;
	ut64 nfiles;
	ut64 text_start;
	ut64 funcname_offset;
	ut64 cu_offset;
	ut64 filetab_offset;
	ut64 pctab_offset;
	ut64 pcln_offset;
	ut64 functab_offset;
} GoPcHeader;

typedef struct {
	char *name;
	char *safe_name;
	char *source_file;
	ut64 addr;
	st32 args;
	st32 start_line;
	ut32 index;
} GoPclnFunc;

typedef struct {
	RAnal *anal;
	RCore *core;
	GoPcHeader header;
	RList/*<GoPclnFunc *>*/ *functions;
	RList/*<char *>*/ *source_files;
	ut8 *section_data;
	ut64 section_size;
	ut64 section_vaddr;
	ut64 text_base;
	bool big_endian;
} GoPclnCtx;

typedef bool (*GoSectionIterCb)(const char *name, ut64 vaddr, ut64 size, void *user);

static void go_func_free(GoPclnFunc *f) {
	if (!f) {
		return;
	}
	free (f->name);
	free (f->safe_name);
	free (f->source_file);
	free (f);
}

static void go_ctx_fini(GoPclnCtx *ctx) {
	if (!ctx) {
		return;
	}
	r_list_free (ctx->functions);
	r_list_free (ctx->source_files);
	free (ctx->section_data);
	ctx->functions = NULL;
	ctx->source_files = NULL;
	ctx->section_data = NULL;
}

static bool read_u8_at(const ut8 *data, ut64 size, ut64 off, ut8 *out) {
	R_RETURN_VAL_IF_FAIL (data && out, false);
	if (off >= size) {
		return false;
	}
	*out = data[off];
	return true;
}

static bool read_u32_at(const ut8 *data, ut64 size, ut64 off, bool be, ut32 *out) {
	R_RETURN_VAL_IF_FAIL (data && out, false);
	if (off > size || (size - off) < sizeof (ut32)) {
		return false;
	}
	*out = r_read_ble32 (data + off, be);
	return true;
}

static bool read_u64_at(const ut8 *data, ut64 size, ut64 off, bool be, ut64 *out) {
	R_RETURN_VAL_IF_FAIL (data && out, false);
	if (off > size || (size - off) < sizeof (ut64)) {
		return false;
	}
	*out = r_read_ble64 (data + off, be);
	return true;
}

static bool read_i32_at(const ut8 *data, ut64 size, ut64 off, bool be, st32 *out) {
	ut32 v = 0;
	if (!read_u32_at (data, size, off, be, &v)) {
		return false;
	}
	*out = (st32)v;
	return true;
}

static bool read_i64_at(const ut8 *data, ut64 size, ut64 off, bool be, st64 *out) {
	ut64 v = 0;
	if (!read_u64_at (data, size, off, be, &v)) {
		return false;
	}
	*out = (st64)v;
	return true;
}

static bool read_ptr_at(const ut8 *data, ut64 size, ut64 off, int ptr_size, bool be, ut64 *out) {
	R_RETURN_VAL_IF_FAIL (out, false);
	if (ptr_size == 4) {
		ut32 v = 0;
		if (!read_u32_at (data, size, off, be, &v)) {
			return false;
		}
		*out = v;
		return true;
	}
	if (ptr_size == 8) {
		return read_u64_at (data, size, off, be, out);
	}
	return false;
}

static bool read_native_int_at(const ut8 *data, ut64 size, ut64 off, int ptr_size, bool be, st64 *out) {
	R_RETURN_VAL_IF_FAIL (out, false);
	if (ptr_size == 4) {
		st32 v = 0;
		if (!read_i32_at (data, size, off, be, &v)) {
			return false;
		}
		*out = v;
		return true;
	}
	if (ptr_size == 8) {
		return read_i64_at (data, size, off, be, out);
	}
	return false;
}

static const char *go_version_string(GoPclnVersion version) {
	switch (version) {
	case GO_PCLN_12:
		return "1.2";
	case GO_PCLN_116:
		return "1.16";
	case GO_PCLN_118:
		return "1.18";
	case GO_PCLN_120:
		return "1.20+";
	default:
		return "unknown";
	}
}

static GoPclnVersion go_version_from_magic(ut32 magic) {
	switch (magic) {
	case GO_MAGIC_12:
		return GO_PCLN_12;
	case GO_MAGIC_116:
		return GO_PCLN_116;
	case GO_MAGIC_118:
		return GO_PCLN_118;
	case GO_MAGIC_120:
		return GO_PCLN_120;
	default:
		return GO_PCLN_UNKNOWN;
	}
}

static bool go_magic_is_known(ut32 magic) {
	return go_version_from_magic (magic) != GO_PCLN_UNKNOWN;
}

static char *go_read_cstring_dup(const ut8 *data, ut64 size, ut64 off) {
	R_RETURN_VAL_IF_FAIL (data, NULL);
	if (off >= size) {
		return NULL;
	}
	ut64 i;
	for (i = off; i < size; i++) {
		if (!data[i]) {
			return r_str_ndup ((const char *)data + off, (int)(i - off));
		}
	}
	return r_str_ndup ((const char *)data + off, (int)(size - off));
}

static bool go_decode_varint(const ut8 *data, ut64 size, ut64 off, ut64 *value, ut64 *used) {
	R_RETURN_VAL_IF_FAIL (data && value && used, false);
	ut64 result = 0;
	ut64 shift = 0;
	ut64 i = 0;
	while ((off + i) < size) {
		const ut8 b = data[off + i];
		result |= ((ut64)(b & 0x7f)) << shift;
		i++;
		if (!(b & 0x80)) {
			*value = result;
			*used = i;
			return true;
		}
		shift += 7;
		if (shift >= 64) {
			break;
		}
	}
	return false;
}

static st64 go_zigzag_decode(ut64 uvdelta) {
	if (uvdelta & 1) {
		return -(st64)((uvdelta + 1) >> 1);
	}
	return (st64)(uvdelta >> 1);
}

static bool go_decode_first_pcdata_value(const ut8 *pctab, ut64 pctab_size, ut64 offset, ut8 quantum, st64 *value) {
	R_RETURN_VAL_IF_FAIL (pctab && value, false);
	ut64 pos = offset;
	ut64 pc = 0;
	st64 val = -1;
	while (pos < pctab_size) {
		ut64 uvdelta = 0;
		ut64 used = 0;
		if (!go_decode_varint (pctab, pctab_size, pos, &uvdelta, &used)) {
			return false;
		}
		if (!uvdelta && pc != 0) {
			return false;
		}
		pos += used;
		val += go_zigzag_decode (uvdelta);
		ut64 pcdelta = 0;
		if (!go_decode_varint (pctab, pctab_size, pos, &pcdelta, &used)) {
			return false;
		}
		pos += used;
		pc += pcdelta * quantum;
		*value = val;
		return true;
	}
	return false;
}

static bool go_parse_header(GoPclnCtx *ctx) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->section_data, false);
	GoPcHeader *h = &ctx->header;
	const ut8 *data = ctx->section_data;
	const ut64 size = ctx->section_size;
	ut8 pad1 = 0;
	ut8 pad2 = 0;
	if (!read_u32_at (data, size, 0, ctx->big_endian, &h->magic)) {
		return false;
	}
	h->version = go_version_from_magic (h->magic);
	if (h->version == GO_PCLN_UNKNOWN) {
		return false;
	}
	if (!read_u8_at (data, size, 4, &pad1)
		|| !read_u8_at (data, size, 5, &pad2)
		|| !read_u8_at (data, size, 6, &h->min_lc)
		|| !read_u8_at (data, size, 7, &h->ptr_size)) {
		return false;
	}
	if (pad1 || pad2) {
		return false;
	}
	if (h->ptr_size != 4 && h->ptr_size != 8) {
		return false;
	}
	if (h->min_lc != 1 && h->min_lc != 2 && h->min_lc != 4) {
		return false;
	}
	ut64 off = 8;
	st64 nfunc = 0;
	switch (h->version) {
	case GO_PCLN_12:
		if (!read_native_int_at (data, size, off, h->ptr_size, ctx->big_endian, &nfunc)) {
			return false;
		}
		if (nfunc <= 0) {
			return false;
		}
		h->nfunc = (ut64)nfunc;
		h->nfiles = 0;
		h->text_start = 0;
		h->funcname_offset = 0;
		h->cu_offset = 0;
		h->filetab_offset = 0;
		h->pctab_offset = 0;
		h->pcln_offset = 0;
		h->functab_offset = off + h->ptr_size;
		return true;
	case GO_PCLN_116:
	case GO_PCLN_118:
	case GO_PCLN_120:
		if (!read_native_int_at (data, size, off, h->ptr_size, ctx->big_endian, &nfunc)) {
			return false;
		}
		if (nfunc <= 0) {
			return false;
		}
		h->nfunc = (ut64)nfunc;
		off += h->ptr_size;
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->nfiles)) {
			return false;
		}
		off += h->ptr_size;
		if (h->version == GO_PCLN_116) {
			h->text_start = 0;
		} else {
			if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->text_start)) {
				return false;
			}
			off += h->ptr_size;
		}
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->funcname_offset)) {
			return false;
		}
		off += h->ptr_size;
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->cu_offset)) {
			return false;
		}
		off += h->ptr_size;
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->filetab_offset)) {
			return false;
		}
		off += h->ptr_size;
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->pctab_offset)) {
			return false;
		}
		off += h->ptr_size;
		if (!read_ptr_at (data, size, off, h->ptr_size, ctx->big_endian, &h->pcln_offset)) {
			return false;
		}
		h->functab_offset = h->pcln_offset;
		return true;
	default:
		return false;
	}
}

static bool go_load_range(GoPclnCtx *ctx, ut64 vaddr, ut64 size) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->anal, false);
	if (!size || size > GO_MAX_SECTION_READ) {
		return false;
	}
	ut8 *buf = malloc ((size_t)size);
	if (!buf) {
		return false;
	}
	const int rc = ctx->anal->iob.read_at (ctx->anal->iob.io, vaddr, buf, (int)size);
	if (rc < 1) {
		free (buf);
		return false;
	}
	free (ctx->section_data);
	ctx->section_data = buf;
	ctx->section_size = size;
	ctx->section_vaddr = vaddr;
	return true;
}

static bool go_sections_foreach(GoPclnCtx *ctx, GoSectionIterCb cb, void *user) {
	R_RETURN_VAL_IF_FAIL (ctx && cb && ctx->anal->coreb.cmdStr, false);
	char *json = ctx->anal->coreb.cmdStr (ctx->core, "iSj");
	if (!json) {
		return false;
	}
	RJson *root = r_json_parseown (json);
	if (!root || root->type != R_JSON_ARRAY) {
		r_json_free (root);
		free (json);
		return false;
	}
	size_t i;
	for (i = 0; i < root->children.count; i++) {
		const RJson *item = r_json_item (root, i);
		if (!item || item->type != R_JSON_OBJECT) {
			continue;
		}
		const char *name = r_json_get_str (item, "name");
		st64 vaddr = r_json_get_num (item, "vaddr");
		st64 size = r_json_get_num (item, "vsize");
		if (size <= 0) {
			size = r_json_get_num (item, "size");
		}
		if (!cb (name, vaddr >= 0? (ut64)vaddr: 0, size > 0? (ut64)size: 0, user)) {
			break;
		}
	}
	r_json_free (root);
	free (json);
	return true;
}

static bool go_is_named_pclntab_section(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	return strstr (name, ".gopclntab") || strstr (name, "__gopclntab");
}

static bool go_try_named_section_cb(const char *name, ut64 vaddr, ut64 size, void *user) {
	GoPclnCtx *ctx = (GoPclnCtx *)user;
	if (!go_is_named_pclntab_section (name)) {
		return true;
	}
	if (size < 16) {
		return true;
	}
	if (go_load_range (ctx, vaddr, size)) {
		return false;
	}
	return true;
}

static bool go_try_named_section(GoPclnCtx *ctx) {
	return go_sections_foreach (ctx, go_try_named_section_cb, ctx) && ctx->section_data;
}

static bool go_find_magic_in_buf(GoPclnCtx *ctx, const ut8 *buf, ut64 size, ut64 *found_off) {
	R_RETURN_VAL_IF_FAIL (ctx && buf && found_off, false);
	ut64 i;
	for (i = 0; i + 8 <= size; i++) {
		const ut32 magic = r_read_ble32 (buf + i, ctx->big_endian);
		if (!go_magic_is_known (magic)) {
			continue;
		}
		const ut8 pad1 = buf[i + 4];
		const ut8 pad2 = buf[i + 5];
		const ut8 min_lc = buf[i + 6];
		const ut8 ptr_size = buf[i + 7];
		if (pad1 || pad2) {
			continue;
		}
		if (ptr_size != 4 && ptr_size != 8) {
			continue;
		}
		if (min_lc != 1 && min_lc != 2 && min_lc != 4) {
			continue;
		}
		*found_off = i;
		return true;
	}
	return false;
}

static bool go_try_scan_sections_cb(const char *name, ut64 vaddr, ut64 sec_size, void *user) {
	GoPclnCtx *ctx = (GoPclnCtx *)user;
	(void)name;
	if (sec_size < 64) {
		return true;
	}
	ut8 *buf = malloc ((size_t)GO_SCAN_CHUNK);
	if (!buf) {
		return false;
	}
	ut64 chunk_off;
	for (chunk_off = 0; chunk_off < sec_size; chunk_off += GO_SCAN_STEP) {
		const ut64 read_size = R_MIN ((ut64)GO_SCAN_CHUNK, sec_size - chunk_off);
		if (ctx->anal->iob.read_at (ctx->anal->iob.io, vaddr + chunk_off, buf, (int)read_size) < 1) {
			continue;
		}
		ut64 found = 0;
		if (!go_find_magic_in_buf (ctx, buf, read_size, &found)) {
			continue;
		}
		const ut64 found_vaddr = vaddr + chunk_off + found;
		const ut64 remain = sec_size - (chunk_off + found);
		free (buf);
		if (go_load_range (ctx, found_vaddr, remain)) {
			return false;
		}
		return true;
	}
	free (buf);
	return true;
}

static bool go_try_scan_sections(GoPclnCtx *ctx) {
	return go_sections_foreach (ctx, go_try_scan_sections_cb, ctx) && ctx->section_data;
}

static bool go_get_text_vaddr_cb(const char *name, ut64 vaddr, ut64 size, void *user) {
	ut64 *res = (ut64 *)user;
	(void)size;
	if (R_STR_ISEMPTY (name)) {
		return true;
	}
	if (!strcmp (name, ".text") || !strcmp (name, "__text") || r_str_endswith (name, ".__text")) {
		*res = vaddr;
		return false;
	}
	return true;
}

static ut64 go_get_text_vaddr(GoPclnCtx *ctx) {
	ut64 vaddr = 0;
	go_sections_foreach (ctx, go_get_text_vaddr_cb, &vaddr);
	return vaddr;
}

static void go_resolve_text_base(GoPclnCtx *ctx) {
	GoPcHeader *h = &ctx->header;
	switch (h->version) {
	case GO_PCLN_118:
	case GO_PCLN_120:
		ctx->text_base = h->text_start? h->text_start: go_get_text_vaddr (ctx);
		break;
	case GO_PCLN_116:
		ctx->text_base = go_get_text_vaddr (ctx);
		break;
	case GO_PCLN_12:
	default:
		ctx->text_base = 0;
		break;
	}
}

static bool go_add_source_file(GoPclnCtx *ctx, const char *path) {
	R_RETURN_VAL_IF_FAIL (ctx && path, false);
	if (R_STR_ISEMPTY (path)) {
		return false;
	}
	RListIter *iter;
	const char *it;
	r_list_foreach (ctx->source_files, iter, it) {
		if (!strcmp (it, path)) {
			return false;
		}
	}
	return r_list_append (ctx->source_files, strdup (path));
}

static char *go_first_source_file(GoPclnCtx *ctx, ut32 pcfile_off, ut32 cu_off) {
	GoPcHeader *h = &ctx->header;
	if (!pcfile_off || !h->pctab_offset || !h->filetab_offset || !h->cu_offset) {
		return NULL;
	}
	if (h->pctab_offset >= ctx->section_size || h->filetab_offset >= ctx->section_size || h->cu_offset >= ctx->section_size) {
		return NULL;
	}
	st64 fileidx = 0;
	if (!go_decode_first_pcdata_value (ctx->section_data + h->pctab_offset, ctx->section_size - h->pctab_offset, pcfile_off, h->min_lc, &fileidx)) {
		return NULL;
	}
	if (fileidx < 0) {
		return NULL;
	}
	const ut64 cu_index = (ut64)cu_off + (ut64)fileidx;
	const ut64 cu_entry_off = h->cu_offset + (cu_index * sizeof (ut32));
	ut32 file_off = 0;
	if (!read_u32_at (ctx->section_data, ctx->section_size, cu_entry_off, ctx->big_endian, &file_off)) {
		return NULL;
	}
	if (file_off == UT32_MAX) {
		return NULL;
	}
	return go_read_cstring_dup (ctx->section_data, ctx->section_size, h->filetab_offset + file_off);
}

static bool go_append_function(GoPclnCtx *ctx, GoPclnFunc *f) {
	R_RETURN_VAL_IF_FAIL (ctx && f, false);
	if (!f->safe_name && R_STR_ISNOTEMPTY (f->name)) {
		f->safe_name = r_name_filter_dup (f->name);
		if (R_STR_ISEMPTY (f->safe_name)) {
			free (f->safe_name);
			f->safe_name = r_str_newf ("go.%"PFMT64x, f->addr);
		}
	}
	return r_list_append (ctx->functions, f);
}

static bool go_parse_functions_12(GoPclnCtx *ctx) {
	GoPcHeader *h = &ctx->header;
	const ut64 base = h->functab_offset;
	const ut64 entry_size = h->ptr_size * 2;
	ut64 i;
	for (i = 0; i < h->nfunc; i++) {
		const ut64 off = base + (i * entry_size);
		ut64 entry_addr = 0;
		ut64 funcoff = 0;
		if (!read_ptr_at (ctx->section_data, ctx->section_size, off, h->ptr_size, ctx->big_endian, &entry_addr)
			|| !read_ptr_at (ctx->section_data, ctx->section_size, off + h->ptr_size, h->ptr_size, ctx->big_endian, &funcoff)) {
			break;
		}
		st32 nameoff = 0;
		if (!read_i32_at (ctx->section_data, ctx->section_size, funcoff + h->ptr_size, ctx->big_endian, &nameoff)) {
			continue;
		}
		GoPclnFunc *f = R_NEW0 (GoPclnFunc);
		if (!f) {
			return false;
		}
		f->addr = entry_addr;
		f->index = (ut32)i;
		if (nameoff >= 0) {
			f->name = go_read_cstring_dup (ctx->section_data, ctx->section_size, (ut64)nameoff);
		}
		if (!go_append_function (ctx, f)) {
			go_func_free (f);
			return false;
		}
	}
	return true;
}

static bool go_parse_functions_116(GoPclnCtx *ctx) {
	GoPcHeader *h = &ctx->header;
	const ut64 entry_size = h->ptr_size * 2;
	ut64 i;
	for (i = 0; i < h->nfunc; i++) {
		const ut64 off = h->pcln_offset + (i * entry_size);
		ut64 entry_addr = 0;
		ut64 funcoff = 0;
		if (!read_ptr_at (ctx->section_data, ctx->section_size, off, h->ptr_size, ctx->big_endian, &entry_addr)
			|| !read_ptr_at (ctx->section_data, ctx->section_size, off + h->ptr_size, h->ptr_size, ctx->big_endian, &funcoff)) {
			break;
		}
		const ut64 func_off = h->pcln_offset + funcoff;
		st32 nameoff = 0;
		st32 args = 0;
		if (!read_i32_at (ctx->section_data, ctx->section_size, func_off + h->ptr_size, ctx->big_endian, &nameoff)
			|| !read_i32_at (ctx->section_data, ctx->section_size, func_off + h->ptr_size + 4, ctx->big_endian, &args)) {
			continue;
		}
		GoPclnFunc *f = R_NEW0 (GoPclnFunc);
		if (!f) {
			return false;
		}
		f->addr = entry_addr;
		f->args = args;
		f->index = (ut32)i;
		if (nameoff >= 0) {
			f->name = go_read_cstring_dup (ctx->section_data, ctx->section_size, h->funcname_offset + (ut64)nameoff);
		}
		if (!go_append_function (ctx, f)) {
			go_func_free (f);
			return false;
		}
	}
	return true;
}

static bool go_parse_functions_118_plus(GoPclnCtx *ctx) {
	GoPcHeader *h = &ctx->header;
	ut64 i;
	for (i = 0; i < h->nfunc; i++) {
		const ut64 off = h->pcln_offset + (i * 8);
		ut32 entryoff = 0;
		ut32 funcoff = 0;
		if (!read_u32_at (ctx->section_data, ctx->section_size, off, ctx->big_endian, &entryoff)
			|| !read_u32_at (ctx->section_data, ctx->section_size, off + 4, ctx->big_endian, &funcoff)) {
			break;
		}
		const ut64 func_off = h->pcln_offset + funcoff;
		st32 nameoff = 0;
		st32 args = 0;
		ut32 pcfile = 0;
		ut32 cu_off = 0;
		st32 start_line = 0;
		if (!read_i32_at (ctx->section_data, ctx->section_size, func_off + 4, ctx->big_endian, &nameoff)
			|| !read_i32_at (ctx->section_data, ctx->section_size, func_off + 8, ctx->big_endian, &args)
			|| !read_u32_at (ctx->section_data, ctx->section_size, func_off + 20, ctx->big_endian, &pcfile)
			|| !read_u32_at (ctx->section_data, ctx->section_size, func_off + 32, ctx->big_endian, &cu_off)) {
			continue;
		}
		if (h->version == GO_PCLN_120 && !read_i32_at (ctx->section_data, ctx->section_size, func_off + 36, ctx->big_endian, &start_line)) {
			continue;
		}
		GoPclnFunc *f = R_NEW0 (GoPclnFunc);
		if (!f) {
			return false;
		}
		f->addr = ctx->text_base + entryoff;
		f->args = args;
		f->start_line = start_line;
		f->index = (ut32)i;
		if (nameoff >= 0) {
			f->name = go_read_cstring_dup (ctx->section_data, ctx->section_size, h->funcname_offset + (ut64)nameoff);
		}
		f->source_file = go_first_source_file (ctx, pcfile, cu_off);
		if (!go_append_function (ctx, f)) {
			go_func_free (f);
			return false;
		}
	}
	return true;
}

static bool go_parse_functions(GoPclnCtx *ctx) {
	switch (ctx->header.version) {
	case GO_PCLN_12:
		return go_parse_functions_12 (ctx);
	case GO_PCLN_116:
		return go_parse_functions_116 (ctx);
	case GO_PCLN_118:
	case GO_PCLN_120:
		return go_parse_functions_118_plus (ctx);
	default:
		return false;
	}
}

static void go_parse_source_files(GoPclnCtx *ctx) {
	GoPcHeader *h = &ctx->header;
	if (h->version == GO_PCLN_12 || !h->filetab_offset || h->filetab_offset >= ctx->section_size) {
		return;
	}
	ut64 pos = h->filetab_offset;
	while (pos < ctx->section_size) {
		char *path = go_read_cstring_dup (ctx->section_data, ctx->section_size, pos);
		if (!path) {
			break;
		}
		if (!*path) {
			free (path);
			pos++;
			continue;
		}
		go_add_source_file (ctx, path);
		pos += strlen (path) + 1;
		free (path);
		if (h->nfiles && r_list_length (ctx->source_files) >= h->nfiles) {
			break;
		}
	}
}

static bool go_ctx_init(GoPclnCtx *ctx, RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (ctx && anal, false);
	memset (ctx, 0, sizeof (*ctx));
	ctx->anal = anal;
	ctx->core = anal->coreb.core;
	if (!ctx->core) {
		R_LOG_ERROR ("This plugin requires an attached RCore");
		return false;
	}
	ctx->functions = r_list_newf ((RListFree)go_func_free);
	ctx->source_files = r_list_newf (free);
	if (!ctx->functions || !ctx->source_files) {
		go_ctx_fini (ctx);
		return false;
	}
	ctx->big_endian = anal->coreb.cfgGetB? anal->coreb.cfgGetB (ctx->core, "cfg.bigendian"): false;
	if (go_try_named_section (ctx) && go_parse_header (ctx)) {
		go_resolve_text_base (ctx);
		if (go_parse_functions (ctx)) {
			go_parse_source_files (ctx);
			return true;
		}
		goto error;
	}
	free (ctx->section_data);
	ctx->section_data = NULL;
	ctx->section_size = 0;
	ctx->section_vaddr = 0;
	memset (&ctx->header, 0, sizeof (ctx->header));
	if (!go_try_scan_sections (ctx) || !go_parse_header (ctx)) {
		R_LOG_ERROR ("Could not find valid gopclntab data");
		goto error;
	}
	go_resolve_text_base (ctx);
	if (!go_parse_functions (ctx)) {
		R_LOG_ERROR ("Failed to parse gopclntab functions");
		goto error;
	}
	go_parse_source_files (ctx);
	return true;
error:
	go_ctx_fini (ctx);
	return false;
}

static char *go_format_header(const GoPclnCtx *ctx) {
	R_RETURN_VAL_IF_FAIL (ctx, NULL);
	const GoPcHeader *h = &ctx->header;
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_append (sb, "============================================================\n");
	r_strbuf_append (sb, "  Go pclntab Header\n");
	r_strbuf_append (sb, "============================================================\n");
	r_strbuf_appendf (sb, "  Magic:           0x%08x\n", h->magic);
	r_strbuf_appendf (sb, "  Go version:      %s\n", go_version_string (h->version));
	r_strbuf_appendf (sb, "  Pointer size:    %u\n", h->ptr_size);
	r_strbuf_appendf (sb, "  Min LC (quantum):%u\n", h->min_lc);
	r_strbuf_appendf (sb, "  Num functions:   %"PFMT64u"\n", h->nfunc);
	r_strbuf_appendf (sb, "  Num files:       %"PFMT64u"\n", h->nfiles);
	if (h->text_start) {
		r_strbuf_appendf (sb, "  textStart:       0x%"PFMT64x"\n", h->text_start);
	}
	if (h->funcname_offset) {
		r_strbuf_appendf (sb, "  funcnameOffset:  0x%"PFMT64x"\n", h->funcname_offset);
	}
	if (h->cu_offset) {
		r_strbuf_appendf (sb, "  cuOffset:        0x%"PFMT64x"\n", h->cu_offset);
	}
	if (h->filetab_offset) {
		r_strbuf_appendf (sb, "  filetabOffset:   0x%"PFMT64x"\n", h->filetab_offset);
	}
	if (h->pctab_offset) {
		r_strbuf_appendf (sb, "  pctabOffset:     0x%"PFMT64x"\n", h->pctab_offset);
	}
	if (h->pcln_offset) {
		r_strbuf_appendf (sb, "  pclnOffset:      0x%"PFMT64x"\n", h->pcln_offset);
	}
	r_strbuf_append (sb, "============================================================\n");
	return r_strbuf_drain (sb);
}

static char *go_format_functions(const GoPclnCtx *ctx, const char *filter) {
	R_RETURN_VAL_IF_FAIL (ctx, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_append (sb, "ADDRESS       FUNCTION NAME\n");
	r_strbuf_append (sb, "----------------------------------------------------------------------\n");
	RListIter *iter;
	GoPclnFunc *f;
	ut64 total = r_list_length (ctx->functions);
	ut64 shown = 0;
	r_list_foreach (ctx->functions, iter, f) {
		if (R_STR_ISNOTEMPTY (filter) && (!f->name || !strstr (f->name, filter))) {
			continue;
		}
		r_strbuf_appendf (sb, "0x%"PFMT64x"   %s", f->addr, r_str_get (f->name));
		if (R_STR_ISNOTEMPTY (f->source_file)) {
			r_strbuf_appendf (sb, "  (%s", f->source_file);
			if (f->start_line > 0) {
				r_strbuf_appendf (sb, ":%d", f->start_line);
			}
			r_strbuf_append (sb, ")");
		}
		r_strbuf_append (sb, "\n");
		shown++;
	}
	if (!shown) {
		r_strbuf_appendf (sb, "\n[-] No functions%s\n", R_STR_ISNOTEMPTY (filter)? " matching filter": " found");
	} else if (R_STR_ISNOTEMPTY (filter)) {
		r_strbuf_appendf (sb, "\n[+] %"PFMT64u" function(s) shown (filtered from %"PFMT64u" total)\n", shown, total);
	} else {
		r_strbuf_appendf (sb, "\n[+] %"PFMT64u" function(s) shown\n", shown);
	}
	return r_strbuf_drain (sb);
}

static char *go_format_files(const GoPclnCtx *ctx) {
	R_RETURN_VAL_IF_FAIL (ctx, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	if (r_list_empty (ctx->source_files)) {
		r_strbuf_append (sb, "[-] No source files found\n");
		return r_strbuf_drain (sb);
	}
	r_strbuf_appendf (sb, "Source files (%d):\n", r_list_length (ctx->source_files));
	r_strbuf_append (sb, "------------------------------------------------------------\n");
	RListIter *iter;
	const char *path;
	r_list_foreach (ctx->source_files, iter, path) {
		r_strbuf_appendf (sb, "%s\n", path);
	}
	return r_strbuf_drain (sb);
}

static char *go_hexstr(ut64 n) {
	return r_str_newf ("0x%"PFMT64x, n);
}

static char *go_format_json(const GoPclnCtx *ctx) {
	R_RETURN_VAL_IF_FAIL (ctx, NULL);
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	const GoPcHeader *h = &ctx->header;
	pj_o (pj);
	pj_ko (pj, "header");
	char *magic = go_hexstr (h->magic);
	char *text = go_hexstr (h->text_start);
	pj_ks (pj, "magic", magic);
	pj_ks (pj, "version", go_version_string (h->version));
	pj_kn (pj, "ptrSize", h->ptr_size);
	pj_kn (pj, "minLC", h->min_lc);
	pj_kn (pj, "nfunc", h->nfunc);
	pj_kn (pj, "nfiles", h->nfiles);
	pj_ks (pj, "textStart", text);
	pj_end (pj);
	free (magic);
	free (text);
	pj_ka (pj, "functions");
	RListIter *iter;
	GoPclnFunc *f;
	r_list_foreach (ctx->functions, iter, f) {
		pj_o (pj);
		char *addr = go_hexstr (f->addr);
		pj_ks (pj, "name", r_str_get (f->name));
		pj_ks (pj, "addr", addr);
		pj_kN (pj, "args", f->args);
		pj_ks (pj, "source_file", r_str_get (f->source_file));
		pj_kN (pj, "start_line", f->start_line);
		free (addr);
		pj_end (pj);
	}
	pj_end (pj);
	pj_kn (pj, "num_source_files", r_list_length (ctx->source_files));
	pj_end (pj);
	return pj_drain (pj);
}

static bool go_comment_contains_line(const char *comment, const char *line) {
	R_RETURN_VAL_IF_FAIL (line, false);
	if (R_STR_ISEMPTY (comment) || R_STR_ISEMPTY (line)) {
		return false;
	}
	const char *p = strstr (comment, line);
	while (p) {
		const bool start_ok = (p == comment) || p[-1] == '\n';
		const char after = p[strlen (line)];
		const bool end_ok = !after || after == '\n';
		if (start_ok && end_ok) {
			return true;
		}
		p = strstr (p + 1, line);
	}
	return false;
}

static void go_append_unique_comment(RAnal *anal, ut64 addr, const char *line) {
	R_RETURN_IF_FAIL (anal && R_STR_ISNOTEMPTY (line));
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, addr);
	if (go_comment_contains_line (comment, line)) {
		return;
	}
	char *next = comment && *comment? r_str_newf ("%s\n%s", comment, line): strdup (line);
	if (!next) {
		return;
	}
	r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, next);
	free (next);
}

static char *go_unique_name_for_addr(RAnal *anal, const char *base, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (base), NULL);
	RAnalFunction *f = r_anal_get_function_at (anal, addr);
	if (f && !strcmp (f->name, base)) {
		return strdup (base);
	}
	return r_str_newf ("%s.%"PFMT64x, base, addr);
}

static char *go_function_name_for_apply(RAnal *anal, ut64 addr, const char *safe_name) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (safe_name), NULL);
	RAnalFunction *f = r_anal_get_function_at (anal, addr);
	if (!f) {
		return strdup (safe_name);
	}
	if (!strcmp (f->name, safe_name)) {
		return strdup (safe_name);
	}
	if (r_anal_function_rename (f, safe_name)) {
		return strdup (safe_name);
	}
	char *alt = go_unique_name_for_addr (anal, safe_name, addr);
	if (alt && r_anal_function_rename (f, alt)) {
		return alt;
	}
	free (alt);
	return NULL;
}

static char *go_create_function_name(RAnal *anal, ut64 addr, const char *safe_name) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (safe_name), NULL);
	RAnalFunction *f = r_anal_create_function (anal, safe_name, addr, R_ANAL_FCN_TYPE_FCN, NULL);
	if (f) {
		return strdup (safe_name);
	}
	char *alt = go_unique_name_for_addr (anal, safe_name, addr);
	if (!alt) {
		return NULL;
	}
	f = r_anal_create_function (anal, alt, addr, R_ANAL_FCN_TYPE_FCN, NULL);
	if (f) {
		return alt;
	}
	free (alt);
	return NULL;
}

static char *go_apply_functions(GoPclnCtx *ctx) {
	R_RETURN_VAL_IF_FAIL (ctx, NULL);
	int applied = 0;
	int skipped = 0;
	RListIter *iter;
	GoPclnFunc *f;
	r_list_foreach (ctx->functions, iter, f) {
		if (R_STR_ISEMPTY (f->name) || !f->addr || R_STR_ISEMPTY (f->safe_name)) {
			skipped++;
			continue;
		}
		char *applied_name = NULL;
		if (r_anal_get_function_at (ctx->anal, f->addr)) {
			applied_name = go_function_name_for_apply (ctx->anal, f->addr, f->safe_name);
		} else {
			applied_name = go_create_function_name (ctx->anal, f->addr, f->safe_name);
		}
		if (!applied_name) {
			skipped++;
			continue;
		}
		if (r_flag_space_push (ctx->core->flags, "go")) {
			char *flag_name = r_str_newf ("go.%s", applied_name);
			if (flag_name) {
				(void)r_flag_set (ctx->core->flags, flag_name, f->addr, 1);
				free (flag_name);
			}
			r_flag_space_pop (ctx->core->flags);
		}
		if (strcmp (applied_name, f->name)) {
			char *orig = r_str_newf ("orig: %s", f->name);
			if (orig) {
				go_append_unique_comment (ctx->anal, f->addr, orig);
				free (orig);
			}
		}
		if (R_STR_ISNOTEMPTY (f->source_file)) {
			char *src = (f->start_line > 0)
				? r_str_newf ("src: %s:%d", f->source_file, f->start_line)
				: r_str_newf ("src: %s", f->source_file);
			if (src) {
				go_append_unique_comment (ctx->anal, f->addr, src);
				free (src);
			}
		}
		free (applied_name);
		applied++;
	}
	return r_str_newf ("[+] Applied %d function names to radare2 (%d skipped)", applied, skipped);
}

static char *go_run_default(const GoPclnCtx *ctx) {
	char *header = go_format_header (ctx);
	char *body = go_format_functions (ctx, NULL);
	if (!header || !body) {
		free (header);
		free (body);
		return NULL;
	}
	char *out = r_str_newf ("%s\n%s", header, body);
	free (header);
	free (body);
	return out;
}

static char *gopclntab_help(void) {
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_append (sb, "| a:gopclntab            parse gopclntab and show header plus recovered functions\n");
	r_strbuf_append (sb, "| a:gopclntab list       list recovered functions\n");
	r_strbuf_append (sb, "| a:gopclntab apply      create/rename functions, go flags, and comments\n");
	r_strbuf_append (sb, "| a:gopclntab files      list recovered source files\n");
	r_strbuf_append (sb, "| a:gopclntab json       print recovered data as json\n");
	r_strbuf_append (sb, "| a:gopclntab name <s>   filter recovered functions by substring\n");
	return r_strbuf_drain (sb);
}

static char *gopclntab_cmd(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, "gopclntab")) {
		return NULL;
	}
	const char *args = r_str_trim_head_ro (input + strlen ("gopclntab"));
	if (*args == '?') {
		return gopclntab_help ();
	}
	GoPclnCtx ctx;
	if (!go_ctx_init (&ctx, anal)) {
		return strdup ("");
	}
	char *out = NULL;
	if (R_STR_ISEMPTY (args)) {
		out = go_run_default (&ctx);
	} else if (!strcmp (args, "list")) {
		out = go_format_functions (&ctx, NULL);
	} else if (!strcmp (args, "apply")) {
		out = go_apply_functions (&ctx);
	} else if (!strcmp (args, "files")) {
		out = go_format_files (&ctx);
	} else if (!strcmp (args, "json")) {
		out = go_format_json (&ctx);
	} else if (r_str_startswith (args, "name ")) {
		out = go_format_functions (&ctx, r_str_trim_head_ro (args + 5));
	} else {
		R_LOG_ERROR ("Unknown subcommand. See 'a:gopclntab?' for help");
		out = strdup ("");
	}
	go_ctx_fini (&ctx);
	return out? out: strdup ("");
}

RAnalPlugin r_anal_plugin_gopclntab = {
	.meta = {
		.name = "gopclntab",
		.author = "AsherDLL",
		.desc = "Parse Go gopclntab metadata and recover function names",
		.license = "MIT",
	},
	.cmd = gopclntab_cmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_gopclntab,
	.version = R2_VERSION
};
#endif
