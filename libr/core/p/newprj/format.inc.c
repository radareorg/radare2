/* radare - MIT - Copyright 2024-2026 - pancake */

#define R_LOG_ORIGIN "prj"

#include "newprj.h"

static const char *rprj_entry_type_tostring(int a) {
	switch (a) {
	case RPRJ_INFO: return "Info";
	case RPRJ_MAPS: return "Maps";
	case RPRJ_CMDS: return "Cmds";
	case RPRJ_FLAG: return "Flags";
	case RPRJ_CMNT: return "Comments";
	case RPRJ_MODS: return "Mods";
	case RPRJ_BLOB: return "Blob";
	case RPRJ_STRS: return "Strings";
	case RPRJ_THEM: return "Theme";
	case RPRJ_HINT: return "Hints";
	case RPRJ_EVAL: return "Evals";
	case RPRJ_XREF: return "Xrefs";
	case RPRJ_FUNC: return "Functions";
	case RPRJ_VART: return "VarTypes";
	}
	return "UNKNOWN";
}

static const char *rprj_st_get(R2ProjectStringTable *st, ut32 idx) {
	if (!st || !st->data || idx >= st->size) {
		return NULL;
	}
	const ut8 *s = st->data + idx;
	return memchr (s, 0, st->size - idx)? (const char *)s: NULL;
}

static bool rprj_st_is_valid(R2ProjectStringTable *st) {
	return st && st->data && st->size > 0 && st->data[st->size - 1] == 0 && rprj_st_get (st, 0);
}

static void rprj_st_write(RBuffer *b, R2ProjectStringTable *st) {
	r_buf_write (b, st->data, st->size);
}

static ut32 rprj_st_append(R2ProjectStringTable *st, const char *s) {
	const size_t slen = strlen (s) + 1;
	const size_t newsize = st->size + slen;
	if (newsize > st->capacity) {
		const size_t new_capacity = newsize + 1024;
		ut8 *nb = st->data? realloc (st->data, new_capacity): malloc (new_capacity);
		if (!nb) {
			return UT32_MAX;
		}
		st->data = nb;
		st->capacity = new_capacity;
	}
	if (!st->data) {
		return UT32_MAX;
	}
	memcpy (st->data + st->size, s, slen);
	ut32 index = st->size;
	st->size += slen;
	return index;
}

static void rprj_write_le32(RBuffer *b, ut32 v) {
	ut8 buf[4];
	r_write_le32 (buf, v);
	r_buf_write (b, buf, sizeof (buf));
}

static void rprj_write_le64(RBuffer *b, ut64 v) {
	ut8 buf[8];
	r_write_le64 (buf, v);
	r_buf_write (b, buf, sizeof (buf));
}

static void rprj_write_u8(RBuffer *b, ut8 v) {
	r_buf_write (b, &v, sizeof (v));
}

static void rprj_write_project_addr(RBuffer *b, R2ProjectAddr addr) {
	rprj_write_le32 (b, addr.mod);
	rprj_write_le64 (b, addr.delta);
}

static void rprj_info_write(RBuffer *b, R2ProjectInfo *info) {
	ut8 buf[RPRJ_INFO_SIZE] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectInfo, name), info->name);
	r_write_le32 (buf + r_offsetof (R2ProjectInfo, user), info->user);
	r_write_le64 (buf + r_offsetof (R2ProjectInfo, time), info->time);
	r_buf_write (b, buf, sizeof (buf));
}

static void rprj_cmnt_write_record(RBuffer *b, R2ProjectComment *cmnt) {
	ut8 buf[RPRJ_CMNT_SIZE] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectComment, text), cmnt->text);
	r_write_le32 (buf + r_offsetof (R2ProjectComment, mod), cmnt->mod);
	r_write_le64 (buf + r_offsetof (R2ProjectComment, delta), cmnt->delta);
	r_write_le64 (buf + r_offsetof (R2ProjectComment, size), cmnt->size);
	r_buf_write (b, buf, sizeof (buf));
}

static void rprj_hint_write(RBuffer *b, R2ProjectHint *hint) {
	ut8 buf[RPRJ_HINT_SIZE] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectHint, kind), hint->kind);
	r_write_le32 (buf + r_offsetof (R2ProjectHint, mod), hint->mod);
	r_write_le64 (buf + r_offsetof (R2ProjectHint, delta), hint->delta);
	r_write_le64 (buf + r_offsetof (R2ProjectHint, value), hint->value);
	r_buf_write (b, buf, sizeof (buf));
}

static bool rprj_read_exact(RBuffer *b, ut8 *buf, size_t len) {
	return r_buf_read (b, buf, len) == (st64)len;
}

static bool rprj_color_is_set(const RColor *color) {
	return color && (color->attr || color->a || color->r || color->g || color->b
		|| color->r2 || color->g2 || color->b2 || color->id16);
}

static bool rprj_color_eq(const RColor *a, const RColor *b) {
	return a && b
		&& a->attr == b->attr && a->a == b->a
		&& a->r == b->r && a->g == b->g && a->b == b->b
		&& a->r2 == b->r2 && a->g2 == b->g2 && a->b2 == b->b2
		&& a->id16 == b->id16;
}

static void rprj_write_color(RBuffer *b, const RColor *color) {
	ut8 buf[RPRJ_COLOR_SIZE] = {
		color->attr, color->a, color->r, color->g, color->b,
		color->r2, color->g2, color->b2, (ut8)color->id16
	};
	r_buf_write (b, buf, sizeof (buf));
}

static bool rprj_read_color(RBuffer *b, RColor *color) {
	ut8 buf[RPRJ_COLOR_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	color->attr = buf[0];
	color->a = buf[1];
	color->r = buf[2];
	color->g = buf[3];
	color->b = buf[4];
	color->r2 = buf[5];
	color->g2 = buf[6];
	color->b2 = buf[7];
	color->id16 = (st8)buf[8];
	return true;
}

static bool rprj_cmnt_read(RBuffer *b, R2ProjectComment *cmnt) {
	ut8 buf[RPRJ_CMNT_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	cmnt->text = r_read_le32 (buf + r_offsetof (R2ProjectComment, text));
	cmnt->mod = r_read_le32 (buf + r_offsetof (R2ProjectComment, mod));
	cmnt->delta = r_read_le64 (buf + r_offsetof (R2ProjectComment, delta));
	cmnt->size = r_read_le64 (buf + r_offsetof (R2ProjectComment, size));
	return true;
}

static bool rprj_flag_read(RBuffer *b, R2ProjectFlag *flag) {
	ut8 buf[RPRJ_FLAG_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	flag->name = r_read_le32 (buf + 0);
	flag->mod = r_read_le32 (buf + 4);
	flag->delta = r_read_le64 (buf + 8);
	flag->size = r_read_le32 (buf + 16);
	flag->extras = buf[20];
	return true;
}

static bool rprj_read_le32(RBuffer *b, ut32 *out) {
	ut8 buf[4];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	*out = r_read_le32 (buf);
	return true;
}

static bool rprj_hint_read(RBuffer *b, R2ProjectHint *hint) {
	ut8 buf[RPRJ_HINT_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	hint->kind = r_read_le32 (buf + r_offsetof (R2ProjectHint, kind));
	hint->mod = r_read_le32 (buf + r_offsetof (R2ProjectHint, mod));
	hint->delta = r_read_le64 (buf + r_offsetof (R2ProjectHint, delta));
	hint->value = r_read_le64 (buf + r_offsetof (R2ProjectHint, value));
	return true;
}

static bool rprj_xref_read(RBuffer *b, R2ProjectXref *xref) {
	ut8 buf[RPRJ_XREF_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	xref->from.mod = r_read_le32 (buf);
	xref->from.delta = r_read_le64 (buf + 4);
	xref->to.mod = r_read_le32 (buf + 12);
	xref->to.delta = r_read_le64 (buf + 16);
	xref->type = r_read_le32 (buf + 24);
	return true;
}

static bool rprj_function_read(RBuffer *b, R2ProjectFunction *fcn) {
	ut8 buf[RPRJ_FUNCTION_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	fcn->name = r_read_le32 (buf);
	fcn->addr.mod = r_read_le32 (buf + 4);
	fcn->addr.delta = r_read_le64 (buf + 8);
	fcn->attr = r_read_le32 (buf + 16);
	fcn->nbbs = r_read_le32 (buf + 20);
	fcn->nvars = r_read_le32 (buf + 24);
	return true;
}

static bool rprj_function_attr_read(RBuffer *b, R2ProjectFunctionAttr *attr) {
	ut8 buf[RPRJ_FUNCTION_ATTR_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	attr->cc = r_read_le32 (buf);
	attr->type = r_read_le32 (buf + 4);
	attr->bits = r_read_le32 (buf + 8);
	attr->flags = r_read_le32 (buf + 12);
	attr->stack = r_read_le64 (buf + 16);
	return true;
}

static bool rprj_block_read(RBuffer *b, R2ProjectBlock *bb) {
	ut8 buf[RPRJ_BLOCK_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	bb->addr.mod = r_read_le32 (buf);
	bb->addr.delta = r_read_le64 (buf + 4);
	bb->size = r_read_le64 (buf + 12);
	bb->jump.mod = r_read_le32 (buf + 20);
	bb->jump.delta = r_read_le64 (buf + 24);
	bb->fail.mod = r_read_le32 (buf + 32);
	bb->fail.delta = r_read_le64 (buf + 36);
	bb->color = r_read_le32 (buf + 44);
	return true;
}

static bool rprj_var_read(RBuffer *b, R2ProjectVar *var) {
	ut8 buf[RPRJ_VAR_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	var->name = r_read_le32 (buf);
	var->type = r_read_le32 (buf + 4);
	var->delta = (st32)r_read_le32 (buf + 8);
	var->kind = buf[12];
	var->isarg = buf[13];
	return true;
}

static void rprj_header_write(RBuffer *b) {
	ut8 buf[RPRJ_HEADER_SIZE] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectHeader, magic), RPRJ_MAGIC);
	r_write_le32 (buf + r_offsetof (R2ProjectHeader, version), RPRJ_VERSION);
	r_buf_write (b, buf, sizeof (buf));
}

static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr) {
	ut8 buf[RPRJ_HEADER_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	hdr->magic = r_read_le32 (buf + r_offsetof (R2ProjectHeader, magic));
	hdr->version = r_read_le32 (buf + r_offsetof (R2ProjectHeader, version));
	return hdr->magic == RPRJ_MAGIC;
}

static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry) {
	ut8 buf[RPRJ_ENTRY_SIZE];
	R_LOG_DEBUG ("reading entry at 0x%08"PFMT64x, r_buf_at (b));
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	entry->size = r_read_le32 (buf + r_offsetof (R2ProjectEntry, size));
	entry->type = r_read_le32 (buf + r_offsetof (R2ProjectEntry, type));
	R_LOG_DEBUG ("entry at 0x%08"PFMT64x" with type=%d(%s) and size=%d",
			r_buf_at (b), entry->type, rprj_entry_type_tostring (entry->type), entry->size);
	return true;
}

static bool rprj_entry_begin(RBuffer *b, ut64 *at, ut32 type, ut32 version) {
	*at = r_buf_at (b);
	ut8 buf[RPRJ_ENTRY_SIZE] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectEntry, size), -1);
	r_write_le32 (buf + r_offsetof (R2ProjectEntry, type), type);
	r_buf_write (b, buf, sizeof (buf));
	return true;
}

static void rprj_entry_end(RBuffer *b, ut64 at) {
	ut8 buf[sizeof (ut32)];
	r_write_le32 (buf, (ut32) (r_buf_at (b) - at));
	r_buf_write_at (b, at, buf, sizeof (buf));
}

static bool rprj_string_read(RBuffer *b, ut64 next_entry, char **s) {
	*s = NULL;
	ut8 buf[sizeof (ut32)] = {0};
	const ut64 at = r_buf_at (b);
	if (next_entry <= at || next_entry - at < sizeof (buf)) {
		return false;
	}
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	const ut32 len = r_read_le32 (buf);
	const ut64 remaining = next_entry - r_buf_at (b);
	if (len < 1 || len > remaining) {
		return false;
	}
	ut8 *data = malloc (len + 1);
	if (!data) {
		return false;
	}
	if (!rprj_read_exact (b, data, len)) {
		free (data);
		return false;
	}
	data[len] = 0;
	*s = (char *)data;
	return true;
}

static bool rprj_info_read(RBuffer *b, R2ProjectInfo *info) {
	ut8 buf[RPRJ_INFO_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	info->name = r_read_le32 (buf + r_offsetof (R2ProjectInfo, name));
	info->user = r_read_le32 (buf + r_offsetof (R2ProjectInfo, user));
	info->time = r_read_le64 (buf + r_offsetof (R2ProjectInfo, time));
	return true;
}
