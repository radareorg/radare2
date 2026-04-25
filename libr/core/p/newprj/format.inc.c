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

static R2ProjectMod *rprj_find_mod(RPrjCursor *cur, ut64 addr, ut32 *mid) {
	RListIter *iter;
	ut32 id = 0;
	R2ProjectMod *mod;
	r_list_foreach (cur->mods, iter, mod) {
		if (addr >= mod->vmin && addr <= mod->vmax) {
			*mid = id;
			return mod;
		}
		id ++;
	}
	return NULL;
}

static R2ProjectMod *rprj_mod_by_id(RPrjCursor *cur, ut32 id) {
	if (id == UT32_MAX) {
		return NULL;
	}
	return (R2ProjectMod *)r_list_get_n (cur->mods, id);
}

static R2ProjectAddr rprj_addr_to_project(RPrjCursor *cur, ut64 addr) {
	R2ProjectAddr res = {
		.mod = UT32_MAX,
		.delta = addr,
	};
	ut32 mid = UT32_MAX;
	R2ProjectMod *mod = rprj_find_mod (cur, addr, &mid);
	if (mod) {
		res.mod = mid;
		res.delta = addr - mod->vmin;
	}
	return res;
}

static bool rprj_project_addr_to_va(RPrjCursor *cur, R2ProjectAddr *addr, ut64 *va) {
	if (addr->mod == UT32_MAX && addr->delta == UT64_MAX) {
		*va = UT64_MAX;
		return true;
	}
	if (addr->mod == UT32_MAX) {
		*va = addr->delta;
		return true;
	}
	R2ProjectMod *mod = rprj_mod_by_id (cur, addr->mod);
	if (!mod) {
		return false;
	}
	const ut64 size = mod->vmax >= mod->vmin? mod->vmax - mod->vmin + 1: 0;
	if (size && addr->delta >= size) {
		return false;
	}
	*va = mod->vmin + addr->delta;
	return true;
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
	ut8 buf[sizeof (R2ProjectComment)];
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
	ut8 buf[sizeof (R2ProjectHint)];
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
	R2ProjectHeader hdr = {0};
	r_write_le32 (&hdr.magic, RPRJ_MAGIC);
	r_write_le32 (&hdr.version, RPRJ_VERSION);
	r_buf_write (b, (ut8*)&hdr, sizeof (hdr));
}

static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr) {
	ut8 buf[sizeof (R2ProjectHeader)];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	hdr->magic = r_read_le32 (buf + r_offsetof (R2ProjectHeader, magic));
	hdr->version = r_read_le32 (buf + r_offsetof (R2ProjectHeader, version));
	return hdr->magic == RPRJ_MAGIC;
}

static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry) {
	ut8 buf[sizeof (R2ProjectEntry)];
	R_LOG_DEBUG ("reading entry at 0x%08"PFMT64x, r_buf_at (b));
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	entry->size = r_read_le32 (buf);
	entry->type = r_read_le32 (buf + 4);
	R_LOG_DEBUG ("entry at 0x%08"PFMT64x" with type=%d(%s) and size=%d",
			r_buf_at (b), entry->type, rprj_entry_type_tostring (entry->type), entry->size);
	return true;
}

static bool rprj_entry_begin(RBuffer *b, ut64 *at, ut32 type, ut32 version) {
	*at = r_buf_at (b);
	ut8 buf[sizeof (R2ProjectEntry)] = {0};
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

static ut32 checksum_update(ut32 csum, const ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		csum = (csum << 1) ^ buf[i] ^ (csum & 1);
	}
	return csum;
}

static ut32 checksum(RCore *core, ut64 va, ut64 size) {
	ut32 csum = 0;
	if (!size) {
		return csum;
	}
	ut8 buf[1024];
	ut64 samples[3] = { va, va, va };
	const int sample_size = R_MIN (sizeof (buf), size);
	if (size > (ut64)sample_size) {
		samples[1] = va + (size / 2);
		if (samples[1] > va + size - sample_size) {
			samples[1] = va + size - sample_size;
		}
		samples[2] = va + size - sample_size;
	}
	int i;
	for (i = 0; i < 3; i++) {
		if (i && samples[i] == samples[i - 1]) {
			continue;
		}
		const int n = r_io_read_at (core->io, samples[i], buf, sample_size);
		if (n > 0) {
			csum = checksum_update (csum ^ (ut32)(samples[i] - va), buf, n);
		}
	}
	return csum;
}

static int mod_match_score(RPrjCursor *cur, R2ProjectMod *mod, RIOMap *map) {
	int score = 0;
	const char *mod_name = rprj_st_get (cur->st, mod->name);
	const char *mod_file = rprj_st_get (cur->st, mod->file);
	const char *map_name = r_str_get (map->name);
	const char *map_file = r_io_fd_get_name (cur->core->io, map->fd);
	const ut64 mod_size = mod->vmax >= mod->vmin? mod->vmax - mod->vmin + 1: 0;
	const ut64 map_size = r_io_map_size (map);
	if (mod->csum) {
		const ut32 csum = checksum (cur->core, r_io_map_from (map), map_size);
		if (csum == mod->csum) {
			score += 100;
		}
	}
	if (mod_file && map_file) {
		if (!strcmp (mod_file, map_file)) {
			score += 30;
		} else if (!strcmp (r_file_basename (mod_file), r_file_basename (map_file))) {
			score += 15;
		}
	}
	if (mod_name && map_name && !strcmp (mod_name, map_name)) {
		score += 30;
	}
	if (mod_size && map_size) {
		if (mod_size == map_size) {
			score += 20;
		} else {
			const ut64 min = R_MIN (mod_size, map_size);
			const ut64 max = R_MAX (mod_size, map_size);
			if (max && (min * 100 / max) >= 90) {
				score += 10;
			}
		}
	}
	if (mod->pmin == map->delta) {
		score += 25;
	}
	return score;
}

static bool rprj_mods_read(RBuffer *b, R2ProjectMod *mod) {
	ut8 buf[sizeof (R2ProjectMod)];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	mod->name = r_read_le32 (buf + r_offsetof (R2ProjectMod, name));
	mod->file = r_read_le32 (buf + r_offsetof (R2ProjectMod, file));
	mod->csum = r_read_le32 (buf + r_offsetof (R2ProjectMod, csum));
	mod->pmin = r_read_le64 (buf + r_offsetof (R2ProjectMod, pmin));
	mod->pmax = r_read_le64 (buf + r_offsetof (R2ProjectMod, pmax));
	mod->vmin = r_read_le64 (buf + r_offsetof (R2ProjectMod, vmin));
	mod->vmax = r_read_le64 (buf + r_offsetof (R2ProjectMod, vmax));
	return true;
}

static void rprj_mods_write_one(RBuffer *b, R2ProjectMod *mod) {
	ut8 buf[sizeof (R2ProjectMod)] = {0};
	ut64 at = r_buf_at (b);
	if (at > UT32_MAX) {
		return;
	}
	r_write_le32 (buf + r_offsetof (R2ProjectMod, name), mod->name);
	r_write_le32 (buf + r_offsetof (R2ProjectMod, file), mod->file);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, pmin), mod->pmin);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, pmax), mod->pmax);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, vmin), mod->vmin);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, vmax), mod->vmax);
	r_write_le32 (buf + r_offsetof (R2ProjectMod, csum), mod->csum);
	r_buf_write (b, buf, sizeof (buf));
	r_buf_seek (b, at + sizeof (buf), SEEK_SET);
}

static RIOMap *rprj_coremod(RPrjCursor *cur, R2ProjectMod *mod) {
	RIDStorage *maps = &cur->core->io->maps;
	ut32 mapid;
	if (!r_id_storage_get_lowest (maps, &mapid)) {
		return NULL;
	}
	RIOMap *best = NULL;
	int best_score = 0;
	do {
		RIOMap *m = r_id_storage_get (maps, mapid);
		if (!m) {
			continue;
		}
		const int score = mod_match_score (cur, mod, m);
		if (score > best_score) {
			best = m;
			best_score = score;
		}
	} while (r_id_storage_get_next (maps, &mapid));
	return best_score >= 50? best: NULL;
}

static void rprj_mods_write(RPrjCursor *cur) {
	// iterate over current maps and write
	RBuffer *b = cur->b;
	RIDStorage *maps = &cur->core->io->maps;
	ut32 mapid;
	if (!r_id_storage_get_lowest (maps, &mapid)) {
		return;
	}
	do {
		RIOMap *m = r_id_storage_get (maps, mapid);
		if (!m) {
			continue;
		}
		ut64 va = r_io_map_from (m);
		ut64 va_end = r_io_map_to (m);
		ut64 pa = m->delta;
		ut64 pa_size = r_itv_size (m->itv);
		ut64 pa_end = pa + pa_size - 1;
		const char *name = r_str_get (m->name);

		R2ProjectMod mod = {0};
		mod.name = rprj_st_append (cur->st, name);
		const char *file = r_io_fd_get_name (cur->core->io, m->fd);
		mod.file = R_STR_ISNOTEMPTY (file)? rprj_st_append (cur->st, file): UT32_MAX;
		mod.pmin = pa;
		mod.pmax = pa_end;
		mod.vmin = va;
		mod.vmax = va_end;
		mod.csum = checksum (cur->core, va, r_io_map_size (m));
		rprj_mods_write_one (b, &mod);
		r_list_append (cur->mods, r_mem_dup (&mod, sizeof (mod)));
	} while (r_id_storage_get_next (maps, &mapid));
}

static bool rprj_info_read(RBuffer *b, R2ProjectInfo *info) {
	ut8 buf[sizeof (R2ProjectInfo)];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	info->name = r_read_le32 (buf + r_offsetof (R2ProjectInfo, name));
	info->user = r_read_le32 (buf + r_offsetof (R2ProjectInfo, user));
	info->time = r_read_le64 (buf + r_offsetof (R2ProjectInfo, time));
	return true;
}
