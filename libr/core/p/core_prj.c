/* radare - MIT - Copyright 2024-2026 - pancake */

// R2R db/cmd/newprj

#define R_LOG_ORIGIN "prj"

#include <r_core.h>

enum {
	RPRJ_MAPS,
	RPRJ_INFO,
	RPRJ_FLAG,
	RPRJ_CMNT,
	RPRJ_CMDS,
	RPRJ_BLOB,
	RPRJ_MODS,
	RPRJ_STRS,
	RPRJ_THEM,
	RPRJ_HINT,
	RPRJ_EVAL,
	RPRJ_MAGIC = 0x4a525052,
};
#define RPRJ_VERSION 2

// optional ut32 fields that may follow a R2ProjectFlag head, in bit order
enum {
	RPRJ_FLAG_SPACE     = 1 << 0, // stridx: flagspace
	RPRJ_FLAG_REALNAME  = 1 << 1, // stridx
	RPRJ_FLAG_RAWNAME   = 1 << 2, // stridx
	RPRJ_FLAG_TYPE      = 1 << 3, // stridx (meta)
	RPRJ_FLAG_COLOR     = 1 << 4, // stridx (meta)
	RPRJ_FLAG_COMMENT   = 1 << 5, // stridx (meta)
	RPRJ_FLAG_ALIAS     = 1 << 6, // stridx (meta)
	RPRJ_FLAG_DEMANGLED = 1 << 7, // no payload
};

enum {
	MODE_LOAD = 1,
	MODE_LOG = 2,
	MODE_CMD = 4,
	MODE_SCRIPT = 8
};

typedef struct {
	ut32 magic;
	ut32 version;
} R2ProjectHeader;

typedef struct {
	ut8 *data;
	ut32 size;
	ut32 capacity;
} R2ProjectStringTable;

typedef struct {
	ut32 size;
	ut32 type;
} R2ProjectEntry;

typedef struct {
	ut32 name;
	ut32 user;
	ut64 time;
} R2ProjectInfo;

typedef struct {
	ut32 name; // section name
	ut32 file; // filename associated
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 csum;
} R2ProjectMod;

typedef struct {
	ut32 name;
	ut32 mod; // associated module, used for rebasing
	ut64 delta;
	ut64 size;
	ut8 extras; // used to specify the extra bits // alignment issues i think
} R2ProjectFlag;

typedef struct {
	ut32 text;
	ut32 mod; // ut16 can be enough imho
	ut64 delta;
	ut64 size;
} R2ProjectComment;

typedef struct {
	ut32 kind; // 1=immbase, 2=newbits
	ut32 mod;  // UT32_MAX when absolute address
	ut64 delta; // relative to mod vmin or absolute if mod==UT32_MAX
	ut64 value; // value for the hint (base or bits)
} R2ProjectHint;

typedef struct {
	RCore *core;
	R2ProjectStringTable *st;
	RBuffer *b;
	RList *mods;
} Cursor;

typedef struct {
	const char *space;
	const char *realname;
	const char *rawname;
	const char *type;
	const char *color;
	const char *comment;
	const char *alias;
} FlagExtras;

static const char *entry_type_tostring(int a) {
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
	}
	return "UNKNOWN";
}

static const char *rprj_st_get(R2ProjectStringTable *st, ut32 idx) {
	if (st->data && idx < st->size) {
		return (const char *)st->data + idx;
	}
	return NULL;
}

static void rprj_st_write(RBuffer *b, R2ProjectStringTable *st) {
	r_buf_write (b, st->data, st->size);
}

static ut32 rprj_st_append(R2ProjectStringTable *st, const char *s) {
	const size_t slen = strlen (s) + 1;
	const size_t newsize = st->size + slen;
	if (newsize > st->capacity) {
		const size_t new_capacity = newsize + 1024;
		ut8 *nb = realloc (st->data, new_capacity);
		if (!nb) {
			return UT32_MAX;
		}
		st->data = nb;
		st->capacity = new_capacity;
	}
	memcpy (st->data + st->size, s, slen);
	ut32 index = st->size;
	st->size += slen;
	return index;
}

static R2ProjectMod *find_mod(Cursor *cur, ut64 addr, ut32 *mid) {
	RListIter *iter;
	ut32 id = 0;
	R2ProjectMod *mod;
	r_list_foreach (cur->mods, iter, mod) {
		if (addr >= mod->vmin && addr < mod->vmax) {
			*mid = id;
			return mod;
		}
		id ++;
	}
	return NULL;
}

static R2ProjectMod *mod_by_id(Cursor *cur, ut32 id) {
	if (id == UT32_MAX) {
		return NULL;
	}
	return (R2ProjectMod *)r_list_get_n (cur->mods, id);
}

static void write_le32(RBuffer *b, ut32 v) {
	ut8 buf[4];
	r_write_le32 (buf, v);
	r_buf_write (b, buf, sizeof (buf));
}

static ut8 emit_str(Cursor *cur, ut8 bit, const char *s) {
	if (R_STR_ISNOTEMPTY (s)) {
		write_le32 (cur->b, rprj_st_append (cur->st, s));
		return bit;
	}
	return 0;
}

static void rprj_flag_write_one(Cursor *cur, RFlagItem *fi) {
	ut32 mid = UT32_MAX;
	ut64 delta = fi->addr;
	R2ProjectMod *mod = find_mod (cur, fi->addr, &mid);
	if (mod) {
		delta = fi->addr - mod->vmin;
	}
	const ut32 space_idx = fi->space? fi->space->privtag: UT32_MAX;
	RFlagItemMeta *fim = r_flag_get_meta (cur->core->flags, fi->id);
	const char *rn = (fi->realname && fi->realname != fi->name
			&& strcmp (fi->realname, fi->name))? fi->realname: NULL;
	const char *rw = (R_STR_ISNOTEMPTY (fi->rawname)
			&& strcmp (fi->rawname, fi->name)
			&& (!rn || strcmp (fi->rawname, rn)))? fi->rawname: NULL;
	// Reserve head, emit tail (accumulating extras), patch head.
	ut64 head_at = r_buf_at (cur->b);
	ut8 head[21] = {0};
	r_buf_write (cur->b, head, sizeof (head));
	ut8 extras = fi->demangled? RPRJ_FLAG_DEMANGLED: 0;
	if (space_idx != UT32_MAX) {
		extras |= RPRJ_FLAG_SPACE;
		write_le32 (cur->b, space_idx);
	}
	extras |= emit_str (cur, RPRJ_FLAG_REALNAME, rn);
	extras |= emit_str (cur, RPRJ_FLAG_RAWNAME, rw);
	extras |= emit_str (cur, RPRJ_FLAG_TYPE, fim? fim->type: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COLOR, fim? fim->color: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COMMENT, fim? fim->comment: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_ALIAS, fim? fim->alias: NULL);
	r_write_le32 (head + 0, rprj_st_append (cur->st, fi->name));
	r_write_le32 (head + 4, mid);
	r_write_le64 (head + 8, delta);
	r_write_le32 (head + 16, fi->size);
	head[20] = extras;
	r_buf_write_at (cur->b, head_at, head, sizeof (head));
}

static bool flag_foreach_cb(RFlagItem *fi, void *user) {
	rprj_flag_write_one (user, fi);
	return true;
}

static void rprj_flag_write(Cursor *cur) {
	// Seed the privtags first
	RSpaceIter *sit;
	RSpace *sp;
	r_flag_space_foreach (cur->core->flags, sit, sp) {
		if (sp) {
			sp->privtag = R_STR_ISNOTEMPTY (sp->name)
				? rprj_st_append (cur->st, sp->name)
				: UT32_MAX;
		}
	}
	write_le32 (cur->b, (ut32)r_flag_count (cur->core->flags, NULL));
	r_flag_foreach (cur->core->flags, flag_foreach_cb, cur);
}

static void rprj_cmnt_write_one(Cursor *cur, RIntervalNode *node, RAnalMetaItem *mi) {
	R2ProjectComment cmnt = {0};
	ut64 va = node->start;
	ut32 text = rprj_st_append (cur->st, mi->str);
	ut32 mid = UT32_MAX;
	R2ProjectMod *mod = find_mod (cur, va, &mid);
	r_write_le32 (&cmnt.text, text);
	if (mod) {
		r_write_le32 (&cmnt.mod, mid);
		r_write_le64 (&cmnt.delta, va - mod->vmin);
	} else {
		r_write_le32 (&cmnt.mod, UT32_MAX);
		r_write_le64 (&cmnt.delta, va);
	}
	const ut64 size = r_meta_node_size (node);
	r_write_le64 (&cmnt.size, size);
	r_buf_write (cur->b, (ut8*)&cmnt, sizeof (cmnt));
}

static void rprj_cmnt_write(Cursor *cur) {
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&cur->core->anal->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (item->type == R_META_TYPE_COMMENT) {
			rprj_cmnt_write_one (cur, node, item);
		}
	}
}

static void rprj_cmnt_read(RBuffer *b, R2ProjectComment *cmnt) {
	ut8 buf[sizeof (R2ProjectComment)];
	r_buf_read (b, buf, sizeof (buf));
	cmnt->text = r_read_le32 (buf + r_offsetof (R2ProjectComment, text));
	cmnt->mod = r_read_le32 (buf + r_offsetof (R2ProjectComment, mod));
	cmnt->delta = r_read_le64 (buf + r_offsetof (R2ProjectComment, delta));
	cmnt->size = r_read_le64 (buf + r_offsetof (R2ProjectComment, size));
}
static bool rprj_flag_read(RBuffer *b, R2ProjectFlag *flag) {
	ut8 buf[4 + 4 + 8 + 4 + 1];
	if (r_buf_read (b, buf, sizeof (buf)) != (st64)sizeof (buf)) {
		return false;
	}
	flag->name = r_read_le32 (buf + 0);
	flag->mod = r_read_le32 (buf + 4);
	flag->delta = r_read_le64 (buf + 8);
	flag->size = r_read_le32 (buf + 16);
	flag->extras = buf[20];
	return true;
}

static bool read_le32(RBuffer *b, ut32 *out) {
	ut8 buf[4];
	if (r_buf_read (b, buf, sizeof (buf)) != (st64)sizeof (buf)) {
		return false;
	}
	*out = r_read_le32 (buf);
	return true;
}

static void rprj_hint_read(RBuffer *b, R2ProjectHint *hint) {
	ut8 buf[sizeof (R2ProjectHint)];
	r_buf_read (b, buf, sizeof (buf));
	hint->kind = r_read_le32 (buf + r_offsetof (R2ProjectHint, kind));
	hint->mod = r_read_le32 (buf + r_offsetof (R2ProjectHint, mod));
	hint->delta = r_read_le64 (buf + r_offsetof (R2ProjectHint, delta));
	hint->value = r_read_le64 (buf + r_offsetof (R2ProjectHint, value));
}

static void rprj_header_write(RBuffer *b) {
	R2ProjectHeader hdr = {0};
	r_write_le32 (&hdr.magic, RPRJ_MAGIC);
	r_write_le32 (&hdr.version, RPRJ_VERSION);
	r_buf_write (b, (ut8*)&hdr, sizeof (hdr));
}

static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr) {
	ut8 buf[sizeof (R2ProjectHeader)];
	if (r_buf_read (b, buf, sizeof (buf)) < 1) {
		return false;
	}
	hdr->magic = r_read_le32 (buf + r_offsetof (R2ProjectHeader, magic));
	hdr->version = r_read_le32 (buf + r_offsetof (R2ProjectHeader, version));
	return hdr->magic == RPRJ_MAGIC;
}

static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry) {
	ut8 buf[sizeof (R2ProjectEntry)];
	R_LOG_DEBUG ("reading entry at 0x%08"PFMT64x, r_buf_at (b));
	if (r_buf_read (b, buf, sizeof (buf)) < 1) {
		return false;
	}
	entry->size = r_read_le32 (buf);
	entry->type = r_read_le32 (buf + 4);
	R_LOG_DEBUG ("entry at 0x%08"PFMT64x" with type=%d(%s) and size=%d",
			r_buf_at (b), entry->type, entry_type_tostring (entry->type), entry->size);
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

static bool rprj_string_read(RBuffer *b, char **s) {
	*s = NULL;
	ut8 buf[sizeof (ut32)] = {0};
	if (r_buf_read (b, buf, sizeof (buf)) != (st64)sizeof (buf)) {
		return false;
	}
	const ut32 len = r_read_le32 (buf);
	const ut64 remaining = r_buf_size (b) - r_buf_at (b);
	if (len < 1 || len > remaining) {
		return false;
	}
	ut8 *data = malloc (len + 1);
	if (!data) {
		return false;
	}
	if (r_buf_read (b, data, len) != (st64)len) {
		free (data);
		return false;
	}
	data[len] = 0;
	*s = (char *)data;
	return true;
}

static ut32 checksum(RCore *core, ut64 va, size_t size) {
	ut32 csum = 0;
	ut8 *buf = malloc (size);
	if (buf) {
		r_io_read_at (core->io, va, buf, size);
		int i;
		for (i = 0; i < size; i++) {
			csum = (csum << 1) ^ buf[i] ^ (csum & 1);
		}
	}
	return csum;
}

static bool rprj_mods_read(RBuffer *b, R2ProjectMod *mod) {
	ut8 buf[sizeof (R2ProjectMod)];
	r_buf_read (b, buf, sizeof (buf));
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

static RIOMap *coremod(Cursor *cur, R2ProjectMod *mod) {
	// iterate over current maps and write
	RBuffer *b = cur->b;
	RIDStorage *maps = &cur->core->io->maps;
	ut32 mapid;
	r_id_storage_get_lowest (maps, &mapid);
	ut64 at = r_buf_at (b);
	ut64 bsz = r_buf_size (b);
	const char *mod_name = rprj_st_get (cur->st, mod->name);
	do {
		RIOMap *m = r_id_storage_get (maps, mapid);
		if (!m) {
			R_LOG_WARN ("Cannot find mapid %d", mapid);
			break;
		}
		const char *name = r_str_get (m->name);
		ut64 va = r_io_map_from (m);
		ut32 csum = checksum (cur->core, va, 1024);
		if (csum && csum == mod->csum) {
			return m;
		}
		// XXX name is a very bad heuristic for 1:1 mapping
		if (mod_name && !strcmp (name, mod_name)) {
			return m;
		}
		if (at + sizeof (R2ProjectMod) >= bsz) {
			// should never happen
			break;
		}
		at += sizeof (R2ProjectMod);
		r_buf_seek (b, at, SEEK_SET);
	} while (r_id_storage_get_next (maps, &mapid));
	return NULL;
}

static void rprj_mods_write(Cursor *cur) {
	// iterate over current maps and write
	RBuffer *b = cur->b;
	RIDStorage *maps = &cur->core->io->maps;
	ut32 mapid;
	r_id_storage_get_lowest (maps, &mapid);
	ut64 at = r_buf_at (b);
	ut64 bsz = r_buf_size (b);
	do {
		RIOMap *m = r_id_storage_get (maps, mapid);
		if (!m) {
			R_LOG_WARN ("Cannot find mapid %d", mapid);
			break;
		}
		ut64 va = r_io_map_from (m);
		ut64 va_end = r_io_map_to (m);
		ut64 pa = m->delta;
		ut64 pa_size = r_itv_size (m->itv);
		ut64 pa_end = pa + pa_size - 1;
		const char *name = r_str_get (m->name);

		R2ProjectMod mod = {0};
		mod.name = rprj_st_append (cur->st, name);
		mod.file = UT32_MAX;
		mod.pmin = pa;
		mod.pmax = pa_end;
		mod.vmin = va;
		mod.vmax = va_end;
		mod.csum = checksum (cur->core, va, 1024);
		rprj_mods_write_one (b, &mod);
		r_list_append (cur->mods, r_mem_dup (&mod, sizeof (mod)));
		if (at + sizeof (R2ProjectMod) >= bsz) {
			// should never happen
			break;
		}
		at += sizeof (R2ProjectMod);
		r_buf_seek (b, at, SEEK_SET);
	} while (r_id_storage_get_next (maps, &mapid));
}

typedef struct {
	Cursor *cur;
} HintsCtx;

static bool rprj_hints_collect_cb(ut64 addr, const RVecAnalAddrHintRecord *records, void *user) {
	HintsCtx *ctx = (HintsCtx*)user;
	Cursor *cur = ctx->cur;
	const RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		ut32 kind = 0;
		ut64 val = 0;
		switch (record->type) {
		case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
			kind = 1;
			val = (ut64)record->immbase;
			break;
		case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
			kind = 2;
			val = (ut64)record->newbits;
			break;
		default:
			break;
		}
		if (!kind) {
			continue;
		}
		R2ProjectHint hint = {0};
		ut32 mid = UT32_MAX;
		R2ProjectMod *mod = find_mod (cur, addr, &mid);
		r_write_le32 (&hint.kind, kind);
		if (mod) {
			r_write_le32 (&hint.mod, mid);
			r_write_le64 (&hint.delta, addr - mod->vmin);
		} else {
			r_write_le32 (&hint.mod, UT32_MAX);
			r_write_le64 (&hint.delta, addr);
		}
		r_write_le64 (&hint.value, val);
		r_buf_write (cur->b, (const ut8*)&hint, sizeof (hint));
	}
	return true;
}

static void rprj_hints_write(Cursor *cur) {
	HintsCtx ctx = { cur };
	r_anal_addr_hints_foreach (cur->core->anal, rprj_hints_collect_cb, &ctx);
}

static bool evalkey_is_saveable(RConfigNode *node) {
	if (r_config_node_is_ro (node)) {
		return false;
	}
	if (R_STR_ISEMPTY (node->name)) {
		return false;
	}
	// TODO this information nust be tied to the config vars and this function must go away soon or late
	static const char *skip_prefixes[] = {
		"dir.",
		"bin.limit", //triggers binreload wtf
		"file.",
		"prj.",
		"scr.",
		"env.",
		"stdin",
		"pdb.",
		"cfg.user",
		"cfg.log.",
		"cfg.debug",
		"cfg.prefixdump",
		"cmd.log",
		"dbg.backend",
		"dbg.btalgo",
		"http.",
		"key.",
		NULL,
	};
	const char *n = node->name;
	int i;
	for (i = 0; skip_prefixes[i]; i++) {
		if (r_str_startswith (n, skip_prefixes[i])) {
			return false;
		}
	}
	return true;
}

static void rprj_eval_write(Cursor *cur) {
	RBuffer *b = cur->b;
	const ut64 count_at = r_buf_at (b);
	write_le32 (b, 0);
	ut32 count = 0;
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (cur->core->config->nodes, iter, node) {
		if (!evalkey_is_saveable (node)) {
			continue;
		}
		const char *val = r_str_get (node->value);
		ut32 k = rprj_st_append (cur->st, node->name);
		ut32 v = rprj_st_append (cur->st, val);
		if (k == UT32_MAX || v == UT32_MAX) {
			continue;
		}
		write_le32 (b, k);
		write_le32 (b, v);
		count++;
	}
	ut8 buf[4];
	r_write_le32 (buf, count);
	r_buf_write_at (b, count_at, buf, sizeof (buf));
}

static void rprj_eval_load(Cursor *cur, int mode) {
	RBuffer *b = cur->b;
	RCore *core = cur->core;
	R2ProjectStringTable *st = cur->st;
	ut32 count = 0;
	if (!read_le32 (b, &count)) {
		return;
	}
	ut32 i;
	for (i = 0; i < count; i++) {
		ut32 k, v;
		if (!read_le32 (b, &k) || !read_le32 (b, &v)) {
			R_LOG_WARN ("Truncated eval record %u/%u", i, count);
			break;
		}
		const char *name = rprj_st_get (st, k);
		const char *value = rprj_st_get (st, v);
		if (!name || !value) {
			R_LOG_WARN ("Invalid eval string index (%u,%u)", k, v);
			continue;
		}
		if (mode & MODE_LOG) {
			r_cons_printf (core->cons, "      %s = %s\n", name, value);
		}
		if (mode & MODE_SCRIPT) {
			r_cons_printf (core->cons, "'e %s=%s\n", name, value);
		}
		if (mode & MODE_LOAD) {
			r_config_set (core->config, name, value);
		}
	}
}

static void rprj_info_read(RBuffer *b, R2ProjectInfo *info) {
	ut8 buf[sizeof (R2ProjectInfo)];
	r_buf_read (b, buf, sizeof (buf));
	info->name = r_read_le32 (buf + r_offsetof (R2ProjectInfo, name));
	info->user = r_read_le32 (buf + r_offsetof (R2ProjectInfo, user));
	info->time = r_read_le64 (buf + r_offsetof (R2ProjectInfo, time));
}

// -------------------------- >8 --------------------------

static void prjhelp(void) {
	R_LOG_INFO ("prj save [file]   - save current state into a project file");
	R_LOG_INFO ("prj info [file]   - show information about the project file");
	R_LOG_INFO ("prj load [file]   - merge project information into the current session");
	R_LOG_INFO ("prj open [file]   - close current session and open the project from scratch");
	R_LOG_INFO ("prj r2 [file]     - print an r2 script for parsing purposes");
}

static void prj_save(RCore *core, const char *file) {
	RBuffer *b = r_buf_new ();
	rprj_header_write (b);
	R2ProjectStringTable st = {0};
	Cursor cur = {
		.core = core,
		.st = &st,
		.b = b,
		.mods = r_list_newf (free),
	};
	ut64 at;
	if (rprj_entry_begin (b, &at, RPRJ_INFO, 1)) {
		const char *prj_name = r_config_get (core->config, "prj.name");
		const char *prj_user = r_config_get (core->config, "cfg.user");
		R2ProjectInfo info = {
			.name = rprj_st_append (&st, r_str_get (prj_name)),
			.user = rprj_st_append (&st, r_str_get (prj_user)),
			.time = r_time_now ()
		};
		r_buf_write (b, (const ut8*)&info, sizeof (info));
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_MODS, 1)) {
		rprj_mods_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_FLAG, 1)) {
		rprj_flag_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_CMNT, 1)) {
		rprj_cmnt_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_HINT, 1)) {
		rprj_hints_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_EVAL, 1)) {
		rprj_eval_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_STRS, 1)) {
		rprj_st_write (b, &st);
		rprj_entry_end (b, at);
	}
	// -------------
	bool can_write = true;
	if (r_file_exists (file)) {
		const bool isint = r_config_get_b (core->config, "scr.interactive");
		if (isint && !r_cons_yesno (core->cons, 'y', "Overwrite project file (Y/n)")) {
			R_LOG_ERROR ("File exists");
			can_write = false;
		} else {
			r_file_rm (file);
		}
	}
	if (can_write) {
		ut64 size;
		const ut8 *data = r_buf_data (b, &size);
		if (!r_file_dump (file, data, size, false)) {
			R_LOG_ERROR ("Cannot write file");
		}
	}
	r_unref (b);
	r_list_free (cur.mods);
	free (st.data);
}

static ut8 *rprj_find(RBuffer *b, ut32 type, ut32 *size) {
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);
	ut64 last = r_buf_size (b);
	ut64 at = r_buf_at (b);
	*size = 0;
	while (r_buf_at (b) < last) {
		R2ProjectEntry entry = {0};
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("find: Cannot read entry");
			break;
		}
		if (entry.size > ST32_MAX) {
			R_LOG_ERROR ("invalid size");
			break;
		}
		if (entry.type == type) {
			const ut32 data_size = entry.size - sizeof (R2ProjectEntry);
			ut8 *buf = malloc (data_size);
			if (buf) {
				*size = data_size;
				r_buf_read_at (b, at + sizeof (R2ProjectEntry), buf, data_size);
				return buf;
			}
			return NULL;
		}
		at += entry.size;
		r_buf_seek (b, at, SEEK_SET); // entry.size, SEEK_CUR);
	}
	return NULL;
}

static FlagExtras read_flag_extras(Cursor *cur, ut8 extras) {
	FlagExtras fe = {0};
	RBuffer *b = cur->b;
	R2ProjectStringTable *st = cur->st;
	ut32 idx;
	if ((extras & RPRJ_FLAG_SPACE) && read_le32 (b, &idx)) {
		fe.space = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_REALNAME) && read_le32 (b, &idx)) {
		fe.realname = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_RAWNAME) && read_le32 (b, &idx)) {
		fe.rawname = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_TYPE) && read_le32 (b, &idx)) {
		fe.type = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_COLOR) && read_le32 (b, &idx)) {
		fe.color = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_COMMENT) && read_le32 (b, &idx)) {
		fe.comment = rprj_st_get (st, idx);
	}
	if ((extras & RPRJ_FLAG_ALIAS) && read_le32 (b, &idx)) {
		fe.alias = rprj_st_get (st, idx);
	}
	return fe;
}

static void rprj_flag_load(Cursor *cur, int mode) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	R2ProjectStringTable *st = cur->st;
	ut32 fcount = 0;
	if (!read_le32 (b, &fcount)) {
		return;
	}
	ut32 i;
	for (i = 0; i < fcount; i++) {
		R2ProjectFlag flag;
		if (!rprj_flag_read (b, &flag)) {
			R_LOG_WARN ("Truncated flag record %u/%u", i, fcount);
			break;
		}
		FlagExtras fe = read_flag_extras (cur, flag.extras);
		const char *flag_name = rprj_st_get (st, flag.name);
		if (!flag_name) {
			R_LOG_WARN ("Invalid flag string index %u", flag.name);
			continue;
		}
		ut64 va = flag.delta;
		if (flag.mod != UT32_MAX) {
			R2ProjectMod *mod = mod_by_id (cur, flag.mod);
			if (!mod) {
				R_LOG_WARN ("Cannot find map for %s", flag_name);
				continue;
			}
			va += mod->vmin;
		}
		if (mode & MODE_SCRIPT) {
			// flag names are sanitized by r_flag_set; meta fields may contain
			// arbitrary bytes and are intentionally skipped here until the
			// flag subcommands support a base64 form (like CCu).
			r_cons_printf (core->cons, fe.space? "'fs %s\n": "'fs *\n", fe.space);
			r_cons_printf (core->cons, "'f %s %u 0x%08"PFMT64x"\n",
				flag_name, flag.size, va);
		}
		if (mode & MODE_LOAD) {
			RFlagItem *fi = fe.space
				? r_flag_set_inspace (core->flags, fe.space, flag_name, va, flag.size)
				: r_flag_set (core->flags, flag_name, va, flag.size);
			if (!fi) {
				continue;
			}
			// override autospace's prefix match with what the file encoded
			fi->space = fe.space? r_flag_space_get (core->flags, fe.space): NULL;
			fi->demangled = (flag.extras & RPRJ_FLAG_DEMANGLED);
			if (fe.realname) {
				r_flag_item_set_realname (core->flags, fi, fe.realname);
			}
			if (fe.rawname && strcmp (fe.rawname, flag_name)) {
				r_flag_item_set_rawname (core->flags, fi, fe.rawname);
			}
			if (fe.type) {
				r_flag_item_set_type (core->flags, fi, fe.type);
			}
			if (fe.color) {
				r_flag_item_set_color (core->flags, fi, fe.color);
			}
			if (fe.comment) {
				r_flag_item_set_comment (core->flags, fi, fe.comment);
			}
			if (R_STR_ISNOTEMPTY (fe.alias)) {
				r_flag_item_set_alias (core->flags, fi, fe.alias);
			}
		}
	}
}

static void prj_load(RCore *core, const char *file, int mode) {
	RBuffer *b = r_buf_new_from_file (file);
	if (!b) {
		R_LOG_ERROR ("Cannot open file");
		return;
	}
	R2ProjectHeader hdr;
	if (!rprj_header_read (b, &hdr)) {
		R_LOG_ERROR ("Invalid file type");
		r_unref (b);
		return;
	}
	if (hdr.version != RPRJ_VERSION) {
		R_LOG_ERROR ("Unsupported project version %d (this build understands version %d)", hdr.version, RPRJ_VERSION);
		r_unref (b);
		return;
	}
	if (mode & MODE_LOG) {
		r_cons_printf (core->cons, "Project {\n");
		r_cons_printf (core->cons, "  Header {\n");
		r_cons_printf (core->cons, "    magic = 0x%08x OK\n", hdr.magic);
		r_cons_printf (core->cons, "    version = %d\n", hdr.version);
		r_cons_printf (core->cons, "  }\n");
	}
	R2ProjectStringTable st = {0};
	Cursor cur = {
		.core = core,
		.st = &st,
		.b = b,
		.mods = r_list_newf (free),
	};
	st.data = rprj_find (b, RPRJ_STRS, &st.size);
	if (!st.data) {
		R_LOG_ERROR ("Missing string table (RPRJ_STRS) in project file");
		r_list_free (cur.mods);
		r_unref (b);
		return;
	}
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);

	ut32 modsize = 0;
	ut8 *modsbuf = rprj_find (b, RPRJ_MODS, &modsize);
	RBuffer *mods = modsbuf? r_buf_new_with_bytes (modsbuf, modsize): NULL;
	if (mods) {
		ut32 n = 0;
		while (n < modsize) {
			R2ProjectMod mod;
			if (!rprj_mods_read (mods, &mod)) {
				R_LOG_ERROR ("Cannot read mod");
				break;
			}
			R_LOG_DEBUG ("MOD: %s + 0x%08"PFMT64x, rprj_st_get (&st, mod.name), mod.vmin);
			r_list_append (cur.mods, r_mem_dup (&mod, sizeof (mod)));
			n += sizeof (mod);
		}
		RListIter *iter;
		R2ProjectMod *mod;
		r_list_foreach (cur.mods, iter, mod) {
			RIOMap *map = coremod (&cur, mod);
			if (map) {
				mod->vmin = r_io_map_from (map);
				mod->vmax = r_io_map_to (map);
			}
		}
	}

	R2ProjectEntry entry;
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);
	ut64 next_entry = r_buf_at (b);
	int n = 0;
	const ut64 bsz = r_buf_size (b);
	while (r_buf_at (b) < bsz) {
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("Cannot read entry");
			break;
		}
		if (mode & MODE_LOG) {
			r_cons_printf (core->cons, "  Entry<%s> {\n", entry_type_tostring (entry.type));
			r_cons_printf (core->cons, "    type = 0x%02x\n", entry.type);
			r_cons_printf (core->cons, "    size = %d\n", entry.size);
		}
		if (mode & MODE_SCRIPT) {
			r_cons_printf (core->cons, "'f entry%d.%s=0x%08"PFMT64x"\n", n, entry_type_tostring (entry.type), r_buf_at (b));
		}
		next_entry += entry.size;
		switch (entry.type) {
		case RPRJ_STRS:
			{
				// string table
				const char *data = (const char *)r_buf_data (b, NULL);
				int i;
				int p = r_buf_at (b);
				// for (i = sizeof (R2ProjectEntry); i < entry.size; i++)
				if (mode & MODE_LOG) {
					r_cons_printf (core->cons, "      => (%d) ", (int)strlen (data + p));
					for (i = 0; i < entry.size - 16; i++) {
						const char ch = data[p + i];
						if (ch == 0) {
							r_cons_printf (core->cons, "\n      => (%d) ", (int)strlen (data + i + p + 1));
						}
						r_cons_printf (core->cons, "%c", ch);
					}
				}
				r_cons_printf (core->cons, "\n");
				break;
			}
		case RPRJ_MODS: // modules
			if (mode & MODE_LOG) {
				// walk and print them
			}
			break;
		case RPRJ_MAPS:
			// rprj_maps_read (fd);
			break;
		case RPRJ_CMDS:
			if (mode & MODE_LOG) {
				r_cons_printf (core->cons, "    [\n");
			}
			while (r_buf_at (b) < next_entry) {
				// this entry requires disabled sandbox
				char *script;
				if (!rprj_string_read (b, &script)) {
					R_LOG_ERROR ("Cannot read string");
					break;
				}
				if (mode & MODE_LOG) {
					r_cons_printf (core->cons, "      '%s'\n", script);
				}
				if (mode & MODE_CMD) {
					r_core_cmd0 (core, script);
				}
				free (script);
			}
			if (mode & MODE_LOG) {
				r_cons_printf (core->cons, "    ]\n");
			}
			break;
		case RPRJ_INFO:
			{
				R2ProjectInfo cmds = {0};
				rprj_info_read (b, &cmds);
				const char *name = rprj_st_get (&st, cmds.name);
				const char *user = rprj_st_get (&st, cmds.user);
				if (mode & MODE_LOG) {
					r_cons_printf (core->cons, "    ProjectInfo {\n");
					r_cons_printf (core->cons, "      Name: %s\n", name);
					r_cons_printf (core->cons, "      User: %s\n", user);
					//r_cons_printf (core->cons, "      Date: %s\n", r_time_usecs_tostring (cmds.time));
					r_cons_printf (core->cons, "    }\n");
				}
			}
			break;
		case RPRJ_CMNT:
			{
				ut64 at = r_buf_at (b);
				ut64 last = at + entry.size - 16;
				while (at < last) {
					R2ProjectComment cmnt;
					rprj_cmnt_read (b, &cmnt);
					const char *cmnt_text = rprj_st_get (&st, cmnt.text);
					if (!cmnt_text) {
						R_LOG_WARN ("Invalid comment string index %u", cmnt.text);
						at += sizeof (cmnt);
						continue;
					}
					R2ProjectMod *mod = mod_by_id (&cur, cmnt.mod);
					if (mod) {
						ut64 va = mod->vmin + cmnt.delta;
						char *b64 = sdb_encode ((const ut8 *)cmnt_text, strlen (cmnt_text));
						if (b64) {
							char *cmd = r_str_newf ("CCu base64:%s", b64);
							if (mode & MODE_SCRIPT) {
								eprintf ("'@0x%08"PFMT64x"'%s\n", va, cmd);
							}
							if (mode & MODE_LOAD) {
								r_core_call_at (core, va, cmd);
							}
							free (cmd);
							free (b64);
						}
					} else {
						R_LOG_WARN ("Cant find map for %s", cmnt_text);
					}
					at += sizeof (cmnt);
				}
			}
			break;
		case RPRJ_FLAG:
			rprj_flag_load (&cur, mode);
			break;
		case RPRJ_EVAL:
			rprj_eval_load (&cur, mode);
			break;
		case RPRJ_HINT:
			{
				ut64 at = r_buf_at (b);
				ut64 last = at + entry.size - 16;
				while (at < last) {
					R2ProjectHint hint;
					rprj_hint_read (b, &hint);
					R2ProjectMod *mod = mod_by_id (&cur, hint.mod);
					ut64 va = mod? mod->vmin + hint.delta: hint.delta;
					if (hint.kind == 1) { // immbase
						int base = (int)hint.value;
						if (mode & MODE_SCRIPT) {
							eprintf ("'ahi %d @ 0x%08"PFMT64x"\n", base, va);
						}
						if (mode & MODE_LOAD) {
							r_anal_hint_set_immbase (core->anal, va, base);
						}
					} else if (hint.kind == 2) { // newbits
						int nbits = (int)hint.value;
						if (mode & MODE_SCRIPT) {
							eprintf ("'ahb %d @ 0x%08"PFMT64x"\n", nbits, va);
						}
						if (mode & MODE_LOAD) {
							r_anal_hint_set_newbits (core->anal, va, nbits);
						}
					}
					at += sizeof (hint);
				}
			}
			break;
		}
		if (mode & MODE_LOG) {
			r_cons_printf (core->cons, "  }\n");
		}
		// skip to the next entry
		r_buf_seek (b, next_entry, SEEK_SET);
		n++;
	}
	if (mode & MODE_LOG) {
		r_cons_printf (core->cons, "}\n");
	}
	r_unref (mods);
	free (modsbuf);
	r_list_free (cur.mods);
	free (st.data);
	r_unref (b);
}

// destructive: wipes the current session and loads the project into a clean
// environment. use prj_load when you want to merge the project data into the
// existing session without losing current analysis.
static void prj_open(RCore *core, const char *file) {
	if (!r_file_exists (file)) {
		R_LOG_ERROR ("Cannot find project file: %s", file);
		return;
	}
	const bool isint = r_config_get_b (core->config, "scr.interactive");
	if (isint && !r_cons_yesno (core->cons, 'n',
			"Opening a project discards the current session (files, flags, anal, config). Continue? (y/N)")) {
		R_LOG_INFO ("Aborted");
		return;
	}
	r_core_cmd0 (core, "o--");
	r_config_set (core->config, "prj.name", "");
	prj_load (core, file, MODE_LOAD | MODE_CMD);
}

static void prjcmd(RCore *core, const char *mod, const char *arg) {
	if (arg) {
		char *argstr = strdup (arg);
		char *arg2 = strchr (argstr, ' ');
		if (arg2) {
			*arg2 = 0;
			arg2 = (char *)r_str_trim_head_ro (arg2 + 1);
		}
		if (arg2) {
			if (!strcmp (argstr, "save")) {
				prj_save (core, arg2);
			} else if (!strcmp (argstr, "load")) {
				prj_load (core, arg2, MODE_LOAD | MODE_CMD);
			} else if (!strcmp (argstr, "open")) {
				prj_open (core, arg2);
			} else if (!strcmp (argstr, "r2")) {
				prj_load (core, arg2, MODE_SCRIPT);
			} else if (!strcmp (argstr, "info")) {
				prj_load (core, arg2, MODE_LOG);
			}
		} else {
			prjhelp ();
		}
		free (argstr);
	} else {
		prjhelp ();
	}
}

static bool callback(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (r_str_startswith (input, "prj")) {
		const char *mod = input + 3;
		const char *arg = strchr (mod, ' ');
		if (*mod == ' ') {
			mod = NULL;
		}
		if (arg) {
			arg = r_str_trim_head_ro (arg + 1);
		}
		prjcmd (core, mod, arg);
		return true;
	}
	return false;
}

static bool plugin_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (!core || !core->autocomplete) {
		return true;
	}
	if (r_core_autocomplete_find (core->autocomplete, "prj", true)) {
		return true;
	}
	RCoreAutocomplete *root = r_core_autocomplete_add (core->autocomplete, "prj", R_CORE_AUTOCMPLT_DFLT, true);
	if (!root) {
		return true;
	}
	const char *subs[] = { "save", "load", "open", "info", "r2", NULL };
	int i;
	for (i = 0; subs[i]; i++) {
		r_core_autocomplete_add (root, subs[i], R_CORE_AUTOCMPLT_FILE, true);
	}
	return true;
}

static bool plugin_fini(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (core && core->autocomplete) {
		r_core_autocomplete_remove (core->autocomplete, "prj");
	}
	return true;
}

RCorePlugin r_core_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Experimental binary projects",
		.author = "pancake",
		.license = "MIT",
	},
	.init = plugin_init,
	.fini = plugin_fini,
	.call = callback,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_prj,
	.version = R2_VERSION
};
#endif
