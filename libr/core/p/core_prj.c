/* radare - MIT - Copyright 2024 - pancake */

#define R_LOG_ORIGIN "prj"

#include <r_core.h>
static inline ut64 r_buf_at(RBuffer *b) {
	return r_buf_seek (b, 0, R_BUF_CUR);
}

enum {
	RPRJ_MAPS,
	RPRJ_INFO,
	RPRJ_FLAG,
	RPRJ_CMNT,
	RPRJ_CMDS,
	RPRJ_BLOB,
	RPRJ_MODS,
	RPRJ_STRS,
	RPRJ_MAGIC = 0x4a525052,
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
	ut32 mod;
	ut64 delta;
	ut64 size;
} R2ProjectFlag;

typedef struct {
	ut32 text;
	ut32 mod;
	ut64 delta;
	ut64 size;
} R2ProjectComment;

typedef struct {
	RCore *core;
	R2ProjectStringTable *st;
	RBuffer *b;
	RList *mods;
} Cursor;

static const char *entry_type_tostring(int a) {
	switch (a) {
	case RPRJ_INFO: return "Info";
	case RPRJ_MAPS: return "Maps";
	case RPRJ_CMDS: return "Cmds";
	case RPRJ_FLAG: return "Flags";
	case RPRJ_MODS: return "Mods";
	case RPRJ_BLOB: return "Blob";
	case RPRJ_STRS: return "Strings";
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

static void rprj_flag_write_one(Cursor *cur, RFlagItem *fi) {
	R2ProjectFlag flag;
	ut32 name = rprj_st_append (cur->st, fi->name);
	ut32 mid = UT32_MAX;
	R2ProjectMod *mod = find_mod (cur, fi->addr, &mid);
	r_write_le32 (&flag.name, name);
	if (mod) {
		r_write_le32 (&flag.mod, mid);
		r_write_le64 (&flag.delta, fi->addr - mod->vmin);
	} else {
		r_write_le32 (&flag.mod, UT32_MAX);
		r_write_le64 (&flag.delta, fi->addr);
	}
	r_write_le32 (&flag.size, fi->size);
	r_buf_write (cur->b, (ut8*)&flag, sizeof (flag));
}

static bool flag_foreach_cb(RFlagItem *fi, void *user) {
	Cursor *cur = (Cursor*) user;
	rprj_flag_write_one (cur, fi);
	return true;
}

static void rprj_flag_write(Cursor *cur) {
	r_flag_foreach (cur->core->flags, flag_foreach_cb, cur);
}

static void rprj_cmnt_write_one(Cursor *cur, RIntervalNode *node, RAnalMetaItem *mi) {
	R2ProjectComment cmnt;
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
	const int size = r_meta_node_size (node);
	r_write_le32 (&cmnt.size, size);
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
	ut8 buf[sizeof (R2ProjectFlag)];
	r_buf_read (b, buf, sizeof (buf));
	cmnt->text = r_read_le32 (buf + r_offsetof (R2ProjectComment, text));
	cmnt->mod = r_read_le32 (buf + r_offsetof (R2ProjectComment, mod));
	cmnt->delta = r_read_le64 (buf + r_offsetof (R2ProjectComment, delta));
	cmnt->size = r_read_le64 (buf + r_offsetof (R2ProjectComment, size));
}
static void rprj_flag_read(RBuffer *b, R2ProjectFlag *flag) {
	ut8 buf[sizeof (R2ProjectFlag)];
	r_buf_read (b, buf, sizeof (buf));
	flag->name = r_read_le32 (buf + r_offsetof (R2ProjectFlag, name));
	flag->mod = r_read_le32 (buf + r_offsetof (R2ProjectFlag, mod));
	flag->delta = r_read_le64 (buf + r_offsetof (R2ProjectFlag, delta));
	flag->size = r_read_le64 (buf + r_offsetof (R2ProjectFlag, size));
}

static void rprj_header_write(RBuffer *b) {
	R2ProjectHeader hdr;
	r_write_le32 (&hdr.magic, RPRJ_MAGIC);
	r_write_le32 (&hdr.version, 1);
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
	ut8 buf[sizeof (ut32)] = {0};
	r_buf_read (b, buf, sizeof (buf));
	int len = r_read_le32 (buf);
	if (len < 1) {
		return false;
	}
	ut8 *data = malloc (len + 1);
	*s = NULL;
	if (R_LIKELY (data)) {
		if (r_buf_read (b, data, len) < 1) {
			free (data);
			return false;
		}
		data[len] = 0;
		*s = (char *)data;
		return true;
	}
	return false;
}

static void rprj_string_write(RBuffer *b, const char *script) {
	ut8 buf[sizeof (ut32)];
	size_t len = strlen (script);
	r_write_le32 (buf, len);
	r_buf_write (b, (const ut8*)buf, sizeof (buf));
	r_buf_write (b, (const ut8*)script, len);
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
	ut8 buf[sizeof (R2ProjectMod)];
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
		if (!strcmp (name, mod_name)) {
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
	R_LOG_INFO ("prj load [file]   - load project file into current session");
	R_LOG_INFO ("prj r2 [file]     - print an r2 script for parsing purposes");
}

static void prj_save(RCore *core, const char *file) {
	RBuffer *b = r_buf_new ();
	rprj_header_write (b);
	R2ProjectStringTable st = {0};
	Cursor cur = { core, &st, b, r_list_newf (free) };
	// --------
	ut64 at;
	if (rprj_entry_begin (b, &at, RPRJ_INFO, 1)) {
		R2ProjectInfo info = {
			.name = rprj_st_append (&st, "test-project"),
			.user = rprj_st_append (&st, "pancake"),
			.time = r_time_now ()
		};
		r_buf_write (b, (const ut8*)&info, sizeof (info));
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_MODS, 1)) {
		rprj_mods_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_CMDS, 1)) {
		rprj_string_write (b, "?e hello projects");
		rprj_string_write (b, "?e goodbye");
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_CMDS, 1)) {
		rprj_string_write (b, "?E clippy");
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
	rprj_st_append (&st, "one string");
	rprj_st_append (&st, "another one");
#if 0
	if (rprj_entry_begin (b, &at, RPRJ_MODS, 1)) {
		// TODO
		rprj_entry_end (b, at);
	}
#endif
	if (rprj_entry_begin (b, &at, RPRJ_STRS, 1)) {
		rprj_st_write (b, &st);
		rprj_entry_end (b, at);
	}
	// -------------
	if (r_file_exists (file)) {
		if (!r_kons_yesno (core->cons, 'y', "Overwrite project file (Y/n)")) {
			R_LOG_ERROR ("File exists");
			return;
		}
		r_file_rm (file);
	}
	ut64 size;
	const ut8 *data = r_buf_data (b, &size);
	if (!r_file_dump (file, data, size, false)) {
		R_LOG_ERROR ("Cannot write file");
	}
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
			ut8 *buf = malloc (entry.size);
			if (buf) {
				*size = entry.size;
				r_buf_read_at (b, at + sizeof (R2ProjectEntry), buf, entry.size);
				return buf;
			}
			return NULL;
		}
		at += entry.size;
		r_buf_seek (b, at, SEEK_SET); // entry.size, SEEK_CUR);
	}
	return NULL;
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
		return;
	}
	if (mode & MODE_LOG) {
		r_kons_printf (core->cons, "Project {\n");
		r_kons_printf (core->cons, "  Header {\n");
		r_kons_printf (core->cons, "    magic = 0x%08x OK\n", hdr.magic);
		r_kons_printf (core->cons, "    version = %d\n", hdr.version);
		r_kons_printf (core->cons, "  }\n");
	}
	R2ProjectStringTable st;
	Cursor cur = { core, &st, b, r_list_newf (free) };
	// load constants
	st.data = rprj_find (b, RPRJ_STRS, &st.size);
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);

	ut32 modsize;
	ut8 *modsbuf = rprj_find (b, RPRJ_MODS, &modsize);
	RBuffer *mods = r_buf_new_with_bytes (modsbuf, modsize);
	if (mods) {
		ut32 n = 0;
		while (n < modsize) {
			R2ProjectMod mod;
			if (!rprj_mods_read (mods, &mod)) {
				R_LOG_ERROR ("Cannot read mod");
				break;
			}
			R_LOG_INFO ("MOD: %s + 0x%08"PFMT64x, rprj_st_get (&st, mod.name), mod.vmin);
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
			r_kons_printf (core->cons, "  Entry<%s> {\n", entry_type_tostring (entry.type));
			r_kons_printf (core->cons, "    type = 0x%02x\n", entry.type);
			r_kons_printf (core->cons, "    size = %d\n", entry.size);
		}
		if (mode & MODE_SCRIPT) {
			r_kons_printf (core->cons, "'f entry%d.%s=0x%08"PFMT64x"\n", n, entry_type_tostring (entry.type), r_buf_at (b));
		}
		next_entry += entry.size;
		switch (entry.type) {
		case RPRJ_STRS: ;
			// string table
			const char *data = (const char *)r_buf_data (b, NULL);
			int i;
			int p = r_buf_at (b);
			// for (i = sizeof (R2ProjectEntry); i < entry.size; i++) {
			if (mode & MODE_LOG) {
				r_kons_printf (core->cons, "      => (%d) ", (int)strlen (data + p));
				for (i = 0; i < entry.size - 16; i++) {
					const char ch = data[p + i];
					if (ch == 0) {
						r_kons_printf (core->cons, "\n      => (%d) ", (int)strlen (data + i + p + 1));
					}
					r_kons_printf (core->cons, "%c", ch);
				}
			}
			r_kons_printf (core->cons, "\n");
			break;
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
				r_kons_printf (core->cons, "    [\n");
			}
			while (r_buf_at (b) < next_entry) {
				// this entry requires disabled sandbox
				char *script;
				if (!rprj_string_read (b, &script)) {
					R_LOG_ERROR ("Cannot read string");
					break;
				}
				if (mode & MODE_LOG) {
					r_kons_printf (core->cons, "      '%s'\n", script);
				}
				if (mode & MODE_CMD) {
					r_core_cmd0 (core, script);
				}
				free (script);
			}
			if (mode & MODE_LOG) {
				r_kons_printf (core->cons, "    ]\n");
			}
			break;
		case RPRJ_INFO:
			{
				R2ProjectInfo cmds = {0};
				rprj_info_read (b, &cmds);
				const char *name = rprj_st_get (&st, cmds.name);
				const char *user = rprj_st_get (&st, cmds.user);
				if (mode & MODE_LOG) {
					r_kons_printf (core->cons, "    ProjectInfo {\n");
					r_kons_printf (core->cons, "      Name: %s\n", name);
					r_kons_printf (core->cons, "      User: %s\n", user);
					//r_kons_printf (core->cons, "      Date: %s\n", r_time_usecs_tostring (cmds.time));
					r_kons_printf (core->cons, "    }\n");
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
					R2ProjectMod *mod = r_list_get_n (cur.mods, cmnt.mod);
					if (mod) {
						ut64 va = mod->vmin + cmnt.delta;
						if (mode & MODE_SCRIPT) {
							eprintf ("'@0x%08"PFMT64x"'CCu %s\n", va, cmnt_text);
						}
						if (mode & MODE_LOAD) {
							r_core_cmdf (core, "'@0x%08"PFMT64x"'CCu %s", va, cmnt_text);
						}
					} else {
						R_LOG_WARN ("Cant find map for %s", cmnt_text);
					}
					at += sizeof (cmnt);
				}
			}
			break;
		case RPRJ_FLAG:
			{
				ut64 at = r_buf_at (b);
				ut64 last = at + entry.size - 16;
				while (at < last) {
					R2ProjectFlag flag;
					rprj_flag_read (b, &flag);
					const char *flag_name = rprj_st_get (&st, flag.name);
					R2ProjectMod *mod = r_list_get_n (cur.mods, flag.mod);
					if (mod) {
						ut64 va = mod->vmin + flag.delta;
						if (mode & MODE_SCRIPT) {
							eprintf ("'f %s=0x%08"PFMT64x"\n", flag_name, va);
						}
						if (mode & MODE_LOAD) {
							r_flag_set (core->flags, flag_name, va, flag.size);
						}
						// r_core_cmdf (core, "'f %s=0x%08"PFMT64x, flag_name, mod->vmin + flag.delta);
						// r_kons_printf (core->cons, "%d + %d = %s\n", (int)flag.mod, (int)flag.delta, flag_name);
					} else {
						eprintf ("Cant find map for %s\n", flag_name);
					}
					at += sizeof (flag);
				}
			}
			break;
		}
		if (mode & MODE_LOG) {
			r_kons_printf (core->cons, "  }\n");
		}
		// skip to the next entry
		r_buf_seek (b, next_entry, SEEK_SET);
		n++;
	}
	if (mode & MODE_LOG) {
		r_kons_printf (core->cons, "}\n");
	}
	r_buf_free (b);
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

static int callback(void *user, const char *input) {
	RCore *core = (RCore *) user;
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

RCorePlugin r_core_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Experimental binary projects",
		.author = "pancake",
		.license = "MIT",
	},
	.call = callback,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_prj,
	.version = R2_VERSION
};
#endif
