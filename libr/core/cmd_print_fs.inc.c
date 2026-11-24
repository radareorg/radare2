/* radare - LGPL - Copyright 2026 - pancake */

enum {
	FS_ZOOM_ALLOCATION = R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN
		| R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN,
	FS_ZOOM_LIVE = 32,
	FS_ZOOM_DELETED = 64,
	FS_ZOOM_MAX_CELLS = 65536,
	FS_ZOOM_MAX_DEPTH = 64,
	FS_ZOOM_ENTRY_LIMIT = 0x400000,
};

typedef struct {
	RCore *core;
	RFSRoot *root;
	ut64 from;
	ut64 to;
	ut64 width;
	ut8 *cells;
	ut8 file_flag;
	bool saw_allocation;
	bool partial_files;
	int entries_left;
	SetU *live_ids;
	SetU *deleted_ids;
} FsZoom;

static RFSRoot *fs_zoom_root(RCore *core) {
	const char *cwd = r_config_get (core->config, "fs.cwd");
	if (R_STR_ISEMPTY (cwd)) {
		cwd = "/";
	}
	RFSRoot *best = NULL;
	RFSRoot *root, *automatic = NULL;
	RListIter *iter;
	size_t best_len = 0;
	r_list_foreach (core->fs->roots, iter, root) {
		size_t len = strlen (root->path);
		if (!strcmp (root->path, "/root")) {
			automatic = root;
		}
		if (len > best_len && !strncmp (root->path, cwd, len)
				&& (len == 1 || !cwd[len] || cwd[len] == '/')) {
			best = root;
			best_len = len;
		}
	}
	if (!best && !strcmp (cwd, "/")) {
		return automatic? automatic: r_list_length (core->fs->roots) == 1
			? r_list_first (core->fs->roots): NULL;
	}
	return best;
}

static bool fs_zoom_mark(FsZoom *zoom, const RFSRange *range, ut8 flags) {
	if (r_cons_is_breaked (zoom->core->cons)) {
		return false;
	}
	if (!range->size || range->physical >= zoom->to) {
		return true;
	}
	ut64 start = R_MAX (zoom->from, range->physical);
	ut64 end = range->physical + R_MIN (range->size, zoom->to - range->physical);
	if (start < end) {
		size_t i = (start - zoom->from) / zoom->width;
		size_t last = (end - 1 - zoom->from) / zoom->width;
		for (; i <= last; i++) {
			zoom->cells[i] |= flags;
		}
	}
	return true;
}

static bool fs_zoom_alloc(const RFSRange *range, void *user) {
	FsZoom *zoom = user;
	zoom->saw_allocation = true;
	return fs_zoom_mark (zoom, range, range->flags & FS_ZOOM_ALLOCATION);
}

static bool fs_zoom_extent(const RFSRange *range, void *user) {
	FsZoom *zoom = user;
	return fs_zoom_mark (zoom, range, zoom->file_flag);
}

static void fs_zoom_file(FsZoom *zoom, ut64 id, bool deleted) {
	RFS *fs = zoom->core->fs;
	RFSFile *file = r_fs_open_id (fs, zoom->root->path, id, R_FS_OPEN_CHAIN);
	if (!file) {
		zoom->partial_files = true;
		return;
	}
	zoom->file_flag = deleted? FS_ZOOM_DELETED: FS_ZOOM_LIVE;
	if (r_fs_extents (file, fs_zoom_extent, zoom) != R_FS_WALK_COMPLETE) {
		zoom->partial_files = true;
	}
	r_fs_close (fs, file);
	r_fs_file_free (file);
}

static void fs_zoom_walk(FsZoom *zoom, ut64 id, int depth, bool deleted, bool inodes) {
	if (depth > FS_ZOOM_MAX_DEPTH || !zoom->entries_left || r_cons_is_breaked (zoom->core->cons)) {
		zoom->partial_files = true;
		return;
	}
	RFSRoot *root = zoom->root;
	int view = inodes? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL | R_FS_VIEW_DELETED;
	// The selected mount must win even if another mount shadows its path.
	RList *files = root->p->dir (root, "/", id, view);
	if (!files) {
		zoom->partial_files = true;
		return;
	}
	RListIter *iter;
	RFSFile *entry;
	r_list_foreach (files, iter, entry) {
		if (!zoom->entries_left || r_cons_is_breaked (zoom->core->cons)) {
			zoom->partial_files = true;
			break;
		}
		zoom->entries_left--;
		if (!strcmp (entry->name, ".") || !strcmp (entry->name, "..")) {
			continue;
		}
		bool directory = entry->type == R_FS_FILE_TYPE_DIRECTORY;
		if ((inodes && directory) || (!directory && !strchr ("frl", entry->type))) {
			continue;
		}
		if (entry->id == UT64_MAX) {
			zoom->partial_files = true;
			continue;
		}
		bool removed = deleted || (entry->flags & R_FS_FILE_DELETED);
		SetU *seen = removed? zoom->deleted_ids: zoom->live_ids;
		if (set_u_contains (seen, entry->id)) {
			continue;
		}
		set_u_add (seen, entry->id);
		if (directory) {
			fs_zoom_walk (zoom, entry->id, depth + 1, removed, false);
		} else if (entry->size) {
			fs_zoom_file (zoom, entry->id, removed);
		}
	}
	r_list_free (files);
}

static const char *fs_zoom_files(FsZoom *zoom, int allocation) {
	RFSPlugin *plugin = zoom->root->p;
	if (allocation == R_FS_WALK_UNSUPPORTED || !plugin->dir || !plugin->open_id || !plugin->extents) {
		return "unsupported";
	}
	zoom->live_ids = set_u_new ();
	zoom->deleted_ids = set_u_new ();
	if (zoom->live_ids && zoom->deleted_ids) {
		zoom->entries_left = FS_ZOOM_ENTRY_LIMIT;
		fs_zoom_walk (zoom, UT64_MAX, 0, false, false);
		if (!strcmp (plugin->meta.name, "ext2")) {
			fs_zoom_walk (zoom, 0, 0, true, true);
		}
	} else {
		zoom->partial_files = true;
	}
	set_u_free (zoom->live_ids);
	set_u_free (zoom->deleted_ids);
	return r_cons_is_breaked (zoom->core->cons)? "stopped": zoom->partial_files? "partial": "complete";
}

static const char *fs_zoom_status(int status) {
	switch (status) {
	case R_FS_WALK_COMPLETE: return "complete";
	case R_FS_WALK_STOPPED: return "stopped";
	case R_FS_WALK_UNSUPPORTED: return "unsupported";
	default: return "error";
	}
}

static const struct {
	ut8 flag;
	char glyph;
	const char *name;
} fs_zoom_states[] = {
	{ 0, '.', "unmapped" },
	{ R_FS_RANGE_FREE, 'F', "free" },
	{ R_FS_RANGE_ALLOCATED, 'A', "allocated" },
	{ R_FS_RANGE_ORPHAN, 'O', "orphan" },
	{ R_FS_RANGE_BAD, 'B', "bad" },
	{ R_FS_RANGE_UNKNOWN, '?', "unknown" },
	{ FS_ZOOM_LIVE, 'L', "file" },
	{ FS_ZOOM_DELETED, 'D', "deleted" },
	{ FS_ZOOM_LIVE | FS_ZOOM_DELETED, '*', "mixed" },
};

static size_t fs_zoom_state(ut8 flags) {
	if ((flags & fs_zoom_states[8].flag) == fs_zoom_states[8].flag) {
		return 8;
	}
	size_t i = 8;
	while (--i) {
		if (flags & fs_zoom_states[i].flag) {
			return i;
		}
	}
	return 0;
}

static void fs_zoom_print(FsZoom *zoom, size_t count, bool json, const char *allocation, const char *files) {
	RCore *core = zoom->core;
	PJ *pj = json? r_core_pj_new (core): NULL;
	if (json) {
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ks (pj, "mount", zoom->root->path);
		pj_kn (pj, "from", zoom->from);
		pj_kn (pj, "to", zoom->to);
		pj_kn (pj, "blocksize", zoom->width);
		pj_ks (pj, "allocation_status", allocation);
		pj_ks (pj, "file_status", files);
		pj_ka (pj, "filesystem");
	} else {
		r_cons_printf (core->cons, "%s allocation=%s files=%s\n", zoom->root->path, allocation, files);
	}
	size_t i;
	for (i = 0; i < count; i++) {
		ut64 addr = zoom->from + i * zoom->width;
		ut8 flags = zoom->cells[i];
		size_t state = fs_zoom_state (flags);
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "addr", addr);
			pj_kn (pj, "size", R_MIN (zoom->width, zoom->to - addr));
			pj_kn (pj, "value", R_MIN (state * 32, 255));
			pj_kn (pj, "flags", flags);
			pj_ks (pj, "state", fs_zoom_states[state].name);
			pj_end (pj);
		} else {
			if (!(i % 64)) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"  ", addr);
			}
			r_cons_printf (core->cons, "%c", fs_zoom_states[state].glyph);
			if (i % 64 == 63 || i + 1 == count) {
				r_cons_newline (core->cons);
			}
		}
	}
	if (pj) {
		pj_end (pj);
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
}

static int cmd_print_fs_zoom(RCore *core, const char *input) {
	bool json = *input == 'j';
	if (json) {
		input++;
	}
	if (*input == '?') {
		r_cons_println (core->cons, "Usage: p=g[j] [N] or pzg[j] [N]  Show filesystem allocation and file extents");
		r_cons_println (core->cons, "fs.cwd selects the mount; zoom.from and zoom.to bound the physical byte range");
		r_cons_println (core->cons, ". unmapped  F free  A allocated  O orphan  B bad  ? unknown  L file  D deleted  * file+deleted");
		return 0;
	}
	const char *err = NULL;
	const char *arg = r_str_trim_head_ro (input);
	ut64 n = *arg? r_num_math_err (core->num, arg, &err): R_MIN (core->blocksize, FS_ZOOM_MAX_CELLS);
	if ((arg == input && *arg) || err || !n || n > FS_ZOOM_MAX_CELLS) {
		R_LOG_ERROR ("Expected a filesystem zoom cell count from 1 to %d", FS_ZOOM_MAX_CELLS);
		return 1;
	}
	RFSRoot *root = fs_zoom_root (core);
	if (!root) {
		R_LOG_ERROR ("No filesystem mount selected (see m and fs.cwd)");
		return 1;
	}
	ut64 from = R_MAX (root->delta, r_config_get_i (core->config, "zoom.from"));
	ut64 to = r_io_size (core->io);
	ut64 end = r_config_get_i (core->config, "zoom.to");
	if (end) {
		to = R_MIN (to, end);
	}
	if (to == UT64_MAX || from >= to) {
		R_LOG_ERROR ("Invalid physical range for filesystem zoom");
		return 1;
	}
	ut64 width = (to - from - 1) / n + 1;
	size_t count = (to - from - 1) / width + 1;
	ut8 *cells = calloc (count, sizeof (ut8));
	if (!cells) {
		return 1;
	}
	FsZoom zoom = { .core = core, .root = root, .from = from, .to = to, .width = width, .cells = cells };
	int va = core->io->va;
	core->io->va = false;
	r_cons_break_push (core->cons, NULL, NULL);
	int status = r_fs_ranges (core->fs, root->path, FS_ZOOM_ALLOCATION, fs_zoom_alloc, &zoom);
	const char *allocation = fs_zoom_status (status);
	if (status == R_FS_WALK_ERROR && !r_cons_is_breaked (core->cons)) {
		if (!zoom.saw_allocation) {
			// Preserve the basic allocation map when live ownership is damaged.
			status = r_fs_ranges (core->fs, root->path, FS_ZOOM_ALLOCATION & ~R_FS_RANGE_ORPHAN, fs_zoom_alloc, &zoom);
			allocation = fs_zoom_status (status);
			if (status == R_FS_WALK_COMPLETE) {
				allocation = "partial";
			}
		} else {
			allocation = "partial";
		}
	}
	const char *files = fs_zoom_files (&zoom, status);
	if (r_cons_is_breaked (core->cons) && !zoom.saw_allocation) {
		allocation = "stopped";
	}
	r_cons_break_pop (core->cons);
	core->io->va = va;
	fs_zoom_print (&zoom, status == R_FS_WALK_UNSUPPORTED? 0: count, json, allocation, files);
	free (cells);
	return 0;
}
