/* radare - LGPL - Copyright 2026 - seifreed */

#include <r_anal.h>

typedef struct drcov_module_t {
	ut64 base;
	ut64 end;
	char *path;
	bool valid;
} DrcovModule;

typedef bool (*DrcovBbCb)(void *user, ut64 addr, ut16 size);

enum {
	DRCOV_PARSE_NOT_DRCOV = -2
};

static char *drcov_next_line(char *buf, size_t len, size_t *off) {
	if (!buf || !off || *off >= len) {
		return NULL;
	}
	char *line = buf + *off;
	char *end = memchr (line, '\n', len - *off);
	if (end) {
		*end = '\0';
		*off = (size_t)(end - buf) + 1;
	} else {
		*off = len;
	}
	size_t line_len = strlen (line);
	if (line_len && line[line_len - 1] == '\r') {
		line[line_len - 1] = '\0';
	}
	return line;
}

static void drcov_free_modules(DrcovModule *modules, ut32 count) {
	ut32 i;

	if (!modules) {
		return;
	}
	for (i = 0; i < count; i++) {
		free (modules[i].path);
	}
	free (modules);
}

static bool drcov_match_path(const char *a, const char *b) {
	if (!a || !b) {
		return false;
	}
	const char *base_a = r_file_basename (a);
	const char *base_b = r_file_basename (b);
	return !r_str_casecmp (base_a, base_b) || !r_str_casecmp (a, b);
}

static void drcov_remap_modules(RAnal *anal, DrcovModule *modules, ut32 count) {
	ut32 i;

	if (!anal || !anal->iob.io || !anal->iob.io->desc) {
		return;
	}
	RIO *io = anal->iob.io;
	const char *desc_name = io->desc->name;
	if (!desc_name) {
		return;
	}
	RList *map_list = r_io_map_get_by_fd (io, io->desc->fd);
	if (!map_list) {
		return;
	}
	ut64 min_addr = UT64_MAX;
	ut64 max_addr = 0;
	RListIter *iter;
	RIOMap *map;
	r_list_foreach (map_list, iter, map) {
		ut64 begin = r_io_map_begin (map);
		ut64 end = r_io_map_end (map);
		if (begin < min_addr) {
			min_addr = begin;
		}
		if (end > max_addr) {
			max_addr = end;
		}
	}
	for (i = 0; i < count; i++) {
		DrcovModule *mod = &modules[i];
		if (!mod->path) {
			continue;
		}
		if (drcov_match_path (mod->path, desc_name)) {
			if (min_addr != UT64_MAX) {
				mod->base = min_addr;
				mod->end = max_addr;
				mod->valid = true;
			}
			break;
		}
	}
	r_list_free (map_list);
}

static int drcov_parse(RAnal *anal, const char *path, DrcovBbCb cb, void *user) {
	size_t fsz = 0;
	char *buf = r_file_slurp (path, &fsz);
	if (!buf) {
		R_LOG_ERROR ("Cannot open drcov file '%s'", path);
		return -1;
	}

	size_t off = 0;
	int loaded = 0;
	char *line = drcov_next_line (buf, fsz, &off);
	if (!line || !r_str_startswith (line, "DRCOV VERSION:")) {
		free (buf);
		return DRCOV_PARSE_NOT_DRCOV;
	}
	ut32 version = (ut32)r_num_get (NULL, line + strlen ("DRCOV VERSION:"));
	if (version != 2) {
		R_LOG_ERROR ("Unsupported drcov version %u in '%s'", version, path);
		free (buf);
		return -1;
	}

	line = drcov_next_line (buf, fsz, &off);
	if (!line || !r_str_startswith (line, "DRCOV FLAVOR:")) {
		R_LOG_ERROR ("Missing drcov flavor in '%s'", path);
		free (buf);
		return -1;
	}

	line = drcov_next_line (buf, fsz, &off);
	if (!line || !r_str_startswith (line, "Module Table:")) {
		R_LOG_ERROR ("Missing module table in '%s'", path);
		free (buf);
		return -1;
	}
	ut32 module_count = 0;
	const char *count_ptr = strstr (line, "count");
	if (count_ptr) {
		count_ptr = strchr (count_ptr, ' ');
		if (count_ptr) {
			module_count = (ut32)r_num_get (NULL, count_ptr);
		}
	}
	if (!module_count) {
		R_LOG_ERROR ("Invalid module count in '%s'", path);
		free (buf);
		return -1;
	}

	line = drcov_next_line (buf, fsz, &off);
	if (!line || !r_str_startswith (line, "Columns:")) {
		R_LOG_ERROR ("Missing module columns in '%s'", path);
		free (buf);
		return -1;
	}

	size_t alloc_size;
	if (r_mul_overflow_size_t (module_count, sizeof (DrcovModule), &alloc_size)) {
		R_LOG_ERROR ("Module table too large in '%s'", path);
		free (buf);
		return -1;
	}
	DrcovModule *modules = R_NEWS0 (DrcovModule, module_count);
	if (!modules) {
		free (buf);
		return -1;
	}

	ut32 i;
	for (i = 0; i < module_count; i++) {
		line = drcov_next_line (buf, fsz, &off);
		if (!line) {
			R_LOG_ERROR ("Unexpected EOF in module table of '%s'", path);
			drcov_free_modules (modules, module_count);
			free (buf);
			return -1;
		}
		RList *tokens = r_str_split_list (line, ",", 5);
		if (!tokens || r_list_length (tokens) < 5) {
			r_list_free (tokens);
			R_LOG_ERROR ("Malformed module entry in '%s'", path);
			drcov_free_modules (modules, module_count);
			free (buf);
			return -1;
		}
		char *id_s = r_list_get_n (tokens, 0);
		char *base_s = r_list_get_n (tokens, 1);
		char *end_s = r_list_get_n (tokens, 2);
		char *path_s = r_list_get_n (tokens, 4);
		ut32 mod_id = (ut32)r_num_get (NULL, id_s);
		if (mod_id < module_count) {
			modules[mod_id].base = r_num_get (NULL, base_s);
			modules[mod_id].end = r_num_get (NULL, end_s);
			modules[mod_id].path = path_s? strdup (path_s): NULL;
			modules[mod_id].valid = true;
		} else {
			R_LOG_WARN ("Skipping out-of-range module id %u", mod_id);
		}
		r_list_free (tokens);
	}

	drcov_remap_modules (anal, modules, module_count);

	line = drcov_next_line (buf, fsz, &off);
	if (!line || !r_str_startswith (line, "BB Table:")) {
		R_LOG_ERROR ("Missing BB table in '%s'", path);
		drcov_free_modules (modules, module_count);
		free (buf);
		return -1;
	}
	ut32 bb_count = (ut32)r_num_get (NULL, line + strlen ("BB Table:"));

	size_t remaining = fsz > off? (fsz - off): 0;
	if (remaining < (size_t)bb_count * 8) {
		R_LOG_ERROR ("Unexpected EOF in BB table of '%s'", path);
		drcov_free_modules (modules, module_count);
		free (buf);
		return -1;
	}
	const ut8 *entry = (const ut8 *)(buf + off);
	for (i = 0; i < bb_count; i++) {
		const ut8 *cur = entry + (i * 8);
		ut32 start = r_read_le32 (cur);
		ut16 size = r_read_le16 (cur + 4);
		ut16 mod_id = r_read_le16 (cur + 6);
		if (mod_id >= module_count || !modules[mod_id].valid) {
			continue;
		}
		DrcovModule *mod = &modules[mod_id];
		ut64 addr;
		if (r_add_overflow (mod->base, (ut64)start, &addr)) {
			continue;
		}
		ut64 addr_end;
		if (size && r_add_overflow (addr, (ut64)size, &addr_end)) {
			continue;
		}
		if (mod->end && mod->end != UT64_MAX && addr > mod->end) {
			continue;
		}
		if (size && mod->end && mod->end != UT64_MAX && addr_end > mod->end) {
			continue;
		}
		if (cb && cb (user, addr, size)) {
			loaded++;
		}
	}

	drcov_free_modules (modules, module_count);
	free (buf);
	return loaded;
}

static bool drcov_apply_cb(void *user, ut64 addr, ut16 size) {
	RAnal *anal = (RAnal *)user;
	(void)size;
	r_anal_trace_bb (anal, addr);
	return true;
}

static int drcov_apply(RAnal *anal, const char *path) {
	R_RETURN_VAL_IF_FAIL (anal && path, -1);
	int loaded = drcov_parse (anal, path, drcov_apply_cb, anal);
	if (loaded == DRCOV_PARSE_NOT_DRCOV) {
		R_LOG_ERROR ("Invalid drcov header in '%s'", path);
		return -1;
	}
	return loaded;
}

static char *drcovcmd(RAnal *anal, const char *cmd) {
	if (!r_str_startswith (cmd, "drcov")) {
		return NULL;
	}
	if (cmd[5] == '?') {
		return strdup ("| a:drcov [file]  apply DRCOV coverage");
	}
	if (cmd[5] == ' ') {
		const char *path = r_str_trim_head_ro (cmd + 6);
		if (R_STR_ISEMPTY (path)) {
			return strdup ("drcov: missing file");
		}
		int loaded = drcov_apply (anal, path);
		if (loaded < 0) {
			return strdup ("drcov: failed");
		}
		return r_str_newf ("drcov: %d entries", loaded);
	}
	return NULL;
}

RAnalPlugin r_anal_plugin_drcov = {
	.meta = {
		.name = "drcov",
		.desc = "DRCOV coverage import",
		.author = "seifreed",
		.license = "LGPL3",
	},
	.cmd = drcovcmd
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_drcov,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
