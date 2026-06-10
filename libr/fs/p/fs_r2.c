/* radare - LGPL - Copyright 2017-2023 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>


typedef RList *(*DirHandler)(RFSRoot *root, const char *path);
typedef int (*CatHandler)(RFSRoot *root, RFSFile *file, const char *path);
typedef int (*WriteHandler)(RFSFile *file, ut64 addr, const ut8 *data, int len);

typedef struct {
	char *file;
	char *vpath;
	ut64 addr;
	int line;
} R2ClLine;

typedef struct {
	const char *path;
	DirHandler dir;
	CatHandler cat;
	WriteHandler write;
} Routes;

static int __flags_cat(RFSRoot *root, RFSFile *file, const char *path);
static int __cfg_cat(RFSRoot *root, RFSFile *file, const char *path);
static int __seek_cat(RFSRoot *root, RFSFile *file, const char *path);
static int __bsize_cat(RFSRoot *root, RFSFile *file, const char *path);
static int __cfg_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static int __seek_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static int __bsize_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static int __version(RFSRoot *root, RFSFile *file, const char *path);
static RList *__root(RFSRoot *root, const char *path);
static RList *__cfg(RFSRoot *root, const char *path);
static RList *__flags(RFSRoot *root, const char *path);
static RList *__cl(RFSRoot *root, const char *path);
static int __cl_cat(RFSRoot *root, RFSFile *file, const char *path);

static Routes routes[] = {
	{ "/cfg", &__cfg, &__cfg_cat, &__cfg_write },
	{ "/cl", &__cl, &__cl_cat, NULL },
	{ "/flags", &__flags, &__flags_cat, NULL},
	{ "/version", NULL, &__version, NULL},
	{ "/seek", NULL, &__seek_cat, &__seek_write },
	{ "/bsize", NULL, &__bsize_cat, &__bsize_write },
	{ "/", &__root},
	{NULL, NULL}
};

static void cl_line_free(R2ClLine *line) {
	if (line) {
		free (line->file);
		free (line->vpath);
		free (line);
	}
}

static void append_file(RList *list, const char *name, int type, int time, ut64 size) {
	if (!list || !name || !*name) {
		return;
	}
	RFSFile *fsf = r_fs_file_new (NULL, name);
	if (!fsf) {
		return;
	}
	fsf->type = type;
	fsf->time = time;
	fsf->size = size;
	r_list_append (list, fsf);
}

static void append_unique_file(RList *list, const char *name, int type, int time, ut64 size) {
	if (!list || !name || !*name) {
		return;
	}
	RListIter *iter;
	RFSFile *fsf;
	r_list_foreach (list, iter, fsf) {
		if (!strcmp (fsf->name, name)) {
			if (type == 'd') {
				fsf->type = type;
			}
			return;
		}
	}
	append_file (list, name, type, time, size);
}

static RList *fscmd(RFSRoot *root, const char *cmd, int type) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	char *res = root->cob.cmdStr (root->cob.core, cmd);
	if (res) {
		RList *list = r_list_newf (free);
		if (!list) {
			free (res);
			return NULL;
		}
		size_t i, count = 0;
		size_t *lines = r_str_split_lines (res, &count);
		if (lines) {
			for (i = 0; i < count; i++) {
				append_file (list, res + lines[i], type, 0, 0);
			}
			free (lines);
		}
		free (res);
		return list;
	}
	return NULL;
}

static char *cl_normalize_vpath(const char *path) {
	if (R_STR_ISEMPTY (path)) {
		return NULL;
	}
	char *dup = strdup (path);
	if (!dup) {
		return NULL;
	}
	r_str_replace_char (dup, '\\', '/');
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		free (dup);
		return NULL;
	}
	char *p = dup;
	while (*p) {
		while (*p == '/') {
			p++;
		}
		char *seg = p;
		while (*p && *p != '/') {
			p++;
		}
		char ch = *p;
		*p = 0;
		if (*seg && strcmp (seg, ".") && strcmp (seg, "..")) {
			if (r_strbuf_length (sb) > 0) {
				r_strbuf_append (sb, "/");
			}
			r_strbuf_append (sb, seg);
		}
		if (!ch) {
			break;
		}
		p++;
	}
	free (dup);
	char *res = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (res)) {
		free (res);
		return NULL;
	}
	return res;
}

static RList *cl_load(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	char *res = root->cob.cmdStr (root->cob.core, "CLj");
	if (!res) {
		return NULL;
	}
	RJson *json = r_json_parse (res);
	if (!json || json->type != R_JSON_ARRAY) {
		r_json_free (json);
		free (res);
		return NULL;
	}
	RList *lines = r_list_newf ((RListFree)cl_line_free);
	if (!lines) {
		r_json_free (json);
		free (res);
		return NULL;
	}
	RJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != R_JSON_OBJECT) {
			continue;
		}
		const char *file = r_json_get_str (child, "file");
		char *vpath = cl_normalize_vpath (file);
		if (!vpath) {
			continue;
		}
		R2ClLine *line = R_NEW0 (R2ClLine);
		line->file = strdup (file);
		line->vpath = vpath;
		line->addr = (ut64)r_json_get_num (child, "addr");
		line->line = (int)r_json_get_num (child, "line");
		r_list_append (lines, line);
	}
	r_json_free (json);
	free (res);
	return lines;
}

static char *cl_path_vpath(const char *path) {
	if (!strcmp (path, "/cl")) {
		return strdup ("");
	}
	if (!strncmp (path, "/cl/", 4)) {
		return cl_normalize_vpath (path + 4);
	}
	return NULL;
}

static RFSFile* fs_r2_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	int i;
	for (i = 0; routes[i].path; i++) {
		const char *cwd = routes[i].path;
		if (routes[i].cat && !strncmp (path, cwd, strlen (cwd))) {
			RFSFile* file = r_fs_file_new (root, path);
			routes[i].cat (root, file, path);
			return file;
		}
	}
	return NULL;
}

static int fs_r2_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);
	int i;
	const char *path = file->path;
	const char *name = file->name;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].write) {
			const size_t rpl = strlen (routes[i].path);
			if (!strncmp (name, routes[i].path + 1, rpl - 1)) {
				return routes[i].write (file, addr, data, len);
			}
			if (!strncmp (path, routes[i].path, rpl)) {
				return routes[i].write (file, addr, data, len);
			}
		}
	}
	return -1;
}

static int fs_r2_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);
	size_t i;
	const char *path = file->name;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].cat && !strncmp (path, routes[i].path, strlen (routes[i].path))) {
			return routes[i].cat (file->root, file, path);
		}
	}
	return -1;
}

static void fs_r2_close(RFSFile *file) {
	//fclose (file->ptr);
}

static int __version(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file && path, -1);
	char *res = root->cob.cmdStrF (root->cob.core, "?V");
	file->ptr = NULL;
	free (file->data);
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static int __flags_cat(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file && path, -1);
	const char *last = r_str_rchr (path, NULL, '/');
	if (last) {
		last++;
	} else {
		last = path;
	}
	char *res = root->cob.cmdStrF (root->cob.core, "?v %s", last);
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static int __bsize_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);
	void *core = file->root->cob.core;
	char *res = file->root->cob.cmdStrF (core, "b %s", data);
	free (res);
	return len;
}

static int __bsize_cat(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file, -1);
	char *res = root->cob.cmdStrF (root->cob.core, "b");
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static int __seek_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);
	void *core = file->root->cob.core;
	char *res = file->root->cob.cmdStrF (core, "s %s", data);
	free (res);
	return len;
}

static int __seek_cat(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file, -1);
	char *res = root->cob.cmdStrF (root->cob.core, "s");
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static int __cfg_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file, -1);
	const char *a = file->name;
	void *core = file->root->cob.core;
	char *prefix = strdup (file->path + strlen ("/cfg/"));
	char *res = file->root->cob.cmdStrF (core, "e %s.%s=%s", prefix, a, data);
	free (prefix);
	free (res);
	return len;
}

static int __cfg_cat(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file, -1);
	if (strlen (path) < 6) {
		return -1;
	}
	char *a = strdup (path + 5);
	r_str_replace_char (a, '/', '.');
	char *res = root->cob.cmdStrF (root->cob.core, "e %s", a);
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static RList *__flags(RFSRoot *root, const char *path) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	const char *prefix = NULL;
	if (!strncmp (path, "/flags/", 7)) {
		prefix = path + 7;
	}
	char *cmd = prefix
		? r_str_newf ("fq@F:%s", prefix)
		: strdup ("fsq");
	RList *res = fscmd (root, cmd, prefix? 'f': 'd');
	free (cmd);
	return res;
}

static RList *__cfg(RFSRoot *root, const char *path) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	const char *prefix = NULL;
	if (!strncmp (path, "/cfg/", 5)) {
		prefix = path + 5;
	}
	char *cmd = prefix
		? r_str_newf ("es %s", prefix)
		: strdup ("es");
	char *res = root->cob.cmdStr (root->cob.core, cmd);
	free (cmd);
	if (res) {
		RList *list = r_list_new ();
		if (!list) {
			free (res);
			return NULL;
		}
		size_t i, count = 0;
		size_t *lines = r_str_split_lines (res, &count);
		if (lines) {
			for (i = 0; i < count; i++) {
				char *line = res + lines[i];
				append_file (list, line, prefix? 'f': 'd', 0, 0);
			}
			free (res);
			free (lines);
		}
		return list;
	}
	return NULL;
}

static RList *__cl(RFSRoot *root, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);
	char *cwd = cl_path_vpath (path);
	if (!cwd) {
		return NULL;
	}
	RList *lines = cl_load (root);
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (lines && list) {
		const size_t cwd_len = strlen (cwd);
		RListIter *iter;
		R2ClLine *line;
		r_list_foreach (lines, iter, line) {
			const char *rel = NULL;
			if (!cwd_len) {
				rel = line->vpath;
			} else if (r_str_startswith (line->vpath, cwd) && line->vpath[cwd_len] == '/') {
				rel = line->vpath + cwd_len + 1;
			}
			if (R_STR_ISEMPTY (rel)) {
				continue;
			}
			const char *slash = strchr (rel, '/');
			char *name = slash? r_str_ndup (rel, slash - rel): strdup (rel);
			append_unique_file (list, name, slash? 'd': 'f', 0, 0);
			free (name);
		}
	}
	r_list_free (lines);
	free (cwd);
	return list;
}

static int __cl_cat(RFSRoot *root, RFSFile *file, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && file && path, -1);
	char *vpath = cl_path_vpath (path);
	if (R_STR_ISEMPTY (vpath)) {
		free (vpath);
		return -1;
	}
	RList *lines = cl_load (root);
	RStrBuf *sb = r_strbuf_new ("");
	if (!lines || !sb) {
		r_list_free (lines);
		free (vpath);
		r_strbuf_free (sb);
		return -1;
	}
	RListIter *iter;
	R2ClLine *line;
	r_list_foreach (lines, iter, line) {
		if (strcmp (line->vpath, vpath)) {
			continue;
		}
		char *row = line->line > 0? r_file_slurp_line (line->file, line->line, 0): NULL;
		r_strbuf_appendf (sb, "0x%08" PFMT64x "\t%d\t%s\n",
			line->addr, line->line, r_str_get (row));
		free (row);
	}
	r_list_free (lines);
	free (vpath);
	char *res = r_strbuf_drain (sb);
	if (R_STR_ISEMPTY (res)) {
		free (res);
		return -1;
	}
	file->ptr = NULL;
	free (file->data);
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file->size;
}

static RList *__root(RFSRoot *root, const char *path) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	RList *list = r_list_newf (NULL);
	if (!list) {
		return NULL;
	}
	size_t i;
	for (i = 0; routes[i].path; i++) {
		char type = routes[i].dir? 'd': 'f';
		append_file (list, routes[i].path + 1, type, 0, 0);
	}
	return list;
}

static RList *fs_r2_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	size_t i;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].dir && !strncmp (path, routes[i].path, strlen (routes[i].path))) {
			return routes[i].dir (root, path);
		}
	}
	return NULL;
}

static bool fs_r2_mount(RFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_r2_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_r2 = {
	.meta = {
		.name = "r2",
		.desc = "r2-based filesystem",
		.license = "MIT",
	},
	.open = fs_r2_open, // open == read
	.read = fs_r2_read, // read == open
	.write = fs_r2_write,
	.close = fs_r2_close,
	.dir = &fs_r2_dir,
	.mount = fs_r2_mount,
	.umount = fs_r2_umount,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_r2,
	.versr2n = R2_VERSION
};
#endif
