/* radare - LGPL - Copyright 2017-2019 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>


typedef RList *(*DirHandler)(RFSRoot *root, const char *path);
typedef RFSFile *(*CatHandler)(RFSRoot *root, RFSFile *file, const char *path);
typedef bool (*WriteHandler)(RFSFile *file, ut64 addr, const ut8 *data, int len);

typedef struct {
	const char *path;
	DirHandler dir;
	CatHandler cat;
	WriteHandler write;
} Routes;

static RFSFile *__flags_cat(RFSRoot *root, RFSFile *file, const char *path);
static RFSFile *__cfg_cat(RFSRoot *root, RFSFile *file, const char *path);
static RFSFile *__seek_cat(RFSRoot *root, RFSFile *file, const char *path);
static RFSFile *__bsize_cat(RFSRoot *root, RFSFile *file, const char *path);
static bool __cfg_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static bool __seek_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static bool __bsize_write(RFSFile *file, ut64 addr, const ut8 *data, int len);
static RFSFile *__version(RFSRoot *root, RFSFile *file, const char *path);
static RList *__root(RFSRoot *root, const char *path);
static RList *__cfg(RFSRoot *root, const char *path);
static RList *__flags(RFSRoot *root, const char *path);

static Routes routes[] = {
	{"/cfg", &__cfg, &__cfg_cat, &__cfg_write },
	{"/flags", &__flags, &__flags_cat, NULL},
	{"/version", NULL, &__version, NULL},
	{"/seek", NULL, &__seek_cat, &__seek_write },
	{"/bsize", NULL, &__bsize_cat, &__bsize_write },
	{"/", &__root},
	{NULL, NULL}
};

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

static RList *fscmd(RFSRoot *root, const char *cmd, int type) {
	char *res = root->cob.cmdstr (root->cob.core, cmd);
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

static RFSFile* fs_r2_open(RFSRoot *root, const char *path, bool create) {
	int i;
	for (i = 0; routes[i].path; i++) {
		const char *cwd = routes[i].path;
		if (routes[i].cat && !strncmp (path, cwd, strlen (cwd))) {
			return routes[i].cat (root, NULL, path);
		}
	}
	return NULL;
}

static bool fs_r2_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	int i;
	const char *path = file->path;
	const char *name = file->name;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].write) {
			if (!strncmp (name, routes[i].path + 1, strlen (routes[i].path) - 1)) {
				return routes[i].write (file, addr, data, len);
			}
			if (!strncmp (path, routes[i].path, strlen (routes[i].path))) {
				return routes[i].write (file, addr, data, len);
			}
		}
	}
	return false;
}

static bool fs_r2_read(RFSFile *file, ut64 addr, int len) {
	int i;
	const char *path = file->name;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].cat && !strncmp (path, routes[i].path, strlen (routes[i].path))) {
			return routes[i].cat (file->root, file, path);
		}
	}
	return false;
}

static void fs_r2_close(RFSFile *file) {
	// eprintf ("TODO: fs.r2.close\n");
	//fclose (file->ptr);
}

static RFSFile *__version(RFSRoot *root, RFSFile *file, const char *path) {
	char *res = root->cob.cmdstrf (root->cob.core, "?V");
	/// root->iob.io->cb_printf ("%s\n", res);
	if (!file) {
		file = r_fs_file_new (root, path);
	}
	file->ptr = NULL;
	free (file->data);
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file;
}

static RFSFile *__flags_cat(RFSRoot *root, RFSFile *file, const char *path) {
	r_return_val_if_fail (root && path, NULL);
	const char *last = r_str_rchr (path, NULL, '/');
	if (last) {
		last++;
	} else {
		last = path;
	}
	char *res = root->cob.cmdstrf (root->cob.core, "?v %s", last);
	if (file) {
		file->ptr = NULL;
		file->data = (ut8*)res;
		file->p = root->p;
		file->size = strlen (res);
	} else {
		file = r_fs_file_new (root, path);
		file->ptr = NULL;
		file->data = (ut8*)res;
		file->p = root->p;
		file->size = strlen (res);
	}
	return file;
}

static bool __bsize_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	void *core = file->root->cob.core;
	char *res = file->root->cob.cmdstrf (core, "b %s", data);
	free (res);
	return true;
}

static RFSFile *__bsize_cat(RFSRoot *root, RFSFile *file, const char *path) {
	char *res = root->cob.cmdstrf (root->cob.core, "b");
	if (!file) {
		file = r_fs_file_new (root, path);
	}
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file;
}

static bool __seek_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	void *core = file->root->cob.core;
	char *res = file->root->cob.cmdstrf (core, "s %s", data);
	free (res);
	return true;
}

static RFSFile *__seek_cat(RFSRoot *root, RFSFile *file, const char *path) {
	char *res = root->cob.cmdstrf (root->cob.core, "s");
	if (!file) {
		file = r_fs_file_new (root, path);
	}
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file;
}

static bool __cfg_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	const char *a = file->name;
	void *core = file->root->cob.core;
	char *prefix = strdup (file->path + strlen ("/cfg/"));
	char *res = file->root->cob.cmdstrf (core, "e %s.%s=%s", prefix, a, data);
	free (prefix);
	free (res);
	return true;
}

static RFSFile *__cfg_cat(RFSRoot *root, RFSFile *file, const char *path) {
	if (strlen (path) < 6) {
		return NULL;
	}
	char *a = strdup (path + 5);
	r_str_replace_char (a, '/', '.');
	char *res = root->cob.cmdstrf (root->cob.core, "e %s", a);
	// root->iob.io->cb_printf ("%s\n", res);
	// eprintf ("%s", res);
	if (!file) {
		file = r_fs_file_new (root, path);
	}
	file->ptr = NULL;
	file->data = (ut8*)res;
	file->p = root->p;
	file->size = strlen (res);
	return file;
}

static RList *__flags(RFSRoot *root, const char *path) {
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
	const char *prefix = NULL;
	if (!strncmp (path, "/cfg/", 5)) {
		prefix = path + 5;
	}
	char *cmd = prefix
		? r_str_newf ("es %s", prefix)
		: strdup ("es");
	char *res = root->cob.cmdstr (root->cob.core, cmd);
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

static RList *__root(RFSRoot *root, const char *path) {
	RList *list = r_list_newf (NULL);
	if (!list) {
		return NULL;
	}
	int i;
	for (i = 0; routes[i].path; i++) {
		char type = routes[i].dir? 'd': 'f';
		append_file (list, routes[i].path + 1, type, 0, 0);
	}
	return list;
}

static RList *fs_r2_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	int i;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].dir && !strncmp (path, routes[i].path, strlen (routes[i].path))) {
			return routes[i].dir (root, path);
		}
	}
	return NULL;
}

static int fs_r2_mount(RFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_r2_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_r2 = {
	.name = "r2",
	.desc = "r2-based filesystem",
	.license = "MIT",
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
