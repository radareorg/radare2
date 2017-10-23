/* radare - LGPL - Copyright 2017 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>


typedef RList *(*DirHandler)(RFSRoot *root, const char *path);
typedef RFSFile *(*CatHandler)(RFSRoot *root, const char *path);

typedef struct {
	const char *path;
	DirHandler dir;
	CatHandler cat;
} Routes;

static RFSFile *__cfg_cat(RFSRoot *root, const char *path);
static RList *__root(RFSRoot *root, const char *path);
static RList *__cfg(RFSRoot *root, const char *path);
static RList *__flags(RFSRoot *root, const char *path);

static Routes routes[] = {
	{"/cfg", &__cfg, &__cfg_cat},
	{"/flags", &__flags},
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
		int i, count = 0;
		int *lines = r_str_split_lines (res, &count);
		for (i = 0; i < count; i++) {
			char *line = strdup (res + lines[i]);
			append_file (list, line, type, 0, 0);
		}
		free (res);
		return list;
	}
	return NULL;
}

static RFSFile* fs_r2_open(RFSRoot *root, const char *path) {
	int i;
	for (i = 0; routes[i].path; i++) {
		if (routes[i].cat && !strncmp (path, routes[i].path, strlen (routes[i].path))) {
			return routes[i].cat (root, path);
		}
	}
	return NULL;
}

static bool fs_r2_read(RFSFile *file, ut64 addr, int len) {
	// eprintf ("TODO: fs.r2.read\n");
	return NULL;
}

static void fs_r2_close(RFSFile *file) {
	// eprintf ("TODO: fs.r2.close\n");
	//fclose (file->ptr);
}

static RFSFile *__cfg_cat(RFSRoot *root, const char *path) {
	char *a = strdup (path + 5);
	r_str_replace_char (a, '/', '.');
	char *res = root->cob.cmdstrf (root->cob.core, "e %s", a);
	// root->iob.io->cb_printf ("%s\n", res);
	eprintf ("%s", res);
	RFSFile *file = r_fs_file_new (root, path);
	file->ptr = NULL;
	file->p = root->p;
	file->size = strlen (res);
	free (res);
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
		int i, count = 0;
		int *lines = r_str_split_lines (res, &count);
		for (i = 0; i < count; i++) {
			char *line = res + lines[i];
			append_file (list, line, prefix? 'f': 'd', 0, 0);
		}
		free (res);
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
		append_file (list, routes[i].path + 1, 'd', 0, 0);
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
	.open = fs_r2_open,
	.read = fs_r2_read,
	.close = fs_r2_close,
	.dir = &fs_r2_dir,
	.mount = fs_r2_mount,
	.umount = fs_r2_umount,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_FS,
        .data = &r_fs_plugin_r2,
        .versr2n = R2_VERSION
};
#endif
