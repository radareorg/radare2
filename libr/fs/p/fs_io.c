/* radare - LGPL - Copyright 2017 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>

static RFSFile* fs_io_open(RFSRoot *root, const char *path) {
	char *res = root->iob.system (root->iob.io, "m");
	if (res) {
		eprintf ("Res %s\n", res);
		free (res);
		RFSFile *file = r_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->ptr = NULL;
		file->p = root->p;
		//file->size = 123;
		// fseek (fd, 0, SEEK_END);
		// file->size = ftell (fd);
		// fclose (fd);
		return file;
	}
	return NULL;
}

static bool fs_io_read(RFSFile *file, ut64 addr, int len) {
	RFSRoot *root = file->root;
	// char *cmd = r_str_newf ("mg %s %"PFMT64x" %d", file->path, addr, len);
	char *cmd = r_str_newf ("mg %s", file->path);
	char *res = root->iob.system (root->iob.io, cmd);
	if (res) {
		eprintf ("Res %s\n", res);
		file->data = (ut8*)calloc (1, len);
		memcpy (file->data, res, R_MIN (len, strlen (res)));
#if 0
		int ret = r_hex_str2bin ((char *)file->data, NULL);
		if (ret != len) {
			eprintf ("Inconsistent read\n");
		}
#endif
		free (res);
	}
	free (cmd);
	return NULL;
}

static void fs_io_close(RFSFile *file) {
	//fclose (file->ptr);
}

static void append_file(RList *list, const char *name, int type, int time, ut64 size) {
	RFSFile *fsf = r_fs_file_new (NULL, name);
	if (!fsf) {
		return;
	}
	fsf->type = type;
	fsf->time = time;
	fsf->size = size;
	r_list_append (list, fsf);
}

static RList *fs_io_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	char *cmd = r_str_newf ("md %s", path);
	char *res = root->iob.system (root->iob.io, cmd);
	if (res) {
		int i, count = 0;
		int *lines = r_str_split_lines (res, &count);
		for (i = 0; i < count; i++) {
			append_file (list, res + lines[i], 'f', 0, 0);
		}
		free (res);
	}
	free (cmd);
	return list;
}

static int fs_io_mount(RFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_io_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_io = {
	.name = "io",
	.desc = "r_io based filesystem",
	.open = fs_io_open,
	.read = fs_io_read,
	.close = fs_io_close,
	.dir = &fs_io_dir,
	.mount = fs_io_mount,
	.umount = fs_io_umount,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_FS,
        .data = &r_fs_plugin_io,
        .version = R2_VERSION
};
#endif
