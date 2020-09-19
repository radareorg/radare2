/* radare - LGPL - Copyright 2017-2019 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>

static RFSFile *fs_io_open(RFSRoot *root, const char *path, bool create) {
	char *cmd = r_str_newf ("m %s", path);
	char *res = root->iob.system (root->iob.io, cmd);
	R_FREE (cmd);
	if (res) {
		ut32 size = 0;
		if (sscanf (res, "%u", &size) != 1) {
			size = 0;
		}
		R_FREE (res);
		if (size == 0) {
			return NULL;
		}
		RFSFile *file = r_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->ptr = NULL;
		file->p = root->p;
		file->size = size;
		return file;
	}
	return NULL;
}

static bool fs_io_read(RFSFile *file, ut64 addr, int len) {
	RFSRoot *root = file->root;
	char *abs_path = r_fs_file_copy_abs_path (file);
	if (!abs_path) {
		return false;
	}
	char *cmd = r_str_newf ("mg %s", abs_path);
	R_FREE (abs_path);
	if (!cmd) {
		return false;
	}
	char *res = root->iob.system (root->iob.io, cmd);
	R_FREE (cmd);
	if (res) {
		int encoded_size = strlen (res);
		if (encoded_size != len * 2) {
			eprintf ("Unexpected size (%d vs %d)\n", encoded_size, len*2);
			R_FREE (res);
			return false;
		}
		file->data = (ut8 *) calloc (1, len);
		if (!file->data) {
			R_FREE (res);
			return false;
		}
		int ret = r_hex_str2bin (res, file->data);
		if (ret != len) {
			eprintf ("Inconsistent read\n");
			R_FREE (file->data);
		}
		R_FREE (res);
	}
	return false;
}

static void fs_io_close(RFSFile *file) {
	// fclose (file->ptr);
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
		size_t i, count = 0;
		size_t *lines = r_str_split_lines (res, &count);
		if (lines) {
			for (i = 0; i < count; i++) {
				const char *line = res + lines[i];
				if (!*line) {
					continue;
				}
				char type = 'f';
				if (line[1] == ' ' && line[0] != ' ') {
					type = line[0];
					line += 2;
				}
				append_file (list, line, type, 0, 0);
			}
			R_FREE (res);
			R_FREE (lines);
		}
	}
	R_FREE (cmd);
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
	.license = "MIT",
	.open = fs_io_open,
	.read = fs_io_read,
	.close = fs_io_close,
	.dir = &fs_io_dir,
	.mount = fs_io_mount,
	.umount = fs_io_umount,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_io,
	.version = R2_VERSION
};
#endif
