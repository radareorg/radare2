/* radare - LGPL - Copyright 2017 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>

static RFSFile* fs_io_open(RFSRoot *root, const char *path) {
	FILE *fd;
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->ptr = NULL;
	file->p = root->p;
	fd = r_sandbox_fopen (path, "r");
	if (fd) {
		fseek (fd, 0, SEEK_END);
		file->size = ftell (fd);
		fclose (fd);
	} else {
		r_fs_file_free (file);
		file = NULL;
	}
	return file;
}

static bool fs_io_read(RFSFile *file, ut64 addr, int len) {
	free (file->data);
	file->data = (void*)r_file_slurp_range (file->name, 0, len, NULL);
	return false;
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
	{
		// snprintf (fullpath, sizeof (fullpath)-1, "%s/%s", path, de->d_name);
		append_file (list, "file-a", 'f', 0, 0);
		append_file (list, "file-b", 'f', 0, 12);
	}
	return list;
}

static int fs_io_mount(RFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
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
