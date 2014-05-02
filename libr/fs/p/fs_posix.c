/* radare - LGPL - Copyright 2011-2012 - pancake */

#include <r_fs.h>
#include <dirent.h>
#include <sys/stat.h>

static RFSFile* fs_posix_open(RFSRoot *root, const char *path) {
	FILE *fd;
	RFSFile *file = r_fs_file_new (root, path);
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

static boolt fs_posix_read(RFSFile *file, ut64 addr, int len) {
	free (file->data);
	file->data = (void*)r_file_slurp_range (file->name, 0, len, NULL);
	return R_FALSE;
}

static void fs_posix_close(RFSFile *file) {
	//fclose (file->ptr);
}

static RList *fs_posix_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	char fullpath[4096];
	RList *list;
	struct stat st;
	struct dirent *de;
	DIR *dir = opendir (path);
	if (!dir) return NULL;
	list = r_list_new ();
	while ((de = readdir (dir))) {
		RFSFile *fsf = r_fs_file_new (NULL, de->d_name);
		fsf->type = 'f';
		snprintf (fullpath, sizeof (fullpath)-1, "%s/%s", path, de->d_name);
		if (!stat (fullpath, &st)) {
			fsf->type = S_ISDIR (st.st_mode)?'d':'f';
			fsf->time = st.st_atime;
		} else {
			fsf->type = 'f';
			fsf->time = 0;
		}
		r_list_append (list, fsf);
	}
	closedir (dir);
	return list;
}

static int fs_posix_mount(RFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
	return R_TRUE;
}

static void fs_posix_umount(RFSRoot *root) {
	root->ptr = NULL;
}

struct r_fs_plugin_t r_fs_plugin_posix = {
	.name = "posix",
	.desc = "POSIX filesystem",
	.open = fs_posix_open,
	.read = fs_posix_read,
	.close = fs_posix_close,
	.dir = &fs_posix_dir,
	.mount = fs_posix_mount,
	.umount = fs_posix_umount,
};
