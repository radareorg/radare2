/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_fs.h>
#include <dirent.h>

static RFSFile* fs_posix_open(RFSRoot *root, const char *path) {
#if 0
	RFSFile *file = r_fs_file_new (root, path);
	GrubFS *gfs = grubfs_new (&FSIPTR, &root->iob);
	file->ptr = gfs;
	file->p = root->p;
	if (gfs->file->fs->open (gfs->file, path)) {
		r_fs_file_free (file);
		grubfs_free (gfs);
		file = NULL;
	} else file->size = gfs->file->size;
	return file;
#endif
	eprintf ("TODO\n");
	return NULL;
}

static boolt fs_posix_read(RFSFile *file, ut64 addr, int len) {
	eprintf ("TODO\n");
	return R_FALSE;
}

static void fs_posix_close(RFSFile *file) {
	//fclose (file->ptr);
}

static RList *fs_posix_dir(RFSRoot *root, const char *path) {
	RList *list;
	struct direct *de;
	DIR *dir = opendir (path);
	if (dir) return NULL;
	list = r_list_new ();
	while ((de = readdir (dir))) {
#if 0
		RFSFile *fsf = r_fs_file_new (NULL, de->d_name);
		fsf->type = 'f'; //info->dir? 'd':'f';
		fsf->time = 0; // TODO: get info from stat(1)
		r_list_append (list, fsf);
#endif
	}
	return list;
}

static void fs_posix_mount(RFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
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
	.dir = fs_posix_dir,
	.mount = fs_posix_mount,
	.umount = fs_posix_umount,
};
