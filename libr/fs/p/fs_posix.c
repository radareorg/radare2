/* radare - LGPL - Copyright 2011-2021 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define MAXPATHLEN 255
#endif
static RFSFile* fs_posix_open(RFSRoot *root, const char *path, bool create) {
	FILE *fd;
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->ptr = NULL;
	file->p = root->p;
	fd = r_sandbox_fopen (path, create? "wb": "rb");
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

static int fs_posix_read(RFSFile *file, ut64 addr, int len) {
	R_FREE (file->data);
	char *abspath = r_str_newf ("%s/%s", file->path, file->name);
	if (abspath) {
		file->data = (void*)r_file_slurp_range (abspath, 0, len, NULL);
		free (abspath);
		return len;
	}
	return 0;
}

static void fs_posix_close(RFSFile *file) {
	// fclose (file->ptr);
}

static RList *fs_posix_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	RListIter *iter;
	struct stat st;
	char *file;
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	RList *files = r_sys_dir (path);
	r_list_foreach (files, iter, file) {
		RFSFile *fsf = r_fs_file_new (NULL, file);
		if (!fsf) {
			r_list_free (list);
			return NULL;
		}
		char *fp = r_str_newf ("%s/%s", path, file);
		fsf->path = fp;
		fsf->type = 'f';
		if (!stat (fp, &st)) {
			fsf->type = S_ISDIR (st.st_mode)?'d':'f';
			fsf->time = st.st_atime;
		} else {
			fsf->type = 'f';
			fsf->time = 0;
		}
		r_list_append (list, fsf);
	}
	r_list_free (files);
	return list;
}

static int fs_posix_mount(RFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_posix_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_posix = {
	.name = "posix",
	.desc = "POSIX filesystem",
	.license = "MIT",
	.open = fs_posix_open,
	.read = fs_posix_read,
	.close = fs_posix_close,
	.dir = &fs_posix_dir,
	.mount = fs_posix_mount,
	.umount = fs_posix_umount,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_FS,
        .data = &r_fs_plugin_posix,
        .version = R2_VERSION
};
#endif
