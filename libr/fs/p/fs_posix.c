/* radare - LGPL - Copyright 2011-2024 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define MAXPATHLEN 255
#endif

static RFSFile* fs_posix_open(RFSRoot *root, const char *path, bool create) {
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->ptr = NULL;
	file->p = root->p;
	FILE *fd = r_sandbox_fopen (path, create? "wb": "rb");
	if (fd) {
		if (fseek (fd, 0, SEEK_END) != 0) {
			fclose (fd);
			r_fs_file_free (file);
			return NULL;
		}
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
			r_list_free (files);
			return NULL;
		}
		char *fp = r_str_newf ("%s/%s", path, file);
		fsf->path = fp;
		fsf->type = 'f';
		fsf->time = 0;
		bool is_symlink = false;
#if R2__UNIX__
		int stat_result = lstat (fp, &st);
		if (stat_result == 0) {
			is_symlink = S_IFLNK == (st.st_mode & S_IFMT);
			if (is_symlink) {
				// uppercase denotes symlink
				stat (fp, &st);
			}
		}
#else
		int stat_result = stat (fp, &st);
#endif
		if (stat_result == 0) {
			fsf->perm = st.st_mode & 0xfff;
			fsf->uid = st.st_uid;
			fsf->gid = st.st_gid;
			if (S_ISDIR (st.st_mode)) {
				fsf->type = 'd';
#if R2__UNIX__
			} else if (S_ISBLK (st.st_mode)) {
				fsf->type = 'b';
			} else if (S_ISCHR (st.st_mode)) {
				fsf->type = 'c';
#endif
			} else {
				// regular file
				fsf->type = 'f';
			}
			if (is_symlink) {
				fsf->type = toupper (fsf->type);
			}
			fsf->time = st.st_atime;
		}
		r_list_append (list, fsf);
	}
	r_list_free (files);
	return list;
}

static bool fs_posix_mount(RFSRoot *root) {
	root->ptr = NULL;
	return true;
}

static void fs_posix_umount(RFSRoot *root) {
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_posix = {
	.meta = {
		.name = "posix",
		.desc = "POSIX filesystem",
		.license = "MIT",
	},
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
