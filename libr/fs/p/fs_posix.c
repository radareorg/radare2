/* radare - LGPL - Copyright 2011-2017 - pancake */

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
	free (file->data);
	file->data = (void*)r_file_slurp_range (file->name, 0, len, NULL);
	return len;
}

static void fs_posix_close(RFSFile *file) {
	//fclose (file->ptr);
}

static RList *fs_posix_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	RList *list;
	char fullpath[4096];
	struct stat st;
#if __WINDOWS__
	WIN32_FIND_DATAW entry;
	HANDLE fh;
	wchar_t *wcpath;
	char *wctocbuff;
	wchar_t directory[MAX_PATH];
#else
	struct dirent *de;
	DIR *dir;
#endif
	list = r_list_new ();
	if (!list) {
		return NULL;
	}
#if __WINDOWS__
	wcpath = r_utf8_to_utf16 (path);
	if (!wcpath) {
		return NULL;
	}
	swprintf (directory, _countof (directory), L"%ls\\*.*", wcpath);
	fh = FindFirstFileW (directory, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		free (wcpath);
		return NULL;
	}
	do {
		if ((wctocbuff = r_utf16_to_utf8 (entry.cFileName))) {
			RFSFile *fsf = r_fs_file_new (NULL, wctocbuff);
			if (!fsf) {
				r_list_free (list);
				FindClose (fh);
				return NULL;
			}
			fsf->type = 'f';
			snprintf (fullpath, sizeof (fullpath)-1, "%s/%s", path, wctocbuff);
			if (!stat (fullpath, &st)) {
				fsf->type = S_ISDIR (st.st_mode)?'d':'f';
				fsf->time = st.st_atime;
			} else {
				fsf->type = 'f';
				fsf->time = 0;
			}
			r_list_append (list, fsf);
			free (wctocbuff);
		}

	} while (FindNextFileW (fh, &entry));
	FindClose (fh);
#else
	dir = opendir (path);
	if (!dir) {
		r_list_free (list);
		return NULL;
	}
	while ((de = readdir (dir))) {
		RFSFile *fsf = r_fs_file_new (NULL, de->d_name);
		if (!fsf) {
			r_list_free (list);
			closedir (dir);
			return NULL;
		}
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
#endif
	return list;
}

static int fs_posix_mount(RFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
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
