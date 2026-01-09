/* radare - LGPL - Copyright 2012-2026 - dso, pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <zip.h>

typedef enum {
	R_IO_PARENT_ZIP = 0x0001,
	R_IO_CHILD_FILE = 0x0002,
	R_IO_NEW_FILE = 0x0004,
	R_IO_EXISTING_FILE = 0x0008,
	R_IO_MODIFIED_FILE = 0x0010,
	R_IO_DELETED_FILE = 0x0020,
} R_IO_ZIP_ARCHIVE_TYPE;

typedef struct r_io_zip_uri_const_t {
	const char *name;
	ut32 len;
} RIOZipConstURI;

static RIOZipConstURI ZIP_URIS[] = {
	{ "zip://", 6 },
	{ "ipa://", 6 },
	{ "jar://", 6 },
	{ NULL, 0 }
};

static RIOZipConstURI ZIP_ALL_URIS[] = {
	{ "apk://", 6 },
	{ "zip0://", 7 },
	{ "zipall://", 9 },
	{ "apkall://", 9 },
	{ "ipaall://", 9 },
	{ "jarall://", 9 },
	{ NULL, 0 }
};

typedef struct r_io_zfo_t {
	char *name;
	char *archivename;
	int mode;
	int rw;
	int fd;
	int opened;
	ut64 entry;
	int perm;
	ut8 modified;
	RBuffer *b;
	char *password;
	ut8 encryption_value;
	RIO *io_backref;
} RIOZipFileObj;

static bool r_io_zip_has_uri_substr(const char *file) {
	return (file && strstr (file, "://"));
}

static bool r_io_zip_check_uri_many(const char *file) {
	int i;
	if (r_io_zip_has_uri_substr (file)) {
		for (i = 0; ZIP_ALL_URIS[i].name; i++) {
			if (!strncmp (file, ZIP_ALL_URIS[i].name, ZIP_ALL_URIS[i].len) && file[ZIP_ALL_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static bool r_io_zip_check_uri(const char *file) {
	int i;
	if (r_io_zip_has_uri_substr (file)) {
		for (i = 0; ZIP_URIS[i].name; i++) {
			if (!strncmp (file, ZIP_URIS[i].name, ZIP_URIS[i].len) && file[ZIP_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static bool r_io_zip_plugin_open(RIO *io, const char *file, bool many) {
	if (io && file) {
		if (many) {
			return r_io_zip_check_uri_many (file);
		}
		return r_io_zip_check_uri (file);
	}
	return false;
}

static struct zip *r_io_zip_open_archive(const char *archivename, ut32 perm, int mode, int rw) {
	R_RETURN_VAL_IF_FAIL (archivename, NULL);
	if (rw & R_PERM_W) {
		R_LOG_ERROR ("Opening zip archives in write mode is not supported");
		return NULL;
	}
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		R_LOG_ERROR ("Sandbox prevents accessing zip archives");
		return NULL;
	}
	(void)mode; // unused
	int zip_errorp;
	struct zip *za = zip_open (archivename, perm, &zip_errorp);
	if (za) {
		return za;
	}
	if (zip_errorp == ZIP_ER_INVAL) {
		R_LOG_ERROR ("Invalid file name (NULL)");
	} else if (zip_errorp == ZIP_ER_OPEN) {
		R_LOG_ERROR ("File could not be opened file name");
	} else if (zip_errorp == ZIP_ER_NOENT) {
		R_LOG_ERROR ("File does not exist");
	} else if (zip_errorp == ZIP_ER_READ) {
		R_LOG_ERROR ("Read error occurred");
	} else if (zip_errorp == ZIP_ER_NOZIP) {
		R_LOG_ERROR ("File is not a valid ZIP archive");
	} else if (zip_errorp == ZIP_ER_INCONS) {
		R_LOG_ERROR ("ZIP file had some inconsistencies archive");
	} else {
		R_LOG_ERROR ("Something bad happened, get your debug on");
	}
	return NULL;
}

static bool r_io_zip_slurp_file(RIOZipFileObj *zfo) {
	R_RETURN_VAL_IF_FAIL (zfo, -1);
	bool res = false;
	struct zip *za = r_io_zip_open_archive (zfo->archivename, zfo->perm, zfo->mode, zfo->rw);
	if (za && zfo && zfo->entry != -1) {
		struct zip_file *zFile = zip_fopen_index (za, zfo->entry, 0);
		if (!zFile) {
			zip_close (za);
			return false;
		}
		if (!zfo->b) {
			zfo->b = r_buf_new ();
		}
		struct zip_stat sb;
		zip_stat_init (&sb);
		if (zfo->b && !zip_stat_index (za, zfo->entry, 0, &sb)) {
			ut8 *buf = calloc (1, sb.size);
			if (buf) {
				zip_fread (zFile, buf, sb.size);
				r_buf_set_bytes (zfo->b, buf, sb.size);
				res = true;
				zfo->opened = true;
				free (buf);
			}
		}
		zip_fclose (zFile);
	}
	zip_close (za);
	return res;
}

static RList *r_io_zip_get_files(char *archivename, ut32 perm, int mode, int rw) {
	struct zip *za = r_io_zip_open_archive (archivename, perm, mode, rw);
	ut64 num_entries = 0, i = 0;
	RList *files = NULL;
	struct zip_stat sb;
	char *name;
	if (za) {
		files = r_list_newf (free);
		if (!files) {
			zip_close (za);
			return NULL;
		}
		num_entries = zip_get_num_files (za);
		for (i = 0; i < num_entries; i++) {
			zip_stat_init (&sb);
			zip_stat_index (za, i, 0, &sb);
			if ((name = strdup (sb.name))) {
				r_list_append (files, name);
			}
		}
	}
	zip_close (za);
	return files;
}

int r_io_zip_flush_file(RIOZipFileObj *zfo) {
	int res = false;
	if (!zfo) {
		return res;
	}
	struct zip *za = r_io_zip_open_archive (
		zfo->archivename, zfo->perm, zfo->mode, zfo->rw);
	if (!za) {
		return res;
	}

	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (zfo->b, &tmpsz);
	struct zip_source *s = zip_source_buffer (za, tmp, tmpsz, 0);
	bool source_owned = true; /* Track whether source ownership was transferred to archive */
	if (s && zfo->entry != -1) {
		if (zip_replace (za, zfo->entry, s) == 0) {
			source_owned = false; /* Ownership transferred to archive */
			res = true;
		}
	} else if (s && zfo->name) {
		if (zip_add (za, zfo->name, s) == 0) {
			source_owned = false; /* Ownership transferred to archive */
			zfo->entry = zip_name_locate (za, zfo->name, 0);
			res = true;
		}
	}
	zip_close (za);
	if (s && source_owned) {
		zip_source_free (s);
	}
	return res;
}

static void r_io_zip_free_zipfileobj(RIOZipFileObj *zfo) {
	if (!zfo) {
		return;
	}
	if (zfo->modified) {
		r_io_zip_flush_file (zfo);
	}
	free (zfo->name);
	free (zfo->password);
	r_buf_free (zfo->b);
	free (zfo);
}

static RIOZipFileObj *r_io_zip_create_new_file(const char *archivename, const char *filename, struct zip_stat *sb, ut32 perm, int mode, int rw) {
	RIOZipFileObj *zfo = R_NEW0 (RIOZipFileObj);
	zfo->b = r_buf_new ();
	zfo->archivename = strdup (archivename);
	zfo->name = strdup (sb? sb->name: filename);
	zfo->entry = !sb? -1: sb->index;
	zfo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
	zfo->perm = perm;
	zfo->mode = mode;
	zfo->rw = rw;
	return zfo;
}

/* The file can be a file in the archive or ::[num].  */
static RIOZipFileObj *alloc_zipfileobj(const char *archivename, const char *filename, ut32 perm, int mode, int rw) {
	RIOZipFileObj *zfo = NULL;
	struct zip_stat sb;
	struct zip *za = r_io_zip_open_archive (archivename, perm, mode, rw);
	if (!za) {
		return NULL;
	}
	ut64 i, num_entries = zip_get_num_files (za);

	for (i = 0; i < num_entries; i++) {
		zip_stat_init (&sb);
		zip_stat_index (za, i, 0, &sb);
		if (sb.name) {
			if (!strcmp (sb.name, filename)) {
				zfo = r_io_zip_create_new_file (
					archivename, filename, &sb, perm, mode, rw);
				r_io_zip_slurp_file (zfo);
				break;
			}
		}
	}
	if (!zfo) {
		zfo = r_io_zip_create_new_file (archivename,
			filename,
			NULL,
			perm,
			mode,
			rw);
	}
	zip_close (za);
	return zfo;
}

// Below this line are the r_io_zip plugin APIs
static RList *r_io_zip_open_many(RIO *io, const char *file, int rw, int mode) {
	char *zip_filename = NULL, *zip_uri;

	if (!r_io_zip_plugin_open (io, file, true)) {
		return NULL;
	}

	zip_uri = strdup (file);
	if (!zip_uri) {
		return NULL;
	}
	// 1) Tokenize to the '//' and find the base file directory ('/')
	zip_filename = strstr (zip_uri, "//");
	if (zip_filename && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/') {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;
	} else {
		free (zip_uri);
		return NULL;
	}

	int perm = 0;
	struct zip_stat sb;
	struct zip *za = r_io_zip_open_archive (zip_filename, perm, mode, rw);
	if (!za) {
		free (zip_uri);
		return NULL;
	}
	RList *list_fds = r_list_new ();
	if (!list_fds) {
		free (zip_uri);
		return NULL;
	}
	ut64 i, num_entries = zip_get_num_files (za);
	for (i = 0; i < num_entries; i++) {
		zip_stat_init (&sb);
		zip_stat_index (za, i, 0, &sb);
		bool append = false;
		if (r_str_startswith (file, "apkall://") || r_str_startswith (file, "apk://")) {
			if (!strcmp (sb.name, "AndroidManifest.xml")) {
				append = true;
			} else if (r_str_endswith (sb.name, ".dex")) {
				append = true;
			}
		} else {
			append = true;
		}
		if (append) {
			RIOZipFileObj *zfo = r_io_zip_create_new_file (zip_filename, sb.name, &sb, perm, mode, rw);
			r_io_zip_slurp_file (zfo);
			zfo->io_backref = io;
			char *name = r_str_newf ("zip://%s//%s", zip_filename, sb.name);
			RIODesc *res = r_io_desc_new (io, &r_io_plugin_zip, name, rw, mode, zfo);
			free (name);
			r_list_append (list_fds, res);
			if (r_str_startswith (zip_uri, "zip0://")) {
				break;
			}
		}
	}

	zip_close (za);
	free (zip_uri);
	return list_fds;
}

static char *r_io_zip_get_by_file_idx(const char *archivename, const char *idx, ut32 perm, int mode, int rw) {
	char *filename = NULL;
	ut64 i, num_entries;
	ut32 file_idx = -1;
	struct zip_stat sb;
	struct zip *za = r_io_zip_open_archive (archivename, perm, mode, rw);
	if (!idx || !za) {
		zip_close (za);
		return filename;
	}
	num_entries = zip_get_num_files (za);
	file_idx = atoi (idx);
	if ((file_idx == 0 && idx[0] != '0') || (file_idx >= num_entries)) {
		zip_close (za);
		return filename;
	}
	for (i = 0; i < num_entries; i++) {
		zip_stat_init (&sb);
		zip_stat_index (za, i, 0, &sb);
		if (file_idx == i) {
			filename = strdup (sb.name);
			break;
		}
	}
	zip_close (za);
	return filename;
}

static RIODesc *r_io_zip_open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *res = NULL;
	char *pikaboo, *tmp;
	char *zip_filename = NULL, *filename_in_zipfile = NULL;

	if (!r_io_zip_plugin_open (io, file, false)) {
		return NULL;
	}
	char *zip_uri = strdup (file);
	if (!zip_uri) {
		return NULL;
	}
	pikaboo = strstr (zip_uri, "://");
	if (pikaboo) {
		tmp = strstr (pikaboo + 3, "//");
		zip_filename = tmp? strdup (tmp): NULL;
		// 1) Tokenize to the '//' and find the base file directory ('/')
		if (!zip_filename) {
			if (r_str_startswith (zip_uri, "ipa://")) {
				RListIter *iter;
				char *name;
				zip_filename = strdup (pikaboo + 3);
				RList *files = r_io_zip_get_files (zip_filename, 0, mode, rw);
				if (files) {
					r_list_foreach (files, iter, name) {
						/* Find matching file */
						char *bin_name = strstr (name, ".app/");
						if (bin_name) {
							const char *slash = r_str_rchr (name, bin_name, '/');
							if (slash) {
								bin_name = r_str_ndup (slash + 1, (bin_name - slash) - 1);
								char *chkstr = r_str_newf ("Payload/%s.app/%s", bin_name, bin_name);
								if (!strcmp (name, chkstr)) {
									free (zip_filename);
									zip_filename = r_str_newf ("//%s", chkstr);
									free (chkstr);
									free (bin_name);
									break;
								}
								free (chkstr);
								free (bin_name);
							}
						}
					}
					r_list_free (files);
				}
			} else {
				zip_filename = strdup (pikaboo + 1);
			}
		} else {
			free (zip_filename);
			zip_filename = strdup (pikaboo + 1);
		}
	}
	tmp = zip_filename;
	if (zip_filename && zip_filename[1] && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/') {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;

		// check for // for file in the archive
		if ((filename_in_zipfile = strstr (zip_filename, "//")) && filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = strdup (filename_in_zipfile);
			// check for :: index
		} else if ((filename_in_zipfile = strstr (zip_filename, "::")) &&
			filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = r_io_zip_get_by_file_idx (
				zip_filename, filename_in_zipfile, ZIP_CREATE, mode, rw);
		} else {
			filename_in_zipfile = r_str_newf ("%s", zip_filename);
			R_FREE (tmp);
			zip_filename = strdup (pikaboo + 3);
			if (!strcmp (zip_filename, filename_in_zipfile)) {
				// R_FREE (zip_filename);
				R_FREE (filename_in_zipfile);
			}
		}
	}

	if (!zip_filename) { // && !filename_in_zipfile) {
		// free (zip_uri);
		eprintf ("usage: zip:///path/to/archive//filepath\n"
			"usage: zip:///path/to/archive::[number]\n"
			"Archive was not found.\n");
		// return res;
	}

	// Failed to find the file name the archive.
	if (!filename_in_zipfile) {
		RListIter *iter;
		char *name;
		// eprintf ("usage: zip:///path/to/archive//filepath\n");
		RList *files = r_io_zip_get_files (zip_filename, 0, mode, rw);
		if (files) {
			ut32 i = 0;
			r_list_foreach (files, iter, name) {
				io->cb_printf ("%d %s\n", i, name);
				i++;
			}
			r_list_free (files);
		}
		goto done;
	}
	// eprintf ("After parsing the given uri: %s\n", file);
	// eprintf ("Zip filename the given uri: %s\n", zip_filename);
	// eprintf ("File in the zip: %s\n", filename_in_zipfile);
	RIOZipFileObj *zfo = alloc_zipfileobj (zip_filename, filename_in_zipfile, ZIP_CREATE, mode, rw);
	if (zfo) {
		if (zfo->entry == -1) {
			R_LOG_WARN ("File did not exist, creating a new one");
		}
		zfo->io_backref = io;
		res = r_io_desc_new (io, &r_io_plugin_zip, zfo->name, rw, mode, zfo);
	}

	if (!res) {
		R_LOG_ERROR ("Failed to open the archive %s and file %s",
			zip_filename,
			filename_in_zipfile);
		// free (zfo); zfo is already freed by r_io_desc_new	//WTF
		r_io_desc_free (res);
		res = NULL;
	}
done:
	free (filename_in_zipfile);
	free (zip_uri);
	free (tmp);
	return res;
}

static ut64 r_io_zip_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOZipFileObj *zfo;
	ut64 seek_val = 0;

	if (!fd || !fd->data) {
		return -1;
	}

	zfo = fd->data;
	seek_val = r_buf_tell (zfo->b);

	switch (whence) {
	case R_IO_SEEK_SET:
		seek_val = (r_buf_size (zfo->b) < offset)? r_buf_size (zfo->b): offset;
		r_buf_seek (zfo->b, seek_val, R_BUF_SET);
		return seek_val;
	case R_IO_SEEK_CUR:
		seek_val = (r_buf_size (zfo->b) < (offset + r_buf_tell (zfo->b)))? r_buf_size (zfo->b): offset + r_buf_tell (zfo->b);
		r_buf_seek (zfo->b, seek_val, R_BUF_SET);
		return seek_val;
	case R_IO_SEEK_END:
		seek_val = r_buf_size (zfo->b);
		r_buf_seek (zfo->b, seek_val, R_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static int r_io_zip_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOZipFileObj *zfo = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	zfo = fd->data;
	if (r_buf_size (zfo->b) < io->off) {
		io->off = r_buf_size (zfo->b);
	}
#if 0
	int r = r_buf_read_at (zfo->b, io->off, buf, count);
	if (r >= 0) {
		r_buf_seek (zfo->b, r, R_BUF_CUR);
	}
#else
	const ut64 off = r_buf_tell (zfo->b);
	const int r = r_buf_read (zfo->b, buf, count);
	r_buf_seek (zfo->b, off + r, R_BUF_SET);
#endif
	return r;
}

static int r_io_zip_realloc_buf(RIOZipFileObj *zfo, int count) {
	return r_buf_resize (zfo->b, r_buf_tell (zfo->b) + count);
}

static bool r_io_zip_truncate_buf(RIOZipFileObj *zfo, int size) {
	return r_buf_resize (zfo->b, size > 0? size: 0);
}

static bool r_io_zip_resize(RIO *io, RIODesc *fd, ut64 size) {
	RIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return false;
	}
	zfo = fd->data;
	if (r_io_zip_truncate_buf (zfo, size)) {
		zfo->modified = 1;
		r_io_zip_flush_file (zfo);
		return true;
	}
	return false;
}

static int r_io_zip_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOZipFileObj *zfo;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	zfo = fd->data;
	if (! (zfo->perm & R_PERM_W)) {
		return -1;
	}
	if (r_buf_tell (zfo->b) + count >= r_buf_size (zfo->b)) {
		r_io_zip_realloc_buf (zfo, count);
	}
	const ut64 off = r_buf_tell (zfo->b);
	const int ret = r_buf_write (zfo->b, buf, count);
	zfo->modified = 1;
	r_buf_seek (zfo->b, off + ret, R_BUF_SET);
	r_io_zip_flush_file (zfo);
	return ret;
}

static bool r_io_zip_close(RIODesc *fd) {
	RIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return false;
	}
	zfo = fd->data;
	r_io_zip_free_zipfileobj (zfo);
	zfo = fd->data = NULL;
	return true;
}

RIOPlugin r_io_plugin_zip = {
	.meta = {
		.author = "pancake",
		.name = "zip",
		.desc = "Open zip files",
		.license = "BSD-3-Clause",
	},
	.uris = "zip://,apk://,ipa://,jar://,zip0://,zipall://,apkall://,ipaall://,jarall://",
	.open = r_io_zip_open,
	.open_many = r_io_zip_open_many,
	.write = r_io_zip_write,
	.read = r_io_zip_read,
	.close = r_io_zip_close,
	.seek = r_io_zip_lseek,
	.check = r_io_zip_plugin_open,
	.resize = r_io_zip_resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_zip,
	.version = R2_VERSION
};
#endif
