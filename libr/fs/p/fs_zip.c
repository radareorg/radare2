/* radare - LGPL - Copyright 2022-2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>
#include <sys/stat.h>
#include <r_userconf.h>
#if WANT_ZIP
#include <zip.h>

static RFSFile *fs_zip_open(RFSRoot *root, const char *path, bool create) {
	R_LOG_INFO ("zip.open (%s)", path);
	// struct zip * zipArch = zip_open (archivename, perm, &zip_errorp);
#if 0
	char *enc_uri = enbase (path);
	char *cmd = r_str_newf ("m %s", enc_uri);
	free (enc_uri);
	char *res = root->zipb.system (root->zipb.zip, cmd);
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
	}

	struct zip_file *zFile = zip_fopen_index (za, zfo->entry, 0);
	if (!zFile) {
		zip_close (za);
		return false;
	}
#endif
	if (true) {
		RFSFile *file = r_fs_file_new (root, path);
		if (!file) {
			return NULL;
		}
		file->ptr = NULL;
		file->p = root->p;
		file->size = 0;
		return file;
	}
	return NULL;
}

static int fs_zip_read(RFSFile *file, ut64 addr, int len) {
	char *abs_path = r_fs_file_copy_abs_path (file);
	if (!abs_path) {
		return -1;
	}
#if 0
	zip_fread (zf, buf, sb.size);
	//r_buf_set_bytes (zfo->b, buf, sb.size);

	RFSRoot *root = file->root;
	char *enc_uri = enbase (abs_path);
	free (abs_path);
	char *cmd = r_str_newf ("mg %s 0x%08"PFMT64x" %d", enc_uri, addr, len);
	free (enc_uri);
	if (!cmd) {
		return -1;
	}
	char *res = root->zipb.system (root->zipb.zip, cmd);
	R_FREE (cmd);
	if (res) {
		int encoded_size = strlen (res);
		if (encoded_size != len * 2) {
			R_LOG_ERROR ("Unexpected size (%d vs %d)", encoded_size, len * 2);
			R_FREE (res);
			return -1;
		}
		file->data = (ut8 *) calloc (1, len);
		if (!file->data) {
			R_FREE (res);
			return -1;
		}
		int ret = r_hex_str2bin (res, file->data);
		if (ret != len) {
			R_LOG_ERROR ("Inconsistent read");
			R_FREE (file->data);
		}
		R_FREE (res);
		return ret;
	}
#endif
	free (abs_path);
	return -1;
}

static void fs_zip_close(RFSFile *file) {
	// fclose (file->ptr);
}

static void fs_zip_close_archive(zip_t *za, zip_source_t *zs) {
	zip_close (za);
#ifdef OTEZIP_H_
	/* otezip's zip_open_from_source() copies the data and never takes
	 * ownership of the source, so it must be freed by the caller. With
	 * libzip the archive owns the source after a successful open and
	 * zip_close() frees it, so freeing it here would be a double free */
	zip_source_free (zs);
#else
	(void)zs;
#endif
}

static RList *fs_zip_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	// zip_open_from_source spills the buffer into a temporary file
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("Sandbox prevents listing zip mounts");
		return NULL;
	}
	ut64 addr = 0;
	RIOMap *map = root->iob.map_get_at (root->iob.io, addr);
	if (!map) {
		R_LOG_ERROR ("no map");
		return NULL;
	}
	int size = r_itv_size (map->itv);
	// r_unref (map);
	int buflen = size;
	ut8 *buf = calloc (buflen, 1);
	if (!buf) {
		R_LOG_ERROR ("cannot allocate %d bytes", buflen);
		return NULL;
	}
	int res = root->iob.read_at (root->iob.io, 0, buf, buflen);
	if (res != buflen) {
		R_LOG_ERROR ("io read problems");
		free (buf);
		return NULL;
	}
	// open dir and enumerate files
	zip_error_t error;
	zip_source_t *zs = zip_source_buffer_create (buf, buflen, 0, &error);
	if (!zs) {
		free (buf);
		return NULL;
	}
	int _flags = 0;
	zip_t *za = zip_open_from_source (zs, _flags, &error);
	if (!za) {
		R_LOG_ERROR ("failed to open zip from source");
		zip_source_free (zs);
		free (buf);
		return NULL;
	}
	int num_entries = zip_get_num_files (za);
	int i;
	if (*path == '/') {
		path++;
	}
	size_t path_len = strlen (path);
	bool hasdir = !path_len;
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	HtPP *names = ht_pp_new0 ();
	bool failed = !list || !names;
	for (i = 0; !failed && i < num_entries; i++) {
		struct zip_stat sb;
		zip_stat_init (&sb);
		if (zip_stat_index (za, i, 0, &sb) < 0 || !sb.name) {
			failed = true;
			break;
		}
		const char *name = sb.name;
		if (path_len) {
			if (strncmp (name, path, path_len) || name[path_len] != '/') {
				continue;
			}
			name += path_len + 1;
		}
		hasdir = true;
		if (!*name) {
			continue;
		}
		const char *slash = strchr (name, '/');
		char *child = slash? r_str_ndup (name, slash - name): strdup (name);
		if (!child) {
			failed = true;
			break;
		}
		if (!*child || ht_pp_find (names, child, NULL)) {
			free (child);
			continue;
		}
		RFSFile *file = r_fs_file_new (NULL, child);
		free (child);
		if (!file || !file->path || !file->name) {
			r_fs_file_free (file);
			failed = true;
			break;
		}
		file->type = slash? 'd': 'f';
		file->size = slash? 0: sb.size;
		if (!ht_pp_insert (names, file->name, file) || !r_list_append (list, file)) {
			r_fs_file_free (file);
			failed = true;
		}
	}
	ht_pp_free (names);
	fs_zip_close_archive (za, zs);
	free (buf);
	if (!hasdir || failed) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

RFSPlugin r_fs_plugin_zip = {
	.meta = {
		.name = "zip",
		.author = "pancake",
		.desc = "access compressed zip contents",
		.license = "MIT",
	},
	.open = fs_zip_open,
	.read = fs_zip_read,
	.close = fs_zip_close,
	.dir = &fs_zip_dir,
};
#else
RFSPlugin r_fs_plugin_zip = {
	.meta = {
		.name = "zip",
		.author = "pancake",
		.desc = "access compressed zip contents (not available)",
		.license = "MIT",
	},
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_zip,
	.version = R2_VERSION
};
#endif
