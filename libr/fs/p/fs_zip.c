/* radare - LGPL - Copyright 2022-2025 - pancake */

#include <r_lib.h>
#include <r_fs.h>
#include <sys/stat.h>

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

static RList *fs_zip_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
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
	if (res < 1) {
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
	int num_entries = zip_get_num_entries (za, 0);
	int i;
	bool hasdir = false;
	bool hasfailed = false;
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	for (i = 0; i < num_entries; i++) {
		struct zip_stat sb;
		zip_stat_init (&sb);
		zip_stat_index (za, i, 0, &sb);
		const char *name = sb.name;
		if (*path == '/') {
			path++;
		}
		bool is_dir = r_str_endswith (sb.name, "/");
		char *k = is_dir? strdup (path): r_str_newf ("%s/", path);
		if (r_str_startswith (name, k)) {
			hasdir = true;
			const char *n = name + strlen (path);
			if (*n != '/' && strlen (path) > 0) {
				hasfailed = true;
				free (k);
				continue;
			}
			if (*n && n[1] != '/') {
				if (*path) {
					n++;
				}
			}
			if (!*n) {
				free (k);
				continue;
			}
			char *p = strchr (n, '/');
			if (!p || (*p && !p[1])) {
				char type = (sb.size == 0 && is_dir)? 'd': 'f';
				char *nn = (type == 'd')? r_str_ndup (n, strlen (n) - 1): strdup (n);
				append_file (list, nn, type, 0, sb.size);
				free (nn);
			}
		}
		free (k);
	}

	zip_close (za); // causes double free somehow
	free (buf);
	if (!hasdir || hasfailed) {
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_zip,
	.verszipn = R2_VERSION
};
#endif
