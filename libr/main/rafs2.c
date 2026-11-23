/* radare - LGPL - Copyright 2025 - MiKi (mikelloc) */

#define R_LOG_ORIGIN "rafs2"

#include <r_main.h>
#include <r_fs.h>
#include <r_io.h>
#include <r_cons.h>

typedef struct {
	const char *fstype;
	const char *file;
	const char *mountpoint;
	const char *mount_options;
	ut64 offset;
	bool interactive;
	bool json;
} Rafs2Options;

typedef struct {
	RLib *l;
	RFS *fs;
	RIO *io;
	RCons *cons;
	Rafs2Options opt;
} Rafs2State;

static bool __lib_fs_cb(RLibPlugin *pl, void *user, void *data) {
	RFSPlugin *hand = (RFSPlugin *)data;
	Rafs2State *s = (Rafs2State *)user;
	r_fs_plugin_add (s->fs, hand);
	return true;
}

static void rafs2_load_internal_cb(void *user) {
	Rafs2State *s = (Rafs2State *)user;
	r_libstore_load (s->io->libstore);
	r_libstore_load (s->fs->libstore);
}

static void rafs2_load_plugins(Rafs2State *s) {
	s->l->cb_internal = rafs2_load_internal_cb;
	s->l->cb_internal_user = s;
	r_lib_add_handler (s->l, R_LIB_TYPE_FS, "filesystem plugins", &__lib_fs_cb, NULL, s);
	r_lib_load_default_paths (s->l, R_LIB_LOAD_DEFAULT);
}

static Rafs2State *rafs2_new(void) {
	Rafs2State *s = R_NEW0 (Rafs2State);
	s->l = r_lib_new (NULL, NULL);
	s->io = r_io_new ();
	s->fs = r_fs_new ();
	s->cons = r_cons_new ();

	const bool load_plugins = !r_sys_getenv_asbool ("R2_NOPLUGINS");
	if (load_plugins) {
		rafs2_load_plugins (s);
	} else {
		rafs2_load_internal_cb (s);
	}
	return s;
}

static void rafs2_free(Rafs2State *s) {
	if (s) {
		r_cons_free (s->cons);
		r_fs_free (s->fs);
		r_io_free (s->io);
		r_lib_free (s->l);
		free (s);
	}
	// r_log_fini ();
}

static void show_usage(void) {
	printf ("Usage: rafs2 [options] -t <fstype> <file>\n"
	"Options:\n"
	"  -t <type>    Filesystem type (ext2, fat, ntfs, iso9660, hfs, ubifs, etc.)\n"
	"  -o <offset>  Offset to mount filesystem (default: 0)\n"
	"  -O <opts>    Mount options (key=value,key=value)\n"
	"  -m <path>    Mount point path (default: /)\n"
	"  -i           Interactive mode (shell)\n"
	"  -l <path>    List directory contents\n"
	"  -c <file>    Cat file contents\n"
	"  -x <src:dst> Extract file from image to host\n"
	"  -n           Show filesystem details (like 'mn' command)\n"
	"  -L           List available filesystem types\n"
	"  -j           Output in JSON format\n"
	"  -h           Show this help\n"
	"  -v           Show version\n"
	"\n"
	"Examples:\n"
	"  rafs2 -L\n"
	"  rafs2 -t ext2 -l / image.img\n"
	"  rafs2 -t fat -o 0x1000 -c /boot/config.txt disk.img\n"
	"  rafs2 -t ntfs -n filesystem.img\n"
	"  rafs2 -t 9fs -O tcp:127.0.0.1:9999 -l / /dev/null\n"
	"  rafs2 -t iso9660 -i cdrom.iso\n"
	"  rafs2 -t ext2 -x /etc/passwd:passwd.txt image.img\n");
}

static int rafs2_list_plugins(Rafs2State *s) {
	RFS *fs = s->fs;
	if (!fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		return 1;
	}
	RList *plugins = fs->libstore->plugins;

	if (s->opt.json) {
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *iter;
		RFSPlugin *plugin;
		r_list_foreach (plugins, iter, plugin) {
			if (plugin->meta.name) {
				pj_o (pj);
				pj_ks (pj, "name", plugin->meta.name);
				if (plugin->meta.desc) {
					pj_ks (pj, "description", plugin->meta.desc);
				}
				pj_end (pj);
			}
		}
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		printf ("Available filesystem types:\n");
		RListIter *iter;
		RFSPlugin *plugin;
		r_list_foreach (plugins, iter, plugin) {
			if (plugin->meta.name) {
				const char *desc = plugin->meta.desc? plugin->meta.desc: "";
				printf ("  %-12s %s\n", plugin->meta.name, desc);
			}
		}
	}

	return 0;
}

static int rafs2_list(Rafs2State *s, const char *path) {
	RList *list = r_fs_dir (s->fs, path, UT64_MAX, R_FS_VIEW_NORMAL);
	if (!list) {
		R_LOG_ERROR ("Cannot list directory: %s", path);
		return 1;
	}

	if (s->opt.json) {
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *iter;
		RFSFile *file;
		r_list_foreach (list, iter, file) {
			pj_o (pj);
			pj_ks (pj, "name", file->name);
			pj_kn (pj, "size", file->size);
			char type_str[2] = {file->type, '\0'};
			pj_ks (pj, "type", type_str);
			pj_end (pj);
		}
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		RListIter *iter;
		RFSFile *file;
		r_list_foreach (list, iter, file) {
			char type = file->type;
			printf ("%c %10"PFMT64u"  %s\n", type, file->size, file->name);
		}
	}
	r_list_free (list);
	return 0;
}

static bool rafs2_copy(RFS *fs, RFSFile *file, FILE *output) {
	ut64 offset = 0;
	while (offset < file->size) {
		int chunk = R_MIN (file->size - offset, 65536);
		int nread = r_fs_read (fs, file, offset, chunk);
		if (nread < 1 || nread > chunk || !file->data || fwrite (file->data, 1, nread, output) != nread) {
			return false;
		}
		offset += nread;
	}
	return true;
}

static int rafs2_cat(Rafs2State *s, const char *path) {
	RFS *fs = s->fs;
	RFSFile *file = r_fs_open (fs, path, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file: %s", path);
		return 1;
	}

	bool ok = rafs2_copy (fs, file, stdout);
	r_fs_close (fs, file);
	r_fs_file_free (file);
	return ok? 0: 1;
}

static int rafs2_details(Rafs2State *s) {
	const char *mountpoint = s->opt.mountpoint;
	RList *roots = r_fs_root (s->fs, mountpoint);
	if (!roots || r_list_empty (roots)) {
		R_LOG_ERROR ("No mounted filesystem found at %s", mountpoint);
		r_list_free (roots);
		return 1;
	}

	RFSRoot *root = (RFSRoot *)r_list_get_n (roots, 0);
	RFSPlugin *plugin = root? root->p: NULL;
	if (!plugin || !plugin->details) {
		R_LOG_ERROR ("This filesystem doesn't support details");
		r_list_free (roots);
		return 1;
	}

	if (s->opt.json) {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "fstype", plugin->meta.name);
		pj_kn (pj, "offset", root->delta);
		pj_ks (pj, "mountpoint", mountpoint);
		RStrBuf *sb = r_strbuf_new ("");
		plugin->details (root, sb);
		pj_ks (pj, "details", r_strbuf_get (sb));
		r_strbuf_free (sb);
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		RStrBuf *sb = r_strbuf_new ("");
		plugin->details (root, sb);
		printf ("%s", r_strbuf_get (sb));
		r_strbuf_free (sb);
	}
	r_list_free (roots);
	return 0;
}

static int rafs2_extract(Rafs2State *s, const char *paths) {
	RFS *fs = s->fs;
	const char *colon = strchr (paths, ':');
	if (!colon) {
		R_LOG_ERROR ("Invalid extract syntax. Use: -x <src:dst>");
		return 1;
	}

	char *src = r_str_ndup (paths, colon - paths);
	const char *dst = colon + 1;

	if (!src || !*src || !*dst) {
		R_LOG_ERROR ("Invalid source or destination path");
		free (src);
		return 1;
	}

	RFSFile *file = r_fs_open (fs, src, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file in image: %s", src);
		free (src);
		return 1;
	}

	FILE *output = r_sandbox_fopen (dst, "wb");
	bool ok = output && rafs2_copy (fs, file, output);
	if (output && fclose (output)) {
		ok = false;
	}
	if (ok) {
		printf ("Extracted %s -> %s (%"PFMT64u" bytes)\n", src, dst, file->size);
	} else if (!output) {
		R_LOG_ERROR ("Cannot open '%s' for writing", dst);
	} else {
		R_LOG_ERROR ("Failed to extract file: %s", src);
	}
	r_fs_close (fs, file);
	r_fs_file_free (file);
	free (src);
	return ok? 0: 1;
}

static int rafs2_shell(Rafs2State *s) {
	RFSShell *shell = r_fs_shell_new ();
	if (!shell) {
		R_LOG_ERROR ("Cannot create filesystem shell");
		return 1;
	}

	shell->cwd = strdup (s->opt.mountpoint);
	shell->cons = s->cons;

	bool ret = r_fs_shell (shell, s->fs, s->opt.mountpoint);
	r_fs_shell_free (shell);

	return ret? 0: 1;
}

R_API int r_main_rafs2(int argc, const char **argv) {
	int c, ret = 0;
	const char *list_path = NULL;
	const char *cat_path = NULL;
	const char *extract_path = NULL;
	bool show_details = false;

	Rafs2State *s = rafs2_new ();
	Rafs2Options *opt = &s->opt;
	opt->mountpoint = "/";

	RGetopt go;
	r_getopt_init (&go, argc, argv, "t:o:O:m:il:c:x:nLhjv");
	while ((c = r_getopt_next (&go)) != -1) {
		switch (c) {
		case 't':
			opt->fstype = go.arg;
			break;
		case 'o':
			opt->offset = r_num_math (NULL, go.arg);
			break;
		case 'O':
			opt->mount_options = go.arg;
			break;
		case 'm':
			opt->mountpoint = go.arg;
			break;
		case 'i':
			opt->interactive = true;
			break;
		case 'l':
			list_path = go.arg;
			break;
		case 'c':
			cat_path = go.arg;
			break;
		case 'x':
			extract_path = go.arg;
			break;
		case 'n':
			show_details = true;
			break;
		case 'j':
			opt->json = true;
			break;
		case 'L':
			ret = rafs2_list_plugins (s);
			rafs2_free (s);
			return ret;
		case 'v':
			ret = r_main_version_print (NULL, "rafs2", 0);
			rafs2_free (s);
			return ret;
		case 'h':
		default:
			show_usage ();
			rafs2_free (s);
			return c == 'h'? 0: 1;
		}
	}

	if (go.ind >= argc) {
		R_LOG_ERROR ("No file specified");
		show_usage ();
		rafs2_free (s);
		return 1;
	}

	if (!opt->fstype) {
		R_LOG_ERROR ("Filesystem type not specified (use -t)");
		show_usage ();
		rafs2_free (s);
		return 1;
	}

	opt->file = argv[go.ind];
	RIO *io = s->io;
	RFS *fs = s->fs;

	if (!io) {
		R_LOG_ERROR ("Cannot create IO instance");
		rafs2_free (s);
		return 1;
	}

	if (!r_io_open (io, opt->file, R_PERM_R, 0)) {
		R_LOG_ERROR ("Cannot open file: %s", opt->file);
		rafs2_free (s);
		return 1;
	}

	if (!fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		rafs2_free (s);
		return 1;
	}

	r_io_bind (io, &(fs->iob));
	r_cons_bind (s->cons, &(fs->csb));

	RFSRoot *root = r_fs_mount_with_options (fs, opt->fstype, opt->mountpoint, opt->offset, opt->mount_options);
	if (!root) {
		R_LOG_ERROR ("Cannot mount %s filesystem at offset 0x%" PFMT64x, opt->fstype, opt->offset);
		rafs2_free (s);
		return 1;
	}

	if (show_details) {
		ret = rafs2_details (s);
	} else if (list_path) {
		ret = rafs2_list (s, list_path);
	} else if (cat_path) {
		ret = rafs2_cat (s, cat_path);
	} else if (extract_path) {
		ret = rafs2_extract (s, extract_path);
	} else if (opt->interactive) {
		ret = rafs2_shell (s);
	} else {
		R_LOG_ERROR ("No action specified (use -l, -c, -x, -n, or -i)");
		show_usage ();
		ret = 1;
	}

	rafs2_free (s);
	return ret;
}
