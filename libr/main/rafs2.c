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

static void rafs2_load_plugins(Rafs2State *s) {
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
	"  rafs2 -t iso9660 -i cdrom.iso\n"
	"  rafs2 -t ext2 -x /etc/passwd:passwd.txt image.img\n");
}

static int rafs2_list_plugins(Rafs2State *s) {
	if (!s->fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		return 1;
	}

	if (s->opt.json) {
		PJ *pj = pj_new ();
		if (!pj) {
			return 1;
		}
		pj_a (pj);
		RListIter *iter;
		RFSPlugin *plugin;
		r_list_foreach (s->fs->plugins, iter, plugin) {
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
		r_list_foreach (s->fs->plugins, iter, plugin) {
			if (plugin->meta.name) {
				const char *desc = plugin->meta.desc? plugin->meta.desc: "";
				printf ("  %-12s %s\n", plugin->meta.name, desc);
			}
		}
	}

	return 0;
}

static int rafs2_list(Rafs2State *s, const char *path) {
	RList *list = r_fs_dir (s->fs, path);
	if (!list) {
		R_LOG_ERROR ("Cannot list directory: %s", path);
		return 1;
	}

	if (s->opt.json) {
		PJ *pj = pj_new ();
		if (!pj) {
			r_list_free (list);
			return 1;
		}
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
			printf ("%c %10u  %s\n", type, file->size, file->name);
		}
	}
	r_list_free (list);
	return 0;
}

static int rafs2_cat(Rafs2State *s, const char *path) {
	RFSFile *file = r_fs_open (s->fs, path, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file: %s", path);
		return 1;
	}

	if (file->size > 0) {
		int len = r_fs_read (s->fs, file, 0, file->size);
		if (len > 0 && file->data) {
			fwrite (file->data, 1, len, stdout);
		}
	}

	r_fs_close (s->fs, file);
	return 0;
}

static int rafs2_details(Rafs2State *s) {
	RList *roots = r_fs_root (s->fs, s->opt.mountpoint);
	if (!roots || r_list_empty (roots)) {
		R_LOG_ERROR ("No mounted filesystem found at %s", s->opt.mountpoint);
		r_list_free (roots);
		return 1;
	}

	RFSRoot *root = (RFSRoot *)r_list_get_n (roots, 0);
	if (!root || !root->p || !root->p->details) {
		R_LOG_ERROR ("This filesystem doesn't support details");
		r_list_free (roots);
		return 1;
	}

	if (s->opt.json) {
		PJ *pj = pj_new ();
		if (!pj) {
			r_list_free (roots);
			return 1;
		}
		pj_o (pj);
		pj_ks (pj, "fstype", root->p->meta.name);
		pj_kn (pj, "offset", root->delta);
		pj_ks (pj, "mountpoint", s->opt.mountpoint);
		RStrBuf *sb = r_strbuf_new ("");
		root->p->details (root, sb);
		pj_ks (pj, "details", r_strbuf_get (sb));
		r_strbuf_free (sb);
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		RStrBuf *sb = r_strbuf_new ("");
		root->p->details (root, sb);
		printf ("%s", r_strbuf_get (sb));
		r_strbuf_free (sb);
	}
	r_list_free (roots);
	return 0;
}

static int rafs2_extract(Rafs2State *s, const char *paths) {
	char *colon = strchr (paths, ':');
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

	RFSFile *file = r_fs_open (s->fs, src, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file in image: %s", src);
		free (src);
		return 1;
	}

	if (file->size > 0) {
		int len = r_fs_read (s->fs, file, 0, file->size);
		if (len > 0 && file->data) {
			FILE *fp = fopen (dst, "wb");
			if (!fp) {
				R_LOG_ERROR ("Cannot create output file: %s", dst);
				r_fs_close (s->fs, file);
				free (src);
				return 1;
			}
			fwrite (file->data, 1, len, fp);
			fclose (fp);
			printf ("Extracted %s -> %s (%d bytes)\n", src, dst, len);
		} else {
			R_LOG_ERROR ("Failed to read file: %s", src);
			r_fs_close (s->fs, file);
			free (src);
			return 1;
		}
	} else {
		printf ("Extracted %s -> %s (0 bytes)\n", src, dst);
		FILE *fp = fopen (dst, "wb");
		if (fp) {
			fclose (fp);
		}
	}

	r_fs_close (s->fs, file);
	free (src);
	return 0;
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

	Rafs2State *s = rafs2_new();
	s->opt.mountpoint = "/";

	RGetopt go;
	r_getopt_init (&go, argc, argv, "t:o:m:il:c:x:nLhjv");
	while ((c = r_getopt_next (&go)) != -1) {
		switch (c) {
		case 't':
			s->opt.fstype = go.arg;
			break;
		case 'o':
			s->opt.offset = r_num_math (NULL, go.arg);
			break;
		case 'm':
			s->opt.mountpoint = go.arg;
			break;
		case 'i':
			s->opt.interactive = true;
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
			s->opt.json = true;
			break;
		case 'L':
			ret = rafs2_list_plugins (s);
			rafs2_free (s);
			return ret;
		case 'v':
			ret = r_main_version_print ("rafs2", 0);
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

	if (!s->opt.fstype) {
		R_LOG_ERROR ("Filesystem type not specified (use -t)");
		show_usage ();
		rafs2_free (s);
		return 1;
	}

	s->opt.file = argv[go.ind];

	// s->io = r_io_new ();
	if (!s->io) {
		R_LOG_ERROR ("Cannot create IO instance");
		rafs2_free (s);
		return 1;
	}

	RIODesc *desc = r_io_open (s->io, s->opt.file, R_PERM_R, 0);
	if (!desc) {
		R_LOG_ERROR ("Cannot open file: %s", s->opt.file);
		rafs2_free (s);
		return 1;
	}

	// s->fs = r_fs_new ();
	if (!s->fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		rafs2_free (s);
		return 1;
	}

	r_fs_view (s->fs, R_FS_VIEW_NORMAL);
	r_io_bind (s->io, &(s->fs->iob));
	r_cons_bind (s->cons, &(s->fs->csb));

	RFSRoot *root = r_fs_mount (s->fs, s->opt.fstype, s->opt.mountpoint, s->opt.offset);
	if (!root) {
		R_LOG_ERROR ("Cannot mount %s filesystem at offset 0x%" PFMT64x, s->opt.fstype, s->opt.offset);
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
	} else if (s->opt.interactive) {
		ret = rafs2_shell (s);
	} else {
		R_LOG_ERROR ("No action specified (use -l, -c, -x, -n, or -i)");
		show_usage ();
		ret = 1;
	}

	rafs2_free (s);
	return ret;
}
