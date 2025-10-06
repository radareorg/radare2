/* radare - LGPL - Copyright 2025 - MiKi (mikelloc) */

#define R_LOG_ORIGIN "rafs2"

#include <r_main.h>
#include <r_fs.h>
#include <r_io.h>
#include <r_cons.h>

typedef struct {
	RFS *fs;
	RIO *io;
	const char *fstype;
	const char *file;
	const char *mountpoint;
	ut64 offset;
	bool interactive;
} Rafs2Options;

static void rafs2_options_init(Rafs2Options *opt) {
	memset (opt, 0, sizeof (Rafs2Options));
	opt->mountpoint = "/";
	opt->offset = 0;
	opt->interactive = false;
}

static void rafs2_options_fini(Rafs2Options *opt) {
	if (opt) {
		r_fs_free (opt->fs);
		r_io_free (opt->io);
	}
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

static int rafs2_list_plugins(void) {
	RFS *fs = r_fs_new ();
	if (!fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		return 1;
	}

	printf ("Available filesystem types:\n");
	RListIter *iter;
	RFSPlugin *plugin;
	r_list_foreach (fs->plugins, iter, plugin) {
		if (plugin->meta.name) {
			const char *desc = plugin->meta.desc ? plugin->meta.desc : "";
			printf ("  %-12s %s\n", plugin->meta.name, desc);
		}
	}

	r_fs_free (fs);
	return 0;
}

static int rafs2_list(Rafs2Options *opt, const char *path) {
	RList *list = r_fs_dir (opt->fs, path);
	if (!list) {
		R_LOG_ERROR ("Cannot list directory: %s", path);
		return 1;
	}

	RListIter *iter;
	RFSFile *file;
	r_list_foreach (list, iter, file) {
		char type = file->type;
		printf ("%c %10u  %s\n", type, file->size, file->name);
	}
	r_list_free (list);
	return 0;
}

static int rafs2_cat(Rafs2Options *opt, const char *path) {
	RFSFile *file = r_fs_open (opt->fs, path, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file: %s", path);
		return 1;
	}

	if (file->size > 0) {
		int len = r_fs_read (opt->fs, file, 0, file->size);
		if (len > 0 && file->data) {
			fwrite (file->data, 1, len, stdout);
		}
	}

	r_fs_close (opt->fs, file);
	return 0;
}

static int rafs2_details(Rafs2Options *opt) {
	RList *roots = r_fs_root (opt->fs, opt->mountpoint);
	if (!roots || r_list_empty (roots)) {
		R_LOG_ERROR ("No mounted filesystem found at %s", opt->mountpoint);
		r_list_free (roots);
		return 1;
	}

	RFSRoot *root = (RFSRoot *)r_list_get_n (roots, 0);
	if (!root || !root->p || !root->p->details) {
		R_LOG_ERROR ("This filesystem doesn't support details");
		r_list_free (roots);
		return 1;
	}

	RStrBuf *sb = r_strbuf_new ("");
	root->p->details (root, sb);
	printf ("%s", r_strbuf_get (sb));
	r_strbuf_free (sb);
	r_list_free (roots);
	return 0;
}

static int rafs2_extract(Rafs2Options *opt, const char *paths) {
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

	RFSFile *file = r_fs_open (opt->fs, src, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file in image: %s", src);
		free (src);
		return 1;
	}

	if (file->size > 0) {
		int len = r_fs_read (opt->fs, file, 0, file->size);
		if (len > 0 && file->data) {
			FILE *fp = fopen (dst, "wb");
			if (!fp) {
				R_LOG_ERROR ("Cannot create output file: %s", dst);
				r_fs_close (opt->fs, file);
				free (src);
				return 1;
			}
			fwrite (file->data, 1, len, fp);
			fclose (fp);
			printf ("Extracted %s -> %s (%d bytes)\n", src, dst, len);
		} else {
			R_LOG_ERROR ("Failed to read file: %s", src);
			r_fs_close (opt->fs, file);
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

	r_fs_close (opt->fs, file);
	free (src);
	return 0;
}

static int rafs2_shell(Rafs2Options *opt) {
	RFSShell *shell = r_fs_shell_new ();
	if (!shell) {
		R_LOG_ERROR ("Cannot create filesystem shell");
		return 1;
	}

	shell->cwd = strdup (opt->mountpoint);
	shell->cons = r_cons_singleton ();

	bool ret = r_fs_shell (shell, opt->fs, opt->mountpoint);
	r_fs_shell_free (shell);

	return ret ? 0 : 1;
}

R_API int r_main_rafs2(int argc, const char **argv) {
	Rafs2Options opt;
	int c;
	const char *list_path = NULL;
	const char *cat_path = NULL;
	const char *extract_path = NULL;
	bool show_details = false;

	rafs2_options_init (&opt);

	RGetopt go;
	r_getopt_init (&go, argc, argv, "t:o:m:il:c:x:nLhv");
	while ((c = r_getopt_next (&go)) != -1) {
		switch (c) {
		case 't':
			opt.fstype = go.arg;
			break;
		case 'o':
			opt.offset = r_num_math (NULL, go.arg);
			break;
		case 'm':
			opt.mountpoint = go.arg;
			break;
		case 'i':
			opt.interactive = true;
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
		case 'L':
			return rafs2_list_plugins ();
		case 'v':
			return r_main_version_print ("rafs2", 0);
		case 'h':
		default:
			show_usage ();
			return c == 'h' ? 0 : 1;
		}
	}

	if (go.ind >= argc) {
		R_LOG_ERROR ("No file specified");
		show_usage ();
		return 1;
	}

	if (!opt.fstype) {
		R_LOG_ERROR ("Filesystem type not specified (use -t)");
		show_usage ();
		return 1;
	}

	opt.file = argv[go.ind];

	opt.io = r_io_new ();
	if (!opt.io) {
		R_LOG_ERROR ("Cannot create IO instance");
		return 1;
	}

	RIODesc *desc = r_io_open (opt.io, opt.file, R_PERM_R, 0);
	if (!desc) {
		R_LOG_ERROR ("Cannot open file: %s", opt.file);
		rafs2_options_fini (&opt);
		return 1;
	}

	opt.fs = r_fs_new ();
	if (!opt.fs) {
		R_LOG_ERROR ("Cannot create FS instance");
		rafs2_options_fini (&opt);
		return 1;
	}

	r_fs_view (opt.fs, R_FS_VIEW_NORMAL);
	opt.fs->iob.io = opt.io;
	opt.fs->iob.read_at = (void *)r_io_read_at;
	opt.fs->iob.write_at = (void *)r_io_write_at;

	RFSRoot *root = r_fs_mount (opt.fs, opt.fstype, opt.mountpoint, opt.offset);
	if (!root) {
		R_LOG_ERROR ("Cannot mount %s filesystem at offset 0x%" PFMT64x, opt.fstype, opt.offset);
		rafs2_options_fini (&opt);
		return 1;
	}

	int ret = 0;

	if (show_details) {
		ret = rafs2_details (&opt);
	} else if (list_path) {
		ret = rafs2_list (&opt, list_path);
	} else if (cat_path) {
		ret = rafs2_cat (&opt, cat_path);
	} else if (extract_path) {
		ret = rafs2_extract (&opt, extract_path);
	} else if (opt.interactive) {
		ret = rafs2_shell (&opt);
	} else {
		R_LOG_ERROR ("No action specified (use -l, -c, -x, -n, or -i)");
		show_usage ();
		ret = 1;
	}

	rafs2_options_fini (&opt);
	return ret;
}
