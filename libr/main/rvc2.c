/* radare - LGPL - Copyright 2021 - pancake */
#include <rvc.h>

static void rvc2_show_help(void) {
	printf ("Usage: rvc2 [options] [file]\n"
		" -a [-a]          add extra 'a' to analysis command\n"
		" -f               interpret the file as a FLIRT .sig file and dump signatures\n"
		" -h               help menu\n"
		" -j               show signatures in json\n"
		" -o sigs.sdb      add signatures to file, create if it does not exist\n"
		" -q               quiet mode\n"
		" -r               show output in radare commands\n"
		" -s signspace     save all signatures under this signspace\n"
		" -v               show version information\n"
		"Examples:\n"
		"  rasign2 -o libc.sdb libc.so.6\n");
}

R_API int r_main_rvc2(int argc, const char **argv) {
	RGetopt opt;
	int c;
	bool git = false;

	r_getopt_init (&opt, argc, argv, "afhjo:qrs:v");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'g':
			git = true;
			break;
		case 'v':
			return r_main_version_print ("rvc2");
		case 'h':
			rvc2_show_help ();
			return 0;
		default:
			rvc2_show_help ();
			return -1;
		}
	}

	char *action = (optind < argc)? optarg: NULL;
	if (action) {
		if (!strcmp (action, "init")) {
			char *path = r_sys_getdir ();
			Rvc *vc = r_vc_new (path);
			if (vc) {
				r_vc_free (vc);
				return 0;
			}
			return 1;
		} else if (!strcmp (action, "branch")) {
			char *path = r_sys_getdir ();
			Rvc *vc = r_vc_new (path);
			if (vc) {
				if (optind + 1 < argc) {
					const char *name = argv[optind + 1];
					r_vc_branch (vc, name);
				}
				r_vc_free (vc);
				return 0;
			}
			return 1;
		} else if (!strcmp (action, "add")) {
			char *path = r_sys_getdir ();
			Rvc *vc = r_vc_new (path);
			if (vc) {
				int i;
				RList *files = r_list_newf (free);
				for (i = optind; i < argc; i++) {
					r_list_append (files, strdup (argv[i]));
				}
				RList *blobs = r_vc_add (vc, files); // print the blobs?
				RListIter *iter;
				RvcBlob *b;
				r_list_foreach (blobs, iter, b) {
					printf ("%s  %s\n", b->hash, b->fname);
				}
				r_list_free (files);
				r_vc_free (vc);
				return 0;
			}
			return 1;
		}
	}
	return 0;
}
