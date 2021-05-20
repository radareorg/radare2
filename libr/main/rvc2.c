/* radare - LGPL - Copyright 2021 - pancake */
#include <rvc.h>

static void rvc2_show_help(void) {
	printf ("Usage: rvc2 [action] [file ...]\n"
		" init            initialize repository in current directory\n"
		" add [file ..]   add files to the current repository\n"
		" checkout [name] checkout given branch name\n"
		" log             list commits in current branch\n"
		" branch          list all available branches\n"
		" branch [name]   change to another branch\n"
		"Examples:\n"
		"  rvc2 init\n"
		"  man rvc2\n");
}

R_API int r_main_rvc2(int argc, const char **argv) {
	RGetopt opt;
	int c;
	bool git = false;

	r_getopt_init (&opt, argc, argv, "gvh");
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

	if (git) {
		eprintf ("TODO: r_vc_git APIs should be called from r_vc\n");
		eprintf ("TODO: r_vc_new should accept options argument\n");
	}
	const char *action = (opt.ind < argc)? opt.arg: NULL;
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
				if (opt.ind + 1 < argc) {
					const char *name = argv[opt.ind + 1];
					r_vc_branch (vc, name);
				} else {
					RListIter *iter;
					RvcBranch *b;
					r_list_foreach (vc->branches, iter, b) {
						printf ("%s  %s\n", b->head->hash, b->name);
					}
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
				for (i = opt.ind ; i < argc; i++) {
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
