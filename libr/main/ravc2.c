/* radare - LGPL - Copyright 2022 - pancake, rhl120 */

#include <rvc.h>

static void usage(void) {
	printf ("Usage: ravc2 [-ghqv] [action] [args ...]\n");
}

static void help(void) {
	usage ();
	printf (
		"Flags:\n"
		" -g                 Use git instead of rvc\n"
		" -h                 Show this help\n"
		" -q                 Be quiet\n"
		" -v                 Show version\n"
		" RAVC2_USER=[n]     Override cfg.user value to author commit.\n"
		" init               Initialize repository in current directory\n"
		" add [file ..]      Add files to the current repository\n"
		" checkout [name]    Checkout given branch name\n"
		" log                List commits in current branch\n"
		" branch             List all available branches\n"
		" commit [a] [m] [f] Perform a commit with the added files\n"
		" branch [name]      Change to another branch\n"
		"Environment:\n"
		" RAVC2_USER=[n]     Override cfg.user value to author commit.\n"
		"Examples:\n"
		"  ravc2 init\n"
		"  man ravc2\n"
	);
}

R_API int r_main_ravc2(int argc, const char **argv) {
	RGetopt opt;
	int c;
	bool git = false;
	bool quiet = false;
	bool version = false;

	if (argc < 2) {
		usage ();
		return 1;
	}
	r_getopt_init (&opt, argc, argv, "gqvh");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'g':
			git = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'v':
			version = true;
			break;
		case 'h':
			help ();
			return 0;
		default:
			usage ();
			return 1;
		}
	}

	if (version) {
		if (quiet) {
			printf ("%s\n", R2_VERSION);
			return 0;
		}
		return r_main_version_print ("ravc2");
	}

	if (git) {
		eprintf ("TODO: r_vc_git APIs should be called from r_vc\n");
		eprintf ("TODO: r_vc_new should accept options argument\n");
	}
	const char *action = opt.argv[opt.ind];
	if (!action) {
		return 1;
	}
	char *rp = r_sys_getdir ();
	if (!strcmp (action, "init")) {
		if (!r_vc_new (rp)) {
			return 1;
		}
		return 0;
	}
	if (!strcmp (action, "branch")) {
		if (opt.argc <= 2) {
			RList *branches = r_vc_get_branches (rp);
			if (!branches) {
				free (rp);
				return 1;
			}
			RListIter *iter;
			const char *b;
			r_list_foreach (branches, iter, b) {
				//Possible segfault here but I don't think it
				//is imporrtant enough to write an if len(a) == len(b)
				//statment.
				printf ("%s\n", b + (r_str_len_utf8 (BPREFIX)));
			}
			r_list_free (branches);
			return 0;
		}
		if (!r_vc_branch (rp, opt.argv[opt.ind + 1])) {
			free (rp);
			return 1;
		}
		return 0;
	}
	if (!strcmp (action, "commit")) {
		int i;
		if (opt.argc < 4) {
			eprintf ("Usage: ravc2 commit [message] [files...]\n");
			free (rp);
			return 1;
		}
		char *message = r_str_new (opt.argv[opt.ind + 1]);
		if (!message) {
			free (rp);
			return 1;
		}
		RList *files = r_list_new ();
		if (!files) {
			free (rp);
			free (message);
			return 1;
		}
		for (i = 2; i < argc - 1; i++) {
			char *cf = r_str_new (argv[opt.ind + i]);
			if (!cf) {
				free (message);
				r_list_free (files);
				free (rp);
				return 1;
			}
			if (!r_list_append (files, cf)) {
				free (message);
				r_list_free (files);
				free (rp);
				return 1;
			}
		}
		char *author = r_sys_getenv ("RAVC2_USER");
		if (R_STR_ISEMPTY (author)) {
			free (author);
			author = r_sys_whoami ();
		}
		if (!author) {
			free (message);
			r_list_free (files);
			free (rp);
			return 1;
		}
		bool ret = r_vc_commit (rp, message, author, files);
		free (message);
		free (author);
		r_list_free (files);
		free (rp);
		if (!ret) {
			return 1;
		}
		return 0;
	}
	if (!strcmp (action, "checkout")) {
		if (opt.argc < 2) {
			free (rp);
			return 1;
		}
		if (!r_vc_checkout (rp, opt.argv[opt.ind + 1])) {
			free (rp);
			return 1;
		}
		free (rp);
		return 0;
	}
	if (!strcmp (action, "log")) {
		RList *commits = r_vc_log (rp);
		if (!commits) {
			return 1;
		}
		RListIter *iter;
		const char *d;
		r_list_foreach (commits, iter, d) {
			printf ("%s\n****\n", d);
		}
		r_list_free (commits);
		return 0;
	}
	if (!strcmp (action, "status")) {
		char *cb = r_vc_current_branch (rp);
		if (!cb) {
			return 1;
		}
		RList *unc = r_vc_get_uncommitted (rp);
		if (!unc) {
			free (cb);
			return 1;
		}
		printf ("Branch: %s\n", cb);
		free (cb);
		if (!r_list_empty (unc)) {
			printf ("The follwing files are uncommitted:\n");
			RListIter *iter;
			const char *i;
			r_list_foreach (unc, iter, i) {
				printf ("%s\n", i);
			}
		} else {
			printf ("All files are committed\n");
		}
		r_list_free (unc);
		return 0;
	}
	if (!strcmp (action, "reset")) {
		if (!r_vc_reset (rp)) {
			free (rp);
			eprintf ("Couldn't reset\n");
			return 1;
		}
		return 0;
	}
	if (!strcmp (action, "clone")) {
		free (rp);
		if (opt.argc < 3) {
			eprintf ("Usage: %s <src> <dst>", argv[0]);
			return -1;
		}
		return !r_vc_clone (argv[1 + opt.ind], argv[2 + opt.ind]);
	}
	free (rp);
	return 1;
}
