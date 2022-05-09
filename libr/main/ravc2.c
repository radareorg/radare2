/* radare - LGPL - Copyright 2022 - pancake, rhl120 */

#include <rvc.h>
#include <r_list.h>

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

static char *get_author(void) {
	char *author = r_sys_getenv ("RAVC2_USER");
	if (R_STR_ISEMPTY(author)) {
		free (author);
		return r_sys_whoami ();
	}
	return author;
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
	if (!rp) {
		return 1;
	}
	// commands that don't need Rvc *
	if (!strcmp (action, "init")) {
		Rvc *rvc = r_vc_new (rp);
		free (rp);
		return rvc? !r_vc_save(rvc) : 1;
	}
	if (!strcmp (action, "clone")) {
		free (rp);
		if (opt.argc < 3) {
			eprintf ("Usage: %s [src] [dst]\n", argv[0]);
			return -1;
		}
		return !r_vc_clone (argv[1 + opt.ind], argv[2 + opt.ind]);
	}
	Rvc *rvc = r_vc_load(rp);
	R_FREE (rp);
	if (!rvc) {
		return 1;
	}
	bool save = false; // only save the db if the command ran successfully
	// commands that need Rvc *
	if (!strcmp(action, "branch")) {
		if (opt.argc <= 2) {
			RList *branches = r_vc_get_branches(rvc);
			RListIter *iter;
			char *branch;
			r_list_foreach(branches, iter, branch) {
				printf ("%s\n", branch + (r_str_len_utf8 (BPREFIX)));
			}
			r_list_free(branches);
		} else {
			save = r_vc_branch (rvc, opt.argv[opt.ind + 1]);
		}
	} else if (!strcmp(action, "commit")) {
		if (opt.argc < 4) {
			eprintf ("Usage: ravc2 commit [message] [files...]\n");
			free (rp);
			return 1;
		}
		char *message = r_str_new (opt.argv[opt.ind + 1]);
		if (message) {
			RList *files = r_list_new();
			if (files) {
				for (size_t i = 2; i < argc - 1; i++) {
					char *file = r_str_new(argv[opt.ind + i]);
					if (!file || !r_list_append (files, file)) {
						free (message);
						r_list_free (files);
						goto ret;
					}
				}
				char *author = get_author();
				if (author) {
					save = r_vc_commit (rvc, message, author,
							files);
					free (author);
				}
				r_list_free (files);
			}
			free (message);
		}
	} else if (!strcmp(action, "checkout") && opt.argc > 2) {
		save =  r_vc_checkout(rvc, opt.argv[opt.ind + 1]);
	} else if (!strcmp(action, "status")) {
		char *current_branch = r_vc_current_branch(rvc);
		if (current_branch) {
			printf ("Branch: %s\n", current_branch);
			RList *uncommitted = r_vc_get_uncommitted(rvc);
			if (r_list_empty (uncommitted)) {
				printf("All files are committed\n");
			} else {
				printf ("The follwing files are uncommitted:\n");
				RListIter *iter;
				char *file;
				r_list_foreach (uncommitted, iter, file) {
					printf ("%s\n", file);
				}
			}
			r_list_free (uncommitted);
		}
	} else if (!strcmp(action, "reset")) {
		save = r_vc_reset(rvc);
	} else if (!strcmp(action, "log")) {
		RList *commits = r_vc_log(rvc);
		RListIter *iter;
		const char *commit;
		r_list_foreach(commits, iter, commit) {
			printf ("%s\n****\n", commit);
		}
		r_list_free (commits);
		return 0;
	}
	eprintf ("Incorrect command\n");
ret:
	r_vc_close (rvc, save);
	return !save;
}
