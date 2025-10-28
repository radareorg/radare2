/* radare - LGPL - Copyright 2022-2025 - pancake, rhl120 */

#define R_LOG_ORIGIN "ravc"

#include <rvc.h>
#include <r_list.h>
#include <r_main.h>

typedef struct {
	const char *name;
	const char *desc;
} RAvcEnv;

static RAvcEnv env[] = {
	{ "RAVC2_USER", "override cfg.user value to author commit" }
};

static void ravc_show_env(bool show_desc);

static void usage(void) {
	printf ("Usage: ravc2 [-qvh] [action] [args ...]\n");
}

static void help(void) {
	usage ();
	printf (
		"Flags:\n"
		" -q         quiet mode\n"
		" -v         show version\n"
		" -h         display this help message\n"
		" -H ([var]) display variable\n"
		" -j         json output\n"
		"Actions:\n"
		" init       [git | rvc]          initialize a repository with the given vc\n"
		" branch     [name]               if a name is provided, create a branch with that name otherwise list branches\n"
		" commit     [message] [files...] commit the files with the message\n"
		" checkout   [branch]             set the current branch to the given branch\n"
		" status                        print a status message\n"
		" reset                         remove all uncommited changes\n"
		" log                           print all commits\n");
	ravc_show_env (true);
}

static char *get_author(void) {
	char *author = r_sys_getenv ("RAVC2_USER");
	if (R_STR_ISEMPTY (author)) {
		free (author);
		return r_sys_whoami ();
	}
	return author;
}

static void ravc_env_print(const char *name) {
	char *value = r_sys_getenv (name);
	printf ("%s\n", R_STR_ISNOTEMPTY (value)? value: "");
	free (value);
}

static void ravc_show_env(bool show_desc) {
	int id = 0;
	for (id = 0; id < (sizeof (env) / sizeof (env[0])); id++) {
		if (show_desc) {
			printf ("%s\t%s\n", env[id].name, env[id].desc);
		} else {
			printf ("%s=", env[id].name);
			ravc_env_print (env[id].name);
		}
	}
}

R_API int r_main_ravc2(int argc, const char **argv) {
	RGetopt opt;
	int c;
	bool quiet = false;
	bool version = false;

	if (argc < 2) {
		usage ();
		return 1;
	}
	if (!r_cons_is_initialized ()) {
		r_cons_new ();
	}
	int rad = 0;
	r_getopt_init (&opt, argc, argv, "gqvhH:j");
	if (argc == 2 && !strcmp (argv[1], "-H")) {
		ravc_show_env (false);
		return 0;
	}
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'q':
			quiet = true;
			rad = 'q';
			break;
		case 'j':
			rad = 'j';
			break;
		case 'v':
			version = true;
			break;
		case 'h':
			help ();
			return 0;
		case 'H':
			ravc_env_print (opt.arg);
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
		return r_main_version_print ("ravc2", rad);
	}
	if (opt.ind >= argc) {
		R_LOG_ERROR ("Try ravc2 -h");
		return 1;
	}

	const char *action = opt.argv[opt.ind];
	if (!action) {
		R_LOG_ERROR ("Unknown action");
		return 1;
	}
	char *rp = r_sys_getdir ();
	if (!rp) {
		return 1;
	}
	// commands that don't need Rvc *
	if (!strcmp (action, "init")) {
		Rvc *rvc = NULL;
		if (opt.argc <= 2) {
			R_LOG_ERROR ("Usage: ravc2 <git | rvc>");
		} else if (!strcmp (opt.argv[opt.ind + 1], "git")) {
			rvc = rvc_open (rp, RVC_TYPE_GIT);
		} else if (!strcmp (opt.argv[opt.ind + 1], "rvc")) {
			rvc = rvc_open (rp, RVC_TYPE_RVC);
		} else {
			R_LOG_ERROR ("unknown option %s", opt.argv[opt.ind + 1]);
		}
		free (rp);
		return rvc? !rvc_save (rvc): 1;
	}
	Rvc *rvc = rvc_open (rp, RVC_TYPE_ANY);
	if (!rvc) {
		R_LOG_ERROR ("Invalid action or repository in %s", rp);
		R_FREE (rp);
		return 1;
	}
	R_FREE (rp);
	bool save = false; // only save the db if the command ran successfully
	// commands that need Rvc *
	if (!strcmp (action, "branch")) {
		if (opt.argc <= 2) {
			RList *branches = rvc_branches (rvc);
			RListIter *iter;
			char *branch;
			r_list_foreach (branches, iter, branch) {
				printf ("%s\n", branch);
			}
			r_list_free (branches);
		} else {
			// TODO: use api not plugin fields: rvc_branch (rvc, opt.argv[opt.ind + 1]);
			save = rvc->p->branch (rvc, opt.argv[opt.ind + 1]);
		}
	} else if (!strcmp (action, "commit")) {
		if (opt.argc < 4) {
			R_LOG_ERROR ("Usage: ravc2 commit [message] [files...]");
			free (rp);
			return 1;
		}
		char *message = strdup (opt.argv[opt.ind + 1]);
		if (message) {
			RList *files = r_list_new ();
			if (files) {
				size_t i;
				for (i = 2; i < argc - 1; i++) {
					char *file = strdup (argv[opt.ind + i]);
					if (!file || !r_list_append (files, file)) {
						free (message);
						r_list_free (files);
						goto ret;
					}
				}
				char *author = get_author ();
				if (author) {
					save = rvc->p->commit (rvc, message, author, files);
					free (author);
				}
				r_list_free (files);
			}
			free (message);
		}
	} else if (!strcmp (action, "checkout") && opt.argc > 2) {
		save = rvc_checkout (rvc, opt.argv[opt.ind + 1]);
	} else if (!strcmp (action, "status")) {
		char *current_branch = rvc->p->curbranch (rvc);
		if (current_branch) {
			printf ("Branch: %s\n", current_branch);
			RList *uncommited = rvc->p->uncommited (rvc);
			if (r_list_empty (uncommited)) {
				printf ("All files are committed\n");
			} else {
				printf ("The following files were NOT committed:\n");
				RListIter *iter;
				const char *file;
				r_list_foreach (uncommited, iter, file) {
					printf ("%s\n", file);
				}
			}
			r_list_free (uncommited);
		}
	} else if (!strcmp (action, "reset")) {
		save = rvc->p->reset (rvc);
	} else if (!strcmp (action, "log")) {
		save = rvc->p->log (rvc);
	} else {
		R_LOG_ERROR ("Incorrect command");
	}
ret:
	rvc_close (rvc, save);
	// rvc_git_close (rvc, save);
	return !save;
}
