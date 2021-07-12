/* radare - LGPL - Copyright 2021 - pancake */
#include <rvc.h>

static void rvc2_show_help(void) {
	printf ("Usage: rvc2 [action] [file ...]\n"
		" init            initialize repository in current directory\n"
		" add [file ..]   add files to the current repository\n"
		" checkout [name] checkout given branch name\n"
		" log             list commits in current branch\n"
		" branch          list all available branches\n"
		" commit [a] [m] [f] perform a commit with the added files\n"
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
	const char *action = (argc >= 2)? opt.argv[opt.ind] : NULL;
	if (!action) {
		return -1;
	}
	char *pwd = r_sys_getdir ();
	if (!pwd) {
		return -2;
	}
	char *rp = r_vc_find_rp (pwd);
	if (rp) {
		free (pwd);
	} else {
		rp = pwd;
	}
	if (!strcmp (action, "init")) {
		if (!r_vc_new (rp)) {
			return -3;
		}
		return 0;
	}
	if (!strcmp (action, "branch")) {
		if (opt.argc < 2) {
			return -4;
		}
		if (!r_vc_branch (rp, opt.argv[opt.ind + 1])) {
			return -5;
		}
		return 0;
	}
	if (!strcmp (action, "commit")) {
		int i;
		if (opt.argc < 5) {
			eprintf ("Usage: rvc2 commit [author] [message] [files...]\n");
			free (rp);
			return -6;
		}
		char *auth = r_str_new (opt.argv[opt.ind + 1]);
		if (!auth) {
			free (rp);
			return -7;
		}
		char *message = r_str_new (opt.argv[opt.ind + 2]);
		if (!message) {
			free (rp);
			free (auth);
			return -8;
		}
		RList *files = r_list_new ();
		if (!files) {
			free (rp);
			free (auth);
			free (message);
			return -9;
		}
		for (i = 3; i < argc - 1; i++) {
			char *cf = r_str_new (argv[opt.ind + i]);
			if (!cf) {
				free (auth);
				free (message);
				r_list_free (files);
				free (rp);
				return -10;
			}
			if (!r_list_append (files, cf)) {
				free (auth);
				free (message);
				r_list_free (files);
				free (rp);
				return -10;
			}
		}
		bool ret = r_vc_commit (rp, message, auth, files);
		free (message);
		free (auth);
		r_list_free (files);
		if (!ret) {
			free (rp);
			return -11;
		}
		return 0;
	}
	if (!strcmp (action, "checkout")) {
		if (opt.argc < 2) {
			free (rp);
			return -12;
		}
		if (!r_vc_checkout (rp, opt.argv[opt.ind + 1])) {
			free (rp);
			return -13;
		}
		return 0;
	}
	return -14;
}
