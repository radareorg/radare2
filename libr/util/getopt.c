/* radare - MIT - Copyright 2019-2024 - pancake */
/*
 * Copyright (c) 1987, 1993, 1994
 * The Regents of the University of California.  All rights reserved.
 * $Id: getopt.c,v 1.2 1998/01/21 22:27:05 billm Exp $ *
 */

#include <r_util.h>

#define	BADCH	(int)'?'
#define	BADARG	(int)':'
#define	EMSG	""

R_API void r_getopt_init(RGetopt *opt, int argc, const char **argv, const char *ostr) {
	memset (opt, 0, sizeof (RGetopt));
	opt->err = true;
	opt->ind = 1;
	opt->opt = 0;
	opt->arg = NULL;
	opt->place = EMSG;
	opt->argc = argc;
	opt->argv = argv;
	opt->ostr = ostr;
}

R_API int r_getopt_next(RGetopt *opt) {
	const char *oli;

	if (!opt->place) {
		opt->place = EMSG;
	}
	if (!*opt->place) {
		if (opt->ind >= opt->argc || *(opt->place = opt->argv[opt->ind]) != '-') {
			opt->place = EMSG;
			return -1;
		}
		if (opt->place[1] && *++opt->place == '-') { // found "--"
			opt->ind++;
			if (opt->place[1]) {
				// any --WHATEVER will be an alias to -h
				return 0;
			}
			opt->place = EMSG;
			return -1;
		}
	}
	/* option letter okay? */
	if ((opt->opt = (int)*opt->place++) == (int)':' || !(oli = strchr (opt->ostr, opt->opt))) {
		/*
		 * if the user didn't specify '-' as an option,
		 * assume it means -1.
		 */
		if (opt->opt == '-') {
			return -1;
		}
		if (!*opt->place) {
			opt->ind++;
		}
		if (opt->err && *opt->ostr != ':') {
			(void)eprintf ("%s: illegal option -- %c\n", opt->argv[0], opt->opt);
		}
		return BADCH;
	}
	if (*++oli == ':') {
		if (*opt->place) {
			opt->arg = opt->place;
			opt->place = EMSG;
			opt->ind++;
		} else {
			if (opt->argc <= ++opt->ind) {  /* no arg */
				opt->place = EMSG;
				if (*opt->ostr == ':') {
					return BADARG;
				}
				if (opt->err) {
					(void)eprintf ("%s: option requires an argument -- %c\n", opt->argv[0], opt->opt);
				}
				return BADCH;
			}
			opt->arg = opt->argv[opt->ind];
			opt->place = EMSG;
			opt->ind++;
		}
	} else {
		opt->arg = NULL;
		if (!*opt->place) {
			opt->ind++;
		}
	}
	return opt->opt;
}
