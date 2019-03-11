/* radare - MIT - Copyright 2019 - pancake */

#define GETOPT_C
#include <r_util.h>

#if __WINDOWS__

/*
 * Copyright (c) 1987, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
/* static char sccsid[] = "from: @(#)getopt.c	8.2 (Berkeley) 4/2/94"; */
static char *rcsid = "$Id: getopt.c,v 1.2 1998/01/21 22:27:05 billm Exp $";
#endif /* LIBC_SCCS and not lint */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

R_API int r_opterr = 1;		/* if error message should be printed */
R_API int r_optind = 1;		/* index into parent argv vector */
R_API int r_optopt;			/* character checked for validity */
R_API int r_optreset;		/* reset getopt */
R_API char *r_optarg = NULL;	/* argument associated with option */

#define	BADCH	(int)'?'
#define	BADARG	(int)':'
#define	EMSG	""

/*
 * getopt --
 *	Parse argc/argv argument vector.
 */
R_API int r_getopt(int nargc, char * const *nargv, const char *ostr) {
	static char *place = EMSG;		/* option letter processing */
	char *oli;				/* option letter list index */

	if (r_optreset || !*place) {		/* update scanning pointer */
		r_optreset = 0;
		if (r_optind >= nargc || *(place = nargv[r_optind]) != '-') {
			place = EMSG;
			return -1;
		}
		if (place[1] && *++place == '-') {	/* found "--" */
			r_optind++;
			place = EMSG;
			return -1;
		}
	}
	/* option letter okay? */
	if ((r_optopt = (int)*place++) == (int)':' || !(oli = strchr (ostr, r_optopt))) {
		/*
		 * if the user didn't specify '-' as an option,
		 * assume it means -1.
		 */
		if (r_optopt == (int)'-') {
			return -1;
		}
		if (!*place) {
			r_optind++;
		}
		if (r_opterr && *ostr != ':') {
			(void)eprintf("%s: illegal option -- %c\n", nargv[0], r_optopt);
		}
		return BADCH;
	}
	if (*++oli != ':') {			/* don't need argument */
		r_optarg = NULL;
		if (!*place) {
			r_optind++;
		}
	} else {					/* need an argument */
		if (*place) { /* no white space */
			r_optarg = place;
		} else if (nargc <= ++r_optind) {  /* no arg */
			place = EMSG;
			if (*ostr == ':') {
				return BADARG;
			}
			if (r_opterr) {
				(void)eprintf("%s: option requires an argument -- %c\n", nargv[0], r_optopt);
			}
			return BADCH;
		} else { /* white space */
			r_optarg = nargv[r_optind];
		}
		place = EMSG;
		r_optind++;
	}
	return r_optopt;			/* dump back option letter */
}
#endif
