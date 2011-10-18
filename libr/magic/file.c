/*	$OpenBSD: file.c,v 1.23 2011/04/15 16:05:34 stsp Exp $ */
/*
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * file - find type of a file or files - main program.
 */

#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include <sys/types.h>
#include <sys/param.h>	/* for MAXPATHLEN */
#include <sys/stat.h>

#include <r_magic.h>
#include "file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* for read() */
#endif
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif

#include <getopt.h>
// TODO: drop support for getopt-long
#ifndef HAVE_GETOPT_LONG
int getopt_long(int argc, char * const *argv, const char *optstring, const struct option *longopts, int *longindex);
#endif

#include <netinet/in.h>		/* for byte swapping */
#include "patchlevel.h"

#ifdef S_IFLNK
#define SYMLINKFLAG "Lh"
#else
#define SYMLINKFLAG ""
#endif

# define USAGE  "Usage: %s [-bcik" SYMLINKFLAG "nNprsvz0] [-e test] [-f namefile] [-F separator] [-m magicfiles] file...\n" \
		"       %s -C -m magicfiles\n"

#ifndef MAXPATHLEN
#define	MAXPATHLEN	512
#endif

static int 		/* Global command-line options 		*/
	bflag = 0,	/* brief output format	 		*/
	nopad = 0,	/* Don't pad output			*/
	nobuffer = 0,   /* Do not buffer stdout 		*/
	nulsep = 0;	/* Append '\0' to the separator		*/

static const char *magicfile = 0;	/* where the magic is	*/
static const char *default_magicfile = MAGIC;
static const char *separator = ":";	/* Default field separator	*/

extern char *__progname;		/* used throughout 		*/

static struct r_magic_set *magic;

static void unwrap(char *);
static void usage(void);
static void help(void);

static void process(const char *, int);
static void load(const char *, int);

static void load(const char *m, int flags) {
	if (magic || m == NULL)
		return;
	magic = r_magic_new (flags);
	if (magic == NULL) {
		eprintf ("%s: %s\n", __progname, strerror (errno));
		exit (1);
	}
	if (r_magic_load(magic, magicfile) == -1) {
		eprintf ("%s: %s\n", __progname, r_magic_error (magic));
		exit (1);
	}
}

/*
 * unwrap -- read a file of filenames, do each one.
 */
static void unwrap(char *fn) {
	char buf[MAXPATHLEN];
	FILE *f;
	int wid = 0, cwid;

	if (strcmp("-", fn) == 0) {
		f = stdin;
		wid = 1;
	} else {
		if ((f = fopen(fn, "r")) == NULL) {
			(void)fprintf(stderr, "%s: Cannot open `%s' (%s).\n",
			    __progname, fn, strerror (errno));
			exit(1);
		}
		while (fgets(buf, sizeof(buf), f) != NULL) {
			buf[strcspn(buf, "\n")] = '\0';
			cwid = file_mbswidth(buf);
			if (cwid > wid)
				wid = cwid;
		}
		rewind(f);
	}

	while (fgets (buf, sizeof (buf), f) != NULL) {
		buf[strcspn (buf, "\n")] = '\0';
		process (buf, wid);
		if (nobuffer)
			fflush (stdout);
	}
	fclose (f);
}

/*
 * Called for each input file on the command line (or in a list of files)
 */
static void process(const char *inname, int wid) {
	const char *type;
	int std_in = strcmp (inname, "-") == 0;

	if (wid > 0 && !bflag) {
		(void)printf ("%s", std_in ? "/dev/stdin" : inname);
		if (nulsep)
			(void)putc('\0', stdout);
		else
			(void)printf("%s", separator);
		(void)printf("%*s ",
		    (int) (nopad ? 0 : (wid - file_mbswidth(inname))), "");
	}

	type = r_magic_file(magic, std_in ? NULL : inname);
	if (type == NULL)
		(void)printf ("ERROR: %s\n", r_magic_error (magic));
	else (void)printf ("%s\n", type);
}

size_t file_mbswidth(const char *s) {
#if defined(HAVE_WCHAR_H) && defined(HAVE_MBRTOWC) && defined(HAVE_WCWIDTH)
	size_t bytesconsumed, old_n, n, width = 0;
	mbstate_t state;
	wchar_t nextchar;
	(void)memset(&state, 0, sizeof(mbstate_t));
	old_n = n = strlen(s);
	int w;

	while (n > 0) {
		bytesconsumed = mbrtowc(&nextchar, s, n, &state);
		if (bytesconsumed == (size_t)(-1) ||
		    bytesconsumed == (size_t)(-2)) {
			/* Something went wrong, return something reasonable */
			return old_n;
		}
		if (s[0] == '\n') {
			/*
			 * do what strlen() would do, so that caller
			 * is always right
			 */
			width++;
		} else {
			w = wcwidth(nextchar);
			if (w > 0)
				width += w;
		}
		s += bytesconsumed, n -= bytesconsumed;
	}
	return width;
#else
	return strlen (s);
#endif
}

static void usage(void) {
	eprintf (USAGE, __progname, __progname);
	fputs ("Try `file --help' for more information.\n", stderr);
	exit (1);
}

static void help(void) {
	(void)fputs(
		"Usage: file [OPTION...] [FILE...]\n"
		"Determine type of FILEs.\n"
		"\n", stderr);
#define OPT(shortname, longname, opt, doc)      \
        fprintf(stderr, "  -%c, --" longname doc, shortname);
#define OPT_LONGONLY(longname, opt, doc)        \
        fprintf(stderr, "      --" longname doc);
#include "file_opts.h"
#undef OPT
#undef OPT_LONGONLY
	exit (0);
}
#endif
