#ifndef R2_REGEX_H
#define	R2_REGEX_H

#include <r_types.h>
#include <sys/types.h>

typedef struct r_regex_t {
	int re_magic;
	size_t re_nsub;	/* number of parenthesized subexpressions */
	const char *re_endp; /* end pointer for R_REGEX_PEND */
	struct re_guts *re_g; /* none of your business :-) */
} RRegex;

typedef struct r_regmatch_t {
	off_t rm_so;		/* start of match */
	off_t rm_eo;		/* end of match */
} RRegexMatch;

typedef int regoff_t;

/* regcomp() flags */
#define	R_REGEX_BASIC		0000
#define	R_REGEX_EXTENDED	0001
#define	R_REGEX_ICASE		0002
#define	R_REGEX_NOSUB		0004
#define	R_REGEX_NEWLINE		0010
#define	R_REGEX_NOSPEC		0020
#define	R_REGEX_PEND		0040
#define	R_REGEX_DUMP		0200

/* regerror() flags */
#define	R_REGEX_ENOSYS		(-1)	/* Reserved */
#define	R_REGEX_NOMATCH		1
#define	R_REGEX_BADPAT		2
#define	R_REGEX_ECOLLATE	3
#define	R_REGEX_ECTYPE		4
#define	R_REGEX_EESCAPE		5
#define	R_REGEX_ESUBREG		6
#define	R_REGEX_EBRACK		7
#define	R_REGEX_EPAREN		8
#define	R_REGEX_EBRACE		9
#define	R_REGEX_BADBR		10
#define	R_REGEX_ERANGE		11
#define	R_REGEX_ESPACE		12
#define	R_REGEX_BADRPT		13
#define	R_REGEX_EMPTY		14
#define	R_REGEX_ASSERT		15
#define	R_REGEX_INVARG		16
#define	R_REGEX_ILLSEQ		17
#define	R_REGEX_ATOI		255		/* convert name to number (!) */
#define	R_REGEX_ITOA		0400	/* convert number to name (!) */

/* regexec() flags */
#define	R_REGEX_NOTBOL		00001
#define	R_REGEX_NOTEOL		00002
#define	R_REGEX_STARTEND	00004
#define	R_REGEX_TRACE		00400	/* tracing of execution */
#define	R_REGEX_LARGE		01000	/* force large representation */
#define	R_REGEX_BACKR		02000	/* force use of backref code */

R_API RRegex *r_regex_new (const char *pattern, const char *cflags);
R_API int r_regex_run (const char *pattern, const char *flags, const char *text);
R_API int r_regex_flags(const char *flags);
R_API int r_regex_comp(RRegex*, const char *, int);
R_API size_t r_regex_error(int, const RRegex*, char *, size_t);
/*
 * gcc under c99 mode won't compile "[]" by itself.  As a workaround,
 * a dummy argument name is added.
 */
R_API int r_regex_exec(const RRegex *, const char *, size_t, RRegexMatch __pmatch[], int);
R_API void r_regex_free(RRegex *);
R_API void r_regex_fini(RRegex *);

#endif /* !_REGEX_H_ */
