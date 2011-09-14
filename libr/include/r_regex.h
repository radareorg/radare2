//#define _DARWIN_C_SOURCE
//#define _POSIX_C_SOURCE
/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1992 Henry Spencer.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer of the University of Toronto.
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
 *
 *	@(#)regex.h	8.2 (Berkeley) 1/3/94
 */

#ifndef _R_REGEX_H_
#define	_R_REGEX_H_

//#include <r_types.h>
//#define ut8 unsigned char
#define R_API
#include <sys/types.h>

#define __off_t off_t
#define __darwin_size_t size_t
/* types */
typedef __off_t regoff_t;

#ifndef _SIZE_T
#define _SIZE_T
typedef __darwin_size_t	size_t;
#endif

typedef struct r_regex_t {
	int re_magic;
	size_t re_nsub;		/* number of parenthesized subexpressions */
	const char *re_endp;	/* end pointer for R_REGEX_PEND */
	struct re_guts *re_g;	/* none of your business :-) */
} RRegex;

typedef struct r_regmatch_t {
	regoff_t rm_so;		/* start of match */
	regoff_t rm_eo;		/* end of match */
} RRegexMatch;


// TODO: rename to R_REGEX_ prefix
/* regcomp() flags */
#define	R_REGEX_BASIC	0000
#define	R_REGEX_EXTENDED	0001
#define	R_REGEX_ICASE	0002
#define	R_REGEX_NOSUB	0004
#define	R_REGEX_NEWLINE	0010
#define	R_REGEX_NOSPEC	0020
#define	R_REGEX_PEND	0040
#define	R_REGEX_DUMP	0200

/* regerror() flags */
#define	R_REGEX_ENOSYS	 (-1)	/* Reserved */
#define	R_REGEX_NOMATCH	 1
#define	R_REGEX_BADPAT	 2
#define	R_REGEX_ECOLLATE	 3
#define	R_REGEX_ECTYPE	 4
#define	R_REGEX_EESCAPE	 5
#define	R_REGEX_ESUBREG	 6
#define	R_REGEX_EBRACK	 7
#define	R_REGEX_EPAREN	 8
#define	R_REGEX_EBRACE	 9
#define	R_REGEX_BADBR	10
#define	R_REGEX_ERANGE	11
#define	R_REGEX_ESPACE	12
#define	R_REGEX_BADRPT	13
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#define	R_REGEX_EMPTY	14
#define	R_REGEX_ASSERT	15
#define	R_REGEX_INVARG	16
#define	R_REGEX_ILLSEQ	17
#define	R_REGEX_ATOI	255	/* convert name to number (!) */
#define	R_REGEX_ITOA	0400	/* convert number to name (!) */
#endif	/* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

/* regexec() flags */
#define	R_REGEX_NOTBOL	00001
#define	R_REGEX_NOTEOL	00002
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#define	R_REGEX_STARTEND	00004
#define	R_REGEX_TRACE	00400	/* tracing of execution */
#define	R_REGEX_LARGE	01000	/* force large representation */
#define	R_REGEX_BACKR	02000	/* force use of backref code */
#endif	/* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

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
