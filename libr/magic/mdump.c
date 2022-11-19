/*	$OpenBSD: print.c,v 1.16 2009/10/27 23:59:37 deraadt Exp $ */
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
 * print.c - debugging printout routines
 */
#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include "file.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#define SZOF(a)	(sizeof (a) / sizeof (a[0]))

#ifndef COMPILE_ONLY
void file_mdump(RMagic *ms, struct r_magic *m) {
	char pp[ASCTIME_BUF_MAXLEN];

	(void) eprintf ("[%u", m->lineno);
	(void) eprintf ("%.*s %u", m->cont_level & 7, ">>>>>>>>", m->offset);

	if (m->flag & INDIR) {
		(void) eprintf ("(%s,",
			       /* Note: type is unsigned */
			       (m->in_type < FILE_NAMES_SIZE) ?
					ms->magic_file_names[m->in_type] : "*bad*");
		if (m->in_op & FILE_OPINVERSE)
			(void) fputc('~', stderr);
		(void) eprintf ("%c%u),",
			       ((m->in_op & FILE_OPS_MASK) < SZOF(FILE_OPS)) ?
					FILE_OPS[m->in_op & FILE_OPS_MASK] : '?',
				m->in_offset);
	}
	(void) eprintf (" %s%s", (m->flag & UNSIGNED) ? "u" : "",
		       /* Note: type is unsigned */
		       (m->type < FILE_NAMES_SIZE) ? ms->magic_file_names[m->type] : "*bad*");
	if (m->mask_op & FILE_OPINVERSE)
		(void) fputc('~', stderr);

	if (MAGIC_IS_STRING(m->type)) {
		if (m->str_flags) {
			(void) fputc('/', stderr);
			if (m->str_flags & STRING_COMPACT_BLANK)
				(void) fputc(CHAR_COMPACT_BLANK, stderr);
			if (m->str_flags & STRING_COMPACT_OPTIONAL_BLANK)
				(void) fputc(CHAR_COMPACT_OPTIONAL_BLANK,
				    stderr);
			if (m->str_flags & STRING_IGNORE_LOWERCASE)
				(void) fputc(CHAR_IGNORE_LOWERCASE, stderr);
			if (m->str_flags & STRING_IGNORE_UPPERCASE)
				(void) fputc(CHAR_IGNORE_UPPERCASE, stderr);
			if (m->str_flags & REGEX_OFFSET_START)
				(void) fputc(CHAR_REGEX_OFFSET_START, stderr);
		}
		if (m->str_range) {
			(void) eprintf ("/%u", m->str_range);
		}
	} else {
		if ((m->mask_op & FILE_OPS_MASK) < SZOF(FILE_OPS)) {
			(void) fputc (FILE_OPS[m->mask_op & FILE_OPS_MASK], stderr);
		} else {
			(void) fputc ('?', stderr);
		}
		if (m->num_mask) {
			(void) eprintf ("%08"PFMT64x, (ut64)m->num_mask);
		}
	}
	(void) eprintf (",%c", m->reln);

	if (m->reln != 'x') {
		switch (m->type) {
		case FILE_BYTE:
		case FILE_SHORT:
		case FILE_LONG:
		case FILE_LESHORT:
		case FILE_LELONG:
		case FILE_MELONG:
		case FILE_BESHORT:
		case FILE_BELONG:
			(void) eprintf ("%d", m->value.l);
			break;
		case FILE_BEQUAD:
		case FILE_LEQUAD:
		case FILE_QUAD:
			(void) eprintf ("%"PFMT64d, (ut64)m->value.q);
			break;
		case FILE_PSTRING:
		case FILE_STRING:
		case FILE_REGEX:
		case FILE_BESTRING16:
		case FILE_LESTRING16:
		case FILE_SEARCH:
			file_showstr(stderr, m->value.s, (size_t)m->vallen);
			break;
		case FILE_DATE:
		case FILE_LEDATE:
		case FILE_BEDATE:
		case FILE_MEDATE:
			(void)eprintf ("%s,",
			    file_fmttime (m->value.l, 1, pp));
			break;
		case FILE_LDATE:
		case FILE_LELDATE:
		case FILE_BELDATE:
		case FILE_MELDATE:
			(void)eprintf ("%s,",
			    file_fmttime (m->value.l, 0, pp));
			break;
		case FILE_QDATE:
		case FILE_LEQDATE:
		case FILE_BEQDATE:
			(void)eprintf ("%s,",
			    file_fmttime ((ut32)m->value.q, 1, pp));
			break;
		case FILE_QLDATE:
		case FILE_LEQLDATE:
		case FILE_BEQLDATE:
			(void)eprintf ("%s,",
			    file_fmttime ((ut32)m->value.q, 0, pp));
			break;
		case FILE_FLOAT:
		case FILE_BEFLOAT:
		case FILE_LEFLOAT:
			(void) eprintf ("%G", m->value.f);
			break;
		case FILE_DOUBLE:
		case FILE_BEDOUBLE:
		case FILE_LEDOUBLE:
			(void) eprintf ("%G", m->value.d);
			break;
		case FILE_DEFAULT:
			/* XXX - do anything here? */
			break;
		default:
			(void) fputs("*bad*", stderr);
			break;
		}
	}
	(void) eprintf (",\"%s\"]\n", m->desc);
}
#endif

/*VARARGS*/
void file_magwarn(struct r_magic_set *ms, const char *f, ...) {
	va_list va;
	RStrBuf *sb = r_strbuf_new ("");
	if (R_STR_ISNOTEMPTY (ms->file)) {
		r_strbuf_appendf (sb, "%s, %lu: ",
			ms->file, (unsigned long)ms->line);
	}
	va_start (va, f);
	r_strbuf_vappendf (sb, f, va);
	va_end (va);
	char *msg = r_strbuf_drain (sb);
	R_LOG_WARN ("%s", msg);
	free (msg);
}

const char *file_fmttime(ut32 v, int local, char *pp) {
	time_t t = (time_t)v;

	if (local) {
		r_ctime_r (&t, pp);
	} else {
#if __MINGW32__
		// nothing
#else
		struct tm timestruct;
		struct tm *tm = gmtime_r (&t, &timestruct);
		if (!tm) {
			return "*Invalid time*";
		}
		r_asctime_r (tm, pp);
#endif
	}
	// TODO i dont like string spoons
	pp[strcspn (pp, "\n")] = '\0';
	return pp;
}
#endif
