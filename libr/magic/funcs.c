/* $OpenBSD: funcs.c,v 1.7 2009/10/27 23:59:37 deraadt Exp $ */
/*
 * Copyright (c) Christos Zoulas 2003.
 * All Rights Reserved.
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

#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include "file.h"
#include <r_util.h>
#include <wctype.h>
#if defined(HAVE_WCHAR_H)
#include <wchar.h>
#endif

static int file_vprintf(RMagic *ms, const char *fmt, va_list ap) {
	if (!r_strbuf_vappendf (&ms->o.sb, fmt, ap)) {
		__magic_file_error (ms, errno, "vasprintf failed");
		return -1;
	}
	return 0;
}

/*
 * Like printf, only we append to a buffer.
 */
int __magic_file_printf(RMagic *ms, const char *fmt, ...) {
	va_list ap;

	va_start (ap, fmt);
	const int ret = file_vprintf (ms, fmt, ap);
	va_end (ap);
	return ret;
}

/*
 * error - print best error message possible
 */
/*VARARGS*/
static void __magic_file_error_core(RMagic *ms, int error, const char *f, va_list va, ut32 lineno) {
	/* Only the first error is ok */
	if (!ms || ms->haderr) {
		return;
	}
	if (lineno != 0) {
		r_strbuf_fini (&ms->o.sb);
		r_strbuf_init (&ms->o.sb);
		(void)__magic_file_printf (ms, "line %u: ", lineno);
	}
	// OPENBSDBUG
	file_vprintf (ms, f, va);
	if (error > 0) {
		(void)__magic_file_printf (ms, " (%s)", strerror (error));
	}
	ms->haderr++;
	ms->error = error;
	R_LOG_ERROR ("%s", r_strbuf_get (&ms->o.sb));
}

/*VARARGS*/
void __magic_file_error(RMagic *ms, int error, const char *f, ...) {
	va_list va;
	va_start (va, f);
	__magic_file_error_core (ms, error, f, va, 0);
	va_end (va);
}

/*
 * Print an error with magic line number.
 */
/*VARARGS*/
void __magic_file_magerror(RMagic *ms, const char *f, ...) {
	va_list va;
	va_start (va, f);
	__magic_file_error_core (ms, 0, f, va, ms->line);
	va_end (va);
}

void __magic_file_oomem(RMagic *ms, size_t len) {
	__magic_file_error (ms, errno, "cannot allocate %u bytes", (unsigned int)len);
}

void __magic_file_badseek(RMagic *ms) {
	__magic_file_error (ms, errno, "error seeking");
}

void __magic_file_badread(RMagic *ms) {
	__magic_file_error (ms, errno, "error reading");
}

R_IPI int __magic_file_buffer(RMagic *ms, int fd, const char *inname, const void *buf, size_t nb) {
	int m = 0;
	if (!ms) {
		return -1;
	}
	const int mime = ms->flags & R_MAGIC_MIME;
	if (nb == 0) {
		if ((!mime || (mime & R_MAGIC_MIME_TYPE)) &&
			__magic_file_printf (ms, mime? "application/x-empty": "empty") == -1) {
			return -1;
		}
		return 1;
	} else if (nb == 1) {
		if ((!mime || (mime & R_MAGIC_MIME_TYPE)) &&
			__magic_file_printf (ms, mime? "application/octet-stream": "very short file (no magic)") == -1) {
			return -1;
		}
		return 1;
	}

	/* Check if we have a tar file */
	if ((ms->flags & R_MAGIC_NO_CHECK_TAR) != 0 ||
		(m = __magic_file_is_tar (ms, buf, nb)) == 0) {
		/* try tests in /etc/magic (or surrogate magic file) */
		if ((ms->flags & R_MAGIC_NO_CHECK_SOFT) != 0 ||
			(m = __magic_file_softmagic (ms, buf, nb, BINTEST)) == 0) {
			/* abandon hope, all ye who remain here */
			{
				if ((!mime || (mime & R_MAGIC_MIME_TYPE))) {
					__magic_file_printf (ms, "application/octet-stream");
					return -1;
				}
				m = 1;
			}
		}
	}
	return m;
}

int __magic_file_reset(RMagic *ms) {
	if (!ms) {
		return 0;
	}
	ms->last_cont_level = 0;
	r_strbuf_fini (&ms->o.sb);
	r_strbuf_init (&ms->o.sb);
	ms->haderr = 0;
	ms->error = -1;
	if (!ms->mlist) {
		// eprintf ("no magic files loaded, nothing to scan\n");
		return -1;
	}
	return 0;
}

#define OCTALIFY(n, o) \
	/*LINTED*/ \
	(void) (*(n)++ = '\\', \
		*(n)++ = (((ut32) *(o) >> 6) & 3) + '0', \
		*(n)++ = (((ut32) *(o) >> 3) & 7) + '0', \
		*(n)++ = (((ut32) *(o) >> 0) & 7) + '0', \
		(o)++)

const char *__magic_file_getbuffer(RMagic *ms) {
	char *pbuf, *op, *np;

	if (ms->haderr) {
		return NULL;
	}

	char *const obuf = r_strbuf_get (&ms->o.sb);
	if (ms->flags & R_MAGIC_RAW) {
		return obuf;
	}

	if (r_strbuf_is_empty (&ms->o.sb)) {
		eprintf ("ms->o.sb is empty\n");
		return NULL;
	}

	/* * 4 is for octal representation, + 1 is for NUL */
	const size_t len = strlen (obuf);
	if (len > (SIZE_MAX - 1) / 4) {
		__magic_file_oomem (ms, len);
		return NULL;
	}
	const size_t psize = len * 4 + 1;
	if (! (pbuf = realloc (ms->o.pbuf, psize))) {
		__magic_file_oomem (ms, psize);
		return NULL;
	}
	ms->o.pbuf = pbuf;
	for (np = ms->o.pbuf, op = obuf; *op; op++) {
		if (isprint ((ut8)*op)) {
			*np++ = *op;
		} else {
			OCTALIFY (np, op);
		}
	}
	*np = '\0';
	return ms->o.pbuf;
}

int __magic_file_check_mem(RMagic *ms, unsigned int level) {
	if (level >= ms->c.len) {
		ms->c.len = level + 20;
		const size_t len = ms->c.len * sizeof (*ms->c.li);
		ms->c.li = (!ms->c.li)? malloc (len): realloc (ms->c.li, len);
		if (!ms->c.li) {
			__magic_file_oomem (ms, len);
			return -1;
		}
	}
	ms->c.li[level].got_match = 0;
	ms->c.li[level].last_match = 0;
	ms->c.li[level].last_cond = COND_NONE;
	return 0;
}
#endif
