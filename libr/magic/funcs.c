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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wctype.h>
#if defined(HAVE_WCHAR_H)
#include <wchar.h>
#endif

/*
 * Like printf, only we append to a buffer.
 */
int file_printf(RMagic *ms, const char *fmt, ...) {
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = file_vprintf (ms, fmt, ap);
	va_end (ap);
	return ret;
}

// copypasta to fix an OPENBSDBUG
int file_vprintf(RMagic *ms, const char *fmt, va_list ap) {
	va_list ap2;
	int len;
	char cbuf[4096];
	char *buf, *newstr;
	int buflen;// = strlen (buf);

	va_copy (ap2, ap);
	len = vsnprintf (cbuf, sizeof (cbuf), fmt, ap2);
	va_end (ap2);
	if (len < 0)
		goto out;
	cbuf[len] = 0;
	buf = strdup (cbuf);

	buflen = len;
	if (ms->o.buf != NULL) {
		int obuflen = strlen (ms->o.buf);
		len = obuflen+buflen+1;
		newstr = malloc (len+1);
		memset (newstr, 0, len+1); // XXX: unnecessary?
		newstr[len] = 0;
		memcpy (newstr, ms->o.buf, obuflen);
		memcpy (newstr+obuflen, buf, buflen);
		free (buf);
		if (len < 0)
			goto out;
		free (ms->o.buf);
		buf = newstr;
	}
	ms->o.buf = buf;
	return 0;
out:
	file_error (ms, errno, "vasprintf failed");
	return -1;
}

/*
 * error - print best error message possible
 */
/*VARARGS*/
static void file_error_core(RMagic *ms, int error, const char *f, va_list va, ut32 lineno) {
	/* Only the first error is ok */
	if (!ms || ms->haderr)
		return;
	if (lineno != 0) {
		free(ms->o.buf);
		ms->o.buf = NULL;
		file_printf (ms, "line %u: ", lineno);
	}
	// OPENBSDBUG
        file_vprintf (ms, f, va);
	if (error > 0)
		(void)file_printf (ms, " (%s)", strerror(error));
	ms->haderr++;
	ms->error = error;
}

/*VARARGS*/
void file_error(RMagic *ms, int error, const char *f, ...) {
	va_list va;
	va_start (va, f);
	file_error_core (ms, error, f, va, 0);
	va_end (va);
}

/*
 * Print an error with magic line number.
 */
/*VARARGS*/
void file_magerror(RMagic *ms, const char *f, ...) {
	va_list va;
	va_start (va, f);
	file_error_core (ms, 0, f, va, ms->line);
	va_end (va);
}

void file_oomem(RMagic *ms, size_t len) {
	file_error (ms, errno, "cannot allocate %zu bytes", len);
}

void file_badseek(RMagic *ms) {
	file_error (ms, errno, "error seeking");
}

void file_badread(RMagic *ms) {
	file_error (ms, errno, "error reading");
}

int file_buffer(RMagic *ms, int fd, const char *inname, const void *buf, size_t nb) {
	int mime, m = 0;
	if (!ms)
		return -1;
	mime = ms->flags & R_MAGIC_MIME;
	if (nb == 0) {
		if ((!mime || (mime & R_MAGIC_MIME_TYPE)) &&
		    file_printf(ms, mime ? "application/x-empty" :
		    "empty") == -1)
			return -1;
		return 1;
	} else if (nb == 1) {
		if ((!mime || (mime & R_MAGIC_MIME_TYPE)) &&
		    file_printf(ms, mime ? "application/octet-stream" :
		    "very short file (no magic)") == -1)
			return -1;
		return 1;
	}

#if 0
	/* try compression stuff */
	if ((ms->flags & R_MAGIC_NO_CHECK_COMPRESS) != 0 ||
	    (m = file_zmagic(ms, fd, inname, buf, nb)) == 0) {
#endif
	    /* Check if we have a tar file */
	    if ((ms->flags & R_MAGIC_NO_CHECK_TAR) != 0 ||
		(m = file_is_tar(ms, buf, nb)) == 0) {
		/* try tests in /etc/magic (or surrogate magic file) */
		if ((ms->flags & R_MAGIC_NO_CHECK_SOFT) != 0 ||
		    (m = file_softmagic(ms, buf, nb, BINTEST)) == 0) {
		    /* try known keywords, check whether it is ASCII */
		    if ((ms->flags & R_MAGIC_NO_CHECK_ASCII) != 0 ||
			(m = file_ascmagic(ms, buf, nb)) == 0) {
			/* abandon hope, all ye who remain here */
			if ((!mime || (mime & R_MAGIC_MIME_TYPE))) {
		//		if (mime)
					file_printf (ms, "application/octet-stream");
				return -1;
			}
			m = 1;
		    }
		}
	    }
#if 0
	}
#endif
	return m;
}

int file_reset(RMagic *ms) {
	if (!ms)
		return 0;
	ms->o.buf = NULL;
	ms->haderr = 0;
	ms->error = -1;
	if (ms->mlist == NULL) {
		file_error (ms, 0, "no magic files loaded! ");
		return -1;
	}
	return 0;
}

#define OCTALIFY(n, o)	\
	/*LINTED*/ \
	(void)(*(n)++ = '\\', \
	*(n)++ = (((ut32)*(o) >> 6) & 3) + '0', \
	*(n)++ = (((ut32)*(o) >> 3) & 7) + '0', \
	*(n)++ = (((ut32)*(o) >> 0) & 7) + '0', \
	(o)++)

const char *file_getbuffer(RMagic *ms) {
	char *pbuf, *op, *np;
	size_t psize, len;

	if (ms->haderr)
		return NULL;

	if (ms->flags & R_MAGIC_RAW)
		return ms->o.buf;

	if (ms->o.buf == NULL) {
		eprintf ("ms->o.buf = NULL\n");
		return NULL;
	}

	/* * 4 is for octal representation, + 1 is for NUL */
	len = strlen (ms->o.buf);
	if (len > (SIZE_MAX - 1) / 4) {
		file_oomem (ms, len);
		return NULL;
	}
	psize = len * 4 + 1;
	if ((pbuf = realloc (ms->o.pbuf, psize)) == NULL) {
		file_oomem (ms, psize);
		return NULL;
	}
	ms->o.pbuf = pbuf;

#if 1
//defined(HAVE_WCHAR_H) && defined(HAVE_MBRTOWC) && defined(HAVE_WCWIDTH)
	{
		mbstate_t state;
		wchar_t nextchar;
		int mb_conv = 1;
		size_t bytesconsumed;
		char *eop;
		(void)memset(&state, 0, sizeof(mbstate_t));

		np = ms->o.pbuf;
		op = ms->o.buf;
		eop = op + len;

		while (op < eop) {
			bytesconsumed = mbrtowc(&nextchar, op,
			    (size_t)(eop - op), &state);
			if (bytesconsumed == (size_t)(-1) ||
			    bytesconsumed == (size_t)(-2)) {
				mb_conv = 0;
				break;
			}

			if (iswprint(nextchar)) {
				(void)memcpy(np, op, bytesconsumed);
				op += bytesconsumed;
				np += bytesconsumed;
			} else {
				while (bytesconsumed-- > 0)
					OCTALIFY(np, op);
			}
		}
		*np = '\0';

		/* Parsing succeeded as a multi-byte sequence */
		if (mb_conv != 0)
			return ms->o.pbuf;
	}
#endif
	for (np = ms->o.pbuf, op = ms->o.buf; *op; op++) {
		if (isprint ((ut8)*op)) {
			*np++ = *op;	
		} else {
			OCTALIFY (np, op);
		}
	}
	*np = '\0';
	return ms->o.pbuf;
}

int file_check_mem(RMagic *ms, unsigned int level) {
	if (level >= ms->c.len) {
		size_t len = (ms->c.len += 20) * sizeof (*ms->c.li);
		ms->c.li = (ms->c.li == NULL) ? malloc (len) :
		    realloc (ms->c.li, len);
		if (ms->c.li == NULL) {
			file_oomem (ms, len);
			return -1;
		}
	}
	ms->c.li[level].got_match = 0;
	ms->c.li[level].last_match = 0;
	ms->c.li[level].last_cond = COND_NONE;
	return 0;
}
#endif
