/* radare - Copyright 2011 pancake<nopcode.org> */

/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */
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
#include <r_types.h>

R_LIB_VERSION (r_magic);

#if USE_LIB_MAGIC
#include <magic.h>
#define RMagic void
#define R_API

R_API RMagic* r_magic_new(int flags) {
	return magic_open (flags);
}

R_API void r_magic_free(RMagic* m) {
#if !USE_LIB_MAGIC
	free (m->magic);
#endif
	if (m) magic_close (m);
}

R_API const char *r_magic_file(RMagic* m, const char * f) {
	return magic_file (m, f);
}

R_API const char *r_magic_descriptor(RMagic* m, int fd) {
	return magic_descriptor (m, fd);
}

R_API const char *r_magic_buffer(RMagic* m, const void *b, size_t s) {
	return magic_buffer (m, b, s);
}

R_API const char *r_magic_error(RMagic* m) {
	return magic_error (m);
}

R_API void r_magic_setflags(RMagic* m, int f) {
	magic_setflags (m, f);
}

R_API int r_magic_load(RMagic* m, const char *f) {
	return magic_load (m, f);
}

R_API int r_magic_compile(RMagic* m, const char *x) {
	return magic_compile (m, x);
}

R_API int r_magic_check(RMagic* m, const char *x) {
	return magic_check (m, x);
}

R_API int r_magic_errno(RMagic* m) {
	return magic_errno (m);
}

#else

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>	/* for MAXPATHLEN */
#include <sys/stat.h>
#include <r_magic.h>

#include "file.h"

#ifdef QUICK
#include <sys/mman.h>
#endif
#include <limits.h>	/* for PIPE_BUF */

#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* for read() */
#endif

#if __UNIX__
#include <netinet/in.h>		/* for byte swapping */
#else
#undef O_NONBLOCK
#endif

#include "patchlevel.h"

#ifndef PIPE_BUF 
/* Get the PIPE_BUF from pathconf */
#ifdef _PC_PIPE_BUF
#define PIPE_BUF pathconf(".", _PC_PIPE_BUF)
#else
#define PIPE_BUF 512
#endif
#endif

static void free_mlist(struct mlist *mlist) {
	struct mlist *ml;
	if (mlist == NULL)
		return;
	for (ml = mlist->next; ml != mlist;) {
		struct mlist *next = ml->next;
		struct r_magic *mg = ml->magic;
		file_delmagic (mg, ml->mapped, ml->nmagic);
		free (ml);
		ml = next;
	}
	free (ml);
}

static int info_from_stat(RMagic *ms, mode_t md) {
	/* We cannot open it, but we were able to stat it. */
	if (md & 0222)
		if (file_printf (ms, "writable, ") == -1)
			return -1;
	if (md & 0111)
		if (file_printf (ms, "executable, ") == -1)
			return -1;
	if (S_ISREG (md))
		if (file_printf (ms, "regular file, ") == -1)
			return -1;
	if (file_printf (ms, "no read permission") == -1)
		return -1;
	return 0;
}

static void close_and_restore (const RMagic *ms, const char *name, int fd, const struct stat *sb) {
	if (fd>0)
		close (fd);
}

static const char *file_or_fd(RMagic *ms, const char *inname, int fd) {
	int ispipe = 0, rv = -1;
	unsigned char *buf;
	struct stat sb;
	ssize_t nbytes = 0;	/* number of bytes read from a datafile */

	/*
	 * one extra for terminating '\0', and
	 * some overlapping space for matches near EOF
	 */
#define SLOP (1 + sizeof(union VALUETYPE))
	if ((buf = malloc (HOWMANY + SLOP)) == NULL)
		return NULL;

	if (file_reset (ms) == -1)
		goto done;

	switch (file_fsmagic (ms, inname, &sb)) {
	case -1: goto done;		/* error */
	case 0:	break;			/* nothing found */
	default: rv = 0; goto done;	/* matched it and printed type */
	}

	if (inname == NULL) {
		if (fstat (fd, &sb) == 0 && S_ISFIFO (sb.st_mode))
			ispipe = 1;
	} else {
		int flags = O_RDONLY|O_BINARY;

		if (stat (inname, &sb) == 0 && S_ISFIFO (sb.st_mode)) {
#if O_NONBLOCK
			flags |= O_NONBLOCK;
#endif
			ispipe = 1;
		}
		errno = 0;
		if ((fd = open (inname, flags)) < 0) {
			eprintf ("couldn't open file\n");
			if (info_from_stat (ms, sb.st_mode) == -1)
				goto done;
			rv = 0;
			goto done;
		}
#ifdef O_NONBLOCK
		if ((flags = fcntl (fd, F_GETFL)) != -1) {
			flags &= ~O_NONBLOCK;
			(void)fcntl (fd, F_SETFL, flags);
		}
#endif
	}

	/*
	 * try looking at the first HOWMANY bytes
	 */
#ifdef O_NONBLOCK
	if (ispipe) {
		ssize_t r = 0;

		//while ((r = sread(fd, (void *)&buf[nbytes],
		while ((r = read(fd, (void *)&buf[nbytes],
		    (size_t)(HOWMANY - nbytes))) > 0) {
			nbytes += r;
			if (r < PIPE_BUF) break;
		}

		if (nbytes == 0) {
			/* We can not read it, but we were able to stat it. */
			if (info_from_stat(ms, sb.st_mode) == -1)
				goto done;
			rv = 0;
			goto done;
		}
	} else {
#endif
		if ((nbytes = read(fd, (char *)buf, HOWMANY)) == -1) {
			file_error(ms, errno, "cannot read `%s'", inname);
			goto done;
		}
#ifdef O_NONBLOCK
	}
#endif

	(void)memset (buf + nbytes, 0, SLOP); /* NUL terminate */
	if (file_buffer (ms, fd, inname, buf, (size_t)nbytes) == -1)
		goto done;
	rv = 0;
done:
	free (buf);
	close_and_restore (ms, inname, fd, &sb);
	return rv == 0 ? file_getbuffer(ms) : NULL;
}

/* API */

// TODO: reinitialize all the time
R_API RMagic* r_magic_new(int flags) {
	RMagic *ms = R_NEW0 (RMagic);
	if (!ms) return NULL;
	r_magic_setflags (ms, flags);
	ms->o.buf = ms->o.pbuf = NULL;
	ms->c.li = malloc ((ms->c.len = 10) * sizeof (*ms->c.li));
	if (ms->c.li == NULL) {
		free (ms);
		return NULL;
	}
	file_reset (ms);
	ms->mlist = NULL;
	ms->file = "unknown";
	ms->line = 0;
	return ms;
}

R_API void r_magic_free(RMagic *ms) {
	if (!ms) return;
	free_mlist (ms->mlist);
	free (ms->o.pbuf);
	free (ms->o.buf);
	free (ms->c.li);
	free (ms);
}

R_API int r_magic_load(RMagic* ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_LOAD);
	if (ml) {
		free_mlist (ms->mlist);
		ms->mlist = ml;
		return 0;
	}
	return -1;
}

R_API int r_magic_compile(RMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_COMPILE);
	free_mlist (ml);
	return ml ? 0 : -1;
}

R_API int r_magic_check(RMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_CHECK);
	free_mlist (ml);
	return ml ? 0 : -1;
}

R_API const char* r_magic_descriptor(RMagic *ms, int fd) {
	return file_or_fd (ms, NULL, fd);
}

R_API const char * r_magic_file(RMagic *ms, const char *inname) {
	return file_or_fd (ms, inname, 0); // 0 = stdin
}

R_API const char * r_magic_buffer(RMagic *ms, const void *buf, size_t nb) {
	if (file_reset (ms) == -1)
		return NULL;
	/*
	 * The main work is done here!
	 * We have the file name and/or the data buffer to be identified. 
	 */
	if (file_buffer (ms, -1, NULL, buf, nb) == -1)
		return NULL;
	return file_getbuffer (ms);
}

R_API const char * r_magic_error(RMagic *ms) {
	if (!ms) return 0;
	return ms->haderr ? ms->o.buf : NULL;
}

R_API int r_magic_errno(RMagic *ms) {
	if (!ms) return 0;
	return ms->haderr ? ms->error : 0;
}

R_API void r_magic_setflags(RMagic *ms, int flags) {
	if (ms) ms->flags = flags;
}
#endif
