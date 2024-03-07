/*	$OpenBSD: file.h,v 1.22 2009/10/27 23:59:37 deraadt Exp $ */
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
 * file.h - definitions for file(1) program
 * @(#)$Id: file.h,v 1.22 2009/10/27 23:59:37 deraadt Exp $
 */

#ifndef __file_h__
#define __file_h__

#include "mconfig.h"
#include <r_magic.h>

#include <stdio.h>	/* Include that here, to make sure __P gets defined */
#include <errno.h>
#include <fcntl.h>	/* For open and flags */
#include <inttypes.h> // TODO: use utX
#include <r_regex.h>
#include <sys/types.h>
/* Do this here and now, because struct stat gets re-defined on solaris */
#include <sys/stat.h>
#include <stdarg.h>
#ifdef _MSC_VER
typedef unsigned int ssize_t;
#endif

/* Type for Unicode characters */
typedef unsigned long unichar;

struct stat;
R_IPI const char *__magic_file_fmttime(unsigned int, int, char *);
R_IPI int __magic_file_buffer(RMagic *, int, const char *, const void *, size_t);
R_IPI int __magic_file_fsmagic(RMagic *, const char *, struct stat *);
R_IPI int __magic_file_printf(RMagic *, const char *, ...);
R_IPI int __magic_file_reset(RMagic *);
R_IPI int __magic_file_zmagic(RMagic *, int, const char *, const ut8*, size_t);
R_IPI int __magic_file_ascmagic(RMagic *, const unsigned char *, size_t);
R_IPI int __magic_file_is_tar(RMagic *, const unsigned char *, size_t);
R_IPI int __magic_file_softmagic(RMagic *, const unsigned char *, size_t, int);
R_IPI struct mlist *__magic_file_apprentice(RMagic *, const char *, size_t, int);
R_IPI ut64 __magic_file_signextend(RMagic *, struct r_magic *, ut64);
R_IPI void __magic_file_delmagic(struct r_magic *, int type, size_t entries);
R_IPI void __magic_file_badread(RMagic *);
R_IPI void __magic_file_badseek(RMagic *);
R_IPI void __magic_file_oomem(RMagic *, size_t);
R_IPI void __magic_file_error(RMagic *, int, const char *, ...);
R_IPI void __magic_file_magerror(RMagic *, const char *, ...);
R_IPI void __magic_file_magwarn(RMagic *, const char *, ...);
R_IPI void __magic_file_mdump(RMagic *, struct r_magic *);
R_IPI void __magic_file_showstr(FILE *, const char *, size_t);
R_IPI const char *__magic_file_getbuffer(RMagic *);
R_IPI int __magic_file_check_mem(RMagic *, unsigned int);
R_IPI int __magic_file_looks_utf8(const unsigned char *, size_t, unichar *, size_t *);

#ifndef HAVE_VASPRINTF
int vasprintf(char **ptr, const char *format_string, va_list vargs);
#endif
#ifndef HAVE_ASPRINTF
int asprintf(char **ptr, const char *format_string, ...);
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#endif /* __file_h__ */
