/*	$OpenBSD: softmagic.c,v 1.16 2010/01/17 20:36:21 chl Exp $ */
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
 * softmagic - interpret variable magic from MAGIC
 */
#include <r_userconf.h>

#if !USE_LIB_MAGIC

#include <r_util.h>
#include "file.h"
#include "r_regex.h"
#include "r_util/r_time.h"

static void magic_debug(RMagic *ms, const char *fmt, ...) {
	if ((ms->flags & R_MAGIC_DEBUG) == 0) {
		return;
	}
	va_list ap;
	va_start (ap, fmt);
	char *msg = r_str_newvf (fmt, ap);
	va_end (ap);
	if (msg) {
		R_LOG_DEBUG ("%s", msg);
		free (msg);
	}
}

static bool magic_hasbytes(size_t nbytes, st64 offset, size_t need) {
	size_t uoffset;

	if (offset < 0) {
		return false;
	}
	uoffset = (size_t)offset;
	if (uoffset > nbytes) {
		return false;
	}
	return need <= nbytes - uoffset;
}

/*
 * Macro to give description string according to whether we want plain
 * text or MIME type
 */
#define R_MAGIC_DESC ((ms->flags & R_MAGIC_MIME)? m->mimetype: m->desc)

static int check_fmt(RMagic *ms, struct r_magic *m) {
	RRegex rx = { 0 };
	int rc;

	if (!strchr (R_MAGIC_DESC, '%')) {
		return 0;
	}

	rc = r_regex_init (&rx, "%[-0-9\\.]*s", R_REGEX_EXTENDED | R_REGEX_NOSUB);
	if (rc) {
		char *errmsg = r_regex_error (&rx, rc);
		__magic_file_magerror (ms, "regex error %d, (%s)", rc, errmsg);
		free (errmsg);
		return -1;
	} else {
		rc = r_regex_exec (&rx, R_MAGIC_DESC, 0, 0, 0);
		r_regex_fini (&rx);
		return !rc;
	}
}

static st32 mprint(RMagic *ms, struct r_magic *m) {
	ut64 v;
	float vf;
	double vd;
	ut64 t = 0;
	char *buf = NULL;
	union VALUETYPE *const p = &ms->ms_value;
	char pp[ASCTIME_BUF_MAXLEN];

	switch (m->type) {
	case FILE_BYTE:
		v = __magic_file_signextend (ms, m, (ut64)p->b);
		switch (check_fmt (ms, m)) {
		case -1:
			return -1;
		case 1:
			buf = malloc (2);
			if (snprintf (buf, 2, "%c", (ut8)v) < 0) {
				free (buf);
				return -1;
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, buf) == -1) {
				free (buf);
				return -1;
			}
			break;
		default:
			if (__magic_file_printf (ms, R_MAGIC_DESC, (ut8)v) == -1) {
				return -1;
			}
			break;
		}
		t = ms->offset + sizeof (char);
		break;
	case FILE_SHORT:
	case FILE_BESHORT:
	case FILE_LESHORT:
		v = __magic_file_signextend (ms, m, (ut64)p->h);
		switch (check_fmt (ms, m)) {
		case -1:
			return -1;
		case 1:
			buf = malloc (32);
			if (snprintf (buf, 32, "%hu", (unsigned short)v) < 0) {
				free (buf);
				return -1;
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, buf) == -1) {
				free (buf);
				return -1;
			}
			break;
		default:
			if (__magic_file_printf (ms, R_MAGIC_DESC, (unsigned short)v) == -1) {
				return -1;
			}
			break;
		}
		t = ms->offset + sizeof (short);
		break;
	case FILE_LONG:
	case FILE_BELONG:
	case FILE_LELONG:
	case FILE_MELONG:
		v = __magic_file_signextend (ms, m, (ut64)p->l);
		switch (check_fmt (ms, m)) {
		case -1:
			return -1;
		case 1:
			buf = malloc (32);
			if (snprintf (buf, 32, "%u", (ut32)v) < 0) {
				free (buf);
				return -1;
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, buf) == -1) {
				free (buf);
				return -1;
			}
			break;
		default:
			if (__magic_file_printf (ms, R_MAGIC_DESC, (ut32)v) == -1) {
				return -1;
			}
			break;
		}
		t = ms->offset + sizeof (st32);
		break;
	case FILE_QUAD:
	case FILE_BEQUAD:
	case FILE_LEQUAD:
		v = __magic_file_signextend (ms, m, p->q);
		if (__magic_file_printf (ms, R_MAGIC_DESC, (ut64)v) == -1) {
			return -1;
		}
		t = ms->offset + sizeof (ut64);
		break;

	case FILE_STRING:
	case FILE_PSTRING:
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		if (m->reln == '=' || m->reln == '!') {
			if (__magic_file_printf (ms, R_MAGIC_DESC, m->value.s) == -1) {
				return -1;
			}
			t = ms->offset + m->vallen;
		} else {
			if (*m->value.s == '\0') {
				p->s[strcspn (p->s, "\n")] = '\0';
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, p->s) == -1) {
				return -1;
			}
			t = ms->offset + strlen (p->s);
			if (m->type == FILE_PSTRING) {
				t++;
			}
		}
		break;
	case FILE_DATE:
	case FILE_BEDATE:
	case FILE_LEDATE:
	case FILE_MEDATE:
		if (__magic_file_printf (ms, R_MAGIC_DESC, __magic_file_fmttime (p->l, 1, pp)) == -1) {
			return -1;
		}
		t = ms->offset + sizeof (time_t);
		break;
	case FILE_LDATE:
	case FILE_BELDATE:
	case FILE_LELDATE:
	case FILE_MELDATE:
		if (__magic_file_printf (ms, R_MAGIC_DESC, __magic_file_fmttime (p->l, 0, pp)) == -1) {
			return -1;
		}
		t = ms->offset + sizeof (time_t);
		break;
	case FILE_QDATE:
	case FILE_BEQDATE:
	case FILE_LEQDATE:
		if (__magic_file_printf (ms, R_MAGIC_DESC, __magic_file_fmttime ((ut32)p->q, 1, pp)) == -1) {
			return -1;
		}
		t = ms->offset + sizeof (ut64);
		break;
	case FILE_QLDATE:
	case FILE_BEQLDATE:
	case FILE_LEQLDATE:
		if (__magic_file_printf (ms, R_MAGIC_DESC, __magic_file_fmttime ((ut32)p->q, 0, pp)) == -1) {
			return -1;
		}
		t = ms->offset + sizeof (ut64);
		break;
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
		vf = p->f;
		switch (check_fmt (ms, m)) {
		case -1:
			return -1;
		case 1:
			buf = malloc (32);
			if (snprintf (buf, 32, "%g", vf) < 0) {
				free (buf);
				return -1;
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, buf) == -1) {
				free (buf);
				return -1;
			}
			break;
		default:
			if (__magic_file_printf (ms, R_MAGIC_DESC, vf) == -1) {
				return -1;
			}
			break;
		}
		t = ms->offset + sizeof (float);
		break;
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
		vd = p->d;
		switch (check_fmt (ms, m)) {
		case -1:
			return -1;
		case 1:
			buf = malloc (32);
			if (snprintf (buf, 32, "%g", vd) < 0) {
				free (buf);
				return -1;
			}
			if (__magic_file_printf (ms, R_MAGIC_DESC, buf) == -1) {
				free (buf);
				return -1;
			}
			break;
		default:
			if (__magic_file_printf (ms, R_MAGIC_DESC, vd) == -1) {
				return -1;
			}
			break;
		}
		t = ms->offset + sizeof (double);
		break;
	case FILE_REGEX:
		{
			char *const cp = r_str_ndup ((const char *)ms->search.s, ms->search.rm_len);
			if (!cp) {
				__magic_file_oomem (ms, ms->search.rm_len);
				return -1;
			}
			const int rval = __magic_file_printf (ms, R_MAGIC_DESC, cp);
			free (cp);
			if (rval == -1) {
				return -1;
			}
			if ((m->str_flags & REGEX_OFFSET_START)) {
				t = ms->search.offset;
			} else {
				t = ms->search.offset + ms->search.rm_len;
			}
			break;
		}

	case FILE_SEARCH:
		if (__magic_file_printf (ms, R_MAGIC_DESC, m->value.s) == -1) {
			return -1;
		}
		if ((m->str_flags & REGEX_OFFSET_START)) {
			t = ms->search.offset;
		} else {
			t = ms->search.offset + m->vallen;
		}
		break;
	case FILE_DEFAULT:
		if (__magic_file_printf (ms, R_MAGIC_DESC, m->value.s) == -1) {
			return -1;
		}
		t = ms->offset;
		break;
	default:
		__magic_file_magerror (ms, "invalid m->type (%d) in mprint()", m->type);
		return -1;
	}
	free (buf);
	return t;
}

#define DO_CVT(fld, cast) \
	if (m->num_mask) \
		switch (m->mask_op & FILE_OPS_MASK) { \
		case FILE_OPAND: \
			p->fld &= cast m->num_mask; \
			break; \
		case FILE_OPOR: \
			p->fld |= cast m->num_mask; \
			break; \
		case FILE_OPXOR: \
			p->fld ^= cast m->num_mask; \
			break; \
		case FILE_OPADD: \
			p->fld += cast m->num_mask; \
			break; \
		case FILE_OPMINUS: \
			p->fld -= cast m->num_mask; \
			break; \
		case FILE_OPMULTIPLY: \
			p->fld *= cast m->num_mask; \
			break; \
		case FILE_OPDIVIDE: \
			p->fld /= cast m->num_mask; \
			break; \
		case FILE_OPMODULO: \
			p->fld %= cast m->num_mask; \
			break; \
		} \
	if (m->mask_op & FILE_OPINVERSE) \
	p->fld = ~p->fld

static void cvt_8(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT (b, (ut8));
}

static void cvt_16(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT (h, (ut16));
}

static void cvt_32(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT (l, (ut32));
}

static void cvt_64(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT (q, (ut64));
}

#define DO_CVT2(fld, cast) \
	if (m->num_mask) \
		switch (m->mask_op & FILE_OPS_MASK) { \
		case FILE_OPADD: \
			p->fld += cast m->num_mask; \
			break; \
		case FILE_OPMINUS: \
			p->fld -= cast m->num_mask; \
			break; \
		case FILE_OPMULTIPLY: \
			p->fld *= cast m->num_mask; \
			break; \
		case FILE_OPDIVIDE: \
			p->fld /= cast m->num_mask; \
			break; \
		}

static void cvt_float(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT2 (f, (float));
}

static void cvt_double(union VALUETYPE *p, const struct r_magic *m) {
	DO_CVT2 (d, (double));
}

static st32 apply_indir_op(st32 value, st32 off, int op) {
	if (off) {
		switch (op & FILE_OPS_MASK) {
		case FILE_OPAND: value &= off; break;
		case FILE_OPOR: value |= off; break;
		case FILE_OPXOR: value ^= off; break;
		case FILE_OPADD: value += off; break;
		case FILE_OPMINUS: value -= off; break;
		case FILE_OPMULTIPLY: value *= off; break;
		case FILE_OPDIVIDE: value /= off; break;
		case FILE_OPMODULO: value %= off; break;
		}
	}
	return (op & FILE_OPINVERSE)? ~value: value;
}

static st32 magic_melong(const ut8 *hl) {
	return (st32) ((hl[1] << 24) | (hl[0] << 16) | (hl[3] << 8) | hl[2]);
}

static bool magic_get_indir_value(st32 *out, const union VALUETYPE *p, int type) {
	switch (type) {
	case FILE_BYTE:
		*out = p->b;
		return true;
	case FILE_SHORT:
		*out = p->h;
		return true;
	case FILE_BESHORT:
		*out = (st16)r_read_be16 (p->hs);
		return true;
	case FILE_LESHORT:
		*out = (st16)r_read_le16 (p->hs);
		return true;
	case FILE_LONG:
		*out = p->l;
		return true;
	case FILE_BELONG:
		*out = (st32)r_read_be32 (p->hl);
		return true;
	case FILE_LELONG:
		*out = (st32)r_read_le32 (p->hl);
		return true;
	case FILE_MELONG:
		*out = magic_melong (p->hl);
		return true;
	default:
		return false;
	}
}

static void magic_rstrip_newline(char *s) {
	size_t len = strlen (s);
	if (len > 0 && s[len - 1] == '\n') {
		s[len - 1] = '\0';
	}
}

/*
 * Convert the byte order of the data we are looking at
 * While we're here, let's apply the mask operation
 *(unless you have a better idea)
 */
static int mconvert(RMagic *ms, struct r_magic *m) {
	union VALUETYPE *const p = &ms->ms_value;

	switch (m->type) {
	case FILE_BYTE:
		cvt_8 (p, m);
		return 1;
	case FILE_SHORT:
		cvt_16 (p, m);
		return 1;
	case FILE_LONG:
	case FILE_DATE:
	case FILE_LDATE:
		cvt_32 (p, m);
		return 1;
	case FILE_QUAD:
	case FILE_QDATE:
	case FILE_QLDATE:
		cvt_64 (p, m);
		return 1;
	case FILE_STRING:
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		p->s[sizeof (p->s) - 1] = '\0';
		magic_rstrip_newline (p->s);
		return 1;
	case FILE_PSTRING:
		{
			char *ptr1 = p->s, *ptr2 = ptr1 + 1;
			size_t len = *p->s;
			if (len >= sizeof (p->s)) {
				len = sizeof (p->s) - 1;
			}
			while (len--) {
				*ptr1++ = *ptr2++;
			}
			*ptr1 = '\0';
			magic_rstrip_newline (p->s);
			return 1;
		}
	case FILE_BESHORT:
		p->h = (short)r_read_be16 (p->hs);
		cvt_16 (p, m);
		return 1;
	case FILE_BELONG:
	case FILE_BEDATE:
	case FILE_BELDATE:
		p->l = (st32)r_read_be32 (p->hl);
		cvt_32 (p, m);
		return 1;
	case FILE_BEQUAD:
	case FILE_BEQDATE:
	case FILE_BEQLDATE:
		p->q = r_read_be64 (p->hq);
		cvt_64 (p, m);
		return 1;
	case FILE_LESHORT:
		p->h = (short)r_read_le16 (p->hs);
		cvt_16 (p, m);
		return 1;
	case FILE_LELONG:
	case FILE_LEDATE:
	case FILE_LELDATE:
		p->l = (st32)r_read_le32 (p->hl);
		cvt_32 (p, m);
		return 1;
	case FILE_LEQUAD:
	case FILE_LEQDATE:
	case FILE_LEQLDATE:
		p->q = r_read_le64 (p->hq);
		cvt_64 (p, m);
		return 1;
	case FILE_MELONG:
	case FILE_MEDATE:
	case FILE_MELDATE:
		p->l = magic_melong (p->hl);
		cvt_32 (p, m);
		return 1;
	case FILE_FLOAT:
		cvt_float (p, m);
		return 1;
	case FILE_BEFLOAT:
		p->l = r_read_be32 (p->hl);
		cvt_float (p, m);
		return 1;
	case FILE_LEFLOAT:
		p->l = r_read_le32 (p->hl);
		cvt_float (p, m);
		return 1;
	case FILE_DOUBLE:
		cvt_double (p, m);
		return 1;
	case FILE_BEDOUBLE:
		p->q = r_read_be64 (p->hq);
		cvt_double (p, m);
		return 1;
	case FILE_LEDOUBLE:
		p->q = r_read_le64 (p->hq);
		cvt_double (p, m);
		return 1;
	case FILE_REGEX:
	case FILE_SEARCH:
	case FILE_DEFAULT:
		return 1;
	default:
		__magic_file_magerror (ms, "invalid type %d in mconvert()", m->type);
		return 0;
	}
}

static void magic_debug_dump(RMagic *ms, struct r_magic *m, ut32 offset, const union VALUETYPE *p) {
	if ((ms->flags & R_MAGIC_DEBUG) == 0) {
		return;
	}
	char *const escaped = r_str_escape_raw ((const ut8 *)p, (int)sizeof (*p));
	if (escaped) {
		magic_debug (ms, "mget @%u: %s", offset, escaped);
		free (escaped);
	} else {
		magic_debug (ms, "mget @%u", offset);
	}
	__magic_file_mdump (ms, m);
}

static int mcopy(RMagic *ms, union VALUETYPE *p, int type, int indir, const ut8 *s, ut32 offset, size_t nbytes, size_t linecnt) {
	// Search and regex types just point into the source buffer.
	if (indir == 0) {
		switch (type) {
		case FILE_SEARCH:
			ms->search.s = (const char *)s + offset;
			ms->search.s_len = nbytes - offset;
			ms->search.offset = offset;
			return 0;
		case FILE_REGEX:
			{
				const char *b;
				const char *c;
				const char *last; /* end of search region */
				const char *buf; /* start of search region */
				size_t lines;

				if (!s) {
					ms->search.s_len = 0;
					ms->search.s = NULL;
					return 0;
				}
				buf = (const char *)s + offset;
				last = (const char *)s + nbytes;
				/* mget () guarantees buf <= last */
				for (lines = linecnt, b = buf;
					lines && ((b = strchr (c = b, '\n')) || (b = strchr (c, '\r')));
					lines--, b++) {
					last = b;
					if (b[0] == '\r' && b[1] == '\n') {
						b++;
					}
				}
				if (lines) {
					last = (const char *)s + nbytes;
				}

				ms->search.s = buf;
				ms->search.s_len = last - buf;
				ms->search.offset = offset;
				ms->search.rm_len = 0;
				return 0;
			}
		case FILE_BESTRING16:
		case FILE_LESTRING16:
			{
				const ut8 *src = s + offset;
				const ut8 *esrc = s + nbytes;
				char *dst = p->s;
				char *edst = &p->s[sizeof (p->s) - 1];

				if (type == FILE_BESTRING16) {
					src++;
				}

				/* check for pointer overflow */
				if (src < s) {
					__magic_file_magerror (ms, "invalid offset %u in mcopy()", offset);
					return -1;
				}
				for (/*EMPTY*/; src < esrc; src += 2, dst++) {
					if (dst < edst) {
						*dst = *src;
					} else {
						break;
					}
					if (*dst == '\0') {
						if (type == FILE_BESTRING16? *(src - 1) != '\0': *(src + 1) != '\0') {
							*dst = ' ';
						}
					}
				}
				*edst = '\0';
				return 0;
			}
		case FILE_STRING: /* XXX - these two should not need */
		case FILE_PSTRING: /* to copy anything, but do anyway. */
		default:
			break;
		}
	}

	if (offset >= nbytes) {
		(void)memset (p, '\0', sizeof (*p));
		return 0;
	}
	nbytes = (nbytes - offset < sizeof (*p))? nbytes - offset: sizeof (*p);

	(void)memcpy (p, s + offset, nbytes);

	if (nbytes < sizeof (*p)) {
		(void)memset (((char *) (void *)p) + nbytes, '\0', sizeof (*p) - nbytes);
	}
	return 0;
}

static int mget(RMagic *ms, const ut8 *s, struct r_magic *m, size_t nbytes, unsigned int cont_level) {
	ut32 offset = ms->offset;
	const ut32 count = m->str_range;
	union VALUETYPE *const p = &ms->ms_value;

	if (mcopy (ms, p, m->type, m->flag & INDIR, s, offset, nbytes, count) == -1) {
		return -1;
	}

	magic_debug_dump (ms, m, offset, p);

	if (m->flag & INDIR) {
		int off = m->in_offset;
		if (m->in_op & FILE_OPINDIRECT) {
			st64 qoff = (st64)offset + off;
			if (!magic_hasbytes (nbytes, qoff, file_magic_type_bytes (m, m->in_type))) {
				return 0;
			}
			const union VALUETYPE *const q =
				((const void *) (s + (size_t)qoff));
			st32 qvalue;
			if (magic_get_indir_value (&qvalue, q, m->in_type)) {
				off = qvalue;
			}
		}
		if (!magic_hasbytes (nbytes, offset, file_magic_type_bytes (m, m->in_type))) {
			return 0;
		}
		st32 pvalue;
		if (magic_get_indir_value (&pvalue, p, m->in_type)) {
			off = apply_indir_op (pvalue, off, m->in_op);
		}
		if (off < 0) {
			return 0;
		}
		offset = (ut32)off;

		if (m->flag & INDIROFFADD) {
			st64 noff = (st64)offset + ms->c.li[cont_level - 1].off;
			if (noff < 0) {
				return 0;
			}
			offset = (ut32)noff;
		}
		if (mcopy (ms, p, m->type, 0, s, offset, nbytes, count) == -1) {
			return -1;
		}
		ms->offset = offset;

		magic_debug_dump (ms, m, offset, p);
	}

	/* Verify we have enough data to match magic type */
	if (m->type != FILE_DEFAULT && !magic_hasbytes (nbytes, offset, file_magic_type_bytes (m, m->type))) {
		return 0;
	}
	return mconvert (ms, m);
}

static ut64 file_strncmp(const char *s1, const char *s2, size_t len, ut32 flags) {
	// Compare unsigned bytes so ctype calls stay valid.
	const ut8 *a = (const ut8 *)s1;
	const ut8 *b = (const ut8 *)s2;
	ut64 v;

	// Match strncmp semantics, but ignore embedded NULs.
	v = 0;
	if (0L == flags) { /* normal string: do it fast */
		while (len-- > 0) {
			if ((v = *b++ - *a++) != '\0') {
				break;
			}
		}
	} else { /* combine the others */
		while (len-- > 0) {
			if ((flags & STRING_IGNORE_LOWERCASE) &&
				islower (*a)) {
				if ((v = tolower (*b++) - *a++) != '\0') {
					break;
				}
			} else if ((flags & STRING_IGNORE_UPPERCASE) && isupper (*a)) {
				if ((v = toupper (*b++) - *a++) != '\0') {
					break;
				}
			} else if ((flags & STRING_COMPACT_BLANK) && isspace (*a)) {
				a++;
				if (isspace (*b++)) {
					while (isspace (*b)) {
						b++;
					}
				} else {
					v = 1;
					break;
				}
			} else if ((flags & STRING_COMPACT_OPTIONAL_BLANK) && isspace (*a)) {
				a++;
				while (isspace (*b)) {
					b++;
				}
			} else {
				if ((v = *b++ - *a++) != '\0') {
					break;
				}
			}
		}
	}
	return v;
}

static int magiccheck(RMagic *ms, struct r_magic *m) {
	ut64 l = m->value.q;
	ut64 v;
	float fl, fv;
	double dl, dv;
	int matched;
	union VALUETYPE *const p = &ms->ms_value;

	switch (m->type) {
	case FILE_BYTE:
		v = p->b;
		break;
	case FILE_SHORT:
	case FILE_BESHORT:
	case FILE_LESHORT:
		v = p->h;
		break;
	case FILE_LONG:
	case FILE_BELONG:
	case FILE_LELONG:
	case FILE_MELONG:
	case FILE_DATE:
	case FILE_BEDATE:
	case FILE_LEDATE:
	case FILE_MEDATE:
	case FILE_LDATE:
	case FILE_BELDATE:
	case FILE_LELDATE:
	case FILE_MELDATE:
		v = p->l;
		break;
	case FILE_QUAD:
	case FILE_LEQUAD:
	case FILE_BEQUAD:
	case FILE_QDATE:
	case FILE_BEQDATE:
	case FILE_LEQDATE:
	case FILE_QLDATE:
	case FILE_BEQLDATE:
	case FILE_LEQLDATE:
		v = p->q;
		break;
	case FILE_FLOAT:
	case FILE_BEFLOAT:
	case FILE_LEFLOAT:
		fl = m->value.f;
		fv = p->f;
		switch (m->reln) {
		case 'x': matched = 1; break;
		case '!': matched = fv != fl; break;
		case '=': matched = fv == fl; break;
		case '>': matched = fv > fl; break;
		case '<': matched = fv < fl; break;
		default:
			__magic_file_magerror (ms, "cannot happen with float: invalid relation `%c'", m->reln);
			return -1;
		}
		return matched;
	case FILE_DOUBLE:
	case FILE_BEDOUBLE:
	case FILE_LEDOUBLE:
		dl = m->value.d;
		dv = p->d;
		switch (m->reln) {
		case 'x': matched = 1; break;
		case '!': matched = dv != dl; break;
		case '=': matched = dv == dl; break;
		case '>': matched = dv > dl; break;
		case '<': matched = dv < dl; break;
		default:
			__magic_file_magerror (ms, "cannot happen with double: invalid relation `%c'", m->reln);
			return -1;
		}
		return matched;
	case FILE_DEFAULT:
		l = 0;
		v = 0;
		break;
	case FILE_STRING:
	case FILE_PSTRING:
	case FILE_BESTRING16:
	case FILE_LESTRING16:
		l = 0;
		v = file_strncmp (m->value.s, p->s, (size_t)m->vallen, file_magic_type_is_string16 (m->type)? 0: m->str_flags);
		break;
	case FILE_SEARCH: { /* search ms->search.s for the string m->value.s */
		size_t idx;

		if (!ms->search.s) {
			return 0;
		}

		const size_t slen = R_MIN (m->vallen, sizeof (m->value.s));
		l = 0;
		v = 0;

		for (idx = 0; m->str_range == 0 || idx < m->str_range; idx++) {
			if (slen > ms->search.s_len || idx > ms->search.s_len - slen) {
				break;
			}
			v = file_strncmp (m->value.s, ms->search.s + idx, slen, m->str_flags);
			if (v == 0) { /* found match */
				ms->search.offset += idx;
				break;
			}
		}
		break;
	}
	case FILE_REGEX:
		{
			int rc;
			RRegex rx = { 0 };
			char *errmsg;

			if (!ms->search.s) {
				return 0;
			}

			l = 0;
			rc = r_regex_init (&rx, m->value.s, R_REGEX_EXTENDED | R_REGEX_NEWLINE | ((m->str_flags & STRING_IGNORE_CASE)? R_REGEX_ICASE: 0));
			if (rc) {
				errmsg = r_regex_error (&rx, rc);
				__magic_file_magerror (ms, "regex error %d, (%s)", rc, errmsg);
				free (errmsg);
				v = (ut64)-1;
			} else {
				RRegexMatch pmatch[1];
#ifndef R_REGEX_STARTEND
#define R_REGEX_STARTEND 0
				size_t l = ms->search.s_len - 1;
				char c = ms->search.s[l];
				((char *) (intptr_t)ms->search.s)[l] = '\0';
#else
				pmatch[0].rm_so = 0;
				pmatch[0].rm_eo = ms->search.s_len;
#endif
				rc = r_regex_exec (&rx, (const char *)ms->search.s, 1, pmatch, R_REGEX_STARTEND);
#if R_REGEX_STARTEND == 0
				((char *) (intptr_t)ms->search.s)[l] = c;
#endif
				switch (rc) {
				case 0:
					ms->search.s += (int)pmatch[0].rm_so;
					ms->search.offset += (size_t)pmatch[0].rm_so;
					ms->search.rm_len = (size_t) (pmatch[0].rm_eo - pmatch[0].rm_so);
					v = 0;
					break;
				case R_REGEX_NOMATCH:
					v = 1;
					break;
				default:
					errmsg = r_regex_error (&rx, rc);
					__magic_file_magerror (ms, "regexec error %d, (%s)", rc, errmsg);
					free (errmsg);
					v = UT64_MAX;
					break;
				}
				r_regex_fini (&rx);
			}
			if (v == (ut64)-1) {
				return -1;
			}
			break;
		}
	default:
		__magic_file_magerror (ms, "invalid type %d in magiccheck()", m->type);
		return -1;
	}

	v = __magic_file_signextend (ms, m, v);
	switch (m->reln) {
	case 'x':
		magic_debug (ms, "%" PFMT64u " == *any* = 1", (ut64)v);
		matched = 1;
		break;
	case '!':
		matched = v != l;
		magic_debug (ms, "%" PFMT64u " != %" PFMT64u " = %d", (ut64)v, (ut64)l, matched);
		break;
	case '=':
		matched = v == l;
		magic_debug (ms, "%" PFMT64u " == %" PFMT64u " = %d", (ut64)v, (ut64)l, matched);
		break;
	case '>':
		if (m->flag & UNSIGNED) {
			matched = v > l;
			magic_debug (ms, "%" PFMT64u " > %" PFMT64u " = %d", (ut64)v, (ut64)l, matched);
		} else {
			matched = (ut64)v > (ut64)l;
			magic_debug (ms, "%" PFMT64u " > %" PFMT64u " = %d", (st64)v, (st64)l, matched);
		}
		break;
	case '<':
		if (m->flag & UNSIGNED) {
			matched = v < l;
			magic_debug (ms, "%" PFMT64u " < %" PFMT64u " = %d", (ut64)v, (ut64)l, matched);
		} else {
			matched = (ut64)v < (ut64)l;
			magic_debug (ms, "%" PFMT64d " < %" PFMT64d " = %d", (st64)v, (st64)l, matched);
		}
		break;
	case '&':
		matched = (v & l) == l;
		magic_debug (ms, "((%" PFMT64x " & %" PFMT64x ") == %" PFMT64x ") = %d", (ut64)v, (ut64)l, (ut64)l, matched);
		break;
	case '^':
		matched = (v & l) != l;
		magic_debug (ms, "((%" PFMT64x " & %" PFMT64x ") != %" PFMT64x ") = %d", (ut64)v, (ut64)l, (ut64)l, matched);
		break;
	default:
		__magic_file_magerror (ms, "cannot happen: invalid relation `%c'", m->reln);
		return -1;
	}
	return matched;
}

static int print_sep(RMagic *ms, int firstline) {
	return firstline? 0: __magic_file_printf (ms, "\n- ");
}

/*
 * Go through the whole list, stopping if you find a match.  Process all
 * the continuations of that match before returning.
 *
 * We support multi-level continuations:
 *
 *	At any time when processing a successful top-level match, there is a
 *	current continuation level; it represents the level of the last
 *	successfully matched continuation.
 *
 *	Continuations above that level are skipped as, if we see one, it
 *	means that the continuation that controls them - i.e, the
 *	lower-level continuation preceding them - failed to match.
 *
 *	Continuations below that level are processed as, if we see one,
 *	it means we've finished processing or skipping higher-level
 *	continuations under the control of a successful or unsuccessful
 *	lower-level continuation, and are now seeing the next lower-level
 *	continuation and should process it.  The current continuation
 *	level reverts to the level of the one we're seeing.
 *
 *	Continuations at the current level are processed as, if we see
 *	one, there's no lower-level continuation that may have failed.
 *
 *	If a continuation matches, we bump the current continuation level
 *	so that higher-level continuations are processed.
 */
static int match(RMagic *ms, struct r_magic *magic, ut32 nmagic, const ut32 *min_bytes, const ut8 *s, size_t nbytes, int mode) {
	ut32 magindex = 0;
	unsigned int cont_level = 0;
	int need_separator = 0;
	int returnval = 0; /* if a match is found it is set to 1*/
	int firstline = 1; /* a flag to print X\n  X\n- X */
	int printed_something = 0;

	if (__magic_file_check_mem (ms, cont_level) == -1) {
		return -1;
	}
	for (magindex = 0; magindex < nmagic; magindex++) {
		int flush;
		struct r_magic *m = &magic[magindex];

		if ((m->flag & BINTEST) != mode) {
			/* Skip sub-tests */
			while (magic[magindex + 1].cont_level != 0 && ++magindex < nmagic - 1) {
				continue;
			}
			continue; /* Skip to next top-level test*/
		}
		if (min_bytes && min_bytes[magindex] > nbytes) {
			while (magindex < nmagic - 1 && magic[magindex + 1].cont_level) {
				magindex++;
			}
			continue;
		}

		ms->offset = m->offset;
		ms->line = m->lineno;

		/* if main entry matches, print it... */
		flush = !mget (ms, s, m, nbytes, cont_level);
		if (flush) {
			if (m->reln == '!') {
				flush = 0;
			}
		} else {
			int ret = magiccheck (ms, m);
			if (ret == -1) {
				return -1;
			}
			if (!ret) {
				flush++;
			}
		}
		if (flush) {
			// Main test failed, so skip its continuations.
			while (magindex < nmagic - 1 && magic[magindex + 1].cont_level) {
				magindex++;
			}
			continue;
		}

		// Track whether later output needs a separator.
		if (*R_MAGIC_DESC) {
			need_separator = 1;
			printed_something = 1;
			if (print_sep (ms, firstline) == -1) {
				return -1;
			}
		}

		if ((ms->c.li[cont_level].off = mprint (ms, m)) == -1) {
			return -1;
		}

		/* and any continuations that match */
		if (__magic_file_check_mem (ms, ++cont_level) == -1) {
			return -1;
		}

		while (++magindex < nmagic - 1 && magic[magindex].cont_level != 0) {
			m = &magic[magindex];
			ms->line = m->lineno; /* for messages */

			if (cont_level < m->cont_level) {
				continue;
			}
			if (cont_level > m->cont_level) {
				// Drop back to the current continuation level.
				cont_level = m->cont_level;
			}
			ms->offset = m->offset;
			if (m->flag & OFFADD) {
				ms->offset += ms->c.li[cont_level - 1].off;
			}

			if (m->cond == COND_ELSE || m->cond == COND_ELIF) {
				if (ms->c.li[cont_level].last_match == 1) {
					continue;
				}
			}
			if (min_bytes && min_bytes[magindex] > nbytes) {
				continue;
			}
			flush = !mget (ms, s, m, nbytes, cont_level);
			if (flush && m->reln != '!') {
				continue;
			}

			switch (flush? 1: magiccheck (ms, m)) {
			case -1:
				return -1;
			case 0:
				ms->c.li[cont_level].last_match = 0;
				break;
			default:
				ms->c.li[cont_level].last_match = 1;
				if (m->type != FILE_DEFAULT) {
					ms->c.li[cont_level].got_match = 1;
				} else if (ms->c.li[cont_level].got_match) {
					ms->c.li[cont_level].got_match = 0;
					break;
				}
				// Print any required separator before this message.
				if (*R_MAGIC_DESC) {
					printed_something = 1;
					if (print_sep (ms, firstline) == -1) {
						return -1;
					}
				}
				/* space if previous printed */
				if (need_separator && ((m->flag & NOSPACE) == 0) && *R_MAGIC_DESC) {
					if (__magic_file_printf (ms, " ") == -1) {
						return -1;
					}
					need_separator = 0;
				}
				if ((ms->c.li[cont_level].off = mprint (ms, m)) == -1) {
					return -1;
				}
				if (*R_MAGIC_DESC) {
					need_separator = 1;
				}

				// Process any deeper continuations.
				if (__magic_file_check_mem (ms, ++cont_level) == -1) {
					return -1;
				}
				break;
			}
		}
		if (printed_something) {
			firstline = 0;
			returnval = 1;
		}
		if ((ms->flags & R_MAGIC_CONTINUE) == 0 && printed_something) {
			return 1; /* don't keep searching */
		}
	}
	return returnval; /* This is hit if -k is set or there is no match */
}

/*
 * softmagic - lookup one file in parsed, in-memory copy of database
 * Passed the name and FILE * of one file to be typed.
 */
/*ARGSUSED1*/ /* nbytes passed for regularity, maybe need later */
int __magic_file_softmagic(RMagic *ms, const ut8 *buf, size_t nbytes, int mode) {
	struct mlist *ml;
	int rv;
	R_VEC_FOREACH (&ms->mlist, ml) {
		if ((rv = match (ms, ml->magic, ml->nmagic, ml->min_bytes, buf, nbytes, mode)) != 0) {
			return rv;
		}
	}
	return 0;
}
#endif
