/*	$OpenBSD: ascmagic.c,v 1.11 2009/10/27 23:59:37 deraadt Exp $ */
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
 * ASCII magic -- file types that we know based on keywords
 * that can appear anywhere in the file.
 *
 * Extensively modified by Eric Fischer <enf@pobox.com> in July, 2000,
 * to handle character codes other than ASCII on a unified basis.
 *
 * Joerg Wunsch <joerg@freebsd.org> wrote the original support for 8-bit
 * international characters, now subsumed into this file.
 */
#include <r_userconf.h>
#include <r_util.h>

/*
 * This table maps each EBCDIC character to an (8-bit extended) ASCII
 * character, as specified in the rationale for the dd (1) command in
 * draft 11.2 (September, 1991) of the POSIX P1003.2 standard.
 *
 * Unfortunately it does not seem to correspond exactly to any of the
 * five variants of EBCDIC documented in IBM's _Enterprise Systems
 * Architecture/390: Principles of Operation_, SA22-7201-06, Seventh
 * Edition, July, 1999, pp. I-1 - I-4.
 *
 * Fortunately, though, all versions of EBCDIC, including this one, agree
 * on most of the printing characters that also appear in (7-bit) ASCII.
 * Of these, only '|', '!', '~', '^', '[', and ']' are in question at all.
 *
 * Fortunately too, there is general agreement that codes 0x00 through
 * 0x3F represent control characters, 0x41 a nonbreaking space, and the
 * remainder printing characters.
 *
 * This is sufficient to allow us to identify EBCDIC text and to distinguish
 * between old-style and internationalized examples of text.
 */

// clang-format off
static ut8 ebcdic_to_ascii[] = {
0,   1,   2,   3, 156,   9, 134, 127, 151, 141, 142,  11,  12,  13,  14,  15,
16,  17,  18,  19, 157, 133,   8, 135,  24,  25, 146, 143,  28,  29,  30,  31,
128, 129, 130, 131, 132,  10,  23,  27, 136, 137, 138, 139, 140,   5,   6,   7,
144, 145,  22, 147, 148, 149, 150,   4, 152, 153, 154, 155,  20,  21, 158,  26,
' ', 160, 161, 162, 163, 164, 165, 166, 167, 168, 213, '.', '<', '(', '+', '|',
'&', 169, 170, 171, 172, 173, 174, 175, 176, 177, '!', '$', '*', ')', ';', '~',
'-', '/', 178, 179, 180, 181, 182, 183, 184, 185, 203, ',', '%', '_', '>', '?',
186, 187, 188, 189, 190, 191, 192, 193, 194, '`', ':', '#', '@', '\'','=', '"',
195, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 196, 197, 198, 199, 200, 201,
202, 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '^', 204, 205, 206, 207, 208,
209, 229, 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 210, 211, 212, '[', 214, 215,
216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, ']', 230, 231,
'{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 232, 233, 234, 235, 236, 237,
'}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 238, 239, 240, 241, 242, 243,
'\\',159, 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 244, 245, 246, 247, 248, 249,
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 250, 251, 252, 253, 254, 255
};

// clang-format off
/*
 * Copy buf[0 ... nbytes-1] into out[], translating EBCDIC to ASCII.
 */
R_API void r_magic_from_ebcdic(const ut8 *buf, size_t nbytes, ut8 *out) {
	size_t i;
	for (i = 0; i < nbytes; i++) {
		out[i] = ebcdic_to_ascii[buf[i]];
	}
}

#if !USE_LIB_MAGIC

#include "file.h"
#include "names.h"

R_IPI int __magic_file_looks_utf8(const ut8 *, size_t, unichar *, size_t *);
R_API void r_magic_from_ebcdic(const ut8 *, size_t, ut8 *);

/*
 * This table reflects a particular philosophy about what constitutes
 * "text," and there is room for disagreement about it.
 *
 * Version 3.31 of the file command considered a file to be ASCII if
 * each of its characters was approved by either the isascii () or
 * isalpha () function.  On most systems, this would mean that any
 * file consisting only of characters in the range 0x00 ... 0x7F
 * would be called ASCII text, but many systems might reasonably
 * consider some characters outside this range to be alphabetic,
 * so the file command would call such characters ASCII.  It might
 * have been more accurate to call this "considered textual on the
 * local system" than "ASCII."
 *
 * It considered a file to be "International language text" if each
 * of its characters was either an ASCII printing character (according
 * to the real ASCII standard, not the above test), a character in
 * the range 0x80 ... 0xFF, or one of the following control characters:
 * backspace, tab, line feed, vertical tab, form feed, carriage return,
 * escape.  No attempt was made to determine the language in which files
 * of this type were written.
 *
 *
 * The table below considers a file to be ASCII if all of its characters
 * are either ASCII printing characters (again, according to the X3.4
 * standard, not isascii ()) or any of the following controls: bell,
 * backspace, tab, line feed, form feed, carriage return, esc, nextline.
 *
 * I include bell because some programs (particularly shell scripts)
 * use it literally, even though it is rare in normal text.  I exclude
 * vertical tab because it never seems to be used in real text.  I also
 * include, with hesitation, the X3.64/ECMA-43 control nextline (0x85),
 * because that's what the dd EBCDIC->ASCII table maps the EBCDIC newline
 * character to.  It might be more appropriate to include it in the 8859
 * set instead of the ASCII set, but it's got to be included in *something*
 * we recognize or EBCDIC files aren't going to be considered textual.
 * Some old Unix source files use SO/SI (^N/^O) to shift between Greek
 * and Latin characters, so these should possibly be allowed.  But they
 * make a real mess on VT100-style displays if they're not paired properly,
 * so we are probably better off not calling them text.
 *
 * A file is considered to be ISO-8859 text if its characters are all
 * either ASCII, according to the above definition, or printing characters
 * from the ISO-8859 8-bit extension, characters 0xA0 ... 0xFF.
 *
 * Finally, a file is considered to be international text from some other
 * character code if its characters are all either ISO-8859 (according to
 * the above definition) or characters in the range 0x80 ... 0x9F, which
 * ISO-8859 considers to be control characters but the IBM PC and Macintosh
 * consider to be printing characters.
 */

#define F 0   /* character never appears in text */
#define T 1   /* character appears in plain ASCII text */
#define I 2   /* character appears in ISO-8859 text */
#define X 3   /* character appears in non-ISO extended ASCII(Mac, IBM PC) */

static char text_chars[256] = {
	/*                  BEL BS HT LF    FF CR    */
	F, F, F, F, F, F, F, T, T, T, T, F, T, T, F, F,  /* 0x0X */
	/*                              ESC          */
	F, F, F, F, F, F, F, F, F, F, F, T, F, F, F, F,  /* 0x1X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x2X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x3X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x4X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x5X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,  /* 0x6X */
	T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, F,  /* 0x7X */
	/*            NEL                            */
	X, X, X, X, X, T, X, X, X, X, X, X, X, X, X, X,  /* 0x8X */
	X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,  /* 0x9X */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xaX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xbX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xcX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xdX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,  /* 0xeX */
	I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I   /* 0xfX */
};

/*
 * Decide whether some text looks like UTF-8. Returns:
 *
 *     -1: invalid UTF-8
 *      0: uses odd control characters, so doesn't look like text
 *      1: 7-bit text
 *      2: definitely UTF-8 text (valid high-bit set bytes)
 *
 * If ubuf is non-NULL on entry, text is decoded into ubuf, *ulen;
 * ubuf must be big enough!
 */
R_IPI int __magic_file_looks_utf8(const ut8 *buf, size_t nbytes, unichar *ubuf, size_t *ulen) {
	size_t i;
	int n;
	unichar c;
	int gotone = 0, ctrl = 0;
	bool done = false;

	if (ubuf) {
		*ulen = 0;
	}

	for (i = 0; i < nbytes && !done; i++) {
		if ((buf[i] & 0x80) == 0) {	   /* 0xxxxxxx is plain ASCII */
			// Reject valid UTF-8 that still uses control characters.
			if (text_chars[buf[i]] != T) {
				ctrl = 1;
			}
			if (ubuf) {
				ubuf[(*ulen)++] = buf[i];
			}
		} else if ((buf[i] & 0x40) == 0) { /* 10xxxxxx never 1st byte */
			return -1;
		} else {			   /* 11xxxxxx begins UTF-8 */
			int following;

			if ((buf[i] & 0x20) == 0) {		/* 110xxxxx */
				c = buf[i] & 0x1f;
				following = 1;
			} else if ((buf[i] & 0x10) == 0) {	/* 1110xxxx */
				c = buf[i] & 0x0f;
				following = 2;
			} else if ((buf[i] & 0x08) == 0) {	/* 11110xxx */
				c = buf[i] & 0x07;
				following = 3;
			} else if ((buf[i] & 0x04) == 0) {	/* 111110xx */
				c = buf[i] & 0x03;
				following = 4;
			} else if ((buf[i] & 0x02) == 0) {	/* 1111110x */
				c = buf[i] & 0x01;
				following = 5;
			} else {
				return -1;
			}
			for (n = 0; n < following; n++) {
				i++;
				if (i >= nbytes) {
					done = true;
					break;
				}

				if ((buf[i] & 0x80) == 0 || (buf[i] & 0x40)) {
					return -1;
				}

				c = (c << 6) + (buf[i] & 0x3f);
			}
			if (ubuf) {
				ubuf[(*ulen)++] = c;
			}
			gotone = 1;
		}
	}
	return ctrl? 0: (gotone? 2: 1);
}

#undef F
#undef T
#undef I
#undef X

#endif
