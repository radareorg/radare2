/*
 * The authors of this software are Rob Pike and Ken Thompson.
 *              Copyright (c) 2002 by Lucent Technologies.
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR LUCENT TECHNOLOGIES MAKE
 * ANY REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */
#include <stdlib.h>
#include <string.h>

#include "utf.h"
#include "utfdata.h"

#define nelem(a) (int)(sizeof (a) / sizeof (a)[0])

typedef unsigned char uchar;

enum
{
	Bit1	= 7,
	Bitx	= 6,
	Bit2	= 5,
	Bit3	= 4,
	Bit4	= 3,
	Bit5	= 2,

	T1	= ((1<<(Bit1+1))-1) ^ 0xFF,	/* 0000 0000 */
	Tx	= ((1<<(Bitx+1))-1) ^ 0xFF,	/* 1000 0000 */
	T2	= ((1<<(Bit2+1))-1) ^ 0xFF,	/* 1100 0000 */
	T3	= ((1<<(Bit3+1))-1) ^ 0xFF,	/* 1110 0000 */
	T4	= ((1<<(Bit4+1))-1) ^ 0xFF,	/* 1111 0000 */
	T5	= ((1<<(Bit5+1))-1) ^ 0xFF,	/* 1111 1000 */

	Rune1	= (1<<(Bit1+0*Bitx))-1,		/* 0000 0000 0000 0000 0111 1111 */
	Rune2	= (1<<(Bit2+1*Bitx))-1,		/* 0000 0000 0000 0111 1111 1111 */
	Rune3	= (1<<(Bit3+2*Bitx))-1,		/* 0000 0000 1111 1111 1111 1111 */
	Rune4	= (1<<(Bit4+3*Bitx))-1,		/* 0001 1111 1111 1111 1111 1111 */

	Maskx	= (1<<Bitx)-1,			/* 0011 1111 */
	Testx	= Maskx ^ 0xFF,			/* 1100 0000 */

	Bad	= Runeerror
};

int
chartorune(Rune *rune, const char *str)
{
	int c, c1, c2, c3;
	int l;

	/* overlong null character */
	if((uchar)str[0] == 0xc0 && (uchar)str[1] == 0x80) {
		*rune = 0;
		return 2;
	}

	/*
	 * one character sequence
	 *	00000-0007F => T1
	 */
	c = *(uchar*)str;
	if(c < Tx) {
		*rune = c;
		return 1;
	}

	/*
	 * two character sequence
	 *	0080-07FF => T2 Tx
	 */
	c1 = *(uchar*)(str+1) ^ Tx;
	if(c1 & Testx)
		goto bad;
	if(c < T3) {
		if(c < T2)
			goto bad;
		l = ((c << Bitx) | c1) & Rune2;
		if(l <= Rune1)
			goto bad;
		*rune = l;
		return 2;
	}

	/*
	 * three character sequence
	 *	0800-FFFF => T3 Tx Tx
	 */
	c2 = *(uchar*)(str+2) ^ Tx;
	if(c2 & Testx)
		goto bad;
	if(c < T4) {
		l = ((((c << Bitx) | c1) << Bitx) | c2) & Rune3;
		if(l <= Rune2)
			goto bad;
		*rune = l;
		return 3;
	}

	/*
	 * four character sequence
	 *	10000-10FFFF => T4 Tx Tx Tx
	 */
	if(UTFmax >= 4) {
		c3 = *(uchar*)(str+3) ^ Tx;
		if(c3 & Testx)
			goto bad;
		if(c < T5) {
			l = ((((((c << Bitx) | c1) << Bitx) | c2) << Bitx) | c3) & Rune4;
			if(l <= Rune3)
				goto bad;
			if(l > Runemax)
				goto bad;
			*rune = l;
			return 4;
		}
	}

	/*
	 * bad decoding
	 */
bad:
	*rune = Bad;
	return 1;
}

int
runetochar(char *str, const Rune *rune)
{
	int c = *rune;

	/* overlong null character */
	if (c == 0) {
		str[0] = (char)0xc0;
		str[1] = (char)0x80;
		return 2;
	}

	/*
	 * one character sequence
	 *	00000-0007F => 00-7F
	 */
	if(c <= Rune1) {
		str[0] = c;
		return 1;
	}

	/*
	 * two character sequence
	 *	00080-007FF => T2 Tx
	 */
	if(c <= Rune2) {
		str[0] = T2 | (c >> 1*Bitx);
		str[1] = Tx | (c & Maskx);
		return 2;
	}

	/*
	 * three character sequence
	 *	00800-0FFFF => T3 Tx Tx
	 */
	if(c > Runemax)
		c = Runeerror;
	if(c <= Rune3) {
		str[0] = T3 |  (c >> 2*Bitx);
		str[1] = Tx | ((c >> 1*Bitx) & Maskx);
		str[2] = Tx |  (c & Maskx);
		return 3;
	}

	/*
	 * four character sequence
	 *	010000-1FFFFF => T4 Tx Tx Tx
	 */
	str[0] = T4 |  (c >> 3*Bitx);
	str[1] = Tx | ((c >> 2*Bitx) & Maskx);
	str[2] = Tx | ((c >> 1*Bitx) & Maskx);
	str[3] = Tx |  (c & Maskx);
	return 4;
}

int
runelen(int c)
{
	Rune rune;
	char str[10];

	rune = c;
	return runetochar(str, &rune);
}

int
utflen(const char *s)
{
	int c;
	int n;
	Rune rune;

	n = 0;
	for(;;) {
		c = *(uchar*)s;
		if(c < Runeself) {
			if(c == 0)
				return n;
			s++;
		} else
			s += chartorune(&rune, s);
		n++;
	}
}

static const Rune *
ucd_bsearch(Rune c, const Rune *t, int n, int ne)
{
	const Rune *p;
	int m;

	while(n > 1) {
		m = n/2;
		p = t + m*ne;
		if(c >= p[0]) {
			t = p;
			n = n-m;
		} else
			n = m;
	}
	if(n && c >= t[0])
		return t;
	return 0;
}

Rune
tolowerrune(Rune c)
{
	const Rune *p;

	p = ucd_bsearch(c, ucd_tolower2, nelem(ucd_tolower2)/3, 3);
	if(p && c >= p[0] && c <= p[1])
		return c + p[2];
	p = ucd_bsearch(c, ucd_tolower1, nelem(ucd_tolower1)/2, 2);
	if(p && c == p[0])
		return c + p[1];
	return c;
}

Rune
toupperrune(Rune c)
{
	const Rune *p;

	p = ucd_bsearch(c, ucd_toupper2, nelem(ucd_toupper2)/3, 3);
	if(p && c >= p[0] && c <= p[1])
		return c + p[2];
	p = ucd_bsearch(c, ucd_toupper1, nelem(ucd_toupper1)/2, 2);
	if(p && c == p[0])
		return c + p[1];
	return c;
}

int
islowerrune(Rune c)
{
	const Rune *p;

	p = ucd_bsearch(c, ucd_toupper2, nelem(ucd_toupper2)/3, 3);
	if(p && c >= p[0] && c <= p[1])
		return 1;
	p = ucd_bsearch(c, ucd_toupper1, nelem(ucd_toupper1)/2, 2);
	if(p && c == p[0])
		return 1;
	return 0;
}

int
isupperrune(Rune c)
{
	const Rune *p;

	p = ucd_bsearch(c, ucd_tolower2, nelem(ucd_tolower2)/3, 3);
	if(p && c >= p[0] && c <= p[1])
		return 1;
	p = ucd_bsearch(c, ucd_tolower1, nelem(ucd_tolower1)/2, 2);
	if(p && c == p[0])
		return 1;
	return 0;
}

int
isalpharune(Rune c)
{
	const Rune *p;

	p = ucd_bsearch(c, ucd_alpha2, nelem(ucd_alpha2)/2, 2);
	if(p && c >= p[0] && c <= p[1])
		return 1;
	p = ucd_bsearch(c, ucd_alpha1, nelem(ucd_alpha1), 1);
	if(p && c == p[0])
		return 1;
	return 0;
}
