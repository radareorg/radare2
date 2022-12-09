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
#ifndef js_utf_h
#define js_utf_h

typedef int Rune;	/* 32 bits */

#define chartorune	jsU_chartorune
#define runetochar	jsU_runetochar
#define runelen		jsU_runelen
#define utflen		jsU_utflen

#define isalpharune	jsU_isalpharune
#define islowerrune	jsU_islowerrune
#define isupperrune	jsU_isupperrune
#define tolowerrune	jsU_tolowerrune
#define toupperrune	jsU_toupperrune

enum
{
	UTFmax		= 4,		/* maximum bytes per rune */
	Runesync	= 0x80,		/* cannot represent part of a UTF sequence (<) */
	Runeself	= 0x80,		/* rune and UTF sequences are the same (<) */
	Runeerror	= 0xFFFD,	/* decoding error in UTF */
	Runemax		= 0x10FFFF,	/* maximum rune value */
};

int	chartorune(Rune *rune, const char *str);
int	runetochar(char *str, const Rune *rune);
int	runelen(int c);
int	utflen(const char *s);

int		isalpharune(Rune c);
int		islowerrune(Rune c);
int		isupperrune(Rune c);
Rune		tolowerrune(Rune c);
Rune		toupperrune(Rune c);

#endif
