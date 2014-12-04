/* 2012 - pancake@nopcode.org - radare2 integration */
/* Z80 assembler by shevek

   Copyright (C) 2002-2009 Bas Wijnen <wijnen@debian.org>
   Copyright (C) 2005 Jan Wilmans <jw@dds.nl>

   This file is part of z80asm.

   Z80asm is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Z80asm is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef R_API_I
#define R_API_I
#endif
#include "z80asm.h"

/* hack */
// must remove: equ, include, incbin, macro
//static void wrt_ref (int val, int type, int count);
static unsigned char *obuf;
static int obuflen = 0;
#define write_one_byte(x,y) obuf[obuflen++] = x
#define wrtb(x) obuf[obuflen++] = x

/* global variables */
/* mnemonics, used as argument to indx() in assemble */
static const char *mnemonics[] = {
	"call", "cpdr", "cpir", "djnz", "halt", "indr", "inir", "lddr", "ldir",
	"otdr", "otir", "outd", "outi", "push", "reti", "retn", "rlca", "rrca",
	"defb", "defw", "defs", "defm",
	"adc", "add", "and", "bit", "ccf", "cpd", "cpi", "cpl", "daa", "dec", "equ",
	"exx", "inc", "ind", "ini", "ldd", "ldi", "neg", "nop", "out", "pop",
	"res", "ret", "rla", "rlc", "rld", "rra", "rrc", "rrd", "rst", "sbc",
	"scf", "set", "sla", "sll", "sli", "sra", "srl", "sub", "xor", "org",
	"cp", "di", "ei", "ex", "im", "in", "jp", "jr", "ld", "or", "rl", "rr",
	"db", "dw", "ds", "dm",
	"include", "incbin", "if", "else", "endif", "end", "macro", "endm",
	"seek", NULL
};

/* number of errors seen so far */
static int errors = 0;

/* current line, address and file */
static int addr = 0, file;
/* current number of characters in list file, for indentation */
//static int listdepth;

/* use readbyte instead of (hl) if writebyte is true */
static int writebyte;
static const char *readbyte;
/* variables which are filled by rd_* functions and used later,
 * like readbyte */
static const char *readword, *indexjmp, *bitsetres;

/* 0, 0xdd or 0xfd depening on which index prefix should be given */
static int indexed;

/* increased for every -v option on the command line */
static int verbose = 0;

/* read commas after indx() if comma > 1. increase for every call */
static int comma;

/* address at start of line (for references) */
static int baseaddr;

/* set by readword and readbyte, used for new_reference */
static char mem_delimiter;

/* line currently being parsed */
static char *z80buffer = NULL;

/* if a macro is currently being defined */
static int define_macro = 0;

/* file (and macro) stack */
static int sp;
static struct stack stack[MAX_INCLUDE];	/* maximum level of includes */

/* hack */
#include "expressions.c"

/* print an error message, including current line and file */
static void printerr (int error, const char *fmt, ...) {
	va_list l;
	va_start (l, fmt);
	if ((sp < 0) || (stack[sp].name == 0)) {
		fprintf (stderr, "internal assembler error, sp == %i\n", sp);
		vfprintf (stderr, fmt, l);
		exit (2);
	}
	fprintf (stderr, "%s%s:%d: %s: ", stack[sp].dir ? stack[sp].dir->name : "",
			stack[sp].name, stack[sp].line, error ? "error" : "warning");
	vfprintf (stderr, fmt, l);
	va_end (l);
	if (error)
		errors++;
}

/* skip over spaces in string */
static const char * delspc (const char *ptr) {
	while (*ptr && isspace ((const unsigned char)*ptr))
		ptr++;
	if (*ptr == ';')
		ptr = "";
	return ptr;
}

/* read away a comma, error if there is none */
static void rd_comma (const char **p) {
	*p = delspc (*p);
	if (**p != ',') {
		printerr (1, "`,' expected. Remainder of line: %s\n", *p);
		return;
	}
	*p = delspc ((*p) + 1);
}

/* look ahead for a comma, no error if not found */
static int has_argument (const char **p) {
	const char *q = delspc (*p);
	return (*q == ',');
}

/* During assembly, many literals are not parsed.  Instead, they are saved
 * until all labels are read.  After that, they are parsed.  This function
 * is used during assembly, to find the place where the command continues. */
static void skipword (const char **pos, char delimiter) {
	/* rd_expr will happily read the expression, and possibly return
	 * an invalid result.  It will update pos, which is what we need.  */
	/* Pass valid to allow using undefined labels without errors.  */
	int valid;
	rd_expr (pos, delimiter, &valid, sp, 0);
}

/* find any of the list[] entries as the start of ptr and return index */
static int indx (const char **ptr, const char **list, int error, const char **expr) {
	int i;
	*ptr = delspc (*ptr);
	if (!**ptr) {
		if (error) {
			printerr (1, "unexpected end of line\n");
			return 0;
		} else return 0;
	}
	if (comma > 1)
		rd_comma (ptr);
	for (i = 0; list[i]; i++) {
		const char *input = *ptr;
		const char *check = list[i];
		int had_expr = 0;
		if (!list[i][0])
			continue;
		while (*check) {
			if (*check == ' ') {
				input = delspc (input);
			} else if (*check == '*') {
				*expr = input;
				mem_delimiter = check[1];
				rd_expr (&input, mem_delimiter, NULL, sp, 0);
				had_expr = 1;
			} else if (*check == '+') {
				if (*input == '+' || *input == '-') {
					*expr = input;
					mem_delimiter = check[1];
					rd_expr (&input, mem_delimiter, NULL, sp, 0);
				}
			} else if (*check == *input || (*check >= 'a' && *check <= 'z'
						&& *check - 'a' + 'A' == *input))
				++input;
			else break;

			++check;
		}
		if (*check || (isalnum ((const unsigned char)check[-1]) && isalnum ((const unsigned char)input[0])))
			continue;
		if (had_expr) {
			input = delspc (input);
			if (*input && *input != ',')
				continue;
		}
		*ptr = input;
		comma++;
		return i + 1;
	}
	if (error)
		printerr (1, "parse error. Remainder of line=%s\n", *ptr);
	return 0;
}

/* read a mnemonic */
static int readcommand (const char **p) {
	return indx (p, mnemonics, 0, NULL);
}

/* try to read a label and optionally store it in the list */
static void readlabel (const char **p, int store) {
	const char *c, *d, *pos, *dummy;
	int i, j;
	struct label *buf, *previous, **thefirstlabel = NULL;
	for (d = *p; *d && *d != ';'; ++d);
	for (c = *p; !strchr (" \r\n\t", *c) && c < d; ++c);
	pos = strchr (*p, ':');
	if (!pos || pos >= c)
		return;
	if (pos == *p) {
		printerr (1, "`:' found without a label");
		return;
	}
	if (!store) {
		*p = pos + 1;
		return;
	}
	c = pos + 1;
	dummy = *p;
	j = rd_label (&dummy, &i, &previous, sp, 0);
	if (i || j) {
		printerr (1, "duplicate definition of label %s\n", *p);
		*p = c;
		return;
	}
	if (NULL == (buf = malloc (sizeof (struct label) + c - *p))) {
		printerr (1, "not enough memory to store label %s\n", *p);
		*p = c;
		return;
	}
	strncpy (buf->name, *p, c - *p - 1);
	buf->name[c - *p - 1] = 0;
	*p = c;
	buf->value = addr;
	//lastlabel = buf;
	if (previous)
		buf->next = previous->next;
	else buf->next = *thefirstlabel;
	buf->prev = previous;
	buf->valid = 1;
	buf->busy = 0;
	buf->ref = NULL;
	if (buf->prev)
		buf->prev->next = buf;
	else *thefirstlabel = buf;
	if (buf->next)
		buf->next->prev = buf;
}

static int compute_ref (struct reference *ref, int allow_invalid) {
	const char *ptr;
	int valid = 0;
	int backup_addr = addr;
	int backup_baseaddr = baseaddr;
	int backup_comma = comma;
	int backup_file = file;
	int backup_sp = sp;
	sp = ref->level;
	addr = ref->addr;
	baseaddr = ref->baseaddr;
	comma = ref->comma;
	file = ref->infile;
	ptr = ref->input;
	if (!ref->done) {
		ref->computed_value = rd_expr (&ptr, ref->delimiter,
				allow_invalid ? &valid : NULL,
				ref->level, 1);
		if (valid)
			ref->done = 1;
	}
	sp = backup_sp;
	addr = backup_addr;
	baseaddr = backup_baseaddr;
	comma = backup_comma;
	file = backup_file;
	return ref->computed_value;
}

/* read a word from input and store it in readword. return 1 on success */
static int rd_word (const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0)
		return 0;
	readword = *p;
	mem_delimiter = delimiter;
	skipword (p, delimiter);
	return 1;
}

/* read a byte from input and store it in readbyte. return 1 on success */
static int rd_byte (const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0)
		return 0;
	readbyte = *p;
	writebyte = 1;
	mem_delimiter = delimiter;
	skipword (p, delimiter);
	return 1;
}

/* read (SP), DE, or AF */
static int rd_ex1 (const char **p) {
#define DE 2
#define AF 3
	const char *list[] = { "( sp )", "de", "af", NULL };
	return indx (p, list, 1, NULL);
}

/* read first argument of IN */
static int rd_in (const char **p) {
#define A 8
	const char *list[] = { "b", "c", "d", "e", "h", "l", "f", "a", NULL };
	return indx (p, list, 1, NULL);
}

/* read second argument of out (c),x */
static int rd_out (const char **p) {
	const char *list[] = { "b", "c", "d", "e", "h", "l", "0", "a", NULL };
	return indx (p, list, 1, NULL);
}

/* read (c) or (nn) */
static int rd_nnc (const char **p) {
#define C 1
	int i;
	const char *list[] = { "( c )", "(*)", "a , (*)", NULL };
	i = indx (p, list, 1, &readbyte);
	if (i < 2)
		return i;
	return 2;
}

/* read (C) */
static int rd_c (const char **p) {
	const char *list[] = { "( c )", "( bc )", NULL };
	return indx (p, list, 1, NULL);
}

/* read a or hl */
static int rd_a_hl (const char **p) {
#define HL 2
	const char *list[] = { "a", "hl", NULL };
	return indx (p, list, 1, NULL);
}

/* read first argument of ld */
static int rd_ld (const char **p) {
#define ldBC	1
#define ldDE	2
#define ldHL	3
#define ldSP	4
#define ldIX	5
#define ldIY	6
#define ldB	7
#define ldC	8
#define ldD	9
#define ldE	10
#define ldH	11
#define ldL	12
#define ld_HL	13
#define ldA	14
#define ldI	15
#define ldR	16
#define ld_BC	17
#define ld_DE	18
#define ld_IX	19
#define ld_IY	20
#define ld_NN	21
	int i;
	const char *list[] = {
		"ixh", "ixl", "iyh", "iyl", "bc", "de", "hl", "sp", "ix",
		"iy", "b", "c", "d", "e", "h", "l", "( hl )", "a", "i",
		"r", "( bc )", "( de )", "( ix +)", "(iy +)", "(*)", NULL
	};
	const char *nn;
	i = indx (p, list, 1, &nn);
	if (!i)
		return 0;
	if (i <= 2) {
		indexed = 0xdd;
		return ldH + (i == 2);
	}
	if (i <= 4) {
		indexed = 0xfd;
		return ldH + (i == 4);
	}
	i -= 4;
	if (i == ldIX || i == ldIY) {
		indexed = i == ldIX ? 0xDD : 0xFD;
		return ldHL;
	}
	if (i == ld_IX || i == ld_IY) {
		indexjmp = nn;
		indexed = i == ld_IX ? 0xDD : 0xFD;
		return ld_HL;
	}
	if (i == ld_NN)
		readword = nn;
	return i;
}

/* read first argument of JP */
static int rd_jp (const char **p) {
	int i;
	const char *list[] = {
		"nz", "z", "nc", "c", "po", "pe", "p", "m", "( ix )", "( iy )",
		"(hl)", NULL
	};
	i = indx (p, list, 0, NULL);
	if (i < 9)
		return i;
	if (i == 11)
		return -1;
	indexed = 0xDD + 0x20 * (i - 9);
	return -1;
}

/* read first argument of JR */
static int rd_jr (const char **p) {
	const char *list[] = { "nz", "z", "nc", "c", NULL };
	return indx (p, list, 0, NULL);
}

/* read A */
static int rd_a (const char **p) {
	const char *list[] = { "a", NULL };
	return indx (p, list, 1, NULL);
}

/* read bc,de,hl,af */
static int rd_stack (const char **p) {
	int i;
	const char *list[] = { "bc", "de", "hl", "af", "ix", "iy", NULL };
	i = indx (p, list, 1, NULL);
	if (i < 5)
		return i;
	indexed = 0xDD + 0x20 * (i - 5);
	return 3;
}

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn 
 * but now with extra hl or i[xy](15) for add-instruction
 * and set variables accordingly */
static int rd_r_add (const char **p) {
#define addHL 	15
	int i;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l",
		"( hl )", "a", "( ix +)", "( iy +)", "hl", "ix", "iy", "*", NULL
	};
	const char *nn;
	i = indx (p, list, 0, &nn);
	if (i == 18) { /* expression */
		readbyte = nn;
		writebyte = 1;
		return 7;
	}
	if (i > 14) { /* hl, ix, iy */
		if (i > 15)
			indexed = 0xDD + 0x20 * (i - 16);
		return addHL;
	}
	if (i <= 4) {/* i[xy][hl]  */
		indexed = 0xdd + 0x20 * (i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9)
		return i;
	indexed = 0xDD + 0x20 * (i - 9);	/* (i[xy] +) */
	indexjmp = nn;
	return 7;
}

/* read bc,de,hl, or sp */
static int rd_rr_ (const char **p) {
	const char *list[] = { "bc", "de", "hl", "sp", NULL };
	return indx (p, list, 1, NULL);
}

/* read bc,de,hl|ix|iy,sp. hl|ix|iy only if it is already indexed the same. */
static int rd_rrxx (const char **p) {
	const char *listx[] = { "bc", "de", "ix", "sp", NULL };
	const char *listy[] = { "bc", "de", "iy", "sp", NULL };
	const char *list[] = { "bc", "de", "hl", "sp", NULL };
	switch (indexed) {
	case 0xDD:
		return indx (p, listx, 1, NULL);
	case 0xFD:
		return indx (p, listy, 1, NULL);
	default:
		return indx (p, list, 1, NULL);
	}
}

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn
 * and set variables accordingly */
static int rd_r (const char **p) {
	int i;
	const char *nn;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l", "( hl )",
		"a", "( ix +)", "( iy +)", "*", NULL
	};
	i = indx (p, list, 0, &nn);
	if (i == 15) { /* expression */
		readbyte = nn;
		writebyte = 1;
		return 7;
	}
	if (i <= 4) {
		indexed = 0xdd + 0x20 * (i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9)
		return i;
	indexed = 0xDD + 0x20 * (i - 9);
	indexjmp = nn;
	return 7;
}

/* like rd_r(), but without nn */
static int rd_r_ (const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx (p, list, 1, &indexjmp);
	if (i < 9)
		return i;
	indexed = 0xDD + 0x20 * (i - 9);
	return 7;
}

/* read a number from 0 to 7, for bit, set or res */
static int rd_0_7 (const char **p) {
	*p = delspc (*p);
	if (**p == 0)
		return 0;
	bitsetres = *p;
	skipword (p, ',');
	return 1;
}

/* read long condition. do not error if not found. */
static int rd_cc (const char **p) {
	const char *list[] = { "nz", "z", "nc", "c", "po", "pe", "p", "m", NULL };
	return indx (p, list, 0, NULL);
}

/* read long or short register,  */
static int rd_r_rr (const char **p) {
	int i;
	const char *list[] = {
		"iy", "ix", "sp", "hl", "de", "bc", "", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx (p, list, 1, &indexjmp);
	if (!i)
		return 0;
	if (i < 16 && i > 2)
		return 7 - i;
	if (i > 15) {
		indexed = 0xDD + (i - 16) * 0x20;
		return -7;
	}
	indexed = 0xDD + (2 - i) * 0x20;
	return 3;
}

/* read hl */
static int rd_hl (const char **p) {
	const char *list[] = { "hl", NULL };
	return indx (p, list, 1, NULL);
}

/* read hl, ix, or iy */
static int rd_hlx (const char **p) {
	int i;
	const char *list[] = { "hl", "ix", "iy", NULL };
	i = indx (p, list, 1, NULL);
	if (i < 2)
		return i;
	indexed = 0xDD + 0x20 * (i - 2);
	return 1;
}

/* read af' */
static int rd_af_ (const char **p) {
	const char *list[] = { "af'", NULL };
	return indx (p, list, 1, NULL);
}

/* read 0(1), 1(3), or 2(4) */
static int rd_0_2 (const char **p) {
	const char *list[] = { "0", "", "1", "2", NULL };
	return indx (p, list, 1, NULL);
}

/* read argument of ld (hl), */
static int rd_ld_hl (const char **p) {
	int i;
	const char *list[] = { "b", "c", "d", "e", "h", "l", "", "a", "*", NULL };
	i = indx (p, list, 0, &readbyte);
	if (i < 9)
		return i;
	writebyte = 1;
	return 7;
}

/* read argument of ld (nnnn), */
static int rd_ld_nn (const char **p) {
#define ld_nnHL 5
#define ld_nnA 6
	int i;
	const char *list[] = { "bc", "de", "", "sp", "hl", "a", "ix", "iy", NULL };
	i = indx (p, list, 1, NULL);
	if (i < 7)
		return i;
	indexed = 0xdd + 0x20 * (i == 8);
	return ld_nnHL;
}

/* read argument of ld a, */
static int rd_lda (const char **p) {
#define A_I 9
#define A_R 10
#define A_NN 11
	int i;
	const char *list[] = {
		"( sp )", "( iy +)", "( de )", "( bc )", "( ix +)", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "i", "r", "(*)", "*", NULL
	};
	const char *nn;
	i = indx (p, list, 0, &nn);
	if (i == 2 || i == 5) {
		indexed = (i == 2) ? 0xFD : 0xDD;
		indexjmp = nn;
		return 7;
	}
	if (i == 17) {
		readbyte = nn;
		writebyte = 1;
		return 7;
	}
	if (i == 16)
		readword = nn;
	return i - 5;
}

/* read argument of ld b|c|d|e|h|l */
static int rd_ldbcdehla (const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", "ixh",
		"ixl", "iyh", "iyl", "*", NULL
	};
	const char *nn;
	i = indx (p, list, 0, &nn);
	if (i == 15) {
		readbyte = nn;
		writebyte = 1;
		return 7;
	}
	if (i > 10) {
		int x;
		x = 0xdd + 0x20 * (i > 12);
		if (indexed && indexed != x) {
			printerr (1, "illegal use of index registers\n");
			return 0;
		}
		indexed = x;
		return 6 - (i & 1);
	}
	if (i > 8) {
		if (indexed) {
			printerr (1, "illegal use of index registers\n");
			return 0;
		}
		indexed = 0xDD + 0x20 * (i == 10);
		indexjmp = nn;
		return 7;
	}
	return i;
}

/* read nnnn, or (nnnn) */
static int rd_nn_nn (const char **p) {
#define _NN 1
	const char *list[] = { "(*)", "*", NULL };
	return 2 - indx (p, list, 0, &readword);
}

/* read {HL|IX|IY},nnnn, or (nnnn) */
static int rd_sp (const char **p) {
#define SPNN 0
#define SPHL 1
	int i;
	const char *list[] = { "hl", "ix", "iy", "(*)", "*", NULL };
	const char *nn;
	i = indx (p, list, 0, &nn);
	if (i > 3) {
		readword = nn;
		return i == 4 ? 2 : 0;
	}
	if (i != 1)
		indexed = 0xDD + 0x20 * (i - 2);
	return 1;
}

/* do the actual work */
static int assemble (const char *str, unsigned char *_obuf) {
	int ifcount = 0, noifcount = 0;
	const char *ptr;
	char *bufptr;
	int r, s;			/* registers */

	obuflen = 0;
	obuf = _obuf;
	/* continue assembling until the last input file is done */
	//for (file = 0; file < infilecount; ++file)
	do {
		int cmd, cont = 1;
// XXX: must free
		  z80buffer = strdup (str);
	  if (!cont)
	    break;		/* break to next source file */
//	  if (havelist)
//	    fprintf (listfile, "%04x", addr);
	  for (bufptr = z80buffer; (bufptr = strchr (bufptr, '\n'));)
	    *bufptr = ' ';
	  for (bufptr = z80buffer; (bufptr = strchr (bufptr, '\r'));)
	    *bufptr = ' ';
	  ptr = z80buffer;
	  //lastlabel = NULL;
	  baseaddr = addr;
	  ++stack[sp].line;
	  ptr = delspc (ptr);
	  if (!*ptr)
	    continue;
	  if (!noifcount && !define_macro)
	    readlabel (&ptr, 1);
	  else
	    readlabel (&ptr, 0);
	  ptr = delspc (ptr);
	  if (!*ptr)
	    continue;
	  comma = 0;
	  indexed = 0;
	  indexjmp = 0;
	  writebyte = 0;
	  readbyte = 0;
	  readword = 0;
	  cmd = readcommand (&ptr) - 1;
	  switch (cmd)
	    {
	      int i, have_quote;
	    case Z80_ADC:
	      if (!(r = rd_a_hl (&ptr)))
		break;
	      if (r == HL)
		{
		  if (!(r = rd_rr_ (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x4A + 0x10 * --r);
		  break;
		}
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0x88 + --r);
	      break;
	    case Z80_ADD:
	      if (!(r = rd_r_add (&ptr)))
		break;
	      if (r == addHL)
		{
		  if (!(r = rd_rrxx (&ptr)))
		    break;
		  wrtb (0x09 + 0x10 * --r);	/* ADD HL/IX/IY, qq  */
		  break;
		}
	      if (has_argument (&ptr))
		{
		  if (r != A)
		    {
		      printerr (1, "parse error before: %s\n", ptr);
		      break;
		    }
		  if (!(r = rd_r (&ptr)))
		    break;
		  wrtb (0x80 + --r);	/* ADD A,r  */
		  break;
		}
	      wrtb (0x80 + --r);	/* ADD r  */
	      break;
	    case Z80_AND:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xA0 + --r);
	      break;
	    case Z80_BIT:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x40 + (r - 1));
	      break;
	    case Z80_CALL:
	      if ((r = rd_cc (&ptr))) {
		  wrtb (0xC4 + 8 * --r);
		  rd_comma (&ptr);
		} else wrtb (0xCD);
	      break;
	    case Z80_CCF:
	      wrtb (0x3F);
	      break;
	    case Z80_CP:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xB8 + --r);
	      break;
	    case Z80_CPD:
	      wrtb (0xED);
	      wrtb (0xA9);
	      break;
	    case Z80_CPDR:
	      wrtb (0xED);
	      wrtb (0xB9);
	      break;
	    case Z80_CPI:
	      wrtb (0xED);
	      wrtb (0xA1);
	      break;
	    case Z80_CPIR:
	      wrtb (0xED);
	      wrtb (0xB1);
	      break;
	    case Z80_CPL:
	      wrtb (0x2F);
	      break;
	    case Z80_DAA:
	      wrtb (0x27);
	      break;
	    case Z80_DEC:
	      if (!(r = rd_r_rr (&ptr)))
		break;
	      if (r < 0) {
		  wrtb (0x05 - 8 * ++r);
		  break;
		}
	      wrtb (0x0B + 0x10 * --r);
	      break;
	    case Z80_DI:
	      wrtb (0xF3);
	      break;
	    case Z80_DJNZ:
	      wrtb (0x10);
	      //rd_wrt_jr (&ptr, '\0');
	      break;
	    case Z80_EI:
	      wrtb (0xFB);
	      break;
	    case Z80_EX:
	      if (!(r = rd_ex1 (&ptr)))
		break;
	      switch (r)
		{
		case DE:
		  if (!rd_hl (&ptr))
		    break;
		  wrtb (0xEB);
		  break;
		case AF:
		  if (!rd_af_ (&ptr))
		    break;
		  wrtb (0x08);
		  break;
		default:
		  if (!rd_hlx (&ptr))
		    break;
		  wrtb (0xE3);
		}
	      break;
	    case Z80_EXX:
	      wrtb (0xD9);
	      break;
	    case Z80_HALT:
	      wrtb (0x76);
	      break;
	    case Z80_IM:
	      if (!(r = rd_0_2 (&ptr)))
		break;
	      wrtb (0xED);
	      wrtb (0x46 + 8 * --r);
	      break;
	    case Z80_IN:
	      if (!(r = rd_in (&ptr)))
		break;
	      if (r == A)
		{
		  if (!(r = rd_nnc (&ptr)))
		    break;
		  if (r == C)
		    {
		      wrtb (0xED);
		      wrtb (0x40 + 8 * (A - 1));
		      break;
		    }
		  wrtb (0xDB);
		  break;
		}
	      if (!rd_c (&ptr))
		break;
	      wrtb (0xED);
	      wrtb (0x40 + 8 * --r);
	      break;
	    case Z80_INC:
	      if (!(r = rd_r_rr (&ptr)))
		break;
	      if (r < 0)
		{
		  wrtb (0x04 - 8 * ++r);
		  break;
		}
	      wrtb (0x03 + 0x10 * --r);
	      break;
	    case Z80_IND:
	      wrtb (0xED);
	      wrtb (0xAA);
	      break;
	    case Z80_INDR:
	      wrtb (0xED);
	      wrtb (0xBA);
	      break;
	    case Z80_INI:
	      wrtb (0xED);
	      wrtb (0xA2);
	      break;
	    case Z80_INIR:
	      wrtb (0xED);
	      wrtb (0xB2);
	      break;
	    case Z80_JP:
	      r = rd_jp (&ptr);
	      if (r < 0)
		{
		  wrtb (0xE9);
		  break;
		}
	      if (r) {
		  wrtb (0xC2 + 8 * --r);
		  rd_comma (&ptr);
		} else wrtb (0xC3);
	      break;
	    case Z80_JR:
	      r = rd_jr (&ptr);
	      if (r)
		rd_comma (&ptr);
	      wrtb (0x18 + 8 * r);
	      break;
	    case Z80_LD:
	      if (!(r = rd_ld (&ptr)))
		break;
	      switch (r)
		{
		case ld_BC:
		case ld_DE:
		  if (!rd_a (&ptr))
		    break;
		  wrtb (0x02 + 0x10 * (r == ld_DE));
		  break;
		case ld_HL:
		  r = rd_ld_hl (&ptr);
		  wrtb (0x70 + --r);
		  break;
		case ld_NN:
		  if (!(r = rd_ld_nn (&ptr)))
		    break;
		  if (r == ld_nnA || r == ld_nnHL)
		    {
		      wrtb (0x22 + 0x10 * (r == ld_nnA));
		      break;
		    }
		  wrtb (0xED);
		  wrtb (0x43 + 0x10 * --r);
		  break;
		case ldA:
		  if (!(r = rd_lda (&ptr)))
		    break;
		  if (r == A_NN)
		    {
		      wrtb (0x3A);
		      break;
		    }
		  if (r == A_I || r == A_R)
		    {
		      wrtb (0xED);
		      wrtb (0x57 + 8 * (r == A_R));
		      break;
		    }
		  if (r < 0)
		    {
		      wrtb (0x0A - 0x10 * ++r);
		      break;
		    }
		  wrtb (0x78 + --r);
		  break;
		case ldB:
		case ldC:
		case ldD:
		case ldE:
		case ldH:
		case ldL:
		  if (!(s = rd_ldbcdehla (&ptr)))
		    break;
		  wrtb (0x40 + 0x08 * (r - 7) + (s - 1));
		  break;
		case ldBC:
		case ldDE:
		  s = rd_nn_nn (&ptr);
		  if (s == _NN)
		    {
		      wrtb (0xED);
		      wrtb (0x4B + 0x10 * (r == ldDE));
		      break;
		    }
		  wrtb (0x01 + (r == ldDE) * 0x10);
		  break;
		case ldHL:
		  r = rd_nn_nn (&ptr);
		  wrtb (0x21 + (r == _NN) * 9);
		  break;
		case ldI:
		case ldR:
		  if (!rd_a (&ptr))
		    break;
		  wrtb (0xED);
		  wrtb (0x47 + 0x08 * (r == ldR));
		  break;
		case ldSP:
		  r = rd_sp (&ptr);
		  if (r == SPHL)
		    {
		      wrtb (0xF9);
		      break;
		    }
		  if (r == SPNN)
		    {
		      wrtb (0x31);
		      break;
		    }
		  wrtb (0xED);
		  wrtb (0x7B);
		  break;
		}
	      break;
	    case Z80_LDD:
	      wrtb (0xED);
	      wrtb (0xA8);
	      break;
	    case Z80_LDDR:
	      wrtb (0xED);
	      wrtb (0xB8);
	      break;
	    case Z80_LDI:
	      wrtb (0xED);
	      wrtb (0xA0);
	      break;
	    case Z80_LDIR:
	      wrtb (0xED);
	      wrtb (0xB0);
	      break;
	    case Z80_NEG:
	      wrtb (0xED);
	      wrtb (0x44);
	      break;
	    case Z80_NOP:
	      wrtb (0x00);
	      break;
	    case Z80_OR:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xB0 + --r);
	      break;
	    case Z80_OTDR:
	      wrtb (0xED);
	      wrtb (0xBB);
	      break;
	    case Z80_OTIR:
	      wrtb (0xED);
	      wrtb (0xB3);
	      break;
	    case Z80_OUT:
	      if (!(r = rd_nnc (&ptr)))
		break;
	      if (r == C)
		{
		  if (!(r = rd_out (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x41 + 8 * --r);
		  break;
		}
	      if (!rd_a (&ptr))
		break;
		wrtb (0xD3);
	      break;
	    case Z80_OUTD:
	      wrtb (0xED);
	      wrtb (0xAB);
	      break;
	    case Z80_OUTI:
	      wrtb (0xED);
	      wrtb (0xA3);
	      break;
	    case Z80_POP:
	      if (!(r = rd_stack (&ptr)))
		break;
	      wrtb (0xC1 + 0x10 * --r);
	      break;
	    case Z80_PUSH:
	      if (!(r = rd_stack (&ptr)))
		break;
	      wrtb (0xC5 + 0x10 * --r);
	      break;
	    case Z80_RES:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x80 + --r);
	      break;
	    case Z80_RET:
	      if (!(r = rd_cc (&ptr)))
		{
		  wrtb (0xC9);
		  break;
		}
	      wrtb (0xC0 + 8 * --r);
	      break;
	    case Z80_RETI:
	      wrtb (0xED);
	      wrtb (0x4D);
	      break;
	    case Z80_RETN:
	      wrtb (0xED);
	      wrtb (0x45);
	      break;
	    case Z80_RL:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x10 + --r);
	      break;
	    case Z80_RLA:
	      wrtb (0x17);
	      break;
	    case Z80_RLC:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x00 + --r);
	      break;
	    case Z80_RLCA:
	      wrtb (0x07);
	      break;
	    case Z80_RLD:
	      wrtb (0xED);
	      wrtb (0x6F);
	      break;
	    case Z80_RR:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x18 + --r);
	      break;
	    case Z80_RRA:
	      wrtb (0x1F);
	      break;
	    case Z80_RRC:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x08 + --r);
	      break;
	    case Z80_RRCA:
	      wrtb (0x0F);
	      break;
	    case Z80_RRD:
	      wrtb (0xED);
	      wrtb (0x67);
	      break;
	    case Z80_RST:
	      ptr = "";
	      break;
	    case Z80_SBC:
	      if (!(r = rd_a_hl (&ptr)))
		break;
	      if (r == HL)
		{
		  if (!(r = rd_rr_ (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x42 + 0x10 * --r);
		  break;
		}
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0x98 + --r);
	      break;
	    case Z80_SCF:
	      wrtb (0x37);
	      break;
	    case Z80_SET:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0xC0 + --r);
	      break;
	    case Z80_SLA:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x20 + --r);
	      break;
	    case Z80_SLI:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x30 + --r);
	      break;
	    case Z80_SRA:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x28 + --r);
	      break;
	    case Z80_SRL:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x38 + --r);
	      break;
	    case Z80_SUB:
	      if (!(r = rd_r (&ptr)))
		break;
	      if (has_argument (&ptr))	/* SUB A,r ?  */
		{
		  if (r != A)
		    {
		      printerr (1, "parse error before: %s\n", ptr);
		      break;
		    }
		  if (!(r = rd_r (&ptr)))
		    break;
		}
	      wrtb (0x90 + --r);
	      break;
	    case Z80_XOR:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xA8 + --r);
	      break;
	    case Z80_DEFB:
	    case Z80_DB:
	    case Z80_DEFM:
	    case Z80_DM:
	      ptr = delspc (ptr);
	      while (1)
		{
		  have_quote = (*ptr == '"' || *ptr == '\'');
		  if (have_quote)
		    {
		      /* Read string.  */
		      int quote = *ptr;
		      ++ptr;
		      while (*ptr != quote)
			{
			  write_one_byte (rd_character (&ptr, NULL, 1), 0);
			  if (*ptr == 0)
			    {
			      printerr (1, "end of line in quoted string\n");
			      break;
			    }
			}
		      ++ptr;
		    }
		  else
		    {
		      /* Read expression.  */
		      skipword (&ptr, ',');
		    }
		  ptr = delspc (ptr);
		  if (*ptr == ',')
		    {
		      ++ptr;
		      continue;
		    }
		  if (*ptr != 0)
		    printerr (1, "junk in byte definition: %s\n", ptr);
		  break;
		}
	      break;
	    case Z80_DEFW:
	    case Z80_DW:
	      if (!(r = rd_word (&ptr, ',')))
		{
		  printerr (1, "No data for word definition\n");
		  break;
		}
	      while (1)
		{
		  ptr = delspc (ptr);
		  if (*ptr != ',')
		    break;
		  ++ptr;
		  if (!(r = rd_word (&ptr, ',')))
		    printerr (1, "Missing expression in defw\n");
		}
	      break;
	    case Z80_DEFS:
	    case Z80_DS:
	      r = rd_expr (&ptr, ',', NULL, sp, 1);
	      if (r < 0)
		{
		  printerr (1, "ds should have its first argument >=0"
			    " (not -0x%x)\n", -r);
		  break;
		}
	      ptr = delspc (ptr);
	      if (*ptr) {
		  rd_comma (&ptr);
		  readbyte = 0;
		  rd_byte (&ptr, '\0');
		  writebyte = 0;
		  break;
		}
	      for (i = 0; i < r; i++) {
		  write_one_byte (0, 0);
		}
	      break;
	    case Z80_END:
	      break;
	    case Z80_ORG:
	      addr = rd_expr (&ptr, '\0', NULL, sp, 1) & 0xffff;
	      break;
	    case Z80_IF:
	      if (rd_expr (&ptr, '\0', NULL, sp, 1))
		ifcount++;
	      else
		noifcount++;
	      break;
	    case Z80_ELSE:
	      if (ifcount == 0)
		{
		  printerr (1, "else without if\n");
		  break;
		}
	      noifcount = 1;
	      ifcount--;
	      break;
	    case Z80_ENDIF:
	      if (noifcount == 0 && ifcount == 0)
		{
		  printerr (1, "endif without if\n");
		  break;
		}
	      if (noifcount)
		noifcount--;
	      else
		ifcount--;
	      break;
	    case Z80_ENDM:
	      if (stack[sp].file)
		printerr (1, "endm outside macro definition\n");
	      break;
	    case Z80_SEEK:
	      fprintf (stderr, "seek error\n");
		  break;
	    default:
	      printerr (1, "command or comment expected (was %s)\n", ptr);
	      return 0;
	    }
    } while (0);
  //free (infile);
return obuflen;
}

// XXX
R_API_I inline int z80asm (unsigned char *outbuf, const char *s) {
	return assemble (s, outbuf);
}

#ifdef MAIN_ASM
int main (int argc, char **argv) {
	int len;
	unsigned char buf[4];

	buf[0] = buf[1] = buf[2] = 0;
	len = z80asm (buf, "nop");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "cp b");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "call 0x123");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "call bla");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	return 0;
}
#endif
