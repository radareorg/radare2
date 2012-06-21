/*
 * ascii85 - Ascii85 encode/decode data and print to standard output
 *
 * Copyright (C) 2011 Remy Oukaour
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define eprintf(args...) fprintf(stderr, args)

#define USAGE_TEXT (\
	"usage: ascii85 [OPTION]... [FILE]\n"\
	"Enter 'ascii85 -h' for more information.\n")

#define HELP_TEXT (\
	"NAME\n"\
	"\tascii85 - Ascii85 encode/decode data and print to standard output\n"\
	"\n"\
	"SYNOPSIS\n"\
	"\tascii85 [OPTION]... [FILE]\n"\
	"\n"\
	"DESCRIPTION\n"\
	"\tAscii85 encode or decode FILE, or standard input, to standard output.\n"\
	"\n"\
	"\t-d, --decode\n"\
	"\t\tdecode data (encodes by default)\n"\
	"\n"\
	"\t-i, --ignore-garbage\n"\
	"\t\twhen decoding, ignore invalid characters\n"\
	"\n"\
	"\t-n, --no-delims\n"\
	"\t\twhen encoding, omit delimiters (<~ and ~>), and when decoding,\n"\
	"\t\tdo not look for delimiters\n"\
	"\n"\
	"\t-w, --wrap=COLS\n"\
	"\t\twrap encoded lines after COLS characters (default 76).  Use 0\n"\
	"\t\tto disable line wrapping.\n"\
	"\n"\
	"\t-y, --y-abbr\n"\
	"\t\tabbreviates four encoded spaces as 'y'\n"\
	"\n"\
	"\t-h, --help\n"\
	"\t\tdisplay this help and exit\n"\
	"\n"\
	"\tWith no FILE, or when FILE is -, read standard input.\n"\
	"\n"\
	"AUTHOR\n"\
	"\tWritten by Remy Oukaour <me@remyoukaour.com>.\n"\
	"\n"\
	"COPYRIGHT\n"\
	"\tCopyright (C) 2011 Remy Oukaour. MIT License.\n"\
	"\tThis is free software: you are free to change and redistribute it.\n"\
	"\tThere is NO WARRANTY, to the extent permitted by law.\n")

int getc_nospace(FILE *f) {
	int c;
	while (isspace(c = getc(f)));
	return c;
}

void putc_wrap(char c, int wrap, int *len) {
	if (wrap && *len >= wrap) {
		putchar('\n');
		*len = 0;
	}
	putchar(c);
	(*len)++;
}

void encode_tuple(unsigned long tuple, int count, int wrap, int *plen, int y_abbr) {
	int i, lim;
	char out[5];
	if (tuple == 0 && count == 4) {
		putc_wrap('z', wrap, plen);
	}
	else if (tuple == 0x20202020 && count == 4 && y_abbr) {
		putc_wrap('y', wrap, plen);
	}
	else {
		for (i = 0; i < 5; i++) {
			out[i] = tuple % 85 + '!';
			tuple /= 85;
		}
		lim = 4 - count;
		for (i = 4; i >= lim; i--) {
			putc_wrap(out[i], wrap, plen);
		}
	}
}

void decode_tuple(unsigned long tuple, int count) {
	int i;
	for (i = 1; i < count; i++) {
		putchar(tuple >> ((4 - i) * 8));
	}
}

void ascii85_encode(FILE *fp, int delims, int wrap, int y_abbr) {
	int c, count = 0, len = 0;
	unsigned long tuple = 0;
	if (delims) {
		putc_wrap('<', wrap, &len);
		putc_wrap('~', wrap, &len);
	}
	for (;;) {
		c = getc(fp);
		if (c != EOF) {
			tuple |= c << ((3 - count++) * 8);
			if (count < 4) continue;
		}
		else if (count == 0) break;
		encode_tuple(tuple, count, wrap, &len, y_abbr);
		if (c == EOF) break;
		tuple = 0;
		count = 0;
	}
	if (delims) {
		putc_wrap('~', wrap, &len);
		putc_wrap('>', wrap, &len);
	}
}

void ascii85_decode(FILE *fp, int delims, int ignore_garbage) {
	int c, count = 0, end = 0;
	unsigned long tuple = 0, pows[] = {85*85*85*85, 85*85*85, 85*85, 85, 1};
	while (delims) {
		c = getc_nospace(fp);
		if (c == '<') {
			c = getc_nospace(fp);
			if (c == '~') break;
			ungetc(c, fp);
		}
		else if (c == EOF) {
			eprintf("ascii85: missing <~\n");
			exit(1);
		}
	}
	for (;;) {
		c = getc_nospace(fp);
		if (c == 'z' && count == 0) {
			decode_tuple(0, 5);
			continue;
		}
		if (c == 'y' && count == 0) {
			decode_tuple(0x20202020, 5);
			continue;
		}
		if (c == '~' && delims) {
			c = getc_nospace(fp);
			if (c != '>') {
				eprintf("ascii85: ~ without >\n");
				exit(1);
			}
			c = EOF;
			end = 1;
		}
		if (c == EOF) {
			if (delims && !end) {
				eprintf("ascii85: missing ~>\n");
				exit(1);
			}
			if (count > 0) {
				tuple += pows[count-1];
				decode_tuple(tuple, count);
			}
			break;
		}
		if (c < '!' || c > 'u') {
			if (ignore_garbage) continue;
			eprintf("ascii85: invalid character '%c'\n", c);
			exit(1);
		}
		tuple += (c - '!') * pows[count++];
		if (count == 5) {
			decode_tuple(tuple, count);
			tuple = 0;
			count = 0;
		}
	}
}

int main(int argc, char *argv[]) {
	extern char *optarg;
	extern int optind, optopt, opterr;
	int opt, long_optind, decode = 0, ignore_garbage = 0, delims = 0, wrap = 76, y_abbr = 0;
	FILE *fp = stdin;
	char *opts = "dinw:yh";
	struct option long_opts[] = {
		{"decode", no_argument, NULL, 'd'},
		{"ignore-garbage", no_argument, NULL, 'i'},
		{"no-delims", no_argument, NULL, 'n'},
		{"wrap", required_argument, NULL, 'w'},
		{"y-abbr", no_argument, NULL, 'y'},
		{"help", no_argument, NULL, 'h'},
		{NULL, no_argument, NULL, 0}
	};
	opterr = 0;
	while ((opt = getopt_long(argc, argv, opts, long_opts, &long_optind)) != -1) {
		switch (opt) {
			case 'd': decode = 1; break;
			case 'i': ignore_garbage = 1; break;
			case 'n': delims = 0; break;
			case 'w': sscanf(optarg, "%d", &wrap); break;
			case 'y': y_abbr = 1; break;
			case 'h': printf(HELP_TEXT); exit(0);
			case '?':
				eprintf("ascii85: ");
				if (strchr("w", optopt) != NULL)
					eprintf("option '-%c' requires an argument\n", optopt);
				else
					eprintf("invalid option -- %c\n", optopt);
				eprintf(USAGE_TEXT);
				exit(1);
			default: break;
		}
	}
	if (optind == argc - 1 && strcmp(argv[optind], "-")) {
		fp = fopen(argv[optind], "rb");
		if (fp == NULL) {
			eprintf("ascii85: %s: %s\n", argv[optind], strerror(errno));
			exit(1);
		}
	}
	else if (optind > argc) {
		eprintf("ascii85: too many operands or wrong operand order\n");
		eprintf(USAGE_TEXT);
		exit(1);
	}
	if (wrap < 1) wrap = 0;
	if (decode)
		ascii85_decode(fp, delims, ignore_garbage);
	else
		ascii85_encode(fp, delims, wrap, y_abbr);
	fflush(stdout);
	fclose(fp);
	return 0;
}
