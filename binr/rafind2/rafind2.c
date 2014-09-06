/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.c>

#include <r_types.h>
#include <r_print.h>
#include <r_search.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_lib.h>
#include <r_io.h>

static struct r_io_t *io;
static RIODesc *fd = NULL;
static int showstr = 0;
static int rad = 0;
struct r_search_t *rs;
static ut64 from = 0LL, to = -1;
static char *mask = "";
static int nonstop = 0;
static int mode = R_SEARCH_STRING;
static ut64 cur = 0;
static ut8 *buf = NULL;
static char *curfile = NULL;
static ut64 bsize = 4096;
static int hexstr = 0;
static struct r_print_t *pr = NULL;
static RList *keywords;

static int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	int delta = addr-cur;
	if (rad) {
		printf ("f hit%d_%d 0x%08"PFMT64x" ; %s\n", 0, kw->count, addr, curfile);
	} else {
		if (showstr) {
			printf ("0x%"PFMT64x" %s\n", addr, buf+delta);
		} else {
			printf ("0x%"PFMT64x"\n", addr);
			if (pr) {
				r_print_hexdump (pr, addr, (ut8*)buf+delta, 78, 16, R_TRUE);
				r_cons_flush ();
			}
		}
	}
	return 1;
}

static int show_help(char *argv0, int line) {
	printf ("Usage: %s [-Xnzhv] [-b sz] [-f/t from/to] [-[m|s|e] str] [-x hex] file ..\n", argv0);
	if (line) return 0;
	printf (
	" -h         show this help\n"
	" -v         print version and exit\n"
	" -b [size]  set block size\n"

	" -f [from]  start searching from address 'from'\n"
	" -t [to]    stop search at address 'to'\n"
	" -n         do not stop on read errors\n"

	" -s [str]   search for a specific string (can be used multiple times)\n"
	" -x [hex]   search for hexpair string (909090) (can be used multiple times)\n"
	" -e [regex] search for regular expression string matches\n"
	" -m [str]   set a binary mask to be applied on keywords\n"
	" -z         search for zero-terminated strings\n"

	" -r         print using radare commands\n"
	" -X         show hexdump of search results\n"
	" -Z         show zero-terminated strings of search results\n"
	);
	return 0;
}

static int rafind_open(char *file) {
	const char *kw;
	RListIter *iter;
	int ret, last = 0;

	io = r_io_new ();
	fd = r_io_open_nomap (io, file, R_IO_READ, 0);
	if (fd == NULL) {
		eprintf ("Cannot open file '%s'\n", file);
		return 1;
	}

	r_cons_new ();
	rs = r_search_new (mode);
	buf = malloc (bsize);
	if (buf==NULL) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", bsize);
		return 1;
	}
	r_search_set_callback (rs, &hit, buf);
	if (to == -1)
		to = r_io_size(io);
	if (mode == R_SEARCH_STRING) {
		eprintf ("TODO: searchin stringz\n");
	}
	if (mode == R_SEARCH_KEYWORD) {
		r_list_foreach (keywords, iter, kw) {
			r_search_kw_add (rs, (hexstr)?
				r_search_keyword_new_hex (kw, mask, NULL) :
				r_search_keyword_new_str (kw, mask, NULL, 0));
		}
	} else if (mode == R_SEARCH_STRING) {
		r_search_kw_add (rs,
				r_search_keyword_new_hexmask ("00", NULL)); //XXX
	}

	curfile = file;
	r_search_begin (rs);
	r_io_seek (io, from, R_IO_SEEK_SET);
	//printf("; %s 0x%08"PFMT64x"-0x%08"PFMT64x"\n", file, from, to);
	for (cur = from; !last && cur < to; cur += bsize) {
		if ((cur+bsize)>to) {
			bsize = to-cur;
			last=1;
		}
		ret = r_io_pread (io, cur, buf, bsize);
		if (ret == 0) {
			if (nonstop) continue;
		//	fprintf(stderr, "Error reading at 0x%08"PFMT64x"\n", cur);
			return 1;
		}
		if (ret != bsize)
			bsize = ret;

		if (r_search_update (rs, &cur, buf, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", cur);
			break;
		}

	}
	rs = r_search_free (rs);
	free (buf);
	return 0;
}

int main(int argc, char **argv) {
	int c;

	keywords = r_list_new ();
	while ((c = getopt(argc, argv, "e:b:m:s:x:Xzf:t:rnhvZ")) != -1) {
		switch (c) {
		case 'r':
			rad = 1;
			break;
		case 'n':
			nonstop = 1;
			break;
		case 'e':
			mode = R_SEARCH_REGEXP;
			hexstr = 0;
			r_list_append (keywords, optarg);
			break;
		case 's':
			mode = R_SEARCH_KEYWORD;
			hexstr = 0;
			r_list_append (keywords, optarg);
			break;
		case 'b':
			bsize = r_num_math (NULL, optarg);
			break;
		case 'x':
			mode = R_SEARCH_KEYWORD;
			hexstr = 1;
			r_list_append (keywords, optarg);
			break;
		case 'm':
			// XXX should be from hexbin
			mask = optarg;
			break;
		case 'f':
			from = r_num_math (NULL, optarg);
			break;
		case 't':
			to = r_num_math (NULL, optarg);
			break;
		case 'X':
			pr = r_print_new ();
			break;
		case 'v':
			printf ("rafind2 v"R2_VERSION"\n");
			return 0;
		case 'h':
			return show_help(argv[0], 0);
		case 'z':
			mode = R_SEARCH_STRING;
			break;
		case 'Z':
			showstr = 1;
			break;
		}
	}

	if (optind == argc)
		return show_help (argv[0], 1);

	for (;optind < argc;optind++)
		rafind_open (argv[optind]);

	return 0;
}
