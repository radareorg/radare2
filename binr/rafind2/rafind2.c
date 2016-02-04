/* radare - LGPL - Copyright 2009-2016 - pancake */

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
static int align = 0;
struct r_search_t *rs;
static ut64 from = 0LL, to = -1;
static char *mask = NULL;
static int nonstop = 0;
static int mode = R_SEARCH_STRING;
static ut64 cur = 0;
static ut8 *buf = NULL;
static char *curfile = NULL;
static ut64 bsize = 4096;
static int hexstr = 0;
static int widestr = 0;
static struct r_print_t *pr = NULL;
static RList *keywords;

static int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	int delta = addr - cur;
	if (delta < 0 || delta >= bsize) {
		eprintf ("Invalid delta\n");
		return 0;
	}
	if (rad) {
		printf ("f hit%d_%d 0x%08"PFMT64x" ; %s\n", 0, kw->count, addr, curfile);
	} else {
		if (showstr) {
			if (widestr) {
				char *str = calloc (1, bsize);
				int i, j = 0;
				for (i = delta; buf[i] && i < bsize; i++) {
					if (!IS_PRINTABLE (buf[i])) {
						break;
					}
					str[j++] = buf[i++];
					if (j > 80) {
						strcpy (str + j, "...");
						j += 3;
						break;
					}
					if (buf[i]) {
						break;
					}
				}
				str[j] = 0;
				printf ("0x%"PFMT64x" %s\n", addr, str);
				free (str);
			} else {
				printf ("0x%"PFMT64x" %s\n", addr, buf + delta);
			}
		} else {
			printf ("0x%"PFMT64x"\n", addr);
			if (pr) {
				r_print_hexdump (pr, addr, (ut8*)buf + delta, 78, 16, true);
				r_cons_flush ();
			}
		}
	}
	return 1;
}

static int show_help(char *argv0, int line) {
	printf ("Usage: %s [-mXnzZhv] [-a align] [-b sz] [-f/t from/to] [-[m|s|S|e] str] [-x hex] file ..\n", argv0);
	if (line) return 0;
	printf (
	" -a [align] only accept aligned hits\n"
	" -b [size]  set block size\n"
	" -e [regex] search for regular expression string matches\n"
	" -f [from]  start searching from address 'from'\n"
	" -h         show this help\n"
	" -m         magic search, file-type carver\n"
	" -M [str]   set a binary mask to be applied on keywords\n"
	" -n         do not stop on read errors\n"
	" -r         print using radare commands\n"
	" -s [str]   search for a specific string (can be used multiple times)\n"
	" -S [str]   search for a specific wide string (can be used multiple times)\n"
	" -t [to]    stop search at address 'to'\n"
	" -v         print version and exit\n"
	" -x [hex]   search for hexpair string (909090) (can be used multiple times)\n"
	" -X         show hexdump of search results\n"
	" -z         search for zero-terminated strings\n"
	" -Z         show string found on each search hit\n"
	);
	return 0;
}

static int rafind_open(char *file) {
	const char *kw;
	RListIter *iter;
	bool last = false;
	int ret;

	io = r_io_new ();
	fd = r_io_open_nomap (io, file, R_IO_READ, 0);
	if (!fd) {
		eprintf ("Cannot open file '%s'\n", file);
		return 1;
	}

	r_cons_new ();
	rs = r_search_new (mode);
	if (!rs) return 1;
	buf = calloc (1, bsize);
	if (!buf) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", bsize);
		return 1;
	}
	rs->align = align;
	r_search_set_callback (rs, &hit, buf);
	if (to == -1) {
		to = r_io_size(io);
	}
	if (mode == R_SEARCH_STRING) {
		/* TODO: implement using api */
		r_sys_cmdf ("rabin2 -qzzz '%s'", file);
		return 0;
	}
	if (mode == R_SEARCH_MAGIC) {
		char *tostr = (to && to != UT64_MAX)?
			r_str_newf ("-e search.to=%"PFMT64d, to): strdup ("");
		char *cmd = r_str_newf ("r2"
			" -e search.in=range"
			" -e search.align=%d"
			" -e search.from=%"PFMT64d
			" %s -qnc/m '%s'",
			align, from, tostr, file);
		r_sandbox_system (cmd, 1);
		free (cmd);
		free (tostr);
		return 0;
	}
	if (mode == R_SEARCH_KEYWORD) {
		r_list_foreach (keywords, iter, kw) {
			if (hexstr) {
				r_search_kw_add (rs, r_search_keyword_new_hex (kw, mask, NULL));
			} else if (widestr) {
				r_search_kw_add (rs, r_search_keyword_new_wide (kw, mask, NULL, 0));
			} else {
				r_search_kw_add (rs, r_search_keyword_new_str (kw, mask, NULL, 0));
			}
		}
	} else if (mode == R_SEARCH_STRING) {
		r_search_kw_add (rs, r_search_keyword_new_hexmask ("00", NULL)); //XXX
	}

	curfile = file;
	r_search_begin (rs);
	r_io_seek (io, from, R_IO_SEEK_SET);
	//printf("; %s 0x%08"PFMT64x"-0x%08"PFMT64x"\n", file, from, to);
	for (cur = from; !last && cur < to; cur += bsize) {
		if ((cur + bsize) > to) {
			bsize = to - cur;
			last = true;
		}
		ret = r_io_pread_at (io, cur, buf, bsize);
		if (ret == 0) {
			if (nonstop) {
				continue;
			}
		//	eprintf ("Error reading at 0x%08"PFMT64x"\n", cur);
			return 1;
		}
		if (ret != bsize && ret > 0) {
			bsize = ret;
		}

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
	while ((c = getopt (argc, argv, "a:e:b:mM:s:S:x:Xzf:t:rnhvZ")) != -1) {
		switch (c) {
		case 'a':
			align = r_num_math (NULL, optarg);
			break;
		case 'r':
			rad = 1;
			break;
		case 'n':
			nonstop = 1;
			break;
		case 'm':
			mode = R_SEARCH_MAGIC;
			break;
		case 'e':
			mode = R_SEARCH_REGEXP;
			hexstr = 0;
			r_list_append (keywords, optarg);
			break;
		case 's':
			mode = R_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 0;
			r_list_append (keywords, optarg);
			break;
		case 'S':
			mode = R_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 1;
			r_list_append(keywords, optarg);
			break;
		case 'b':
			bsize = r_num_math (NULL, optarg);
			break;
		case 'x':
			mode = R_SEARCH_KEYWORD;
			hexstr = 1;
			widestr = 0;
			r_list_append (keywords, optarg);
			break;
		case 'M':
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
		default:
			return show_help (argv[0], 1);
		}
	}
	if (optind == argc) {
		return show_help (argv[0], 1);
	}
	for (; optind < argc; optind++) {
		rafind_open (argv[optind]);
	}
	return 0;
}
