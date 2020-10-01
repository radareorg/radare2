/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <stdio.h>
#include <stdlib.h>

#include <r_main.h>
#include <r_types.h>
#include <r_search.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <r_cons.h>
#include <r_lib.h>
#include <r_io.h>

// XXX kill those globals
static bool showstr = false;
static bool rad = false;
static bool identify = false;
static bool quiet = false;
static bool hexstr = false;
static bool widestr = false;
static bool nonstop = false;
static bool json = false;
static int mode = R_SEARCH_STRING;
static int align = 0;
static ut8 *buf = NULL;
static ut64 bsize = 4096;
static ut64 from = 0LL, to = -1;
static ut64 cur = 0;
static RPrint *pr = NULL;
static RList *keywords;
static const char *mask = NULL;
static const char *curfile = NULL;
static const char *comma = "";

static int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	int delta = addr - cur;
	if (cur > addr && (cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = cur - addr;
	}
	if (delta < 0 || delta >= bsize) {
		eprintf ("Invalid delta\n");
		return 0;
	}
	char _str[128];
	char *str = _str;
	*_str = 0;
	if (showstr) {
		if (widestr) {
			str = _str;
			int i, j = 0;
			for (i = delta; buf[i] && i < sizeof (_str); i++) {
				char ch = buf[i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!IS_PRINTABLE (ch)) {
					break;
				}
				str[j++] = ch;
				i++;
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
		} else {
			size_t i;
			for (i = 0; i < sizeof (_str); i++) {
				char ch = buf[delta + i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!ch || !IS_PRINTABLE (ch)) {
					break;
				}
				str[i] = ch;
			}
			str[i] = 0;
		}
	} else {
		size_t i;
		for (i = 0; i < sizeof (_str); i++) {
			char ch = buf[delta + i];
			if (ch == '"' || ch == '\\') {
				ch = '\'';
			}
			if (!ch || !IS_PRINTABLE (ch)) {
				break;
			}
			str[i] = ch;
		}
		str[i] = 0;
	}
	if (json) {
		const char *type = "string";
		printf ("%s{\"offset\":%"PFMT64d",\"type\":\"%s\",\"data\":\"%s\"}", comma, addr, type, str);
		comma = ",";
	} else if (rad) {
		printf ("f hit%d_%d 0x%08"PFMT64x" ; %s\n", 0, kw->count, addr, curfile);
	} else {
		if (showstr) {
			printf ("0x%"PFMT64x" %s\n", addr, str);
		} else {
			printf ("0x%"PFMT64x"\n", addr);
			if (pr) {
				r_print_hexdump (pr, addr, (ut8*)buf + delta, 78, 16, 1, 1);
				r_cons_flush ();
			}
		}
	}
	return 1;
}

static int show_help(const char *argv0, int line) {
	printf ("Usage: %s [-mXnzZhqv] [-a align] [-b sz] [-f/t from/to] [-[e|s|S] str] [-x hex] -|file|dir ..\n", argv0);
	if (line) {
		return 0;
	}
	printf (
	" -a [align] only accept aligned hits\n"
	" -b [size]  set block size\n"
	" -e [regex] search for regex matches (can be used multiple times)\n"
	" -f [from]  start searching from address 'from'\n"
	" -F [file]  read the contents of the file and use it as keyword\n"
	" -h         show this help\n"
	" -i         identify filetype (r2 -nqcpm file)\n"
	" -j         output in JSON\n"
	" -m         magic search, file-type carver\n"
	" -M [str]   set a binary mask to be applied on keywords\n"
	" -n         do not stop on read errors\n"
	" -r         print using radare commands\n"
	" -s [str]   search for a specific string (can be used multiple times)\n"
	" -S [str]   search for a specific wide string (can be used multiple times). Assumes str is UTF-8.\n"
	" -t [to]    stop search at address 'to'\n"
	" -q         quiet - do not show headings (filenames) above matching contents (default for searching a single file)\n"
	" -v         print version and exit\n"
	" -x [hex]   search for hexpair string (909090) (can be used multiple times)\n"
	" -X         show hexdump of search results\n"
	" -z         search for zero-terminated strings\n"
	" -Z         show string found on each search hit\n"
	);
	return 0;
}

static int rafind_open_file(const char *file, const ut8 *data, int datalen) {
	RListIter *iter;
	RSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	buf = NULL;
	if (!quiet) {
		printf ("File: %s\n", file);
	}

	char *efile = r_str_escape_sh (file);

	if (identify) {
		char *cmd = r_str_newf ("r2 -e search.show=false -e search.maxhits=1 -nqcpm \"%s\"", efile);
		r_sandbox_system (cmd, 1);
		free (cmd);
		free (efile);
		return 0;
	}

	RIO *io = r_io_new ();
	if (!io) {
		free (efile);
		return 1;
	}

	if (!r_io_open_nomap (io, file, R_PERM_R, 0)) {
		eprintf ("Cannot open file '%s'\n", file);
		result = 1;
		goto err;
	}

	if (data) {
		r_io_write_at (io, 0, data, datalen);
	}

	rs = r_search_new (mode);
	if (!rs) {
		result = 1;
		goto err;
	}

	buf = calloc (1, bsize);
	if (!buf) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", bsize);
		result = 1;
		goto err;
	}
	rs->align = align;
	r_search_set_callback (rs, &hit, buf);
	if (to == -1) {
		to = r_io_size (io);
	}

	if (!r_cons_new ()) {
		result = 1;
		goto err;
	}

	if (mode == R_SEARCH_STRING) {
		/* TODO: implement using api */
		r_sys_cmdf ("rabin2 -q%szzz \"%s\"", json? "j": "", efile);
		goto done;
	}
	if (mode == R_SEARCH_MAGIC) {
		/* TODO: implement using api */
		char *tostr = (to && to != UT64_MAX)?
			r_str_newf ("-e search.to=%"PFMT64d, to): strdup ("");
		r_sys_cmdf ("r2"
			" -e search.in=range"
			" -e search.align=%d"
			" -e search.from=%"PFMT64d
			" %s -qnc/m%s \"%s\"",
			align, from, tostr, json? "j": "", efile);
		free (tostr);
		goto done;
	}
	if (mode == R_SEARCH_ESIL) {
		/* TODO: implement using api */
		r_list_foreach (keywords, iter, kw) {
			r_sys_cmdf ("r2 -qc \"/E %s\" \"%s\"", kw, efile);
		}
		goto done;
	}
	if (mode == R_SEARCH_KEYWORD) {
		r_list_foreach (keywords, iter, kw) {
			if (hexstr) {
				if (mask) {
					r_search_kw_add (rs, r_search_keyword_new_hex (kw, mask, NULL));
				} else {
					r_search_kw_add (rs, r_search_keyword_new_hexmask (kw, NULL));
				}
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
	(void)r_io_seek (io, from, R_IO_SEEK_SET);
	result = 0;
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
			result = 1;
			break;
		}
		if (ret != bsize && ret > 0) {
			bsize = ret;
		}

		if (r_search_update (rs, cur, buf, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", cur);
			break;
		}
	}
done:
	r_cons_free ();
err:
	free (buf);
	free (efile);
	r_search_free (rs);
	r_io_free (io);
	return result;
}
static int rafind_open_dir(const char *dir);

static int rafind_open(const char *file) {
	if (!strcmp (file, "-")) {
		int sz = 0;
		ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
		char *ff = r_str_newf ("malloc://%d", sz);
		int res = rafind_open_file (ff, buf, sz);
		free (ff);
		free (buf);
		return res;
	}
	return r_file_is_directory (file)
		? rafind_open_dir (file)
		: rafind_open_file (file, NULL, -1);
}

static int rafind_open_dir(const char *dir) {
	RListIter *iter;
	char *fullpath;
	char *fname = NULL;

	RList *files = r_sys_dir (dir);

	if (files) {
		r_list_foreach (files, iter, fname) {
			/* Filter-out unwanted entries */
			if (*fname == '.') {
				continue;
			}
			fullpath = r_str_newf ("%s"R_SYS_DIR"%s", dir, fname);
			(void)rafind_open (fullpath);
			free (fullpath);
		}
		r_list_free (files);
	}
	return 0;
}

R_API int r_main_rafind2(int argc, const char **argv) {
	int c;
	const char *file = NULL;

	keywords = r_list_newf (NULL);
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "a:ie:b:jmM:s:S:x:Xzf:F:t:E:rqnhvZ");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			align = r_num_math (NULL, opt.arg);
			break;
		case 'r':
			rad = true;
			break;
		case 'i':
			identify = true;
			break;
		case 'j':
			json = true;
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
			r_list_append (keywords, (void*)opt.arg);
			break;
		case 'E':
			mode = R_SEARCH_ESIL;
			r_list_append (keywords, (void*)opt.arg);
			break;
		case 's':
			mode = R_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 0;
			r_list_append (keywords, (void*)opt.arg);
			break;
		case 'S':
			mode = R_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 1;
			r_list_append (keywords, (void*)opt.arg);
			break;
		case 'b':
			bsize = r_num_math (NULL, opt.arg);
			break;
		case 'M':
			// XXX should be from hexbin
			mask = opt.arg;
			break;
		case 'f':
			from = r_num_math (NULL, opt.arg);
			break;
		case 'F':
			{
				size_t data_size;
				char *data = r_file_slurp (opt.arg, &data_size);
				if (!data) {
					eprintf ("Cannot slurp '%s'\n", opt.arg);
					return 1;
				}
				char *hexdata = r_hex_bin2strdup ((ut8*)data, data_size);
				if (hexdata) {
					mode = R_SEARCH_KEYWORD;
					hexstr = true;
					widestr = false;
					r_list_append (keywords, (void*)hexdata);
				}
				free (data);
			}
			break;
		case 't':
			to = r_num_math (NULL, opt.arg);
			break;
		case 'x':
			mode = R_SEARCH_KEYWORD;
			hexstr = 1;
			widestr = 0;
			r_list_append (keywords, (void*)opt.arg);
			break;
		case 'X':
			pr = r_print_new ();
			break;
		case 'q':
			quiet = true;
			break;
		case 'v':
			return r_main_version_print ("rafind2");
		case 'h':
			return show_help(argv[0], 0);
		case 'z':
			mode = R_SEARCH_STRING;
			break;
		case 'Z':
			showstr = true;
			break;
		default:
			return show_help (argv[0], 1);
		}
	}
	if (opt.ind == argc) {
		return show_help (argv[0], 1);
	}
	/* Enable quiet mode if searching just a single file */
	if (opt.ind + 1 == argc && !r_file_is_directory (argv[opt.ind])) {
		quiet = true;
	}
	if (json) {
		printf ("[");
	}
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];

		if (file && !*file) {
			eprintf ("Cannot open empty path\n");
			return 1;
		}

		rafind_open (file);
	}
	if (json) {
		printf ("]\n");
	}
	return 0;
}
