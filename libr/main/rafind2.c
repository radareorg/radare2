/* radare - LGPL - Copyright 2009-2026 - pancake */

#define R_LOG_ORIGIN "rafind2"

#include <ctype.h>
#include <r_main.h>
#include <r_bin.h>
#include <r_search.h>
#include <r_util/r_print.h>

typedef struct {
	RCons *cons;
	RIO *io;
	RBin *bin;
	RList *hits;
	bool showstr;
	bool rad;
	bool color;
	bool identify;
	bool quiet;
	bool hexstr;
	bool widestr;
	bool nonstop;
	bool pluglist;
	bool bigendian;
	bool json;
	bool insert;
	bool replace;
	int mode;
	int align;
	ut8 *buf;
	ut64 bsize;
	ut64 from;
	ut64 to;
	ut64 cur;
	ut8 *repbuf;
	int replen;
	RPrint *pr;
	RList *keywords;
	const char *mask;
	const char *valstr;
	const char *curfile;
	const char *idfilter;
	PJ *pj;
} RafindOptions;

typedef struct {
	ut64 addr;
	ut32 len;
} ReplaceHit;

static void rafind_options_fini(RafindOptions *ro) {
	if (ro) {
		// 	r_io_free (ro->io);
		ro->io = NULL;
		free (ro->buf);
		free (ro->repbuf);
		ro->cur = 0;
		r_list_free (ro->hits);
		r_list_free (ro->keywords);
		ro->keywords = NULL;
		if (ro->bin) {
			r_bin_file_delete_all (ro->bin);
			r_bin_free (ro->bin);
			ro->bin = NULL;
		}
		r_cons_free2 (ro->cons);
	}
}

static void rafind_options_init(RafindOptions *ro) {
	memset (ro, 0, sizeof (RafindOptions));
	ro->mode = R_SEARCH_STRING;
	ro->bsize = 4096;
	ro->to = UT64_MAX;
	ro->color = true;
	ro->keywords = r_list_newf (NULL);
	ro->hits = r_list_newf (free);
	ro->pj = NULL;
	ro->cons = r_cons_new ();
}

static int rafind_open(RafindOptions *ro, const char *file);

static RBin *rafind_bin(RafindOptions *ro) {
	if (!ro->bin) {
		ro->bin = r_bin_new ();
	}
	if (ro->bin && ro->io) {
		r_io_bind (ro->io, &ro->bin->iob);
	}
	return ro->bin;
}
static bool rafind_info_match_token(const RBinInfo *info, const char *token) {
	if (R_STR_ISEMPTY (token) || !info) {
		return false;
	}
	if (r_str_isnumber (token)) {
		int bits = atoi (token);
		return info->bits == bits;
	}
	if (info->arch && r_str_casestr (info->arch, token)) {
		return true;
	}
	if (info->type && r_str_casestr (info->type, token)) {
		return true;
	}
	if (info->bclass && r_str_casestr (info->bclass, token)) {
		return true;
	}
	if (info->rclass && r_str_casestr (info->rclass, token)) {
		return true;
	}
	if (info->cpu && r_str_casestr (info->cpu, token)) {
		return true;
	}
	if (info->machine && r_str_casestr (info->machine, token)) {
		return true;
	}
	if (info->os && r_str_casestr (info->os, token)) {
		return true;
	}
	if (info->abi && r_str_casestr (info->abi, token)) {
		return true;
	}
	if (info->subsystem && r_str_casestr (info->subsystem, token)) {
		return true;
	}
	return false;
}

static bool rafind_info_match_filter(const RBinInfo *info, const char *filter) {
	if (R_STR_ISEMPTY (filter)) {
		return true;
	}
	char *tokens = strdup (filter);
	if (!tokens) {
		return false;
	}
	char *p;
	for (p = tokens; *p; p++) {
		if (*p == ',' || isspace ((ut8)*p)) {
			*p = ' ';
		}
	}
	int count = r_str_word_set0 (tokens);
	int i;
	for (i = 0; i < count; i++) {
		const char *token = r_str_word_get0 (tokens, i);
		if (!rafind_info_match_token (info, token)) {
			free (tokens);
			return false;
		}
	}
	free (tokens);
	return true;
}

static bool rafind_match_bininfo(RafindOptions *ro, const char *file) {
	if (!ro->idfilter) {
		return true;
	}
	RBin *bin = rafind_bin (ro);
	if (!bin) {
		return false;
	}
	bool match = false;
	r_bin_file_delete_all (bin);
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = file;
	if (r_bin_open (bin, file, &opt)) {
		const RBinInfo *info = r_bin_get_info (bin);
		match = rafind_info_match_filter (info, ro->idfilter);
		RBinFile *bf = r_bin_cur (bin);
		if (bf) {
			r_bin_file_delete (bin, bf->id);
		}
	}
	return match;
}

static bool rafind_replace_at(RafindOptions *ro, ut64 addr, ut32 match_len) {
	if (!ro->replace || !ro->repbuf || ro->replen < 0) {
		return false;
	}
	if (!ro->insert) {
		if (ro->replen > match_len) {
			R_LOG_WARN ("Replace string longer than match at 0x%08" PFMT64x, addr);
			return false;
		}
		r_io_write_at (ro->io, addr, ro->repbuf, ro->replen);
		return true;
	}
	ut64 size = r_io_size (ro->io);
	ut64 tail_off = addr + match_len;
	if (tail_off > size) {
		return false;
	}
	ut64 tail_len = size - tail_off;
	ut8 *tail = NULL;
	if (tail_len > 0) {
		tail = malloc (tail_len);
		if (!tail) {
			return false;
		}
		r_io_pread_at (ro->io, tail_off, tail, tail_len);
	}
	st64 delta = (st64)ro->replen - (st64)match_len;
	ut64 new_size = size + delta;
	if (delta > 0) {
		if (!r_io_resize (ro->io, new_size)) {
			free (tail);
			return false;
		}
	}
	r_io_write_at (ro->io, addr, ro->repbuf, ro->replen);
	if (tail_len > 0) {
		r_io_write_at (ro->io, addr + ro->replen, tail, tail_len);
	}
	if (delta < 0) {
		if (!r_io_resize (ro->io, new_size)) {
			free (tail);
			return false;
		}
	}
	free (tail);
	return true;
}
static int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RafindOptions *ro = (RafindOptions *)user;
	ut8 *buf = ro->buf;
	int delta = addr - ro->cur;
	if (ro->cur > addr && (ro->cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = ro->cur - addr;
	}
	if (delta > 0 && delta >= ro->bsize) {
		R_LOG_ERROR ("Invalid delta %d from 0x%08" PFMT64x, delta, addr);
		return 0;
	}
	if (delta != 0) {
		// rollback the buffer and reset the delta
		buf = calloc (1, ro->bsize * 2);
		if (!buf) {
			R_LOG_ERROR ("Cannot allocate")
			return 0;
		}
		r_io_pread_at (ro->io, addr, buf, ro->bsize * 2);
		delta = 0;
	}
	char _str[128];
	char *str = _str;
	*_str = 0;
	if (ro->showstr) {
		if (ro->widestr) {
			str = _str;
			int i, j = 0;
			for (i = delta; buf[i] && i < sizeof (_str) - 1; i++) {
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
			for (i = 0; i < sizeof (_str) - 1; i++) {
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
		for (i = 0; i < sizeof (_str) - 1; i++) {
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
	if (ro->json) {
		pj_o (ro->pj);
		pj_ks (ro->pj, "file", ro->curfile);
		pj_kn (ro->pj, "offset", addr);
		pj_ks (ro->pj, "type", "string");
		pj_ks (ro->pj, "data", str);
		pj_end (ro->pj);
	} else if (ro->rad) {
		printf ("f hit%d_%d = 0x%08" PFMT64x " # %s\n", 0, kw->count, addr, ro->curfile);
	} else {
		if (!ro->quiet) {
			printf ("%s: ", ro->curfile);
		}
		if (ro->showstr) {
			printf ("0x%" PFMT64x " %s\n", addr, str);
		} else {
			printf ("0x%" PFMT64x "\n", addr);
			if (ro->pr) {
				int bs = R_MIN (ro->bsize, 64);
				r_print_hexdump (ro->pr, addr, (ut8 *)buf + delta, bs, 16, 1, 1);
				r_cons_flush (ro->cons);
			}
		}
	}
	if (buf != ro->buf) {
		free (buf);
	}
	if (ro->replace) {
		if (kw->keyword_length > 0) {
			ReplaceHit *rh = R_NEW0 (ReplaceHit);
			rh->addr = addr;
			rh->len = kw->keyword_length;
			r_list_append (ro->hits, rh);
		}
	}
	return 1;
}

static bool rafind_parse_replace(RafindOptions *ro, const char *arg) {
	const char *s = arg;
	bool hex = false;
	bool wide = false;
	if (r_str_startswith (s, "h:")) {
		hex = true;
		s += 2;
	} else if (r_str_startswith (s, "w:")) {
		wide = true;
		s += 2;
	} else if (r_str_startswith (s, "s:")) {
		s += 2;
	}
	free (ro->repbuf);
	ro->repbuf = NULL;
	ro->replen = 0;
	if (hex) {
		int len = strlen (s);
		ut8 *buf = malloc (len + 1);
		if (!buf) {
			return false;
		}
		int outlen = r_hex_str2bin (s, buf);
		if (outlen < 1) {
			free (buf);
			return false;
		}
		ro->repbuf = buf;
		ro->replen = outlen;
		return true;
	}
	if (wide) {
		int len = strlen (s);
		char *str = malloc ((len + 1) * 2);
		if (!str) {
			return false;
		}
		const char *p2 = s;
		char *p = str;
		while (*p2) {
			RRune ch;
			const int num_utf8_bytes = r_utf8_decode ((const ut8 *)p2, s + len - p2, &ch);
			if (num_utf8_bytes < 1) {
				p[0] = *p2;
				p[1] = 0;
				p2++;
				p += 2;
				continue;
			}
			const int num_wide_bytes = ro->bigendian
				? r_utf16be_encode ((ut8 *)p, ch)
				: r_utf16le_encode ((ut8 *)p, ch);
			R_WARN_IF_FAIL (num_wide_bytes != 0);
			p2 += num_utf8_bytes;
			p += num_wide_bytes;
		}
		ro->repbuf = (ut8 *)str;
		ro->replen = p - str;
		return true;
	}
	ro->repbuf = (ut8 *)strdup (s);
	ro->replen = strlen (s);
	return true;
}

static int show_help(const char *argv0, int line) {
	printf ("Usage: %s [-mBXnzZhqv] [-a align] [-b sz] [-f/t from/to] [-[e|s|S] str] [-x hex] [-R str] [-I str] [-g] -|file|dir ..\n", argv0);
	if (line) {
		return 0;
	}
	printf (
		" -a [align] only accept aligned hits\n"
		" -b [size]  set block size\n"
		" -B         use big endian instead of the little one (See -V)\n"
		" -c         disable colourful output (mainly for for -X)\n"
		" -e [regex] search for regex matches (can be used multiple times)\n"
		" -E         perform a search using an esil expression\n"
		" -f [from]  start searching from address 'from'\n"
		" -F [file]  read the contents of the file and use it as keyword\n"
		" -g         allow resize while replacing (insert/grow mode)\n"
		" -h         show this help\n"
		" -i         identify filetype (r2 -nqcpm file)\n"
		" -I [str]   filter by rbin info (arch/type/bits/...) before searching\n"
		" -j         output in JSON\n"
		" -L         list all io plugins (same as r2 for now)\n"
		" -m         magic search, file-type carver\n"
		" -M [str]   set a binary mask to be applied on keywords\n"
		" -n         do not stop on read errors\n"
		" -r         print using radare commands\n"
		" -R [str]   replace each hit (prefix with h: hex, w: wide, s: string)\n"
		" -s [str]   search for a string (more than one string can be passed)\n"
		" -S [str]   search for a wide string (more than one string can be passed).\n"
		" -t [to]    stop search at address 'to'\n"
		" -q         quiet: fewer output do not show headings or filenames.\n"
		" -v         print version and exit\n"
		" -V [s:num | s:num1,num2] search for a value or range in the specified endian (-V 4:123 or -V 4:100,200)\n"
		" -x [hex]   search hexadecimal patterns. Inline nibble mask using `.` dots (94a2..34) (multiple keywords can be used)\n"
		" -X         show hexdump of search results\n"
		" -z         search for zero-terminated strings\n"
		" -Z         show string found on each search hit\n");
	return 0;
}

static int rafind_open_file(RafindOptions *ro, const char *file, const ut8 *data, int datalen) {
	RListIter *iter;
	RSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	ro->buf = NULL;
	r_list_free (ro->hits);
	ro->hits = r_list_newf (free);
	char *efile = r_str_escape_sh (file);

	if (ro->identify) {
		char *cmd = r_str_newf ("r2 -e search.show=false -e search.maxhits=1 -nqcpm \"%s\"", efile);
		r_sandbox_system (cmd, 1);
		free (cmd);
		free (efile);
		return 0;
	}

	RIO *io = r_io_new ();
	ro->io = io;
	int perm = ro->replace ? R_PERM_RW : R_PERM_R;
	if (!r_io_open_nomap (io, file, perm, 0)) {
		R_LOG_ERROR ("Cannot open file '%s'", file);
		result = 1;
		goto err;
	}

	if (ro->idfilter && !rafind_match_bininfo (ro, file)) {
		goto err;
	}

	if (data) {
		r_io_write_at (io, 0, data, datalen);
	}

	rs = r_search_new (ro->mode);
	if (!rs) {
		result = 1;
		goto err;
	}

	ro->buf = calloc (1, ro->bsize);
	if (!ro->buf) {
		R_LOG_ERROR ("Cannot allocate %" PFMT64d " bytes", ro->bsize);
		result = 1;
		goto err;
	}
	rs->align = ro->align;
	r_search_set_callback (rs, &hit, ro);
	ut64 to = ro->to;
	if (to == -1) {
		to = r_io_size (io);
	}

	if (ro->mode == R_SEARCH_STRING) {
		/* TODO: implement using api */
		r_sys_cmdf ("rabin2 -q%szzz \"%s\"", ro->json? "j": "", efile);
		goto done;
	}
	if (ro->mode == R_SEARCH_MAGIC) {
		/* TODO: implement using api */
		char *tostr = (to && to != UT64_MAX)? r_str_newf ("-e search.to=%" PFMT64d, to): strdup ("");
		r_sys_cmdf ("r2"
			" -e scr.color=%s"
			" -e search.in=range"
			" -e search.align=%d"
			" -e search.from=%" PFMT64d
			" %s -qnc/m%s \"%s\"",
			r_str_bool (ro->color),
			ro->align, ro->from, tostr, ro->json? "j": "", efile);
		free (tostr);
		goto done;
	}
	if (ro->mode == R_SEARCH_ESIL) {
		/* TODO: implement using api */
		r_list_foreach (ro->keywords, iter, kw) {
			r_sys_cmdf ("r2 -qc \"/E %s\" \"%s\"", kw, efile);
		}
		goto done;
	}
	if (ro->mode == R_SEARCH_KEYWORD) {
		r_list_foreach (ro->keywords, iter, kw) {
			RSearchKeyword *k = NULL;
			if (ro->hexstr) {
				if (ro->mask) {
					k = r_search_keyword_new_hex (kw, ro->mask, NULL);
				} else {
					k = r_search_keyword_new_hexmask (kw, NULL);
				}
			} else if (ro->widestr) {
				k = r_search_keyword_new_wide (kw, ro->mask, NULL, 0, ro->bigendian);
			} else {
				k = r_search_keyword_new_str (kw, ro->mask, NULL, 0);
			}
			if (k) {
				r_search_kw_add (rs, k);
			} else {
				R_LOG_ERROR ("Invalid keyword");
			}
		}
	}
	if (ro->mode == R_SEARCH_REGEXP) {
		r_list_foreach (ro->keywords, iter, kw) {
			r_search_kw_add (rs, r_search_keyword_new_regexp (kw, NULL));
		}
	}

	ro->curfile = file;
	r_search_begin (rs);
	(void)r_io_seek (io, ro->from, R_IO_SEEK_SET);
	result = 0;
	ut64 bsize = ro->bsize;
	for (ro->cur = ro->from; !last && ro->cur < to; ro->cur += bsize) {
		if ((ro->cur + bsize) > to) {
			bsize = to - ro->cur;
			last = true;
		}
		ret = r_io_pread_at (io, ro->cur, ro->buf, bsize);
		if (ret == 0) {
			if (ro->nonstop) {
				continue;
			}
			result = 1;
			break;
		}
		if (ret != bsize && ret > 0) {
			bsize = ret;
		}
		if (r_search_update (rs, ro->cur, ro->buf, ret) == -1) {
			R_LOG_ERROR ("search.update read error at 0x%08" PFMT64x, ro->cur);
			break;
		}
	}
	if (ro->replace && ro->repbuf && ro->replen > 0 && !r_list_empty (ro->hits)) {
		ReplaceHit *rh;
		RListIter *it;
		if (ro->insert) {
			r_list_foreach_prev (ro->hits, it, rh) {
				rafind_replace_at (ro, rh->addr, rh->len);
			}
		} else {
			r_list_foreach (ro->hits, it, rh) {
				rafind_replace_at (ro, rh->addr, rh->len);
			}
		}
	}
done:
//	r_cons_free2 (ro);
err:
	free (efile);
	r_io_free (io);
	r_search_free (rs);
	return result;
}

static int rafind_open_dir(RafindOptions *ro, const char *dir) {
	RListIter *iter;
	char *fname = NULL;

	RList *files = r_sys_dir (dir);

	if (files) {
		r_list_foreach (files, iter, fname) {
			/* Filter-out unwanted entries */
			if (*fname == '.') {
				continue;
			}
			char *fullpath = r_str_newf ("%s" R_SYS_DIR "%s", dir, fname);
			(void)rafind_open (ro, fullpath);
			free (fullpath);
		}
		r_list_free (files);
	}
	return 0;
}

static int rafind_open(RafindOptions *ro, const char *file) {
	if (!strcmp (file, "-")) {
		int sz = 0;
		ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
		if (!buf) {
			return 0;
		}
		char *ff = r_str_newf ("malloc://%d", sz);
		int res = rafind_open_file (ro, ff, buf, sz);
		free (ff);
		free (buf);
		return res;
	}
	return r_file_is_directory (file)
		? rafind_open_dir (ro, file)
		: rafind_open_file (ro, file, NULL, -1);
}

R_API int r_main_rafind2(int argc, const char **argv) {
	int c;
	const char *file = NULL;

	if (argc < 1) {
		return show_help (argv[0], 0);
	}

	RafindOptions ro;
	rafind_options_init (&ro);

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "a:ie:Eb:BcjmM:s:S:x:Xzf:F:t:E:rqnhvZLV:R:I:g");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			ro.align = r_num_math (NULL, opt.arg);
			break;
		case 'b':
			{
				int bs = (int)r_num_math (NULL, opt.arg);
				if (bs < 2) {
					rafind_options_fini (&ro);
					R_LOG_ERROR ("Invalid blocksize <= 1");
					return 1;
				}
				ro.bsize = bs;
			}
			break;
		case 'B':
			ro.bigendian = true;
			break;
		case 'c':
			ro.color = false;
			break;
		case 'r':
			ro.rad = true;
			break;
		case 'R':
			if (!rafind_parse_replace (&ro, opt.arg)) {
				rafind_options_fini (&ro);
				R_LOG_ERROR ("Invalid replace string");
				return 1;
			}
			ro.replace = true;
			break;
		case 'g':
			ro.insert = true;
			break;
		case 'I':
			ro.idfilter = opt.arg;
			break;
		case 'i':
			ro.identify = true;
			break;
		case 'L':
			ro.pluglist = true;
			break;
		case 'j':
			ro.json = true;
			break;
		case 'n':
			ro.nonstop = 1;
			break;
		case 'm':
			ro.mode = R_SEARCH_MAGIC;
			break;
		case 'e':
			ro.mode = R_SEARCH_REGEXP;
			ro.hexstr = 0;
			r_list_append (ro.keywords, (void *)opt.arg);
			break;
		case 'E':
			ro.mode = R_SEARCH_ESIL;
			r_list_append (ro.keywords, (void *)opt.arg);
			break;
		case 's':
			ro.mode = R_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = false;
			r_list_append (ro.keywords, (void *)opt.arg);
			break;
		case 'S':
			ro.mode = R_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = true;
			r_list_append (ro.keywords, (void *)opt.arg);
			break;
		case 'M':
			// XXX should be from hexbin
			ro.mask = opt.arg;
			break;
		case 'f':
			ro.from = r_num_math (NULL, opt.arg);
			break;
		case 'F':
			{
				size_t data_size;
				char *data = r_file_slurp (opt.arg, &data_size);
				if (!data) {
					R_LOG_ERROR ("Cannot slurp '%s'", opt.arg);
					return 1;
				}
				char *hexdata = r_hex_bin2strdup ((ut8 *)data, data_size);
				if (hexdata) {
					ro.mode = R_SEARCH_KEYWORD;
					ro.hexstr = true;
					ro.widestr = false;
					r_list_append (ro.keywords, (void *)hexdata);
				}
				free (data);
			}
			break;
		case 't':
			ro.to = r_num_math (NULL, opt.arg);
			break;
		case 'x':
			ro.mode = R_SEARCH_KEYWORD;
			ro.hexstr = true;
			ro.widestr = false;
			r_list_append (ro.keywords, (void *)opt.arg);
			break;
		case 'X':
			ro.pr = r_print_new ();
			break;
		case 'q':
			ro.quiet = true;
			break;
		case 'V':
			{
				char *arg = strdup (opt.arg);
				char *colon = strchr (arg, ':');
				char *comma = NULL;
				ut8 buf[8] = { 0 };
				int size = R_SYS_BITS_CHECK (R_SYS_BITS, 64)? 8: 4;
				ut64 value, min_value = 0, max_value = 0;

				if (colon) {
					*colon++ = 0;
					size = atoi (arg);
					size = R_MIN (8, size);
					size = R_MAX (1, size);
					comma = strchr (colon, ',');

					if (comma) {
						*comma++ = 0;
						min_value = r_num_math (NULL, colon);
						max_value = r_num_math (NULL, comma);
					} else {
						min_value = r_num_math (NULL, colon);
						max_value = min_value;
					}
				} else {
					min_value = r_num_math (NULL, arg);
					max_value = min_value;
				}
				for (value = min_value; value <= max_value; value++) {
					switch (size) {
				case 1:
						buf[0] = value;
						break;
				case 2:
						r_write_ble16 (buf, value, ro.bigendian);
						break;
				case 4:
						r_write_ble32 (buf, value, ro.bigendian);
						break;
				case 8:
						r_write_ble64 (buf, value, ro.bigendian);
						break;
					default:
						R_LOG_ERROR ("Invalid value size. Must be 1, 2, 4 or 8");
						rafind_options_fini (&ro);
						free (arg);
						return 1;
					}
					char *hexdata = r_hex_bin2strdup ((ut8 *)buf, size);
					if (hexdata) {
						ro.align = size;
						ro.mode = R_SEARCH_KEYWORD;
						ro.hexstr = true;
						ro.widestr = false;
						r_list_append (ro.keywords, (void *)hexdata);
					}
				}
				free (arg);
			}
			break;
		case 'v':
			rafind_options_fini (&ro);
			int mode = ro.json? 'j': ro.quiet? 'q'
							: 0;
			return r_main_version_print ("rafind2", mode);
		case 'h':
			rafind_options_fini (&ro);
			return show_help (argv[0], 0);
		case 'z':
			ro.mode = R_SEARCH_STRING;
			break;
		case 'Z':
			ro.showstr = true;
			break;
		default:
			return show_help (argv[0], 1);
		}
	}
	if (ro.pr) {
		if (ro.color) {
			ro.pr->flags |= R_PRINT_FLAGS_COLOR;
		} else {
			ro.pr->flags &= ~R_PRINT_FLAGS_COLOR;
		}
	}
	if (ro.pluglist) {
		// list search plugins when implemented
#if 0
		if (ro.json) {
			r_io_plugin_list_json (ro.io);
		} else {
			r_io_plugin_list (ro.io);
		}
#endif
		r_cons_flush (ro.cons);
		return 0;
	}
	if (opt.ind == argc) {
		return show_help (argv[0], 1);
	}
	if (ro.replace && ro.mode != R_SEARCH_KEYWORD) {
		R_LOG_ERROR ("Replace only supported for keyword searches (-s/-S/-x/-V/-F)");
		return 1;
	}
	/* Enable quiet mode if searching just a single file */
	if (opt.ind + 1 == argc && argv[opt.ind] && argv[opt.ind][0] && !r_file_is_directory (argv[opt.ind])) {
		ro.quiet = true;
	}
	if (ro.json && (ro.mode == R_SEARCH_KEYWORD || ro.mode == R_SEARCH_REGEXP)) {
		// TODO: remove mode check when all modes use api
		ro.pj = pj_new ();
		pj_a (ro.pj);
	}
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];
		if (file) {
			if (!*file) {
				R_LOG_ERROR ("Cannot open empty path");
				return 1;
			}
			rafind_open (&ro, file);
		}
	}
	r_list_free (ro.keywords);
	if (ro.pj) {
		pj_end (ro.pj);
		printf ("%s\n", pj_string (ro.pj));
		pj_free (ro.pj);
	}
	return 0;
}
