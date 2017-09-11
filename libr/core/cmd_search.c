/* radare - LGPL - Copyright 2010-2017 - pancake */

#include <stddef.h>

#include "r_core.h"
#include "r_io.h"
#include "r_list.h"
#include "r_types_base.h"
#include "cmd_search_rop.c"

static const char *help_msg_slash[] = {
	"Usage:", "/[amx/] [arg]", "Search stuff (see 'e??search' for options)\n"
	"|Use io.va for searching in non virtual addressing spaces",
	"/", " foo\\x00", "search for string 'foo\\0'",
	"/j", " foo\\x00", "search for string 'foo\\0' (json output)",
	"/!", " ff", "search for first occurrence not matching",
	"/+", " /bin/sh", "construct the string with chunks",
	"/!x", " 00", "inverse hexa search (find first byte != 0x00)",
	"//", "", "repeat last search",
	"/h", "[t] [hash] [len]", "find block matching this hash. See /#?",
	"/a", " jmp eax", "assemble opcode and search its bytes",
	"/A", " jmp", "find analyzed instructions of this type (/A? for help)",
	"/b", "", "search backwards",
	"/B", "", "search recognized RBin headers",
	"/c", " jmp [esp]", "search for asm code",
	"/C", "[ar]", "search for crypto materials",
	"/d", " 101112", "search for a deltified sequence of bytes",
	"/e", " /E.F/i", "match regular expression",
	"/E", " esil-expr", "offset matching given esil expressions %%= here",
	"/f", " file [off] [sz]", "search contents of file with offset and size",
	"/i", " foo", "search for string 'foo' ignoring case",
	"/m", " magicfile", "search for matching magic file (use blocksize)",
	"/o", " [n]", "show offset of n instructions backward",
	"/p", " patternsize", "search for pattern of given size",
	"/P", " patternsize", "search similar blocks",
	"/r[e]", "[?] sym.printf", "analyze opcode reference an offset (/re for esil)",
	"/R", " [grepopcode]", "search for matching ROP gadgets, semicolon-separated",
	"/v", "[1248] value", "look for an `cfg.bigendian` 32bit value",
	"/V", "[1248] min max", "look for an `cfg.bigendian` 32bit value in range",
	"/w", " foo", "search for wide string 'f\\0o\\0o\\0'",
	"/wi", " foo", "search for wide string ignoring case 'f\\0o\\0o\\0'",
	"/x", " ff..33", "search for hex string ignoring some nibbles",
	"/x", " ff0033", "search for hex string",
	"/x", " ff43:ffd0", "search for hexpair with mask",
	"/z", " min max", "search for strings of given size",
#if 0
	"\nConfiguration:", "", " (type `e??search.` for a complete list)",
	"e", " cmd.hit = x", "command to execute on every search hit",
	"e", " search.in = ?", "specify where to search stuff (depends on .from/.to)",
	"e", " search.align = 4", "only catch aligned search hits",
	"e", " search.from = 0", "start address",
	"e", " search.to = 0", "end address",
	"e", " search.flags = true", "if enabled store flags on keyword hits",
#endif
	NULL
};

static const char *help_msg_slash_c[] = {
	"Usage:", "/c [inst]", " Search for asm",
	"/c ", "instr", "search for instruction 'instr'",
	"/c/ ", "instr", "search for instruction that matches regexp 'instr'",
	"/c ", "instr1;instr2", "search for instruction 'instr1' followed by 'instr2'",
	"/c/ ", "instr1;instr2", "search for regex instruction 'instr1' followed by regex 'instr2'",
	"/cj ", "instr", "json output",
	"/c/j ", "instr", "regex search with json output",
	"/c* ", "instr", "r2 command output",
	NULL
};

static const char *help_msg_slash_C[] = {
	"Usage: /C", "", "Search for crypto materials",
	"/Ca", "", "Search for AES keys",
	"/Cr", "", "Search for private RSA keys",
	NULL
};

static const char *help_msg_slash_r[] = {
	"Usage:", "/r[e] [address]", " search references to this specific address",
	"/r", " [addr]", "search references to this specific address",
	"/re", " [addr]", "search references using esil",
	"/rc", "", "search for call references",
	"/ra", "", "search all references",
NULL
};

static const char *help_msg_slash_R[] = {
	"Usage: /R", "", "Search for ROP gadgets",
	"/R", " [filter-by-string]", "Show gadgets",
	"/R/", " [filter-by-regexp]", "Show gadgets [regular expression]",
	"/Rl", " [filter-by-string]", "Show gadgets in a linear manner",
	"/R/l", " [filter-by-regexp]", "Show gadgets in a linear manner [regular expression]",
	"/Rj", " [filter-by-string]", "JSON output",
	"/R/j", " [filter-by-regexp]", "JSON output [regular expression]",
	"/Rk", " [select-by-class]", "Query stored ROP gadgets",
	NULL
};

static const char *help_msg_slash_Rk[] = {
	"Usage: /Rk", "", "Query stored ROP gadgets",
	"/Rk", " [nop|mov|const|arithm|arithm_ct]", "Show gadgets",
	"/Rkj", "", "JSON output",
	"/Rkq", "", "List Gadgets offsets",
	NULL
};

static const char *help_msg_slash_x[] = {
	"Usage:", "/x [hexpairs]:[binmask]", "Search in memory",
	"/x ", "9090cd80", "search for those bytes",
	"/x ", "9090cd80:ffff7ff0", "search with binary mask",
	NULL
};

static int preludecnt = 0;
static int searchflags = 0;
static int searchshow = 0;
static int searchhits = 0;
static bool maplist = false;
static int maxhits = 0;
static bool json = false;
static int first_hit = true;
static const char *cmdhit = NULL;
static const char *searchprefix = NULL;
static unsigned int searchcount = 0;

struct search_parameters {
	RList *boundaries;
	const char *mode;
/*
	ut64 from;
	ut64 to;
*/
	bool inverse;
	bool crypto_search;
	bool bckwrds;
	bool do_bckwrd_srch;
	bool aes_search;
	bool rsa_search;
};

struct endlist_pair {
	int instr_offset;
	int delay_size;
};

static void cmd_search_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /, slash);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /c, slash_c);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /C, slash_C);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /r, slash_r);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /R, slash_R);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /Rk, slash_Rk);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, /x, slash_x);
}

static int search_hash(RCore *core, const char *hashname, const char *hashstr, ut32 minlen, ut32 maxlen) {
	RIOMap *map;
	ut8 *buf;
	int i, j;
	RList *list;
	RListIter *iter;

	list = r_core_get_boundaries_ok (core);
	if (!list) {
		eprintf ("Invalid boundaries\n");
		goto hell;
	}
	if (!minlen || minlen == UT32_MAX) {
		minlen = core->blocksize;
	}
	if (!maxlen || maxlen == UT32_MAX) {
		maxlen = minlen;
	}

	for (j = minlen; j <= maxlen; j++) {
		ut32 len = j;
		eprintf ("Searching %s for %d byte length.\n", hashname, j);
		r_list_foreach (list, iter, map) {
			ut64 from = map->from;
			ut64 to = map->to;
			st64 bufsz;
			if (from > to) {
				eprintf ("Invalid range (from > to)\n");
				continue;
			}
			bufsz = to - from;
			if (len > bufsz) {
				eprintf ("Hash length is bigger than range 0x%"PFMT64x "\n", from);
				continue;
			}
			buf = malloc (bufsz);
			if (!buf) {
				eprintf ("Cannot allocate %"PFMT64d " bytes\n", bufsz);
				goto hell;
			}
			eprintf ("Search in range 0x%08"PFMT64x " and 0x%08"PFMT64x "\n", from, to);
			int blocks = (int) (to - from - len);
			eprintf ("Carving %d blocks...\n", blocks);
			(void) r_io_read_at (core->io, from, buf, bufsz);
			for (i = 0; (from + i + len) < to; i++) {
				char *s = r_hash_to_string (NULL, hashname, buf + i, len);
				if (!(i % 5)) {
					eprintf ("%d\r", i);
				}
				if (!s) {
					eprintf ("Hash fail\n");
					break;
				}
				// eprintf ("0x%08"PFMT64x" %s\n", from+i, s);
				if (!strcmp (s, hashstr)) {
					eprintf ("Found at 0x%"PFMT64x "\n", from + i);
					r_cons_printf ("f hash.%s.%s = 0x%"PFMT64x "\n",
						hashname, hashstr, from + i);
					free (s);
					free (buf);
					r_list_free (list);
					return 1;
				}
				free (s);
			}
			free (buf);
		}
	}
	r_list_free (list);
	eprintf ("No hashes found\n");
	return 0;
hell:
	r_list_free (list);
	return -1;
}

static void cmd_search_bin(RCore *core, ut64 from, ut64 to) {
	RBinPlugin *plug;
	ut8 buf[1024];
	int size, sz = sizeof (buf);

	r_cons_break_push (NULL, NULL);
	while (from < to) {
		if (r_cons_is_breaked ()) {
			break;
		}
		r_io_read_at (core->io, from, buf, sz);
		plug = r_bin_get_binplugin_by_bytes (core->bin, buf, sz);
		if (plug) {
			r_cons_printf ("0x%08"PFMT64x "  %s\n", from, plug->name);
			// TODO: load the bin and calculate its size
			if (plug->size) {
				r_bin_load_io_at_offset_as_sz (core->bin, core->file->fd,
					0, 0, 0, core->offset, plug->name, 4096);
				size = plug->size (core->bin->cur);
				if (size > 0) {
					r_cons_printf ("size %d\n", size);
				}
			}
		}
		from++;
	}
	r_cons_break_pop ();
}

static int __prelude_cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *) user;
	int depth = r_config_get_i (core->config, "anal.depth");
	// eprintf ("ap: Found function prelude %d at 0x%08"PFMT64x"\n", preludecnt, addr);
	searchhits++;  // = kw->count+1;
	r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	preludecnt++;
	return true;
}

R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	ut64 at;
	ut8 *b = (ut8 *) malloc (core->blocksize);
	if (!b) {
		return 0;
	}
	// TODO: handle sections ?
	if (from >= to) {
		eprintf ("aap: Invalid search range 0x%08"PFMT64x " - 0x%08"PFMT64x "\n", from, to);
		free (b);
		return 0;
	}
	r_search_reset (core->search, R_SEARCH_KEYWORD);
	r_search_kw_add (core->search, r_search_keyword_new (buf, blen, mask, mlen, NULL));
	r_search_begin (core->search);
	r_search_set_callback (core->search, &__prelude_cb_hit, core);
	preludecnt = 0;
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (!r_io_is_valid_offset (core->io, at, 0)) {
			break;
		}
		(void)r_io_read_at (core->io, at, b, core->blocksize);
		if (r_search_update (core->search, &at, b, core->blocksize) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x "\n", at);
			break;
		}
	}
	free (b);
	return preludecnt;
}

static int count_functions(RCore *core) {
	return r_list_length (core->anal->fcns);
}

R_API int r_core_search_preludes(RCore *core) {
	int ret = -1;
	const char *prelude = r_config_get (core->config, "anal.prelude");
	const char *arch = r_config_get (core->config, "asm.arch");
	int bits = r_config_get_i (core->config, "asm.bits");
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	int fc0, fc1;
	int cfg_debug = r_config_get_i (core->config, "cfg.debug");
	const char *where = cfg_debug? "dbg.map": "io.sections.exec";

	RList *list = r_core_get_boundaries_prot (core, R_IO_EXEC, where);
	RListIter *iter;
	RIOMap *p;

	fc0 = count_functions (core);
	r_list_foreach (list, iter, p) {
		eprintf ("\r[>] Scanning %s 0x%"PFMT64x " - 0x%"PFMT64x " ", r_str_rwx_i (p->flags), p->from, p->to);
		if (!(p->flags & R_IO_EXEC)) {
			eprintf ("skip\n");
			continue;
		}
		from = p->from;
		to = p->to;
		if (prelude && *prelude) {
			ut8 *kw = malloc (strlen (prelude) + 1);
			int kwlen = r_hex_str2bin (prelude, kw);
			ret = r_core_search_prelude (core, from, to, kw, kwlen, NULL, 0);
			free (kw);
		} else if (strstr (arch, "ppc")) {
			ret = r_core_search_prelude (core, from, to,
				(const ut8 *) "\x7c\x08\x02\xa6", 4, NULL, 0);
		} else if (strstr (arch, "arm")) {
			switch (bits) {
			case 16:
				ret = r_core_search_prelude (core, from, to,
					(const ut8 *) "\xf0\xb5", 2, NULL, 0);
				break;
			case 32:
				ret = r_core_search_prelude (core, from, to,
					(const ut8 *) "\x00\x48\x2d\xe9", 4, NULL, 0);
				break;
			case 64:
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\xf6\x57\xbd\xa9", 4, NULL, 0);
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\xfd\x7b\xbf\xa9", 4, NULL, 0);
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\xfc\x6f\xbe\xa9", 4, NULL, 0);
				break;
			default:
				eprintf ("ap: Unsupported bits: %d\n", bits);
			}
		} else if (strstr (arch, "mips")) {
			ret = r_core_search_prelude (core, from, to,
				(const ut8 *) "\x27\xbd\x00", 3, NULL, 0);
		} else if (strstr (arch, "x86")) {
			switch (bits) {
			case 32:
				r_core_search_prelude (core, from, to, // mov edi, edi;push ebp; mov ebp,esp
					(const ut8 *) "\x8b\xff\x55\x8b\xec", 5, NULL, 0);
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\x55\x89\xe5", 3, NULL, 0);
				r_core_search_prelude (core, from, to, // push ebp; mov ebp, esp
					(const ut8 *) "\x55\x8b\xec", 3, NULL, 0);
				break;
			case 64:
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\x55\x48\x89\xe5", 4, NULL, 0);
				r_core_search_prelude (core, from, to,
					(const ut8 *) "\x55\x48\x8b\xec", 4, NULL, 0);
				break;
			default:
				eprintf ("ap: Unsupported bits: %d\n", bits);
			}
		} else {
			eprintf ("ap: Unsupported asm.arch and asm.bits\n");
		}
		eprintf ("done\n");
	}
	fc1 = count_functions (core);
	r_list_free (list);
	eprintf ("Analyzed %d functions based on preludes\n", fc1 - fc0);
	return ret;
}

/* TODO: maybe move into util/str */
static char *getstring(char *b, int l) {
	char *r, *res = malloc (l + 1);
	int i;
	if (!res) {
		return NULL;
	}
	for (i = 0, r = res; i < l; b++, i++) {
		if (IS_PRINTABLE (*b)) {
			*r++ = *b;
		}
	}
	*r = 0;
	return res;
}

static int __cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *) user;
	ut64 base_addr = 0;
	bool use_color;

	if (!core) {
		eprintf ("Error: Callback has an invalid RCore.\n");
		return false;
	}
	use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	if (maxhits && searchhits >= maxhits) {
		// eprintf ("Error: search.maxhits reached.\n");
		return false;
	}

	searchhits++;  ///= kw->count+1;
	if (searchcount) {
		if (!--searchcount) {
			// eprintf ("\nsearch stop: search.count reached\n");
			return false;
		}
	}
	if (searchshow && kw && kw->keyword_length > 0) {
		int len, i, extra, mallocsize;
		ut32 buf_sz = kw->keyword_length;
		ut8 *buf = malloc (buf_sz + 1);
		char *s = NULL, *str = NULL, *p = NULL;
		extra = (json)? 3: 1;
		const char *type = "hexpair";
		bool escaped = false;
		switch (kw->type) {
		case R_SEARCH_KEYWORD_TYPE_STRING:
		{
			const int ctx = 16;
			const int prectx = addr > 16 ? ctx : addr;
			char *pre, *pos, *wrd;
			const int len = kw->keyword_length;
			char *buf = calloc (1, len + 32 + ctx * 2);
			type = "string";
			r_core_read_at (core, addr - prectx, (ut8 *) buf, len + (ctx * 2));
			pre = getstring (buf, prectx);
			wrd = r_str_utf16_encode (buf + prectx, len);
			pos = getstring (buf + prectx + len, ctx);
			if (!pos) {
				pos = strdup ("");
			}
			free (buf);
			if (json) {
				char *pre_esc = r_str_escape (pre);
				char *pos_esc = r_str_escape (pos);
				s = r_str_newf ("%s%s%s", pre_esc, wrd, pos_esc);
				escaped = true;
				free (pre_esc);
				free (pos_esc);
			} else if (use_color) {
				s = r_str_newf (".%s"Color_YELLOW "%s"Color_RESET "%s.", pre, wrd, pos);
			} else {
				// s = r_str_newf ("\"%s"Color_INVERT"%s"Color_RESET"%s\"", pre, wrd, pos);
				s = r_str_newf ("\"%s%s%s\"", pre, wrd, pos);
			}
			free (pre);
			free (wrd);
			free (pos);
		}
			free (p);
			break;
		default:
			len = kw->keyword_length; // 8 byte context
			mallocsize = (len * 2) + extra;
			str = (len > 0xffff)? NULL: malloc (mallocsize);
			if (str) {
				p = str;
				memset (str, 0, len);
				r_core_read_at (core, base_addr + addr, buf, kw->keyword_length);
				if (json) {
					p = str;
				}
				const int bytes = (len > 40)? 40: len;
				for (i = 0; i < bytes; i++) {
					sprintf (p, "%02x", buf[i]);
					p += 2;
				}
				if (bytes != len) {
					strcpy (p, "...");
					p += 3;
				}
				*p = 0;
			} else {
				eprintf ("Cannot allocate %d\n", mallocsize);
			}
			s = str;
			str = NULL;
			break;
		}

		if (json) {
			if (!first_hit) {
				r_cons_printf (",");
			}
			char *es = escaped ? s : r_str_escape (s);
			r_cons_printf ("{\"offset\": %"PFMT64d ",\"id:\":%d,\"type\":\"%s\",\"data\":\"%s\"}",
				base_addr + addr, kw->kwidx, type, es);
			if (!escaped) {
				free (es);
			}
		} else {
			r_cons_printf ("0x%08"PFMT64x " %s%d_%d %s\n",
				base_addr + addr, searchprefix, kw->kwidx, kw->count, s);
		}
		free (s);
		free (buf);
		free (str);
	} else if (kw) {
		if (json) {
			if (!first_hit) {
				r_cons_printf (",");
			}
			r_cons_printf ("{\"offset\": %"PFMT64d ",\"id:\":%d,\"len\":%d}",
				base_addr + addr, kw->kwidx, kw->keyword_length);
		} else {
			if (searchflags) {
				r_cons_printf ("%s%d_%d\n", searchprefix, kw->kwidx, kw->count);
			} else {
				r_cons_printf ("f %s%d_%d %d 0x%08"PFMT64x "\n", searchprefix,
					kw->kwidx, kw->count, kw->keyword_length, base_addr + addr);
			}
		}
	}
	if (first_hit) {
		first_hit = false;
	}
	if (searchflags && kw) {
		const char *flag = sdb_fmt (0, "%s%d_%d", searchprefix, kw->kwidx, kw->count);
		r_flag_set (core->flags, flag, base_addr + addr, kw->keyword_length);
	}
	if (!STRNULL (cmdhit)) {
		ut64 here = core->offset;
		r_core_seek (core, base_addr + addr, true);
		r_core_cmd (core, cmdhit, 0);
		r_core_seek (core, here, true);
	}
	return true;
}

static int c = 0;

static inline void print_search_progress(ut64 at, ut64 to, int n) {
	if ((++c % 64) || (json)) {
		return;
	}
	if (r_cons_singleton ()->columns < 50) {
		eprintf ("\r[  ]  0x%08"PFMT64x "  hits = %d   \r%s",
			at, n, (c % 2)? "[ #]": "[# ]");
	} else {
		eprintf ("\r[  ]  0x%08"PFMT64x " < 0x%08"PFMT64x "  hits = %d   \r%s",
			at, to, n, (c % 2)? "[ #]": "[# ]");
	}
}

static void append_bound(RList *list, RIO *io, ut64 from, ut64 to) {
	// TODO: use rinterval
	RIOMap *map = R_NEW0 (RIOMap);
	if (io && io->desc) {
		map->fd = io->desc->fd;
	}
	map->from = from;
	map->to = to;
	r_list_append (list, map);
}

R_API RList *r_core_get_boundaries_prot(RCore *core, int protection, const char *mode) {
	RList *list = r_list_newf (free); // XXX r_io_map_free);
#if 0
	int fd = -1;
	if (core && core->io && core->io->cur) {
		fd = core->io->cur->fd; 
	}
#endif
	if (!core->io->va) {
		ut64 from = core->offset;
		ut64 to = r_io_size (core->io);
		append_bound (list, core->io, from, to);
	} else if (!strcmp (mode, "block")) {
		append_bound (list, core->io, core->offset, core->offset + core->blocksize);
	} else if (!strcmp (mode, "io.map")) {
		RIOMap *m = r_io_map_get (core->io, core->offset);
		if (m) {
			append_bound (list, core->io, m->from, m->to);
		}
	} else if (!strcmp (mode, "io.maps")) {
		SdbListIter *iter;
		RIOMap *m;
		ls_foreach (core->io->maps, iter, m) {
			RIOMap *map = R_NEW0 (RIOMap);
			if (map) {
				map->fd = m->fd;
				map->from = m->from;
				map->to = m->to;
				map->flags = m->flags;
				map->delta = m->delta;
				r_list_append (list, map);
			}
		}
	} else if (!strcmp (mode, "io.section")) {
		RIOSection *s = r_io_section_get (core->io, core->offset);
		if (s) {
			append_bound (list, core->io, s->vaddr, s->vaddr + s->vsize);
		}
	} else if (!strcmp (mode, "anal.fcn") || !strcmp (mode, "anal.bb")) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (f) {
			ut64 from = f->addr;
			ut64 to = f->addr + r_anal_fcn_size (f);

			/* Search only inside the basic block */
			if (!strcmp (mode, "anal.bb")) {
				RListIter *iter;
				RAnalBlock *bb;

				r_list_foreach (f->bbs, iter, bb) {
					ut64 at = core->offset;
					if ((at >= bb->addr) && (at < (bb->addr + bb->size))) {
						from = bb->addr;
						to = bb->addr + bb->size;
						break;
					}
				}
			}
			append_bound (list, core->io, from, to);
		} else {
			eprintf ("WARNING: search.in = ( anal.bb | anal.fcn )"\
				"requires to seek into a valid function\n");
			ut64 from = core->offset;
			ut64 to = core->offset + 1;
			append_bound (list, core->io, from, to);
		}
	} else if (!strncmp (mode, "io.sections", sizeof ("io.sections") - 1)) {
		int mask = 0;
		RIOMap *map;
		SdbListIter *iter;
		RIOSection *s;

		if (!strcmp (mode, "io.sections.exec")) {
			mask = R_IO_EXEC;
		}
		if (!strcmp (mode, "io.sections.write")) {
			mask = R_IO_WRITE;
		}

		ut64 from = UT64_MAX;
		ut64 to = 0;
		ls_foreach (core->io->sections, iter, s) {
			if (!mask || (s->flags & mask)) {
				map = R_NEW0 (RIOMap);
				if (!map) {
					eprintf ("RIOMap allocation failed\n");
					break;
				}
				map->fd = s->fd;
				map->from = s->vaddr;
				map->to = s->vaddr + s->vsize - 1;
				if (map->from && map->to) {
					if (map->from < from) {
						from = map->from;
					}
					if (map->to > to) {
						to = map->to;
					}
				}
				map->flags = s->flags;
				map->delta = 0;
				if (!(map->flags & protection)) {
					R_FREE (map);
					continue;
				}
				r_list_append (list, map);
			}
		}
	} else if (!strncmp (mode, "dbg.", 4)) {
		if (core->io->debug) {
			int mask = 0;
			int add = 0;
			bool heap = false;
			bool stack = false;
			bool all = false;
			bool first = false;
			RListIter *iter;
			RDebugMap *map;

			r_debug_map_sync (core->dbg);

			if (!strcmp (mode, "dbg.map")) {
				int perm = 0;
				ut64 from = core->offset;
				ut64 to = core->offset;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (from >= map->addr && from < map->addr_end) {
						from = map->addr;
						to = map->addr_end;
						perm = map->perm;
						break;
					}
				}
				if (perm) {
					RIOMap *nmap = R_NEW0 (RIOMap);
					if (nmap) {
						// nmap->fd = core->io->desc->fd;
						nmap->from = from;
						nmap->to = to;
						nmap->flags = perm;
						nmap->delta = 0;
						r_list_append (list, nmap);
					}
				}
			} else {
				if (!strcmp (mode, "dbg.program")) {
					first = true;
					mask = R_IO_EXEC;
				} else if (!strcmp (mode, "dbg.maps")) {
					all = true;
				} else if (!strcmp (mode, "dbg.maps.exec")) {
					mask = R_IO_EXEC;
				} else if (!strcmp (mode, "dbg.maps.write")) {
					mask = R_IO_WRITE;
				} else if (!strcmp (mode, "dbg.heap")) {
					heap = true;
				} else if (!strcmp (mode, "dbg.stack")) {
					stack = true;
				}

				ut64 from = UT64_MAX;
				ut64 to = 0;
				r_list_foreach (core->dbg->maps, iter, map) {
					add = (stack && strstr (map->name, "stack"))? 1: 0;
					if (!add && (heap && (map->perm & R_IO_WRITE)) && strstr (map->name, "heap")) {
						add = 1;
					}
					if ((mask && (map->perm & mask)) || add || all) {
						if (!list) {
							list = r_list_newf (free);
							maplist = true;
						}
						RIOMap *nmap = R_NEW0 (RIOMap);
						if (!nmap) {
							break;
						}
						nmap->from = map->addr;
						nmap->to = map->addr_end;
						if (nmap->from && nmap->to) {
							if (nmap->from < from) {
								from = nmap->from;
							}
							if (nmap->to > to) {
								to = nmap->to;
							}
						}
						nmap->flags = map->perm;
						nmap->delta = 0;
						r_list_append (list, nmap);
						if (first) {
							break;
						}
					}
				}
			}
		}
	} else {
		// if (!strcmp (mode, "raw")) {
		/* obey temporary seek if defined '/x 8080 @ addr:len' */
		if (core->tmpseek) {
			ut64 from = core->offset;
			ut64 to = core->offset + core->blocksize;
			append_bound (list, core->io, from, to);
		} else {
			// TODO: repeat last search doesnt works for /a
			ut64 from = r_config_get_i (core->config, "search.from");
			if (from == UT64_MAX) {
				from = core->offset;
			}
			ut64 to = r_config_get_i (core->config, "search.to");
			if (to == UT64_MAX) {
				if (core->io->va) {
					/* TODO: section size? */
				} else {
					if (core->file) {
						to = r_io_fd_size (core->io, core->file->fd);
					}
				}
			}
			append_bound (list, core->io, from, to);
		}
	}
	if (r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

// XXX: deprecate and use _ok function only
R_API RList *r_core_get_boundaries(RCore *core, const char *mode) {
	return r_core_get_boundaries_prot (core, R_IO_EXEC | R_IO_WRITE | R_IO_READ, mode);
}

static bool is_end_gadget(const RAnalOp *aop, const ut8 crop) {
	switch (aop->type) {
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CALL:
		return true;
	}
	if (crop) { // if conditional jumps, calls and returns should be used for the gadget-search too
		switch (aop->type) {
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_UCJMP:
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_UCCALL:
		case R_ANAL_OP_TYPE_CRET:   // i'm a condret
			return true;
		}
	}
	return false;
}

// TODO: follow unconditional jumps
static RList *construct_rop_gadget(RCore *core, ut64 addr, ut8 *buf, int idx,
                                   const char *grep, int regex, RList *rx_list, struct endlist_pair *end_gadget,
                                   RList *badstart, int *max_count) {
	int endaddr = end_gadget->instr_offset;
	int branch_delay = end_gadget->delay_size;
	RAsmOp asmop;
	const char *start = NULL, *end = NULL;
	char *grep_str = NULL;
	RCoreAsmHit *hit = NULL;
	RList *hitlist = r_core_asm_hit_list_new ();
	ut8 nb_instr = 0;
	const ut8 max_instr = r_config_get_i (core->config, "rop.len");
	bool valid = false;
	int grep_find;
	int search_hit;
	char *rx = NULL;
	RList /*<intptr_t>*/ *localbadstart = r_list_new ();
	RListIter *iter;
	void *p;
	int count = 0;

	if (*max_count == 0) {
		r_list_free (localbadstart);
		r_list_free (hitlist);
		return NULL;
	}
	if (grep) {
		start = grep;
		end = strstr (grep, ";");
		if (!end) { // We filter on a single opcode, so no ";"
			end = start + strlen (grep);
		}
		grep_str = calloc (1, end - start + 1);
		strncpy (grep_str, start, end - start);
		if (regex) {
			// get the first regexp.
			if (r_list_length (rx_list) > 0) {
				rx = r_list_get_n (rx_list, count++);
			}
		}
	}

	if (r_list_contains (badstart, (void *) (intptr_t) idx)) {
		valid = false;
		goto ret;
	}
	while (nb_instr < max_instr) {
		r_list_append (localbadstart, (void *) (intptr_t) idx);
		r_asm_set_pc (core->assembler, addr);
		if (!r_asm_disassemble (core->assembler, &asmop, buf + idx, 15)) {
			goto ret;
		}
		if (!strncasecmp (asmop.buf_asm, "invalid", strlen ("invalid")) ||
		    !strncasecmp (asmop.buf_asm, ".byte", strlen (".byte"))) {
			valid = false;
			goto ret;
		}

		hit = r_core_asm_hit_new ();
		hit->addr = addr;
		hit->len = asmop.size;
		r_list_append (hitlist, hit);

		// Move on to the next instruction
		idx += asmop.size;
		addr += asmop.size;
		if (rx) {
			// grep_find = r_regex_exec (rx, asmop.buf_asm, 0, 0, 0);
			grep_find = !r_regex_match (rx, "e", asmop.buf_asm);
			search_hit = (end && grep && (grep_find < 1));
		} else {
			search_hit = (end && grep && strstr (asmop.buf_asm, grep_str));
		}

		// Handle (possible) grep
		if (search_hit) {
			if (end[0] == ';') { // fields are semicolon-separated
				start = end + 1; // skip the ;
				end = strstr (start, ";");
				end = end? end: start + strlen (start); // latest field?
				free (grep_str);
				grep_str = calloc (1, end - start + 1);
				strncpy (grep_str, start, end - start);
			} else {
				end = NULL;
			}
			if (regex) {
				rx = r_list_get_n (rx_list, count++);
			}
		}

		if (endaddr <= (idx - asmop.size)) {
			valid = (endaddr == idx - asmop.size);
			goto ret;
		}
		nb_instr++;
	}
ret:
	free (grep_str);
	if (regex && rx) {
		r_list_free (hitlist);
		r_list_free (localbadstart);
		return NULL;
	}
	if (!valid || (grep && end)) {
		r_list_free (hitlist);
		r_list_free (localbadstart);
		return NULL;
	}
	r_list_foreach (localbadstart, iter, p) {
		r_list_append (badstart, p);
	}
	r_list_free (localbadstart);
	// If our arch has bds then we better be including them
	if (branch_delay && r_list_length (hitlist) < (1 + branch_delay)) {
		r_list_free (hitlist);
		return NULL;
	}
	*max_count = *max_count - 1;
	return hitlist;
}

static void print_rop(RCore *core, RList *hitlist, char mode, bool *json_first) {
	const char *otype;
	RCoreAsmHit *hit = NULL;
	RListIter *iter;
	RList *ropList = NULL;
	char *buf_asm;
	unsigned int size = 0;
	RAnalOp analop = R_EMPTY;
	RAsmOp asmop;
	Sdb *db = NULL;
	const bool colorize = r_config_get_i (core->config, "scr.color");
	const bool rop_comments = r_config_get_i (core->config, "rop.comments");
	const bool esil = r_config_get_i (core->config, "asm.esil");
	const bool rop_db = r_config_get_i (core->config, "rop.db");

	if (rop_db) {
		db = sdb_ns (core->sdb, "rop", true);
		ropList = r_list_newf (free);
		if (!db) {
			eprintf ("Error: Could not create SDB 'rop' namespace\n");
			r_list_free (ropList);
			return;
		}
	}

	switch (mode) {
	case 'j':
		// Handle comma between gadgets
		if (*json_first) {
			*json_first = 0;
		} else {
			r_cons_strcat (",");
		}
		r_cons_printf ("{\"opcodes\":[");
		r_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc (hit->len);
			r_core_read_at (core, hit->addr, buf, hit->len);
			r_asm_set_pc (core->assembler, hit->addr);
			r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			r_cons_printf ("{\"offset\":%"PFMT64d ",\"size\":%d,"
				"\"opcode\":\"%s\",\"type\":\"%s\"}%s",
				hit->addr, hit->len, asmop.buf_asm,
				r_anal_optype_to_string (analop.type),
				iter->n? ",": "");
			free (buf);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt (0, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
			r_cons_printf ("],\"retaddr\":%"PFMT64d ",\"size\":%d}", hit->addr, size);
		} else if (hit) {
			r_cons_printf ("],\"retaddr\":%"PFMT64d ",\"size\":%d}", hit->addr, size);
		}
		break;
	case 'l':
		// Print gadgets in a 'linear manner', each sequence
		// on one line.
		r_cons_printf ("0x%08"PFMT64x ":",
			((RCoreAsmHit *) hitlist->head->data)->addr);
		r_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc (hit->len);
			r_core_read_at (core, hit->addr, buf, hit->len);
			r_asm_set_pc (core->assembler, hit->addr);
			r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len);
			size += hit->len;
			const char *opstr = R_STRBUF_SAFEGET (&analop.esil);
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", opstr);
				r_list_append (ropList, (void *) opstr_n);
			}
			if (esil) {
				r_cons_printf ("%s\n", opstr);
			} else if (colorize) {
				buf_asm = r_print_colorize_opcode (core->print, asmop.buf_asm,
					core->cons->pal.reg, core->cons->pal.num, false);
				r_cons_printf (" %s%s;", buf_asm, Color_RESET);
				free (buf_asm);
			} else {
				r_cons_printf (" %s;", asmop.buf_asm);
			}
			free (buf);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt (0, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
		break;
	default:
		// Print gadgets with new instruction on a new line.
		r_list_foreach (hitlist, iter, hit) {
			char *comment = rop_comments? r_meta_get_string (core->anal,
				R_META_TYPE_COMMENT, hit->addr): NULL;
			if (hit->len < 0) {
				eprintf ("Invalid hit length here\n");
				continue;
			}
			ut8 *buf = malloc (1 + hit->len);
			buf[hit->len] = 0;
			r_core_read_at (core, hit->addr, buf, hit->len);
			r_asm_set_pc (core->assembler, hit->addr);
			r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			if (colorize) {
				buf_asm = r_print_colorize_opcode (core->print, asmop.buf_asm,
					core->cons->pal.reg, core->cons->pal.num, false);
				otype = r_print_color_op_type (core->print, analop.type);
				if (comment) {
					r_cons_printf ("  0x%08"PFMT64x " %18s%s  %s%s ; %s\n",
						hit->addr, asmop.buf_hex, otype, buf_asm, Color_RESET, comment);
				} else {
					r_cons_printf ("  0x%08"PFMT64x " %18s%s  %s%s\n",
						hit->addr, asmop.buf_hex, otype, buf_asm, Color_RESET);
				}
				free (buf_asm);
			} else {
				if (comment) {
					r_cons_printf ("  0x%08"PFMT64x " %18s  %s ; %s\n",
						hit->addr, asmop.buf_hex, asmop.buf_asm, comment);
				} else {
					r_cons_printf ("  0x%08"PFMT64x " %18s  %s\n",
						hit->addr, asmop.buf_hex, asmop.buf_asm);
				}
			}
			free (buf);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			const char *key = sdb_fmt (0, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
	}
	if (mode != 'j') {
		r_cons_newline ();
	}
	r_list_free (ropList);
}

R_API RList *r_core_get_boundaries_ok(RCore *core) {
	const char *searchin;
	ut8 prot;
	ut64 from, to;
	ut64 __from, __to;
	RList *list;
	if (!core) {
		return NULL;
	}
	prot = r_config_get_i (core->config, "rop.nx")?
	       R_IO_READ | R_IO_WRITE | R_IO_EXEC: R_IO_EXEC;
	searchin = r_config_get (core->config, "search.in");

	from = core->offset;
	to = core->offset + core->blocksize;

	__from = r_config_get_i (core->config, "search.from");
	__to = r_config_get_i (core->config, "search.to");
	if (__from != UT64_MAX) {
		from = __from;
	}
	if (__to != UT64_MAX) {
		to = __to;
	}

	if (!strncmp (searchin, "dbg.", 4)\
	    || !strncmp (searchin, "io.sections", 11)\
	    || prot & R_IO_EXEC) { /* always true */
		list = r_core_get_boundaries_prot (core, prot, searchin);
	} else {
		list = NULL;
	}
	if (!list) {
		RIOMap *map = R_NEW0 (RIOMap);
		if (!map) {
			eprintf ("Cannot allocate map\n");
			return NULL;
		}
		map->fd = core->io->desc->fd;
		map->from = from;
		map->to = to;
		list = r_list_newf (free);
		r_list_append (list, map);
	}
	return list;
}
static int r_core_search_rop(RCore *core, ut64 from, ut64 to, int opt, const char *grep, int regexp) {
	const ut8 crop = r_config_get_i (core->config, "rop.conditional");      // decide if cjmp, cret, and ccall should be used too for the gadget-search
	const ut8 subchain = r_config_get_i (core->config, "rop.subchains");
	const ut8 max_instr = r_config_get_i (core->config, "rop.len");
	const ut8 prot = r_config_get_i (core->config, "rop.nx")? R_IO_READ | R_IO_WRITE | R_IO_EXEC: R_IO_EXEC;
	const char *smode = r_config_get (core->config, "search.in");
	const char *arch = r_config_get (core->config, "asm.arch");
	int max_count = r_config_get_i (core->config, "search.count");
	ut64 search_from = r_config_get_i (core->config, "search.from");
	ut64 search_to = r_config_get_i (core->config, "search.to");
	int i = 0, end = 0, mode = 0, increment = 1, ret;
	RList /*<endlist_pair>*/ *end_list = r_list_newf (free);
	RList /*<intptr_t>*/ *badstart = r_list_new ();
	RList /*<RRegex>*/ *rx_list = NULL;
	RList /*<RIOMap>*/ *list = NULL;
	int align = core->search->align;
	RListIter *itermap = NULL;
	char *tok, *gregexp = NULL;
	char *grep_arg = NULL;
	bool json_first = true;
	char *rx = NULL;
	int delta = 0;
	ut8 *buf;
	RIOMap *map;
	RAsmOp asmop;

	if (max_count == 0) {
		max_count = -1;
	}
	if (max_instr <= 1) {
		r_list_free (badstart);
		r_list_free (end_list);
		eprintf ("ROP length (rop.len) must be greater than 1.\n");
		if (max_instr == 1) {
			eprintf ("For rop.len = 1, use /c to search for single "
				"instructions. See /c? for help.\n");
		}
		return false;
	}
	if (search_from == UT64_MAX) {
		search_from = 0;
	}

	if (!strcmp (arch, "mips")) { // MIPS has no jump-in-the-middle
		increment = 4;
	} else if (!strcmp (arch, "arm")) { // ARM has no jump-in-the-middle
		increment = r_config_get_i (core->config, "asm.bits") == 16? 2: 4;
	} else if (!strcmp (arch, "avr")) { // AVR is halfword aligned.
		increment = 2;
	}

	// Options, like JSON, linear, ...
	grep_arg = strchr (grep, ' ');
	if (*grep) {
		if (grep_arg) {
			mode = *(grep_arg - 1);
			grep = grep_arg;
		} else {
			mode = *grep;
			++grep;
		}
	}

	if (*grep == ' ') { // grep mode
		for (++grep; *grep == ' '; grep++) {
			;
		}
	} else {
		grep = NULL;
	}

	// Deal with the grep guy.
	if (grep && regexp) {
		if (!rx_list) {
			rx_list = r_list_newf (free);
		}
		gregexp = strdup (grep);
		tok = strtok (gregexp, ";");
		while (tok) {
			rx = strdup (tok);
			r_list_append (rx_list, rx);
			tok = strtok (NULL, ";");
		}
	}

	maxhits = r_config_get_i (core->config, "search.maxhits");
	if (!strncmp (smode, "dbg.", 4)\
	    || !strncmp (smode, "io.sections", 11)\
	    || prot & R_IO_EXEC) {
		list = r_core_get_boundaries_prot (core, prot, smode);
	} else {
		list = NULL;
	}

	if (!list) {
		map = R_NEW0 (RIOMap);
		if (!map) {
			eprintf ("Cannot allocate map\n");
			free (gregexp);
			r_list_free (rx_list);
			r_list_free (end_list);
			r_list_free (badstart);
			r_list_free (list);
			return false;
		}
		map->fd = core->io->desc->fd;
		map->from = from;
		map->to = to;
		list = r_list_newf (free);
		r_list_append (list, map);
		maplist = true;
	}

	if (json) {
		r_cons_printf ("[");
	}
	r_cons_break_push (NULL, NULL);

	r_list_foreach (list, itermap, map) {
		from = map->from;
		to = map->to;
		if (to > search_to) {
			if (to < from) {
				continue;
			}
			to = search_to;
		}
		if (from < search_from) {
			if (search_from > to) {
				continue;
			}
			from = search_from;
		}

		if (from > to) {
			eprintf ("Invalid range 0x%"PFMT64x " - 0x%"PFMT64x "\n", from, to);
			continue;
		}
		if (r_cons_is_breaked ()) {
			break;
		}
		delta = to - from;
		if (delta < 1) {
			delta = from - to;
			if (delta < 1) {
				free (gregexp);
				r_list_free (rx_list);
				r_list_free (end_list);
				r_list_free (badstart);
				r_list_free (list);
				return false;
			}
		}

		buf = calloc (1, delta);
		if (!buf) {
			free (gregexp);
			r_list_free (rx_list);
			r_list_free (end_list);
			r_list_free (badstart);
			r_list_free (list);
			return -1;
		}
		(void) r_io_read_at (core->io, from, buf, delta);

		// Find the end gadgets.
		for (i = 0; i + 32 < delta; i += increment) {
			RAnalOp end_gadget = R_EMPTY;
			// Disassemble one.
			if (r_anal_op (core->anal, &end_gadget, from + i, buf + i,
				    delta - i) <= 0) {
				r_anal_op_fini (&end_gadget);
				continue;
			}
			if (is_end_gadget (&end_gadget, crop)) {
				struct endlist_pair *epair;
				if (maxhits && r_list_length (end_list) >= maxhits) {
					// limit number of high level rop gadget results
					r_anal_op_fini (&end_gadget);
					break;
				}
				epair = R_NEW0 (struct endlist_pair);
				// If this arch has branch delay slots, add the next instr as well
				if (end_gadget.delay) {
					epair->instr_offset = i + increment;
					epair->delay_size = end_gadget.delay;
					r_list_append (end_list, (void *) (intptr_t) epair);
				} else {
					epair->instr_offset = (intptr_t) i;
					epair->delay_size = end_gadget.delay;
					r_list_append (end_list, (void *) epair);
				}
			}
			r_anal_op_fini (&end_gadget);
			if (r_cons_is_breaked ()) {
				break;
			}
			// Right now we have a list of all of the end/stop gadgets.
			// We can just construct gadgets from a little bit before them.
		}
		r_list_reverse (end_list);
		// If we have no end gadgets, just skip all of this search nonsense.
		if (r_list_length (end_list) > 0) {
			int prev, next, ropdepth;
			const int max_inst_size_x86 = 15;
			// Get the depth of rop search, should just be max_instr
			// instructions, x86 and friends are weird length instructions, so
			// we'll just assume 15 byte instructions.
			ropdepth = increment == 1?
			           max_instr * max_inst_size_x86 /* wow, x86 is long */:
			           max_instr * increment;
			if (r_cons_is_breaked ()) {
				break;
			}
			struct endlist_pair *end_gadget = (struct endlist_pair *) r_list_pop (end_list);
			next = end_gadget->instr_offset;
			prev = 0;
			// Start at just before the first end gadget.
			for (i = next - ropdepth; i < (delta - max_inst_size_x86) && max_count != 0; i += increment) {
				if (increment == 1) {
					// give in-boundary instructions a shot
					if (i < prev - max_inst_size_x86) {
						i = prev - max_inst_size_x86;
					}
				} else {
					if (i < prev) {
						i = prev;
					}
				}
				if (i < 0) {
					i = 0;
				}
				if (r_cons_is_breaked ()) {
					break;
				}
				if (i >= next) {
					// We've exhausted the first end-gadget section,
					// move to the next one.
					if (r_list_get_n (end_list, 0)) {
						prev = i;
						free (end_gadget);
						end_gadget = (struct endlist_pair *) r_list_pop (end_list);
						next = end_gadget->instr_offset;
						i = next - ropdepth;
						if (i < 0) {
							i = 0;
						}
					} else {
						break;
					}
				}
				if (i >= end) { // read by chunk of 4k
					r_core_read_at (core, from + i, buf + i,
						R_MIN ((delta - i), 4096));
					end = i + 2048;
				}
				ret = r_asm_disassemble (core->assembler, &asmop, buf + i, delta - i);
				if (ret) {
					RList *hitlist;
					r_asm_set_pc (core->assembler, from + i);
					hitlist = construct_rop_gadget (core,
						from + i, buf, i, grep, regexp,
						rx_list, end_gadget, badstart, &max_count);
					if (!hitlist) {
						continue;
					}
					if (align && (0 != ((from + i) % align))) {
						continue;
					}
					if (json) {
						mode = 'j';
					}
					if ((mode == 'l') && subchain) {
						do {
							print_rop (core, hitlist, mode, &json_first);
							hitlist->head = hitlist->head->n;
						} while (hitlist->head->n);
					} else {
						print_rop (core, hitlist, mode, &json_first);
					}
				}
				if (increment != 1) {
					i = next;
				}
			}
		}
		r_list_purge (badstart);
		free (buf);
	}
	if (r_cons_is_breaked ()) {
		eprintf ("\n");
	}
	r_cons_break_pop ();

	if (json) {
		r_cons_printf ("]\n");
	}
	r_list_free (list);
	r_list_free (rx_list);
	r_list_free (end_list);
	r_list_free (badstart);
	free (gregexp);

	return true;
}

static int esil_addrinfo(RAnalEsil *esil) {
	RCore *core = (RCore *) esil->cb.user;
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		num = r_core_anal_address (core, num);
		r_anal_esil_pushnum (esil, num);
	} else {
// error. empty stack?
		return 0;
	}
	free (src);
	return 1;
}

static void do_esil_search(RCore *core, struct search_parameters *param, const char *input) {
	const int hit_combo_limit = r_config_get_i (core->config, "search.esilcombo");
	RSearchKeyword kw = R_EMPTY;
	searchhits = 0;
	if (input[0] == 'E' && input[1] != ' ') {
		eprintf ("Usage: /E [esil-expr]\n");
		return;
	}
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (param->boundaries, iter, map) {
		const int kwidx = r_config_get_i (core->config, "search.kwidx");
		const int iotrap = r_config_get_i (core->config, "esil.iotrap");
		const int stacksize = r_config_get_i (core->config, "esil.stacksize");
		int nonull = r_config_get_i (core->config, "esil.nonull");
		int hit_happens = 0;
		int hit_combo = 0;
		char *res;
		ut64 nres, addr = map->from;
		if (!core->anal->esil) {
			core->anal->esil = r_anal_esil_new (stacksize, iotrap);
		}
		if (!core->anal->esil) {
			return;
		}
		/* hook addrinfo */
		core->anal->esil->cb.user = core;
		r_anal_esil_set_op (core->anal->esil, "AddrInfo", esil_addrinfo);
		/* hook addrinfo */
		r_anal_esil_setup (core->anal->esil, core->anal, 1, 0, nonull);
		r_anal_esil_stack_free (core->anal->esil);
		core->anal->esil->verbose = 0;

		r_cons_break_push (NULL, NULL);
		for (; addr < map->to; addr++) {
			if (core->search->align) {
				if ((addr % core->search->align)) {
					continue;
				}
			}
#if 0
			// we need a way to retrieve info from a speicif address, and make it accessible from the esil search
			// maybe we can just do it like this: 0x804840,AddressType,3,&, ... bitmask
			// executable = 1
			// writable = 2
			// inprogram
			// instack
			// inlibrary
			// inheap
			r_anal_esil_set_op (core->anal->esil, "AddressInfo", esil_search_address_info);
#endif
			if (r_cons_is_breaked ()) {
				eprintf ("Breaked at 0x%08"PFMT64x "\n", addr);
				break;
			}
			r_anal_esil_set_pc (core->anal->esil, addr);
			if (!r_anal_esil_parse (core->anal->esil, input + 2)) {
				// XXX: return value doesnt seems to be correct here
				eprintf ("Cannot parse esil (%s)\n", input + 2);
				break;
			}
			hit_happens = false;
			res = r_anal_esil_pop (core->anal->esil);
			if (r_anal_esil_get_parm (core->anal->esil, res, &nres)) {
				if (nres) {
					if (!__cb_hit (&kw, core, addr)) {
						free (res);
						break;
					}
					// eprintf (" HIT AT 0x%"PFMT64x"\n", addr);
					kw.type = 0; // R_SEARCH_TYPE_ESIL;
					kw.kwidx = kwidx;
					kw.count++;
					eprintf ("Hits: %d\r", kw.count);
					kw.keyword_length = 0;
					hit_happens = true;
				}
			} else {
				eprintf ("Cannot parse esil (%s)\n", input + 2);
				r_anal_esil_stack_free (core->anal->esil);
				free (res);
				break;
			}
			r_anal_esil_stack_free (core->anal->esil);
			free (res);

			if (hit_happens) {
				hit_combo++;
				if (hit_combo > hit_combo_limit) {
					eprintf ("Hit combo limit reached. Stopping search. Use f-\n");
					break;
				}
			} else {
				hit_combo = 0;
			}
		}
		r_config_set_i (core->config, "search.kwidx", kwidx + 1);
		r_cons_break_pop ();
	}
	r_cons_clear_line (1);
}

static void do_anal_search(RCore *core, struct search_parameters *param, const char *input) {
	ut64 at;
	ut8 *buf;
	RAnalOp aop;
	int chk_family = 0;
	int mode = 0;
	int i, ret, bsize = R_MIN (64, core->blocksize);
	int kwidx = core->search->n_kws;
	int maxhits, count = 0;
	bool firstItem = true;

	param->boundaries = r_core_get_boundaries (core, param->mode);
	if (*input == 'f') {
		chk_family = 1;
		input++;
	}
	switch (*input) {
	case 'j':
		r_cons_printf ("[");
		mode = *input;
		input++;
		break;
	case 'q':
		mode = *input;
		input++;
		break;
	case 0:
		r_cons_printf (
			"Usage: /A[f][?jq] [op.type | op.family]\n"
			" /A?      - list all opcode types\n"
			" /Af?     - list all opcode families\n"
			" /A ucall - find calls with unknown destination\n"
			" /Af sse  - find SSE instructions\n");
		return;
	case '?':
		for (i = 0; i < 64; i++) {
			const char *str = chk_family
				? r_anal_op_family_to_string (i)
				: r_anal_optype_to_string (i);
			if (chk_family && atoi (str)) {
				break;
			}
			if (!str || !*str) {
				break;
			}
			if (!strcmp (str, "undefined")) {
				continue;
			}
			r_cons_println (str);
		}
		return;
	}
	input = r_str_chop_ro (input);
	buf = malloc (bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d bytes\n", bsize);
		return;
	}
	maxhits = (int) r_config_get_i (core->config, "search.count");
	r_cons_break_push (NULL, NULL);
RIOMap* map;
RListIter *iter;
r_list_foreach (param->boundaries, iter, map) {
	ut64 from = map->from;
	ut64 to = map->to;
	for (i = 0, at = from; at < to; at++, i++) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			r_core_read_at (core, at, buf, bsize);
		}
		ret = r_anal_op (core->anal, &aop, at, buf + i, bsize - i);
		if (ret) {
			bool match = false;
			if (chk_family) {
				const char *fam = r_anal_op_family_to_string (aop.family);
				if (fam) {
					if (!*input || !strcmp (input, fam)) {
						match = true;
						r_cons_printf ("0x%08"PFMT64x " - %d %s\n", at, ret, fam);
					}
				}
			} else {
				const char *type = r_anal_optype_to_string (aop.type);
				if (type) {
					if (!*input || !strcmp (input, type)) {
						match = true;
					}
				}
			}
			if (match) {
				// char *opstr = r_core_disassemble_instr (core, at, 1);
				char *opstr = r_core_op_str (core, at);
				switch (mode) {
				case 'j':
					r_cons_printf ("%s{\"addr\":%"PFMT64d ",\"size\":%d,\"opstr\":\"%s\"}",
						firstItem? "": ",",
						at, ret, opstr);
					break;
				case 'q':
					r_cons_printf ("0x%08"PFMT64x "\n", at);
					break;
				default:
					r_cons_printf ("0x%08"PFMT64x " %d %s\n", at, ret, opstr);
					break;
				}
				R_FREE (opstr);
				if (*input && searchflags) {
					char flag[64];
					snprintf (flag, sizeof (flag), "%s%d_%d",
						searchprefix, kwidx, count);
					r_flag_set (core->flags, flag, at, ret);
				}
				count++;
				if (maxhits && count >= maxhits) {
					break;
				}
				firstItem = false;
			}
			if (core->search->align > 0) {
				i += core->search->align - 1;
				at += core->search->align - 1;
			} else {
				// skip instruction
				i += ret - 1; // aop.size-1;
				at += ret - 1;
			}
		}
	}
}
	if (mode == 'j') {
		r_cons_println ("]\n");
	}
	r_cons_break_pop ();
	free (buf);
}

static void do_asm_search(RCore *core, struct search_parameters *param, const char *input) {
	RCoreAsmHit *hit;
	RListIter *iter, *itermap;
	int count = 0, maxhits = 0, filter = 0;
	int kwidx = core->search->n_kws; // (int)r_config_get_i (core->config, "search.kwidx")-1;
	RList *hits;
	RIOMap *map;
	int regexp = input[1] == '/';
	char *end_cmd = strstr (input, " ");
	int outmode;
	if (!end_cmd) {
		outmode = input[1];
	} else {
		outmode = *(end_cmd - 1);
	}
	if (outmode != 'j') {
		json = 0;
	}

	r_list_free (param->boundaries);
	param->boundaries = r_core_get_boundaries (core, param->mode);
	maxhits = (int) r_config_get_i (core->config, "search.count");
	filter = (int) r_config_get_i (core->config, "asm.filter");

	if (!param->boundaries) {
		map = R_NEW0 (RIOMap);
		map->fd = core->io->desc->fd;
		map->from = r_config_get_i (core->config, "search.from");
		map->to = r_config_get_i (core->config, "search.to");
		param->boundaries = r_list_newf (free);
		r_list_append (param->boundaries, map);
		maplist = true;
	}

	if (json) {
		r_cons_print ("[");
	}
	r_cons_break_push (NULL, NULL);
	r_list_foreach (param->boundaries, itermap, map) {
		ut64 from = map->from;
		ut64 to = map->to;
		if (r_cons_is_breaked ()) {
			break;
		}
		if (maxhits && count >= maxhits) {
			break;
		}
		if (!outmode) {
			hits = NULL;
		} else {
			hits = r_core_asm_strsearch (core, input + 2,
				from, to, maxhits, regexp);
		}
		if (hits) {
			const char *cmdhit = r_config_get (core->config, "cmd.hit");
			r_list_foreach (hits, iter, hit) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (cmdhit && *cmdhit) {
					r_core_cmdf (core, "%s @ 0x%"PFMT64x, cmdhit, hit->addr);
				}
				switch (outmode) {
				case 'j':
					if (count > 0) {
						r_cons_printf (",");
					}
					r_cons_printf (
						"{\"offset\":%"PFMT64d ",\"len\":%d,\"code\":\"%s\"}",
						hit->addr, hit->len, hit->code);
					break;
				case '*':
					r_cons_printf ("f %s%d_%i = 0x%08"PFMT64x "\n",
						searchprefix, kwidx, count, hit->addr);
					break;
				default:
					if (filter) {
						char tmp[128] = {
							0
						};
						r_parse_filter (core->parser, core->flags, hit->code, tmp, sizeof (tmp), core->print->big_endian);
						r_cons_printf ("0x%08"PFMT64x "   # %i: %s\n",
							hit->addr, hit->len, tmp);
					} else {
						r_cons_printf ("0x%08"PFMT64x "   # %i: %s\n",
							hit->addr, hit->len, hit->code);
					}
					break;
				}
				if (searchflags) {
					const char *flagname = sdb_fmt (0, "%s%d_%d", searchprefix, kwidx, count);
					r_flag_set (core->flags, flagname, hit->addr, hit->len);
				}
				count++;
			}
			r_list_purge (hits);
			free (hits);
		}
	}
	if (json) {
		r_cons_printf ("]");
	}
	r_cons_break_pop ();

	if (maplist) {
		param->boundaries->free = free;
		r_list_free (param->boundaries);
		param->boundaries = NULL;
	}
}

static void do_string_search(RCore *core, struct search_parameters *param) {
	ut64 at;
	ut8 *buf;
	int oldfd = (core && core->io) ? r_io_fd_get_current (core->io) : -1;
	int bufsz;

	if (json) {
		r_cons_printf ("[");
	}
	RListIter *iter;
	RIOMap *map;
	if (!searchflags && !json) {
		r_cons_printf ("fs hits\n");
	}
	core->search->inverse = param->inverse;
	searchcount = r_config_get_i (core->config, "search.count");
	if (searchcount) {
		searchcount++;
	}
	if (core->search->n_kws > 0 || param->crypto_search) {
		RSearchKeyword aeskw;
		if (param->crypto_search) {
			memset (&aeskw, 0, sizeof (aeskw));
			aeskw.keyword_length = 31;
		}
		/* set callback */
		/* TODO: handle last block of data */
		/* TODO: handle ^C */
		/* TODO: launch search in background support */
		// REMOVE OLD FLAGS r_core_cmdf (core, "f-%s*", r_config_get (core->config, "search.prefix"));
		r_search_set_callback (core->search, &__cb_hit, core);
		cmdhit = r_config_get (core->config, "cmd.hit");
		// XXX required? imho nor_io_set_fd (core->io, core->file->fd);
		if (!param->boundaries) {
			RIOMap *map = R_NEW0 (RIOMap);
			map->fd = r_io_fd_get_current (core->io);
			map->from = r_config_get_i (core->config, "search.from");
			map->to = r_config_get_i (core->config, "search.to");
			param->boundaries = r_list_newf (free);
			r_list_append (param->boundaries, map);
			maplist = true;
		}
		buf = (ut8 *) malloc (core->blocksize + 1);
		buf[core->blocksize] = 0;
		bufsz = core->blocksize;
		r_cons_break_push (NULL, NULL);
		r_list_foreach (param->boundaries, iter, map) {
			searchhits = 0;
			if (r_cons_is_breaked ()) {
				break;
			}
			if (map->to < map->from) {
				eprintf ("invalid from/to values\n");
				break;
			}

			r_io_use_fd (core->io, map->fd);
			if (!json) {
				RSearchKeyword *kw = r_list_first (core->search->kws);
				eprintf ("Searching %d bytes in [0x%"PFMT64x "-0x%"PFMT64x "]\n",
					kw? kw->keyword_length: 0, map->from, map->to);
			}
			if (r_sandbox_enable (0)) {
				if ((map->to - map->from) > 1024 * 64) {
					eprintf ("Sandbox restricts search range\n");
					break;
				}
			}

			if (param->bckwrds) {
				if ((map->to - bufsz) <= map->from) {
					at = map->from;
					param->do_bckwrd_srch = false;
				} else {
					at = map->to - bufsz;
				}
			} else {
				at = map->from;
			}
			/* bckwrds = false -> normal search -> must be at < to
			   bckwrds search -> check later */
			for (; (!param->bckwrds && at < map->to) || param->bckwrds;) {
				print_search_progress (at, map->to, searchhits);
				if (r_cons_is_breaked ()) {
					eprintf ("\n\n");
					break;
				}
				// avoid searching beyond limits
				if ((at + bufsz) > map->to) {
					bufsz = map->to - at;
				}
				if (!r_io_is_valid_offset (core->io, at, 0)) {
					break;
				}
				(void)r_io_read_at (core->io, at, buf, bufsz);
				if (param->crypto_search) {
					int delta = 0;
					if (param->aes_search) {
						delta = r_search_aes_update (core->search, at, buf, bufsz);
					} else if (param->rsa_search) {
						delta = r_search_rsa_update (core->search, at, buf, bufsz);
					}
					if (delta != -1) {
						if (!r_search_hit_new (core->search, &aeskw, at + delta)) {
							eprintf ("ERROR 2\n");
							break;
						}
						aeskw.count++;
					}
				} else if (r_search_update (core->search, &at, buf, bufsz) == -1) {
					// eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
					break;
				}

				if (param->bckwrds) {
					if (!param->do_bckwrd_srch) {
						break;
					}
					if ((at - bufsz) < map->from) {
						param->do_bckwrd_srch = false;
						bufsz = at - map->from;
						at = map->from;
					} else {
						at -= bufsz;
					}
				} else {
					at += bufsz;
				}
			}
			print_search_progress (at, map->to, searchhits);
			r_cons_clear_line (1);
			core->num->value = searchhits;
			if (searchflags && (searchcount > 0) && !json) {
				eprintf ("hits: %d  %s%d_0 .. %s%d_%d\n",
					searchhits,
					searchprefix, core->search->n_kws - 1,
					searchprefix, core->search->n_kws - 1, searchcount - 1);
			} else if (!json) {
				eprintf ("hits: %d\n", searchhits);
			}
			{
				RListIter *iter;
				RSearchKeyword *kw;
				r_list_foreach (core->search->kws, iter, kw) {
					kw->kwidx++;
				}
			}
		}
		r_cons_break_pop ();
		free (buf);
		if (maplist) {
			param->boundaries->free = free;
			r_list_free (param->boundaries);
			param->boundaries = NULL;
		}
		r_io_use_fd (core->io, oldfd);
	} else {
		eprintf ("No keywords defined\n");
	}

	/* Crazy party counter (kill me please) */
	if (!searchhits && core->search->n_kws > 0) {
		core->search->n_kws--;
	}
	if (json) {
		r_cons_printf ("]");
	}
}

static void rop_kuery(void *data, const char *input) {
	RCore *core = (RCore *) data;
	Sdb *db_rop = sdb_ns (core->sdb, "rop", false);
	bool json_first = true;
	SdbListIter *sdb_iter, *it;
	SdbList *sdb_list;
	SdbNs *ns;
	SdbKv *kv;
	char *out;

	if (!db_rop) {
		eprintf ("Error: could not find SDB 'rop' namespace\n");
		return;
	}

	switch (*input) {
	case 'q':
		ls_foreach (db_rop->ns, it, ns) {
			sdb_list = sdb_foreach_list (ns->sdb, false);
			ls_foreach (sdb_list, sdb_iter, kv) {
				r_cons_printf ("%s ", kv->key);
			}
		}
		break;
	case 'j':
		r_cons_print ("{\"gadgets\":[");
		ls_foreach (db_rop->ns, it, ns) {
			sdb_list = sdb_foreach_list (ns->sdb, false);
			ls_foreach (sdb_list, sdb_iter, kv) {
				char *dup = strdup (kv->value);
				bool flag = false; // to free tok when doing strdup
				char *size = strtok (dup, " ");
				char *tok = strtok (NULL, "{}");
				tok = strtok (NULL, "{}");
				if (!tok) {
					tok = strdup ("NOP");
					flag = true;
				}
				if (json_first) {
					json_first = false;
				} else {
					r_cons_print (",");
				}
				r_cons_printf ("{\"address\":%s, \"size\":%s, \"type\":\"%s\", \"effect\":\"%s\"}",
					kv->key, size, ns->name, tok);
				free (dup);
				if (flag) {
					free (tok);
				}
			}
		}
		r_cons_printf ("]}\n");
		break;
	case ' ':
		if (!strcmp (input + 1, "nop")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/nop/*");
			if (out) {
				r_cons_println (out);
				free (out);
			}
		} else if (!strcmp (input + 1, "mov")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/mov/*");
			if (out) {
				r_cons_println (out);
				free (out);
			}
		} else if (!strcmp (input + 1, "const")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/const/*");
			if (out) {
				r_cons_println (out);
				free (out);
			}
		} else if (!strcmp (input + 1, "arithm")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/arithm/*");
			if (out) {
				r_cons_println (out);
				free (out);
			}
		} else if (!strcmp (input + 1, "arithm_ct")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/arithm_ct/*");
			if (out) {
				r_cons_println (out);
				free (out);
			}
		} else {
			eprintf ("Invalid ROP class\n");
		}
		break;
	default:
		out = sdb_querys (core->sdb, NULL, 0, "rop/***");
		if (out) {
			r_cons_println (out);
			free (out);
		}
		break;
	}
}

static int memcmpdiff(const ut8 *a, const ut8 *b, int len) {
	int i, diff = 0;
	for (i = 0; i < len; i++) {
		if (a[i] == b[i] && a[i] == 0x00) {
			/* ignore nulls */
		} else if (a[i] != b[i]) {
			diff++;
		}
	}
	return diff;
}

static void search_similar_pattern_in(RCore *core, int count, ut64 from, ut64 to) {
	ut64 addr = from;
	ut8 *block = calloc (core->blocksize, 1);
	while (addr < to) {
		(void) r_io_read_at (core->io, addr, block, core->blocksize);
		if (r_cons_is_breaked ()) {
			break;
		}
		int diff = memcmpdiff (core->block, block, core->blocksize);
		int equal = core->blocksize - diff;
		if (equal >= count) {
			int pc = (equal * 100) / core->blocksize;
			r_cons_printf ("0x%08"PFMT64x " %4d/%d %3d%%  ", addr, equal, core->blocksize, pc);
			ut8 ptr[2] = {
				pc * 2.5, 0
			};
			r_print_fill (core->print, ptr, 1, UT64_MAX, core->blocksize);
		}
		addr += core->blocksize;
	}
	free (block);
}

static void search_similar_pattern(RCore *core, int count) {
	RIOMap *p;
	RListIter *iter;
	const char *where = r_config_get (core->config, "search.in");

	r_cons_break_push (NULL, NULL);
	RList *list = r_core_get_boundaries_prot (core, R_IO_EXEC, where);
	r_list_foreach (list, iter, p) {
		search_similar_pattern_in (core, count, p->from, p->to);
	}
	r_list_free (list);
	r_cons_break_pop ();
}

static bool isArm(RCore *core) {
	RAsm *as = core ? core->assembler : NULL;
	if (as && as->cur && as->cur->arch) {
		if (r_str_startswith (as->cur->arch, "arm")) {
			if (as->cur->bits < 64) {
				return true;
			}
		}
	}
	return false;
}

void _CbInRangeSearchV(RCore *core, ut64 from, ut64 to, int vsize, bool asterisk, int count) {
	bool isarm = isArm (core);
	// this is expensive operation that could be cached but is a callback
	// and for not messing adding a new param 
	const char *prefix = r_config_get (core->config, "search.prefix");
	if (isarm) {
		if (to & 1) {
			to--;
		}
	}
	r_cons_printf ("0x%"PFMT64x ": 0x%"PFMT64x"\n", from, to); 
	r_core_cmdf (core, "f %s.0x%08"PFMT64x" %d = 0x%08"PFMT64x "# from 0x%"PFMT64x "\n", prefix, to, vsize, to, from);
}

static int cmd_search(void *data, const char *input) {
	struct search_parameters param;
	bool dosearch = false;
	int i, len, ret = true;
	RCore *core = (RCore *) data;
	int ignorecase = false;
	int param_offset = 2;
	char *inp;
	ut64 n64, __from, __to;
	ut32 n32;
	ut16 n16;
	ut8 n8;
	if (!core || !core->io || !core->io->desc) {
		eprintf ("Can't search if we don't have an open file.\n");
		return false;
	}
	if (core->in_search) {
		eprintf ("Can't search from within a search.\n");
		return false;
	}
	if (input[0] == '/') {
		if (core->lastsearch) {
			input = core->lastsearch;
		} else {
			eprintf ("No previous search done\n");
			return false;
		}
	} else {
		free (core->lastsearch);
		core->lastsearch = strdup (input);
	}

	core->in_search = true;
	r_flag_space_push (core->flags, "searches");
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	param.inverse = false;
	param.crypto_search = false;
	param.bckwrds = false;
	param.do_bckwrd_srch = false;
	param.aes_search = false;
	param.rsa_search = false;
	param.do_bckwrd_srch = false;

	c = 0;
	json = false;
	first_hit = true;
	// core->search->n_kws = 0;
	maplist = false;
	__from = r_config_get_i (core->config, "search.from");
	__to = r_config_get_i (core->config, "search.to");

	searchshow = r_config_get_i (core->config, "search.show");
	param.mode = r_config_get (core->config, "search.in");
	param.boundaries = r_core_get_boundaries (core, param.mode);

	if (__from != UT64_MAX) {
		from = __from;
	}
	if (__to != UT64_MAX) {
		to = __to;
	}
	/*
	   this introduces a bug until we implement backwards search
	   for all search types
	   if (__to < __from) {
	        eprintf ("Invalid search range. Check 'e search.{from|to}'\n");
	        return false;
	   }
	   since the backward search will be implemented soon I'm not gonna stick
	   checks for every case in switch // jjdredd
	   remove when everything is done
	 */

	core->search->align = r_config_get_i (core->config, "search.align");
	searchflags = r_config_get_i (core->config, "search.flags");
	// TODO: handle section ranges if from&&to==0
/*
        section = r_io_section_vget (core->io, core->offset);
        if (section) {
                from += section->vaddr;
                //fin = ini + s->size;
        }
 */
	maxhits = r_config_get_i (core->config, "search.maxhits");
	searchprefix = r_config_get (core->config, "search.prefix");
	core->search->overlap = r_config_get_i (core->config, "search.overlap");
	// TODO: get ranges from current IO section
	// XXX: Think how to get the section ranges here

	if (from == UT64_MAX) {
		from = core->offset;
	}
	/* we don't really care what's bigger bc there's a flag for backward search
	   from now on 'from' and 'to' represent only the search boundaries, not
	   search direction */
	if (core->io->va) {
		__from = R_MIN (from, to);
		to = R_MAX (from, to);
		from = __from;
	} else {
		ut64 rawsize = r_io_size (core->io);
		from = R_MIN (from, rawsize);
		to = R_MIN (to, rawsize);
	}
	core->search->bckwrds = false;

	if (from == to) {
		eprintf ("WARNING from == to?\n");
	}
	/* Quick & dirty check for json output */
	if (input[0] && (input[1] == 'j') && (input[0] != ' ')) {
		json = true;
		param_offset++;
	}

reread:
	switch (*input) {
	case '!':
		input++;
		param.inverse = true;
		goto reread;
	case 'B':
	{
		bool bin_verbose = r_config_get_i (core->config, "bin.verbose");
		r_config_set_i (core->config, "bin.verbose", false);
		// TODO : iter maps?
		cmd_search_bin (core, from, to);
		r_config_set_i (core->config, "bin.verbose", bin_verbose);
	}
	break;
	case 'b':
		if (*(++input) == '?') {
			eprintf ("Usage: /b<command> [value] backward search, see '/?'\n");
			goto beach;
		}
		core->search->bckwrds = param.bckwrds = param.do_bckwrd_srch = true;
		/* if backward search and __to wasn't specified
		   search from the beginning */
		if ((unsigned int) to == UT32_MAX) {
			to = from;
			from = 0;
		}
		goto reread;
	case 'o': { // "/o" print the offset of the Previous opcode
		ut64 addr, n = input[param_offset] ? r_num_math (core->num, input + param_offset) : 0;
		if (!n) {
			n = 1;
		}
		if (!r_core_prevop_addr (core, core->offset, n, &addr)) {
			addr = UT64_MAX;
			(void)r_core_asm_bwdis_len (core, NULL, &addr, n);
		}
		if (json) {
			r_cons_printf ("[%"PFMT64u "]", addr);
		} else {
			r_cons_printf ("0x%08"PFMT64x "\n", addr);
		}
	}
	break;
	case 'R':
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_R);
		} else if (input[1] == '/') {
// TODO search on boundaries
			r_core_search_rop (core, from, to, 0, input + 1, 1);
		} else if (input[1] == 'k') {
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_slash_Rk);
			} else {
				rop_kuery (core, input + 2);
			}
		} else {
			r_core_search_rop (core, from, to, 0, input + 1, 0);
		}
		goto beach;
	case 'r': // "/r" and "/re"
		switch (input[1]) {
		case 'c': // "/rc"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- %llx %llx\n", map->from, map->to);
					r_core_anal_search (core, map->from, map->to, UT64_MAX, 'c');
				}
			}
			break;
		case 'a': // "/ra"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- %llx %llx\n", map->from, map->to);
					r_core_anal_search (core, map->from, map->to, UT64_MAX, 0);
				}
			}
			break;
		case 'e': // "/re"
			if (input[2] == '?') {
				eprintf ("Usage: /re $$ - to find references to current address\n");
			} else {
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- %llx %llx\n", map->from, map->to);
					ut64 refptr = r_num_math (core->num, input + 2);
					ut64 curseek = core->offset;
					r_core_seek (core, map->from, 1);
					char *arg = r_str_newf ("%"PFMT64d, map->to - map->from);
					char *trg = refptr? r_str_newf ("%"PFMT64d, refptr): strdup ("");
					r_core_anal_esil (core, arg, trg);
					free (arg);
					free (trg);
					r_core_seek (core, curseek, 1);
				}
			}
			break;
		case 'r': // "/rr"
			eprintf ("TODO: https://github.com/radare/radare2/issues/6549\n");
			break;
		case ' ': // "/r $$"
		case 0: // "/r"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					ut64 from = map->from;
					ut64 to = map->to;
					if (input[param_offset - 1] == ' ') {
						r_core_anal_search (core, from, to,
								r_num_math (core->num, input + 2), 0);
						r_core_cmdf (core, "axt @ 0x%"PFMT64x "\n", r_num_math (core->num, input + 2));
					} else {
						r_core_anal_search (core, from, to, core->offset, 0);
						r_core_cmdf (core, "axt @ 0x%"PFMT64x "\n", core->offset);
					}
					//r_core_anal_search (core, param.from, param.to, UT64_MAX, 'c');
					//			r_core_anal_search (core, map->from, map->to, UT64_MAX, 'c');
				}
			}
			break;
		case '?':
			break;
		}
		break;
	case 'A': // "/A"
		do_anal_search (core, &param, input + 1);
		dosearch = false;
		break;
	case 'a': // "/a"
		if (input[1]) {
			RListIter *iter;
			RIOMap *map;
			r_list_foreach (param.boundaries, iter, map) {
				eprintf ("-- %llx %llx\n", map->from, map->to);
				char *kwd = r_core_asm_search (core, input + param_offset,
					map->from, map->to);
				if (kwd) {
					r_search_reset (core->search, R_SEARCH_KEYWORD);
					r_search_set_distance (core->search, (int)
						r_config_get_i (core->config, "search.distance"));
					r_search_kw_add (core->search,
						r_search_keyword_new_hexmask (kwd, NULL));
					r_search_begin (core->search);
					free (kwd);
					dosearch = true;
				} else {
					ret = false;
					goto beach;
				}
				r_core_anal_search (core, map->from, map->to, UT64_MAX, 0);
			}
		}
		break;
	case 'C': { // "/C"
		dosearch = true;
		param.crypto_search = true;
		switch (input[1]) {
		case 'a':
			param.aes_search = true;
			break;
		case 'r':
			param.rsa_search = true;
			break;
		default: {
			dosearch = false;
			param.crypto_search = false;
			r_core_cmd_help (core, help_msg_slash_C);
		}
		}
	} break;
	case 'm': // "/m"
		dosearch = false;
		if (input[1] == ' ' || input[1] == '\0') {
			int ret;
			const char *file = input[1]? input + 2: NULL;
			ut64 addr = from;
			RListIter *iter;
			RIOMap *map;
			r_list_foreach (param.boundaries, iter, map) {
				eprintf ("-- %llx %llx\n", map->from, map->to);
				r_cons_break_push (NULL, NULL);
				for (addr = map->from; addr < map->to; addr++) {
					if (r_cons_is_breaked ()) {
						break;
					}
					ret = r_core_magic_at (core, file, addr, 99, false);
					if (ret == -1) {
						// something went terribly wrong.
						break;
					}
					addr += ret - 1;
				}
				r_cons_clear_line (1);
				r_cons_break_pop ();
			}
		} else {
			eprintf ("Usage: /m [file]\n");
		}
		r_cons_clear_line (1);
		break;
	case 'p': // "/p"
	{
		if (input[param_offset - 1]) {
			int ps = atoi (input + param_offset);
			if (ps > 1) {
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- %llx %llx\n", map->from, map->to);
					r_cons_break_push (NULL, NULL);
					r_search_pattern_size (core->search, ps);
					r_search_pattern (core->search, map->from, map->to);
					r_cons_break_pop ();
				}
				break;
			}
		}
		eprintf ("Invalid pattern size (must be > 0)\n");
	}
	break;
	case 'P': // "/P"
		search_similar_pattern (core, atoi (input + 1));
		break;
	case 'V': // "/V"
		// TODO: add support for json
	{
		int err = 1, vsize = atoi (input + 1);
		bool asterisk = strchr (input + 1, '*');
		if (vsize && input[2] && input[3]) {
			char *w = strchr (input + 3, ' ');
			if (w) {
				*w++ = 0;
				ut64 vmin = r_num_math (core->num, input + 3);
				ut64 vmax = r_num_math (core->num, w);
				if (vsize > 0) {
					err = 0;
					int hits = r_core_search_value_in_range (core, from,
									to, vmin, vmax, vsize, asterisk,
									_CbInRangeSearchV);
					eprintf ("hits: %d\n", hits);
				}
			}
		}
		if (err) {
			eprintf ("Usage: /V[1|2|4|8] [minval] [maxval]\n");
		}
	}
	break;
	case 'v': // "/v"
		if (input[1]) {
			if (input[1] == '?') {
				r_cons_print ("Usage: /v[1|2|4|8] [value]\n");
				break;
			}
			if (input[2] == 'j') {
				json = true;
				param_offset++;
			}
		}
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		switch (input[1]) {
		case '8':
			if (input[param_offset]) {
				n64 = r_num_math (core->num, input + param_offset);
				ut8 buf[sizeof (ut64)];
				r_write_le64 (buf, n64);
				r_search_kw_add (core->search,
					r_search_keyword_new ((const ut8 *) buf, sizeof (ut64), NULL, 0, NULL));
			} else {
				eprintf ("Usage: /v8 value\n");
			}
			break;
		case '1':
			if (input[param_offset]) {
				n8 = (ut8) r_num_math (core->num, input + param_offset);
				r_search_kw_add (core->search,
					r_search_keyword_new ((const ut8 *) &n8, 1, NULL, 0, NULL));
			} else {
				eprintf ("Usage: /v1 value\n");
			}
			break;
		case '2':
			if (input[param_offset]) {
				n16 = (ut16) r_num_math (core->num, input + param_offset);
				ut8 buf[sizeof (ut16)];
				r_write_le16 (buf, n16);
				r_search_kw_add (core->search,
					r_search_keyword_new ((const ut8 *) buf, sizeof (ut16), NULL, 0, NULL));
			} else {
				eprintf ("Usage: /v2 value\n");
			}
			break;
		default: // default size
		case '4':
			if (input[param_offset - 1]) {
				if (input[param_offset]) {
					n32 = (ut32) r_num_math (core->num, input + param_offset);
					ut8 buf[sizeof (ut32)];
					r_write_le32 (buf, n32);
					r_search_kw_add (core->search,
						r_search_keyword_new ((const ut8 *) buf, sizeof (ut32), NULL, 0, NULL));
				}
			} else {
				eprintf ("Usage: /v4 value\n");
			}
			break;
		}
		r_search_begin (core->search);
		dosearch = true;
		break;
	case 'w': // "/w" search wide string, includes ignorecase search functionality (/wi cmd)!
		if (input[1]) {
			if (input[2]) {
				if (input[1] == 'j' || input[2] == 'j') {
					json = true;
				}
				if (input[1] == 'i' || input[2] == 'i') {
					ignorecase = true;
				}
			}

			if (input[1 + json + ignorecase] == ' ') {
				int strstart, len;
				const char *p2;
				char *p, *str;
				strstart = 2 + json + ignorecase;
				len = strlen (input + strstart);
				str = calloc ((len + 1), 2);
				for (p2 = input + strstart, p = str; *p2; p += 2, p2++) {
					if (ignorecase) {
						p[0] = tolower ((const ut8) *p2);
					} else {
						p[0] = *p2;
					}
					p[1] = 0;
				}
				r_search_reset (core->search, R_SEARCH_KEYWORD);
				r_search_set_distance (core->search, (int)
					r_config_get_i (core->config, "search.distance"));
				RSearchKeyword *skw;
				skw = r_search_keyword_new ((const ut8 *) str, len * 2, NULL, 0, NULL);
				free (str);
				if (skw) {
					skw->icase = ignorecase;
					r_search_kw_add (core->search, skw);
					r_search_begin (core->search);
					dosearch = true;
				} else {
					eprintf ("Invalid keyword\n");
					break;
				}
			}
		}
		break;
	case 'i': // "/i"
		if (input[param_offset - 1] != ' ') {
			eprintf ("Missing ' ' after /i\n");
			ret = false;
			goto beach;
		}
		ignorecase = true;
	case 'j': // "/j"
		if (input[0] == 'j') {
			json = true;
		}
	/* pass-thru */
	case ' ': // "/ " search string
		inp = strdup (input + 1 + ignorecase + json);
		len = r_str_unescape (inp);
		if (!json) {
			eprintf ("Searching %d bytes from 0x%08"PFMT64x " to 0x%08"PFMT64x ": ",
				len, from, to);
			for (i = 0; i < len; i++) {
				eprintf ("%02x ", (ut8) inp[i]);
			}
			eprintf ("\n");
		}
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		{
			RSearchKeyword *skw;
			skw = r_search_keyword_new ((const ut8 *) inp, len, NULL, 0, NULL);
			free (inp);
			if (skw) {
				skw->icase = ignorecase;
				skw->type = R_SEARCH_KEYWORD_TYPE_STRING;
				r_search_kw_add (core->search, skw);
			} else {
				eprintf ("Invalid keyword\n");
				break;
			}
		}
		r_search_begin (core->search);
		dosearch = true;
		break;
	case 'e': // "/e" match regexp
		if (input[1]) {
			RSearchKeyword *kw;
			kw = r_search_keyword_new_regexp (input + param_offset, NULL);
			if (!kw) {
				eprintf ("Invalid regexp specified\n");
				break;
			}
			r_search_reset (core->search, R_SEARCH_REGEXP);
			r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
			r_search_kw_add (core->search, kw);
			r_search_begin (core->search);
			dosearch = true;
		} else {
			eprintf ("Missing regex\n");
		}
		break;
	case 'E': // "/E"
		if (core->io && core->io->debug) {
			r_debug_map_sync (core->dbg);
		}
		do_esil_search (core, &param, input);
		goto beach;
	case 'd': // "/d" search delta key
		if (input[1]) {
			r_search_reset (core->search, R_SEARCH_DELTAKEY);
			r_search_kw_add (core->search,
				r_search_keyword_new_hexmask (input + param_offset, NULL));
			r_search_begin (core->search);
			dosearch = true;
		} else {
			eprintf ("Missing delta\n");
		}
		break;
	case 'h': // "/h"
	{
		char *p, *arg = r_str_chop (strdup (input + 1));
		p = strchr (arg, ' ');
		if (p) {
			*p++ = 0;
			if (*arg == '?') {
				eprintf ("Usage: /h md5 [hash] [datalen]\n");
			} else {
				ut32 min = UT32_MAX;
				ut32 max = UT32_MAX;
				char *pmax, *pmin = strchr (p, ' ');
				if (pmin) {
					*pmin++ = 0;
					pmax = strchr (pmin, ' ');
					if (pmax) {
						*pmax++ = 0;
						max = r_num_math (core->num, pmax);
					}
					min = r_num_math (core->num, pmin);
				}
				search_hash (core, arg, p, min, max);
			}
		} else {
			eprintf ("Missing hash. See ph?\n");
		}
		free (arg);
	}
	break;
	case 'f': /* search file  "/f [file] ([offset] ([size])) */
		if (input[1] == ' ') {
			char *arg = strdup (input + 2);
			char *off = strchr (arg, ' ');
			char *sze = NULL;
			int size = 0;
			int offset = 0;
			if (off) {
				*off++ = 0;
				offset = r_num_math (core->num, off);
				sze = strchr (off, ' ');
				if (sze) {
					size = r_num_math (core->num, sze);
				}
			}
			if (offset > size) {
				eprintf ("Invalid offset or size\n");
			} else {
				ut8 *buf = (ut8*)r_file_slurp (arg, &size);
				if (buf) {
					RSearchKeyword *kw;
					r_search_reset (core->search, R_SEARCH_KEYWORD);
					r_search_set_distance (core->search, (int)
							r_config_get_i (core->config, "search.distance"));
					kw = r_search_keyword_new (buf + offset, size - offset, NULL, 0, NULL);
					if (kw) {
						r_search_kw_add (core->search, kw);
						// eprintf ("Searching %d bytes...\n", kw->keyword_length);
						r_search_begin (core->search);
						dosearch = true;
					} else {
						eprintf ("no keyword\n");
					}
					free (buf);
				} else {
					eprintf ("Cannot open '%s'\n", arg);
				}
			}
			free (arg);
		} else {
			eprintf ("Usage: /f [file] ([offset] ([size]))\n");
		}
		break;
	case 'x': // "/x" search hex
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_x);
		} else {
			RSearchKeyword *kw;
			char *s, *p = strdup (input + json + 2);
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)r_config_get_i (core->config, "search.distance"));
			s = strchr (p, ':');
			if (s) {
				*s++ = 0;
				kw = r_search_keyword_new_hex (p, s, NULL);
			} else {
				kw = r_search_keyword_new_hexmask (p, NULL);
			}
			if (kw) {
				r_search_kw_add (core->search, kw);
				// eprintf ("Searching %d bytes...\n", kw->keyword_length);
				r_search_begin (core->search);
				dosearch = true;
			} else {
				eprintf ("no keyword\n");
			}
			free (p);
		}
		break;
	case 'c': // "/c" search asm
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_c);
		}
		do_asm_search (core, &param, input);
		dosearch = 0;
		break;
	case '+': // "/+"
		if (input[1] == ' ') {
			// TODO: support /+j
			char *buf = malloc (strlen (input) * 2);
			char *str = strdup (input + 2);
			int ochunksize;
			int i, len, chunksize = r_config_get_i (core->config, "search.chunk");
			if (chunksize < 1) {
				chunksize = core->assembler->bits / 8;
			}
			len = r_str_unescape (str);
			ochunksize = chunksize = R_MIN (len, chunksize);
			eprintf ("Using chunksize: %d\n", chunksize);
			core->in_search = false;
			for (i = 0; i < len; i += chunksize) {
				chunksize = ochunksize;
again:
				r_hex_bin2str ((ut8 *) str + i, R_MIN (chunksize, len - i), buf);
				eprintf ("/x %s\n", buf);
				r_core_cmdf (core, "/x %s", buf);
				if (core->num->value == 0) {
					chunksize--;
					if (chunksize < 1) {
						eprintf ("Oops\n");
						free (buf);
						free (str);
						goto beach;
					}
					eprintf ("Repeat with chunk size %d\n", chunksize);
					goto again;
				}
			}
			free (str);
			free (buf);
		} else {
			eprintf ("Usage: /+ [string]\n");
		}
		break;
	case 'z': // "/z" search strings of min-max range
	{
		char *p;
		ut32 min, max;
		if (!input[1]) {
			eprintf ("Usage: /z min max\n");
			break;
		}
		if ((p = strchr (input + 2, ' '))) {
			*p = 0;
			max = r_num_math (core->num, p + 1);
		} else {
			eprintf ("Usage: /z min max\n");
			break;
		}
		min = r_num_math (core->num, input + 2);
		if (!r_search_set_string_limits (core->search, min, max)) {
			eprintf ("Error: min must be lower than max\n");
			break;
		}
		r_search_reset (core->search, R_SEARCH_STRING);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		{
			RSearchKeyword *kw = r_search_keyword_new_hexmask ("00", NULL);
			kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
			r_search_kw_add (core->search, kw);
		}
		r_search_begin (core->search);
		dosearch = true;
	}
	break;
	case '?': // "/?"
		r_core_cmd_help (core, help_msg_slash);
		break;
	default:
		eprintf ("See /? for help.\n");
		break;
	}
	searchhits = 0;
	r_config_set_i (core->config, "search.kwidx", core->search->n_kws);
	if (dosearch) {
		do_string_search (core, &param);
	}
beach:
	core->num->value = searchhits;
	core->in_search = false;
	r_flag_space_pop (core->flags);
	if (json) {
		r_cons_newline ();
	}
	return ret;
}
