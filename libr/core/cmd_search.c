/* radare - LGPL - Copyright 2010-2022 - pancake */

#include <ht_uu.h>
#include <r_core.h>
#include <r_hash.h>
#include "r_io.h"
#include "r_list.h"
#include "r_types_base.h"
#include "cmd_search_rop.c"

static int cmd_search(void *data, const char *input);

#define USE_EMULATION 0

#define AES_SEARCH_LENGTH 40
#define PRIVATE_KEY_SEARCH_LENGTH 11

static const char *help_msg_search_wide_string[] = {
	"Usage: /w[ij]", "[str]", "Wide string search subcommands",
	"/w ", "foo", "search for wide string 'f\\0o\\0o\\0'",
	"/wj ", "foo", "search for wide string 'f\\0o\\0o\\0' (json output)",
	"/wi ", "foo", "search for wide string 'f\\0o\\0o\\0' but ignoring case",
	"/wij ", "foo", "search for wide string 'f\\0o\\0o\\0' but ignoring case (json output)",
	NULL
};

static const char *help_msg_search_offset[] = {
	"Usage: /o", "[n]", "Shows offset of 'n' Backward instruction",
	NULL
};

static const char *help_msg_search_offset_without_anal[] = {
	"Usage: /O", "[n]", "Shows offset of 'n' Backward instruction, but with a different fallback if anal cannot be used.",
	NULL
};

static const char *help_msg_search_string_no_case[] = {
	"Usage: /i", "[str]", "Search str string ignorning case",
	NULL
};

static const char *help_msg_search_esil[] = {
	"/E", " [esil-expr]", "search offsets matching a specific esil expression",
	"/Ej", " [esil-expr]", "same as above but using the given magic file",
	"/E?", " ", "show this help",
	"\nExamples:", "", "",
	"", "/E $$,0x100001060,-,!", "hit when address is 0x100001060",
	NULL
};

static const char *help_msg_search_backward[] = {
	"Usage: /b[p]<command>", "[value]", "Backward search subcommands",
	"/b", "[x] [str|414243]", "search in hexadecimal 'ABC' backwards starting in current address",
	"/bp", "", "search previous prelude and set hit.prelude flag",
	NULL
};

static const char *help_msg_search_forward[] = {
	"Usage: /f", " ", "search forwards, command modifier, followed by other command",
	NULL
};

static const char *help_msg_search_sections[] = {
	"Usage: /s[*]", "[threshold]", "finds sections by grouping blocks with similar entropy.",
	NULL
};

static const char *help_msg_search_delta[] = {
	"Usage: /d", "delta", "search for a deltified sequence of bytes.",
	NULL
};

static const char *help_msg_search_pattern[] = {
	"Usage: /p[p]", " [pattern]", "Search for patterns or preludes",
	"/p", " [hexpattern]", "search in hexpairs pattern in search.in",
	"/pp", "", "search for function preludes",
	NULL
};

static const char *help_msg_search_ad[] = {
	"Usage: /ad<jq>", "[value]", "Backward search subcommands",
	"/ad", " rax", "search in disasm plaintext for matching instructions",
	"/adq", " rax", "quiet mode ideal for scripting",
	NULL
};

static const char *help_msg_slash_m[] = {
	"/m", "", "search for known magic patterns",
	"/m", " [file]", "same as above but using the given magic file",
	"/me", " ", "like ?e similar to IRC's /me",
	"/mm", " ", "search for known filesystems and mount them automatically",
	"/mb", "", "search recognized RBin headers",
	NULL
};

static const char *help_msg_slash[] = {
	"Usage:", "/[!bf] [arg]", "Search stuff (see 'e??search' for options)\n"
	"|Use io.va for searching in non virtual addressing spaces",
	"/", " foo\\x00", "search for string 'foo\\0'",
	"/j", " foo\\x00", "search for string 'foo\\0' (json output)",
	"/!", " ff", "search for first occurrence not matching, command modifier",
	"/!x", " 00", "inverse hexa search (find first byte != 0x00)",
	"/+", " /bin/sh", "construct the string with chunks",
	"//", "", "repeat last search",
	"/a", "[?][1aoditfmsltf] jmp eax", "find instructions by text or bytes (asm/disasm)",
	"/b", "[?][p]", "search backwards, command modifier, followed by other command",
	"/c", "[?][adr]", "search for crypto materials",
	"/d", " 101112", "search for a deltified sequence of bytes",
	"/e", " /E.F/i", "match regular expression",
	"/E", " esil-expr", "offset matching given esil expressions $$ = here",
	"/f", "", "search forwards, (command modifier)",
	"/F", " file [off] [sz]", "search contents of file with offset and size",
	// TODO: add subcommands to find paths between functions and filter only function names instead of offsets, etc
	"/g", "[g] [from]", "find all graph paths A to B (/gg follow jumps, see search.count and anal.depth)",
	"/h", "[t] [hash] [len]", "find block matching this hash. See ph",
	"/i", " foo", "search for string 'foo' ignoring case",
	"/k", " foo", "search for string 'foo' using Rabin Karp alg",
	"/m", "[?][ebm] magicfile", "search for magic, filesystems or binary headers",
	"/o", " [n]", "show offset of n instructions backward",
	"/O", " [n]", "same as /o, but with a different fallback if anal cannot be used",
	"/p", "[?][p] patternsize", "search for pattern of given size",
	"/P", " patternsize", "search similar blocks",
	"/s", "[*] [threshold]", "find sections by grouping blocks with similar entropy",
	"/r[erwx]", "[?] sym.printf", "analyze opcode reference an offset (/re for esil)",
	"/R", "[?] [grepopcode]", "search for matching ROP gadgets, semicolon-separated",
	// moved into /as "/s", "", "search for all syscalls in a region (EXPERIMENTAL)",
	"/v", "[1248] value", "look for an `cfg.bigendian` 32bit value",
	"/V", "[1248] min max", "look for an `cfg.bigendian` 32bit value in range",
	"/w", " foo", "search for wide string 'f\\0o\\0o\\0'",
	"/wi", " foo", "search for wide string ignoring case 'f\\0o\\0o\\0'",
	"/x", " ff..33", "search for hex string ignoring some nibbles",
	"/x", " ff0033", "search for hex string",
	"/x", " ff43:ffd0", "search for hexpair with mask",
	"/z", " min max", "search for strings of given size",
	"/*", " [comment string]", "add multiline comment, end it with '*/'",
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

static const char *help_msg_slash_a[] = {
	"Usage:", "/a[?] [arg]", "Search for assembly instructions matching given properties",
	"/a", " push rbp", "assemble given instruction and search the bytes",
	"/a1", " [number]", "find valid assembly generated by changing only the nth byte",
	"/aI", "", "search for infinite loop instructions (jmp $$)",
	"/aa", " mov eax", "linearly find aproximated assembly (case insensitive strstr)",
	"/ab", " [delta]", "search for backward jumps (usually loops)",
	"/ac", " mov eax", "same as /aa, but case-sensitive",
	"/ad", "[/*j] push;mov", "match ins1 followed by ins2 in linear disasm",
	"/ad/", " ins1;ins2", "search for regex instruction 'ins1' followed by regex 'ins2'",
	"/ad/a", " instr", "search for every byte instruction that matches regexp 'instr'",
	"/ae", " esil", "search for esil expressions matching substring",
	"/af", "[l] family", "search for instruction of specific family (afl=list",
	"/aF", " opstr", "find instructions matching given opstr only in analyzed code",
	"/ai", "[j] 0x300 [0x500]", "find all the instructions using that immediate (in range)",
	"/al", "", "same as aoml, list all opcodes",
	"/am", " opcode", "search for specific instructions of specific mnemonic",
	"/ao", " instr", "search for instruction 'instr' (in all offsets)",
	"/as", "[l] ([type])", "search for syscalls (See /at swi and /af priv)",
	"/at", "[l] ([type])", "search for instructions of given type",
	NULL
};

static const char *help_msg_slash_c[] = {
	"Usage: /c", "", "Search for crypto materials",
	"/ca", "", "search for AES keys expanded in memory",
	"/cc", "[algo] [digest]", "find collisions (bruteforce block length values until given checksum is found)",
	"/cd", "", "search for ASN1/DER certificates",
	"/cg", "", "search for GPG/PGP keys and signatures (Plaintext and binary form)",
	"/ck", "", "find well known constant tables from different hash and crypto algorithms",
	"/cr", "", "search for ASN1/DER private keys (RSA and ECC)",
	NULL
};

static const char *help_msg_slash_re[] = {
	"Usage:", "/re $$", "search references using linear esil emulation",
	"/re", " [addr]", "target address is specified as addr",
	NULL,
};

static const char *help_msg_slash_r[] = {
	"Usage:", "/r[acerwx] [address]", " search references to this specific address",
	"/r", " [addr]", "search references to this specific address",
	"/ra", "", "search all references",
	"/rc", "", "search for call references",
	"/re", " [addr]", "search references using esil",
	"/rr", "", "find read references",
	"/ru", "[*qj]", "search for UDS CAN database tables (binbloom)",
	"/rw", "", "find write references",
	"/rx", "", "find exec references",
	NULL
};

static const char *help_msg_slash_R[] = {
	"Usage: /R", "", "search for ROP gadgets",
	"/R", " [filter-by-string]", "show gadgets",
	"/R/", " [filter-by-regexp]", "show gadgets [regular expression]",
	"/R/j", " [filter-by-regexp]", "json output [regular expression]",
	"/R/q", " [filter-by-regexp]", "show gadgets in a quiet manner [regular expression]",
	"/Rj", " [filter-by-string]", "json output",
	"/Rk", " [select-by-class]", "query stored ROP gadgets",
	"/Rq", " [filter-by-string]", "show gadgets in a quiet manner",
	NULL
};

static const char *help_msg_slash_Rk[] = {
	"Usage: /Rk", "", "query stored ROP gadgets",
	"/Rk", " [nop|mov|const|arithm|arithm_ct]", "show gadgets",
	"/Rkj", "", "json output",
	"/Rkq", "", "list Gadgets offsets",
	NULL
};

static const char *help_msg_slash_x[] = {
	"Usage:", "/x [hexpairs]:[binmask]", "search in memory",
	"/x ", "9090cd80", "search for those bytes",
	"/x ", "9090cd80:ffff7ff0", "search with binary mask",
	NULL
};

static R_TH_LOCAL int preludecnt = 0;
static R_TH_LOCAL int searchflags = 0;
static R_TH_LOCAL int searchshow = 0;
static R_TH_LOCAL const char *searchprefix = NULL;

struct search_parameters {
	RCore *core;
	RList *boundaries;
	const char *mode;
	const char *cmd_hit;
	PJ *pj;
	int outmode; // 0 or R_MODE_RADARE or R_MODE_JSON
	bool inverse;
	bool aes_search;
	bool privkey_search;
	int c; // used for progress
};

struct endlist_pair {
	int instr_offset;
	int delay_size;
};

static int search_hash(RCore *core, const char *hashname, const char *hashstr, ut32 minlen, ut32 maxlen, struct search_parameters *param) {
	RIOMap *map;
	ut8 *buf;
	int i, j;
	RListIter *iter;

	if (!minlen || minlen == UT32_MAX) {
		minlen = core->blocksize;
	}
	if (!maxlen || maxlen == UT32_MAX) {
		maxlen = minlen;
	}

	r_cons_break_push (NULL, NULL);
	for (j = minlen; j <= maxlen; j++) {
		ut32 len = j;
		eprintf ("Searching %s for %d byte length.\n", hashname, j);
		r_list_foreach (param->boundaries, iter, map) {
			if (r_cons_is_breaked ()) {
				break;
			}
			ut64 from = r_io_map_begin (map);
			ut64 to = r_io_map_end (map);
			st64 bufsz;
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
				if (r_cons_is_breaked ()) {
					break;
				}
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
					return 1;
				}
				free (s);
			}
			free (buf);
		}
	}
	r_cons_break_pop ();
	eprintf ("No hashes found\n");
	return 0;
hell:
	return -1;
}

static void cmd_search_bin(RCore *core, RInterval itv) {
	ut64 from = itv.addr, to = r_itv_end (itv);
	int size; // , sz = sizeof (buf);

	int fd = core->io->desc->fd;
	RBuffer *b = r_buf_new_with_io (&core->anal->iob, fd);
	r_cons_break_push (NULL, NULL);
	while (from < to) {
		if (r_cons_is_breaked ()) {
			break;
		}
		RBuffer *ref = r_buf_new_slice (b, from, to);
		RBinPlugin *plug = r_bin_get_binplugin_by_buffer (core->bin, NULL, ref);
		if (plug) {
			r_cons_printf ("0x%08" PFMT64x "  %s\n", from, plug->name);
			if (plug->size) {
				RBinFileOptions opt = {
					.pluginname = plug->name,
					.baseaddr = 0,
					.loadaddr = 0,
					.sz = 4096,
					.xtr_idx = 0,
					.rawstr = core->bin->rawstr,
					.fd = fd,
				};
				r_bin_open_io (core->bin, &opt);
				size = plug->size (core->bin->cur);
				if (size > 0) {
					r_cons_printf ("size %d\n", size);
				}
			}
		}
		r_buf_free (ref);
		from++;
	}
	r_buf_free (b);
	r_cons_break_pop ();
}

typedef struct {
	RCore *core;
	bool forward;
} UserPrelude;

static int __backward_prelude_cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	UserPrelude *up = (UserPrelude*) user;
	r_flag_set (up->core->flags, "hit.prelude", addr, kw->keyword_length);
	if (up->forward) {
		return 0;
	}
	return 1;
}

static int __prelude_cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *) user;
	int depth = r_config_get_i (core->config, "anal.depth");
	if (r_config_get_b (core->config, "anal.calls")) {
		r_core_cmdf (core, "afr@0x%"PFMT64x, addr);
	} else {
		r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	}
	preludecnt++;
	return 1;
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
		if (r_search_update (core->search, at, b, core->blocksize) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x "\n", at);
			break;
		}
	}
	// r_search_reset might also benifet from having an if(s->data) R_FREE(s->data), but im not sure.
	//add a commit that puts it in there to this PR if it wouldn't break anything. (don't have to worry about this happening again, since all searches start by resetting core->search)
	//For now we will just use r_search_kw_reset
	r_search_kw_reset (core->search);
	free (b);
	return preludecnt;
}

R_API int r_core_search_uds(RCore *core, int mode) {
	int ret = 0;
	const char *where = r_config_get (core->config, "search.in");

	RList *list = r_core_get_boundaries_prot (core, R_PERM_R, where, "search");
	RListIter *iter;
	RIOMap *p;
	PJ *pj = NULL;

	bool verbose = (mode == 0);
	if (!list) {
		return -1;
	}
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	r_list_foreach (list, iter, p) {
		if (!mode) {
			eprintf ("\r[>] Scanning %s 0x%"PFMT64x " - 0x%"PFMT64x " (%"PFMT64d")" ,
					r_str_rwx_i (p->perm), p->itv.addr, r_itv_end (p->itv), r_itv_size (p->itv));
		}
		ut64 addr = p->itv.addr;
		ut64 size = r_itv_size (p->itv);
		ut8 *data = malloc (size);
		if (!data) {
			continue;
		}
		if (!mode) {
			eprintf ("\r[>] Reading %s 0x%"PFMT64x " - 0x%"PFMT64x " (%"PFMT64d")" ,
				r_str_rwx_i (p->perm), p->itv.addr, r_itv_end (p->itv), r_itv_size (p->itv));
		}
		r_io_read_at (core->io, addr, data, size);
		if (!mode) {
			eprintf ("\r[>] Finding UDS %s 0x%"PFMT64x " - 0x%"PFMT64x " (%"PFMT64d")" ,
				r_str_rwx_i (p->perm), p->itv.addr, r_itv_end (p->itv), r_itv_size (p->itv));
		}
		RSearchUds *uds;
		RListIter *uds_iter;
		RList *uds_list = r_search_find_uds (core->search, addr, data, size, verbose);
		r_list_foreach (uds_list, uds_iter, uds) {
			if (pj) {
				pj_o (pj);
				pj_kn (pj, "addr", uds->addr);
				pj_ki (pj, "score", uds->score);
				pj_ki (pj, "stride", uds->stride);
				pj_end (pj);
			} else {
				if (mode == '*') {
					r_cons_printf ("f uds.%"PFMT64x".%d=0x%08" PFMT64x "\n", uds->addr, uds->stride, uds->addr);
				}
				if (mode != 'q') {
					// use table instead?
					eprintf ("0x%08" PFMT64x " score=%d stride=%d\n", uds->addr, uds->score, uds->stride);
				}
			}
			ret++;
		}
		r_list_free (uds_list);
		free (data);
	}
	r_list_free (list);
	if (mode == 'j') {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (s);
		free (s);
	}
	return ret;
}

R_API int r_core_search_preludes(RCore *core, bool log) {
	int ret = -1;
	const char *prelude = r_config_get (core->config, "anal.prelude");
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	const char *where = r_config_get (core->config, "anal.in");

	RList *list = r_core_get_boundaries_prot (core, R_PERM_X, where, "search");
	RListIter *iter;
	RIOMap *p;

	if (!list) {
		return -1;
	}

	size_t fc0 = r_list_length (core->anal->fcns);
	r_list_foreach (list, iter, p) {
		if ((r_itv_end (p->itv) - p->itv.addr) >= ST32_MAX) {
			// skip searching in large regions
			eprintf ("aap: skipping large range, please check 'anal.in' variable.\n");
			continue;
		}
		if (log) {
			eprintf ("\r[>] Scanning %s 0x%"PFMT64x " - 0x%"PFMT64x " ",
				r_str_rwx_i (p->perm), p->itv.addr, r_itv_end (p->itv));
			if (!(p->perm & R_PERM_X)) {
				eprintf ("skip\n");
				continue;
			}
		}
		from = p->itv.addr;
		to = r_itv_end (p->itv);
		if (prelude && *prelude) {
			ut8 *kw = malloc (strlen (prelude) + 1);
			int kwlen = r_hex_str2bin (prelude, kw);
			ret = r_core_search_prelude (core, from, to, kw, kwlen, NULL, 0);
			free (kw);
		} else {
			RList *preds = r_anal_preludes (core->anal);
			if (preds) {
				RListIter *iter;
				RSearchKeyword *kw;
				r_list_foreach (preds, iter, kw) {
					ret = r_core_search_prelude (core, from, to,
						kw->bin_keyword, kw->keyword_length,
						kw->bin_binmask, kw->binmask_length);
				}
			} else {
				if (log) {
					eprintf ("ap: Unsupported asm.arch and asm.bits\n");
				}
			}
			r_list_free (preds);
		}
		if (log) {
			eprintf ("done\n");
		}
	}
	if (log) {
		if (list) {
			size_t fc1 = r_list_length (core->anal->fcns);
			eprintf ("Analyzed %d functions based on preludes\n", (int)(fc1 - fc0));
		} else {
			eprintf ("No executable section found, cannot analyze anything. Use 'S' to change or define permissions of sections\n");
		}
	}
	r_list_free (list);
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

static int _cb_hit_sz(RSearchKeyword *kw, int klen, void *user, ut64 addr) {
	r_return_val_if_fail (kw && user, -1);
	struct search_parameters *param = user;
	RCore *core = param->core;
	ut64 base_addr = 0;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;

	if (searchshow && kw && kw->keyword_length > 0) {
		int len, i, extra, mallocsize;
		char *s = NULL, *str = NULL, *p = NULL;
		extra = (param->outmode == R_MODE_JSON)? 3: 1;
		const char *type = "hexpair";
		ut8 *buf = malloc (klen);
		if (!buf) {
			return 0;
		}
		switch (kw->type) {
		case R_SEARCH_KEYWORD_TYPE_STRING:
		{
			const int ctx = 16;
			const int prectx = addr > 16 ? ctx : addr;
			char *pre, *pos, *wrd;
			const int len = klen;
			char *buf = calloc (1, len + 32 + ctx * 2);
			type = "string";
			r_io_read_at (core->io, addr - prectx, (ut8 *) buf, len + (ctx * 2));
			pre = getstring (buf, prectx);
			pos = getstring (buf + prectx + len, ctx);
			if (!pos) {
				pos = strdup ("");
			}
			if (param->outmode == R_MODE_JSON) {
				wrd = getstring (buf + prectx, len);
				s = r_str_newf ("%s%s%s", pre, wrd, pos);
			} else {
				wrd = r_str_utf16_encode (buf + prectx, len);
				s = r_str_newf (use_color ? ".%s"Color_YELLOW "%s"Color_RESET "%s."
					: "\"%s%s%s\"", pre, wrd, pos);
			}
			free (buf);
			free (pre);
			free (wrd);
			free (pos);
		}
			free (p);
			break;
		default:
			len = klen; // 8 byte context
			mallocsize = (len * 2) + extra;
			str = (len > 0xffff)? NULL: malloc (mallocsize);
			if (str) {
				p = str;
				memset (str, 0, len);
				r_io_read_at (core->io, base_addr + addr, buf, klen);
				if (param->outmode == R_MODE_JSON) {
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

		if (param->outmode == R_MODE_JSON) {
			pj_o (param->pj);
			pj_kN (param->pj, "offset", base_addr + addr);
			pj_ks (param->pj, "type", type);
			pj_ks (param->pj, "data", s);
			pj_end (param->pj);
		} else {
			r_cons_printf ("0x%08"PFMT64x " %s%d_%d %s\n",
				base_addr + addr, searchprefix, kw->kwidx, kw->count, s);
		}
		free (s);
		free (buf);
		free (str);
	} else if (kw) {
		if (param->outmode == R_MODE_JSON) {
			pj_o (param->pj);
			pj_kN (param->pj, "offset", base_addr + addr);
			pj_ki (param->pj, "len", klen);
			pj_end (param->pj);
		} else {
			if (searchflags) {
				r_cons_printf ("%s%d_%d\n", searchprefix, kw->kwidx, kw->count);
			} else {
				r_cons_printf ("f %s%d_%d %d 0x%08"PFMT64x "\n", searchprefix,
					kw->kwidx, kw->count, klen, base_addr + addr);
			}
		}
	}
	if (searchflags && kw) {
		char *flag = r_str_newf ("%s%d_%d", searchprefix, kw->kwidx, kw->count);
		r_flag_set (core->flags, flag, base_addr + addr, klen);
		free (flag);
	}
	if (*param->cmd_hit) {
		ut64 here = core->offset;
		r_core_seek (core, base_addr + addr, true);
		r_core_cmd (core, param->cmd_hit, 0);
		r_core_seek (core, here, true);
	}
	return true;
}

static int _cb_hit(R_NULLABLE RSearchKeyword *kw, void *user, ut64 addr) {
	RSearchKeyword kw_fake = {0};
	RSearchKeyword *kw_used = &kw_fake;
	int klen = 0;
	if (kw) {
		struct search_parameters *param = user;
		const RSearch *search = param->core->search;
		klen = kw? kw->keyword_length + (search->mode == R_SEARCH_DELTAKEY): 0;
		kw_used = kw;
	}
	return _cb_hit_sz (kw_used, klen, user, addr);
}

static inline void print_search_progress(ut64 at, ut64 to, int n, struct search_parameters *param) {
	if ((++param->c % 64) || (param->outmode == R_MODE_JSON)) {
		return;
	}
	if (r_cons_singleton ()->columns < 50) {
		eprintf ("\r[  ]  0x%08" PFMT64x "  hits = %d   \r%s",
			at, n, (param->c % 2)? "[ #]": "[# ]");
	} else {
		eprintf ("\r[  ]  0x%08" PFMT64x " < 0x%08" PFMT64x "  hits = %d   \r%s",
			at, to, n, (param->c % 2)? "[ #]": "[# ]");
	}
}

static void append_bound(RList *list, RIO *io, RInterval search_itv, ut64 from, ut64 size, int perms) {
	RIOMap *map = R_NEW0 (RIOMap);
	if (!map) {
		return;
	}
	if (io && io->desc) {
		map->fd = r_io_fd_get_current (io);
	}

	map->perm = perms;
	RInterval itv = {from, size};
	if (size == -1) {
		eprintf ("Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x\n");
		free (map);
		return;
	}
	// TODO UT64_MAX is a valid address. search.from and search.to are not specified
	if (search_itv.addr == UT64_MAX && !search_itv.size) {
		map->itv = itv;
		r_list_append (list, map);
	} else if (r_itv_overlap (itv, search_itv)) {
		map->itv = r_itv_intersect (itv, search_itv);
		if (r_io_map_size (map)) {
			r_list_append (list, map);
		} else {
			free (map);
		}
	} else {
		free (map);
	}
}

static bool maskMatches(int perm, int mask, bool only) {
	if (mask) {
		if (only) {
			return ((perm & 7) != mask);
		}
		return (perm & mask) != mask;
	}
	return false;
}

// TODO(maskray) returns RList<RInterval>
// XXX perm parameter is unused
R_API RList *r_core_get_boundaries_prot(RCore *core, R_UNUSED int perm, const char *mode, const char *prefix) {
	r_return_val_if_fail (core, NULL);

	RList *list = r_list_newf (free); // XXX r_io_map_free);
	if (!list) {
		return NULL;
	}

	char bound_in[32];
	char bound_from[32];
	char bound_to[32];
	snprintf (bound_in, sizeof (bound_in), "%s.%s", prefix, "in");
	snprintf (bound_from, sizeof (bound_from), "%s.%s", prefix, "from");
	snprintf (bound_to, sizeof (bound_to), "%s.%s", prefix, "to");
	const ut64 search_from = r_config_get_i (core->config, bound_from),
	      search_to = r_config_get_i (core->config, bound_to);
	const RInterval search_itv = {search_from, search_to - search_from};
	if (!mode) {
		mode = r_config_get (core->config, bound_in);
	}
	if (perm == -1) {
		perm = R_PERM_RWX;
	}
	if (!strcmp (mode, "flag")) {
		const RList *ls = r_flag_get_list (core->flags, core->offset);
		RFlagItem *fi;
		RListIter *iter;
		r_list_foreach (ls, iter, fi) {
			if (fi->size > 1) {
				append_bound (list, core->io, search_itv, fi->offset, fi->size, 7);
			}
		}
	} else if (!r_config_get_b (core->config, "cfg.debug") && !core->io->va) {
		append_bound (list, core->io, search_itv, 0, r_io_size (core->io), 7);
	} else if (!strcmp (mode, "file")) {
		append_bound (list, core->io, search_itv, 0, r_io_size (core->io), 7);
	} else if (!strcmp (mode, "block")) {
		append_bound (list, core->io, search_itv, core->offset, core->blocksize, 7);
	} else if (!strcmp (mode, "io.map")) {
		RIOMap *m = r_io_map_get_at (core->io, core->offset);
		if (m) {
			append_bound (list, core->io, search_itv, m->itv.addr, m->itv.size, m->perm);
		}
	} else if (!strcmp (mode, "io.maps")) { // Non-overlapping RIOMap parts not overridden by others (skyline)
		ut64 begin = UT64_MAX;
		ut64 end = UT64_MAX;
		RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
		RListIter *iter;
		RIOMapRef *mapref;
		if (bank) {
			r_list_foreach (bank->maprefs, iter, mapref) {
				RIOMap *map = r_io_map_get_by_ref (core->io, mapref);
				if (!map) {
					continue;
				}
				const ut64 from = r_io_map_begin (map);
				const ut64 to = r_io_map_end (map);
				const int rwx = map->perm;
				if (begin == UT64_MAX) {
					begin = from;
				}
				if (end == UT64_MAX) {
					end = to;
				} else {
					if (end == from) {
						end = to;
					} else {
						append_bound (list, NULL, search_itv,
							begin, end - begin, rwx);
						begin = from;
						end = to;
					}
				}
			}
		}
		if (end != UT64_MAX) {
			append_bound (list, NULL, search_itv, begin, end - begin, 7);
		}
	} else if (r_str_startswith (mode, "io.maps.")) {
		int len = strlen ("io.maps.");
		int mask = (mode[len - 1] == '.')? r_str_rwx (mode + len): 0;
		// bool only = (bool)(size_t)strstr (mode, ".only");
		RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
		RListIter *iter;
		RIOMapRef *mapref;
		if (bank) {
			r_list_foreach (bank->maprefs, iter, mapref) {
				RIOMap *map = r_io_map_get_by_ref (core->io, mapref);
				if (!map) {
					continue;
				}
				const ut64 from = r_io_map_begin (map);
				const int rwx = map->perm;
				if ((rwx & mask) != mask) {
					continue;
				}
				append_bound (list, core->io, search_itv, from, r_io_map_size (map), rwx);
			}
		}
	} else if (r_str_startswith (mode, "bin.segments")) {
		int len = strlen ("bin.segments.");
		int mask = (mode[len - 1] == '.')? r_str_rwx (mode + len): 0;
		bool only = (bool)(size_t)strstr (mode, ".only");
		RBinObject *obj = r_bin_cur_object (core->bin);
		if (obj) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (obj->sections, iter, s) {
				if (!s->is_segment) {
					continue;
				}
				if (maskMatches (s->perm, mask, only)) {
					continue;
				}
				ut64 addr = core->io->va? s->vaddr: s->paddr;
				ut64 size = core->io->va? s->vsize: s->size;
				append_bound (list, core->io, search_itv, addr, size, s->perm);
			}
		}
	} else if (r_str_startswith (mode, "code")) {
		RBinObject *obj = r_bin_cur_object (core->bin);
		if (obj) {
			ut64 from = UT64_MAX;
			ut64 to = 0;
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				if (maskMatches (s->perm, 1, false)) {
					continue;
				}
				ut64 addr = core->io->va? s->vaddr: s->paddr;
				ut64 size = core->io->va? s->vsize: s->size;
				from = R_MIN (addr, from);
				to = R_MAX (to, addr + size);
			}
			if (from == UT64_MAX) {
				int mask = 1;
				RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
				RIOMapRef *mapref;
				if (bank) {
					r_list_foreach (bank->maprefs, iter, mapref) {
						RIOMap *map = r_io_map_get_by_ref (core->io, mapref);
						if (!map) {
							continue;
						}
						const ut64 from = r_io_map_begin (map);
						const ut64 size = r_io_map_size (map);
						const int rwx = map->perm;
						if ((rwx & mask) != mask) {
							continue;
						}
						append_bound (list, core->io, search_itv, from, size, rwx);
					}
				}
			}
			append_bound (list, core->io, search_itv, from, to-from, 1);
		}
	} else if (r_str_startswith (mode, "bin.sections")) {
		int len = strlen ("bin.sections.");
		int mask = (mode[len - 1] == '.')? r_str_rwx (mode + len): 0;
		bool only = (bool)(size_t)strstr (mode, ".only");
		RBinObject *obj = r_bin_cur_object (core->bin);
		if (obj) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				if (maskMatches (s->perm, mask, only)) {
					continue;
				}
				ut64 addr = core->io->va? s->vaddr: s->paddr;
				ut64 size = core->io->va? s->vsize: s->size;
				append_bound (list, core->io, search_itv, addr, size, s->perm);
			}
		}
	} else if (!strcmp (mode, "bin.segment")) {
		RBinObject *obj = r_bin_cur_object (core->bin);
		if (obj) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (obj->sections, iter, s) {
				if (!s->is_segment) {
					continue;
				}
				ut64 addr = core->io->va? s->vaddr: s->paddr;
				ut64 size = core->io->va? s->vsize: s->size;
				if (R_BETWEEN (addr, core->offset, addr + size)) {
					append_bound (list, core->io, search_itv, addr, size, s->perm);
				}
			}
		}
	} else if (!strcmp (mode, "bin.section")) {
		RBinObject *obj = r_bin_cur_object (core->bin);
		if (obj) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (obj->sections, iter, s) {
				if (s->is_segment) {
					continue;
				}
				ut64 addr = core->io->va? s->vaddr: s->paddr;
				ut64 size = core->io->va? s->vsize: s->size;
				if (R_BETWEEN (addr, core->offset, addr + size)) {
					append_bound (list, core->io, search_itv, addr, size, s->perm);
				}
			}
		}
	} else if (!strcmp (mode, "anal.fcn") || !strcmp (mode, "anal.bb")) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (f) {
			ut64 from = f->addr, size = r_anal_function_size_from_entry (f);

			/* Search only inside the basic block */
			if (!strcmp (mode, "anal.bb")) {
				RListIter *iter;
				RAnalBlock *bb;

				r_list_foreach (f->bbs, iter, bb) {
					ut64 at = core->offset;
					if ((at >= bb->addr) && (at < (bb->addr + bb->size))) {
						from = bb->addr;
						size = bb->size;
						break;
					}
				}
			}
			append_bound (list, core->io, search_itv, from, size, 5);
		} else {
			eprintf ("Warning: search.in = ( anal.bb | anal.fcn )"\
				"requires to seek into a valid function\n");
			append_bound (list, core->io, search_itv, core->offset, 1, 5);
		}
	} else if (!strncmp (mode, "dbg.", 4)) {
		if (r_config_get_b (core->config, "cfg.debug")) {
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
						r_io_map_set_begin(nmap, from);
						r_io_map_set_size(nmap, to - from);
						nmap->perm = perm;
						nmap->delta = 0;
						r_list_append (list, nmap);
					}
				}
			} else {
				bool only = false;
				mask = 0;
				if (!strcmp (mode, "dbg.program")) {
					first = true;
					mask = R_PERM_X;
				} else if (!strcmp (mode, "dbg.maps")) {
					all = true;
				} else if (r_str_startswith (mode, "dbg.maps.")) {
					mask = r_str_rwx (mode + 9);
					only = (bool)(size_t)strstr (mode, ".only");
				} else if (!strcmp (mode, "dbg.heap")) {
					heap = true;
				} else if (!strcmp (mode, "dbg.stack")) {
					stack = true;
				}

				ut64 from = UT64_MAX;
				ut64 to = 0;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (!all && maskMatches (map->perm, mask, only)) {
						continue;
					}
					add = (stack && strstr (map->name, "stack"))? 1: 0;
					if (!add && (heap && (map->perm & R_PERM_W)) && strstr (map->name, "heap")) {
						add = 1;
					}
					if ((mask && (map->perm & mask)) || add || all) {
						if (!list) {
							list = r_list_newf (free);
						}
						RIOMap *nmap = R_NEW0 (RIOMap);
						if (!nmap) {
							break;
						}
						r_io_map_set_begin (nmap, map->addr);
						r_io_map_set_size (nmap, map->addr_end - map->addr);
						if (r_io_map_begin (nmap)) {
							from = R_MIN (from, r_io_map_begin (nmap));
							to = R_MAX (to, r_io_map_end (nmap));
						}
						nmap->perm = map->perm;
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
		/* obey temporary seek if defined '/x 8080 @ addr:len' */
		if (core->tmpseek) {
			append_bound (list, core->io, search_itv, core->offset, core->blocksize, 5);
		} else {
			// TODO: repeat last search doesnt works for /a
			ut64 from = r_config_get_i (core->config, bound_from);
			if (from == UT64_MAX) {
				from = core->offset;
			}
			ut64 to = r_config_get_i (core->config, bound_to);
			if (to == UT64_MAX) {
				if (core->io->va) {
					/* TODO: section size? */
				} else {
					if (core->io->desc) {
						to = r_io_fd_size (core->io, core->io->desc->fd);
					}
				}
			}
			append_bound (list, core->io, search_itv, from, to - from, 5);
		}
	}
	return list;
}

static bool is_end_gadget(const RAnalOp *aop, const ut8 crop) {
	if (aop->family == R_ANAL_OP_FAMILY_SECURITY) {
		return false;
	}
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

static bool insert_into(void *user, const ut64 k, const ut64 v) {
	HtUU *ht = (HtUU *)user;
	ht_uu_insert (ht, k, v);
	return true;
}

// TODO: follow unconditional jumps
static RList *construct_rop_gadget(RCore *core, ut64 addr, ut8 *buf, int buflen, int idx, const char *grep, int regex, RList *rx_list, struct endlist_pair *end_gadget, HtUU *badstart) {
	int endaddr = end_gadget->instr_offset;
	int branch_delay = end_gadget->delay_size;
	RAnalOp aop = {0};
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
	HtUUOptions opt = {0};
	HtUU *localbadstart = ht_uu_new_opt (&opt);
	int count = 0;

	if (grep) {
		start = grep;
		end = strchr (grep, ';');
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

	bool found;
	ht_uu_find (badstart, idx, &found);
	if (found) {
		valid = false;
		goto ret;
	}
	while (nb_instr < max_instr) {
		ht_uu_insert (localbadstart, idx, 1);
		int error = r_anal_op (core->anal, &aop, addr, buf + idx, buflen - idx, R_ANAL_OP_MASK_DISASM);
		if (error < 0 || (nb_instr == 0 && (is_end_gadget (&aop, 0) || aop.type == R_ANAL_OP_TYPE_NOP))) {
			valid = false;
			goto ret;
		}
		const int opsz = aop.size;
		// opsz = r_strbuf_length (asmop.buf);
		char *opst = aop.mnemonic;
		if (!opst) {
			eprintf ("Missing mnemonic after disasm with '%s'\n", core->anal->cur->name);
			RAsmOp asmop;
			r_asm_set_pc (core->rasm, addr);
			if (r_asm_disassemble (core->rasm, &asmop, buf + idx, buflen - idx) < 0) {
				valid = false;
				goto ret;
			}
			opst = strdup (r_asm_op_get_asm (&asmop));
			r_asm_op_fini (&asmop);
		}
		if (!r_str_ncasecmp (opst, "invalid", strlen ("invalid")) ||
		    !r_str_ncasecmp (opst, ".byte", strlen (".byte"))) {
			valid = false;
			goto ret;
		}

		hit = r_core_asm_hit_new ();
		if (hit) {
			hit->addr = addr;
			hit->len = opsz;
			r_list_append (hitlist, hit);
		}

		// Move on to the next instruction
		idx += opsz;
		addr += opsz;
		if (rx) {
			grep_find = !r_regex_match (rx, "e", opst);
			search_hit = (end && grep && (grep_find < 1));
		} else {
			search_hit = (end && grep && strstr (opst, grep_str));
		}

		// Handle (possible) grep
		if (search_hit) {
			if (end[0] == ';') { // fields are semicolon-separated
				start = end + 1; // skip the ;
				end = strchr (start, ';');
				end = end? end: start + strlen (start); // latest field?
				free (grep_str);
				grep_str = calloc (1, end - start + 1);
				if (grep_str) {
					strncpy (grep_str, start, end - start);
				}
			} else {
				end = NULL;
			}
			if (regex) {
				rx = r_list_get_n (rx_list, count++);
			}
		}
		if (endaddr <= (idx - opsz)) {
			valid = (endaddr == idx - opsz);
			goto ret;
		}
		free (opst);
		aop.mnemonic = NULL;
		r_strbuf_fini (&aop.esil);
		nb_instr++;
	}
ret:
	r_anal_op_fini (&aop);
	free (grep_str);
	if (regex && rx) {
		r_list_free (hitlist);
		ht_uu_free (localbadstart);
		return NULL;
	}
	if (!valid || (grep && end)) {
		r_list_free (hitlist);
		ht_uu_free (localbadstart);
		return NULL;
	}
	ht_uu_foreach (localbadstart, insert_into, badstart);
	ht_uu_free (localbadstart);
	// If our arch has bds then we better be including them
	if (branch_delay && r_list_length (hitlist) < (1 + branch_delay)) {
		r_list_free (hitlist);
		return NULL;
	}
	return hitlist;
}

static void print_rop(RCore *core, RList *hitlist, PJ *pj, int mode) {
	const char *otype;
	RCoreAsmHit *hit = NULL;
	RListIter *iter;
	RList *ropList = NULL;
	char *buf_asm = NULL;
	unsigned int size = 0;
	RAnalOp analop = {0};
	RAsmOp asmop;
	Sdb *db = NULL;
	const bool colorize = r_config_get_i (core->config, "scr.color");
	const bool rop_comments = r_config_get_i (core->config, "rop.comments");
	const bool esil = r_config_get_i (core->config, "asm.esil");
	const bool rop_db = r_config_get_i (core->config, "rop.db");

	if (rop_db) {
		ropList = r_list_newf (free);
		db = sdb_ns (core->sdb, "rop", true);
		if (!db) {
			R_LOG_ERROR ("Could not create SDB 'rop' namespace");
			r_list_free (ropList);
			return;
		}
	}

	switch (mode) {
	case 'j':
		pj_o (pj);
		pj_ka (pj, "opcodes");
		r_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc (hit->len);
			if (!buf) {
				return;
			}
			r_io_read_at (core->io, hit->addr, buf, hit->len);
			r_asm_set_pc (core->rasm, hit->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ANAL_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			pj_o (pj);
			pj_kN (pj, "offset", hit->addr);
			pj_ki (pj, "size", hit->len);
			pj_ks (pj, "opcode", r_asm_op_get_asm (&asmop));
			pj_ks (pj, "type", r_anal_optype_to_string (analop.type));
			pj_end (pj);
			free (buf);
		}
		pj_end (pj);
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			r_strf_var (key, 32, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
		if (hit) {
			pj_kN (pj, "retaddr", hit->addr);
			pj_ki (pj, "size", size);
		}
		pj_end (pj);
		break;
	case 'q':
		// Print gadgets in a 'linear manner', each sequence
		// on one line.
		r_cons_printf ("0x%08"PFMT64x ":",
			((RCoreAsmHit *) hitlist->head->data)->addr);
		r_list_foreach (hitlist, iter, hit) {
			ut8 *buf = malloc (hit->len);
			r_io_read_at (core->io, hit->addr, buf, hit->len);
			r_asm_set_pc (core->rasm, hit->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ANAL_OP_MASK_BASIC);
			size += hit->len;
			const char *opstr = R_STRBUF_SAFEGET (&analop.esil);
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				r_list_append (ropList, r_str_newf (" %s", opstr));
			}
			if (esil) {
				r_cons_printf ("%s\n", opstr);
			} else if (colorize) {
				buf_asm = r_print_colorize_opcode (core->print, r_asm_op_get_asm (&asmop),
					core->cons->context->pal.reg, core->cons->context->pal.num, false, 0);
				r_cons_printf (" %s%s;", buf_asm, Color_RESET);
				free (buf_asm);
			} else {
				r_cons_printf (" %s;", r_asm_op_get_asm (&asmop));
			}
			free (buf);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			r_strf_var (key, 32, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
		break;
	default:
		// Print gadgets with new instruction on a new line.
		r_list_foreach (hitlist, iter, hit) {
			const char *comment = rop_comments? r_meta_get_string (core->anal, R_META_TYPE_COMMENT, hit->addr): NULL;
			if (hit->len < 0) {
				eprintf ("Invalid hit length here\n");
				continue;
			}
			ut8 *buf = malloc (1 + hit->len);
			if (!buf) {
				break;
			}
			buf[hit->len] = 0;
			r_io_read_at (core->io, hit->addr, buf, hit->len);
			r_asm_set_pc (core->rasm, hit->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ANAL_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			char *asm_op_hex = r_asm_op_get_hex (&asmop);
			if (colorize) {
				char *buf_asm = r_print_colorize_opcode (core->print, r_asm_op_get_asm (&asmop),
					core->cons->context->pal.reg, core->cons->context->pal.num, false, 0);
				otype = r_print_color_op_type (core->print, analop.type);
				if (comment) {
					r_cons_printf ("  0x%08" PFMT64x " %18s%s  %s%s ; %s\n",
						hit->addr, asm_op_hex, otype, buf_asm, Color_RESET, comment);
				} else {
					r_cons_printf ("  0x%08" PFMT64x " %18s%s  %s%s\n",
						hit->addr, asm_op_hex, otype, buf_asm, Color_RESET);
				}
				free (buf_asm);
			} else {
				if (comment) {
					r_cons_printf ("  0x%08" PFMT64x " %18s  %s ; %s\n",
						hit->addr, asm_op_hex, r_asm_op_get_asm (&asmop), comment);
				} else {
					r_cons_printf ("  0x%08" PFMT64x " %18s  %s\n",
						hit->addr, asm_op_hex, r_asm_op_get_asm (&asmop));
				}
			}
			free (asm_op_hex);
			free (buf);
			r_anal_op_fini (&analop);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf ("Gadget size: %d\n", (int)size);
			r_strf_var (key, 32, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
	}
	if (mode != 'j') {
		r_cons_newline ();
	}
	r_list_free (ropList);
}

static int r_core_search_rop(RCore *core, RInterval search_itv, int opt, const char *grep, int regexp, struct search_parameters *param) {
	const ut8 crop = r_config_get_i (core->config, "rop.conditional");      // decide if cjmp, cret, and ccall should be used too for the gadget-search
	const ut8 subchain = r_config_get_i (core->config, "rop.subchains");
	const ut8 max_instr = r_config_get_i (core->config, "rop.len");
	const char *arch = r_config_get (core->config, "asm.arch");
	int max_count = r_config_get_i (core->config, "search.maxhits");
	int i = 0, end = 0, mode = 0, increment = 1, ret, result = true;
	RList /*<endlist_pair>*/ *end_list = r_list_newf (free);
	RList /*<RRegex>*/ *rx_list = NULL;
	int align = core->search->align;
	RListIter *itermap = NULL;
	char *tok, *gregexp = NULL;
	char *grep_arg = NULL;
	char *rx = NULL;
	int delta = 0;
	ut8 *buf;
	RIOMap *map;
	RAsmOp asmop;

	Sdb *gadgetSdb = NULL;
	if (r_config_get_i (core->config, "rop.sdb")) {
		if (!(gadgetSdb = sdb_ns (core->sdb, "gadget_sdb", false))) {
			gadgetSdb = sdb_ns (core->sdb, "gadget_sdb", true);
		}
	}
	if (max_count == 0) {
		max_count = -1;
	}
	if (max_instr <= 1) {
		r_list_free (end_list);
		eprintf ("ROP length (rop.len) must be greater than 1.\n");
		if (max_instr == 1) {
			eprintf ("For rop.len = 1, use /c to search for single "
				"instructions. See /c? for help.\n");
		}
		return false;
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
		} else {
			mode = *grep;
			++grep;
		}
	}
	if (grep_arg) {
		grep_arg = strdup (grep_arg);
		grep_arg = r_str_replace (grep_arg, ",,", ";", true);
		grep = grep_arg;
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
	if (param->outmode == R_MODE_JSON) {
		pj_a (param->pj);
	}
	r_cons_break_push (NULL, NULL);

	r_list_foreach (param->boundaries, itermap, map) {
		HtUUOptions opt = {0};
		HtUU *badstart = ht_uu_new_opt (&opt);
		if (!r_itv_overlap (search_itv, map->itv)) {
			continue;
		}
		RInterval itv = r_itv_intersect (search_itv, map->itv);
		ut64 from = itv.addr, to = r_itv_end (itv);
		if (r_cons_is_breaked ()) {
			break;
		}
		delta = to - from;
		buf = calloc (1, delta);
		if (!buf) {
			result = false;
			goto bad;
		}
		(void) r_io_read_at (core->io, from, buf, delta);

		// Find the end gadgets.
		for (i = 0; i + 32 < delta; i += increment) {
			RAnalOp end_gadget = {0};
			// Disassemble one.
			if (r_anal_op (core->anal, &end_gadget, from + i, buf + i,
				    delta - i, R_ANAL_OP_MASK_BASIC) < 1) {
				r_anal_op_fini (&end_gadget);
				continue;
			}
			if (is_end_gadget (&end_gadget, crop)) {
#if 0
				if (search->maxhits && r_list_length (end_list) >= search->maxhits) {
					// limit number of high level rop gadget results
					r_anal_op_fini (&end_gadget);
					break;
				}
#endif
				struct endlist_pair *epair = R_NEW0 (struct endlist_pair);
				if (epair) {
					// If this arch has branch delay slots, add the next instr as well
					if (end_gadget.delay) {
						epair->instr_offset = i + increment;
						epair->delay_size = end_gadget.delay;
					} else {
						epair->instr_offset = (intptr_t) i;
						epair->delay_size = end_gadget.delay;
					}
					r_list_append (end_list, (void *) (intptr_t) epair);
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
		if (!r_list_empty (end_list)) {
			int prev, next, ropdepth;
			const int max_inst_size_x86 = 15;
			// Get the depth of rop search, should just be max_instr
			// instructions, x86 and friends are weird length instructions, so
			// we'll just assume 15 byte instructions.
			ropdepth = (increment == 1)
				? max_instr * max_inst_size_x86 /* wow, x86 is long */
				: max_instr * increment;
			if (r_cons_is_breaked ()) {
				break;
			}
			struct endlist_pair *end_gadget = (struct endlist_pair *) r_list_pop (end_list);
			next = end_gadget->instr_offset;
			prev = 0;
			// Start at just before the first end gadget.
			for (i = next - ropdepth; i < (delta - max_inst_size_x86) && max_count; i += increment) {
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
					free (end_gadget);
					if (r_list_get_n (end_list, 0)) {
						prev = i;
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
					r_io_read_at (core->io, from + i, buf + i,
						R_MIN ((delta - i), 4096));
					end = i + 2048;
				}
				ret = r_asm_disassemble (core->rasm, &asmop, buf + i, delta - i);
				if (ret) {
					r_asm_set_pc (core->rasm, from + i);
					RList *hitlist = construct_rop_gadget (core,
						from + i, buf, delta, i, grep, regexp,
						rx_list, end_gadget, badstart);
					if (!hitlist) {
						continue;
					}
					if (align && (0 != ((from + i) % align))) {
						continue;
					}
					if (gadgetSdb) {
						RListIter *iter;

						RCoreAsmHit *hit = (RCoreAsmHit *) hitlist->head->data;
						char *headAddr = r_str_newf ("%"PFMT64x, hit->addr);
						if (!headAddr) {
							result = false;
							goto bad;
						}

						r_list_foreach (hitlist, iter, hit) {
							char *addr = r_str_newf ("%"PFMT64x"(%"PFMT32d")", hit->addr, hit->len);
							if (!addr) {
								free (headAddr);
								result = false;
								goto bad;
							}
							sdb_concat (gadgetSdb, headAddr, addr, 0);
							free (addr);
						}
						free (headAddr);
					}

					if (param->outmode == R_MODE_JSON) {
						mode = 'j';
					}
					if ((mode == 'q') && subchain) {
						do {
							print_rop (core, hitlist, NULL, mode);
							hitlist->head = hitlist->head->n;
						} while (hitlist->head->n);
					} else {
						print_rop (core, hitlist, param->pj, mode);
					}
					r_list_free (hitlist);
					if (max_count > 0) {
						max_count--;
						if (max_count < 1) {
							break;
						}
					}
				}
				if (increment != 1) {
					i = next;
				}
			}
		}
		free (buf);
		ht_uu_free (badstart);
	}
	if (r_cons_is_breaked ()) {
		eprintf ("\n");
	}
	r_cons_break_pop ();

	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
bad:
	r_list_free (rx_list);
	r_list_free (end_list);
	free (grep_arg);
	free (gregexp);
	return result;
}

static bool esil_addrinfo(RAnalEsil *esil) {
	RCore *core = (RCore *) esil->cb.user;
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		num = r_core_anal_address (core, num);
		r_anal_esil_pushnum (esil, num);
	} else {
// error. empty stack?
		return false;
	}
	free (src);
	return true;
}

static void do_esil_search(RCore *core, struct search_parameters *param, const char *input) {
	const int hit_combo_limit = r_config_get_i (core->config, "search.esilcombo");
	const bool cfgDebug = r_config_get_b (core->config, "cfg.debug");
	RSearch *search = core->search;
	RSearchKeyword kw = {0};
	if (input[0] != 'E') {
		return;
	}
	if (input[1] == 'j') { // "/Ej"
		pj_a (param->pj);
		param->outmode = R_MODE_JSON;
		input++;
	}
	if (input[1] != ' ') { // "/E?"
		r_core_cmd_help (core, help_msg_search_esil);
		return;
	}
	if (!core->anal->esil) {
		// initialize esil vm
		r_core_cmd0 (core, "aei");
		if (!core->anal->esil) {
			eprintf ("Cannot initialize the ESIL vm\n");
			return;
		}
	}
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (param->boundaries, iter, map) {
		const int iotrap = r_config_get_i (core->config, "esil.iotrap");
		const int stacksize = r_config_get_i (core->config, "esil.stacksize");
		int nonull = r_config_get_i (core->config, "esil.nonull");
		bool hit_happens = false;
		size_t hit_combo = 0;
		char *res;
		ut64 nres, addr;
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
		if (!core->anal->esil) {
			core->anal->esil = r_anal_esil_new (stacksize, iotrap, addrsize);
		}
		/* hook addrinfo */
		core->anal->esil->cb.user = core;
		r_anal_esil_set_op (core->anal->esil, "AddrInfo", esil_addrinfo, 1, 1, R_ANAL_ESIL_OP_TYPE_UNKNOWN);
		/* hook addrinfo */
		r_anal_esil_setup (core->anal->esil, core->anal, 1, 0, nonull);
		r_anal_esil_stack_free (core->anal->esil);
		core->anal->esil->verbose = 0;

		r_cons_break_push (NULL, NULL);
		for (addr = from; addr < to; addr++) {
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
				if (cfgDebug) {
					eprintf ("RES 0x%08"PFMT64x" %"PFMT64d"\n", addr, nres);
				}
				if (nres) {
					eprintf ("hits: %d\r", kw.count);
					hit_happens = true;
					if (param->outmode != R_MODE_JSON) {
						if (!_cb_hit (&kw, param, addr)) {
							free (res);
							break;
						}
						// eprintf (" HIT AT 0x%"PFMT64x"\n", addr);
						kw.type = 0; // R_SEARCH_TYPE_ESIL;
						kw.kwidx = search->n_kws;
						kw.count++;
						kw.keyword_length = 0;
					}
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
				if (param->outmode == R_MODE_JSON) {
					pj_o (param->pj);
					pj_kn (param->pj, "addr", addr);
					pj_kn (param->pj, "value", nres);
					pj_end (param->pj);
				}
				hit_combo++;
				if (hit_combo > hit_combo_limit) {
					eprintf ("Hit search.esilcombo reached (%d). Stopping search. Use f-\n", hit_combo_limit);
					break;
				}
			} else {
				hit_combo = 0;
			}
		}
		r_config_set_i (core->config, "search.kwidx", search->n_kws); // TODO remove
		r_cons_break_pop ();
	}
	r_cons_clear_line (1);
	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
}

#define MAXINSTR 8
#define SUMARRAY(arr, size, res) do (res) += (arr)[--(size)]; while ((size))

#if USE_EMULATION
// IMHO This code must be deleted
static int emulateSyscallPrelude(RCore *core, ut64 at, ut64 curpc) {
	int i, inslen, bsize = R_MIN (64, core->blocksize);
	ut8 *arr;
	RAnalOp aop;
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const char *a0 = r_reg_get_name (core->anal->reg, R_REG_NAME_SN);
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
	RRegItem *reg_a0 = r_reg_get (core->dbg->reg, a0, -1);

	arr = malloc (bsize);
	if (!arr) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (arr);
		return -1;
	}
	r_reg_set_value (core->dbg->reg, r, curpc);
	for (i = 0; curpc < at; curpc++, i++) {
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			r_io_read_at (core->io, curpc, arr, bsize);
		}
		inslen = r_anal_op (core->anal, &aop, curpc, arr + i, bsize - i, R_ANAL_OP_MASK_BASIC);
		if (inslen) {
 			int incr = (core->search->align > 0)? core->search->align - 1:  inslen - 1;
			if (incr < 0) {
				incr = minopcode;
			}
			i += incr;
			curpc += incr;
			if (r_anal_op_nonlinear (aop.type)) {	// skip the instr
				r_reg_set_value (core->dbg->reg, r, curpc + 1);
			} else {	// step instr
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
		}
	}
	free (arr);
	int sysno = r_debug_reg_get (core->dbg, a0);
	r_reg_set_value (core->dbg->reg, reg_a0, -2); // clearing register A0
	return sysno;
}
#endif

static void do_syscall_search(RCore *core, struct search_parameters *param) {
	RSearch *search = core->search;
	ut64 at;
#if USE_EMULATION
	ut64 curpc;
#endif
	ut8 *buf;
	int curpos, idx = 0, count = 0;
	RAnalOp aop = {0};
	int i, ret, bsize = R_MAX (64, core->blocksize);
	int kwidx = core->search->n_kws;
	RIOMap* map;
	RListIter *iter;
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	RAnalEsil *esil;
	int align = core->search->align;
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");

	if (!(esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
		return;
	}
	int *previnstr = calloc (MAXINSTR + 1, sizeof (int));
	if (!previnstr) {
		r_anal_esil_free (esil);
		return;
	}
	buf = malloc (bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		r_anal_esil_free (esil);
		free (previnstr);
		return;
	}
	ut64 oldoff = core->offset;
	int syscallNumber = 0;
	r_cons_break_push (NULL, NULL);
	// XXX: the syscall register depends on arcm
	const char *a0 = r_reg_get_name (core->anal->reg, R_REG_NAME_SN);
	if (!strcmp (core->anal->config->arch, "arm") && core->anal->config->bits == 64) {
		const char *os = core->anal->config->os;
		if (!strcmp (os, "linux")) {
			a0 = "x8";
		} else if (!strcmp (os, "macos")) {
			a0 = "x16";
		}
	}
	char *esp = r_str_newf ("%s,=", a0);
	char *esp32 = NULL;
	if (core->anal->config->bits == 64) {
		const char *reg = r_reg_64_to_32 (core->anal->reg, a0);
		if (reg) {
			esp32 = r_str_newf ("%s,=", reg);
		}
	}
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (from >= to) {
			R_LOG_ERROR ("from must be lower than to");
			goto beach;
		}
		if (to == UT64_MAX) {
			R_LOG_ERROR ("Invalid destination boundary");
			goto beach;
		}
		for (i = 0, at = from; at < to; at++, i++) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (i >= (bsize - 32)) {
				i = 0;
			}
			if (align && (at % align)) {
				continue;
			}
			if (!i) {
				r_io_read_at (core->io, at, buf, bsize);
			}
			ret = r_anal_op (core->anal, &aop, at, buf + i, bsize - i, R_ANAL_OP_MASK_ESIL);
			curpos = idx++ % (MAXINSTR + 1);
			previnstr[curpos] = ret; // This array holds prev n instr size + cur instr size
			if (aop.type == R_ANAL_OP_TYPE_MOV) {
				const char *es = R_STRBUF_SAFEGET (&aop.esil);
				if (strstr (es, esp)) {
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				} else if (esp32 && strstr (es, esp32)){
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				}
			}
			if ((aop.type == R_ANAL_OP_TYPE_SWI) && ret) { // && (aop.val > 10)) {
				int scVector = -1; // int 0x80, svc 0x70, ...
				int scNumber = 0; // r0/eax/...
#if USE_EMULATION
				// This for calculating no of bytes to be subtracted , to get n instr above syscall
				int nbytes = 0;
				int nb_opcodes = MAXINSTR;
				SUMARRAY (previnstr, nb_opcodes, nbytes);
				curpc = at - (nbytes - previnstr[curpos]);
				scNumber = emulateSyscallPrelude (core, at, curpc);
#else
				scNumber = syscallNumber;
#endif
				scVector = (aop.val > 0)? aop.val: -1; // int 0x80 (aop.val = 0x80)
				RSyscallItem *item = r_syscall_get (core->anal->syscall, scNumber, scVector);
				if (item) {
					r_cons_printf ("0x%08"PFMT64x" %s\n", at, item->name);
				}
				memset (previnstr, 0, (MAXINSTR + 1) * sizeof (*previnstr)); // clearing the buffer
				if (searchflags) {
					char *flag = r_str_newf ("%s%d_%d.%s", searchprefix, kwidx, count, item? item->name: "syscall");
					r_flag_set (core->flags, flag, at, ret);
					free (flag);
				}
				r_syscall_item_free (item);
				if (*param->cmd_hit) {
					ut64 here = core->offset;
					r_core_seek (core, at, true);
					r_core_cmd (core, param->cmd_hit, 0);
					r_core_seek (core, here, true);
				}
				count++;
				if (search->maxhits > 0 && count >= search->maxhits) {
					r_anal_op_fini (&aop);
					break;
				}
				syscallNumber = 0;
			}
			int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
			if (inc < 0) {
				inc = minopcode;
			}
			i += inc;
			at += inc;
			r_anal_op_fini (&aop);
		}
	}
beach:
	r_core_seek (core, oldoff, true);
	r_anal_esil_free (esil);
	r_cons_break_pop ();
	free (buf);
	free (esp32);
	free (esp);
	free (previnstr);
}

static void do_ref_search(RCore *core, ut64 addr,ut64 from, ut64 to, struct search_parameters *param) {
	const int size = 12;
	bool be = core->print->config->big_endian;
	char str[512];
	RAnalFunction *fcn;
	RAnalRef *ref;
	RListIter *iter;
	ut8 buf[12];
	RAsmOp asmop;
	RList *list = r_anal_xrefs_get (core->anal, addr);
	if (list) {
		r_list_foreach (list, iter, ref) {
			r_io_read_at (core->io, ref->addr, buf, size);
			r_asm_set_pc (core->rasm, ref->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, size);
			fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
			RAnalHint *hint = r_anal_hint_get (core->anal, ref->addr);
			r_parse_filter (core->parser, ref->addr, core->flags, hint, r_strbuf_get (&asmop.buf_asm),
				str, sizeof (str), be);
			r_anal_hint_free (hint);
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ref->addr);
			char *print_comment = NULL;
			const char *nl = comment ? strchr (comment, '\n') : NULL;
			if (nl) { // display only until the first newline
				comment = print_comment = r_str_ndup (comment, nl - comment);
			}
			char *buf_fcn = comment
				? r_str_newf ("%s; %s", fcn ?  fcn->name : "(nofunc)", comment)
				: r_str_newf ("%s", fcn ? fcn->name : "(nofunc)");
			free (print_comment);
			if (from <= ref->addr && to >= ref->addr) {
				r_cons_printf ("%s 0x%" PFMT64x " [%s] %s\n",
						buf_fcn, ref->addr, r_anal_ref_type_tostring (ref->type), str);
				if (*param->cmd_hit) {
					ut64 here = core->offset;
					r_core_seek (core, ref->addr, true);
					r_core_cmd (core, param->cmd_hit, 0);
					r_core_seek (core, here, true);
				}
			}
			free (buf_fcn);
		}
	}
	r_list_free (list);
}

static void cmd_search_aF(RCore *core, const char *input) {
	bool quiet = *input == 'd';
	if (*input && *input != ' ' && *input != 'd') {
		eprintf ("Usage: /aF mov ## search in instructions covered by basic blocks ('uses the pi command')\n");
		eprintf ("Usage: /aFd mov ## uses internal disasm api (15x faster than /aF), no flag subst\n");
		return;
	}
	RAnalFunction *fcn;
	RListIter *iter, *iter2;
	RAnalBlock *bb;
	input = r_str_trim_head_ro (input + 1);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_list_foreach (fcn->bbs, iter2, bb) {
			ut8 *bbdata = malloc (bb->size);
			r_io_read_at (core->io, bb->addr, bbdata, bb->size);
			// eprintf ("0x08%"PFMT64x"%c", bb->addr, 10);
			int i;
			for (i = 0; i < bb->ninstr; i++) {
				ut64 addr = bb->addr + bb->op_pos[i];
				ut8 *idata = bbdata + bb->op_pos[i];
				RAsmOp asmop = {0};
				size_t left = bb->size - bb->op_pos[i];
				int ret = r_asm_disassemble (core->rasm, &asmop, idata, left);
				if (ret  < 1) {
					break;
				}
				char *s = NULL;
				if (quiet) {
					s = strdup (r_strbuf_get (&asmop.buf_asm));
				} else {
					s = r_core_cmd_strf (core, "pi 1 @ 0x%"PFMT64x, addr);
				}
				r_str_trim (s);
				if (strstr (s, input)) {
					r_cons_printf ("0x%08"PFMT64x" %s: %s\n", addr, fcn->name, s);
				}
				free (s);
			}
			free (bbdata);
		}
	}
}

static bool do_anal_search(RCore *core, struct search_parameters *param, const char *input) {
	RSearch *search = core->search;
	ut64 at;
	RAnalOp aop;
	int type = 0;
	int mode = 0;
	int kwidx = core->search->n_kws;
	int i, ret, count = 0;

	while (*input && *input != ' ') {
		switch (*input) {
		case 'j':
		case 'q':
			mode = *input;
			break;
		case 'l': // "/alt" "/alf"
			switch (type) {
			case 't': // "/alt"
			case 'f': // "/alf"
				for (i = 0; i < 64; i++) {
					const char *str = type == 'f'
						? r_anal_op_family_to_string (i)
						: r_anal_optype_to_string (i);
					if (!str || !*str) {
						break;
					}
					if (!strcmp (str, "undefined")) {
						continue;
					}
					r_cons_println (str);
				}
				break;
			case 's': // "als"
				r_core_cmd0 (core, "asl");
				break;
			case 0:
				r_core_cmd0 (core, "aoml");
				break;
			default:
				eprintf ("wat\n");
				break;
			}
			return false;
		case 'F': // "/aF"
			cmd_search_aF (core, input + 1);
			return true;
			break;
		case 'f': // "/af"
		case 's': // "/as"
		case 't': // "/at"
		case 'm': // "/am"
		case ' ':
			type = *input;
			break;
		case 0:
		case '?':
		default:
			r_core_cmd_help (core, help_msg_slash_a);
			return false;
		}
		input++;
	}
	if (type == 's') {
		eprintf ("Shouldn't reach\n");
		return true;
	}
	if (mode == 'j') {
		pj_a (param->pj);
	}
	input = r_str_trim_head_ro (input);
	r_cons_break_push (NULL, NULL);
	RIOMap* map;
	RListIter *iter;
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		for (i = 0, at = from; at < to; i++, at++) {
			if (r_cons_is_breaked ()) {
				break;
			}
			at = from + i;
			ut8 bufop[32];
			r_io_read_at (core->io, at, bufop, sizeof (bufop));
			ret = r_anal_op (core->anal, &aop, at, bufop, sizeof(bufop), R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_DISASM);
			if (ret) {
				bool match = false;
				if (type == 'm') {
					const char *fam = aop.mnemonic;
					if (fam && (!*input || r_str_startswith (fam, input))) {
						match = true;
					}
				} else if (type == 'f') {
					const char *fam = r_anal_op_family_to_string (aop.family);
					if (fam && (!*input || !strcmp (input, fam))) {
						match = true;
					}
				} else {
					const char *type = r_anal_optype_to_string (aop.type);
					if (type) {
						bool isCandidate = !*input;
						if (!strcmp (input, "cswi")) {
							if (!strcmp (input + 1, type)) {
								isCandidate = true;
							}
						} else {
							if (!strcmp (input, type)) {
								isCandidate = true;
							}
						}
						if (isCandidate) {
							if (strstr (input, "swi")) {
								if (*input  == 'c') {
									match = true; // aop.cond;
								} else {
									match = !aop.cond;
								}
							} else {
								match = true;
							}
						}
					}
				}
				if (match) {
					// char *opstr = r_core_disassemble_instr (core, at, 1);
					char *opstr = r_core_op_str (core, at);
					switch (mode) {
					case 'j':
						pj_o (param->pj);
						pj_kN (param->pj, "addr", at);
						pj_ki (param->pj, "size", ret);
						pj_ks (param->pj, "opstr", opstr);
						pj_end (param->pj);
						break;
					case 'q':
						r_cons_printf ("0x%08"PFMT64x "\n", at);
						break;
					default:
						if (type == 'f') {
							const char *fam = r_anal_op_family_to_string (aop.family);
							r_cons_printf ("0x%08"PFMT64x " %d %s %s\n", at, ret, fam, opstr);
						} else {
							r_cons_printf ("0x%08"PFMT64x " %d %s\n", at, ret, opstr);
						}
						break;
					}
					R_FREE (opstr);
					if (*input && searchflags) {
						char flag[64];
						snprintf (flag, sizeof (flag), "%s%d_%d",
							searchprefix, kwidx, count);
						r_flag_set (core->flags, flag, at, ret);
					}
					if (*param->cmd_hit) {
						ut64 here = core->offset;
						r_core_seek (core, at, true);
						r_core_cmd (core, param->cmd_hit, 0);
						r_core_seek (core, here, true);
					}
					count++;
					if (search->maxhits && count >= search->maxhits) {
						goto done;
					}
				}
				int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
				if (inc < 0) {
					inc = 0;
				}
	 			i += inc;
	 			at += inc;
			}
		}
	}
done:
	if (mode == 'j') {
		pj_end (param->pj);
	}
	r_cons_break_pop ();
	return false;
}

static void do_section_search(RCore *core, struct search_parameters *param, const char *input) {
	double threshold = 1;
	bool r2mode = false;
	if (input && *input) {
		if (*input == '*') {
			r2mode = true;
		}
		sscanf (input, "%lf", &threshold);
		if (threshold < 1) {
			threshold = 1;
		}
	}
	int buf_size = core->blocksize;
	ut8 *buf = malloc (buf_size);
	if (!buf) {
		return;
	}
	double oe = 0;
	RListIter *iter;
	RIOMap *map;
	ut64 begin = UT64_MAX;
	ut64 at, end = 0;
	int index = 0;
	bool lastBlock = true;
	r_cons_break_push (NULL, NULL);
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (r_cons_is_breaked ()) {
			break;
		}
		for (at = from; at < to; at += buf_size) {
			if (begin == UT64_MAX) {
				begin = at;
			}
			r_io_read_at (core->io, at, buf, buf_size);
			double e = r_hash_entropy (buf, buf_size);
			double diff = oe - e;
			diff = R_ABS (diff);
			end = at + buf_size;
			if (diff > threshold) {
				if (r2mode) {
					r_cons_printf ("f entropy_section_%d 0x%08"PFMT64x" 0x%08"PFMT64x"\n", index, end - begin, begin);
				} else {
					r_cons_printf ("0x%08"PFMT64x" - 0x%08"PFMT64x" ~ %lf\n", begin, end, e);
				}
				begin = UT64_MAX;
				index++;
				lastBlock = false;
			} else {
				lastBlock = true;
			}
			oe = e;
		}
		begin = UT64_MAX;
	}
	if (begin != UT64_MAX && lastBlock) {
		if (r2mode) {
			r_cons_printf ("f entropy_section_%d 0x%08"PFMT64x" 0x%08"PFMT64x"\n", index, end - begin, begin);
		} else {
			r_cons_printf ("0x%08"PFMT64x" - 0x%08"PFMT64x" ~ %d .. last\n", begin, end, 0);
		}
		index++;
	}
	r_cons_break_pop();
	free (buf);
}

static void do_asm_search(RCore *core, struct search_parameters *param, const char *input, int mode, RInterval search_itv) {
	RCoreAsmHit *hit;
	RListIter *iter, *itermap;
	bool be = core->rasm->config->big_endian;
	int count = 0, maxhits = 0, filter = 0;
	int kwidx = core->search->n_kws; // (int)r_config_get_i (core->config, "search.kwidx")-1;
	RList *hits;
	RIOMap *map;
	bool regexp = input[1] == '/'; // "/c/"
	bool everyByte = regexp && input[2] == 'a';
	char *end_cmd = strchr (input, ' ');
	switch ((end_cmd ? *(end_cmd - 1) : input[1])) {
	case 'j':
		param->outmode = R_MODE_JSON;
		break;
	case 'q':
		param->outmode = R_MODE_SIMPLE;
		break;
	case '*':
		param->outmode = R_MODE_RADARE;
		break;
	case '?':
		r_core_cmd_help (core, help_msg_search_ad);
		return;
	default:
		break;
	}
	if (mode == 'o') {
		everyByte = true;
	}

	maxhits = (int) r_config_get_i (core->config, "search.maxhits");
	filter = (int) r_config_get_i (core->config, "asm.sub.names");
	if (param->outmode == R_MODE_JSON) {
		pj_a (param->pj);
	}
	r_cons_break_push (NULL, NULL);
	if (everyByte) {
		input ++;
	}
	r_list_foreach (param->boundaries, itermap, map) {
		if (!r_itv_overlap (search_itv, map->itv)) {
			continue;
		}
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (r_cons_is_breaked ()) {
			break;
		}
		if (maxhits && count >= maxhits) {
			break;
		}
		hits = r_core_asm_strsearch (core, end_cmd,
				from, to, maxhits, regexp, everyByte, mode);
		if (hits) {
			r_cons_singleton ()->context->breaked = false;
			const char *cmdhit = r_config_get (core->config, "cmd.hit");
			r_list_foreach (hits, iter, hit) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (cmdhit && *cmdhit) {
					r_core_cmdf (core, "%s @ 0x%"PFMT64x, cmdhit, hit->addr);
				}
				switch (param->outmode) {
				case R_MODE_JSON:
					pj_o (param->pj);
					pj_kN (param->pj, "offset", hit->addr);
					pj_ki (param->pj, "len", hit->len);
					pj_ks (param->pj, "code", hit->code);
					pj_end (param->pj);
					break;
				case R_MODE_RADARE:
					r_cons_printf ("f %s%d_%i = 0x%08"PFMT64x "\n",
						searchprefix, kwidx, count, hit->addr);
					break;
				default:
					if (filter) {
						char tmp[128] = {
							0
						};
						RAnalHint *hint = r_anal_hint_get (core->anal, hit->addr);
						r_parse_filter (core->parser, hit->addr, core->flags, hint, hit->code, tmp, sizeof (tmp), be);
						r_anal_hint_free (hint);
						if (param->outmode == R_MODE_SIMPLE) {
							r_cons_printf ("0x%08"PFMT64x "   # %i: %s\n", hit->addr, hit->len, tmp);
						} else {
							char *s = (hit->len > 0)
								? r_core_cmd_strf (core, "pDi %d @e:asm.flags=0@0x%08"PFMT64x, (int)hit->len, hit->addr)
								: r_core_cmd_strf (core, "pdi 1 @e:asm.flags=0@0x%08"PFMT64x, hit->addr);
							if (s) {
								r_cons_printf ("%s", s);
							}
							free (s);
						}
					} else {
						r_cons_printf ("0x%08"PFMT64x "   # %i: %s\n",
							hit->addr, hit->len, hit->code);
					}
					break;
				}
				if (searchflags) {
					char *flagname = r_str_newf ("%s%d_%d", searchprefix, kwidx, count);
					if (flagname) {
						r_flag_set (core->flags, flagname, hit->addr, hit->len);
						free (flagname);
					}
				}
				count++;
			}
			r_list_free (hits);
		}
	}
	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
	r_cons_break_pop ();
}

static void do_string_search(RCore *core, RInterval search_itv, struct search_parameters *param) {
	ut64 at;
	ut8 *buf;
	RSearch *search = core->search;

	if (param->outmode == R_MODE_JSON) {
		pj_a (param->pj);
	}
	RListIter *iter;
	RIOMap *map;
	if (!searchflags && param->outmode != R_MODE_JSON) {
		r_cons_printf ("fs hits\n");
	}
	core->search->inverse = param->inverse;
	// TODO Bad but is to be compatible with the legacy behavior
	if (param->inverse) {
		core->search->maxhits = 1;
	}
	if (core->search->n_kws > 0) {
		/* set callback */
		/* TODO: handle last block of data */
		/* TODO: handle ^C */
		/* TODO: launch search in background support */
		// REMOVE OLD FLAGS r_core_cmdf (core, "f-%s*", r_config_get (core->config, "search.prefix"));
		r_search_set_callback (core->search, &_cb_hit, param);
		if (!(buf = malloc (core->blocksize))) {
			return;
		}
		if (search->bckwrds) {
			r_search_string_prepare_backward (search);
		}
		r_cons_break_push (NULL, NULL);
		// TODO search cross boundary
		r_list_foreach (param->boundaries, iter, map) {
			if (!r_itv_overlap (search_itv, map->itv)) {
				continue;
			}
			const ut64 saved_nhits = search->nhits;
			RInterval itv = r_itv_intersect (search_itv, map->itv);
			if (r_cons_is_breaked ()) {
				break;
			}
			if (param->outmode != R_MODE_JSON) {
				RSearchKeyword *kw = r_list_first (core->search->kws);
				int lenstr = kw? kw->keyword_length: 0;
				const char *bytestr = lenstr > 1? "bytes": "byte";
				eprintf ("Searching %d %s in [0x%"PFMT64x "-0x%"PFMT64x "]\n",
					kw? kw->keyword_length: 0, bytestr, itv.addr, r_itv_end (itv));
			}
			if (r_sandbox_enable (0) && itv.size > 1024 * 64) {
				eprintf ("Sandbox restricts search range\n");
				break;
			}
			if (!core->search->bckwrds) {
				RListIter* it;
				RSearchKeyword* kw;
				r_list_foreach (core->search->kws, it, kw) {
					kw->last = 0;
				}
			}

			const ut64 from = itv.addr, to = r_itv_end (itv),
					from1 = search->bckwrds? to: from,
					to1 = search->bckwrds? from: to;
			ut64 len;
			for (at = from1; at != to1; at = search->bckwrds? at - len: at + len) {
				print_search_progress (at, to1, search->nhits, param);
				if (r_cons_is_breaked ()) {
					eprintf ("\n\n");
					break;
				}
				if (search->bckwrds) {
					len = R_MIN (core->blocksize, at - from);
					// TODO prefix_read_at
					if (!r_io_is_valid_offset (core->io, at - len, 0)) {
						break;
					}
					(void)r_io_read_at (core->io, at - len, buf, len);
				} else {
					len = R_MIN (core->blocksize, to - at);
					if (!r_io_is_valid_offset (core->io, at, 0)) {
						break;
					}
					(void)r_io_read_at (core->io, at, buf, len);
				}
				r_search_update (core->search, at, buf, len);
				if (param->aes_search) {
					// Adjust length to search between blocks.
					if (len == core->blocksize) {
						len -= AES_SEARCH_LENGTH - 1;
					}
				} else if (param->privkey_search) {
					// Adjust length to search between blocks.
					if (len == core->blocksize) {
						len -= PRIVATE_KEY_SEARCH_LENGTH - 1;
					}
				}
				if (core->search->maxhits > 0 && core->search->nhits >= core->search->maxhits) {
					goto done;
				}
			}
			print_search_progress (at, to1, search->nhits, param);
			r_cons_clear_line (1);
			r_core_return_value (core, search->nhits);
			if (param->outmode != R_MODE_JSON) {
				eprintf ("hits: %" PFMT64d "\n", search->nhits - saved_nhits);
			}
		}
	done:
		r_cons_break_pop ();
		free (buf);
	} else {
		eprintf ("No keywords defined\n");
	}

	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
}

static void rop_kuery(void *data, const char *input, PJ *pj) {
	RCore *core = (RCore *) data;
	SdbListIter *sdb_iter, *it;
	SdbList *sdb_list;
	SdbNs *ns;
	SdbKv *kv;
	char *out;

	Sdb *db_rop = sdb_ns (core->sdb, "rop", false);
	if (!db_rop) {
		R_LOG_ERROR ("could not find SDB 'rop' namespace");
		return;
	}

	switch (*input) {
	case 'q':
		ls_foreach (db_rop->ns, it, ns) {
			sdb_list = sdb_foreach_list (ns->sdb, false);
			ls_foreach (sdb_list, sdb_iter, kv) {
				r_cons_printf ("%s ", sdbkv_key (kv));
			}
		}
		break;
	case 'j':
		pj_o (pj);
		pj_ka (pj, "gadgets");
		ls_foreach (db_rop->ns, it, ns) {
			sdb_list = sdb_foreach_list (ns->sdb, false);
			ls_foreach (sdb_list, sdb_iter, kv) {
				char *dup = strdup (sdbkv_value (kv));
				bool flag = false; // to free tok when doing strdup
				char *size = strtok (dup, " ");
				char *tok = strtok (NULL, "{}");
				if (!tok) {
					tok = strdup ("NOP");
					flag = true;
				}
				pj_o (pj);
				pj_ks (pj, "address", sdbkv_key (kv));
				pj_ks (pj, "size", size);
				pj_ks (pj, "type", ns->name);
				pj_ks (pj, "effect", tok);
				pj_end (pj);
				free (dup);
				if (flag) {
					free (tok);
				}
			}
		}
		pj_end (pj);
		pj_end (pj);
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
	if (!block) {
		return;
	}
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
				(ut8)(pc * 2.5), 0
			};
			r_print_fill (core->print, ptr, 1, UT64_MAX, core->blocksize);
		}
		addr += core->blocksize;
	}
	free (block);
}

static void search_similar_pattern(RCore *core, int count, struct search_parameters *param) {
	RIOMap *p;
	RListIter *iter;

	r_cons_break_push (NULL, NULL);
	r_list_foreach (param->boundaries, iter, p) {
		search_similar_pattern_in (core, count, p->itv.addr, r_itv_end (p->itv));
	}
	r_cons_break_pop ();
}

static bool isArm(RCore *core) {
	RAsm *as = core ? core->rasm : NULL;
	if (as && as->cur && as->cur->arch) {
		if (r_str_startswith (as->cur->arch, "arm")) {
			if (as->cur->bits < 64) {
				return true;
			}
		}
	}
	return false;
}

void _CbInRangeSearchV(RCore *core, ut64 from, ut64 to, int vsize, void *user) {
	struct search_parameters *param = user;
	bool isarm = isArm (core);
	// this is expensive operation that could be cached but is a callback
	// and for not messing adding a new param
	const char *prefix = r_config_get (core->config, "search.prefix");
	if (isarm) {
		if (to & 1) {
			to--;
		}
	}
	if (param->outmode != R_MODE_JSON) {
		r_cons_printf ("0x%"PFMT64x ": 0x%"PFMT64x"\n", from, to);
	} else {
		pj_o (param->pj);
		pj_kN (param->pj, "offset", from);
		pj_kN (param->pj, "value", to);
		pj_end (param->pj);
	}
	r_core_cmdf (core, "f %s.value.0x%08"PFMT64x" %d = 0x%08"PFMT64x, prefix, to, vsize, to); // flag at value of hit
	r_core_cmdf (core, "f %s.offset.0x%08"PFMT64x" %d = 0x%08"PFMT64x, prefix, from, vsize, from); // flag at offset of hit
	const char *cmdHit = r_config_get (core->config, "cmd.hit");
	if (cmdHit && *cmdHit) {
		ut64 addr = core->offset;
		r_core_seek (core, from, true);
		r_core_cmd (core, cmdHit, 0);
		r_core_seek (core, addr, true);
	}
}

static ut8 *v_writebuf(RCore *core, RList *nums, int len, char ch, int bsize) {
	ut8 *ptr;
	ut64 n64;
	ut32 n32;
	ut16 n16;
	ut8 n8;
	int i = 0;
	ut8 *buf = calloc (1, bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (buf);
		return NULL;
	}
	ptr = buf;
	for (i = 0; i < len; i++) {
		switch (ch) {
		case '1':
			n8 = r_num_math (core->num, r_list_pop_head (nums));
			r_write_le8 (ptr, n8);
			ptr = (ut8 *) ptr + sizeof (ut8);
			break;
		case '2':
			n16 = r_num_math (core->num, r_list_pop_head (nums));
			r_write_ble16 (ptr, n16, core->anal->config->big_endian);
			ptr = (ut8 *) ptr + sizeof (ut16);
			break;
		case '4':
			n32 = (ut32)r_num_math (core->num, r_list_pop_head (nums));
			r_write_ble32 (ptr, n32, core->anal->config->big_endian);
			ptr = (ut8 *) ptr + sizeof (ut32);
			break;
		default:
		case '8':
			n64 = r_num_math (core->num, r_list_pop_head (nums));
			r_write_ble64 (ptr, n64, core->anal->config->big_endian);
			ptr = (ut8 *) ptr + sizeof (ut64);
			break;
		}
		if (ptr > ptr + bsize) {
			return NULL;
		}
	}
	return buf;
}

// maybe useful as in util/big.c .?
static void incBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (!buf[i]) {
			i++;
			continue;
		}
		break;
	}
	// may overflow/hang/end/stop/whatever here
}

static void incPrintBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (!buf[i]) {
			i++;
			continue;
		}
		if (IS_PRINTABLE (buf[i])) {
			break;
		}
	}
}

static void incLowerBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha (buf[i]) && islower (buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
}

static void incUpperBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha (buf[i]) && isupper (buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
}

static void incAlphaBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isalpha (buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
	// may overflow/hang/end/stop/whatever here
}

static void incDigitBuffer(ut8 *buf, int bufsz) {
	int i = 0;
	while (i < bufsz) {
		buf[i]++;
		if (buf[i] && isdigit (buf[i])) {
			break;
		}
		if (!buf[i]) {
			i++;
			continue;
		}
	}
	// may overflow/hang/end/stop/whatever here
}

static void search_collisions(RCore *core, const char *hashName, const ut8 *hashValue, int hashLength, int mode) {
	ut8 R_ALIGNED(8) cmphash[128];
	int i, algoType = R_HASH_CRC32;
	int bufsz = core->blocksize;
	ut8 *buf = calloc (1, bufsz);
	if (!buf) {
		return;
	}
	memcpy (buf, core->block, bufsz);
	if (hashLength > sizeof (cmphash)) {
		eprintf ("Hashlength mismatch %d %d\n", hashLength, (int)sizeof (cmphash));
		free (buf);
		return;
	}
	memcpy (cmphash, hashValue, hashLength);

	ut64 hashBits = r_hash_name_to_bits (hashName);
	int hashSize = r_hash_size (hashBits);
	if (hashLength != hashSize) {
		eprintf ("Invalid hash size %d vs %d\n", hashLength, hashSize);
		free (buf);
		return;
	}

	RHash *ctx = r_hash_new (true, algoType);
	if (!ctx) {
		free (buf);
		return;
	}
	r_cons_break_push (NULL, NULL);
	ut64 prev = r_time_now_mono ();
	ut64 inc = 0;
	int amount = 0;
	int mount = 0;
	while (!r_cons_is_breaked ()) {
		ut64 now = r_time_now_mono ();
		if (now < (prev + 1000000)) {
			amount++;
		} else {
			mount += amount;
			mount /= 2;
			amount = 0;
			prev = now;
		}
		switch (mode) {
		case 'p': // digits+alpha
			incPrintBuffer (buf, bufsz);
			break;
		case 'a': // lowercase alpha
			incLowerBuffer (buf, bufsz);
			break;
		case 'A': // uppercase alpha
			incUpperBuffer (buf, bufsz);
			break;
		case 'l': // letters
			incAlphaBuffer (buf, bufsz);
			break;
		case 'd': // digits
			incDigitBuffer (buf, bufsz);
			break;
		default: // binary
			incBuffer (buf, bufsz);
			break;
		}

		eprintf ("0x%08" PFMT64x " input:", inc);
		for (i = 0; i < bufsz; i++) {
			eprintf ("%02x", buf[i]);
		}
		if (mode) {
			eprintf (" \"%s\"", buf);
		}

		r_hash_do_begin (ctx, hashBits);
		(void)r_hash_calculate (ctx, hashBits, buf, bufsz);
		r_hash_do_end (ctx, hashBits);

		eprintf (" digest:");
		for (i = 0; i < hashLength; i++) {
			eprintf ("%02x", ctx->digest[i]);
		}
		eprintf (" (%d h/s)  \r", mount);
		if (!memcmp (hashValue, ctx->digest, hashLength)) {
			eprintf ("\nCOLLISION FOUND!\n");
			r_print_hexdump (core->print, core->offset, buf, bufsz, 0, 16, 0);
			r_cons_flush ();
		}
		inc++;
	}
	r_cons_break_pop ();
	free (buf);
	r_hash_free (ctx);
}

static void __core_cmd_search_asm_infinite(RCore *core, const char *arg) {
	const char *search_in = r_config_get (core->config, "search.in");
	RList *boundaries = r_core_get_boundaries_prot (core, -1, search_in, "search");
	RListIter *iter;
	RIOMap *map;
	RAnalOp analop;
	ut64 at;
	r_cons_break_push (NULL, NULL);
	r_list_foreach (boundaries, iter, map) {
		if (r_cons_is_breaked ()) {
			break;
		}
		ut64 map_begin = r_io_map_begin (map);
		ut64 map_size = r_io_map_size (map);
		ut64 map_end = r_io_map_end (map);
		ut8 *buf = calloc (map_size, 1);
		if (!buf) {
			continue;
		}
		(void) r_io_read_at (core->io, map_begin, buf, map_size);
		for (at = map_begin; at + 24 < map_end; at += 1) {
			r_anal_op (core->anal, &analop, at, buf + (at - map_begin), 24, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
			if (at == analop.jump) {
				r_cons_printf ("0x%08"PFMT64x"\n", at);
			}
			at += analop.size;
			r_anal_op_fini (&analop);
		}
		free (buf);
	}
	r_cons_break_pop ();
}

static void __core_cmd_search_backward_prelude(RCore *core, bool doseek, bool forward) {
	RList *preds = r_anal_preludes (core->anal);
	int bs = core->blocksize;
	ut8 *bf = calloc (bs, 1);
	if (preds) {
		RListIter *iter;
		RSearchKeyword *kw;
		ut64 addr = core->offset;
		if (forward) {
			addr -= bs;
			addr += 4;
		}
		r_cons_break_push (NULL, NULL);
		while (addr > bs) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (forward) {
				addr += bs;
			} else {
				addr -= bs;
			}
			(void)r_io_read_at (core->io, addr, bf, bs);
			r_flag_unset_name (core->flags, "hit.prelude");
			// swap memory to search preludes backward
			bool fail = false;
			r_list_foreach (preds, iter, kw) {
				UserPrelude up = { core, forward };
				r_search_reset (core->search, R_SEARCH_KEYWORD);
				r_search_kw_add (core->search, r_search_keyword_new (kw->bin_keyword, kw->keyword_length, kw->bin_binmask, kw->binmask_length, NULL));
				r_search_begin (core->search);
				r_search_set_callback (core->search, &__backward_prelude_cb_hit, &up);
				if (r_search_update (core->search, addr, bf, bs) == -1) {
					if (forward) {
						// do nothing
					} else {
						eprintf ("search: update read error at 0x%08"PFMT64x "\n", addr);
						r_flag_unset_name (core->flags, "hit.prelude");
						fail = true;
					}
					break;
				}
			}
			if (fail) {
				break;
			}
			RFlagItem *item = r_flag_get (core->flags, "hit.prelude");
			if (item) {
				if (doseek) {
					r_core_seek (core, item->offset, true);
					r_flag_unset (core->flags, item);
				}
				break;
			}
		}
		r_cons_break_pop ();
		r_search_kw_reset (core->search);
		r_list_free (preds);
	}
	free (bf);
}

static void __core_cmd_search_backward(RCore *core, int delta) {
	const char *search_in = r_config_get (core->config, "search.in");
	RList *boundaries = r_core_get_boundaries_prot (core, -1, search_in, "search");
	RListIter *iter;
	RIOMap *map;
	RAnalOp analop;
	ut64 at;
	r_cons_break_push (NULL, NULL);
	int minopsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	int maxopsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	if (minopsz < 1 || maxopsz < 1) {
		eprintf ("Invalid MAX_OPSIZE. assuming 4\n");
		minopsz = 4;
		maxopsz = 4;
	}
	r_list_foreach (boundaries, iter, map) {
		ut64 map_begin = r_io_map_begin (map);
		ut64 map_size = r_io_map_size (map);
		ut64 map_end = r_io_map_end (map);
		ut8 *buf = calloc (map_size, 1);
		if (!buf) {
			continue;
		}
		(void) r_io_read_at (core->io, map_begin, buf, map_size);
		for (at = map_begin; at + maxopsz < map_end; at += 1) {
			if (r_cons_is_breaked ()) {
				break;
			}
			int left = R_MIN ((map_end - at), maxopsz);
			int rc = r_anal_op (core->anal, &analop, at, buf + (at - map_begin), left,
				R_ANAL_OP_MASK_DISASM | R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
			if (rc < 1) {
				at += minopsz - 1;
				continue;
			}
			// eprintf ("0x%08"PFMT64x" / 0x%08"PFMT64x" (%d) %s\n",
				// at, map_end, analop.size, analop.mnemonic);
			bool found = false;
			switch (analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
				if (analop.jump < at) {
					found = true;
					if (delta > 0) {
						ut64 jdelta = at - analop.jump;
						if (jdelta < delta) {
							found = false;
						}
					}
				}
				break;
			}
			if (found) {
				r_cons_printf ("0x%08"PFMT64x"\n", at);
			}
			at += analop.size - 1;
			r_anal_op_fini (&analop);
		}
		free (buf);
	}
	r_cons_break_pop ();
	r_list_free (boundaries);
}

static void __core_cmd_search_asm_byteswap(RCore *core, int nth) {
	RAsmOp asmop;
	ut8 buf[32];
	int i;
	r_io_read_at (core->io, 0, buf, sizeof (buf));
	if (nth < 0 || nth >= sizeof (buf) - 1) {
		return;
	}
	for (i = 0; i <= 0xff; i++) {
		buf[nth] = i;
		if (r_asm_disassemble (core->rasm, &asmop, buf, sizeof (buf)) > 0) {
			const char *asmstr = r_strbuf_get (&asmop.buf_asm);
			if (!strstr (asmstr, "invalid") && !strstr (asmstr, "unaligned")) {
				r_cons_printf ("%02x  %s\n", i, asmstr);
			}
		}
	}
}

static int cmd_search(void *data, const char *input) {
	bool dosearch = false;
	bool dosearch_read = false;
	int errcode = -1;
	RCore *core = (RCore *) data;
	struct search_parameters param = {
		.core = core,
		.cmd_hit = r_config_get (core->config, "cmd.hit"),
		.outmode = 0,
		.inverse = false,
		.aes_search = false,
		.privkey_search = false,
		.c = 0,
	};
	if (!param.cmd_hit) {
		param.cmd_hit = "";
	}
	RSearch *search = core->search;
	int ignorecase = false;
	int param_offset = 2;
	char *inp;
	if (!core || !core->io) {
		eprintf ("Can't search if we don't have an open file.\n");
		return false;
	}
	if (core->in_search) {
		eprintf ("Can't search from within a search.\n");
		return R_CMD_RC_SUCCESS;
	}
	if (input[0] == '/') {
		if (core->lastsearch) {
			input = core->lastsearch;
		} else {
			eprintf ("No previous search done\n");
			return R_CMD_RC_SUCCESS;
		}
	} else {
		free (core->lastsearch);
		core->lastsearch = strdup (input);
	}

	core->in_search = true;
	r_flag_space_push (core->flags, "search");
	const ut64 search_from = r_config_get_i (core->config, "search.from");
	const ut64 search_to = r_config_get_i (core->config, "search.to");
	if (search_from > search_to && search_to) {
		eprintf ("Invalid search range where search.from > search.to.\n");
		errcode = 0;
		goto beach;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RInterval search_itv = {search_from, search_to - search_from};
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		eprintf ("Warning: from == to?\n");
		errcode = 0;
		goto beach;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv.addr = 0;
		search_itv.size = UT64_MAX;
	}

	searchshow = r_config_get_i (core->config, "search.show");
	param.mode = r_config_get (core->config, "search.in");
	param.boundaries = r_core_get_boundaries_prot (core, -1, param.mode, "search");

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
	core->search->maxhits = r_config_get_i (core->config, "search.maxhits");
	searchprefix = r_config_get (core->config, "search.prefix");
	core->search->overlap = r_config_get_i (core->config, "search.overlap");
	core->search->bckwrds = false;

	/* Quick & dirty check for json output */
	if (input[0] && (input[1] == 'j') && (input[0] != ' ')) {
		param.outmode = R_MODE_JSON;
		param_offset++;
	}
	param.pj = r_core_pj_new (core);

reread:
	switch (*input) {
	case '!':
		input++;
		param.inverse = true;
		goto reread;
	case 'b': // "/b" backward search TODO(maskray) add a generic reverse function
		if (*(++input) == '?') {
			r_core_cmd_help (core, help_msg_search_backward);
			goto beach;
		}
		if (*input == 'p') { // "/bp" backward prelude
			__core_cmd_search_backward_prelude (core, false, false);
			goto beach;
		}
		search->bckwrds = true;
		if (core->offset) {
			RInterval itv = {0, core->offset};
			if (!r_itv_overlap (search_itv, itv)) {
				goto beach;
			} else {
				search_itv = r_itv_intersect (search_itv, itv);
			}
		}
		goto reread;
	case 'o': { // "/o" print the offset of the Previous opcode
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_offset);
			break;
		}
		ut64 addr, n = input[param_offset - 1] ? r_num_math (core->num, input + param_offset) : 1;
		n = R_ABS((st64)n);
		if (((st64)n) < 1) {
			n = 1;
		}
		if (!r_core_prevop_addr (core, core->offset, n, &addr)) {
			addr = UT64_MAX;
			(void)r_core_asm_bwdis_len (core, NULL, &addr, n);
		}
		if (param.outmode == R_MODE_JSON) {
			r_cons_printf ("[%"PFMT64u "]", addr);
		} else {
			r_cons_printf ("0x%08"PFMT64x "\n", addr);
		}
		break;
	}
	case 'O': { // "/O" alternative to "/o"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_offset_without_anal);
			break;
		}
		ut64 addr, n = input[param_offset - 1] ? r_num_math (core->num, input + param_offset) : 1;
		if (!n) {
			n = 1;
		}
		addr = r_core_prevop_addr_force (core, core->offset, n);
		if (param.outmode == R_MODE_JSON) {
			r_cons_printf ("[%"PFMT64u "]", addr);
		} else {
			r_cons_printf ("0x%08"PFMT64x "\n", addr);
		}
		break;
	}
	case 'R': // "/R"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_R);
		} else if (input[1] == '/') {
			r_core_search_rop (core, search_itv, 0, input + 1, 1, &param);
		} else if (input[1] == 'k') {
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_slash_Rk);
			} else {
				rop_kuery (core, input + 2, param.pj);
			}
		} else {
			Sdb *gadgetSdb = sdb_ns (core->sdb, "gadget_sdb", false);

			if (!gadgetSdb) {
				r_core_search_rop (core, search_itv, 0, input + 1, 0, &param);
			} else {
				SdbKv *kv;
				SdbListIter *sdb_iter;
				SdbList *sdb_list = sdb_foreach_list (gadgetSdb, true);

				ls_foreach (sdb_list, sdb_iter, kv) {
					RList *hitlist = r_core_asm_hit_list_new ();
					if (!hitlist) {
						goto beach;
					}

					char *s = sdbkv_value (kv);
					ut64 addr;
					int opsz;
					int mode = 0;

					// Options, like JSON, linear, ...
					if (input[1]) {
						mode = *(input + 1);
					}

					do {
						RCoreAsmHit *hit = r_core_asm_hit_new ();
						if (!hit) {
							r_list_free (hitlist);
							goto beach;
						}
						sscanf (s, "%"PFMT64x"(%"PFMT32d")", &addr, &opsz);
						hit->addr = addr;
						hit->len = opsz;
						r_list_append (hitlist, hit);
					} while (*(s = strchr (s, ')') + 1) != '\0');

					print_rop (core, hitlist, param.pj, mode);
					r_list_free (hitlist);
				}
			}
		}
		goto beach;
	case 'r': // "/r" and "/re"
		{
		ut64 n = (input[1] == ' ' || (input[1] && input[2]==' '))
			? r_num_math (core->num, input + 2): UT64_MAX;
		if (!n) {
			eprintf ("Cannot find null references.\n");
			break;
		}
		switch (input[1]) {
		case 'c': // "/rc"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- 0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 'c');
				}
			}
			break;
		case 'a': // "/ra"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- 0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 0);
				}
			}
			break;
		case 'e': // "/re"
			if (input[2] == ' ') {
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- 0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
					ut64 refptr = r_num_math (core->num, input + 2);
					ut64 curseek = core->offset;
					r_core_seek (core, r_io_map_begin (map), true);
					char *arg = r_str_newf (" %"PFMT64d, r_io_map_size (map));
					char *trg = refptr? r_str_newf (" %"PFMT64d, refptr): strdup ("");
					r_core_anal_esil (core, arg, trg);
					free (arg);
					free (trg);
					r_core_seek (core, curseek, true);
				}
			} else {
				r_core_cmd_help (core, help_msg_slash_re);
				dosearch = false;
			}
			break;
		case 'r': // "/rr" - read refs
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- 0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 'r');
				}
			}
			break;
		case 'u': // "/ru"
			{
				bool v = r_config_get_i (core->config, "search.verbose");
				int mode = input[2];
				if (!mode && !v) {
					mode = 'q';
				}
				(void)r_core_search_uds (core, mode);
				dosearch = false;
				break;
			}
		case 'w': // "/rw" - write refs
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					eprintf ("-- 0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 'w');
				}
			}
			break;
		case ' ': // "/r $$"
		case 0: // "/r"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					ut64 from = r_io_map_begin (map);
					ut64 to = r_io_map_end (map);
					if (input[param_offset - 1] == ' ') {
						r_core_anal_search (core, from, to,
								r_num_math (core->num, input + 2), 0);
						do_ref_search (core, r_num_math (core->num, input + 2), from, to, &param);
					} else {
						r_core_anal_search (core, from, to, core->offset, 0);
						do_ref_search (core, core->offset, from, to, &param);
					}
					if (r_cons_is_breaked ()) {
						break;
					}
				}
			}
			break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_slash_r);
			dosearch = false;
			break;
		}
		}
		break;
	case 'a': // "/a"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_slash_a);
			break;
		case 'd': // "/ad"
			dosearch = false;
			do_asm_search (core, &param, input + 1, 0, search_itv);
			break;
		case 'e': // "/ae"
			dosearch = false;
			do_asm_search (core, &param, input + 2, 'e', search_itv);
			break;
		case 'c': // "/ac"
			dosearch = false;
			do_asm_search (core, &param, input + 2, 'c', search_itv);
			break;
		case 'o':  // "/ao"
			dosearch = false;
			do_asm_search (core, &param, input + 2, 'o', search_itv);
			break;
		case 'a': // "/aa"
			dosearch = false;
			do_asm_search (core, &param, input + 2, 'a', search_itv);
			break;
		case 'i': // "/ai"
			do_asm_search (core, &param, input + 2, 'i', search_itv);
			break;
		case 'b': // "ab"
			__core_cmd_search_backward (core, (int)r_num_math (core->num, input + 2));
			break;
		case '1': // "a1"
			__core_cmd_search_asm_byteswap (core, (int)r_num_math (core->num, input + 2));
			break;
		case 'I': //  "/aI" - infinite
			__core_cmd_search_asm_infinite (core, r_str_trim_head_ro (input + 1));
			break;
		case ' ': // "a "
			if (input[param_offset - 1]) {
				char *kwd = r_core_asm_search (core, input + param_offset);
				if (!kwd) {
					goto beach;
				}
				dosearch = true;
				r_search_reset (core->search, R_SEARCH_KEYWORD);
				r_search_set_distance (core->search, (int)
						r_config_get_i (core->config, "search.distance"));
				r_search_kw_add (core->search,
						r_search_keyword_new_hexmask (kwd, NULL));
				free (kwd);
			}
			break;
		case 's': // "asl"
			if (input[2] == 'l') { // "asl"
				r_core_cmd0 (core, "asl");
			} else { // "as"
				do_syscall_search (core, &param);
			}
			dosearch = false;
			break;
		default:
			dosearch = do_anal_search (core, &param, input + 1);
			break;
		}
		break;
	case 'c': { // "/c"
		dosearch = true;
		switch (input[1]) {
		case 'k': // "/ck"
			{
				const bool le = !r_config_get_b (core->config, "cfg.bigendian");
				RSearchKeyword *kw;
				r_search_reset (core->search, R_SEARCH_KEYWORD);

				// aes round constant table
				kw = r_search_keyword_new_hexmask ("01020408102040801b366cc0ab4d9a2f5ebf63c697356ad4b37dfaefc591", NULL); // AES
				r_search_kw_add (search, kw);

				// base64
				kw = r_search_keyword_new_str ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", NULL, NULL, false);
				r_search_kw_add (search, kw);

				// blowfish
				if (le) {
					// LE blowfish
					kw = r_search_keyword_new_hexmask ("886a3f24d308a3852e8a191344737003223809a4d0319f2998fa2e08896c4eece62128457713d038cf6654be6c0ce934b729acc0dd507cc9b5d5843f170947b5", NULL);
				} else {
					// BE blowfish
					kw = r_search_keyword_new_hexmask ("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b5470917", NULL);
				}
				r_search_kw_add (search, kw);

				// crc32
				kw = (le)
					? r_search_keyword_new_hexmask ("00000000963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e3288db0ea4b8dc791ee9d5e088d9d2972b4cb609bd7cb17e072db8e7911dbf90", NULL)
					: r_search_keyword_new_hexmask ("0000000077073096ee0e612c990951ba076dc419706af48fe963a5359e6495a30edb883279dcb8a4e0d5e91e97d2d98809b64c2b7eb17cbde7b82d0790bf1d91", NULL);
				r_search_kw_add (search, kw);

				// sha256
				kw = (le)
					? r_search_keyword_new_hexmask ("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b", NULL)
					: r_search_keyword_new_hexmask ("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19", NULL);
				r_search_kw_add (search, kw);

				// rc2
				kw = r_search_keyword_new_hexmask ("d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2", NULL);
				r_search_kw_add (search, kw);

				// serpent
				kw = r_search_keyword_new_hexmask ("00204060012141610222426203234363042444640525456506264666072747", NULL);
				r_search_kw_add (search, kw);
				break;
			}
		case 'c': // "/cc"
			{
				char *space = strchr (input, ' ');
				const char *arg = space? r_str_trim_head_ro (space + 1): NULL;
				if (!arg || input[2] == '?') {
					eprintf ("Usage: /cc[aAdlpb] [hashname] [hexpairhashvalue]\n");
					eprintf (" /cca - lowercase alphabet chars only\n");
					eprintf (" /ccA - uppercase alphabet chars only\n");
					eprintf (" /ccl - letters (lower + upper alphabet chars)\n");
					eprintf (" /ccd - digits (only numbers)\n");
					eprintf (" /ccp - printable (alpha + digit)\n");
					eprintf (" /ccb - binary (any number is valid)\n");
					goto beach;
				}
				char *s = strdup (arg);
				char *sp = strchr (s, ' ');
				int mode = input[2];
				if (sp) {
					*sp = 0;
					sp++;
					char *hashName = s;
					ut8 *hashValue = (ut8*)strdup (sp);
					if (hashValue) {
						if (!r_str_startswith ((const char *)hashValue, "0x")) {
							// TODO: support bigger hashes
							int hashLength = 4;
							ut32 n = (ut32)r_num_get (NULL, (const char *)hashValue);
							memcpy (hashValue, (const ut8*)&n, sizeof (ut32));
							search_collisions (core, hashName, hashValue, hashLength, mode);
						} else {
							int hashLength = r_hex_str2bin (sp, hashValue);
							if (hashLength > 0) {
								search_collisions (core, hashName, hashValue, hashLength, mode);
							} else {
								eprintf ("Invalid expected hash hexpairs.\n");
							}
						}
						free (hashValue);
						r_core_return_value (core, 0);
					} else {
						eprintf ("Cannot allocate memory.\n");
						r_core_return_value (core, 1);
					}
				} else {
					eprintf ("Usage: /cc [hashname] [hexpairhashvalue]\n");
					eprintf ("Usage: /CC to search ascii collisions\n");
				}
				free (s);
				goto beach;
			}
			break;
		case 'd': // "/cd"
			{
				RSearchKeyword *kw;
				if (input[2] == 'j') {
					param.outmode = R_MODE_JSON;
				}
				kw = r_search_keyword_new_hex ("308200003082", "ffff0000ffff", NULL);
				r_search_reset (core->search, R_SEARCH_KEYWORD);
				if (kw) {
					r_search_kw_add (core->search, kw);
					r_search_begin (core->search);
				} else {
					eprintf ("bad pointer\n");
					dosearch = false;
				}
			}
			break;
		case 'g': // "/cg"
			{
				RSearchKeyword *kw;
				if (input[2] == 'j') {
					param.outmode = R_MODE_JSON;
				}
				r_search_reset (core->search, R_SEARCH_KEYWORD);
				// PGP ASCII Armor according to https://datatracker.ietf.org/doc/html/rfc4880
				kw = r_search_keyword_new_str ("BEGIN PGP PRIVATE KEY", NULL, NULL, false);
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_str ("BEGIN PGP PUBLIC KEY", NULL, NULL, false);
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_str ("BEGIN PRIVATE KEY", NULL, NULL, false);
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_str ("BEGIN PUBLIC KEY", NULL, NULL, false);
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_str ("BEGIN PGP SIGNATURE", NULL, NULL, false);
				r_search_kw_add (search, kw);

				// PGP binary format according to https://datatracker.ietf.org/doc/html/rfc4880
				kw = r_search_keyword_new_hexmask ("8c0d04010302", NULL); // IDEA
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04020302", NULL); // 3DES
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04030302", NULL); // CAST5
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04040302", NULL); // BFISH
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04070302", NULL); // AES128
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04080302", NULL); // AES192
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d04090302", NULL); // AES256
				r_search_kw_add (search, kw);
				kw = r_search_keyword_new_hexmask ("8c0d040a0302", NULL); // 2FISH
				r_search_kw_add (search, kw);

				// PGP RSA encrypted key v4 artifacts.
				// RSA Public exponent e = 2^16+1: 0011010001
				// Secret-key data is encrypted: ff or fe
				// Sym algo mask: 00 to 0a.
				// String to key identifier: 03
				// Hash Algorithm mask: 00 to 0b
				kw = r_search_keyword_new_hex ("0011010001ff000300", "fffffffffffef0fff0", NULL);
				r_search_kw_add (search, kw);
				r_search_begin (core->search);

				break;
			}
		case 'a': // "/ca"
			{
				RSearchKeyword *kw;
				if (input[2] == 'j') {
					param.outmode = R_MODE_JSON;
				}
				kw = r_search_keyword_new_hexmask ("00", NULL);
				// AES search is done over 40 bytes
				kw->keyword_length = AES_SEARCH_LENGTH;
				r_search_reset (core->search, R_SEARCH_AES);
				r_search_kw_add (search, kw);
				r_search_begin (core->search);
				param.aes_search = true;
				break;
			}
		case 'r': // "/cr"
			{
				RSearchKeyword *kw;
				if (input[2] == 'j') {
					param.outmode = R_MODE_JSON;
				}
				kw = r_search_keyword_new_hexmask ("00", NULL);
				// Private key search is at least 11 bytes
				kw->keyword_length = PRIVATE_KEY_SEARCH_LENGTH;
				r_search_reset (core->search, R_SEARCH_PRIV_KEY);
				r_search_kw_add (search, kw);
				r_search_begin (core->search);
				param.privkey_search = true;
				break;
			}
		default: {
			dosearch = false;
			r_core_cmd_help (core, help_msg_slash_c);
		}
		}
	} break;
	case 'm': // "/m"
		dosearch = false;
		if (input[1] == '?') { // "/me"
			r_core_cmd_help (core, help_msg_slash_m);
		} else if (input[1] == 'b') { // "/mb"
			bool bin_verbose = r_config_get_i (core->config, "bin.verbose");
			r_config_set_i (core->config, "bin.verbose", false);
			// TODO : iter maps?
			cmd_search_bin (core, search_itv);
			r_config_set_i (core->config, "bin.verbose", bin_verbose);
		} else if (input[1] == 'm') { // "/mm"
			ut64 addr = search_itv.addr;
			RListIter *iter;
			RIOMap *map;
			int count = 0;
			const int align = core->search->align;
			r_list_foreach (param.boundaries, iter, map) {
				// eprintf ("-- %llx %llx\n", r_io_map_begin (map), r_io_map_end (map));
				r_cons_break_push (NULL, NULL);
				for (addr = r_io_map_begin (map); addr < r_io_map_end (map); addr++) {
					if (r_cons_is_breaked ()) {
						break;
					}
					if (align && (0 != (addr % align))) {
						addr += (addr % align) - 1;
						continue;
					}
					char *mp = r_str_newf ("/mnt%d", count);
					eprintf ("[*] Trying to mount at 0x%08"PFMT64x"\r[", addr);
					if (r_fs_mount (core->fs, NULL, mp, addr)) {
						count ++;
						eprintf ("Mounted %s at 0x%08"PFMT64x"\n", mp, addr);
					}
					free (mp);
				}
				r_cons_clear_line (1);
				r_cons_break_pop ();
			}
			eprintf ("\n");
		} else if (input[1] == 'e') { // "/me"
			r_cons_printf ("* r2 thinks%s\n", input + 2);
		} else if (input[1] == ' ' || input[1] == '\0' || param.outmode == R_MODE_JSON) {
			int ret;
			const char *file = input[param_offset - 1]? input + param_offset: NULL;
			ut64 addr = search_itv.addr;
			RListIter *iter;
			RIOMap *map;
			if (param.outmode == R_MODE_JSON) {
				pj_a (param.pj);
			}
			r_core_magic_reset (core);
			int maxHits = r_config_get_i (core->config, "search.maxhits");
			int hits = 0;
			r_list_foreach (param.boundaries, iter, map) {
				if (param.outmode != R_MODE_JSON) {
					eprintf ("-- %"PFMT64x" %"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
				}
				r_cons_break_push (NULL, NULL);
				for (addr = r_io_map_begin (map); addr < r_io_map_end (map); addr++) {
					if (r_cons_is_breaked ()) {
						break;
					}
					ret = r_core_magic_at (core, file, addr, 99, false, param.outmode == R_MODE_JSON ? param.pj : NULL, &hits);
					if (ret == -1) {
						// something went terribly wrong.
						break;
					}
					if (maxHits && hits >= maxHits) {
						break;
					}
					addr += ret - 1;
				}
				r_cons_clear_line (1);
				r_cons_break_pop ();
			}
			if (param.outmode == R_MODE_JSON) {
				pj_end (param.pj);
			}
		} else {
			eprintf ("Usage: /m [file]\n");
		}
		r_cons_clear_line (1);
		break;
	case 'p': // "/p"
		if (input[1] == '?') { // "/pp" -- find next prelude
			r_core_cmd_help (core, help_msg_search_pattern);
		} else if (input[1] == 'p') { // "/pp" -- find next prelude
			__core_cmd_search_backward_prelude (core, false, true);
		} else if (input[param_offset - 1]) {
			int ps = atoi (input + param_offset);
			if (ps > 1) {
				r_search_set_mode (search, R_SEARCH_PATTERN);
				r_search_pattern_size (search, ps);
				dosearch_read = true;
			} else {
				eprintf ("Invalid pattern size (must be > 0)\n");
			}
		}
		break;
	case 'P': // "/P"
		search_similar_pattern (core, atoi (input + 1), &param);
		break;
	case 'V': // "/V"
		{
			if (input[2] == 'j') {
				param.outmode = R_MODE_JSON;
				param_offset++;
			} else if (strchr (input + 1, '*')) {
				param.outmode = R_MODE_RADARE;
			}
			int err = 1, vsize = atoi (input + 1);
			const char *num_str = input + param_offset + 1;
			if (vsize && input[2] && num_str) {
				if (param.outmode == R_MODE_JSON) {
					pj_a (param.pj);
				}
				char *w = strchr (num_str, ' ');
				if (w) {
					*w++ = 0;
					ut64 vmin = r_num_math (core->num, num_str);
					ut64 vmax = r_num_math (core->num, w);
					if (vsize > 0) {
						RIOMap *map;
						RListIter *iter;
						r_list_foreach (param.boundaries, iter, map) {
							err = 0;
							int hits = r_core_search_value_in_range (core, false, map->itv,
									vmin, vmax, vsize,
									_CbInRangeSearchV, &param);
							if (param.outmode != R_MODE_JSON) {
								eprintf ("hits: %d\n", hits);
							}
						}
					}
				}
				if (param.outmode == R_MODE_JSON) {
					pj_end (param.pj);
				}
			}
			if (err) {
				eprintf ("Usage: /V[1|2|4|8] [minval] [maxval]\n");
			}
		}
		dosearch = false;
		break;
	case 'v': // "/v"
		if (input[1]) {
			if (input[1] == '?') {
				r_cons_print ("Usage: /v[1|2|4|8] [value]\n");
				break;
			}
			if (input[2] == 'j') {
				param.outmode = R_MODE_JSON;
				param_offset++;
			}
		}
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		char *v_str = (char *)r_str_trim_head_ro (input + param_offset);
		RList *nums = r_num_str_split_list (v_str);
		int len = r_list_length (nums);
		int bsize = 0;
		ut8 *v_buf = NULL;
		switch (input[1]) {
		case '8':
			if (input[param_offset]) {
				bsize = sizeof (ut64) * len;
				v_buf = v_writebuf (core, nums, len, '8', bsize);
			} else {
				eprintf ("Usage: /v8 value\n");
			}
			break;
		case '1':
			if (input[param_offset]) {
				bsize = sizeof (ut8) * len;
				v_buf = v_writebuf (core, nums, len, '1', bsize);
			} else {
				eprintf ("Usage: /v1 value\n");
			}
			break;
		case '2':
			if (input[param_offset]) {
				bsize = sizeof (ut16) * len;
				v_buf = v_writebuf (core, nums, len, '2', bsize);
			} else {
				eprintf ("Usage: /v2 value\n");
			}
			break;
		default: // default size
		case '4':
			if (input[param_offset - 1]) {
				if (input[param_offset]) {
					bsize = sizeof (ut32) * len;
					v_buf = v_writebuf (core, nums, len, '4', bsize);
				}
			} else {
				eprintf ("Usage: /v4 value\n");
			}
			break;
		}
		if (v_buf) {
			r_search_kw_add (core->search,
					r_search_keyword_new ((const ut8 *) v_buf, bsize, NULL, 0, NULL));
			free (v_buf);
		}
		r_search_begin (core->search);
		dosearch = true;
		break;
	case 'w': // "/w" search wide string, includes ignorecase search functionality (/wi cmd)!
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_wide_string);
			break;
		}
		if (input[2]) {
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_search_wide_string);
				break;
			}
			if (input[1] == 'j' || input[2] == 'j') {
				param.outmode = R_MODE_JSON;
			}
			if (input[1] == 'i' || input[2] == 'i') {
				ignorecase = true;
			}
		} else {
			param.outmode = R_MODE_RADARE;
		}

		size_t shift = 1 + ignorecase;
		if (param.outmode == R_MODE_JSON) {
			shift++;
		}
		size_t strstart;
		const char *p2;
		char *p;
		strstart = shift + 1;
		len = strlen (input + strstart);
		inp = calloc ((len + 1), 2);
		for (p2 = input + strstart, p = inp; *p2; p += 2, p2++) {
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
		skw = r_search_keyword_new ((const ut8 *) inp, len * 2, NULL, 0, NULL);
		free (inp);
		if (skw) {
			skw->icase = ignorecase;
			r_search_kw_add (core->search, skw);
			r_search_begin (core->search);
			dosearch = true;
		} else {
			eprintf ("Invalid keyword\n");
			break;
		}
	case 'i': // "/i"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_string_no_case);
			break;
		}
		if (input[param_offset - 1] != ' ') {
			eprintf ("Missing ' ' after /i\n");
			r_core_return_value (core, R_CMD_RC_FAILURE);
			goto beach;
		}
		ignorecase = true;
	case 'j': // "/j"
		if (input[0] == 'j' && input[1] == ' ') {
			param.outmode = R_MODE_JSON;
		}
		// fallthrough
	case ' ': // "/ " search string
		inp = strdup (input + 1 + ignorecase + (param.outmode == R_MODE_JSON ? 1 : 0));
		len = r_str_unescape (inp);
#if 0
		if (!json) {
			eprintf ("Searching %d byte(s) from 0x%08"PFMT64x " to 0x%08"PFMT64x ": ",
					len, search_itv.addr, r_itv_end (search_itv));
			for (i = 0; i < len; i++) {
				eprintf ("%02x ", (ut8) inp[i]);
			}
			eprintf ("\n");
		}
#endif
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
	case 'k': // "/k" Rabin Karp String search
		inp = r_str_trim_dup (input + 1);
		len = r_str_unescape (inp);
		r_search_reset (core->search, R_SEARCH_RABIN_KARP);
		r_search_set_distance (core->search, (int)r_config_get_i (core->config, "search.distance"));
		{
			RSearchKeyword *skw;
			skw = r_search_keyword_new ((const ut8 *)inp, len, NULL, 0, NULL);
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
		dosearch_read = true;
		break;
	case 'e': // "/e" match regexp
		if (input[1] == '?') {
			eprintf ("Usage: /e /foo/i or /e/foo/i\n");
		} else if (input[1]) {
			RSearchKeyword *kw;
			kw = r_search_keyword_new_regexp (input + 1, NULL);
			if (!kw) {
				eprintf ("Invalid regexp specified\n");
				break;
			}
			r_search_reset (core->search, R_SEARCH_REGEXP);
			// TODO distance is unused
			r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
			r_search_kw_add (core->search, kw);
			r_search_begin (core->search);
			dosearch_read = true;
		} else {
			eprintf ("Missing regex\n");
		}
		break;
	case 'E': // "/E"
		if (core->bin && r_config_get_b (core->config, "cfg.debug")) {
			r_debug_map_sync (core->dbg);
		}
		do_esil_search (core, &param, input);
		goto beach;
	case 'd': // "/d" search delta key
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_delta);
			break;
		}
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
		char *p, *arg = r_str_trim_dup (input + 1);
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
				search_hash (core, arg, p, min, max, &param);
			}
		} else {
			eprintf ("Missing hash. See ph?\n");
		}
		free (arg);
	}
	break;
	case 'f': // "/f" forward search
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_forward);
			break;
		}
		if (core->offset) {
			st64 coff = core->offset;
			RInterval itv = {core->offset, -coff};
			if (!r_itv_overlap (search_itv, itv)) {
				r_core_return_value (core, R_CMD_RC_SUCCESS);
				goto beach;
			} else {
				search_itv = r_itv_intersect (search_itv, itv);
			}
		}
		break;
	case 'g': // "/g" graph search
		if (input[1] == '?') {
			r_cons_printf ("Usage: /g[g] [fromaddr] @ [toaddr]\n");
			r_cons_printf ("(find all graph paths A to B (/gg follow jumps, see search.count and anal.depth)");
		} else {
			ut64 addr = UT64_MAX;
			if (input[1]) {
				addr = r_num_math (core->num, input + 2);
			} else {
				RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
				if (fcn) {
					addr = fcn->addr;
				} else {
					addr = core->offset;
				}
			}
			const int depth = r_config_get_i (core->config, "anal.depth");
			// Va;ifate input length
			if (input[1] != '\0') {
				r_core_anal_paths (core, addr, core->offset, input[1] == 'g', depth, (input[1] == 'j' || input[2] == 'j'));
			}
		}
		break;
	case 'F': // "/F" search file /F [file] ([offset] ([sz]))
		if (input[param_offset - 1] == ' ') {
			int n_args;
			char **args = r_str_argv (input + param_offset, &n_args);
			ut8 *buf = NULL;
			ut64 offset = 0;
			size_t size;
			buf = (ut8 *)r_file_slurp (args[0], &size);
			if (!buf) {
				eprintf ("Cannot open '%s'\n", args[0]);
				r_str_argv_free (args);
				break;
			}
			if (n_args > 1) {
				offset = r_num_math (core->num, args[1]);
				if (size <= offset) {
					eprintf ("size <= offset\n");
					r_str_argv_free (args);
					free (buf);
					break;
				}
			}
			if (n_args > 2) {
				len = r_num_math (core->num, args[2]);
				if (len > size - offset) {
					eprintf ("len too large\n");
					r_str_argv_free (args);
					free (buf);
					break;
				}
			} else {
				len = size - offset;
			}
			RSearchKeyword *kw;
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)r_config_get_i (core->config, "search.distance"));
			kw = r_search_keyword_new (buf + offset, len, NULL, 0, NULL);
			if (kw) {
				r_search_kw_add (core->search, kw);
				// eprintf ("Searching %d byte(s)...\n", kw->keyword_length);
				r_search_begin (core->search);
				dosearch = true;
			} else {
				eprintf ("no keyword\n");
			}

			r_str_argv_free (args);
			free (buf);
		} else {
			eprintf ("Usage: /F[j] [file] ([offset] ([sz]))\n");
		}
		break;
	case 'x': // "/x" search hex
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_x);
		} else {
			RSearchKeyword *kw;
			char *s, *p = strdup (input + param_offset);
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
				// eprintf ("Searching %d byte(s)...\n", kw->keyword_length);
				r_search_begin (core->search);
				dosearch = true;
			} else {
				eprintf ("no keyword\n");
			}
			free (p);
		}
		break;
	case 's': // "/s"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_search_sections);
			break;
		}
		do_section_search (core, &param, input + 1);
		break;
	case '+': // "/+"
		if (input[1] == ' ') {
			// TODO: support /+j
			char *buf = malloc (strlen (input) * 2);
			char *str = strdup (input + 2);
			int ochunksize;
			int i, len, chunksize = r_config_get_i (core->config, "search.chunk");
			if (chunksize < 1) {
				chunksize = core->rasm->config->bits / 8;
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
			R_LOG_ERROR ("min must be lower than max");
			break;
		}
		r_search_reset (core->search, R_SEARCH_STRING);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		{
			RSearchKeyword *kw = r_search_keyword_new_hexmask ("00", NULL);
			kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
			r_search_kw_add (search, kw);
		}
		r_search_begin (search);
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
	r_config_set_i (core->config, "search.kwidx", search->n_kws);
	if (dosearch) {
		do_string_search (core, search_itv, &param);
	} else if (dosearch_read) {
		// TODO: update pattern search to work with this
		if (search->mode != R_SEARCH_PATTERN) {
			r_search_set_read_cb (search, &_cb_hit_sz, &param);
		}
		r_search_maps (search, param.boundaries);
	}
beach:
	if (errcode != -1) {
		r_core_return_value (core, errcode);
	} else {
		r_core_return_value (core, search->nhits);
	}
	core->in_search = false;
	r_flag_space_pop (core->flags);
	if (param.outmode == R_MODE_JSON) {
		r_cons_println (pj_string (param.pj));
	}
	pj_free (param.pj);
	r_list_free (param.boundaries);
	r_search_kw_reset (search);
	return R_CMD_RC_SUCCESS;
}
