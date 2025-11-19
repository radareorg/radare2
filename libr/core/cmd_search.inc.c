/* radare - LGPL - Copyright 2010-2025 - pancake */

#if R_INCLUDE_BEGIN

#include <sdb/ht_uu.h>
#include "cmd_search_rop.inc.c"

static int cmd_search(void *data, const char *input);

#define USE_EMULATION 1

#define AES_SEARCH_LENGTH 40
#define SM4_SEARCH_LENGTH 24
#define ASN1_PRIVATE_KEY_SEARCH_LENGTH 11
#define RAW_PRIVATE_KEY_SEARCH_LENGTH 32
#define ED25519_PUBKEY_LENGTH 32*2

static RCoreHelpMessage help_msg_slash_wide_string = {
	"Usage: /w[ij]", "[str]", "Wide string search subcommands",
	"/w ", "foo", "search for wide string 'f\\0o\\0o\\0'",
	"/wj ", "foo", "search for wide string 'f\\0o\\0o\\0' (json output)",
	"/wi ", "foo", "search for wide string 'f\\0o\\0o\\0' but ignoring case",
	"/wij ", "foo", "search for wide string 'f\\0o\\0o\\0' but ignoring case (json output)",
	NULL
};

static RCoreHelpMessage help_msg_slash_esil = {
	"/E", " [esil-expr]", "search offsets matching a specific esil expression",
	"/Ej", " [esil-expr]", "same as above but using the given magic file",
	"/E?", " ", "show this help",
	"\nExamples:", "", "",
	"", "/E $$,0x100001060,-,!", "hit when address is 0x100001060",
	NULL
};

static RCoreHelpMessage help_msg_slash_backward = {
	"Usage: /b[p]<command>", "[value]", "Backward search subcommands",
	"/b", "[x] [str|414243]", "search in hexadecimal 'ABC' backwards starting in current address",
	"/bp", "", "search previous prelude and set hit.prelude flag",
	NULL
};

static RCoreHelpMessage help_msg_slash_forward = {
	"Usage: /f", " ", "search forwards, command modifier, followed by other command",
	NULL
};

static RCoreHelpMessage help_msg_slash_sections = {
	"Usage: /s[*]", "[threshold]", "Find sections by grouping blocks with similar entropy.",
	"/s", "[threshold]", "find sections using human friendly output",
	"/sj", "[threshold]", "use json output",
	"/s*", "[threshold]", "use r2 flavor output",
	NULL
};

static RCoreHelpMessage help_msg_slash_delta = {
	"Usage: /d", "delta", "search for a deltified sequence of bytes.",
	NULL
};

static RCoreHelpMessage help_msg_slash_pattern = {
	"Usage: /p[p]", " [pattern]", "Search for patterns or preludes",
	"/p", " [hexpattern]", "search in hexpairs pattern in search.in",
	"/pp", "", "search for function preludes",
	NULL
};

static RCoreHelpMessage help_msg_slash_ad = {
	"Usage: /ad[/<*jq>]", "[value]", "Backward search subcommands",
	"/ad", " rax", "search in plaintext disasm for matching instructions",
	"/ad", " rax$", "search in plaintext disasm for instruction matchin given glob expression",
	"/adj", " rax", "json output searching in disasm with plaintext",
	"/adq", " rax", "quiet mode ideal for scripting",
	"/ad/", " ins1;ins2", "search for regex instruction 'ins1' followed by regex 'ins2'",
	"/ad/a", " instr", "search for every byte instruction that matches regexp 'instr'",
	NULL
};

static RCoreHelpMessage help_msg_slash_magic = {
	"/m", "", "search for known magic patterns",
	"/m", " [file]", "same as above but using the given magic file",
	"/me", " [msg]", "like ?e similar to IRC's /me",
	"/mm", "", "search for known filesystems and mount them automatically",
	"/mb", "", "search recognized RBin headers",
	NULL
};

static RCoreHelpMessage help_msg_slash = {
	"Usage:", "/[!bf] [arg]", "Search stuff (see 'e??search' for options)\n"
	"Use io.va for searching in non virtual addressing spaces",
	"/", " foo\\x00", "search for string 'foo\\0'",
	"/j", " foo\\x00", "search for string 'foo\\0' (json output)",
	"/!", " ff", "search for first occurrence not matching, command modifier",
	"/!x", " 00", "inverse hexa search (find first byte != 0x00)",
	"/+", " /bin/sh", "construct the string with chunks",
	"//", "", "repeat last search",
	"/a", "[?][1aoditfmsltf] jmp eax", "find instructions by text or bytes (asm/disasm)",
	"/b", "[?][p]", "search backwards, command modifier, followed by other command",
	"/B", "", "search possible base address",
	"/c", "[?][adr]", "search for crypto materials",
	"/d", " 101112", "search for a deltified sequence of bytes",
	"/e", " /E.F/i", "match regular expression",
	"/E", " esil-expr", "address matching given esil expressions $$ = here",
	"/f", "", "search forwards, (command modifier)",
	"/F", " file [off] [sz]", "search contents of file with offset and size",
	// TODO: add subcommands to find paths between functions and filter only function names instead of offsets, etc
	"/g", "[g] [from]", "find all graph paths A to B (/gg follow jumps, see search.count and anal.depth)",
	"/h", "[?*] [algo] [digest] [size]", "find block of size bytes having this digest (see ph)",
	"/i", " foo", "search for string 'foo' ignoring case",
	"/k", " foo", "search for string 'foo' using Rabin Karp alg",
	"/m", "[?][ebm] magicfile", "search for magic, filesystems or binary headers",
	"/o", " [n]", "show offset of n instructions backward",
	"/O", " [n]", "same as /o, but with a different fallback if anal cannot be used",
	"/p", "[?][p] patternsize", "search for pattern of given size",
	"/P", " patternsize", "search similar blocks",
	"/s", "[*] [threshold]", "find sections by grouping blocks with similar entropy",
	"/r", "[?][erwx] sym.printf", "analyze opcode reference an offset (/re for esil)",
	"/R", "[?] [grepopcode]", "search for matching ROP gadgets, semicolon-separated",
	// moved into /as "/s", "", "search for all syscalls in a region (EXPERIMENTAL)",
	"/v", "[1248] value", "look for an `cfg.bigendian` 32bit value",
	"/V", "[1248] min max", "look for an `cfg.bigendian` 32bit value in range",
	"/w", " foo", "search for wide string 'f\\0o\\0o\\0'",
	"/wi", " foo", "search for wide string ignoring case 'f\\0o\\0o\\0'",
	"/x", "[?] [bytes]", "search for hex string with mask, ignoring some nibbles",
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

static RCoreHelpMessage help_msg_slash_at = {
	"Usage:", "/at[flmj] [arg]", "Search for instructions matching type/family/mnemonic",
	"/at", " [optype,optype2]", "list instructions matching any of the comma separated optypes",
	"/atj", " [optype,optype2]", "same as above but using json as output",
	"/atf", " [family]", "search for given-family type of instructions",
	"/atl", "", "list all the instruction types (RAnalOp.Type)",
	"/atm", "", "search matching only the instruction mnemonic",
	NULL
};

static RCoreHelpMessage help_msg_slash_a = {
	"Usage:", "/a[?] [arg]", "Search for assembly instructions matching given properties",
	"/a", " push rbp", "assemble given instruction and search the bytes",
	"/a1", " [number]", "find valid assembly generated by changing only the nth byte",
	"/aI", "", "search for infinite loop instructions (jmp $$)",
	"/aa", " mov eax", "linearly find aproximated assembly (case insensitive strstr)",
	"/ab", "[f] [delta]", "search for backward jumps (usually loops)",
	"/ac", " mov eax", "same as /aa, but case-sensitive",
	"/ad", "[?][/*jq] push;mov", "match ins1 followed by ins2 in linear disasm",
	"/ae", " esil", "search for esil expressions matching substring",
	"/af", "[l] family", "search for instruction of specific family (afl=list)",
	"/aF", "[d] opstr", "find instructions matching given opstr only in analyzed code",
	"/ai", "[j] 0x300 [0x500]", "find all the instructions using that immediate (in range)",
	"/al", "", "same as aoml, list all opcodes",
	"/am", " opcode", "search for specific instructions of specific mnemonic",
	"/ao", " instr", "search for instruction 'instr' (in all offsets)",
	"/as", "[qjl] ([type])", "search for syscalls (See /at swi and /af priv)",
	"/at", "[?][qjl] ([type])", "search for instructions of given type",
	"/az", "[q] ([minstr])", "search assembly constructed strings (q)uiet reduces FP (uses bin.minsz)",
	NULL
};

static RCoreHelpMessage help_msg_slash_c = {
	"Usage: /c", "", "Search for crypto materials",
	"/ca", "[?] [algo]", "search for keys expanded in memory (algo can be 'aes' or 'sm4')",
	"/cc", "[?] [algo] [digest]", "find collisions (bruteforce block length values until given checksum is found)",
	"/cd", "", "search for ASN1/DER certificates",
	"/cg", "", "search for GPG/PGP keys and signatures (Plaintext and binary form)",
	"/ck", "", "find well known constant tables from different hash and crypto algorithms",
	"/cp", "[?] [algo] [pubkey]", "search for a private key matching a given public key",
	"/cr", "", "search for ASN1/DER private keys (RSA and ECC)",
	NULL
};

static RCoreHelpMessage help_msg_slash_cc = {
	"Usage: /cc[aAldpb]", "[algo] [digest]", "find collisions",
	"/cca", " [algo] [digest]", "lowercase alphabet chars only",
	"/ccA", " [algo] [digest]", "uppercase alphabet chars only",
	"/ccl", " [algo] [digest]", "letters (lower + upper alphabet chars)",
	"/ccd", " [algo] [digest]", "digits (only numbers)",
	"/ccp", " [algo] [digest]", "printable (alpha + digit)",
	"/ccb", " [algo] [digest]", "binary (any number is valid)",
	NULL
};

static RCoreHelpMessage help_msg_slash_k = {
	"Usage:", "/k[j] [foo]", "search for string using Rabin Karp algorithm",
	"/k", " foo", "search for string 'foo'",
	"/kj", " foo", "same as above but using json as output",
	NULL
};

static RCoreHelpMessage help_msg_slash_r = {
	"Usage:", "/r[acerwx] [address]", " search references to this specific address",
	"/r", " [addr]", "search references to this specific address",
	"/ra", "", "search all references",
	"/rc", " ([addr])", "search for call references",
	"/re", " [addr]", "search references using esil",
	"/rr", "", "find read references",
	"/ru", "[*qj]", "search for UDS CAN database tables (binbloom)",
	"/rw", "", "find write references",
	"/rx", "", "find exec references",
	NULL
};

static RCoreHelpMessage help_msg_slash_R = {
	"Usage: /R", "", "search for ROP gadgets (see \"? for escaping chars in the shell)",
	"/R", " [string]", "show gadgets",
	"/R/", " [regexp]", "show gadgets [regular expression]",
	"/R/j", " [regexp]", "json output [regular expression]",
	"/R/q", " [regexp]", "show gadgets in a quiet manner [regular expression]",
	"/Rj", " [string]", "json output",
	"/Rk", " [ropklass]", "query stored ROP gadgets klass",
	"/Rq", " [string]", "show gadgets in a quiet manner",
	NULL
};

static RCoreHelpMessage help_msg_slash_Rk = {
	"Usage: /Rk", "", "query stored ROP gadgets",
	"/Rk", " [nop|mov|const|arithm|arithm_ct]", "show gadgets",
	"/Rkj", "", "json output",
	"/Rkq", "", "list Gadgets offsets",
	NULL
};

static RCoreHelpMessage help_msg_slash_x = {
	"Usage:", "/x[v] [hexpairs]:[binmask]", "search in memory",
	"/x ", "9090cd80", "search for those bytes",
	"/x ", "ff..33", "search for hex string ignoring some nibbles",
	"/x ", "9090cd80:ffff7ff0", "search with binary mask",
	"/xn", "[1|2|4|8] value amount", "search for an array of Value repeated Amount of times",
	"/xv", "[1|2|4|8] v0 v1 v2 v3 ..", "search for an array of values with given size and endian",
	NULL
};

struct search_parameters {
	RCore *core;
	RList *boundaries;
	const char *mode;
	const char *cmd_hit;
	PJ *pj;
	int outmode; // 0 or R_MODE_RADARE or R_MODE_JSON
	bool inverse;
	bool key_search;
	int key_search_len;
	int searchflags;
	int searchshow;
	const char *searchprefix;
	int c; // used for progress
	int count;
	bool progressbar;
};

struct endlist_pair {
	int instr_offset;
	int delay_size;
};

static inline void print_search_progress(ut64 at, ut64 to, int n, struct search_parameters *param) {
	if (!param->progressbar) {
		return;
	}
	if ((++param->c % 64) || (param->outmode == R_MODE_JSON)) {
		return;
	}
	RCons *cons = param->core->cons;
	if (cons->columns < 50) {
		eprintf ("\r[  ]  0x%08" PFMT64x "  hits = %d   \r%s",
			at, n, (param->c % 2)? "[ #]": "[# ]");
	} else {
		eprintf ("\r[  ]  0x%08" PFMT64x " < 0x%08" PFMT64x "  hits = %d   \r%s",
			at, to, n, (param->c % 2)? "[ #]": "[# ]");
	}
}

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

	r_cons_break_push (core->cons, NULL, NULL);
	for (j = minlen; j <= maxlen; j++) {
		ut32 len = j;
		R_LOG_INFO ("Searching %s for %d byte length", hashname, j);
		r_list_foreach (param->boundaries, iter, map) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			ut64 from = r_io_map_begin (map);
			ut64 to = r_io_map_end (map);
			st64 bufsz;
			bufsz = to - from;
			if (len > bufsz) {
				R_LOG_ERROR ("Hash length is bigger than range 0x%"PFMT64x, from);
				continue;
			}
			buf = malloc (bufsz);
			if (!buf) {
				R_LOG_ERROR ("Cannot allocate %"PFMT64d " bytes", bufsz);
				goto hell;
			}
			R_LOG_INFO ("Search in range 0x%08"PFMT64x " and 0x%08"PFMT64x, from, to);
			int blocks = (int) (to - from - len);
			R_LOG_INFO ("Carving %d blocks", blocks);
			(void) r_io_read_at (core->io, from, buf, bufsz);
			for (i = 0; (from + i + len) < to; i++) {
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				char *s = r_hash_tostring (NULL, hashname, buf + i, len);
				print_search_progress (i, to, 0, param);
				if (!s) {
					R_LOG_ERROR ("Hash fail");
					break;
				}
				if (!strcmp (s, hashstr)) {
					if (param->searchflags) {
						char hash_short[9];
						r_str_ncpy (hash_short, hashstr, sizeof (hash_short));
						r_strf_var (flag, 256, "%s.%s", hashname, hash_short);
						r_cons_printf (core->cons, "0x%" PFMT64x ": %s : %s\n", from + i, flag, hashstr);
						r_flag_set (core->flags, flag, from + i, len);
					} else {
						r_cons_printf (core->cons, "f hash.%s.%s = 0x%" PFMT64x "\n", hashname, hashstr, from + i);
					}

					free (s);
					free (buf);
					return 1;
				}
				free (s);
			}
			free (buf);
		}
	}
	r_cons_break_pop (core->cons);
	R_LOG_WARN ("No hashes found");
	return 0;
hell:
	return -1;
}

static void cmd_search_bin(RCore *core, RInterval itv) {
	ut64 from = itv.addr;
	ut64 to = r_itv_end (itv);
	int size; // , sz = sizeof (buf);
	if (to == UT64_MAX) {
		size = r_io_size (core->io);
		to = from + size;
	}
	int fd = core->io->desc->fd;
	RBuffer *b = r_buf_new_with_io (&core->anal->iob, fd);

	r_cons_break_push (core->cons, NULL, NULL);
	while (from < to) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		RBuffer *ref = r_buf_new_slice (b, from, to);
		RBinPlugin *plug = r_bin_get_binplugin_by_buffer (core->bin, NULL, ref);
		if (plug) {
			// ignore bin plugins with lots of false positives
			if (plug->weak_guess) {
				goto next;
			}
			r_cons_printf (core->cons, "0x%08" PFMT64x "  %s\n", from, plug->meta.name);
			if (plug->size) {
				RBinFileOptions opt = {
					.pluginname = plug->meta.name,
					.baseaddr = 0,
					.loadaddr = 0,
					.sz = 4096,
					.xtr_idx = 0,
					.rawstr = core->bin->options.rawstr,
					.fd = fd,
				};
				r_bin_open_io (core->bin, &opt);
				size = plug->size (core->bin->cur);
				if (size > 0) {
					r_cons_printf (core->cons, "size %d\n", size);
				}
			}
		}
next:;
		r_buf_free (ref);
		from++;
	}
	r_buf_free (b);
	r_cons_break_pop (core->cons);
}

typedef struct {
	RCore *core;
	bool forward;
	int preludecnt;
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
	UserPrelude *up = (UserPrelude*) user;
	RCore *core = up->core;
	if (r_config_get_b (core->config, "anal.calls")) {
		// XXX dont use RCore.cmdf here its slow
		r_core_cmdf (core, "afr@0x%"PFMT64x, addr);
	} else {
		int depth = r_config_get_i (core->config, "anal.depth");
		r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	}
	up->preludecnt++;
	return 1;
}

R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	ut64 at;
	ut8 *b = (ut8 *) malloc (core->blocksize);
	if (!b) {
		return 0;
	}
	char *zeropage = calloc (core->blocksize, 1);
	if (!zeropage) {
		free (b);
		return 0;
	}
	// TODO: handle sections ?
	if (from >= to) {
		R_LOG_ERROR ("aap: Invalid search range 0x%08"PFMT64x " - 0x%08"PFMT64x, from, to);
		free (b);
		free (zeropage);
		return 0;
	}
	r_search_reset (core->search, R_SEARCH_KEYWORD);
	RSearchKeyword *kw = r_search_keyword_new (buf, blen, mask, mlen, NULL);
	const int afuncali = r_anal_archinfo (core->anal, R_ARCH_INFO_FUNC_ALIGN);
	const int ufuncali = r_config_get_i (core->config, "cfg.fcnalign");
	if (ufuncali > 1) {
		kw->align = ufuncali;
	} else if (afuncali > 1) {
		kw->align = afuncali;
	}
	r_search_kw_add (core->search, kw);
	r_search_begin (core->search);
	UserPrelude up = {core, false, 0};
	r_search_set_callback (core->search, &__prelude_cb_hit, &up);
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (!r_io_is_valid_offset (core->io, at, 0)) {
			break;
		}
		(void)r_io_read_at (core->io, at, b, core->blocksize);
		// if the whole block is 00 skip, if its all ff da same
		// aap takes 14s instead of 1s to scan a 800MB page
		if (!memcmp (b, zeropage, core->blocksize)) {
			continue;
		}
		if (r_search_update (core->search, at, b, core->blocksize) == -1) {
			R_LOG_ERROR ("update read error at 0x%08"PFMT64x, at);
			break;
		}
	}
	free (zeropage);
	// r_search_reset might also benifet from having an if (s->data) R_FREE(s->data),
	// but im not sure. Add a commit that puts it in there to this PR if it wouldn't
	// break anything. (don't have to worry about this happening again, since all
	// searches start by resetting core->search) For now we use `r_search_kw_reset`
	r_search_kw_reset (core->search);
	free (b);
	return up.preludecnt;
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
					r_cons_printf (core->cons, "f uds.%"PFMT64x".%d=0x%08" PFMT64x "\n", uds->addr, uds->stride, uds->addr);
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
		r_cons_print (core->cons, s);
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

	// 256MB scan region limit
// #define RANGE_LIMIT 0xfffffff
	// 4GB scan region limit
#define RANGE_LIMIT 0xffffffff
	size_t fc0 = r_list_length (core->anal->fcns);
	r_list_foreach (list, iter, p) {
		if ((r_itv_end (p->itv) - p->itv.addr) >= RANGE_LIMIT) {
			// skip searching in large regions
			R_LOG_ERROR ("aap: skipping large range, please check 'anal.in' variable");
			continue;
		}
		if (log) {
			eprintf ("\r[>] Scanning %s 0x%"PFMT64x " - 0x%"PFMT64x " ",
				r_str_rwx_i (p->perm), p->itv.addr, r_itv_end (p->itv));
			if (!(p->perm & R_PERM_X)) {
				R_LOG_INFO ("skip");
				continue;
			}
		}
		from = p->itv.addr;
		to = r_itv_end (p->itv);
		if (R_STR_ISNOTEMPTY (prelude)) {
			ut8 *kw = malloc (strlen (prelude) + 1);
			if (kw) {
				int kwlen = r_hex_str2bin (prelude, kw);
				if (kwlen < 1) {
					R_LOG_ERROR ("Invalid prelude hex string (%s)", prelude);
					break;
				}
				ret = r_core_search_prelude (core, from, to, kw, kwlen, NULL, 0);
				free (kw);
			}
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
					R_LOG_WARN ("ap: Unsupported asm.arch and asm.bits");
				}
			}
			r_list_free (preds);
		}
		if (log) {
			R_LOG_INFO ("done");
		}
	}
	if (log) {
		if (list) {
			size_t fc1 = r_list_length (core->anal->fcns);
			R_LOG_INFO ("Found %d new functions based on preludes", (int)(fc1 - fc0));
		} else {
			R_LOG_ERROR ("No executable regions to scan, cannot analyze anything");
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
	R_RETURN_VAL_IF_FAIL (kw && user, -1);
	struct search_parameters *param = user;
	RCore *core = param->core;
	ut64 base_addr = 0;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;

	if (param->searchshow && kw && kw->keyword_length > 0) {
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
					snprintf (p, 3, "%02x", buf[i]);
					p += 2;
				}
				if (bytes != len) {
					r_str_cpy (p, "...");
					p += 3;
				}
				*p = 0;
			} else {
				R_LOG_ERROR ("Cannot allocate %d bytes", mallocsize);
			}
			s = str;
			str = NULL;
			break;
		}

		if (param->outmode == R_MODE_JSON) {
			pj_o (param->pj);
			pj_kn (param->pj, "addr", base_addr + addr);
			pj_ks (param->pj, "type", type);
			pj_ks (param->pj, "data", s);
			pj_end (param->pj);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x " %s%d_%d %s\n",
				base_addr + addr, param->searchprefix, kw->kwidx, kw->count, s);
		}
		free (s);
		free (buf);
		free (str);
	} else if (kw) {
		if (param->outmode == R_MODE_JSON) {
			pj_o (param->pj);
			pj_kn (param->pj, "addr", base_addr + addr);
			pj_ki (param->pj, "len", klen);
			pj_end (param->pj);
		} else {
			if (param->searchflags) {
				r_cons_printf (core->cons, "%s%d_%d\n", param->searchprefix, kw->kwidx, kw->count);
			} else {
				r_cons_printf (core->cons, "f %s%d_%d %d 0x%08"PFMT64x "\n", param->searchprefix,
					kw->kwidx, kw->count, klen, base_addr + addr);
			}
		}
	}
	if (param->searchflags && kw) {
		char *flag = r_str_newf ("%s%d_%d", param->searchprefix, kw->kwidx, kw->count);
		r_flag_set (core->flags, flag, base_addr + addr, klen);
		free (flag);
	}
	if (*param->cmd_hit) {
		ut64 here = core->addr;
		r_core_seek (core, base_addr + addr, true);
		r_core_cmd (core, param->cmd_hit, 0);
		r_core_seek (core, here, true);
	}
	return true;
}

static int _cb_hit(RSearchKeyword * R_NULLABLE kw, void *user, ut64 addr) {
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

static void append_bound(RList *list, RIO *io, RInterval search_itv, ut64 from, ut64 size, int perms) {
	RIOMap *map = R_NEW0 (RIOMap);
	if (io && io->desc) {
		map->fd = r_io_fd_get_current (io);
	}

	map->perm = perms;
	RInterval itv = {from, size};
	if (size == -1) {
		R_LOG_WARN ("Invalid range. Use different search.in=? or anal.in=dbg.maps.x");
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
	R_RETURN_VAL_IF_FAIL (core, NULL);

	RList *list = r_list_newf (free); // XXX r_io_map_free);
	if (!list) {
		return NULL;
	}

	char bound_in[32] = {0};
	char bound_from[32] = {0};
	char bound_to[32] = {0};
	snprintf (bound_in, sizeof (bound_in), "%s.%s", prefix, "in");
	snprintf (bound_from, sizeof (bound_from), "%s.%s", prefix, "from");
	snprintf (bound_to, sizeof (bound_to), "%s.%s", prefix, "to");
	const ut64 search_from = r_config_get_i (core->config, bound_from);
	const ut64 search_to = r_config_get_i (core->config, bound_to);
	const RInterval search_itv = {search_from, search_to - search_from};
	if (!mode) {
		mode = r_config_get (core->config, bound_in);
		if (!mode) {
			mode = "search";
		}
	}
	if (perm == -1) {
		perm = R_PERM_RWX;
	}
	if (!strcmp (mode, "flag")) {
		const RList *ls = r_flag_get_list (core->flags, core->addr);
		RFlagItem *fi;
		RListIter *iter;
		r_list_foreach (ls, iter, fi) {
			if (fi->size > 1) {
				append_bound (list, core->io, search_itv, fi->addr, fi->size, 7);
			}
		}
	} else if (r_str_startswith (mode, "flag:")) {
		const char *match = mode + 5;
		const RList *ls = r_flag_get_list (core->flags, core->addr);
		RFlagItem *fi;
		RListIter *iter;
		r_list_foreach (ls, iter, fi) {
			if (fi->size > 1 && r_str_glob (fi->name, match)) {
				append_bound (list, core->io, search_itv, fi->addr, fi->size, 7);
			}
		}
	} else if (!r_config_get_b (core->config, "cfg.debug") && !core->io->va) {
		append_bound (list, core->io, search_itv, 0, r_io_size (core->io), 7);
	} else if (!strcmp (mode, "file")) {
		append_bound (list, core->io, search_itv, 0, r_io_size (core->io), 7);
	} else if (!strcmp (mode, "block")) {
		append_bound (list, core->io, search_itv, core->addr, core->blocksize, 7);
	} else if (!strcmp (mode, "io.map")) {
		RIOMap *m = r_io_map_get_at (core->io, core->addr);
		if (m) {
			append_bound (list, core->io, search_itv, m->itv.addr, m->itv.size, m->perm);
		}
	} else if (!strcmp (mode, "io.maps")) {
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
		const char *sperm = mode + strlen ("io.maps.");
		int mask = r_str_rwx (sperm);
		if (mask < 0) {
			R_LOG_WARN ("Invalid permissions string %s", sperm);
			mask = 0;
		}
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
		int len = strlen ("bin.segments");
		const char *sperm = mode + len;
		int mask = (mode[len] == '.')? r_str_rwx (sperm + 1): 0;
		if (mask < 0) {
			R_LOG_WARN ("Invalid permissions string %s", sperm + 1);
			mask = 0;
		}
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
			append_bound (list, core->io, search_itv, from, to - from, 1);
		}
	} else if (r_str_startswith (mode, "bin.ormaps")) {
		// int mask = (mode[len - 1] == '.')? r_str_rwx (mode + len): 0;
		r_list_free (list);
		list = r_core_get_boundaries_prot (core, perm, "bin.sections.x", prefix);
		if (r_list_length (list) == 0) {
			r_list_free (list);
			return r_core_get_boundaries_prot (core, perm, "io.maps.x", prefix);
		}
		return list;
	} else if (r_str_startswith (mode, "bin.sections")) {
		const size_t len = strlen ("bin.sections");
		const char *sperm = mode + len;
		int mask = (mode[len] == '.')? r_str_rwx (sperm + 1): 0;
		if (mask < 0) {
			R_LOG_WARN ("Invalid permissions string %s", sperm + 1);
			mask = 0;
		}
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
				ut64 addr = core->io->va?
					r_bin_file_get_vaddr(core->bin->cur, s->paddr, s->vaddr) : s->paddr;
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
				if (R_BETWEEN (addr, core->addr, addr + size)) {
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
				if (R_BETWEEN (addr, core->addr, addr + size)) {
					append_bound (list, core->io, search_itv, addr, size, s->perm);
				}
			}
		}
	} else if (!strcmp (mode, "anal.fcn") || !strcmp (mode, "anal.bb")) {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
			R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (f) {
			ut64 from = f->addr, size = r_anal_function_size_from_entry (f);

			/* Search only inside the basic block */
			if (!strcmp (mode, "anal.bb")) {
				RListIter *iter;
				RAnalBlock *bb;

				r_list_foreach (f->bbs, iter, bb) {
					ut64 at = core->addr;
					if ((at >= bb->addr) && (at < (bb->addr + bb->size))) {
						from = bb->addr;
						size = bb->size;
						break;
					}
				}
			}
			append_bound (list, core->io, search_itv, from, size, 5);
		} else {
			R_LOG_WARN ("search.in = ( anal.bb | anal.fcn ) requires to seek into a valid function");
			append_bound (list, core->io, search_itv, core->addr, 1, 5);
		}
	} else if (r_str_startswith (mode, "dbg.")) {
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
				ut64 from = core->addr;
				ut64 to = core->addr;
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
					// nmap->fd = core->io->desc->fd;
					r_io_map_set_begin (nmap, from);
					r_io_map_set_size (nmap, to - from);
					nmap->perm = perm;
					nmap->delta = 0;
					r_list_append (list, nmap);
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
					const char *sperm = mode + strlen ("dbg.maps.");
					mask = r_str_rwx (sperm);
					if (mask < 1) {
						R_LOG_WARN ("Invalid permissions string %s", sperm);
						mask = 0;
					}
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
			append_bound (list, core->io, search_itv, core->addr, core->blocksize, 5);
		} else {
			// TODO: repeat last search doesnt works for /a
			ut64 from = r_config_get_i (core->config, bound_from);
			if (from == UT64_MAX) {
				from = core->addr;
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
	HtUU *localbadstart = ht_uu_new0 ();
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
		int error = r_anal_op (core->anal, &aop, addr, buf + idx, buflen - idx, R_ARCH_OP_MASK_DISASM);
		if (error < 0 || (nb_instr == 0 && (is_end_gadget (&aop, 0) || aop.type == R_ANAL_OP_TYPE_NOP))) {
			valid = false;
			goto ret;
		}
		const int opsz = aop.size;
		// opsz = r_strbuf_length (asmop.buf);
		char *opst = aop.mnemonic;
		if (!opst) {
			R_LOG_ERROR ("Missing mnemonic after disasm");
			RAnalOp asmop;
			r_asm_set_pc (core->rasm, addr);
			if (r_asm_disassemble (core->rasm, &asmop, buf + idx, buflen - idx) < 0) {
				valid = false;
				goto ret;
			}
			opst = strdup (r_str_get (asmop.mnemonic));
			r_anal_op_fini (&asmop);
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
		nb_instr++;
		r_anal_op_fini (&aop);
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
			RAnalOp asmop;
			ut8 *buf = malloc (hit->len);
			if (!buf) {
				return;
			}
			r_io_read_at (core->io, hit->addr, buf, hit->len);
			r_asm_set_pc (core->rasm, hit->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ARCH_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			pj_o (pj);
			pj_kn (pj, "addr", hit->addr);
			pj_ki (pj, "size", hit->len);
			pj_ks (pj, "opcode", asmop.mnemonic);
			pj_ks (pj, "type", r_anal_optype_tostring (analop.type));
			pj_end (pj);
			free (buf);
			r_anal_op_fini (&asmop);
			r_anal_op_fini (&analop);
		}
		pj_end (pj);
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf (core->cons, "Gadget size: %d\n", (int)size);
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
		r_cons_printf (core->cons, "0x%08"PFMT64x ":",
			((RCoreAsmHit *) hitlist->head->data)->addr);
		r_list_foreach (hitlist, iter, hit) {
			RAnalOp asmop;
			ut8 *buf = malloc (hit->len);
			r_io_read_at (core->io, hit->addr, buf, hit->len);
			r_asm_set_pc (core->rasm, hit->addr);
			r_asm_disassemble (core->rasm, &asmop, buf, hit->len);
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ARCH_OP_MASK_BASIC);
			size += hit->len;
			const char *opstr = R_STRBUF_SAFEGET (&analop.esil);
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				r_list_append (ropList, r_str_newf (" %s", opstr));
			}
			if (esil) {
				r_cons_printf (core->cons, "%s\n", opstr);
			} else if (colorize) {
				buf_asm = r_print_colorize_opcode (core->print, asmop.mnemonic,
					core->cons->context->pal.reg, core->cons->context->pal.num, false, 0);
				r_cons_printf (core->cons, " %s%s;", buf_asm, Color_RESET);
				free (buf_asm);
			} else {
				r_cons_printf (core->cons, " %s;", asmop.mnemonic);
			}
			free (buf);
			r_anal_op_fini (&asmop);
			r_anal_op_fini (&analop);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf (core->cons, "Gadget size: %d\n", (int)size);
			r_strf_var (key, 32, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
		break;
	default:
		// Print gadgets with new instruction on a new line.
		r_list_foreach (hitlist, iter, hit) {
			RAnalOp asmop;
			const char *comment = rop_comments? r_meta_get_string (core->anal, R_META_TYPE_COMMENT, hit->addr): NULL;
			if (hit->len < 0) {
				R_LOG_ERROR ("Invalid hit length here");
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
			r_anal_op (core->anal, &analop, hit->addr, buf, hit->len, R_ARCH_OP_MASK_ESIL);
			size += hit->len;
			if (analop.type != R_ANAL_OP_TYPE_RET) {
				char *opstr_n = r_str_newf (" %s", R_STRBUF_SAFEGET (&analop.esil));
				r_list_append (ropList, (void *) opstr_n);
			}
			char *asm_op_hex = r_hex_bin2strdup(asmop.bytes, asmop.size);
			if (colorize) {
				char *buf_asm = r_print_colorize_opcode (core->print, asmop.mnemonic,
					core->cons->context->pal.reg, core->cons->context->pal.num, false, 0);
				otype = r_print_color_op_type (core->print, analop.type);
				if (comment) {
					r_cons_printf (core->cons, "  0x%08" PFMT64x " %18s%s  %s%s ; %s\n",
						hit->addr, asm_op_hex, otype, buf_asm, Color_RESET, comment);
				} else {
					r_cons_printf (core->cons, "  0x%08" PFMT64x " %18s%s  %s%s\n",
						hit->addr, asm_op_hex, otype, buf_asm, Color_RESET);
				}
				free (buf_asm);
			} else {
				if (comment) {
					r_cons_printf (core->cons, "  0x%08" PFMT64x " %18s  %s ; %s\n",
						hit->addr, asm_op_hex, asmop.mnemonic, comment);
				} else {
					r_cons_printf (core->cons, "  0x%08" PFMT64x " %18s  %s\n",
						hit->addr, asm_op_hex, asmop.mnemonic);
				}
			}
			free (asm_op_hex);
			free (buf);
			r_anal_op_fini (&analop);
			r_anal_op_fini (&asmop);
		}
		if (db && hit) {
			const ut64 addr = ((RCoreAsmHit *) hitlist->head->data)->addr;
			// r_cons_printf (core->cons, "Gadget size: %d\n", (int)size);
			r_strf_var (key, 32, "0x%08"PFMT64x, addr);
			rop_classify (core, db, ropList, key, size);
		}
	}
	if (mode != 'j') {
		r_cons_newline (core->cons);
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
	char *save_ptr = NULL;
	char *grep_arg = NULL;
	char *rx = NULL;
	int delta = 0;
	ut8 *buf;
	RIOMap *map;

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
		R_LOG_ERROR ("ROP length (rop.len) must be greater than 1");
		if (max_instr == 1) {
			R_LOG_ERROR ("For rop.len = 1, use /c to search for single instructions. See /c? for help");
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
		tok = r_str_tok_r (gregexp, ";", &save_ptr);
		while (tok) {
			rx = strdup (tok);
			r_list_append (rx_list, rx);
			tok = r_str_tok_r (NULL, ";", &save_ptr);
		}
	}
	if (param->outmode == R_MODE_JSON) {
		pj_a (param->pj);
	}
	r_cons_break_push (core->cons, NULL, NULL);

	r_list_foreach (param->boundaries, itermap, map) {
		HtUU *badstart = ht_uu_new0 ();
		if (!r_itv_overlap (search_itv, map->itv)) {
			continue;
		}
		RInterval itv = r_itv_intersect (search_itv, map->itv);
		ut64 from = itv.addr, to = r_itv_end (itv);
		if (r_cons_is_breaked (core->cons)) {
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
					delta - i, R_ARCH_OP_MASK_BASIC) < 1) {
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
			r_anal_op_fini (&end_gadget);
			if (r_cons_is_breaked (core->cons)) {
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
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			struct endlist_pair *end_gadget = (struct endlist_pair *) r_list_pop (end_list);
			next = end_gadget->instr_offset;
			prev = 0;
			// Start at just before the first end gadget.
			for (i = next - ropdepth; i < (delta - max_inst_size_x86) && max_count; i += increment) {
				RAnalOp asmop;
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
				if (r_cons_is_breaked (core->cons)) {
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
						r_anal_op_fini (&asmop);
						continue;
					}
					if (align && (0 != ((from + i) % align))) {
						r_anal_op_fini (&asmop);
						continue;
					}
					if (gadgetSdb) {
						RListIter *iter;

						RCoreAsmHit *hit = (RCoreAsmHit *) hitlist->head->data;
						char *headAddr = r_str_newf ("%"PFMT64x, hit->addr);
						if (!headAddr) {
							result = false;
							r_anal_op_fini (&asmop);
							goto bad;
						}

						r_list_foreach (hitlist, iter, hit) {
							char *addr = r_str_newf ("%"PFMT64x"(%"PFMT32d")", hit->addr, hit->len);
							if (!addr) {
								free (headAddr);
								result = false;
								r_anal_op_fini (&asmop);
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
							r_anal_op_fini (&asmop);
							break;
						}
					}
				}
				r_anal_op_fini (&asmop);
				if (increment != 1) {
					i = next;
				}
			}
		}
		free (buf);
		ht_uu_free (badstart);
	}
	if (r_cons_is_breaked (core->cons)) {
		eprintf ("\n");
	}
	r_cons_break_pop (core->cons);

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

static bool esil_addrinfo(REsil *esil) {
	RCore *core = (RCore *) esil->cb.user;
	ut64 num = 0;
	char *src = r_esil_pop (esil);
	if (src && *src && r_esil_get_parm (esil, src, &num)) {
		num = r_core_anal_address (core, num);
		r_esil_pushnum (esil, num);
	} else {
		// error. empty stack?
		return false;
	}
	free (src);
	return true;
}

static bool esil_address(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	return r_esil_pushnum (esil, esil->addr);
}

static void do_esil_search(RCore *core, struct search_parameters *param, const char *input) {
	const int hit_combo_limit = r_config_get_i (core->config, "search.esilcombo");
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
		r_core_cmd_help (core, help_msg_slash_esil);
		return;
	}
	const unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	const int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int stacksize = r_config_get_i (core->config, "esil.stack.size");
	const int nonull = r_config_get_i (core->config, "esil.nonull");
	const int romem = r_config_get_i (core->config, "esil.romem");
	const int stats = r_config_get_i (core->config, "esil.stats");
	if (stacksize < 16) {
		stacksize = 16;
	}
	REsil *esil = r_esil_new (stacksize, iotrap, addrsize);
	if (!esil) {
		R_LOG_ERROR ("Cannot create an esil instance");
		return;
	}
	r_esil_set_op (esil, "$$", esil_address, 0, 1, R_ESIL_OP_TYPE_UNKNOWN, "current address");
	esil->cb.user = core;
	// TODO:? cmd_aei (core);
	RIOMap *map;
	RListIter *iter;
	r_esil_setup (esil, core->anal, romem, stats, nonull);
	r_list_foreach (param->boundaries, iter, map) {
		bool hit_happens = false;
		size_t hit_combo = 0;
		char *res;
		ut64 nres, addr;
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		/* hook addrinfo */
		r_esil_set_op (esil, "AddrInfo", esil_addrinfo, 1, 1, R_ESIL_OP_TYPE_UNKNOWN, NULL);
		/* hook addrinfo */
		r_esil_setup (esil, core->anal, 1, 0, nonull);
		r_esil_stack_free (esil);
		esil->verbose = 0;

		r_cons_break_push (core->cons, NULL, NULL);
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
			r_esil_set_op (core->anal->esil, "AddressInfo", esil_search_address_info);
#endif
			if (r_cons_is_breaked (core->cons)) {
				R_LOG_INFO ("Breaked at 0x%08"PFMT64x, addr);
				break;
			}
			r_esil_set_pc (esil, addr);
			if (!r_esil_parse (esil, input + 2)) {
				// XXX: return value doesnt seems to be correct here
				R_LOG_ERROR ("Cannot parse esil (%s)", input + 2);
				break;
			}
			hit_happens = false;
			res = r_esil_pop (esil);
			if (r_esil_get_parm (esil, res, &nres)) {
				R_LOG_DEBUG ("RES 0x%08"PFMT64x" %"PFMT64d, addr, nres);
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
				R_LOG_ERROR ("Cannot parse esil (%s)", input + 2);
				r_esil_stack_free (esil);
				free (res);
				break;
			}
			r_esil_stack_free (esil);
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
					R_LOG_INFO ("Hit search.esilcombo reached (%d). Stopping search. Use f-", hit_combo_limit);
					break;
				}
			} else {
				hit_combo = 0;
			}
		}
		r_config_set_i (core->config, "search.kwidx", search->n_kws); // TODO remove
		r_cons_break_pop (core->cons);
	}
	r_cons_clear_line (core->cons, true, true);
	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
	r_esil_free (esil);
}

#define MAXINSTR 8
#define SUMARRAY(arr, size, res) do (res) += (arr)[--(size)]; while ((size))

#if USE_EMULATION
static const char *get_syscall_register(RCore *core) {
	const char *sn = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SN);
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	if (!strcmp (cfg->arch, "arm") && cfg->bits == 64) {
		const char *os = cfg->os;
		if (!os) {
			os = r_config_get (core->config, "asm.os");
		}
		if (!strcmp (os, "linux") || !strcmp (os, "android")) {
			sn = "x8";
		} else if (!strcmp (os, "macos")) {
			sn= "x16";
		}
	}
	return sn;
}

static int emulateSyscallPrelude(RCore *core, ut64 at, ut64 curpc) {
	int i, bsize = R_MIN (64, core->blocksize);
	RAnalOp aop;
	const int mininstrsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	RRegItem *reg_pc = r_reg_get (core->dbg->reg, "PC", -1);
	const char *screg = get_syscall_register (core);

	ut8 *arr = malloc (bsize);
	if (!arr) {
		return -1;
	}
	int codealign = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
	r_reg_set_value (core->dbg->reg, reg_pc, curpc);
	// XXX maybe i is not necessary
	for (i = 0; curpc < at; curpc++, i++) {
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (codealign > 1) {
			int rest = curpc % codealign;
			if (rest) {
				curpc += (rest - 1);
				continue;
			}
		}
		if (!i) {
			r_io_read_at (core->io, curpc, arr, bsize);
		}
		int result = r_anal_op (core->anal, &aop, curpc, arr + i, bsize - i, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL);
		if (result > 0) {
			int incr = ((core->search->align > 0)? core->search->align:  aop.size) - 1;
			if (incr < 0) {
				incr = minopcode;
			}
			i += incr;
			curpc += incr;
			if (r_anal_op_nonlinear (aop.type)) {
				r_reg_set_value (core->dbg->reg, reg_pc, curpc + 1);
			} else {
				const char *ee = r_strbuf_get (&aop.esil);
				r_esil_parse (core->anal->esil, ee);
				// r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			}
		} else {
			// next op, honoring code align
		//	i += 1;
		}
		r_anal_op_fini (&aop);
	}
	free (arr);
	int sysno = r_debug_reg_get (core->dbg, screg);
	r_reg_setv (core->dbg->reg, screg, -2); // clearing register A0
	return sysno;
}
#endif

static void do_syscall_search(RCore *core, struct search_parameters *param) {
	RSearch *search = core->search;
	ut64 at;
#if USE_EMULATION
	ut64 curpc;
#endif
	int curpos, idx = 0, count = 0;
	RAnalOp aop = {0};
	int i, ret, bsize = R_MAX (64, core->blocksize);
	int kwidx = core->search->n_kws;
	RIOMap* map;
	RListIter *iter;
	const int mininstrsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	REsil *esil;
	int align = core->search->align;
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	const bool isx86 = r_str_startswith (r_config_get (core->config, "asm.arch"), "x86");

	if (!(esil = r_esil_new (stacksize, iotrap, addrsize))) {
		return;
	}
	int *previnstr = calloc (MAXINSTR + 1, sizeof (int));
	if (!previnstr) {
		r_esil_free (esil);
		return;
	}
	ut8 *buf = malloc (bsize);
	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
		r_esil_free (esil);
		free (previnstr);
		return;
	}

	cmd_aei (core);// requied to have core->anal->esil initialized.. imho esil should never be NULL!
	ut64 oldoff = core->addr;
#if !USE_EMULATION
	int syscallNumber = 0;
#endif
	r_cons_break_push (core->cons, NULL, NULL);
	// XXX: the syscall register depends on arcm
	const char *screg = get_syscall_register (core);
	char *esp = r_str_newf ("%s,=", screg);
	char *esp32 = NULL;
	r_reg_arena_push (core->anal->reg);
	if (core->anal->config->bits == 64) {
		const char *reg = r_reg_64_to_32 (core->anal->reg, screg);
		if (reg) {
			esp32 = r_str_newf ("%s,=", reg);
		}
	}
	if (param->pj) {
		pj_o (param->pj);
		pj_ks (param->pj, "cmd", "/asj");
		pj_ka (param->pj, "results");
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
			if (r_cons_is_breaked (core->cons)) {
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
			ret = r_anal_op (core->anal, &aop, at, buf + i, bsize - i, R_ARCH_OP_MASK_ESIL);
			curpos = idx++ % (MAXINSTR + 1);
			previnstr[curpos] = ret; // This array holds prev n instr size + cur instr size
#if !USE_EMULATION
			if (aop.type == R_ANAL_OP_TYPE_MOV) {
				const char *es = R_STRBUF_SAFEGET (&aop.esil);
				if (strstr (es, esp)) {
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				} else if (esp32 && strstr (es, esp32)) {
					if (aop.val != -1) {
						syscallNumber = aop.val;
					}
				}
			}
#endif
			if ((aop.type == R_ANAL_OP_TYPE_SWI) && ret > 0) { // && (aop.val > 10)) {
				int scVector = aop.val; // int 0x80, svc 0x70, ...
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
				if (isx86 && aop.val == 0 && (aop.bytes[0] == 0xcd || aop.bytes[0] == 0x64)) {
					goto theverynext;
				}
#if 1
				// scNumber = aop.val;
				if (scNumber < 0 || scNumber > 0xFFFFF) {
					scNumber = aop.val;
					if (scNumber < 0 || scNumber > 0xFFFFF) {
						R_LOG_DEBUG ("Invalid syscall number %d at 0x%08"PFMT64x, scNumber, aop.addr);
						// r_core_cmd0 (core, "dr0");
						goto theverynext;
					}
				}
#endif
				scVector = (aop.val > 0)? aop.val: -1; // int 0x80 (aop.val = 0x80)
				RSyscallItem *item = r_syscall_get (core->anal->syscall, scNumber, scVector);
				if (!item) {
					if (scNumber == scVector && !isx86) {
						if (scVector > 10 && scVector < 200) {
							item = r_syscall_get (core->anal->syscall, scVector, -1);
						}
					}
				}
				if (item) {
					if (param->pj) {
						pj_o (param->pj);
						pj_kn (param->pj, "addr", at);
						pj_ks (param->pj, "name", item->name);
						pj_kn (param->pj, "sysnum", item->num);
						if (aop.val && aop.val != UT64_MAX) {
							pj_kn (param->pj, "num", aop.val);
						}
						pj_end (param->pj);
					} else {
						r_cons_printf (core->cons, "0x%08"PFMT64x" %s\n", at, item->name);
					}
#if 0
				} else {
					if (param->pj) {
						pj_o (param->pj);
						pj_kn (param->pj, "addr", at);
						pj_kn (param->pj, "sysnum", scNumber);
						pj_kn (param->pj, "num", scVector);
						pj_end (param->pj);
					} else {
						r_cons_printf (core->cons, "0x%08"PFMT64x" %d\n", at, scNumber);
					}
#endif
				} else {
					R_LOG_DEBUG ("Cant find an syscall for %d %d", scNumber, scVector);
				}
				memset (previnstr, 0, (MAXINSTR + 1) * sizeof (*previnstr)); // clearing the buffer
				if (param->searchflags) {
					char *flag = r_str_newf ("%s%d_%d.%s", param->searchprefix, kwidx, count, item? item->name: "syscall");
					r_flag_set (core->flags, flag, at, ret);
					free (flag);
				}
				r_syscall_item_free (item);
				if (*param->cmd_hit) {
					ut64 here = core->addr;
					r_core_seek (core, at, true);
					r_core_cmd (core, param->cmd_hit, 0);
					r_core_seek (core, here, true);
				}
				count++;
				// r_core_cmd0 (core, "dr0");
				if (search->maxhits > 0 && count >= search->maxhits) {
					r_anal_op_fini (&aop);
					break;
				}
#if !USE_EMULATION
				syscallNumber = 0;
#endif
			}
theverynext:
			{
				int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
				if (inc < 0) {
					inc = minopcode;
				}
				i += inc;
				at += inc;
				r_anal_op_fini (&aop);
			}
		}
	}
beach:
	if (param->pj) {
		pj_end (param->pj);
		pj_end (param->pj);
	}
	r_core_seek (core, oldoff, true);
	r_esil_free (esil);
	r_cons_break_pop (core->cons);
	free (buf);
	free (esp32);
	free (esp);
	free (previnstr);
	r_reg_arena_pop (core->anal->reg);
}

static void do_ref_search(RCore *core, ut64 addr,ut64 from, ut64 to, struct search_parameters *param) {
	const int size = 12;
	ut8 buf[12];
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	if (!xrefs) {
		return;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (xrefs, ref) {
		RAnalOp asmop;
		r_io_read_at (core->io, ref->addr, buf, size);
		r_asm_set_pc (core->rasm, ref->addr);
		r_asm_disassemble (core->rasm, &asmop, buf, size);
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
		RAnalHint *hint = r_anal_hint_get (core->anal, ref->addr);
		char *disasm = r_asm_parse_filter (core->rasm, ref->addr, core->flags, hint, asmop.mnemonic);
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
			r_cons_printf (core->cons, "%s 0x%" PFMT64x " [%s] %s\n",
					buf_fcn, ref->addr, r_anal_ref_type_tostring (ref->type),
					disasm? disasm: asmop.mnemonic);
			if (*param->cmd_hit) {
				ut64 here = core->addr;
				r_core_seek (core, ref->addr, true);
				r_core_cmd (core, param->cmd_hit, 0);
				r_core_seek (core, here, true);
			}
		}
		free (buf_fcn);
		r_anal_op_fini (&asmop);
	}
	RVecAnalRef_free (xrefs);
}

static void cmd_search_aF(RCore *core, const char *input) {
	bool quiet = *input == 'd';
	if (*input && *input != ' ' && *input != 'd') {
		r_core_cmd_help_contains (core, help_msg_slash_a, "aF");
		return;
	}
	RAnalFunction *fcn;
	RListIter *iter, *iter2;
	RAnalBlock *bb;
	input = r_str_trim_head_ro (input + 1);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_list_foreach (fcn->bbs, iter2, bb) {
			ut8 *bbdata = malloc (bb->size);
			if (!bbdata) {
				break;
			}
			r_io_read_at (core->io, bb->addr, bbdata, bb->size);
			// eprintf ("0x08%"PFMT64x"%c", bb->addr, 10);
			int i;
			for (i = 0; i < bb->ninstr; i++) {
				if (i >= bb->op_pos_size) {
					R_LOG_ERROR ("Prevent op_pos overflow on large basic block at 0x%08"PFMT64x, bb->addr);
					break;
				}
				ut64 addr = bb->addr + bb->op_pos[i];
				ut8 *idata = bbdata + bb->op_pos[i];
				RAnalOp asmop;
				r_anal_op_init (&asmop);
				size_t left = bb->size - bb->op_pos[i];
				int ret = r_asm_disassemble (core->rasm, &asmop, idata, left);
				if (ret  < 1) {
					r_anal_op_fini (&asmop);
					break;
				}
				char *s = NULL;
				if (quiet) {
					s = strdup (asmop.mnemonic);
				} else {
					s = r_core_cmd_strf (core, "pi 1 @ 0x%"PFMT64x, addr);
				}
				r_str_trim (s);
				if (strstr (s, input)) {
					r_cons_printf (core->cons, "0x%08"PFMT64x" %s: %s\n", addr, fcn->name, s);
				}
				free (s);
				r_anal_op_fini (&asmop);
			}
			free (bbdata);
		}
	}
}

static bool check_false_positive(const char *s) {
	if (strlen (s) < 4) {
		return false;
	}
	bool ok = true;
	int rep = 0;
	ut8 s0 = *s;
	if (!isalpha (s0) && !isdigit (s0)) {
		return false;
	}
	while (*s) {
		if (rep > 3) {
			ok = false;
			break;
		}
		if (*s == '%') {
			ok = false;
			break;
		}
		if (s0 == *s) {
			rep++;
		}
		s++;
	}
	return ok;
}

// XXX must use searchhit and be generic RSearchHit *hit) {
static void search_hit_at(RCore *core, struct search_parameters *param, RCoreAsmHit *hit, const char *str) {
	bool asm_sub_names = r_config_get_b (core->config, "asm.sub.names");
	const int kwidx = core->search->n_kws;
	const char *cmdhit = r_config_get (core->config, "cmd.hit");
	param->count++;
	if (R_STR_ISNOTEMPTY (cmdhit)) {
		r_core_cmdf (core, "'0x%08"PFMT64x"'%s", hit->addr, cmdhit);
	}
	if (!str) {
		switch (param->outmode) {
		case R_MODE_JSON:
			pj_o (param->pj);
			pj_kn (param->pj, "addr", hit->addr);
			pj_ki (param->pj, "len", hit->len);
			pj_ks (param->pj, "code", hit->code);
			pj_end (param->pj);
			break;
		case R_MODE_RADARE:
			r_cons_printf (core->cons, "f %s%d_%i = 0x%08"PFMT64x "\n",
					param->searchprefix, kwidx, param->count, hit->addr);
			break;
		default:
			if (asm_sub_names) {
				RAnalHint *hint = r_anal_hint_get (core->anal, hit->addr);
				char *tmp = r_asm_parse_filter (core->rasm, hit->addr, core->flags, hint, hit->code);
				if (tmp) {
					r_anal_hint_free (hint);
					if (param->outmode == R_MODE_SIMPLE) {
						r_cons_printf (core->cons, "0x%08"PFMT64x "   # %i: %s\n", hit->addr, hit->len, tmp);
					} else {
						char *s = (hit->len > 0)
							? r_core_cmd_strf (core, "pDi %d @e:asm.flags=0@0x%08"PFMT64x, (int)hit->len, hit->addr)
							: r_core_cmd_strf (core, "pdi 1 @e:asm.flags=0@0x%08"PFMT64x, hit->addr);
						if (s) {
							r_cons_printf (core->cons, "%s", s);
						}
						free (s);
					}
				}
			} else {
				r_cons_printf (core->cons, "0x%08"PFMT64x "   # %i: %s\n", hit->addr, hit->len, r_str_get (hit->code));
			}
			break;
		}
	}
	if (param->searchflags) {
		if (R_STR_ISNOTEMPTY (str)) {
			// TODO: use the api instead
			char *s = r_str_newf ("string \"%s\"", str);
			r_core_cmdf (core, "'0x%08"PFMT64x"'CC %s", hit->addr, s);
			free (s);
		}
		if (param->outmode != R_MODE_SIMPLE) {
			char *flagname = (R_STR_ISNOTEMPTY (str)) // XXX i think hit->code is not used anywhere
				? r_str_newf ("asm.str.%d_%s_%d", kwidx, str, param->count)
				: r_str_newf ("%s%d_%d", param->searchprefix, kwidx, param->count);
			if (flagname) {
				r_flag_set (core->flags, flagname, hit->addr, hit->len);
				free (flagname);
			}
		}
	}
}

static bool invalid_page(RCore *core, const ut8 *buf, size_t buf_size) {
	const ut8 OxFF = core->io->Oxff;
	size_t i;
	for (i = 0; i < buf_size; i++) {
		if (buf[i] != OxFF) {
			return false;
		}
	}
	return true;
}

static void do_unkjmp_search(RCore *core, struct search_parameters *param, bool quiet, const char *input) {
	const int flags = R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM;
	const bool badpages = r_config_get_b (core->config, "search.badpages");
	RAnalOp aop;
	ut64 i, at;
	RIOMap *map;
	RListIter *iter;
	const char *where = "bin.sections.x";

	r_list_free (param->boundaries);
	param->boundaries = r_core_get_boundaries_prot (core, R_PERM_X, where, "search");
	if (r_list_empty (param->boundaries)) {
		where = r_config_get (core->config, "anal.in");
		param->boundaries = r_core_get_boundaries_prot (core, R_PERM_X, where, "search");
	}
	if (!core->anal->esil) {
		// initialize esil vm
		cmd_aei (core);
		if (!core->anal->esil) {
			R_LOG_ERROR ("Cannot initialize the ESIL vm");
			return;
		}
	}
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (!(map->perm & R_PERM_X)) {
			continue;
		}
		r_cons_break_push (core->cons, NULL, NULL);
		for (i = 0, at = from; at < to; i++, at++) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			ut64 at = from + i;
			ut8 bufop[32] = {0};
			if (!r_io_read_at (core->io, at, bufop, sizeof (bufop))) {
				break;
			}
			if (badpages && invalid_page (core, bufop, sizeof (bufop))) {
				R_LOG_DEBUG ("Invalid read at 0x%08"PFMT64x, at);
				break;
			}

			int ret = r_anal_op (core->anal, &aop, at, bufop, sizeof (bufop), flags);
			if (ret) {
				r_esil_set_pc (core->anal->esil, at);
				r_reg_setv (core->anal->reg, "PC", at);
				const char *esil = r_strbuf_get (&aop.esil);
				bool res = r_esil_parse (core->anal->esil, esil);
				if (res) {
					ut64 d = r_reg_getv (core->anal->reg, "PC");
					// Validate the register value before using it
					if (!d || d == UT64_MAX || !r_io_is_valid_offset (core->io, d, 0) || d == at + aop.size) {
						R_LOG_DEBUG ("Invalid destination offset");
					} else {
						switch (aop.type) {
						case R_ANAL_OP_TYPE_UCALL:
						case R_ANAL_OP_TYPE_RCALL:
							r_cons_printf (core->cons, "CC RCALL 0x%08"PFMT64x" // %s @ 0x%08"PFMT64x"\n", d, aop.mnemonic, at);
							break;
						case R_ANAL_OP_TYPE_UJMP:
						case R_ANAL_OP_TYPE_RJMP:
							r_cons_printf (core->cons, "CC RJMP 0x%08"PFMT64x" // %s @ 0x%08"PFMT64x"\n", d, aop.mnemonic, at);
							break;
						default:
							// eprintf ("--> 0x%08"PFMT64x" %s\n", aop.addr, aop.mnemonic);
							break;
						}
					}
				}
				i += aop.size - 1;
			}
			r_anal_op_fini (&aop);
		}
		r_cons_break_pop (core->cons);
	}
}

// TODO: reuse with `do_analstr_search`
static char *print_analstr(RCore *core, ut64 addr, int maxlen) {
	const bool badpages = r_config_get_b (core->config, "search.badpages");
	ut8 buf[128];
	ut64 at;
	RAnalOp aop;
	int hasch = 0;
	int i, ret;
	r_cons_break_push (core->cons, NULL, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	ut64 lastch = UT64_MAX;
	int minstr = r_config_get_i (core->config, "bin.str.min");
	if (minstr < 1) {
		minstr = 1;
	}

	ut64 from = addr;
	ut64 to = addr + sizeof (buf);
#if 0
	if (!(map->perm & R_PERM_X)) {
		continue;
	}
#endif
	if (!r_io_read_at (core->io, addr, buf, sizeof (buf))) {
		return NULL;
	}
	for (i = 0, at = from; at < to; i++, at++) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		at = from + i;
		ut8 bufop[32] = {0};
		memcpy (bufop, buf + i, R_MIN (sizeof (bufop), sizeof (buf) - i));
		if (badpages && invalid_page (core, bufop, sizeof (bufop))) {
			R_LOG_DEBUG ("Invalid read at 0x%08"PFMT64x, at);
			break;
		}

		ret = r_anal_op (core->anal, &aop, at, bufop, sizeof (bufop), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
		if (ret) {
			if (hasch > 0) {
				hasch--;
			}
			if (aop.type & R_ANAL_OP_TYPE_MOV) {
				if (aop.val > 0 && aop.val < UT32_MAX) {
					if (aop.val < 255) {
						if (IS_PRINTABLE (aop.val)) {
							char chstr[2] = {aop.val, 0};
							r_strbuf_append (sb, chstr);
							hasch = 1;
							// eprintf ("MOVE %llx = %d '%c'\n", at, (int)aop.val, (char)aop.val);
						}
					} else if (aop.val < UT16_MAX) {
						char ch0 = aop.val & 0xff;
						char ch1 = (aop.val >> 8) & 0xff;
						if ((ut8)ch1 == 0xef) {
							ch1 = 0;
						}
						if (IS_PRINTABLE (ch0) && (!ch1 || IS_PRINTABLE (ch1))) {
							char chstr[2] = {ch0, 0};
							r_strbuf_append (sb, chstr);
							chstr[0] = ch1;
							r_strbuf_append (sb, chstr);
							hasch = 1;
							// eprintf ("MOVE %llx = %d '%c%c'\n", at, (int)aop.val, ch0, ch1);
						}
					} else if (aop.val < UT32_MAX) {
						char ch0 = aop.val & 0xff;
						char ch1 = (aop.val >> 8) & 0xff;
						char ch2 = (aop.val >> 16) & 0xff;
						char ch3 = (aop.val >> 24) & 0xff;
						if (IS_PRINTABLE (ch0) && IS_PRINTABLE (ch1) && IS_PRINTABLE (ch2)) {
							char chstr[2] = {ch0, 0};
							r_strbuf_append (sb, chstr);
							chstr[0] = ch1;
							r_strbuf_append (sb, chstr);
							chstr[0] = ch2;
							r_strbuf_append (sb, chstr);
							chstr[0] = ch3;
							r_strbuf_append (sb, chstr);
							hasch = 2;
							// eprintf ("MOVE %llx = %d '%c%c'\n", at, (int)aop.val, ch0, ch1);
						}
					}
				}
			}
			if (hasch) {
				lastch = at;
			} else if (lastch != UT64_MAX) {
				if (r_strbuf_length (sb) > minstr) { // maybe 2
					const char *s = r_strbuf_get (sb);
					if (!check_false_positive (s)) {
						s = "";
					}
					if (R_STR_ISNOTEMPTY (s)) {
						char *ss = r_str_trim_dup (s);
						return ss;
					}
				}
				r_strbuf_set (sb, "");
				lastch = UT64_MAX;
			}
			int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
			if (inc > 0) {
				i += inc;
				at += inc;
			}
		}
		r_anal_op_fini (&aop);
	}
	r_strbuf_free (sb);
	return NULL;
}

// R2R db/cmd/cmd_search_asm
static bool do_analstr_search(RCore *core, struct search_parameters *param, bool quiet, const char *input) {
	const bool badpages = r_config_get_b (core->config, "search.badpages");
	bool silent = false;
	if (!input) {
		input = "5";
		silent = true;
	}
	const char *where = "bin.sections.x";
	PJ *pj = param->pj;

	r_list_free (param->boundaries);
	param->boundaries = r_core_get_boundaries_prot (core, R_PERM_X, where, "search");
	if (r_list_empty (param->boundaries)) {
		where = r_config_get (core->config, "anal.in");
		param->boundaries = r_core_get_boundaries_prot (core, R_PERM_X, where, "search");
	}
	ut64 at;
	RAnalOp aop;
	int hasch = 0;
	int i, ret;
	input = r_str_trim_head_ro (input);
	r_cons_break_push (core->cons, NULL, NULL);
	RIOMap* map;
	RListIter *iter;
	char *word = strdup (input);
	RList *words = r_str_split_list (word, ",", 0);
	RStrBuf *sb = r_strbuf_new ("");
	RStrBuf *rb = r_strbuf_new ("");
	ut64 lastch = UT64_MAX;
	const bool json = param->pj != NULL;
	ut64 firstch = UT64_MAX;
	int minstr = r_num_math (core->num, input);
	if (minstr < 1) {
		minstr = r_config_get_i (core->config, "bin.str.min");
		if (minstr < 1) {
			minstr = 1;
		}
	}
	if (json) {
		pj_a (pj);
	}

	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (!(map->perm & R_PERM_X)) {
			continue;
		}
		bool inmov = false;
		for (i = 0, at = from; at < to; i++, at++) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			at = from + i;
			ut8 bufop[32] = {0};
			if (!r_io_read_at (core->io, at, bufop, sizeof (bufop))) {
				break;
			}
			if (badpages && invalid_page (core, bufop, sizeof (bufop))) {
				R_LOG_DEBUG ("Invalid read at 0x%08"PFMT64x, at);
				break;
			}

			ret = r_anal_op (core->anal, &aop, at, bufop, sizeof (bufop), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			if (ret) {
				if (hasch > 0) {
					hasch--;
				}
				if (aop.type == R_ANAL_OP_TYPE_ADD || aop.type == R_ANAL_OP_TYPE_SUB) {
					continue;
				}
				if (inmov && aop.type == R_ANAL_OP_TYPE_OR) {
					hasch = 1;
					lastch = at + 4;
				} else if (aop.type & R_ANAL_OP_TYPE_MOV) {
					inmov = true;
					if (aop.val > 0 && aop.val < UT32_MAX) {
						if (aop.val < 255) {
							if (IS_PRINTABLE (aop.val)) {
								char chstr[2] = {aop.val, 0};
								r_strbuf_append (sb, chstr);
								hasch = 1;
								// eprintf ("MOVE %llx = %d '%c'\n", at, (int)aop.val, (char)aop.val);
							}
						} else if (aop.val < UT16_MAX) {
							char ch0 = aop.val & 0xff;
							char ch1 = (aop.val >> 8) & 0xff;
							if ((ut8)ch1 == 0xef || (ut8)ch1 == 0xed) {
								ch1 = 0;
							}
							if (IS_PRINTABLE (ch0) && (!ch1 || IS_PRINTABLE (ch1))) {
								char chstr[2] = {ch0, 0};
								r_strbuf_append (sb, chstr);
								chstr[0] = ch1;
								r_strbuf_append (sb, chstr);
								hasch = 1;
								// eprintf ("MOVE %llx = %d '%c%c'\n", at, (int)aop.val, ch0, ch1);
							}
						} else if (aop.val < UT32_MAX) {
							char ch0 = aop.val & 0xff;
							char ch1 = (aop.val >> 8) & 0xff;
							char ch2 = (aop.val >> 16) & 0xff;
							char ch3 = (aop.val >> 24) & 0xff;
							if (IS_PRINTABLE (ch0) && IS_PRINTABLE (ch1) && IS_PRINTABLE (ch2)) {
								char chstr[2] = {ch0, 0};
								r_strbuf_append (sb, chstr);
								chstr[0] = ch1;
								r_strbuf_append (sb, chstr);
								chstr[0] = ch2;
								r_strbuf_append (sb, chstr);
								chstr[0] = ch3;
								r_strbuf_append (sb, chstr);
								hasch = 2;
								// eprintf ("MOVE %llx = %d '%c%c'\n", at, (int)aop.val, ch0, ch1);
							}
						}
					}
				} else {
					inmov = false;
				}
				if (hasch) {
					if (lastch == UT64_MAX) {
						firstch = at;
					}
					lastch = at;
				} else if (lastch != UT64_MAX) { //  && firstch != UT64_MAX) {
					if (r_strbuf_length (sb) > minstr) { // maybe 2
						const char *s = r_strbuf_get (sb);
						if (quiet) {
							if (!check_false_positive (s)) {
								s = "";
							}
						}
						if (R_STR_ISNOTEMPTY (s)) {
							char *ss = r_str_trim_dup (s);
							if (*ss && (minstr < 1 || strlen (ss) > minstr)) {
								if (json) {
									pj_o (pj);
									pj_kn (pj, "addr", firstch);
									pj_ks (pj, "text", ss);
									pj_end (pj);
								} else {
									r_strbuf_appendf (rb, "0x%08"PFMT64x" %s\n", firstch, ss);
									r_name_filter (ss, -1);
									RCoreAsmHit cah = {
										.addr = firstch,
										.len = lastch - firstch,
									};
									search_hit_at (core, param, &cah, ss);
								}
							}
							free (ss);
						}
					}
					r_strbuf_set (sb, "");
					lastch = UT64_MAX;
				}
				int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
				if (inc > 0) {
					i += inc;
					at += inc;
				}
			}
			r_anal_op_fini (&aop);
		}
	}
	r_list_free (words);
	free (word);
	r_cons_break_pop (core->cons);
	if (json) {
		r_strbuf_free (rb);
		pj_end (pj);
#if 0
		char *res = pj_drain (pj);
		if (R_STR_ISNOTEMPTY (res)) {
			r_cons_println (core->cons, res);
		}
		free (res);
#endif
	} else if (silent) {
		r_strbuf_free (rb);
	} else {
		char *res = r_strbuf_drain (rb);
		if (R_STR_ISNOTEMPTY (res)) {
			r_cons_println (core->cons, res);
		}
		free (res);
	}
	r_strbuf_free (sb);
	return false;
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
		case 'l': // "/alt" "/alf" "/atl"
			switch (type) {
			case 't': // "/alt"
			case 'f': // "/alf"
				for (i = 0; i < 64; i++) {
					const char *str = type == 'f'
						? r_anal_op_family_tostring (i)
						: r_anal_optype_index (i);
					if (R_STR_ISEMPTY (str)) {
						break;
					}
					if (!strcmp (str, "undefined")) {
						continue;
					}
					r_cons_println (core->cons, str);
				}
				break;
			case 's': // "als"
				r_core_cmd_call (core, "asl");
				break;
			case 0:
				r_core_cmd_call (core, "aoml");
				break;
			default:
				R_LOG_ERROR ("Unknown command");
				break;
			}
			return false;
		case 'F': // "/aF"
			cmd_search_aF (core, input + 1);
			return false;
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
			if (type == 't') {
				r_core_cmd_help (core, help_msg_slash_at);
			} else {
				r_core_cmd_help (core, help_msg_slash_a);
			}
			return false;
		}
		input++;
	}
	if (type == 's') {
		R_LOG_ERROR ("Shouldn't be reached");
		return true;
	}
	input = r_str_trim_head_ro (input);
	if (param->outmode == R_MODE_JSON) {
		pj_o (param->pj);
		pj_ks (param->pj, "cmd", "/atj");
		pj_ks (param->pj, "arg", input);
		pj_ka (param->pj, "result");
	}
	r_cons_break_push (core->cons, NULL, NULL);
	RIOMap* map;
	RListIter *iter;
	char *word = strdup (input);
	// check if its a valid instruction type or family
	r_str_replace_ch (word, ' ', ',', -1);
	RList *words = r_str_split_list (word, ",", 0);
	if ((type == 't' || type == 'f') && r_list_length (words) > 0) {
		bool failed = false;
		RListIter *iter;
		char *word;
		r_list_foreach (words, iter, word) {
			if (R_STR_ISEMPTY (word) || !strcmp (word, "(null)")) {
				continue;
			}
			bool found = false;
			for (i = 0; i < 1024; i++) {
				const char *str = type == 'f'
					? r_anal_op_family_tostring (i)
					: r_anal_optype_index (i);
				if (R_STR_ISEMPTY (str)) {
					break;
				}
				if (!strcmp (str, word)) {
					found = true;
					break;
				}
			}
			if (!found) {
				failed = true;
				break;
			}
		}
		if (failed) {
			R_LOG_ERROR ("Invalid argument for /at or /af, see /atl or /afl");
			return true;
		}
	}

	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		for (i = 0, at = from; at < to; i++, at++) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			at = from + i;
			ut8 bufop[32];
			r_io_read_at (core->io, at, bufop, sizeof (bufop));
			ret = r_anal_op (core->anal, &aop, at, bufop, sizeof (bufop), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			if (ret) {
				bool match = false;
				if (type == 'm') { // "/atm"
					const char *fam = aop.mnemonic;
					if (fam && (!*input || r_str_startswith (fam, input))) {
						match = true;
					}
				} else if (type == 'f') { // "/atf"
					const char *fam = r_anal_op_family_tostring (aop.family);
					if (fam && (!*input || !strcmp (input, fam))) {
						match = true;
					}
				} else { // "/at"
					const char *type = r_anal_optype_tostring (aop.type);
					if (type) {
						bool isCandidate = !*input;
						if (!strcmp (input, "cswi")) {
							if (!strcmp (input + 1, type)) {
								isCandidate = true;
							}
						} else {
							RListIter *iter;
							const char *w;
							r_list_foreach (words, iter, w) {
								if (!strcmp (type, w)) {
									isCandidate = true;
									match = true;
									break;
								}
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
					char *opstr = r_core_op_str (core, at);
					const char *optype = r_anal_optype_tostring (aop.type);
					switch (mode) {
					case 'j':
						pj_o (param->pj);
						pj_kN (param->pj, "addr", at);
						pj_ki (param->pj, "size", ret);
						pj_ks (param->pj, "opstr", opstr);
						pj_ks (param->pj, "type", optype);
						pj_end (param->pj);
						break;
					case 'q':
						r_cons_printf (core->cons, "0x%08"PFMT64x "\n", at);
						break;
					default:
						if (type == 'f') {
							const char *fam = r_anal_op_family_tostring (aop.family);
							r_cons_printf (core->cons, "0x%08"PFMT64x " %s %s %d %s\n", at, fam, optype, ret, opstr);
						} else {
							r_cons_printf (core->cons, "0x%08"PFMT64x " %s %d %s\n", at, optype, ret, opstr);
						}
						break;
					}
					R_FREE (opstr);
					if (*input && param->searchflags) {
						r_strf_var (flag, 64, "%s%d_%d", param->searchprefix, kwidx, count);
						r_flag_set (core->flags, flag, at, ret);
					}
					if (*param->cmd_hit) {
						ut64 here = core->addr;
						r_core_seek (core, at, true);
						r_core_cmd (core, param->cmd_hit, 0);
						r_core_seek (core, here, true);
					}
					count++;
					if (search->maxhits && count >= search->maxhits) {
						r_anal_op_fini (&aop);
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
			r_anal_op_fini (&aop);
		}
	}
done:
	r_list_free (words);
	free (word);
	if (mode == 'j') {
		pj_end (param->pj);
		pj_end (param->pj);
	}
	r_cons_break_pop (core->cons);
	return false;
}

static void do_section_search(RCore *core, struct search_parameters *param, const char *input) {
	double threshold = 1;
	bool r2mode = false;
	if (R_STR_ISNOTEMPTY (input)) {
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
	PJ *pj = NULL;
	if (param->outmode == R_MODE_JSON) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	double oe = 0;
	RListIter *iter;
	RIOMap *map;
	ut64 begin = UT64_MAX;
	ut64 at, end = 0;
	int index = 0;
	bool lastBlock = true;
	r_cons_break_push (core->cons, NULL, NULL);
	r_list_foreach (param->boundaries, iter, map) {
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (r_cons_is_breaked (core->cons)) {
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
					r_cons_printf (core->cons, "f entropy_section_%d 0x%08"PFMT64x" 0x%08"PFMT64x"\n", index, end - begin, begin);
				} else if (pj) {
					pj_o (pj);
					pj_kn (pj, "start", begin);
					pj_kn (pj, "end", end);
					pj_kd (pj, "entropy", e);
					pj_end (pj);
				} else {
					r_cons_printf (core->cons, "0x%08"PFMT64x" - 0x%08"PFMT64x" ~ %lf\n", begin, end, e);
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
			r_cons_printf (core->cons, "f entropy_section_%d 0x%08"PFMT64x" 0x%08"PFMT64x"\n", index, end - begin, begin);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x" - 0x%08"PFMT64x" ~ %d .. last\n", begin, end, 0);
		}
		index++;
	}
	r_cons_break_pop(core->cons);
	free (buf);

	if (pj) {
		pj_end (pj);
		RCons *cons = r_cons_singleton ();
		r_cons_print (cons, pj_string (pj));
		pj_free (pj);
	}
}

static void do_asm_search(RCore *core, struct search_parameters *param, const char *input, int mode, RInterval search_itv) {
	RCoreAsmHit *hit; // WTF LOL must use RSearchHit in here!
	RListIter *iter, *itermap;
	int count = 0;
	RIOMap *map;
	bool regexp = input[0] && input[1] == '/'; // "/ad/"
	bool everyByte = regexp && input[0] && input[1] && input[2] == 'a';
	char *end_cmd = strchr (input, ' ');
	if (regexp && input[2] == '?') {
		r_core_cmd_help_contains (core, help_msg_slash_ad, "/ad/");
		return;
	}
	switch ((end_cmd ? *(end_cmd - 1) : input[0]? input[1]: 0)) {
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
		r_core_cmd_help (core, help_msg_slash_ad);
		return;
	default:
		break;
	}
	if (mode == 'o') {
		everyByte = true;
	}

	int maxhits = (int) r_config_get_i (core->config, "search.maxhits");
	if (param->outmode == R_MODE_JSON) {
		pj_a (param->pj);
	}
	r_cons_break_push (core->cons, NULL, NULL);
	if (everyByte) {
		input ++;
	}
	r_list_foreach (param->boundaries, itermap, map) {
		if (!r_itv_overlap (search_itv, map->itv)) {
			continue;
		}
		ut64 from = r_io_map_begin (map);
		ut64 to = r_io_map_end (map);
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (maxhits && count >= maxhits) {
			break;
		}
		RList *hits = r_core_asm_strsearch (core, end_cmd, from, to, maxhits, regexp, everyByte, mode);
		if (hits) {
			r_list_foreach (hits, iter, hit) {
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				search_hit_at (core, param, hit, NULL);
			}
			r_list_free (hits);
		}
	}
	if (param->outmode == R_MODE_JSON) {
		pj_end (param->pj);
	}
	r_cons_break_pop (core->cons);
	// increment search index
	r_config_set_i (core->config, "search.kwidx", ++core->search->n_kws);
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
	if (!param->searchflags && param->outmode != R_MODE_JSON) {
		r_cons_printf (core->cons, "fs hits\n");
	}
	core->search->inverse = param->inverse;
	// TODO Bad but is to be compatible with the legacy behavior
	if (param->inverse) {
		core->search->maxhits = 1;
	}
	const bool search_verbose = r_config_get_b (core->config, "search.verbose");
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
		r_cons_break_push (core->cons, NULL, NULL);
		// TODO search cross boundary
		r_list_foreach (param->boundaries, iter, map) {
			if (!r_itv_overlap (search_itv, map->itv)) {
				continue;
			}
			const ut64 saved_nhits = search->nhits;
			RInterval itv = r_itv_intersect (search_itv, map->itv);
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			RSearchKeyword *kw = r_list_first (core->search->kws);
			if (param->outmode != R_MODE_JSON) {
				int lenstr = kw? kw->keyword_length: 0;
				const char *bytestr = lenstr > 1? "bytes": "byte";
				if (search_verbose) {
					R_LOG_INFO ("Searching %d %s in [0x%"PFMT64x "-0x%"PFMT64x "]",
						kw? kw->keyword_length: 0, bytestr, itv.addr, r_itv_end (itv));
				}
			}
			if (r_sandbox_enable (0) && itv.size > 1024 * 64) {
				R_LOG_ERROR ("Sandbox restricts search range");
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
				if (r_cons_is_breaked (core->cons)) {
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
				if (param->key_search) {
					// Adjust length to search between blocks.
					if (len == core->blocksize) {
						len -= param->key_search_len - 1;
					}
				}
				if (core->search->maxhits > 0 && core->search->nhits >= core->search->maxhits) {
					goto done;
				}
			}
			if (param->progressbar) {
				print_search_progress (at, to1, search->nhits, param);
				r_cons_clear_line (core->cons, true, true);
			}
			r_core_return_value (core, search->nhits);
			if (search_verbose && param->outmode != R_MODE_JSON) {
				R_LOG_INFO ("hits: %" PFMT64d, search->nhits - saved_nhits);
			}
		}
	done:
		r_cons_break_pop (core->cons);
		free (buf);
	} else {
		R_LOG_ERROR ("No keywords defined");
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
				r_cons_printf (core->cons, "%s ", sdbkv_key (kv));
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
				char *save_ptr = NULL;
				char *size = r_str_tok_r (dup, " ", &save_ptr);
				char *tok = r_str_tok_r (NULL, "{}", &save_ptr);
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
	case '?':
		r_core_cmd_help (core, help_msg_slash_R);
		break;
	case ' ':
		if (!strcmp (input + 1, "nop")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/nop/*");
			if (out) {
				r_cons_println (core->cons, out);
				free (out);
			}
		} else if (!strcmp (input + 1, "mov")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/mov/*");
			if (out) {
				r_cons_println (core->cons, out);
				free (out);
			}
		} else if (!strcmp (input + 1, "const")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/const/*");
			if (out) {
				r_cons_println (core->cons, out);
				free (out);
			}
		} else if (!strcmp (input + 1, "arithm")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/arithm/*");
			if (out) {
				r_cons_println (core->cons, out);
				free (out);
			}
		} else if (!strcmp (input + 1, "arithm_ct")) {
			out = sdb_querys (core->sdb, NULL, 0, "rop/arithm_ct/*");
			if (out) {
				r_cons_println (core->cons, out);
				free (out);
			}
		} else {
			R_LOG_ERROR ("Invalid ROP class");
		}
		break;
	default:
		out = sdb_querys (core->sdb, NULL, 0, "rop/***");
		if (out) {
			r_cons_println (core->cons, out);
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
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		int diff = memcmpdiff (core->block, block, core->blocksize);
		int equal = core->blocksize - diff;
		if (equal >= count) {
			int pc = (equal * 100) / core->blocksize;
			r_cons_printf (core->cons, "0x%08"PFMT64x " %4d/%d %3d%%  ", addr, equal, core->blocksize, pc);
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

	r_cons_break_push (core->cons, NULL, NULL);
	r_list_foreach (param->boundaries, iter, p) {
		search_similar_pattern_in (core, count, p->itv.addr, r_itv_end (p->itv));
	}
	r_cons_break_pop (core->cons);
}

static bool isArm(RCore *core) {
	RAsm *as = core ? core->rasm : NULL;
	if (as && as->config) {
		if (r_str_startswith (as->config->arch, "arm")) {
			if (as->config->bits < 64) {
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
		r_cons_printf (core->cons, "0x%"PFMT64x ": 0x%"PFMT64x"\n", from, to);
	} else {
		pj_o (param->pj);
		pj_kn (param->pj, "addr", from);
		pj_kn (param->pj, "value", to);
		pj_end (param->pj);
	}
	r_core_cmdf (core, "f %s.value.0x%08"PFMT64x" %d = 0x%08"PFMT64x, prefix, to, vsize, to); // flag at value of hit
	r_core_cmdf (core, "f %s.offset.0x%08"PFMT64x" %d = 0x%08"PFMT64x, prefix, from, vsize, from); // flag at offset of hit
	const char *cmdHit = r_config_get (core->config, "cmd.hit");
	if (cmdHit && *cmdHit) {
		ut64 addr = core->addr;
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
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
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
			r_write_ble16 (ptr, n16, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config));
			ptr = (ut8 *) ptr + sizeof (ut16);
			break;
		case '4':
			n32 = (ut32)r_num_math (core->num, r_list_pop_head (nums));
			r_write_ble32 (ptr, n32, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config));
			ptr = (ut8 *) ptr + sizeof (ut32);
			break;
		default:
		case '8':
			n64 = r_num_math (core->num, r_list_pop_head (nums));
			r_write_ble64 (ptr, n64, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config));
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
		R_LOG_INFO ("Hashlength mismatch %d %d", hashLength, (int)sizeof (cmphash));
		free (buf);
		return;
	}
	memcpy (cmphash, hashValue, hashLength);

	ut64 hashBits = r_hash_name_to_bits (hashName);
	int hashSize = r_hash_size (hashBits);
	if (hashLength != hashSize) {
		R_LOG_ERROR ("Invalid hash size %d vs %d", hashLength, hashSize);
		free (buf);
		return;
	}

	RHash *ctx = r_hash_new (true, algoType);
	if (!ctx) {
		free (buf);
		return;
	}
	r_cons_break_push (core->cons, NULL, NULL);
	ut64 prev = r_time_now_mono ();
	ut64 inc = 0;
	int amount = 0;
	int mount = 0;
	while (!r_cons_is_breaked (core->cons)) {
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
			r_print_hexdump (core->print, core->addr, buf, bufsz, 0, 16, 0);
			r_cons_flush (core->cons);
		}
		inc++;
	}
	r_cons_break_pop (core->cons);
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
	r_cons_break_push (core->cons, NULL, NULL);
	r_list_foreach (boundaries, iter, map) {
		if (r_cons_is_breaked (core->cons)) {
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
			r_anal_op (core->anal, &analop, at, buf + (at - map_begin), 24, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
			if (at == analop.jump) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", at);
			}
			at += analop.size;
			r_anal_op_fini (&analop);
		}
		free (buf);
	}
	r_cons_break_pop (core->cons);
}

static void cmd_search_xn(RCore *core, const char *input) {
	if (strchr (input, '?')) {
		r_core_cmd_help_match (core, help_msg_slash_x, "/xn");
		return;
	}
	char sizeChar = input[2];
	bool be = r_config_get_b (core->config, "cfg.bigendian");
	const char *arg = r_str_trim_head_ro (input + 3);
	int size = isdigit (sizeChar)? sizeChar - '0': 1;
	if (size != 1 && size != 2 && size != 4 && size != 8) {
		R_LOG_ERROR ("Invalid value size. Must be 1, 2, 4 or 8");
		return;
	}
	char *args = strdup (arg);
	char *arg1 = strchr (args, ' ');
	if (arg1) {
		*arg1++ = 0;
	} else {
		R_LOG_ERROR ("Usage: /xn [value] [amount]");
		free (args);
		return;
	}
	int amount = r_num_math (core->num, arg1);
	if (amount < 1) {
		R_LOG_ERROR ("Usage: /xn [value] [amount]");
		free (args);
		return;
	}
	ut8 b[8];
	RStrBuf *sb = r_strbuf_new ("");
	ut64 v = r_num_math (core->num, args);
	int i;
	for (i = 0; i < amount; i++) {
		switch (size) {
		case 1:
			if (v > 0xff) {
				R_LOG_WARN ("Invalid byte value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x", (ut8)(v & 0xff));
			break;
		case 2:
			r_write_ble16 (b, v, be);
			if (v > UT16_MAX) {
				R_LOG_WARN ("Invalid word value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x%02x", b[0], b[1]);
			break;
		case 4:
			r_write_ble32 (b, v, be);
			if (v > UT32_MAX) {
				R_LOG_WARN ("Invalid dword value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
			break;
		case 8:
			r_write_ble64 (b, v, be);
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[4], b[5], b[6], b[7]);
			break;
		}
	}
	free (args);
	char *s = r_strbuf_drain (sb);
	core->in_search = false;
	r_core_cmdf (core, "/x %s", s);
	free (s);
}

static void cmd_search_xv(RCore *core, const char *input) {
	if (strchr (input, '?')) {
		r_core_cmd_help_match (core, help_msg_slash_x, "/xv");
		return;
	}
	char sizeChar = input[2];
	bool be = r_config_get_b (core->config, "cfg.bigendian");
	const char *arg = r_str_trim_head_ro (input + 3);
	int size = isdigit (sizeChar)? sizeChar - '0': 1;
	if (size != 1 && size != 2 && size != 4 && size != 8) {
		R_LOG_ERROR ("Invalid value size. Must be 1, 2, 4 or 8");
		return;
	}
	char *args = strdup (arg);
	RList *list = r_str_split_list (args, " ", 0);
	RListIter *iter;
	const char *str;
	ut8 b[8];
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (list, iter, str) {
		ut64 v = r_num_math (core->num, str);
		switch (size) {
		case 1:
			if (v > 0xff) {
				R_LOG_WARN ("Invalid byte value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x", (ut8)(v & 0xff));
			break;
		case 2:
			r_write_ble16 (b, v, be);
			if (v > UT16_MAX) {
				R_LOG_WARN ("Invalid word value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x%02x", b[0], b[1]);
			break;
		case 4:
			r_write_ble32 (b, v, be);
			if (v > UT32_MAX) {
				R_LOG_WARN ("Invalid dword value %"PFMT64d, v);
			}
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
			break;
		case 8:
			r_write_ble64 (b, v, be);
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
			r_strbuf_appendf (sb, "%02x%02x%02x%02x", b[4], b[5], b[6], b[7]);
			break;
		}
	}
	free (args);
	r_list_free (list);
	char *s = r_strbuf_drain (sb);
	core->in_search = false;
	r_core_cmdf (core, "/x %s", s);
	free (s);
}

static void __core_cmd_search_backward_prelude(RCore *core, bool doseek, bool forward) {
	RList *preds = r_anal_preludes (core->anal);
	int bs = core->blocksize;
	ut8 *bf = calloc (bs, 1);
	if (preds) {
		RListIter *iter;
		RSearchKeyword *kw;
		ut64 addr = core->addr;
		if (forward) {
			addr -= bs;
			addr += 4;
		}
		r_cons_break_push (core->cons, NULL, NULL);
		while (addr > bs) {
			if (r_cons_is_breaked (core->cons)) {
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
						R_LOG_ERROR ("search update read failed at 0x%08"PFMT64x, addr);
						r_flag_unset_name (core->flags, "hit.prelude");
						fail = true;
					}
					break;
				}
			}
			if (fail) {
				break;
			}
			RFlagItem *fi = r_flag_get (core->flags, "hit.prelude");
			if (fi) {
				if (doseek) {
					r_core_seek (core, fi->addr, true);
					r_flag_unset (core->flags, fi);
				}
				break;
			}
		}
		r_cons_break_pop (core->cons);
		r_search_kw_reset (core->search);
		r_list_free (preds);
	}
	free (bf);
}

static void cmd_slash_ab(RCore *core, int delta, bool infunc) {
	const char *search_in = r_config_get (core->config, "search.in");
	if (infunc) {
		search_in = "anal.fcn";
	}
	RList *boundaries = r_core_get_boundaries_prot (core, -1, search_in, "search");
	RListIter *iter;
	RIOMap *map;
	RAnalOp analop;
	ut64 at;
	r_cons_break_push (core->cons, NULL, NULL);
	int minopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	int maxopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
	if (minopsz < 1 || maxopsz < 1) {
		R_LOG_ERROR ("Invalid MAX_OPSIZE. assuming 4");
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
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			int left = R_MIN ((map_end - at), maxopsz);
			int rc = r_anal_op (core->anal, &analop, at, buf + (at - map_begin), left,
				R_ARCH_OP_MASK_DISASM | R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
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
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", at);
			}
			at += analop.size - 1;
			r_anal_op_fini (&analop);
		}
		free (buf);
	}
	r_cons_break_pop (core->cons);
	r_list_free (boundaries);
}

static void __core_cmd_search_asm_byteswap(RCore *core, int nth) {
	ut8 buf[32];
	int i;
	r_io_read_at (core->io, 0, buf, sizeof (buf));
	if (nth < 0 || nth >= sizeof (buf) - 1) {
		return;
	}
	for (i = 0; i <= 0xff; i++) {
		RAnalOp asmop;
		buf[nth] = i;
		r_anal_op_init (&asmop);
		if (r_asm_disassemble (core->rasm, &asmop, buf, sizeof (buf)) > 0) {
			const char *asmstr = asmop.mnemonic;
			if (!strstr (asmstr, "invalid") && !strstr (asmstr, "unaligned")) {
				r_cons_printf (core->cons, "%02x  %s\n", i, asmstr);
			}
		}
		r_anal_op_fini (&asmop);
	}
}

static int chatoi(const char *arg) {
	if (isdigit (*arg)) {
		return *arg - '0';
	}
	return 0;
}

static bool is_json_command(const char *input, int *param_offset) {
	const char *lastch = strchr (input, ' ');
	if (lastch) {
		if (lastch > input) {
			lastch--;
			const char *nextch = r_str_trim_head_ro (lastch);
			if (param_offset) {
				if (*lastch && lastch[1]) {
					int delta = 2 + (nextch - input);
					*param_offset = delta;
				}
			}
			return (*lastch == 'j');
		}
		return false;
	}
	lastch = input + strlen (input) - 1;
	return (*lastch == 'j');
}

#if 1
// arm16
#define BADDR_BSZ (16 * 1024)
#define BADDR_MSK (UT64_MAX << 16)
#define BADDR_MIN (ut64)0x1000000ULL
#define BADDR_MAX (ut64)0x100000000ULL
#else
// stm8 - experimental
#define BADDR_BSZ (8 * 1024)
#define BADDR_MSK (UT64_MAX << 12)
#define BADDR_MIN 0x1000
#define BADDR_MAX 0x10000
#endif

static void appendbaddr(RList *res, ut64 n) {
	if (n == UT64_MAX) {
		return;
	}
	if (n & 1) {
		return;
	}
	if (n < BADDR_MIN) {
		return;
	}
	if (n > BADDR_MAX) {
		return;
	}
	ut8 lo = ((n >> 16) & 0xff);
	ut8 hi = ((n >> 24) & 0xff);
	if (lo == 0xff || hi == 0xff) {
		return;
	}
	if (lo && hi) {
		return;
	}
	ut64 mn = n & BADDR_MSK;
	if (mn) {
		r_list_append (res, ut64_new (mn));
	}
}


static void cmd_search_baddr_asm(RCore *core, RList *res, RIOMap *map) {
	ut64 from = r_io_map_begin (map);
	ut64 to = r_io_map_end (map);
	RAnalOp aop;
	size_t len = to - from;
	if (len > BADDR_BSZ) {
		char hs[32];
		r_num_units (hs, sizeof (hs), BADDR_BSZ);
		R_LOG_WARN ("Dim scan to %s", hs);
		len = BADDR_BSZ;
	}
	ut8 *buf = malloc (len);
	if (!buf) {
		return;
	}
	r_io_read_at (core->io, from, buf, len);
	int codealign = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
	ut64 idx;
	for (idx = 0; idx < len; idx++) {
		ut64 at = from + idx;
		r_anal_op_init (&aop);
		int error = r_anal_op (core->anal, &aop, at, buf + idx, len - idx, R_ARCH_OP_MASK_DISASM);
		if (error < 1 || aop.type == R_ANAL_OP_TYPE_ILL) {
			if (codealign > 1) {
				idx += codealign - 1;
				continue;
			}
		}
		// eprintf ("0x%llx %s%c", at, aop.mnemonic, 10);
		switch (aop.type) {
		case R_ANAL_OP_TYPE_LOAD:
			if (aop.refptr == 4) {
				ut8 b[4] = {0};
				(void) r_io_read_at (core->io, aop.ptr, b, sizeof b);
				ut32 w = r_read_le32 (b);
				appendbaddr (res, w);
			}
			break;
		default:
			appendbaddr (res, aop.ptr);
			appendbaddr (res, aop.val);
			break;
		}
		idx += aop.size - 1;
		r_anal_op_fini (&aop);
	}
	free (buf);
}

static int ut64cmp(const void *a, const void *b) {
	ut64 *na = (ut64*)a;
	ut64 *nb = (ut64*)b;
	if (*nb > *na) {
		return 1;
	}
	if (*nb < *na) {
		return -1;
	}
	return 0;
}

static ut64 ut64item(const void *a) {
	ut64 *na = (ut64*)a;
	return *na;
}

static void cmd_search_baddr(RCore *core, const char *input) {
	const char *where = r_config_get (core->config, "search.in");
	RList *res = r_list_newf (free);
	RList *bounds = r_core_get_boundaries_prot (core, R_PERM_R, where, "search");
	RBinObject *obj = r_bin_cur_object (core->bin);
	if (obj) {
		RBinString *s;
		RListIter *iter;
		r_list_foreach (obj->strings, iter, s) {
			if (strstr (s->string, "0x")) {
				ut64 n = r_num_math (NULL, s->string);
				appendbaddr (res, n);
			}
		}
	}
	// find strings with addresses
	// find absolute references
	{
		RIOMap *map;
		RListIter *iter;
		r_list_foreach (bounds, iter, map) {
			cmd_search_baddr_asm (core, res, map);
		}
	}
	{
		RListIter *iter;
		ut64 *n;
		r_list_uniq_inplace (res, ut64item);
		r_list_sort (res, ut64cmp);
		r_list_foreach (res, iter, n) {
			r_cons_printf (core->cons, "0x%08"PFMT64x"%c", *n, 10);
		}
		r_list_free (res);
	}
	r_list_free (bounds);
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
		.key_search = false,
		.key_search_len = 0,
		.searchflags = r_config_get_i (core->config, "search.flags"),
		.searchshow = r_config_get_i (core->config, "search.show"),
		.searchprefix = r_config_get (core->config, "search.prefix"),
		.count = 0,
		.c = 0
	};
	if (!param.cmd_hit) {
		param.cmd_hit = "";
	}
	RSearch *search = core->search;
	int ignorecase = false;
	char *inp;
	if (!core || !core->io) {
		R_LOG_ERROR ("Can't search if we don't have an open file");
		return false;
	}
	if (core->in_search) {
		R_LOG_ERROR ("Can't search from within a search");
		return R_CMD_RC_SUCCESS;
	}
	if (input[0] == '/') { // "//" - repeat last search
		if (core->lastsearch) {
			input = core->lastsearch;
		} else {
			R_LOG_ERROR ("No previous search done");
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
		R_LOG_ERROR ("Invalid search range where search.from > search.to");
		errcode = 0;
		goto beach;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RInterval search_itv = {search_from, search_to - search_from};
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		R_LOG_WARN ("from == to?");
		errcode = 0;
		goto beach;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv.addr = 0;
		search_itv.size = UT64_MAX;
	}

	param.mode = r_config_get (core->config, "search.in");
	param.boundaries = r_core_get_boundaries_prot (core, -1, param.mode, "search");
	param.progressbar = r_config_get_b (core->config, "scr.progressbar");
	if (param.progressbar) {
		param.progressbar = r_config_get_b (core->config, "scr.interactive");
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
	core->search->maxhits = r_config_get_i (core->config, "search.maxhits");
	if (r_config_get_b (core->config, "search.named")) {
		param.searchprefix = r_str_newf ("hit.%s.", r_str_trim_head_ro (input));
	}
	core->search->overlap = r_config_get_i (core->config, "search.overlap");
	core->search->bckwrds = false;

	int param_offset = r_str_nlen (input, 2);
	if (is_json_command (input, &param_offset)) {
		param.outmode = R_MODE_JSON;
	}
	// eprintf ("COMMAND (%d) %d (%s)(%s)\n", param.outmode == R_MODE_JSON, param_offset, input, input + param_offset);
	if (param.outmode == R_MODE_JSON) {
		param.pj = r_core_pj_new (core);
	} else {
		param.pj = NULL;
	}

reread:
	switch (*input) {
	case '!': // "/!"
		input++;
		param_offset--;
		param.inverse = true;
		goto reread;
	case 'b': // "/b" backward search
		if (*(++input) == '?') {
			r_core_cmd_help (core, help_msg_slash_backward);
			goto beach;
		}
		param_offset--;
		if (*input == 'p') { // "/bp" backward prelude
			__core_cmd_search_backward_prelude (core, false, false);
			goto beach;
		}
		search->bckwrds = true;
		if (core->addr) {
			RInterval itv = {0, core->addr};
			if (!r_itv_overlap (search_itv, itv)) {
				goto beach;
			} else {
				search_itv = r_itv_intersect (search_itv, itv);
			}
		}
		goto reread;
	case 'B': // "/B" base address search
		cmd_search_baddr (core, input);
		goto beach;
		break;
	case 'o': { // "/o" print the offset of the Previous opcode
			  if (input[1] == '?') {
				  r_core_cmd_help_match (core, help_msg_slash, "/o");
				  break;
			  }
			  ut64 addr, n = input[param_offset - 1] ? r_num_math (core->num, input + param_offset) : 1;
			  n = R_ABS((st64)n);
			  if (((st64)n) < 1) {
				  n = 1;
			  }
			  if (!r_core_prevop_addr (core, core->addr, n, &addr)) {
				  addr = UT64_MAX;
				  (void)r_core_asm_bwdis_len (core, NULL, &addr, n);
			  }
			  if (param.outmode == R_MODE_JSON) {
				  r_cons_printf (core->cons, "[%"PFMT64u "]", addr);
			  } else {
				  r_cons_printf (core->cons, "0x%08"PFMT64x "\n", addr);
			  }
		}
		break;
	case 'O': { // "/O" alternative to "/o"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_slash, "/O");
			break;
		}
		ut64 addr, n = input[param_offset - 1] ? r_num_math (core->num, input + param_offset) : 1;
		if (!n) {
			n = 1;
		}
		addr = r_core_prevop_addr_force (core, core->addr, n);
		if (param.outmode == R_MODE_JSON) {
			r_cons_printf (core->cons, "[%"PFMT64u "]", addr);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x "\n", addr);
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
		ut64 n = (input[1] == ' ' || (input[1] && input[2] == ' '))
			? r_num_math (core->num, input + 2): UT64_MAX;
		if (!n) {
			R_LOG_ERROR ("Cannot find null references");
			break;
		}
		switch (input[1]) {
		case 'a': // "/ra"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					R_LOG_DEBUG ("-- 0x%"PFMT64x" 0x%"PFMT64x, r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 0);
				}
			}
			break;
		case 'c': // "/rc"
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					R_LOG_DEBUG ("-- 0x%"PFMT64x" 0x%"PFMT64x, r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, 'c');
				}
			}
			break;
		case 'e': // "/re"
			if (input[2] == ' ') {
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					R_LOG_DEBUG ("-- 0x%"PFMT64x" 0x%"PFMT64x, r_io_map_begin (map), r_io_map_end (map));
					ut64 refptr = r_num_math (core->num, input + 2);
					ut64 curseek = core->addr;
					r_core_seek (core, r_io_map_begin (map), true);
					char *arg = r_str_newf (" %"PFMT64d, r_io_map_size (map));
					char *trg = refptr? r_str_newf (" %"PFMT64d, refptr): strdup ("");
					r_core_anal_esil (core, arg, trg);
					free (arg);
					free (trg);
					r_core_seek (core, curseek, true);
				}
			} else {
				r_core_cmd_help_match (core, help_msg_slash_r, "/re");
				dosearch = false;
			}
			break;
		case 'u': // "/ru"
			{
				bool v = r_config_get_b (core->config, "search.verbose");
				int mode = input[2];
				if (!mode && !v) {
					mode = 'q';
				}
				(void)r_core_search_uds (core, mode);
				dosearch = false;
				break;
			}
		case 'r': // "/rr" - read refs
		case 'w': // "/rw" - write refs
		case 'x': // "/rx" - exec refs
			{
				RListIter *iter;
				RIOMap *map;
				r_list_foreach (param.boundaries, iter, map) {
					R_LOG_DEBUG ("-- 0x%"PFMT64x" 0x%"PFMT64x, r_io_map_begin (map), r_io_map_end (map));
					r_core_anal_search (core, r_io_map_begin (map), r_io_map_end (map), n, input[1]);
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
						r_core_anal_search (core, from, to, r_num_math (core->num, input + 2), 0);
						do_ref_search (core, r_num_math (core->num, input + 2), from, to, &param);
					} else {
						r_core_anal_search (core, from, to, core->addr, 0);
						do_ref_search (core, core->addr, from, to, &param);
					}
					if (r_cons_is_breaked (core->cons)) {
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
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ad");
			} else {
				do_asm_search (core, &param, input + 1, 0, search_itv);
			}
			break;
		case 'e': // "/ae"
			dosearch = false;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ae");
			} else {
				do_asm_search (core, &param, input + 2, 'e', search_itv);
			}
			break;
		case 'c': // "/ac"
			dosearch = false;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ac");
			} else {
				do_asm_search (core, &param, input + 2, 'c', search_itv);
			}
			break;
		case 'o':  // "/ao"
			dosearch = false;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ao");
			} else {
				do_asm_search (core, &param, input + 2, 'o', search_itv);
			}
			break;
		case 'a': // "/aa"
			dosearch = false;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/aa");
			} else {
				do_asm_search (core, &param, input + 2, 'a', search_itv);

			}
			break;
		case 'i': // "/ai"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ai");
			} else {
				do_asm_search (core, &param, input + 2, 'i', search_itv);
			}
			break;
		case 'b': // "ab"
			if (input[2] == 'f') {
				cmd_slash_ab (core, (int)r_num_math (core->num, input + 2), true);
			} else if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/ab");
			} else if (input[2] == ' ' || input[2] == 0) {
				cmd_slash_ab (core, (int)r_num_math (core->num, input + 2), false);
			} else {
				r_core_return_invalid_command (core, "/ab", input[2]);
			}
			break;
		case '1': // "a1"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/a1");
			} else {
				__core_cmd_search_asm_byteswap (core, (int)r_num_math (core->num, input + 2));
			}
			break;
		case 'I': //  "/aI" - infinite
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/aI");
			} else {
				__core_cmd_search_asm_infinite (core, r_str_trim_head_ro (input + 1));
			}
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
		case 's': // "/asl"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/as");
			} else if (input[2] == 'l') { // "asl"
				if (input[2] == '?') {
					r_core_cmd_help_match (core, help_msg_slash_a, "/as");
				} else {
					r_core_cmd_call (core, "asl");
				}
			} else { // "/as" "/asj"
				do_syscall_search (core, &param);
			}
			dosearch = false;
			break;
		case 'u': // "/au"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_a, "/az");
			} else {
				do_unkjmp_search (core, &param, false, r_str_trim_head_ro (input + 2));
			}
			break;
		case 'z': // "/az"
			switch (input[2]) {
			case '?': // "/az"
				r_core_cmd_help_match (core, help_msg_slash_a, "/az");
				break;
			case 'q': // "/azq"
				do_analstr_search (core, &param, true, r_str_trim_head_ro (input + 3));
				break;
			case 's': // "/azs"
				param.outmode = R_MODE_SIMPLE;
				do_analstr_search (core, &param, true, NULL);
				break;
			case 'j': // "/azj"
				param.outmode = R_MODE_JSON;
				do_analstr_search (core, &param, false, NULL);
				break;
			case ' ': // "/az [num]"
				do_analstr_search (core, &param, false, r_str_trim_head_ro (input + 2));
				break;
			case 0:
				do_analstr_search (core, &param, false, "");
				break;
			default:
				r_core_cmd_help_match (core, help_msg_slash_a, "/az");
				break;
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
		case '?':
			r_core_cmd_help (core, help_msg_slash_c);
			goto beach;

		case 'k': // "/ck"
			{
				const bool le = !r_config_get_b (core->config, "cfg.bigendian");
				RSearchKeyword *kw;
				r_search_reset (core->search, R_SEARCH_TIRE);

				// aes round constant table
				kw = r_search_keyword_new_hexmask ("01020408102040801b366cc0ab4d9a2f5ebf63c697356ad4b37dfaefc591", NULL); // AES
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
				dosearch = false;
				dosearch_read = true;
				break;
			}
		case 'c': // "/cc"
			{
				char *space = strchr (input, ' ');
				const char *arg = space? r_str_trim_head_ro (space + 1): NULL;
				if (!arg || input[2] == '?') {
					r_core_cmd_help (core, help_msg_slash_cc);
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
					r_core_cmd_help (core, help_msg_slash_cc);
				}
				free (s);
				goto beach;
			}
			break;
		case 'd': // "/cd"
			{
			RSearchKeyword *kw_1, *kw_2, *kw_3;
			if (input[2] == 'j') {
				param.outmode = R_MODE_JSON;
			}
			// Certificate with version number
			kw_1 = r_search_keyword_new_hex ("30820000308100A0030201", "ffff0000ffff00ffffffff", NULL);
			kw_2 = r_search_keyword_new_hex ("3082000030820000A0030201", "ffff0000ffff0000ffffffff", NULL);
			// Certificate with serial number
			kw_3 = r_search_keyword_new_hex ("308200003082000002", "ffff0000ffff0000ff", NULL);
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			if (kw_1 && kw_2 && kw_3) {
				r_search_kw_add (core->search, kw_1);
				r_search_kw_add (core->search, kw_2);
				r_search_kw_add (core->search, kw_3);
				r_search_begin (core->search);
			} else {
				R_LOG_ERROR ("invalid pointer");
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
				char *space = strchr (input, ' ');
				const char *arg = space? r_str_trim_head_ro (space + 1): NULL;
				if (!arg || *(space - 1) == '?') {
					r_core_cmd_help_match (core, help_msg_slash_c, "/ca");
					goto beach;
				} else {
					if (input[2] == 'j') {
						param.outmode = R_MODE_JSON;
					}
					if (!strcmp (arg, "aes")) {
						// AES search is done over 40 bytes
						param.key_search_len = AES_SEARCH_LENGTH;
						r_search_reset (core->search, R_SEARCH_AES);
					} else if (!strcmp (arg, "sm4")) {
						param.key_search_len = SM4_SEARCH_LENGTH;
						r_search_reset (core->search, R_SEARCH_SM4);
					} else {
						R_LOG_ERROR ("Unsupported block cipher: %s", arg);
						goto beach;
					}
					if (core->blocksize < param.key_search_len) {
						R_LOG_ERROR ("Block size must be larger than %d bytes", param.key_search_len);
						goto beach;
					}
					RSearchKeyword *kw = r_search_keyword_new_hexmask ("00", NULL);
					r_search_kw_add (search, kw);
					r_search_begin (core->search);
					param.key_search = true;
				}
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
				kw->keyword_length = ASN1_PRIVATE_KEY_SEARCH_LENGTH;
				r_search_reset (core->search, R_SEARCH_ASN1_PRIV_KEY);
				r_search_kw_add (search, kw);
				r_search_begin (core->search);
				param.key_search = true;
				break;
			}
		case 'p': // "/cp"
			{
				RSearchKeyword *kw;
				if (input[2] == 'j') {
					param.outmode = R_MODE_JSON;
				}
				char *space = strchr (input, ' ');
				const char *arg = space? r_str_trim_head_ro (space + 1): NULL;
				if (!arg || *(space - 1) == '?') {
					r_core_cmd_help_match (core, help_msg_slash_c, "/cp");
					goto beach;
				} else {
					char *p = strchr (arg, ' ');
					if (p) {
						*p++ = 0;
					} else {
						r_core_cmd_help_match (core, help_msg_slash_c, "/cp");
						goto beach;
					}

					char *algo = strdup (arg);
					char *pubkey = strdup (r_str_trim_head_ro (p));
					if (!strcmp (algo, "ed25519")) {
						r_search_reset (core->search, R_SEARCH_RAW_PRIV_KEY);
					} else {
						R_LOG_ERROR ("Unsupported signature: %s", arg);
						goto beach;
					}

					if (strlen (pubkey) == ED25519_PUBKEY_LENGTH) {
						core->search->data = (void *)pubkey;
					} else {
						R_LOG_ERROR ("Wrong key length");
						goto beach;
					}

					kw = r_search_keyword_new_hexmask ("00", NULL);
					// Private key search is at least 32 bytes
					kw->keyword_length = RAW_PRIVATE_KEY_SEARCH_LENGTH;
					r_search_kw_add (search, kw);
					r_search_begin (core->search);
					param.key_search = true;
					free (algo);
					break;
				}
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
			r_core_cmd_help (core, help_msg_slash_magic);
		} else if (input[1] == 'b') { // "/mb"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_magic, "/mb");
				break;
			}
			bool bin_verbose = r_config_get_i (core->config, "bin.verbose");
			r_config_set_b (core->config, "bin.verbose", false);
			// TODO : iter maps?
			cmd_search_bin (core, search_itv);
			r_config_set_b (core->config, "bin.verbose", bin_verbose);
		} else if (input[1] == 'm') { // "/mm"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_magic, "/mm");
				break;
			}
			ut64 addr = search_itv.addr;
			RListIter *iter;
			RIOMap *map;
			int count = 0;
			const int align = core->search->align;
			r_list_foreach (param.boundaries, iter, map) {
				// eprintf ("-- %llx %llx\n", r_io_map_begin (map), r_io_map_end (map));
				r_cons_break_push (core->cons, NULL, NULL);
				for (addr = r_io_map_begin (map); addr < r_io_map_end (map); addr++) {
					if (r_cons_is_breaked (core->cons)) {
						break;
					}
					if (align && (0 != (addr % align))) {
						addr += (addr % align) - 1;
						continue;
					}
					char *mp = r_str_newf ("/mnt%d", count);
					if (r_fs_mount (core->fs, NULL, mp, addr)) {
						count ++;
						R_LOG_INFO ("Mounted %s at 0x%08"PFMT64x, mp, addr);
					}
					free (mp);
				}
				r_cons_clear_line (core->cons, true, true);
				r_cons_break_pop (core->cons);
			}
			eprintf ("\n");
		} else if (input[1] == 'e') { // "/me"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_magic, "/me");
				break;
			}
			r_cons_printf (core->cons, "* r2 thinks%s\n", input + 2);
		} else if (input[1] == ' ' || input[1] == '\0' || param.outmode == R_MODE_JSON) {
			int ret;
			const char *file = input[param_offset - 1]? input + param_offset: NULL;
			ut64 addr = search_itv.addr;
			RListIter *iter;
			RIOMap *map;
			RSearchKeyword *kw;

			kw = r_search_keyword_new_hexmask ("00", NULL);
			kw->keyword_length = 1;
			r_search_reset (core->search, R_SEARCH_MAGIC);
			r_search_kw_add (core->search, kw);

			if (param.outmode == R_MODE_JSON) {
				pj_a (param.pj);
			}

			int maxHits = r_config_get_i (core->config, "search.maxhits");
			MagicContext mc = {
				.core = core,
				.ofile = NULL,
				.hits = 0
			};
			r_list_foreach (param.boundaries, iter, map) {
				if (param.outmode != R_MODE_JSON) {
					eprintf ("-- %"PFMT64x" %"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
				}
				r_cons_break_push (core->cons, NULL, NULL);
				for (addr = r_io_map_begin (map); addr < r_io_map_end (map); addr++) {
					if (r_cons_is_breaked (core->cons)) {
						break;
					}
					ret = magic_at (&mc, kw, file, addr, 0, false,
							param.outmode == R_MODE_JSON? param.pj: NULL);
					if (ret == -1) {
						// something went terribly wrong.
						break;
					}
					if (maxHits && mc.hits >= maxHits) {
						break;
					}
					addr += ret - 1;
				}
				r_cons_clear_line (core->cons, true, true);
				r_cons_break_pop (core->cons);
			}
			free (mc.ofile);
			if (param.outmode == R_MODE_JSON) {
				pj_end (param.pj);
			}
		} else {
			r_core_cmd_help (core, help_msg_slash_magic);
		}
		r_cons_clear_line (core->cons, true, true);
		break;
	case 'p': // "/p"
		if (input[1] == '?') { // "/p" -- find next pattern
			r_core_cmd_help (core, help_msg_slash_pattern);
		} else if (input[1] == 'p') { // "/pp" -- find next prelude
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_slash_pattern, "/pp");
			} else {
				__core_cmd_search_backward_prelude (core, false, true);
			}
		} else if (input[param_offset - 1]) {
			int ps = atoi (input + param_offset);
			if (ps > 1) {
				r_search_set_mode (search, R_SEARCH_PATTERN);
				r_search_pattern_size (search, ps);
				dosearch_read = true;
			} else {
				R_LOG_ERROR ("Invalid pattern size (must be > 0)");
			}
		}
		break;
	case 'P': // "/P"
		search_similar_pattern (core, atoi (input + 1), &param);
		break;
	case 'V': // "/V"
		{
			if (strchr (input + 1, '*')) {
				param.outmode = R_MODE_RADARE;
			}
			int err = 1, vsize = chatoi (input + 1);
			const char *num_str = input + param_offset;
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
								R_LOG_INFO ("hits: %d", hits);
							}
						}
					}
				}
				if (param.outmode == R_MODE_JSON) {
					pj_end (param.pj);
				}
			}
			if (err) {
				r_core_cmd_help_match (core, help_msg_slash, "/V");
			}
		}
		dosearch = false;
		break;
	case 'v': // "/v"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_slash, "/v");
			break;
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
				r_core_cmd_help_match (core, help_msg_slash, "/v");
			}
			break;
		case '1':
			if (input[param_offset]) {
				bsize = sizeof (ut8) * len;
				v_buf = v_writebuf (core, nums, len, '1', bsize);
			} else {
				r_core_cmd_help_match (core, help_msg_slash, "/v");
			}
			break;
		case '2':
			if (input[param_offset]) {
				bsize = sizeof (ut16) * len;
				v_buf = v_writebuf (core, nums, len, '2', bsize);
			} else {
				r_core_cmd_help_match (core, help_msg_slash, "/v");
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
				r_core_cmd_help_match (core, help_msg_slash, "/v");
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
			r_core_cmd_help (core, help_msg_slash_wide_string);
			break;
		}
		if (input[2]) {
			if (input[2] == '?') { // "/w?"
				r_core_cmd_help (core, help_msg_slash_wide_string);
				break;
			}
			if (input[1] == 'j' || input[2] == 'j') { // "/wj"
				param.outmode = R_MODE_JSON;
			}
			if (input[1] == 'i' || input[2] == 'i') { // "/wi"
				ignorecase = true;
			}
		} else {
			param.outmode = R_MODE_RADARE;
		}
		size_t shift = 1 + ignorecase;
		if (param.outmode == R_MODE_JSON) {
			shift++;
		}
		size_t strstart = shift + 1;
		const bool be = r_config_get_b (core->config, "cfg.bigendian");
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
		RSearchKeyword *skw = r_search_keyword_new_wide (input + strstart, NULL, NULL, ignorecase, be);
		if (skw) {
			r_search_kw_add (core->search, skw);
			r_search_begin (core->search);
			dosearch = true;
		} else {
			R_LOG_ERROR ("Invalid keyword");
			break;
		}
		break;
	case 'i': // "/i"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_slash, "/i");
			break;
		}
		if (input[param_offset - 1] != ' ') {
			R_LOG_ERROR ("Missing ' ' after /i");
			r_core_return_value (core, R_CMD_RC_FAILURE);
			goto beach;
		}
		ignorecase = true;
		// fallthrough
	case 'j': // "/j"
		if (input[0] == 'j' && input[1] == ' ') {
			param.outmode = R_MODE_JSON;
		}
		// fallthrough
	case ' ': // "/ " search string
		{
			const int distance = r_config_get_i (core->config, "search.distance");
			inp = strdup (input + 1 + ignorecase + (param.outmode == R_MODE_JSON ? 1 : 0));
			len = r_str_unescape (inp);
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, distance);
			RSearchKeyword *skw = r_search_keyword_new_str (inp, NULL, NULL, ignorecase);
			if (skw) {
				skw->icase = ignorecase;
				skw->type = R_SEARCH_KEYWORD_TYPE_STRING;
				r_search_kw_add (core->search, skw);
				r_search_begin (core->search);
				dosearch = true;
			} else {
				R_LOG_ERROR ("Invalid keyword");
			}
		}
		break;
	case 'k': // "/k" Rabin Karp String search
		{
			if (input[1] == '?') {
				r_core_cmd_help (core, help_msg_slash_k);
				break;
			}
			inp = r_str_trim_dup (input + 1 + ignorecase + (param.outmode == R_MODE_JSON ? 1 : 0));
			len = r_str_unescape (inp);
			r_search_reset (core->search, R_SEARCH_RABIN_KARP);
			r_search_set_distance (core->search, (int)r_config_get_i (core->config, "search.distance"));
			RSearchKeyword *skw = r_search_keyword_new_str (inp, NULL, NULL, ignorecase);
			free (inp);
			if (skw) {
				r_search_kw_add (core->search, skw);
				r_search_begin (core->search);
				dosearch_read = true;
			} else {
				R_LOG_ERROR ("Invalid keyword");
			}
		}
		break;
	case 'e': // "/e" match regexp
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_slash, "/e");
		} else if (input[1]) {
			if (input[1] == 'j') {
				param.outmode = R_MODE_JSON;
				input++;
			}
			RSearchKeyword *kw;
			kw = r_search_keyword_new_regexp (input + 1, NULL);
			if (!kw) {
				R_LOG_ERROR ("Invalid regexp specified");
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
			R_LOG_ERROR ("Missing regex");
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
			r_core_cmd_help (core, help_msg_slash_delta);
			break;
		}
		if (input[1]) {
			r_search_reset (core->search, R_SEARCH_DELTAKEY);
			r_search_kw_add (core->search,
				r_search_keyword_new_hexmask (input + param_offset, NULL));
			r_search_begin (core->search);
			dosearch = true;
		} else {
			R_LOG_ERROR ("Missing delta");
		}
		break;
	case 'h': // "/h"
	{

		char *p, *arg = r_str_trim_dup (input + 1);
		if (*arg == '?') {
			r_core_cmd_help_match (core, help_msg_slash, "/h");
			break;
		}
		// "/h*" we do not add a flag for the search hit.
		if (*arg == '*') {
			param.searchflags = 0;
			free (arg);
			arg = r_str_trim_dup (input + 2);
		}
		p = strchr (arg, ' ');
		if (p) {
			*p++ = 0;
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
		} else {
			R_LOG_ERROR ("Missing hash. See ph?");
		}
		free (arg);
	}
	break;
	case 'f': // "/f" forward search
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_forward);
			break;
		}
		if (core->addr) {
			st64 coff = core->addr;
			RInterval itv = {core->addr, -coff};
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
			r_core_cmd_help_match (core, help_msg_slash, "/g");
		} else {
			ut64 addr = UT64_MAX;
			if (input[1]) {
				addr = r_num_math (core->num, input + 2);
			} else {
				RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
				if (fcn) {
					addr = fcn->addr;
				} else {
					addr = core->addr;
				}
			}
			const int depth = r_config_get_i (core->config, "anal.depth");
			// Va;ifate input length
			if (input[1] != '\0') {
				r_core_anal_paths (core, addr, core->addr, input[1] == 'g', depth, (input[1] == 'j' || input[2] == 'j'));
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
				R_LOG_ERROR ("Cannot open '%s'", args[0]);
				r_str_argv_free (args);
				break;
			}
			if (n_args > 1) {
				offset = r_num_math (core->num, args[1]);
				if (size <= offset) {
					R_LOG_ERROR ("size <= offset");
					r_str_argv_free (args);
					free (buf);
					break;
				}
			}
			if (n_args > 2) {
				len = r_num_math (core->num, args[2]);
				if (len > size - offset) {
					R_LOG_ERROR ("len too large");
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
				R_LOG_ERROR ("no keyword");
			}

			r_str_argv_free (args);
			free (buf);
		} else {
			r_core_cmd_help_match (core, help_msg_slash, "/F");
		}
		break;
	case 'x': // "/x" search hex
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_x);
		} else if (input[1] == 'n') {
			cmd_search_xn (core, input);
		} else if (input[1] == 'v') {
			cmd_search_xv (core, input);
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
				// R_LOG_INFO ("Searching %d byte(s)", kw->keyword_length);
				r_search_begin (core->search);
				dosearch = true;
			} else {
				R_LOG_ERROR ("no keyword");
			}
			free (p);
		}
		break;
	case 's': // "/s"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_slash_sections);
			break;
		}
		if (input[1] == 'j') { // "/sj"
			param.outmode = R_MODE_JSON;
			input++;
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
			R_LOG_INFO ("Using chunksize: %d", chunksize);
			core->in_search = false;
			for (i = 0; i < len; i += chunksize) {
				chunksize = ochunksize;
again:
				r_hex_bin2str ((ut8 *) str + i, R_MIN (chunksize, len - i), buf);
				R_LOG_INFO ("/x %s", buf);
				r_core_cmdf (core, "/x %s", buf);
				if (core->num->value == 0) {
					chunksize--;
					if (chunksize < 1) {
						R_LOG_ERROR ("Invalid chunksize");
						free (buf);
						free (str);
						goto beach;
					}
					R_LOG_INFO ("Repeat with chunk size %d", chunksize);
					goto again;
				}
			}
			free (str);
			free (buf);
		} else {
			r_core_cmd_help_match (core, help_msg_slash, "/+");
		}
		break;
	case 'z': // "/z" search strings of min-max range
	{
		char *p;
		ut32 min, max;
		if (!input[1]) {
			r_core_cmd_help_match (core, help_msg_slash, "/z");
			break;
		}
		const char *maxstr = NULL;
		if ((p = strchr (input + 2, ' '))) {
			*p = 0;
			maxstr = r_str_trim_head_ro (p + 1);
			max = r_num_math (core->num, maxstr);
		} else {
			r_core_cmd_help_match (core, help_msg_slash, "/z");
			break;
		}
		const char *minstr = r_str_trim_head_ro (input + 2);
		if ((maxstr && *maxstr == '-') || (minstr && *minstr == '-')) {
			R_LOG_ERROR ("min and max must be positive");
			break;
		}
		min = r_num_math (core->num, minstr);
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
		R_LOG_INFO ("See /? for help");
		break;
	}
	r_config_set_i (core->config, "search.kwidx", search->n_kws);
	if (dosearch) {
		do_string_search (core, search_itv, &param);
	} else if (dosearch_read) {
		// TODO: update pattern search to work with this
		if (param.outmode == R_MODE_JSON) {
			pj_a (param.pj);
		}
		if (search->mode != R_SEARCH_PATTERN) {
			r_search_set_read_cb (search, &_cb_hit_sz, &param);
		}
		r_search_maps (search, param.boundaries);
		if (param.outmode == R_MODE_JSON) {
			pj_end (param.pj);
		}
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
		r_cons_println (core->cons, pj_string (param.pj));
	}
	pj_free (param.pj);
	r_list_free (param.boundaries);
	r_search_kw_reset (search);
	return R_CMD_RC_SUCCESS;
}

#endif
