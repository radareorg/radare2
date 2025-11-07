/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#define R_LOG_ORIGIN "core"

#include <r_core.h>
#include <r_vec.h>

#define DB core->sdb

R_LIB_VERSION (r_core);
R_VEC_TYPE (RVecAnalRef, RAnalRef);
// R2_600
#if !R2_USE_NEW_ABI
R_IPI int Gload_index = 0;
#endif

static ut64 letter_divs[R_CORE_ASMQJMPS_LEN_LETTERS - 1] = {
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS
};

static int on_fcn_new(RAnal *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.new");
	if (R_STR_ISNOTEMPTY (cmd)) {
		ut64 oaddr = core->addr;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd); // TODO: use r_core_cmd_at
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static int on_fcn_delete(RAnal *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.delete");
	if (R_STR_ISNOTEMPTY (cmd)) {
		ut64 oaddr = core->addr;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd); // use r_core_cmd_at
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static int on_fcn_rename(RAnal *_anal, void* _user, RAnalFunction *fcn, const char *oname) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.rename");
	if (R_STR_ISNOTEMPTY (cmd)) {
		// XXX: wat do with old name here?
		ut64 oaddr = core->addr;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd); // use r_core_cmd_at
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static void r_core_debug_breakpoint_hit(RCore *core, RBreakpointItem *bpi) {
	const char *cmdbp = r_config_get (core->config, "cmd.bp");
	const bool cmdbp_exists = R_STR_ISNOTEMPTY (cmdbp);
	const bool bpcmd_exists = R_STR_ISNOTEMPTY (bpi->data);
	const bool may_output = (cmdbp_exists || bpcmd_exists);
	if (may_output) {
		r_cons_push (core->cons);
	}
	if (cmdbp_exists) {
		r_core_cmd0 (core, cmdbp);
	}
	if (bpcmd_exists) {
		r_core_cmd0 (core, bpi->data);
	}
	if (may_output) {
		r_cons_flush (core->cons);
		r_cons_pop (core->cons);
	}
}

static void r_core_debug_syscall_hit(RCore *core) {
	const char *cmdhit = r_config_get (core->config, "cmd.onsyscall");
	if (R_STR_ISNOTEMPTY (cmdhit)) {
		r_core_cmd0 (core, cmdhit);
		r_cons_flush (core->cons);
	}
}

struct getreloc_t {
	ut64 vaddr;
	int size;
};

static int getreloc_tree(void *incoming, void *in, void *user) {
	struct getreloc_t *gr = (struct getreloc_t *)incoming;
	RBinReloc *r = (RBinReloc *)in;
	if ((r->vaddr >= gr->vaddr) && (r->vaddr < (gr->vaddr + gr->size))) {
		return 0;
	}
	if (gr->vaddr > r->vaddr) {
		return 1;
	}
	if (gr->vaddr < r->vaddr) {
		return -1;
	}
	return 0;
}

R_API RBinReloc *r_core_getreloc(RCore *core, ut64 addr, int size) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	if (size < 1 || addr == UT64_MAX) {
		return NULL;
	}
	RRBTree *relocs = r_bin_get_relocs (core->bin);
	if (R_LIKELY (relocs)) {
		struct getreloc_t gr = { .vaddr = addr, .size = size };
		return r_crbtree_find (relocs, &gr, getreloc_tree, NULL);
	}
	return NULL;
}

/* returns the address of a jmp/call given a shortcut by the user or UT64_MAX
 * if there's no valid shortcut. When is_asmqjmps_letter is true, the string
 * should be of the form XYZWu, where XYZW are uppercase letters and u is a
 * lowercase one. If is_asmqjmps_letter is false, the string should be a number
 * between 1 and 9 included. */
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str) {
	R_RETURN_VAL_IF_FAIL (core, UT64_MAX);
	if (!core->asmqjmps) {
		return UT64_MAX;
	}
	if (core->is_asmqjmps_letter) {
		int i, pos = 0;
		const int len = strlen (str);
		for (i = 0; i < len - 1; i++) {
			if (!isupper ((ut8)str[i])) {
				return UT64_MAX;
			}
			pos *= R_CORE_ASMQJMPS_LETTERS;
			pos += str[i] - 'A' + 1;
		}
		if (!islower ((ut8)str[i])) {
			return UT64_MAX;
		}
		pos *= R_CORE_ASMQJMPS_LETTERS;
		pos += str[i] - 'a';
		if (pos < core->asmqjmps_count) {
			return core->asmqjmps[pos + 1];
		}
	} else if (isdigit (str[0])) {
		const int pos = str[0] - '0';
		if (pos <= core->asmqjmps_count) {
			return core->asmqjmps[pos];
		}
	}
	return UT64_MAX;
}

/**
 * Takes addr and returns already saved shortcut or a new one
 * The returned buffer needs to be freed
 */
R_API char* r_core_add_asmqjmp(RCore *core, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	bool found = false;
	if (!core->asmqjmps) {
		return NULL;
	}
	if (core->is_asmqjmps_letter) {
		if (core->asmqjmps_count >= R_CORE_ASMQJMPS_MAX_LETTERS) {
			return NULL;
		}
		if (core->asmqjmps_count >= core->asmqjmps_size - 2) {
			core->asmqjmps = realloc (core->asmqjmps, core->asmqjmps_size * 2 * sizeof (ut64));
			if (!core->asmqjmps) {
				return NULL;
			}
			core->asmqjmps_size *= 2;
		}
	}
	if (core->asmqjmps_count < core->asmqjmps_size - 1) {
		int i = 0;
		char t[R_CORE_ASMQJMPS_LEN_LETTERS + 1] = {0};
		for (i = 0; i < core->asmqjmps_count + 1; i++) {
			if (core->asmqjmps[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found) {
			i = ++core->asmqjmps_count;
			core->asmqjmps[i] = addr;
		}
		// This check makes pos never be <1, thefor not fill 't' with trash
		if (i < 1) {
			return NULL;
		}
		r_core_set_asmqjmps (core, t, sizeof (t), i);
		return strdup (t);
	}
	return NULL;
}

/* returns in str a string that represents the shortcut to access the asmqjmp
 * at position pos. When is_asmqjmps_letter is true, pos is converted into a
 * multiletter shortcut of the form XYWZu and returned (see r_core_get_asmqjmps
 * for more info). Otherwise, the shortcut is the string representation of pos. */
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int pos) {
	R_RETURN_IF_FAIL (core && str && pos > 0);
	if (core->is_asmqjmps_letter) {
		int i, j = 0;
		pos --;
		for (i = 0; i < R_CORE_ASMQJMPS_LEN_LETTERS - 1; i++) {
			const int div = pos / letter_divs[i];
			pos %= letter_divs[i];
			if (div > 0 && j < len) {
				str[j++] = 'A' + div - 1;
			}
		}
		if (j < len) {
			const int div = pos % R_CORE_ASMQJMPS_LETTERS;
			str[j++] = 'a' + div;
		}
		str[j] = '\0';
	} else {
		snprintf (str, len, "%d", pos);
	}
}

static void core_help(RCore *core, RCoreHelpMessage help) {
	r_core_cmd_help (core, help);
}

static void setab(RCore *core, const char *arch, int bits) {
	if (arch) {
		r_config_set (core->config, "asm.arch", arch);
	}
	if (bits > 0) {
		r_config_set_i (core->config, "asm.bits", bits);
	}
}

static const char *getName(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_in (core->flags, addr);
	if (item) {
		if (core->flags->realnames) {
			return item->realname
				? item->realname: item->name;
		}
		return item->name;
	}
	return NULL;
}

static char *getNameDelta(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_at (core->flags, addr, true);
	if (item) {
		if (item->addr != addr) {
			return r_str_newf ("%s + %d", item->name, (int)(addr - item->addr));
		}
		return strdup (item->name);
	}
	return NULL;
}

static void archbits(RCore *core, ut64 addr) {
	r_core_seek_arch_bits (core, addr);
}

static bool cfggetb(RCore *core, const char *k) {
	return r_config_get_b (core->config, k);
}

static ut64 cfggeti(RCore *core, const char *k) {
	return r_config_get_i (core->config, k);
}

static const char *cfgget(RCore *core, const char *k) {
	return r_config_get (core->config, k);
}

static ut64 numget(RCore *core, const char *k) {
	return r_num_math (core->num, k);
}

static bool __isMapped(RCore *core, ut64 addr, int perm) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		RDebugMap *map;
		RListIter *iter;
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				if (perm > 0) {
					if (map->perm & perm) {
						return true;
					}
				} else {
					return true;
				}
			}
		}
		return false;
	}
	return r_io_map_is_mapped (core->io, addr);
}

static bool __syncDebugMaps(RCore *core) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		return r_debug_map_sync (core->dbg);
	}
	return false;
}

R_API char *r_core_cmd_call_str_at(RCore *core, ut64 addr, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (core && core->cons, NULL);
	r_cons_push (core->cons);
	core->cons->context->noflush = true;
	core->cons->context->cmd_str_depth++;
	if (cmd && r_core_cmd_call_at (core, addr, cmd) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		if (--core->cons->context->cmd_str_depth == 0) {
			core->cons->context->noflush = false;
			r_cons_flush (core->cons);
		}
		r_cons_pop (core->cons);
		return NULL;
	}
	if (--core->cons->context->cmd_str_depth == 0) {
		core->cons->context->noflush = false;
	}
	r_cons_filter (core->cons);
	const char *static_str = r_cons_get_buffer (core->cons, NULL);
	char *retstr = strdup (r_str_get (static_str));
	r_cons_pop (core->cons);
	r_cons_echo (core->cons, NULL);
	return retstr;
}

R_API void r_core_bind(RCore *core, RCoreBind *bnd) {
	R_RETURN_IF_FAIL (core && bnd);
	bnd->core = core;
	bnd->bpHit = (RCoreDebugBpHit)r_core_debug_breakpoint_hit;
	bnd->sysHit = (RCoreDebugSyscallHit)r_core_debug_syscall_hit;
	bnd->cmd = (RCoreCmd)r_core_cmd0;
	bnd->cmdf = (RCoreCmdF)r_core_cmdf;
	bnd->callAt = (RCoreCallAt)r_core_cmd_call_str_at;
	bnd->cmdStr = (RCoreCmdStr)r_core_cmd_str;
	bnd->cmdStrF = (RCoreCmdStrF)r_core_cmd_strf;
	bnd->help = (RCoreBindHelp)core_help;
	bnd->puts = (RCorePuts)r_cons_print;
	bnd->setArchBits = (RCoreSetArchBits)setab;
	bnd->getName = (RCoreGetName)getName;
	bnd->getNameDelta = (RCoreGetNameDelta)getNameDelta;
	bnd->archBits = (RCoreSeekArchBits)archbits;
	bnd->cfgGetB = (RCoreConfigGetB)cfggetb;
	bnd->cfgGetI = (RCoreConfigGetI)cfggeti;
	bnd->cfgGet = (RCoreConfigGet)cfgget;
	bnd->numGet = (RCoreNumGet)numget;
	bnd->isMapped = (RCoreIsMapped)__isMapped;
	bnd->syncDebugMaps = (RCoreDebugMapsSync)__syncDebugMaps;
	bnd->pjWithEncoding = (RCorePJWithEncoding)r_core_pj_new;
}

R_API RCore *r_core_ncast(ut64 p) {
	return (RCore*)(size_t)p;
}

R_API RCore *r_core_cast(void *p) {
	return (RCore*)p;
}

static const char *str_callback(RNum *user, ut64 off, bool *ok) {
	RFlag *f = (RFlag*)user;
	if (ok) {
		*ok = false;
	}
	if (f) {
		RFlagItem *item = r_flag_get_in (f, off);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

#include "numvars.inc.c"

R_API RCore *r_core_new(void) {
	RCore *c = R_NEW0 (RCore);
	r_core_init (c);
	return c;
}

#define radare_argc (sizeof (radare_argv) / sizeof (const char*) - 1)
#define ms_argc (sizeof (ms_argv) / sizeof (const char*) - 1)
static const char *ms_argv[] = {
	"?", "!", "ls", "cd", "cat", "get", "mount", "help", "q", "exit", NULL
};

static const char *radare_argv[] = {
	"whereis", "which", "ls", "rm", "mkdir", "pwd", "cat", "sort", "uniq", "join", "less", "exit", "quit",
	"#?", "#!", "#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5",
	"#!python", "#!vala", "#!pipe", "#!qjs", "#!tiny",
	"*?", "*", "$",
	"(", "(*", "(-", "()", ".?", ".", "..", "...", ".:", ".--", ".-", ".!", ".(", "./", ".*",
	"_?", "_",
	"=?", "=", "=<", "=!", "=+", "=-", "==", "=!=", "!=!", "=:", "=&:",
	"=g?", "=g", "=h?", "=h", "=h-", "=h--", "=h*", "=h&", "=H?", "=H", "=H&",
	"<",
	"/?", "/", "/j", "/j!", "/j!x", "/+", "//", "/a", "/a1", "/ab", "/ad", "/aa", "/as", "/asl", "/at", "/atl", "/af", "/afl", "/ae", "/aej", "/ai", "/aij",
	"/c", "/ca", "/car", "/d", "/e", "/E", "/Ej", "/f", "/F", "/g", "/gg", "/h", "/ht", "/i", "/m", "/mb", "/mm",
	"/o", "/O", "/p", "/P", "/s", "/s*", "/r?", "/r", "/ra", "/rc", "/re", "/rr", "/rw", "/rc",
	"/R",
	"/v?", "/v", "/v1", "/v2", "/v4", "/v8",
	"/V?", "/V", "/V1", "/V2", "/V4", "/V8",
	"/w", "/wi", "/x", "/z",
	"!?", "!", "!!", "!!!", "!!!-", "!-", "!-*", "!=!",
	"a?", "a", "aa", "aa*",
	"aaa", "aab", "aac", "aac*", "aad", "aae", "aaf", "aaF", "aaFa", "aai", "aaij", "aan", "aang", "aao", "aap",
	"aar?", "aar", "aar*", "aarj", "aas", "aat", "aaT", "aau", "aav",
	"a8", "ab", "abb",
	"acl", "acll", "aclj", "acl*", "ac?", "ac", "ac-", "acn", "acv", "acvf", "acv-", "acb", "acb-", "acm", "acm-", "acmn",
	"aC?", "aC", "aCe", "ad", "ad4", "ad8", "adf", "adfg", "adt", "adk",
	"ae?", "ae??", "ae", "aea", "aeA", "aeaf", "aeAf", "aeC", "aec?", "aec", "aecs", "aecc", "aecu", "aecue",
	"aef", "aefa",
	"aei", "aeim", "aeip", "aek", "aek-", "aeli", "aelir", "aep?", "aep", "aep-", "aepc",
	"aer", "aets?", "aets+", "aets-", "aes", "aesp", "aesb", "aeso", "aesou", "aess", "aesu", "aesue", "aetr", "aex",
	"af?", "af", "afr", "af+", "af-",
	"afa", "afan",
	"afb?", "afb", "afb.", "afb+", "afbb", "afbr", "afbi", "afbj", "afbe", "afB", "afbc", "afb=",
	"afB", "afC", "afCl", "afCc", "afc?", "afc", "afcr", "afcrj", "afca", "afcf", "afcfj",
	"afck", "afcl", "afco", "afcR",
	"afd", "aff", "afF", "afi",
	"afl?", "afl", "afl+", "aflc", "aflj", "afll", "afllj", "aflm", "aflq", "aflqj", "afls",
	"afm", "afM", "afn?", "afna", "afns", "afnsj", "afl=",
	"afo", "afs", "afS", "aft?", "aft", "afu",
	"afv?", "afv", "afvr?", "afvr", "afvr*", "afvrj", "afvr-", "afvrg", "afvrs",
	"afvb?", "afvb", "afvbj", "afvb-", "afvbg", "afvbs",
	"afvs?", "afvs", "afvs*", "afvsj", "afvs-", "afvsg", "afvss",
	"afv*", "afvR", "afvW", "afva", "afvd", "afvn", "afvt", "afv-", "af*", "afx",
	"aF",
	"ag?", "ag", "aga", "agA", "agc", "agC", "agd", "agf", "agi", "agr", "agR", "agx", "agg", "ag-",
	"agn?", "agn", "agn-", "age?", "age", "age-",
	"agl", "agfl",
	"ah?", "ah", "ah.", "ah-", "ah*", "aha", "ahb", "ahc", "ahe", "ahf", "ahh", "ahi?", "ahi", "ahj", "aho",
	"ahp", "ahr", "ahs", "ahS", "aht",
	"ai", "aL", "an",
	"ao?", "ao", "aoj", "aoe", "aor", "aos", "aom", "aod", "aoda", "aoc", "ao*",
	"aO", "ap",
	"ar?", "ar", "ar0", "ara?", "ara", "ara+", "ara-", "aras", "arA", "arC", "arr", "arrj", "ar=",
	"arb", "arc", "ard", "arn", "aro", "arp?", "arp", "arpi", "arpg", "arp.", "arpj", "arps",
	"ars", "art", "arw",
	"as?", "as", "asc", "asca", "asf", "asj", "asl", "ask",
	"av?", "av", "avj", "av*", "avr", "avra", "avraj", "avrr", "avrD",
	"at",
	"ax?", "ax", "ax*", "ax-", "ax-*", "axc", "axC", "axg", "axg*", "axgj", "axd", "axw", "axj", "axF",
	"axt", "axf", "ax.", "axff", "axffj", "axs",
	"b?", "b", "b+", "b-", "bf", "bm",
	"c?", "c", "c1", "c2", "c4", "c8", "cc", "ccd", "cf", "cg?", "cg", "cgf", "cgff", "cgfc", "cgfn", "cgo",
	"cu?", "cu", "cu1", "cu2", "cu4", "cu8", "cud",
	"cv", "cv1", "cv2", "cv4", "cv8",
	"cV", "cV1", "cV2", "cV4", "cV8",
	"cw?", "cw", "cw*", "cwr", "cwu",
	"cx", "cx*", "cX",
	"cl", "cls", "clear",
	"d?", "db ", "db-", "db-*", "db.", "dbj", "dbc", "dbC", "dbd", "dbe", "dbs", "dbf", "dbm", "dbn",
	"db?", "dbi", "dbi.", "dbix", "dbic", "dbie", "dbid", "dbis", "dbite", "dbitd", "dbits", "dbh", "dbh-",
	"dbt", "dbt*", "dbt=", "dbtv", "dbtj", "dbta", "dbte", "dbtd", "dbts", "dbx", "dbw",
	"dc?", "dc", "dca", "dcb", "dcc", "dccu", "dcf", "dck", "dcp", "dcr", "dcs", "dcs*", "dct", "dcu", "dcu.",
	"dd?", "dd", "dd-", "dd+", "dd*", "dds", "ddd", "ddr", "ddw",
	"de",
	"dg",
	"dH",
	"di?", "di", "di*", "diq", "dij",
	"dk?", "dk", "dko", "dkj",
	"dL?", "dL", "dLq", "dLj",
	"dm?", "dm", "dm=", "dm.", "dm*", "dm-", "dmd",
	"dmh?", "dmh", "dmha", "dmhb", "dmhbg", "dmhc", "dmhf", "dmhg", "dmhi", "dmhm", "dmht",
	"dmi?", "dmi", "dmi*", "dmi.", "dmiv",
	"dmj",
	"dml?", "dml",
	"dmm?", "dmm", "dmm*", "dmm.", "dmmj",
	"dmp?", "dmp",
	"dms?", "dms", "dmsj", "dms*", "dms-", "dmsA", "dmsC", "dmsd", "dmsw", "dmsa", "dmsf", "dmst",
	"dmS", "dmS*",
	"do?", "do", "dor", "doo",
	"dp?", "dp", "dpj", "dpl", "dplj", "dp-", "dp=", "dpa", "dpc", "dpc*", "dpe", "dpf", "dpk", "dpn", "dptn", "dpt",
	"dr?", "dr", "drps", "drpj", "drr", "drrj", "drs", "drs+", "drs-", "drt", "drt*", "drtj", "drw", "drx", "drx-",
	".dr*", ".dr-",
	"ds?", "ds", "dsb", "dsf", "dsi", "dsl", "dso", "dsp", "dss", "dsu", "dsui", "dsuo", "dsue", "dsuf",
	"dt?", "dt", "dt%", "dt*", "dt+", "dt-", "dt=", "dtD", "dta", "dtc", "dtd", "dte", "dte-*", "dtei", "dtek",
	"dtg", "dtg*", "dtgi",
	"dtr",
	"dts?", "dts", "dts+", "dts-", "dtsf", "dtst", "dtsC", "dtt",
	"dw",
	"dx?", "dx", "dxa", "dxe", "dxr", "dxs",
	"e?", "e", "e+", "-e", "-i", "e-", "e*", "e!", "ec", "ee?", "ee", "?ed", "ed", "ej", "env", "er", "es", "et", "ev", "evj",
	"ec?", "ec", "ec*", "ecd", "ecr", "ecs", "ecj", "ecc", "eco", "ecp", "ecn",
	"ecH?", "ecH", "ecHi", "ecHw", "ecH-",
	"f?", "f", "f.", "f*", "f-", "f--", "f+", "f=", "fa", "fb", "fc?", "fc", "fC", "fd", "fe-", "fe",
	"ff", "fi", "fg", "fj",
	"fl", "fla", "fm", "fn", "fnj", "fo", "fO", "fr", "fR", "fR?",
	"fs?", "fs", "fs*", "fsj", "fs-", "fs+", "fs-.", "fsq", "fsm", "fss", "fss*", "fssj", "fsr",
	"ft?", "ft", "ftn", "fV", "fx", "fq",
	"fz?", "fz", "fz-", "fz.", "fz:", "fz*",
	"g?", "g", "gw", "gc", "gl?", "gl", "gs", "gi", "gp", "ge", "gr", "gS",
	"help",
	"i?", "i", "ij", "iA", "ia", "ib", "ic", "icc", "iC",
	"id?", "id", "idp", "idpi", "idpi*", "idpd", "iD", "ie", "iee", "iE", "iE.",
	"ih", "iHH", "ii", "iI", "ik", "il", "iL", "im", "iM", "io", "iO?", "iO",
	"ir", "iR", "is", "is.", "iS", "iS.", "iS=", "iSS",
	"it", "iV", "iX", "iz", "izj", "izz", "izzz", "iz-", "iZ",
	"k?", "k", "ko", "kd", "ks", "kj",
	"l",
	"L?", "L", "L-", "Ll", "LL", "La", "Lc", "Ld", "Lh", "Li", "Lo",
	"m?", "m", "m*", "ml", "m-", "md", "mf?", "mf", "mg", "mo", "mi", "mp", "ms", "my",
	"o?", "o", "o-", "o--", "o+", "oe", "oa", "oa-", "oq", "oqq", "open", "o*", "o**", "o.", "o=",
	"ob?", "ob", "ob*", "obo", "oba", "obf", "obj", "obr", "ob-", "ob-*", "obi",
	"oc", "of", "oi", "oj", "oL", "om", "on",
	"oo?", "oo", "oo+", "oob", "ood", "oom", "oon", "oon+", "oonn", "oonn+",
	"op",  "opn", "opp", "opr", "ox",
	"p?", "p-", "p=", "p2", "p3", "p6?", "p6", "p6d", "p6e", "p8?", "p8", "p8f", "p8j",
	"pa?", "paD", "pad", "pade", "pae", "pA",
	"pb?", "pb", "pB", "pxb", "pB?",
	"pc?", "pc", "pc*", "pca", "pcA", "pcd", "pch", "pcj", "pcp", "pcs", "pcS", "pcw",
	"pC?", "pC", "pCa", "pCA", "pCc", "pCd", "pCD", "pCx", "pCw",
	"pd?", "pd", "pd--", "pD", "pda", "pdb", "pdc", "pdC", "pdf", "pdi", "pdj", "pdJ",
	"pdk", "pdl", "pdp", "pdr", "pdr.", "pdR", "pds?", "pds", "pdsb", "pdsf", "pdt",
	"pD",
	"pf?", "pf", "pf??", "pf???", "pf.", "pfj", "pfj.", "pf*", "pf*.", "pfc", "pfc.", "pfd", "pfd.",
	"pfo", "pfq", "pfv", "pfv.", "pfs", "pfs.",
	"pF?", "pF", "pFa", "pFaq", "pFo", "pFp", "pFx",
	"pg?", "pg", "pg*", "pg-*",
	"ph?", "ph", "ph=",
	"pi?", "pi", "pia", "pib", "pid", "pie", "pif?", "pif", "pifc", "pifcj", "pifj", "pij", "pir",
	"pI?", "pI", "pIa", "pIb", "pId", "pIe", "pIf?", "pIf", "pIfc", "pIfcj", "pIfj", "pIj",	"pIr",
	"pj?", "pj", "pj.", "pj..",
	"pk?", "pk", "pK?", "pK",
	"pm?", "pm",
	"pq?", "pq", "pqi", "pqz",
	"pr?", "pr", "prc", "prl", "prx", "prg?", "prg", "prgi", "prgo", "prz",
	"ps?", "ps", "psb", "psi", "psj", "psp", "pss", "psu", "psw", "psW", "psx", "psz", "ps+",
	"pt?", "pt", "pt.", "ptd", "pth", "ptn",
	"pu?", "pu", "puw", "pU",
	"pv?", "pv", "pv1", "pv2", "pv4", "pv8", "pvz", "pvj", "pvh", "pv1j", "pv2j", "pv4j", "pv8j",
	"pv1h", "pv2h", "pv4h", "pv8h",
	"px?", "px", "px/", "px0", "pxa", "pxA?", "pxA", "pxb", "pxc", "pxd?", "pxd", "pxd2", "pxd4", "pxd8",
	"pxe", "pxf", "pxh", "pxH", "pxi", "pxl", "pxo", "pxq", "pxq", "pxQ", "pxQq", "pxr", "pxrj",
	"pxs", "pxt", "pxt*", "pxt.", "pxw", "pxW", "pxWq", "pxx", "pxX",
	"pz?", "pz", "pzp", "pzf", "pzs", "pz0", "pzF", "pze", "pzh",
	"P?", "P", "Pc", "Pd", "Pi", "Pn", "Pnj", "Po", "Ps", "PS", "P-",
	"q?", "q", "q!", "q!!", "q!!!", "qy", "qn", "qyy", "qyn", "qny", "qnn",
	"r?", "r", "r-", "r+", "rh",
	"s?", "s", "s:", "s-", "s-*", "s--", "s+", "s++", "sj", "s*", "s=", "s!", "s/", "s/x", "s.", "sa", "sb",
	"sC?", "sC", "sC*",
	"sf", "sf.", "sg", "sG", "sl?", "sl", "sl+", "sl-", "slc", "sll", "sn", "sp", "so", "sr", "ss",
	"t?", "t", "tj", "t*", "t-", "t-*", "ta", "tb", "tc", "te?", "te", "tej", "teb", "tec",
	"td?", "td", "td-", "tf", "tk", "tl", "tn", "to", "tos", "tp", "tpx", "ts?", "ts", "tsj", "ts*", "tsc", "tss",
	"tu?", "tu", "tuj", "tu*", "tuc", "tt?", "tt", "ttj", "ttc",
	"T?", "T", "T*", "T-", "Tl", "Tj", "Tm", "Ts", "TT", "T=", "T=.", "T=&",
	"u?", "u", "uw", "us", "uc",
	"v", "v.", "V", "v!", "vv", "vV", "vVV", "VV",
	"w?", "w", "w1+", "w1-", "w2+", "w2-", "w4+", "w4-", "w8+", "w8-",
	"w0", "w", "w6", "w6d", "w6e", "wa", "wa*", "waf", "wao?", "wao",
	"wA?", "wA", "wB", "wB-", "wc", "wcj", "wc-", "wc+", "wc*", "wcr", "wci", "wcp", "wcp*", "wcpi",
	"wd", "we?", "we", "wen", "weN", "wes", "wex", "weX",
	"wf?", "wf", "wff", "wfs", "wF", "wh", "wm",
	"wo?", "wo", "wo2", "wo4", "woa", "woA", "wod", "woD", "woe", "woE", "wol", "wom", "woo",
	"wop?", "wop", "wopD", "wopD*", "wopO",
	"wp?", "wp", "wr", "ws",
	"wt?", "wt", "wta", "wtf", "wtf!", "wtff", "wts",
	"wu",
	"wv?", "wv", "wv1", "wv2",  "wv4", "wv8",
	"ww",
	"wx?", "wx", "wxf", "wxs",
	"wz",
	"x?", "x", "x/", "x0", "xa", "xA?", "xA", "xb", "xc", "xd?", "xd", "xd2", "xd4", "xd8",
	"xe", "xf", "xh", "xH", "xi", "xl", "xo", "xq", "xq", "xQ", "xQq", "xr", "xrj",
	"xs", "xt", "xt*", "xt.", "xw", "xW", "xWq", "xx", "xX",
	"y?", "y", "yz", "yp", "yx", "ys", "yt", "ytf", "yf", "yfa", "yfx", "yw", "ywx", "yy", "yr",
	"z?", "z", "z*", "zj", "z-", "z-*",
	"za?", "za??", "za", "zaf", "zaF", "zg",
	"zo?", "zo", "zoz", "zos",
	"zf?", "zfd", "zfs", "zfz",
	"z/?", "z/", "z/*",
	"zc",
	"zs?", "zs", "zs-", "zs-*", "zs+", "zsr",
	"zi",
	"?", "?v", "?$?", "?@?", "?>?",
	NULL
};

static void autocomplete_mount_point(RLineCompletion *completion, RCore *core, const char *path) {
	RFSRoot *r;
	RListIter *iter;
	r_list_foreach (core->fs->roots, iter, r) {
		char *base = strdup (r->path);
		char *ls = (char *) r_str_lchr (base, '/');
		if (ls) {
			ls++;
			*ls = 0;
		}
		if (!strcmp (path, base)) {
			r_line_completion_push (completion, r->path);
		}
		free (base);
	}
}

static void autocomplete_ms_path(RLineCompletion *completion, RCore *core, const char *str, const char *path) {
	R_RETURN_IF_FAIL (completion && core && str && path);
	char *dirname = NULL , *basename = NULL;
	char *pwd = strdup (core->rfs->cwd? (const char *)core->rfs->cwd: ".");
	int n = 0;
	RFSFile *file;
	char *lpath = strdup (path);
	char *p = (char *)r_str_last (lpath, R_SYS_DIR);
	if (p) {
		*p = 0;
		if (p == lpath) { // /xxx
			dirname  = strdup ("/");
		} else if (lpath[0] == '.') { // ./xxx/yyy
			dirname = r_str_newf ("%s%s", pwd, R_SYS_DIR);
		} else if (lpath[0] == '/') { // /xxx/yyy
			dirname = r_str_newf ("%s%s", lpath, R_SYS_DIR);
		} else { // xxx/yyy
			if (strlen (pwd) == 1) { // if pwd is root
				dirname = r_file_new ("", lpath, NULL);
			} else {
				dirname = r_file_new (pwd, lpath, NULL);
			}
		}
		basename = strdup (p + 1);
	} else { // xxx
		if (strlen (pwd) == 1) {
			dirname = r_str_newf ("%s", R_SYS_DIR);
		} else {
			dirname = r_str_newf ("%s%s", pwd, R_SYS_DIR);
		}
		basename = strdup (lpath);
	}
	R_FREE (pwd);

	if (!dirname || !basename) {
		goto out;
	}
	RList *list = r_fs_dir (core->fs, dirname);
	n = strlen (basename);
	bool chgdir = r_str_startswith (str, "cd ");
	if (list) {
		RListIter *iter;
		r_list_foreach (list, iter, file) {
			if (!file) {
				continue;
			}
			if (!basename[0] || !strncmp (file->name, basename, n))  {
				char *tmpstring = r_str_newf ("%s%s", dirname, file->name);
				if (r_file_is_directory (tmpstring)) {
					char *s = r_str_newf ("%s/", tmpstring);
					r_line_completion_push (completion, s);
					free (s);
				} else if (!chgdir) {
					r_line_completion_push (completion, tmpstring);
				}
				free (tmpstring);
			}
		}
		r_list_free (list);
	}
	autocomplete_mount_point (completion, core, path);
out:
	free (lpath);
	free (dirname);
	free (basename);
}

typedef struct {
	const char *needle;
	int needle_len;
	bool must_be_data;
	const char **valid_completions;
	const RCmdAliasVal **valid_completion_vals;
	int num_completions;
} AliasAutocompletions;

static bool check_alias_completion(void *in, const void *k, const void *v) {
	AliasAutocompletions *c = in;
	const char *needle = c->needle;
	const int needle_len = c->needle_len;
	const RCmdAliasVal *val = v;

	/* Skip command aliases if we're filtering them out */
	if (c->must_be_data && !val->is_data) {
		return true;
	}

	if (!needle_len || !strncmp (k, needle, needle_len)) {
		c->valid_completions[c->num_completions] = k;
		c->valid_completion_vals[c->num_completions] = v;
		c->num_completions++;
	}

	return true;
}

static void autocomplete_alias(RLineCompletion *completion, RCmd *cmd, const char *needle, bool must_be_data) {
	AliasAutocompletions c;
	const int needle_len = strlen (needle);
	int i;

	c.needle = needle;
	c.needle_len = needle_len;
	// Filter out command aliases?
	c.must_be_data = must_be_data;
	// Single block, borrowed pointers
	c.valid_completions = R_NEWS (const char *, cmd->aliases->count);
	c.valid_completion_vals = R_NEWS (const RCmdAliasVal *, cmd->aliases->count);
	c.num_completions = 0;

	ht_pp_foreach (cmd->aliases, check_alias_completion, &c);
	RCore *core = cmd->data;
	RCons *cons = core->cons;

	const int match_count = c.num_completions;
	if (match_count == 1) {
		/* If only 1 possible completion, use it */
		const char *k = c.valid_completions[0];
		const RCmdAliasVal *val = c.valid_completion_vals[0];

		char *v = r_cmd_alias_val_strdup ((RCmdAliasVal *)val);
		r_cons_printf (cons, "$%s=%s%s\n", k, val->is_data? "$": "", v);
		r_cons_flush (cons);

		char *completed_alias = r_str_newf ("$%s", k);
		r_line_completion_push (completion, completed_alias);

		free (completed_alias);
		free (v);
	} else if (match_count > 1) {
		/* If multiple possible completions, show them */
		for (i = 0; i < c.num_completions; i++) {
			const char *k = c.valid_completions[i];
			const RCmdAliasVal *val = c.valid_completion_vals[i];

			char *v = r_cmd_alias_val_strdup ((RCmdAliasVal *)val);
			char *line = r_str_newf ("$%s=%s%s", k, val->is_data? "$": "", v);
			r_line_completion_push (completion, line);

			free (line);
			free (v);
		}
	}
	/* If 0 possible completions, do nothing */
	free ((void*)c.valid_completions);
	free ((void*)c.valid_completion_vals);
}

static void autocomplete_process_path(RLineCompletion *completion, const char *str, const char *path) {
	char *lpath = NULL, *dirname = NULL , *basename = NULL;
	char *home = NULL, *filename = NULL, *p = NULL;
	int n = 0;
	bool is_pipe = false; // currently unused, might help complete without space after '>'

	if (!path) {
		goto out;
	}
#if 0
	if (path[0] == '>') {
		is_pipe = true;
		path++;
	}
#endif
	lpath = strdup (path);
#if R2__WINDOWS__
	r_str_replace_ch (lpath, '/', '\\', true);
#endif
	p = (char *)r_str_last (lpath, R_SYS_DIR);
	if (p) {
		*p = 0;
		if (p == lpath) { // /xxx
#if R2__WINDOWS__
			dirname = strdup ("\\.\\");
#else
			dirname = strdup (R_SYS_DIR);
#endif
		} else if (lpath[0] == '~' && lpath[1]) { // ~/xxx/yyy
			dirname = r_file_home (lpath + 2);
		} else if (lpath[0] == '~') { // ~/xxx
			if (!(home = r_file_home (NULL))) {
				goto out;
			}
			dirname = r_str_newf ("%s%s", home, R_SYS_DIR);
			free (home);
		} else if (lpath[0] == '.' || lpath[0] == R_SYS_DIR[0] ) { // ./xxx/yyy || /xxx/yyy
			dirname = r_str_newf ("%s%s", lpath, R_SYS_DIR);
		} else { // xxx/yyy
			char *fmt = ".%s%s%s";
#if R2__WINDOWS__
			if (strchr (path, ':')) {
				fmt = "%.0s%s%s";
			}
#endif
			dirname = r_str_newf (fmt, R_SYS_DIR, lpath, R_SYS_DIR);
		}
		basename = strdup (p + 1);
	} else { // xxx
		dirname = r_str_newf (".%s", R_SYS_DIR);
		basename = strdup (lpath);
	}

	if (!dirname || !basename) {
		goto out;
	}

	RList *list = r_sys_dir (dirname);
	n = strlen (basename);
	bool chgdir = !strncmp (str, "cd ", 3);
	if (list) {
		RListIter *iter;
		r_list_foreach (list, iter, filename) {
			if (*filename == '.') {
				continue;
			}
			if (!basename[0] || !strncmp (filename, basename, n)) {
				char *tmpstring = r_str_newf ("%s%s%s", is_pipe? ">": "",
						dirname, filename);

				if (r_file_is_directory (tmpstring)) {
					char *s = r_str_newf ("%s%s", tmpstring, R_SYS_DIR);
					r_line_completion_push (completion, s);
					free (s);
				} else if (!chgdir) {
					r_line_completion_push (completion, tmpstring);
				}
				free (tmpstring);
			}
		}
		r_list_free (list);
	}
out:
	free (lpath);
	free (dirname);
	free (basename);
}

static void autocomplete_filename(RLineCompletion *completion, RLineBuffer *buf, RCmd *cmd, char **extra_paths, int narg) {
	char *args = NULL, *input = NULL;
	int n = 0, i = 0;
	char *pipe = strchr (buf->data, '>');

	if (pipe) {
		args = strdup (pipe);
#if 0
		if (pipe[1] == ' ') {
			// currently unreachable
			narg++;
		}
#endif
	} else {
		args = strdup (buf->data);
	}

	if (!args) {
		goto out;
	}

	n = r_str_word_set0 (args);
	if (n < narg) {
		goto out;
	}

	input = strdup (r_str_word_get0 (args, narg));
	if (!input) {
		goto out;
	}
	const char *tinput = r_str_trim_head_ro (input);

	if (input[0] == '$') {
		// Only show existing data aliases
		autocomplete_alias (completion, cmd, input + 1, true);
		goto out;
	}

	autocomplete_process_path (completion, buf->data, tinput);

	if (input[0] == '/' || input[0] == '.' || !extra_paths) {
		goto out;
	}

	for (i = 0; extra_paths[i]; i ++) {
		char *s = r_str_newf ("%s%s%s", extra_paths[i], R_SYS_DIR, tinput);
		if (!s) {
			break;
		}
		autocomplete_process_path (completion, buf->data, s);
		free (s);
	}
out:
	free (args);
	free (input);
}

//TODO: make it recursive to handle nested struct
static int autocomplete_pfele(RCore *core, RLineCompletion *completion, char *key, char *pfx, int idx, char *ptr) {
	int i, ret = 0;
	int len = strlen (ptr);
	char* fmt = sdb_get (core->print->formats, key, NULL);
	if (fmt) {
		int nargs = r_str_word_set0_stack (fmt);
		if (nargs > 1) {
			for (i = 1; i < nargs; i++) {
				const char *arg = r_str_word_get0 (fmt, i);
				char *p = strchr (arg, '(');
				char *p2 = strchr (arg, ')');
				// remove '(' and ')' from fmt
				if (p && p2) {
					arg = p + 1;
					*p2 = '\0';
				}
				if (!len || !strncmp (ptr, arg, len)) {
					char *s = r_str_newf ("pf%s.%s.%s", pfx, key, arg);
					r_line_completion_push (completion, s);
					free (s);
				}
			}
		}
	}
	free (fmt);
	return ret;
}

#define ADDARG(x) if (!strncmp (buf->data+chr, x, strlen (buf->data+chr))) { r_line_completion_push (completion, x); }

static void autocomplete_default(RCore * R_NULLABLE core, RLineCompletion *completion, RLineBuffer *buf) {
	RCoreAutocomplete *a = core ? core->autocomplete : NULL;
	int i;
	if (a) {
		for (i = 0; i < a->n_subcmds; i++) {
			if (buf->data[0] == 0 || !strncmp (a->subcmds[i]->cmd, buf->data, a->subcmds[i]->length)) {
				r_line_completion_push (completion, a->subcmds[i]->cmd);
			}
		}
	} else {
		for (i = 0; i < radare_argc && radare_argv[i]; i++) {
			int length = strlen (radare_argv[i]);
			if (!strncmp (radare_argv[i], buf->data, length)) {
				r_line_completion_push (completion, radare_argv[i]);
			}
		}
	}
}

static void autocomplete_evals(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	RConfigNode *bt;
	RListIter *iter;
	const char *tmp = strrchr (str, ' ');
	if (tmp) {
		str = tmp + 1;
	}
	size_t n = strlen (str);
	r_list_foreach (core->config->nodes, iter, bt) {
		if (!strncmp (bt->name, str, n)) {
			r_line_completion_push (completion, bt->name);
		}
	}
}

static void autocomplete_project(RCore *core, RLineCompletion *completion, const char* str) {
	R_RETURN_IF_FAIL (str);
	char *foo, *projects_path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	RList *list = r_sys_dir (projects_path);
	RListIter *iter;
	int n = strlen (str);
	if (projects_path) {
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				if (!strncmp (foo, str, n)) {
					r_line_completion_push (completion, foo);
				}
			}
		}
		free (projects_path);
		r_list_free (list);
	}
}

static void autocomplete_minus(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	int length = strlen (str);
	int i;

	char **keys = (char **)r_cmd_alias_keys (core->rcmd);
	for (i = 0; i < core->rcmd->aliases->count; i++) {
		if (!strncmp (keys[i], str, length)) {
			r_line_completion_push (completion, keys[i]);
		}
	}

	free (keys);
}

static void autocomplete_breakpoints(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	RListIter *iter;
	RBreakpoint *bp = core->dbg->bp;
	RBreakpointItem *b;
	int n = strlen (str);
	r_list_foreach (bp->bps, iter, b) {
		char *addr = r_str_newf ("0x%"PFMT64x, b->addr);
		if (!strncmp (addr, str, n)) {
			r_line_completion_push (completion, addr);
		}
		free (addr);
	}
}

static bool add_argv(RFlagItem *fi, void *user) {
	RLineCompletion *completion = user;
	r_line_completion_push (completion, fi->name);
	return true;
}

static void autocomplete_flags(RCore *core, RLineCompletion *completion, const char* str) {
	R_RETURN_IF_FAIL (str);
	int n = strlen (str);
	r_flag_foreach_prefix (core->flags, str, n, add_argv, completion);
}

// TODO: Should be refactored
static void autocomplete_sdb(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (core && completion && str);
	char *pipe = strchr (str, '>');
	Sdb *sdb = core->sdb;
	char *lpath = NULL, *p1 = NULL, *out = NULL, *p2 = NULL;
	char *cur_pos = NULL, *cur_cmd = NULL, *next_cmd = NULL;
	char *temp_cmd = NULL, *temp_pos = NULL, *key = NULL;
	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	lpath = strdup (str);
	p1 = strchr (lpath, '/');
	if (p1) {
		*p1 = 0;
		char *ns = p1 + 1;
		p2 = strchr (ns, '/');
		if (!p2) { // anal/m
			char *tmp = p1 + 1;
			int n = strlen (tmp);
			out = sdb_querys (sdb, NULL, 0, "anal/**");
			if (!out) {
				return;
			}
			while (*out) {
				cur_pos = strchr (out, '\n');
				if (!cur_pos) {
					break;
				}
				cur_cmd = r_str_ndup (out, cur_pos - out);
				if (!strncmp (tmp, cur_cmd, n)) {
					char *cmplt = r_str_newf ("anal/%s/", cur_cmd);
					r_line_completion_push (completion, cmplt);
					free (cmplt);
				}
				out += cur_pos - out + 1;
			}

		} else { // anal/meta/*
			char *tmp = p2 + 1;
			int n = strlen (tmp);
			char *spltr = strchr (ns, '/');
			*spltr = 0;
			next_cmd = r_str_newf ("anal/%s/*", ns);
			out = sdb_querys (sdb, NULL, 0, next_cmd);
			if (!out) {
				free (lpath);
				return;
			}
			while (*out) {
				temp_pos = strchr (out, '\n');
				if (!temp_pos) {
					break;
				}
				temp_cmd = r_str_ndup (out, temp_pos - out); // contains the key=value pair
				key = strchr (temp_cmd, '=');
				*key = 0;
				if (!strncmp (tmp, temp_cmd, n)) {
					char *cmplt = r_str_newf ("anal/%s/%s", ns, temp_cmd);
					r_line_completion_push (completion, cmplt);
					free (cmplt);
				}
				out += temp_pos - out + 1;
			}
		}
	} else {
		int n = strlen (lpath);
		if (!strncmp (lpath, "anal", n)) {
			r_line_completion_push (completion, "anal/");
		}
	}
}

static void autocomplete_zignatures(RCore *core, RLineCompletion *completion, const char* msg) {
	R_RETURN_IF_FAIL (msg);
	int length = strlen (msg);
	RSpaces *zs = &core->anal->zign_spaces;
	RSpace *s;
	RSpaceIter *it;

	r_spaces_foreach (zs, it, s) {
		if (!strncmp (msg, s->name, length)) {
			r_line_completion_push (completion, s->name);
		}
	}

	if (strlen (msg) == 0) {
		r_line_completion_push (completion, "*");
	}
}

static void autocomplete_flagspaces(RCore *core, RLineCompletion *completion, const char* msg) {
	R_RETURN_IF_FAIL (msg);
	int length = strlen (msg);
	RFlag *flag = core->flags;
	RSpaceIter *it;
	RSpace *s;
	r_flag_space_foreach (flag, it, s) {
		if (!strncmp (msg, s->name, length)) {
			r_line_completion_push (completion, s->name);
		}
	}

	if (strlen (msg) == 0) {
		r_line_completion_push (completion, "*");
	}
}

static void autocomplete_functions(RCore *core, RLineCompletion *completion, const char* str) {
	R_RETURN_IF_FAIL (str);
	RListIter *iter;
	RAnalFunction *fcn;
	int n = strlen (str);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		char *name = r_core_anal_fcn_name (core, fcn);
		if (!strncmp (name, str, n)) {
			r_line_completion_push (completion, name);
		}
		free (name);
	}
}

static void autocomplete_vars(RCore *core, RLineCompletion *completion, const char* str) {
	R_RETURN_IF_FAIL (str);
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	if (!fcn) {
		return;
	}
	RListIter *iter;
	RAnalVar *var;
	size_t len = strlen (str);
	RList *vars = r_anal_var_all_list (core->anal, fcn);
	r_list_foreach (vars, iter, var) {
		if (!strncmp (var->name, str, len)) {
			r_line_completion_push (completion, var->name);
		}
	}
	r_list_free (vars);
}

static void autocomplete_macro(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (core && core->rcmd && completion && str);
	RCmdMacroItem *item;
	RListIter *iter;
	size_t n = strlen (str);
	r_list_foreach (core->rcmd->macro.macros, iter, item) {
		char *p = item->name;
		if (!*str || !strncmp (str, p, n)) {
			char *buf = r_str_newf ("%s%s)", str, p);
			if (buf) {
				r_line_completion_push (completion, buf);
				free (buf);
			}
		}
	}
}

static void autocomplete_file(RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (completion && str);
	char *pipe = strchr (str, '>');
	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	const char *arg = (str && !*str)? "./": str;
	autocomplete_process_path (completion, str, arg);
}

static void autocomplete_ms_file(RCore* core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	char *pipe = strchr (str, '>');
	char *path = strdup ((core->rfs->cwd && *core->rfs->cwd) ? (const char *)core->rfs->cwd: "/");
	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	const char *arg = (str && !*str)? path: str;
	autocomplete_ms_path (completion, core, str, arg);
	free (path);
}

static void autocomplete_charsets(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	int len = strlen (str);
	char *name;
	RListIter *iter;
	RList *chs = r_charset_list (core->print->charset);
	r_list_foreach (chs, iter, name) {
		if (!len || !strncmp (str, name, len)) {
			r_line_completion_push (completion, name);
		}
	}
	r_list_free (chs);
}

static void autocomplete_theme(RCore *core, RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (str);
	int len = strlen (str);
	char *theme;
	RListIter *iter;
	RList *themes = r_core_list_themes (core);
	r_list_foreach (themes, iter, theme) {
		if (!len || !strncmp (str, theme, len)) {
			r_line_completion_push (completion, theme);
		}
	}
	r_list_free (themes);
}

static bool find_e_opts(RCore *core, RLineCompletion *completion, RLineBuffer *buf) {
	// required to get the new list of items to autocomplete for cmd.pdc at least
	r_core_config_update (core);
	char *str = (char *)r_str_trim_head_ro (buf->data + 1);
	char *eq = strchr (str, '=');
	if (!eq) {
		return false;
	}
	*eq = 0;
	char *k = r_str_trim_dup (str);
	RConfigNode *node = r_config_node_get (core->config, k);
	free (k);
	*eq = '=';
	if (!node) {
		return false;
	}
	const char *p = r_str_trim_head_ro (eq + 1);
	int n = strlen (p);
	if (node->flags & 1) {
		if (!strncmp ("true", p, n)) {
			r_line_completion_push (completion, "true");
		}
		if (!strncmp ("false", p, n)) {
			r_line_completion_push (completion, "false");
		}
	} else {
		RListIter *iter;
		char *option;
		r_list_foreach (node->options, iter, option) {
			if (!strncmp (option, p, n)) {
				r_line_completion_push (completion, option);
			}
		}
	}
	completion->opt = true;
	return true;
}

static bool find_autocomplete(RCore *core, RLineCompletion *completion, RLineBuffer *buf) {
	RCoreAutocomplete* child = NULL;
	RCoreAutocomplete* parent = core->autocomplete;
	const char* p = buf->data;
	if (!*p) {
		return false;
	}
	char arg[256];
	arg[0] = 0;
	while (*p) {
		const char* e = r_str_trim_head_wp (p);
		if (!e || (e - p) >= 256 || e == p) {
			return false;
		}
		memcpy (arg, p, e - p);
		arg[e - p] = 0;
		child = r_core_autocomplete_find (parent, arg, false);
		if (child && child->length < buf->length && p[child->length] == ' ') {
			// if is spaced then i can provide the
			// next subtree as suggestion..
			p = r_str_trim_head_ro (p + child->length);
			if (child->type == R_CORE_AUTOCMPLT_OPTN) {
				continue;
			}
			parent = child;
		} else {
			break;
		}
	}
	int i;
	/* if something went wrong this will prevent bad behavior */
	r_line_completion_clear (completion);
	switch (parent->type) {
	case R_CORE_AUTOCMPLT_SEEK:
		autocomplete_functions (core, completion, p);
	case R_CORE_AUTOCMPLT_FLAG:
		autocomplete_flags (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FLSP:
		autocomplete_flagspaces (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FCN:
		autocomplete_functions (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_ZIGN:
		autocomplete_zignatures (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_EVAL:
		autocomplete_evals (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_PRJT:
		autocomplete_project (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MINS:
		autocomplete_minus (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_BRKP:
		autocomplete_breakpoints (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_VARS:
		autocomplete_vars (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MACR:
		autocomplete_macro (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MS:
		autocomplete_ms_file (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FILE:
		autocomplete_file (completion, p);
		break;
	case R_CORE_AUTOCMPLT_THME:
		autocomplete_theme (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_CHRS:
		autocomplete_charsets (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_SDB:
		autocomplete_sdb (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_OPTN:
		// handled before
		break;
	default:
		{
			size_t length = strlen (arg);
			for (i = 0; i < parent->n_subcmds; i++) {
				if (!strncmp (arg, parent->subcmds[i]->cmd, length)) {
					r_line_completion_push (completion, parent->subcmds[i]->cmd);
				}
			}
		}
		break;
	}
	return true;
}

static bool check_tabhelp_exceptions(const char *s) {
	if (r_str_startswith (s, "pf.")) {
		return true;
	}
	if (r_str_startswith (s, "pf*")) {
		return true;
	}
	if (r_str_startswith (s, "pfc.")) {
		return true;
	}
	if (r_str_startswith (s, "pfj.")) {
		return true;
	}
	return false;
}

R_API void r_core_autocomplete(RCore * R_NULLABLE core, RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type) {
	if (!core) {
		autocomplete_default (core, completion, buf);
		return;
	}
	const bool tabhelp_exception = check_tabhelp_exceptions (buf->data);
	if (!tabhelp_exception && r_config_get_b (core->config, "scr.prompt.tabhelp")) {
		if (buf->data[0] != '$' // handle aliases below
				&& strncmp (buf->data, "#!", 2) // rlang help fails
				&& !strchr (buf->data, ' ')) {
			r_line_completion_clear (completion);
			char *s = r_core_cmd_strf (core, "%s?", buf->data);
			if (!s) {
				return;
			}
			eprintf ("%s%s\n%s", core->cons->line->prompt, buf->data, s);
			r_str_ansi_filter (s, NULL, NULL, -1);
			r_str_trim (s);
			RList *list = r_str_split_list (s, "\n", 0);
			RListIter *iter;
			char *line;
			r_list_foreach (list, iter, line) {
				char *bracket_start = strstr (line, " [");
				if (bracket_start) {
					if (r_str_startswith (bracket_start, " [addr]") || r_str_startswith (bracket_start, " [file]")) {
						const char *registered_option = strstr (bracket_start, "addr") ? "'!!!%s $flag" : "'!!!%s $file";
						char *cur = strchr (line, '[');
						if (cur) {
							*cur = 0;
						}
						cur = strchr (line, '|');
						if (cur) {
							*cur = 0;
						}
						cur = strchr (line, '>');
						if (cur) {
							*cur = 0;
						}
						*bracket_start = 0;
						const char *cmd = line;
						r_core_cmdf (core, "'!!!-%s", cmd);
						r_core_cmdf (core, registered_option, cmd);
					}
				}
			}
			r_list_free (list);
			free (s);
			return;
		}
	}
	r_line_completion_clear (completion);
	char *pipe = strchr (buf->data, '>');
	char *ptr = strchr (buf->data, '@');
	char *eq = strchr (buf->data, '=');

	if (pipe) {
		/* XXX this doesn't handle filenames with spaces */
		// accept "> " and ">"
		char *pipe_space = pipe[1] == ' '
			? strchr (pipe + 2, ' ')
			: strchr (pipe, ' ');
		bool should_complete = buf->data + buf->index >= pipe;
		if (pipe_space) {
			should_complete &= buf->data + buf->index < pipe_space;
		}
		if (should_complete) {
			if (pipe[1] != ' ') {
				r_line_completion_push (completion, ">");
				return;
			}
			autocomplete_filename (completion, buf, core->rcmd, NULL, 1);
		}
	} else if (ptr) {
		char *ptr_space = ptr[1] == ' '
			? strchr (ptr + 2, ' ')
			: strchr (ptr, ' ');
		bool should_complete = buf->data + buf->index >= ptr;
		if (ptr_space) {
			should_complete &= buf->data + buf->index < ptr_space;
		}
		if (should_complete) {
			if (ptr[1] != ' ') {
				r_line_completion_push (completion, "@");
				return;
			}
			autocomplete_flags (core, completion, ptr+2);
		}
	} else if (r_str_startswith (buf->data, "#!pipe ")) {
		if (strchr (buf->data + 7, ' ')) {
			autocomplete_filename (completion, buf, core->rcmd, NULL, 2);
		} else {
			int chr = 7;
			ADDARG ("node");
			ADDARG ("vala");
			ADDARG ("ruby");
			ADDARG ("newlisp");
			ADDARG ("perl");
			ADDARG ("python");
		}
	} else if (r_str_startswith (buf->data, "f ") && eq) {
		// Enable address/math completion after "f name = <expr>"
		char *expr_start = eq + ((eq[1] == ' ')? 2: 1);
		char *expr_end = strchr (expr_start, ' ');
		bool should_complete = (buf->data + buf->index) >= eq;
		if (expr_end) {
			should_complete &= (buf->data + buf->index) <= expr_end;
		}
		if (should_complete) {
			if (eq[1] == ' ') {
				autocomplete_flags (core, completion, expr_start);
			}
		}
	} else if (r_str_startswith (buf->data, "ec ")) {
		if (strchr (buf->data + 3, ' ')) {
			autocomplete_filename (completion, buf, core->rcmd, NULL, 2);
		} else {
			int chr = 3;
			ADDARG ("comment");
			ADDARG ("usrcmt");
			ADDARG ("args");
			ADDARG ("fname");
			ADDARG ("floc");
			ADDARG ("fline");
			ADDARG ("flag");
			ADDARG ("label");
			ADDARG ("help");
			ADDARG ("flow");
			ADDARG ("prompt");
			ADDARG ("offset");
			ADDARG ("input");
			ADDARG ("invalid");
			ADDARG ("other");
			ADDARG ("b0x00");
			ADDARG ("b0x7f");
			ADDARG ("b0xff");
			ADDARG ("math");
			ADDARG ("bin");
			ADDARG ("btext");
			ADDARG ("push");
			ADDARG ("pop");
			ADDARG ("muta");
			ADDARG ("jmp");
			ADDARG ("cjmp");
			ADDARG ("call");
			ADDARG ("nop");
			ADDARG ("ret");
			ADDARG ("trap");
			ADDARG ("swi");
			ADDARG ("cmp");
			ADDARG ("reg");
			ADDARG ("creg");
			ADDARG ("num");
			ADDARG ("mov");
			ADDARG ("var");
			ADDARG ("var.type");
			ADDARG ("var.addr");
			ADDARG ("var.name");
			ADDARG ("widget.bg");
			ADDARG ("widget.sel");
			ADDARG ("ai.read");
			ADDARG ("ai.write");
			ADDARG ("ai.exec");
			ADDARG ("ai.seq");
			ADDARG ("ai.ascii");
			ADDARG ("ai.unmap");
			ADDARG ("graph.box");
			ADDARG ("graph.box2");
			ADDARG ("graph.box3");
			ADDARG ("graph.box4");
			ADDARG ("graph.true");
			ADDARG ("graph.false");
			ADDARG ("graph.trufae");
			ADDARG ("graph.current");
			ADDARG ("graph.traced");
			ADDARG ("gui.cflow");
			ADDARG ("gui.dataoffset");
			ADDARG ("gui.background");
			ADDARG ("gui.background2");
			ADDARG ("gui.border");
			ADDARG ("diff.unknown");
			ADDARG ("diff.new");
			ADDARG ("diff.match");
			ADDARG ("diff.unmatch");
		}
	} else if (r_str_startswith (buf->data, "pf.")
			|| r_str_startswith (buf->data, "pf*.")
			|| r_str_startswith (buf->data, "pfd.")
			|| r_str_startswith (buf->data, "pfc.")
			|| r_str_startswith (buf->data, "pfv.")
			|| r_str_startswith (buf->data, "pfj.")
		  ) {
		char pfx[2];
		int chr = (buf->data[2] == '.')? 3: 4;
		if (chr == 4) {
			pfx[0] = buf->data[2];
			pfx[1] = 0;
		} else {
			*pfx = 0;
		}
		SdbList *sls = sdb_foreach_list (core->print->formats, false);
		SdbListIter *iter;
		SdbKv *kv;
		ls_foreach (sls, iter, kv) {
			int len = strlen (buf->data + chr);
			int minlen = R_MIN (len,  strlen (sdbkv_key (kv)));
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), minlen)) {
				char *p = strchr (buf->data + chr, '.');
				if (p) {
					autocomplete_pfele (core, completion, sdbkv_key (kv), pfx, 0, p + 1);
					break;
				} else {
					char *s = r_str_newf ("pf%s.%s", pfx, sdbkv_key (kv));
					r_line_completion_push (completion, s);
					free (s);
				}
			}
		}
	} else if (!strncmp (buf->data, "t ", 2) || !strncmp (buf->data, "t- ", 3)) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = (buf->data[1] == ' ')? 2: 3;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), len)) {
				if (!strcmp (sdbkv_value (kv), "type")
						|| !strcmp (sdbkv_value (kv), "enum")
						|| !strcmp (sdbkv_value (kv), "struct")) {
					r_line_completion_push (completion, sdbkv_key (kv));
				}
			}
		}
		ls_free (l);
	} else if ((!strncmp (buf->data, "te ", 3))) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = 3;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), len)) {
				if (!strcmp (sdbkv_value (kv), "enum")) {
					r_line_completion_push (completion, sdbkv_key (kv));
				}
			}
		}
		ls_free (l);
	} else if (buf->data[0] == '$') {
		autocomplete_alias (completion, core->rcmd, buf->data + 1, false);
	} else if (!strncmp (buf->data, "ts ", 3)
			|| !strncmp (buf->data, "ta ", 3)
			|| !strncmp (buf->data, "tp ", 3)
			|| !strncmp (buf->data, "tl ", 3)
			|| !strncmp (buf->data, "tpx ", 4)
			|| !strncmp (buf->data, "tss ", 4)
			|| !strncmp (buf->data, "ts* ", 4)) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = (buf->data[2] == ' ')? 3: 4;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			const char *key = sdbkv_key (kv);
			if (!len || !strncmp (buf->data + chr, key, len)) {
				if (!strncmp (sdbkv_value (kv), "struct", strlen ("struct") + 1)) {
					r_line_completion_push (completion, key);
				}
			}
		}
		ls_free (l);
	} else if (r_str_startswith (buf->data, "zo ") || r_str_startswith (buf->data, "zoz ")) {
		if (core->anal->zign_path && core->anal->zign_path[0]) {
			char *zignpath = r_file_abspath (core->anal->zign_path);
			char *paths[2] = { zignpath, NULL };
			autocomplete_filename (completion, buf, core->rcmd, paths, 1);
			free (zignpath);
		} else {
			autocomplete_filename (completion, buf, core->rcmd, NULL, 1);
		}
	} else if (find_e_opts (core, completion, buf)) {
		return;
	} else if (prompt_type == R_LINE_PROMPT_OFFSET) {
		autocomplete_flags (core, completion, buf->data);
	} else if (prompt_type == R_LINE_PROMPT_FILE) {
		autocomplete_file (completion, buf->data);
	} else if (!find_autocomplete (core, completion, buf)) {
		autocomplete_default (core, completion, buf);
	}
}

static int autocomplete(RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type, void *user) {
	RCore *core = (RCore *)user;
	if (core == NULL) {
		R_LOG_WARN ("core->cons->line->user is nul, but should be equals to core");
	}
	r_core_autocomplete (core, completion, buf, prompt_type);
	return true;
}

R_API int r_core_fgets(RCons *cons, char *buf, int len) {
	R_RETURN_VAL_IF_FAIL (buf, -1);
	RLine *rli = cons->line;
#if R2_590
	cons->maxlength = len; /// R2_590
#endif
	bool prompt = cons->context->is_interactive;
	buf[0] = '\0';
	if (prompt) {
		r_line_completion_set (&rli->completion, radare_argc, radare_argv);
		rli->completion.run = autocomplete;
		rli->completion.run_user = rli->user;
	} else {
		r_line_hist_free (cons->line);
		r_line_completion_set (&rli->completion, 0, NULL);
		rli->completion.run = NULL;
		rli->completion.run_user = NULL;
	}
	const char *ptr = r_line_readline (cons);
	if (!ptr) {
		return -1;
	}
	if (cons->line->buffer.length >= len - 2) {
		R_LOG_ERROR ("input is too large");
		*buf = 0;
		return 0;
	}
	return r_str_ncpy (buf, ptr, len - 1);
}

static const char *r_core_print_offname(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_in (c->flags, addr);
	return item ? item->name : NULL;
}

static int r_core_print_offsize(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_in (c->flags, addr);
	return item ? item->size: -1;
}

/**
 * Disassemble one instruction at specified address.
 */
static int __disasm(void *_core, ut64 addr) {
	RCore *core = _core;
	ut64 prevaddr = core->addr;

	r_core_seek (core, addr, true);
	int len = r_core_print_disasm_instructions (core, 0, 1);
	r_core_seek (core, prevaddr, true);

	return len;
}

static void update_sdb(RCore *core) {
	Sdb *d;
	RBinObject *o;
	if (!core) {
		return;
	}
	//SDB// anal/
	if (core->anal && core->anal->sdb) {
		sdb_ns_set (DB, "anal", core->anal->sdb);
	}
	//SDB// bin/
	if (core->bin && core->bin->sdb) {
		sdb_ns_set (DB, "bin", core->bin->sdb);
	}
	//SDB// bin/info
	o = r_bin_cur_object (core->bin);
	if (o) {
		sdb_ns_set (sdb_ns (DB, "bin", 1), "info", o->kv);
	}
	//sdb_ns_set (core->sdb, "flags", core->flags->sdb);
	//sdb_ns_set (core->sdb, "bin", core->bin->sdb);
	//SDB// syscall/
	if (core->rasm && core->rasm->syscall && core->rasm->syscall->db) {
		core->rasm->syscall->db->refs++;
		sdb_ns_set (DB, "syscall", core->rasm->syscall->db);
	}
	d = sdb_ns (DB, "debug", 1);
	if (core->dbg->sgnls) {
		core->dbg->sgnls->refs++;
		sdb_ns_set (d, "signals", core->dbg->sgnls);
	}
}

static void init_cmd_suggestions(RCore *core) {
	if (!core || !core->sdb) {
		return;
	}
	// Fallback commands with ?e (safe echo) for missing plugin commands
	// Using fallbackcmd.* prefix to distinguish from regular SDB entries
	sdb_set (core->sdb, "fallbackcmd.pdd", "?e You need to install the plugin with r2pm -ci r2dec", 0);
	sdb_set (core->sdb, "fallbackcmd.pdg", "?e You need to install the plugin with r2pm -ci r2ghidra", 0);
	sdb_set (core->sdb, "fallbackcmd.pd:g", "?e You need to install the plugin with r2pm -ci r2ghidra", 0);
	sdb_set (core->sdb, "fallbackcmd.pdz", "?e You need to install the plugin with r2pm -ci r2retdec", 0);
	sdb_set (core->sdb, "fallbackcmd.pdv", "?e You need to install the plugin with r2pm -ci east", 0);

	// Suggestions for common user-facing command names (redirect to actual commands)
	sdb_set (core->sdb, "fallbackcmd.r2dec", "?e You are probably looking for the pdd command", 0);
	sdb_set (core->sdb, "fallbackcmd.r2ghidra", "?e You are probably looking for the pdg command", 0);

	// Users can add custom fallback commands at runtime using:
	// k fallbackcmd.mycommand=?e Use 'othercommand' instead
}

#define MINLEN 1
static int is_string(const ut8 *buf, int size, int *len) {
	int i;
	if (size < 1) {
		return 0;
	}
	if (size > 3 && buf[0] && !buf[1] && buf[2] && !buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i = 0; i < size; i++) {
		if (!buf[i] && i > MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i] == 10|| buf[i] == 13|| buf[i] == 9) {
			continue;
		}
		if (buf[i] < 32 || buf[i] > 127) {
			// not ascii text
			return 0;
		}
		if (!IS_PRINTABLE (buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

R_API char *r_core_anal_hasrefs(RCore *core, ut64 value, int mode) {
	if (mode) {
		PJ *pj = (mode == 'j')? pj_new (): NULL;
		const int hex_depth = 1; // r_config_get_i (core->config, "hex.depth");
		char *res = r_core_anal_hasrefs_to_depth (core, value, pj, hex_depth);
		if (pj) {
			free (res);
			return pj_drain (pj);
		}
		return res;
	}
	RFlagItem *fi = r_flag_get_in (core->flags, value);
	return fi? strdup (fi->name): NULL;
}

static char *getvalue(ut64 value, int bits) {
	switch (bits) {
	case 16: // umf, not in sync with pxr
		{
			st16 v = (st16)(value & UT16_MAX);
			st16 h = UT16_MAX / 0x100;
			if (v > -h && v < h) {
				return r_str_newf ("%hd", v);
			}
		}
		break;
	case 32:
		{
			st32 v = (st32)(value & UT32_MAX);
			st32 h = UT32_MAX / 0x10000;
			if (v > -h && v < h) {
				return r_str_newf ("%d", v);
			}
		}
		break;
	case 64:
		{
			st64 v = (st64)(value);
			st64 h = UT64_MAX / 0x1000000;
			if (v > -h && v < h) {
				return r_str_newf ("%"PFMT64d, v);
			}
		}
		break;
	}
	return NULL;
}

/*
 pxr logic is dupplicated in other places
 * ai, ad
 * no json support
*/
R_API char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, PJ *pj, int depth) {
	const int bits = core->rasm->config->bits;
	R_RETURN_VAL_IF_FAIL (core, NULL);
	RStrBuf *s = r_strbuf_new (NULL);
	if (pj) {
		pj_o (pj);
		pj_kn (pj, "addr", value);
	}
	if (depth < 1 || value == UT64_MAX) {
		if (pj) {
			pj_end (pj);
		}
		return NULL;
	}

	char *val = getvalue (value, bits);
	if (val) {
		if (pj) {
			pj_ks (pj, "value", val);
		} else {
			r_strbuf_appendf (s, "%s ", val);
		}
		R_FREE (val);
	}

	if (value && value != UT64_MAX) {
		RDebugMap *map = r_debug_map_get (core->dbg, value);
		if (map && map->name && map->name[0]) {
			if (pj) {
				pj_ks (pj, "map", map->name);
			} else {
				r_strbuf_appendf (s, "%s ", map->name);
			}
		}
	}
	ut64 type = r_core_anal_address (core, value);
	RBinObject *bo = r_bin_cur_object (core->bin);
	RBinSection *sect = (bo && value)? r_bin_get_section_at (bo, value, true): NULL;
	if ((int)value < 0 && ((int)value > -0xffff)) {
		ut64 dst = core->addr + (st32)value;
		if (r_io_is_valid_offset (core->io, dst, false)) {
			r_strbuf_appendf (s, " rptr(%d)=0x%08"PFMT64x" ", (int)value, dst);
			value = dst;
		}
	}
	if (! ((type & R_ANAL_ADDR_TYPE_HEAP) || (type & R_ANAL_ADDR_TYPE_STACK)) ) {
		// Do not repeat "stack" or "heap" words unnecessarily.
		if (sect && sect->name[0]) {
			if (pj) {
				pj_ks (pj, "section", sect->name);
			} else {
				r_strbuf_appendf (s, "%s ", sect->name);
			}
		}
	}
	if (value != 0 && value != UT64_MAX) {
		if (pj) {
			RListIter *iter;
			RFlagItem *f;
			const RList *flags = r_flag_get_list (core->flags, value);
			if (flags && !r_list_empty (flags)) {
				pj_ka (pj, "flags");
				r_list_foreach (flags, iter, f) {
					pj_s (pj, f->name);
				}
				pj_end (pj);
			}
		} else {
			char *flags = r_flag_get_liststr (core->flags, value);
			if (flags) {
				r_strbuf_appendf (s, "%s ", flags);
				free (flags);
			}
		}
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, value, 0);
	if (fcn) {
		if (pj) {
			pj_ks (pj, "fcn", fcn->name);
		} else {
			r_strbuf_appendf (s, "%s ", fcn->name);
		}
	}
	if (type) {
		const char *c = r_core_anal_optype_colorfor (core, fcn? fcn->addr: value, value, true);
		const char *cend = (R_STR_ISNOTEMPTY (c)) ? Color_RESET: "";
		if (!c) {
			c = "";
		}
		if (pj) {
			pj_ka (pj, "attr");
		}
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			if (pj) {
				pj_s (pj, "heap");
			} else {
				r_strbuf_appendf (s, "%sheap%s ", c, cend);
			}
		} else if (type & R_ANAL_ADDR_TYPE_STACK) {
			if (pj) {
				pj_s (pj, "stack");
			} else {
				r_strbuf_appendf (s, "%sstack%s ", c, cend);
			}
		}
		if (type & R_ANAL_ADDR_TYPE_PROGRAM) {
			if (pj) {
				pj_s (pj, "program");
			} else {
				r_strbuf_appendf (s, "%sprogram%s ", c, cend);
			}
		}
		if (type & R_ANAL_ADDR_TYPE_LIBRARY) {
			if (pj) {
				pj_s (pj, "library");
			} else {
				r_strbuf_appendf (s, "%slibrary%s ", c, cend);
			}
		}
		if (type & R_ANAL_ADDR_TYPE_ASCII) {
			if (pj) {
				pj_s (pj, "ascii");
			} else {
				r_strbuf_appendf (s, "%sascii%s ('%c') ", c, cend, (char)value);
			}
		}
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
			if (pj) {
				pj_s (pj, "sequence");
			} else {
				r_strbuf_appendf (s, "%ssequence%s ", c, cend);
			}
		}
		if (pj) {
			if (type & R_ANAL_ADDR_TYPE_READ) {
				pj_s (pj, "R");
			}
			if (type & R_ANAL_ADDR_TYPE_WRITE) {
				pj_s (pj, "W");
			}
			if (type & R_ANAL_ADDR_TYPE_EXEC) {
				pj_s (pj, "X");
			}
		} else {
			if (type & R_ANAL_ADDR_TYPE_READ) {
				r_strbuf_appendf (s, "%sR%s ", c, cend);
			}
			if (type & R_ANAL_ADDR_TYPE_WRITE) {
				r_strbuf_appendf (s, "%sW%s ", c, cend);
			}
			if (type & R_ANAL_ADDR_TYPE_EXEC) {
				RAnalOp op;
				ut8 buf[32];
				r_strbuf_appendf (s, "%sX%s ", c, cend);
				/* instruction disassembly */
				r_io_read_at (core->io, value, buf, sizeof (buf));
				r_asm_set_pc (core->rasm, value);
				r_asm_disassemble (core->rasm, &op, buf, sizeof (buf));
				r_strbuf_appendf (s, "'%s' ", op.mnemonic);
				r_anal_op_fini (&op);
				/* get library name */
				{ // NOTE: dup for mapname?
					RDebugMap *map;
					RListIter *iter;
					r_list_foreach (core->dbg->maps, iter, map) {
						if ((value >= map->addr) &&
							(value<map->addr_end)) {
							const char *lastslash = r_str_lchr (map->name, '/');
							r_strbuf_appendf (s, "'%s' ", lastslash?
								lastslash + 1: map->name);
							break;
						}
					}
				}
			} else if (type & R_ANAL_ADDR_TYPE_READ) {
				ut8 buf[32];
				ut32 *n32 = (ut32 *)buf;
				ut64 *n64 = (ut64*)buf;
				if (r_io_read_at (core->io, value, buf, sizeof (buf))) {
					ut64 n = (bits == 64)? *n64: *n32;
					r_strbuf_appendf (s, "0x%"PFMT64x" ", n);
				}
			}
		}
		if (pj) {
			pj_end (pj);
		}
	}
	{
		ut8 buf[128], widebuf[256];
		const char *c = r_config_get_i (core->config, "scr.color")? core->cons->context->pal.ai_ascii: "";
		const char *cend = (c && *c) ? Color_RESET: "";
		int len, r;
		if (r_io_read_at (core->io, value, buf, sizeof (buf))) {
			buf[sizeof (buf) - 1] = 0;
			switch (is_string (buf, sizeof (buf), &len)) {
			case 1:
				if (pj) {
					pj_ks (pj, "string", (const char *)buf);
				} else {
					r_strbuf_appendf (s, "%s%s%s ", c, buf, cend);
				}
				break;
			case 2:
				r = r_utf8_encode_str ((const RRune *)buf, widebuf, sizeof (widebuf) - 1);
				if (r == -1) {
					R_LOG_ERROR ("Something was wrong with refs");
				} else {
					if (pj) {
						pj_ks (pj, "string", (const char *)widebuf);
					} else {
						r_strbuf_appendf (s, "%s%s%s ", c, widebuf, cend);
					}
				}
				break;
			}
		}
	}
	if ((type & R_ANAL_ADDR_TYPE_READ) && !(type & R_ANAL_ADDR_TYPE_EXEC) && depth) {
		// Try to telescope further, but only several levels deep.
		ut8 buf[32];
		ut32 *n32 = (ut32 *)buf;
		ut64 *n64 = (ut64*)buf;
		if (r_io_read_at (core->io, value, buf, sizeof (buf))) {
			ut64 n = (bits == 64)? *n64: *n32;
			if (n != value) {
				if (pj) {
					pj_k (pj, "ref");
				}
				char* rrstr = r_core_anal_hasrefs_to_depth (core, n, pj, depth - 1);
				if (rrstr) {
					if (!pj && rrstr[0]) {
						r_strbuf_appendf (s, " -> %s", rrstr);
					}
					free (rrstr);
				}
			}
		}
	}
	if (pj) {
		pj_end (pj);
	}
	char *res = r_strbuf_drain (s);
	r_str_trim_tail (res);
	return res;
}

// XXX must be deprecated
static R_TH_LOCAL char *const_color = NULL;

R_API const char *colorforop(RCore *core, ut64 addr) {
	RList *fcns = r_anal_get_functions_in (core->anal, addr);
	if (r_list_empty (fcns)) {
		r_list_free (fcns);
		return NULL;
	}
	RAnalFunction *fcn = r_list_pop (fcns);
	r_list_free (fcns);
	if (!fcn) {
		return NULL;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr >= bb->addr && addr < (bb->addr + bb->size)) {
			ut64 opat = r_anal_bb_opaddr_at (bb, addr);
			RAnalOp *op = r_core_anal_op (core, opat, 0);
			if (op) {
				const char* res = r_print_color_op_type (core->print, op->type);
				r_anal_op_free (op);
				return res;
			}
			break;
		}
	}
	return NULL;
}

R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr, ut8 ch, bool verbose) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	if (!(core->print->flags & R_PRINT_FLAGS_COLOR)) {
		return NULL;
	}
	if (!verbose && (core->print->flags & R_PRINT_FLAGS_COLOROP)) {
		// if function in place check optype for given offset
		return colorforop (core, addr);
	}
	if (r_config_get_i (core->config, "scr.color") == 0) {
		return NULL;
	}
	if (!verbose) {
		// check for flag colors
		RFlagItem *fi = r_flag_get_at (core->flags, addr, true);
		if (fi && fi->addr + fi->size >= addr) {
			const char *ficolor = r_flag_item_set_color (core->flags, fi, NULL);
			if (ficolor) {
				free (const_color);
				const_color = r_cons_pal_parse (core->cons, ficolor, NULL);
				return const_color;
			}
		}
		return NULL;
	}
	ut64 type = r_core_anal_address (core, addr);
	if (type & R_ANAL_ADDR_TYPE_EXEC) {
		return core->cons->context->pal.ai_exec; //Color_RED;
	}
	if (type & R_ANAL_ADDR_TYPE_WRITE) {
		return core->cons->context->pal.ai_write; //Color_BLUE;
	}
	if (type & R_ANAL_ADDR_TYPE_READ) {
		return core->cons->context->pal.ai_read; //Color_GREEN;
	}
	if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
		return core->cons->context->pal.ai_seq; //Color_MAGENTA;
	}
	if (type & R_ANAL_ADDR_TYPE_ASCII) {
		return core->cons->context->pal.ai_ascii; //Color_YELLOW;
	}
	return NULL;
}

static void r_core_setenv(RCore *core) {
	char *e = r_sys_getenv ("PATH");
	char *h = r_xdg_datadir ("prefix/bin"); // support \\ on windows :?
	char *n = r_str_newf ("%s%s%s", h, R_SYS_ENVSEP, e);
	r_sys_setenv ("PATH", n);
	r_strf_var (coreptr, 64, "%p", core);
	r_sys_setenv ("R2CORE", coreptr);
	free (n);
	free (h);
	free (e);
}

static bool exists_var(RPrint *print, ut64 func_addr, char *str) {
	RAnal *anal = ((RCore*)(print->user))->anal;
	RAnalFunction *fcn = r_anal_get_function_at (anal, func_addr);
	if (fcn) {
		return !!r_anal_function_get_var_byname (fcn, str);
	}
	return false;
}

static bool r_core_anal_log(struct r_anal_t *anal, const char *msg) {
	RCore *core = anal->user;
	if (core->cfglog) {
		r_core_log_add (core, msg);
	}
	return true;
}

static bool r_core_anal_read_at(struct r_anal_t *anal, ut64 addr, ut8 *buf, int len) {
	return r_io_read_at (anal->iob.io, addr, buf, len);
}

static void *r_core_sleep_begin(RCore *core) {
	R_CRITICAL_ENTER (core);
	RCoreTask *task = r_core_task_self (&core->tasks);
	if (task) {
		r_core_task_sleep_begin (task);
	}
	R_CRITICAL_LEAVE (core);
	return task;
}

static void r_core_sleep_end(RCore *core, void *user) {
	R_CRITICAL_ENTER (core);
	RCoreTask *task = (RCoreTask *)user;
	if (task) {
		r_core_task_sleep_end (task);
	}
	R_CRITICAL_LEAVE (core);
}

static void __foreach(RCore *core, const char **cmds, int type) {
	int i;
	for (i = 0; cmds[i]; i++) {
		r_core_autocomplete_add (core->autocomplete, cmds[i], type, true);
	}
}

static void __init_autocomplete_default(RCore* core) {
	// TODO: if we sort those strings alphabetically we can probably break earlier
	const char *fcns[] = {
		"afi", "afcf", "afn", "afm", NULL
	};
	const char *seeks[] = {
		"s", NULL
	};
	const char *flags[] = {
		"*", "s", "s+", "b", "f", "fg", "?", "?v", "ad", "bf", "c1", "db", "dbw",
		"f-", "fr", "tf", "/a", "/v", "/r", "/re", "aav", "aep", "aef", "afb", "o=",
		"afc", "axg", "axt", "axf", "dcu", "ag", "agfl", "aecu", "aesu", "aeim", "abp", NULL
	};
	const char *evals[] = {
		"-e", "e", "e+", "ee", "et", "e?", "e!", "ev", "evj", NULL
	};
	const char *breaks[] = {
		"db-", "dbc", "dbC", "dbd", "dbe", "dbs", "dbi", "dbte", "dbtd", "dbts", NULL
	};
	const char *files[] = {
		".", "..", ".*", "/F", "/m", "!", "!!", "#!c", "#!v", "#!cpipe", "#!qjs", "#!tiny", "#!vala", "v.",
		"#!rust", "#!zig", "#!pipe", "#!python", "aeli", "arp", "arpg", "dmd", "drp", "drpg", "oe", "ot", "o+", "o++", "on", "open",
		"idp", "idpi", "L", "obf", "o+", "o", "oc", "of", "r2", "rabin2", "rasm2", "rahash2", "rax2", "wff",
		"rafind2", "cd", "ls", "lua", "on", "wf", "rm", "wF", "wp", "Sd", "Sl", "to", "pm",
		"/m", "zos", "zfd", "zfs", "zfz", "cat", "wta", "wtf", "wxf", "dml", "dd", "dd+",
		"vi", "vim", "nvi", "neovim", "nvim", "nano", "-i", "yr",
#if R2__WINDOWS__
		"notepad",
#endif
		"less", "head", "tail", NULL
	};
	const char *vars[] = {
		"afvn", "afan", NULL
	};
	const char *projs[] = {
		"Pc", "Pd", "Pi", "Po", "Ps", "P-", NULL
	};
	const char *mounts[] = {
		"m", "md", "mg", "mo", "ms", "mc", "mi", "mw", NULL
	};
	__foreach (core, files, R_CORE_AUTOCMPLT_FILE);
	__foreach (core, flags, R_CORE_AUTOCMPLT_FLAG);
	__foreach (core, seeks, R_CORE_AUTOCMPLT_SEEK);
	__foreach (core, fcns, R_CORE_AUTOCMPLT_FCN);
	__foreach (core, evals, R_CORE_AUTOCMPLT_EVAL);
	__foreach (core, vars, R_CORE_AUTOCMPLT_VARS);
	__foreach (core, breaks, R_CORE_AUTOCMPLT_BRKP);
	__foreach (core, projs, R_CORE_AUTOCMPLT_PRJT);
	__foreach (core, mounts, R_CORE_AUTOCMPLT_MS);

	r_core_autocomplete_add (core->autocomplete, "-", R_CORE_AUTOCMPLT_MINS, true);
	r_core_autocomplete_add (core->autocomplete, "zs", R_CORE_AUTOCMPLT_ZIGN, true);
	r_core_autocomplete_add (core->autocomplete, "fs", R_CORE_AUTOCMPLT_FLSP, true);
	r_core_autocomplete_add (
		r_core_autocomplete_add (core->autocomplete, "ls", R_CORE_AUTOCMPLT_DFLT, true),
		"-l", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "eco", R_CORE_AUTOCMPLT_THME, true);
	r_core_autocomplete_add (core->autocomplete, "k", R_CORE_AUTOCMPLT_SDB, true);
	/* macros */
	r_core_autocomplete_add (core->autocomplete, ".(", R_CORE_AUTOCMPLT_MACR, true);
	r_core_autocomplete_add (core->autocomplete, "(-", R_CORE_AUTOCMPLT_MACR, true);
	/* just for hints */
	int i;
	for (i = 0; i < radare_argc && radare_argv[i]; i++) {
		if (!r_core_autocomplete_find (core->autocomplete, radare_argv[i], true)) {
			r_core_autocomplete_add (core->autocomplete, radare_argv[i], R_CORE_AUTOCMPLT_DFLT, true);
		}
	}
}

static void __init_autocomplete(RCore* core) {
	int i;
	core->autocomplete = R_NEW0 (RCoreAutocomplete);
	if (core->autocomplete_type == AUTOCOMPLETE_DEFAULT) {
		__init_autocomplete_default (core);
	} else if (core->autocomplete_type == AUTOCOMPLETE_MS) {
		r_core_autocomplete_add (core->autocomplete, "ls", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "cd", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "cat", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "get", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "mount", R_CORE_AUTOCMPLT_MS, true);
		for (i = 0; i < ms_argc && ms_argv[i]; i++) {
			if (!r_core_autocomplete_find (core->autocomplete, ms_argv[i], true)) {
				r_core_autocomplete_add (core->autocomplete, ms_argv[i], R_CORE_AUTOCMPLT_MS, true);
			}
		}
	}
}

static const char *colorfor_cb(void *user, ut64 addr, ut8 ch, bool verbose) {
	return r_core_anal_optype_colorfor ((RCore *)user, addr, ch, verbose);
}

static char *hasrefs_cb(void *user, ut64 addr, int mode) {
	RCore *core = (RCore *)user;
	if (mode) {
		return r_core_anal_hasrefs ((RCore *)user, addr, mode);
	}
	core->addr = addr;
	char *res = r_core_anal_hasrefs ((RCore *)user, addr, mode);
	if (R_STR_ISEMPTY (res)) {
		free (res);
		addr &= 0xffffffffffffULL;
		res = r_core_anal_hasrefs ((RCore *)user, addr, mode);
	}
	return res;
}

static const char *get_section_name(void *user, ut64 addr) {
	return r_core_get_section_name ((RCore *)user, addr);
}

static char *get_comments_cb(void *user, ut64 addr) {
	return r_core_anal_get_comments ((RCore *)user, addr);
}

static void cb_event_handler(REvent *ev, int event_type, void *user, void *data) {
	RCore *core = (RCore *)ev->user;
	if (!core->log_events) {
		return;
	}
	REventMeta *rems = data;
	r_strf_buffer (64);
	char *pstr;
	char *str = r_base64_encode_dyn ((const ut8*)rems->string, -1);
	switch (event_type) {
	case R_EVENT_META_SET:
		if (rems->type == 'C') {
			pstr = r_str_newf (":add-comment 0x%08"PFMT64x" %s\n", rems->addr, r_str_get (str));
			r_core_log_add (ev->user, pstr);
			free (pstr);
		}
		break;
	case R_EVENT_META_DEL:
		if (rems->type == 'C') {
			r_core_log_add (ev->user, r_strf (":del-comment 0x%08"PFMT64x, rems->addr));
		} else {
			r_core_log_add (ev->user, r_strf (":del-comment 0x%08"PFMT64x, rems->addr));
		}
		break;
	case R_EVENT_META_CLEAR:
		switch (rems->type) {
		case 'C':
			r_core_log_add (ev->user, r_strf (":clear-comments 0x%08"PFMT64x, rems->addr));
			break;
		default:
			r_core_log_add (ev->user, r_strf (":clear-comments 0x%08"PFMT64x, rems->addr));
			break;
		}
		break;
	default:
		// TODO
		break;
	}
	free (str);
}

static RFlagItem *core_flg_class_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	r_flag_space_push (f, R_FLAGS_FS_CLASSES);
	RFlagItem *res = r_flag_set (f, name, addr, size);
	r_flag_space_pop (f);
	return res;
}

static RFlagItem *core_flg_class_get(RFlag *f, const char *name) {
	r_flag_space_push (f, R_FLAGS_FS_CLASSES);
	RFlagItem *res = r_flag_get (f, name);
	r_flag_space_pop (f);
	return res;
}

static RFlagItem *core_flg_fcn_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	r_flag_space_push (f, R_FLAGS_FS_FUNCTIONS);
	RFlagItem *res = r_flag_set (f, name, addr, size);
	r_flag_space_pop (f);
	return res;
}

R_API void r_core_autocomplete_reload(RCore *core) {
	R_RETURN_IF_FAIL (core);
	r_core_autocomplete_free (core->autocomplete);
	__init_autocomplete (core);
}

R_API RFlagItem *r_core_flag_get_by_spaces(RFlag *f, bool prionospace, ut64 off) {
	return r_flag_get_by_spaces (f, prionospace, off,
		R_FLAGS_FS_FUNCTIONS,
		R_FLAGS_FS_SIGNS,
		R_FLAGS_FS_CLASSES,
		R_FLAGS_FS_SYMBOLS,
		R_FLAGS_FS_IMPORTS,
		R_FLAGS_FS_RELOCS,
		R_FLAGS_FS_STRINGS,
		R_FLAGS_FS_RESOURCES,
		R_FLAGS_FS_SYMBOLS_SECTIONS,
#if 1
		R_FLAGS_FS_SECTIONS,
		R_FLAGS_FS_SEGMENTS,
#endif
		NULL);
}

static void ev_iowrite_cb(REvent *ev, int type, void *user, void *data) {
	RCore *core = user;
	REventIOWrite *iow = data;
	if (r_config_get_i (core->config, "anal.onchange")) {
		// works, but loses varnames and such, but at least is not crashing
		char *cmd = r_str_newf ("af-0x%08"PFMT64x";af 0x%08"PFMT64x, iow->addr, iow->addr);
		r_list_append (core->cmdqueue, cmd);
#if 0
		r_anal_update_analysis_range (core->anal, iow->addr, iow->len);
		if (core->cons->event_resize && core->cons->event_data) {
			// Force a reload of the graph
			core->cons->event_resize (core->cons->event_data);
		}
#endif
	}
}

static RThreadFunctionRet thchan_handler(RThread *th) {
	RCore *core = (RCore *)th->user;
	// r_cons_thready ();
	while (r_th_is_running (th) && !th->breaked) {
		r_th_sem_wait (core->chan->sem); // busy because stack is empty
		if (!r_th_is_running (th) || th->breaked) {
			break;
		}
		RThreadChannelMessage *cm = r_th_channel_read (core->chan);
		if (!cm) {
			// eprintf ("thchan_handler no message\n");
			// r_th_sem_post (cm->sem);
			// r_th_channel_write (core->chan, NULL);
			// r_th_lock_leave (cm->lock);
			continue;
		}
		char *res = r_core_cmd_str (core, (const char *)cm->msg);
		free (cm->msg);
		if (res) {
			cm->msg = (ut8 *)res;
			cm->len = strlen (res) + 1;
		} else {
			cm->msg = NULL;
			cm->len = 0;
		}
		r_th_channel_post (core->chan, cm);
		r_th_sem_post (cm->sem);
	}
	return 0;
}

static bool cbcore(void *user, int type, const char *origin, const char *msg) {
	if (!msg) {
		return false;
	}
	if (!origin) {
		origin = "*";
	}
	RCore *core = (RCore*)user;
	char *s = R_STR_ISNOTEMPTY (msg)
		? r_str_newf ("%s %s", origin, msg)
		: strdup (origin);
	r_core_log_add (core, s);
	free (s);
	return false;
}

#if R2__UNIX__
static R_TH_LOCAL RCore *Gcore = NULL;

static void cmdusr1(int p) {
	const char *cmd = r_config_get (Gcore->config, "cmd.usr1");
	if (R_STR_ISNOTEMPTY (cmd)) {
		r_core_cmd0 (Gcore, cmd);
		r_cons_flush (Gcore->cons);
	}
}

static void cmdusr2(int p) {
	const char *cmd = r_config_get (Gcore->config, "cmd.usr2");
	if (R_STR_ISNOTEMPTY (cmd)) {
		r_core_cmd0 (Gcore, cmd);
		r_cons_flush (Gcore->cons);
	}
}
#endif

static void core_visual_init(RCoreVisual *visual) {
	visual->printidx = 0;
	visual->textedit_mode = true;
	visual->obs = 0;
	visual->ime = false;
	visual->imes = false;
	visual->nib = -1;
	visual->blocksize = 0;
	visual->autoblocksize = true;
	visual->disMode = 0;
	visual->hexMode = 0;
	visual->printMode = 0;
	visual->snowMode = false;
	visual->snows = NULL;
	visual->color = 1;
	visual->zoom = 0;
	visual->currentFormat = 0;
	visual->current0format = 0;
	memset (visual->numbuf, 0, sizeof (visual->numbuf));
	visual->numbuf_i = 0;
	visual->splitView = false;
	visual->splitPtr = UT64_MAX;
	visual->current3format = 0;
	visual->current4format = 0;
	visual->current5format = 0;
	visual->hold = NULL;
	visual->oldpc = 0;
	visual->oseek = UT64_MAX;
	memset (visual->debugstr, 0, sizeof (visual->debugstr));

	visual->firstRun = true;
	visual->fromVisual = false;
	memset (visual->menus_Colors, 0, sizeof (visual->menus_Colors));
}

R_API bool r_core_init(RCore *core) {
#if R2__UNIX__
	Gcore = core;
	r_sys_signal (SIGUSR1, cmdusr1);
	r_sys_signal (SIGUSR2, cmdusr2);
#endif
	r_w32_init ();
	core->priv = R_NEW0 (RCorePriv);
	core->log = r_core_log_new ();
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8 *)calloc (R_CORE_BLOCKSIZE + 1, 1);
	if (!core->block) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", R_CORE_BLOCKSIZE);
		return false;
	}
	r_core_vmark_reset (core);
	core->chan = NULL;
	r_core_setenv (core);
	core->lock = r_th_lock_new (true);
	core->in_log_process = false;
	core->rfs = r_fs_shell_new ();
	core->ev = r_event_new (core);
	r_event_hook (core->ev, R_EVENT_ALL, cb_event_handler, NULL);
	core->max_cmd_depth = R_CONS_CMD_DEPTH + 1;
	core->sdb = sdb_new (NULL, "r2kv.sdb", 0); // XXX: path must be in home?
	core->lastsearch = NULL;
	core->cmdfilter = NULL;
	core->switch_file_view = 0;
	core->cmdremote = 0;
	core->incomment = false;
	core->config = NULL;
	core->prj = r_project_new ();
	core->http_up = false;
	core->print = r_print_new ();
	core->ropchain = r_list_newf ((RListFree)free);
	r_core_bind (core, &(core->print->coreb));
	core->print->user = core;
	core->num = r_num_new (&num_callback, &str_callback, core);
	core->print->num = core->num;
	core->print->offname = r_core_print_offname;
	core->print->offsize = r_core_print_offsize;
	// core->print->cb_color = r_cons_rainbow_get; // NEVER CALLED
	core->print->exists_var = exists_var;
	core->print->disasm = __disasm;
	core->print->colorfor = colorfor_cb;
	core->print->hasrefs = hasrefs_cb;
	core->print->get_comments = get_comments_cb;
	core->print->get_section_name = get_section_name;
	core->print->use_comments = false;
	core->rtr_n = 0;
	core->blocksize_max = R_CORE_BLOCKSIZE_MAX;
	r_core_task_scheduler_init (&core->tasks, core);
	core->watchers = r_list_new ();
	core->watchers->free = (RListFree)r_core_cmpwatch_free;
	core->scriptstack = r_list_new ();
	core->scriptstack->free = (RListFree)free;
	core->times = R_NEW0 (RCoreTimes);
	core->vmode = false;
	core_visual_init (&core->visual);
	core->lastcmd = NULL;

	if (core->print->charset) {
		sdb_free (core->print->charset->db);
		core->print->charset->db = sdb_ns (core->sdb, "charset", 1);
		core->print->charset->db->refs++; // increase reference counter to avoid double-free
	}
	// ideally sdb_ns_set should be used here, but it doesnt seems to work well. must fix
	// sdb_ns_set (DB, "charset", core->print->charset->db);
	core->stkcmd = NULL;
	core->cmdqueue = r_list_newf (free);
	core->cmdrepeat = true;
	core->yank_buf = r_buf_new ();
	core->muta = r_muta_new ();
	core->egg = r_egg_new ();
// 	core->egg->rasm = core->rasm;

	core->undos = r_list_newf ((RListFree)r_core_undo_free);

	core->theme = strdup ("default");
	/* initialize libraries */
	core->cons = r_cons_new ();
	core->cons->line->user = core;
	r_cons_bind (core->cons, &core->print->consb);
	core->cmdlog = NULL;
	// XXX causes uaf
	r_log_add_callback (cbcore, core);

	// We save the old num ad user, in order to restore it after free
	core->lang = r_lang_new ();
	core->lang->cons = core->cons;
	core->lang->cmd_str = (char *(*)(void *, const char *))r_core_cmd_str;
	core->lang->cmdf = (RCoreCmdF)r_core_cmdf;
	core->lang->call_at = (RCoreCallAtCallback) r_core_cmd_call_str_at;
	r_core_bind_cons (core);
	core->table = NULL;
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->rasm = core->egg->rasm;
	core->rasm->num = core->num;
	core->anal = r_anal_new ();
	core->anal->arch->user = core;
	r_anal_bind (core->anal, &core->egg->rasm->analb);
	r_anal_bind (core->anal, &(core->rasm->analb));
	r_asm_set_user_ptr (core->rasm, core);
	// XXX this should be tied to RArchConfig
	r_egg_setup (core->egg, R_SYS_ARCH, R_SYS_BITS, 0, R_SYS_OS);
#if 1
	// TODO: use r_ref_set
	r_ref (core->rasm->config);
	r_unref (core->print->config);
	core->print->config = core->rasm->config;

	r_ref (core->rasm->config);
	r_unref (core->anal->config);
	core->anal->config = core->rasm->config;

	r_ref (core->rasm->config);
	core->anal->reg->endian = core->rasm->config->endian;
#else
	r_ref_set (core->print->config, core->rasm->config);
	r_ref_set (core->anal->config, core->rasm->config);
#endif
	// RAnal.new() doesnt initializes this field. but it should be refcounted
	core->anal->print = core->print;
	r_anal_set_bits (core->anal, 32); // core->rasm->config->bits);
	core->gadgets = r_list_newf ((RListFree)r_core_gadget_free);
	core->anal->ev = core->ev;
	core->anal->log = r_core_anal_log;
	core->anal->read_at = r_core_anal_read_at;
	core->anal->flag_get = r_core_flag_get_by_spaces;
	core->anal->cb.on_fcn_new = on_fcn_new;
	core->anal->cb.on_fcn_delete = on_fcn_delete;
	core->anal->cb.on_fcn_rename = on_fcn_rename;
	core->print->sdb_types = core->anal->sdb_types;
	core->rasm->syscall = r_syscall_ref (core->anal->syscall); // BIND syscall anal/asm
	r_anal_set_user_ptr (core->anal, core);
	core->anal->cb_printf = (void *) r_cons_gprintf;
	core->rasm->parse->varlist = r_anal_function_get_var_fields;
	core->bin = r_bin_new ();
	r_cons_bind (core->cons, &core->bin->consb);
	// XXX we should use RConsBind instead of this hardcoded pointer
	core->bin->cb_printf = (PrintfCallback) r_cons_gprintf;
	r_bin_set_user_ptr (core->bin, core);
	core->io = r_io_new ();
	r_event_hook (core->io->event, R_EVENT_IO_WRITE, ev_iowrite_cb, core);
	core->io->ff = 1;
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	core->flags = r_flag_new ();
	int flags = r_cons_canvas_flags (core->cons);
	core->graph = r_agraph_new (r_cons_canvas_new (core->cons, 1, 1, flags));
	core->graph->need_reload_nodes = false;
	core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
	if (sizeof (ut64) * core->asmqjmps_size < core->asmqjmps_size) {
		core->asmqjmps_size = 0;
		core->asmqjmps = NULL;
	} else {
		core->asmqjmps = R_NEWS (ut64, core->asmqjmps_size);
	}

	r_bin_bind (core->bin, &(core->anal->binb));
	r_bin_bind (core->bin, &(core->anal->arch->binb));
	r_num_free (core->anal->arch->num);
	core->anal->arch->num = core->num;
	r_io_bind (core->io, &(core->search->iob));
	r_io_bind (core->io, &(core->print->iob));
	r_io_bind (core->io, &(core->anal->iob));
	r_io_bind (core->io, &(core->fs->iob));
	r_cons_bind (core->cons, &(core->fs->csb));
	r_cons_bind (core->cons, &(core->search->consb));
	r_core_bind (core, &(core->fs->cob));
	r_io_bind (core->io, &(core->bin->iob));
	r_flag_bind (core->flags, &(core->anal->flb));
	core->anal->flg_class_set = core_flg_class_set;
	core->anal->flg_class_get = core_flg_class_get;
	core->anal->flg_fcn_set = core_flg_fcn_set;
	core->rasm->parse->flag_get = r_core_flag_get_by_spaces;
	core->rasm->parse->label_get = r_anal_function_get_label_at;

	r_core_bind (core, &(core->anal->coreb));

	core->addr = 0LL;
	core->prompt_addr = 0LL;
	r_core_cmd_init (core);
	core->dbg = r_debug_new (true);

	r_io_bind (core->io, &(core->dbg->iob));
	r_io_bind (core->io, &(core->dbg->bp->iob));
	r_core_bind (core, &core->dbg->coreb);
	r_core_bind (core, &core->dbg->bp->coreb);
	r_core_bind (core, &core->io->coreb);
	core->dbg->egg = core->egg;
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	// r_debug_use (core->dbg, "native");
// XXX pushing uninitialized regstate results in trashed reg values
//	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->io->cb_printf = r_cons_gprintf;
	core->dbg->cb_printf = r_cons_gprintf;
	core->dbg->ev = core->ev;
	r_core_config_init (core);
	r_core_loadlibs_init (core);
	//r_core_loadlibs (core);
	// TODO: get arch from r_bin or from native arch
#if 0
	// Seems unnecessary
	r_asm_use (core->rasm, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
#endif
	if (R_SYS_BITS_CHECK (R_SYS_BITS, 64)) {
		r_config_set_i (core->config, "asm.bits", 64);
	} else if (R_SYS_BITS_CHECK (R_SYS_BITS, 32)) {
		r_config_set_i (core->config, "asm.bits", 32);
	}
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH, core->anal->config->bits);
	update_sdb (core);
	init_cmd_suggestions (core);
	{
		char *a = r_str_r2_prefix (R2_FLAGS);
		if (a) {
			char *file = r_str_newf ("%s/tags.r2", a);
			bool p = core->print->enable_progressbar;
			core->print->enable_progressbar = false;
			(void)r_core_run_script (core, file);
			core->print->enable_progressbar = p;
			free (file);
			free (a);
		}
	}
	r_core_anal_type_init (core);
	__init_autocomplete (core);
	r_anal_bind (core->anal, &(core->rasm->analb));
	return 0;
}

R_API void __cons_cb_fkey(RCore *core, int fkey) {
	if (fkey < 1) {
		R_LOG_ERROR ("Invalid function key index %d received", fkey);
		return;
	}
	r_strf_var (keyvar, 64, "key.f%d", fkey);
	const char *v = r_config_get (core->config, keyvar);
	if (R_STR_ISNOTEMPTY (v)) {
		r_core_cmd0 (core, v);
		r_cons_flush (core->cons);
	}
}

R_API void r_core_bind_cons(RCore *core) {
	R_RETURN_IF_FAIL (core);
	core->cons->num = core->num;
	core->cons->cb_fkey = (RConsFunctionKey)__cons_cb_fkey;
	core->cons->cb_editor = (RConsEditorCallback)r_core_editor;
	core->cons->cb_break = NULL; // (RConsBreakCallback)r_core_break;
	core->cons->cb_sleep_begin = (RConsSleepBeginCallback)r_core_sleep_begin;
	core->cons->cb_sleep_end = (RConsSleepEndCallback)r_core_sleep_end;
	core->cons->user = (void*)core;
}

R_API void r_core_fini(RCore *c) {
	R_RETURN_IF_FAIL (c);
	if (c->chan) {
		r_th_channel_free (c->chan);
	}
#if R2__UNIX__
	Gcore = NULL;
#endif
	r_log_add_callback (cbcore, NULL);
	r_muta_free (c->muta);
	r_th_lock_free (c->lock);
	r_core_task_cancel_all (c, true);
	r_core_task_join (&c->tasks, NULL, -1);
	r_core_wait (c);
	//update_sdb (c);
	// avoid double free
	r_list_free (c->ropchain);
	r_table_free (c->table);
	R_FREE (c->cmdlog);
	free (c->lastsearch);
	r_list_free (c->cmdqueue);
	free (c->lastcmd);
	free (c->stkcmd);
	r_project_free (c->prj);
	r_list_free (c->visual.tabs);
	free (c->block);
	r_core_autocomplete_free (c->autocomplete);

	r_list_free (c->gadgets);
	r_list_free (c->undos);
	r_num_free (c->num);
	// TODO: sync or not? sdb_sync (c->sdb);
	// TODO: sync all dbs?
	//c->file = NULL;
	free (c->table_query);
	r_list_free (c->watchers);
	r_list_free (c->scriptstack);
	r_core_task_scheduler_fini (&c->tasks);
	r_event_free (c->ev);
	// Free cmd and its plugins before freeing event system
	c->rcmd = r_cmd_free (c->rcmd);
	r_lib_free (c->lib);
	/*
	r_unref (c->anal->config);
	*/
	if (c->anal->esil) {
		c->anal->esil->anal = NULL;
	}
	r_anal_free (c->anal);
	r_asm_free (c->rasm);
	c->rasm = NULL;
	r_print_free (c->print);
	c->print = NULL;
	c->bin = (r_bin_free (c->bin), NULL);
	c->dbg = (r_debug_free (c->dbg), NULL);
	c->io = (r_io_free (c->io), NULL);
	c->lang = (r_lang_free (c->lang), NULL);
	r_config_free (c->config);
	c->config = NULL;
	/* after r_config_free, the value of I.teefile is trashed */
	/* rconfig doesnt knows how to deinitialize vars, so we
	should probably need to add a r_config_free_payload callback */
	r_cons_free (c->cons);
	c->cons = NULL;
	free (c->theme);
	free (c->themepath);
	r_search_free (c->search);
	r_flag_free (c->flags);
	r_fs_free (c->fs);
	c->egg->rasm = NULL;
	r_egg_free (c->egg);
	r_buf_free (c->yank_buf);
	r_agraph_free (c->graph);
	free (c->asmqjmps);
	sdb_free (c->sdb);
	r_core_log_free (c->log);
	r_fs_shell_free (c->rfs);
	free (c->times);
	free (c->priv);
}

R_API void r_core_free(RCore * R_NULLABLE c) {
	if (c) {
		r_core_fini (c);
		free (c);
	}
}

R_API bool r_core_prompt_loop(RCore *r) {
#if !R2_USE_NEW_ABI
	Gload_index = r->cons->line->history.index;
#endif
	int ret = 0;
	do {
		int err = r_core_prompt (r, false);
		if (err < 1) {
			// handle ^D
			r->num->value = 0; // r.num->value will be read by r_main_radare2() after calling this fcn
			return false;
		}
		/* -1 means invalid command, -2 means quit prompt loop */
		ret = r_core_prompt_exec (r);
		if (ret == R_CMD_RC_QUIT) {
			break;
		}
	} while (ret != R_CORE_CMD_EXIT);
	return true;
}

static int prompt_flag(RCore *core, char *s, size_t maxlen) {
	const char DOTS[] = "...";
	const RFlagItem *f = r_flag_get_at (core->flags, core->addr, true);
	if (!f) {
		return false;
	}
	if (core->addr > f->addr) {
		snprintf (s, maxlen, "0x%08" PFMT64x " | %s+0x%" PFMT64x,
				core->addr, f->name, core->addr - f->addr);
	} else {
		snprintf (s, maxlen, "0x%08" PFMT64x " | %s",
				core->addr, f->name);
	}
	if (strlen (s) > maxlen - sizeof (DOTS)) {
		s[maxlen - sizeof (DOTS) - 1] = '\0';
		strcat (s, DOTS);
	}
	return true;
}

// ugly function signature
static void prompt_sec(RCore *core, char *s, size_t maxlen) {
	RBinObject *bo = r_bin_cur_object (core->bin);
	if (bo) {
		const RBinSection *sec = r_bin_get_section_at (bo, core->addr, true);
		if (sec) {
			r_str_ncpy (s, sec->name, maxlen - 2);
			strcat (s, ":");
		}
	}
}

static void chop_prompt(RCore *core, const char *filename, char *tmp, size_t max_tmp_size) {
	unsigned int OTHRSCH = 3;
	const char DOTS[] = "...";

	int w = r_cons_get_size (core->cons, NULL);
	size_t file_len = strlen (filename);
	size_t tmp_len = strlen (tmp);
	int p_len = R_MAX (0, w - 6);
	if (file_len + tmp_len + OTHRSCH >= p_len) {
		size_t dots_size = sizeof (DOTS);
		size_t chop_point = (size_t)(p_len - OTHRSCH - file_len - dots_size);
		if (chop_point < max_tmp_size - dots_size) {
			snprintf (tmp + chop_point, dots_size, "%s", DOTS);
		}
	}
}

static void set_prompt(RCore *core) {
	if (core->incomment) {
		r_line_set_prompt (core->cons->line, " * ");
		return;
	}
	char tmp[128];
	char *filename = strdup ("");
	const char *cmdprompt = r_config_get (core->config, "cmd.prompt");
	const char *BEGIN = "";
	const char *END = "";
	const char *remote = "";

	if (R_STR_ISNOTEMPTY (cmdprompt)) {
		r_core_cmd (core, cmdprompt, 0);
	}

	if (r_config_get_b (core->config, "scr.prompt.prj")) {
		free (filename);
		const char *pn = r_config_get (core->config, "prj.name");
		filename = r_str_newf ("<%s>", pn);
	} else if (r_config_get_b (core->config, "scr.prompt.file")) {
		free (filename);
		const char *fn = core->io->desc ? r_file_basename (core->io->desc->name) : "";
		filename = r_str_newf ("<%s>", fn);
	}
	if (core->cmdremote) {
		char *s = r_core_cmd_str (core, "s");
		core->addr = r_num_math (NULL, s);
		free (s);
		remote = "=!";
	}

	if (r_config_get_i (core->config, "scr.color") > 0) {
		BEGIN = core->cons->context->pal.prompt;
		END = core->cons->context->pal.reset;
	}

	// TODO: also in visual prompt and disasm/hexdump ?
	if (r_config_get_b (core->config, "asm.addr.segment")) {
		ut32 sb = r_config_get_i (core->config, "anal.cs"); // segment base value
		ut32 sg = r_config_get_i (core->config, "asm.addr.segment.bits"); // segment granurality
		ut32 a, b;
		r_num_segaddr (core->addr, sb, sg, &a, &b);
		snprintf (tmp, sizeof (tmp), "%04x:%04x", a, b);
	} else {
		char p[64], sec[32];
		int promptset = false;

		sec[0] = '\0';
		if (r_config_get_b (core->config, "scr.prompt.flag")) {
			promptset = prompt_flag (core, p, sizeof (p));
		}
		if (r_config_get_b (core->config, "scr.prompt.sect")) {
			prompt_sec (core, sec, sizeof (sec));
		}
		if (!promptset) {
			const char *fmt = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
				? "0x%016" PFMT64x : "0x%08" PFMT64x;
			snprintf (p, sizeof (p), fmt, core->addr);
		}
		snprintf (tmp, sizeof (tmp), "%s%s", sec, p);
	}
	if (!BEGIN) {
		BEGIN = "";
	}
	if (!END) {
		END = "";
	}
	chop_prompt (core, filename, tmp, 128);
	char *prompt = NULL;
	if (r_config_get_b (core->config, "scr.prompt.code")) {
		st64 code = core->num->value;
		prompt = r_str_newf ("%s%s[%"PFMT64d":%s%s]> %s", filename, BEGIN, code, remote, tmp, END);
	} else {
		prompt = r_str_newf ("%s%s[%s%s]> %s", filename, BEGIN, remote, tmp, END);
	}
	r_line_set_prompt (core->cons->line, r_str_get (prompt));

	R_FREE (filename);
	R_FREE (prompt);
}

R_API void r_core_cmd_queue_wait(RCore *core) {
	const bool interactive = r_config_get_b (core->config, "scr.interactive");
	if (!interactive) {
		return;
	}
	r_cons_push (core->cons);
	r_cons_break_push (core->cons, NULL, NULL);
	while (!r_cons_is_breaked (core->cons)) {
		char *cmd = r_list_pop (core->cmdqueue);
		if (cmd) {
			r_core_cmd0 (core, cmd);
			r_cons_flush (core->cons);
			free (cmd);
		}
		r_sys_usleep (100);
	}
	r_cons_break_pop (core->cons);
	r_cons_pop (core->cons);
}

R_API void r_core_cmd_queue(RCore *core, const char *line) {
	if (line) {
		r_list_append (core->cmdqueue, strdup (line));
	} else {
		r_list_free (core->cmdqueue);
		core->cmdqueue = r_list_newf (free);
	}
}

R_API int r_core_prompt(RCore *r, int sync) {
	char line[4096];

	int rnv = r->num->value;
	set_prompt (r);
	int ret = r_cons_fgets (r->cons, line, sizeof (line), 0, NULL);
	if (ret == -2) {
		return R_CORE_CMD_EXIT; // ^D
	}
	if (ret == -1) {
		if (r->incomment) {
			r->incomment = false;
			return 1;
		}
		return false; // FD READ ERROR
	}
	r->num->value = rnv;
	if (sync) {
		return r_core_prompt_exec (r);
	}
	r_core_cmd_queue (r, line);
	if (r->scr_gadgets && *line && *line != 'q') {
		r_core_cmd0 (r, "pg");
	}
	// r->num->value = r->rc;
	return true;
}

R_API int r_core_prompt_exec(RCore *r) {
	int ret = -1;
	while (!r_list_empty (r->cmdqueue)) {
		char *cmd = r_list_pop (r->cmdqueue);
		if (!cmd) {
			break;
		}
		ret = r_core_cmd (r, cmd, true); // initial free
		free (cmd);
		if (ret < 0) {
			if (r->cons && r->cons->line && r->cons->line->zerosep) {
				r_cons_zero (r->cons);
			}
			r_core_cmd_queue (r, NULL);
			break;
		}
		if (r->cons && r->cons->context->use_tts) {
			const char *buf = r_cons_get_buffer (r->cons, NULL);
			if (R_STR_ISNOTEMPTY (buf)) {
				r_sys_tts (buf, true);
			}
			r->cons->context->use_tts = false;
		}
		r_cons_echo (r->cons, NULL);
		r_cons_flush (r->cons); // double free
		if (r->cons && r->cons->line && r->cons->line->zerosep) {
			r_cons_zero (r->cons);
		}
	}
	return ret;
}

R_API int r_core_seek_size(RCore *core, ut64 addr, int bsize) {
	ut8 *bump;
	int ret = false;
	if (bsize < 0) {
		return false;
	}
	if (bsize == core->blocksize) {
		return true;
	}
	if (r_sandbox_enable (0)) {
		// TODO : restrict to filesize?
		if (bsize > 1024 * 32) {
			R_LOG_ERROR ("Sandbox mode restricts blocksize bigger than 32k");
			return false;
		}
	}
	if (bsize > core->blocksize_max) {
		R_LOG_ERROR ("Block size %d is too big", bsize);
		return false;
	}
	R_CRITICAL_ENTER (core);
	core->addr = addr;
	if (bsize < 1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize>core->blocksize_max) {
		R_LOG_ERROR ("bsize is bigger than `bm`. dimmed to 0x%x > 0x%x",
			bsize, core->blocksize_max);
		bsize = core->blocksize_max;
	}
	bump = realloc (core->block, bsize + 1);
	if (!bump) {
		R_LOG_ERROR ("Oops. cannot allocate that much (%u)", bsize);
		ret = false;
	} else {
		ret = true;
		core->block = bump;
		core->blocksize = bsize;
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core);
	}
	R_CRITICAL_LEAVE (core);
	return ret;
}

R_API int r_core_block_size(RCore *core, int bsize) {
	return r_core_seek_size (core, core->addr, bsize);
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int inc = (times >= 0)? 1: -1;
	ut64 seek = core->addr;
	if (!align) {
		return false;
	}
	int diff = core->addr % align;
	if (!times) {
		diff = -diff;
	} else if (diff) {
		if (inc > 0) {
			diff += align-diff;
		} else {
			diff = -diff;
		}
		if (times) {
			times -= inc;
		}
	}
	while ((times*inc) > 0) {
		times -= inc;
		diff += (align * inc);
	}
	if (diff < 0 && -diff > seek) {
		seek = diff = 0;
	}
	return r_core_seek (core, seek + diff, true);
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAnalOp op;
	r_anal_op_init (&op);
	r_asm_set_pc (core->rasm, addr);
	ut8 buf[64];
	// TODO: use archinfo to avoid readingn 64bytes always
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	int ret = r_asm_disassemble (core->rasm, &op, buf, sizeof (buf));
	char *str = (ret > 0)? strdup (op.mnemonic): NULL;
	r_anal_op_fini (&op);
	return str;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr, RAnalOpMask mask) {
	ut8 buf[64];
	RAnalOp *op = R_NEW (RAnalOp);
	if (op) {
		r_io_read_at (core->io, addr, buf, sizeof (buf));
		r_anal_op (core->anal, op, addr, buf, sizeof (buf), mask);
	}
	return op;
}

static void rap_break(void *u) {
	RIORap *rior = (RIORap*) u;
	if (u) {
		r_socket_close (rior->fd);
		rior->fd = NULL;
	}
}

// TODO: PLEASE move into core/io/rap? */
// TODO: use static buffer instead of mallocs all the time. it's network!
R_API bool r_core_serve(RCore *core, RIODesc *file) {
	// TODO: use r_socket_rap_server API instead of duplicating the logic
	ut8 cmd, flg, *ptr = NULL, buf[1024];
	int i, pipefd = -1;
	ut64 x;

	RIORap *rior = (RIORap *)file->data;
	if (!rior || !rior->fd) {
		R_LOG_ERROR ("rap: cannot listen");
		return false;
	}
	RSocket *fd = rior->fd;
	const char *arg = r_config_get (core->config, "rap.loop");
	R_LOG_INFO ("RAP Server started (rap.loop=%s)", arg);
	r_cons_break_push (core->cons, rap_break, rior);
reaccept:
	while (!r_cons_is_breaked (core->cons)) {
		RSocket *c = r_socket_accept (fd);
		if (!c) {
			break;
		}
		if (r_cons_is_breaked (core->cons)) {
			goto out_of_function;
		}
		if (!c) {
			R_LOG_ERROR ("rap: cannot accept");
			r_socket_free (c);
			goto out_of_function;
		}
		R_LOG_INFO ("rap: client connected");
		for (;!r_cons_is_breaked (core->cons);) {
			if (!r_socket_read_block (c, &cmd, 1)) {
				R_LOG_INFO ("rap: connection closed");
				if (r_config_get_i (core->config, "rap.loop")) {
					R_LOG_INFO ("rap: waiting for new connection");
					r_socket_free (c);
					goto reaccept;
				}
				goto out_of_function;
			}
			switch (cmd) {
			case RAP_PACKET_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				R_LOG_DEBUG ("open (%d)", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				if (UT8_ADD_OVFCHK (cmd, 1)) {
					goto out_of_function;
				}
				ptr = malloc ((size_t)cmd + 1);
				if (!ptr) {
					R_LOG_ERROR ("Cannot malloc in rmt-open len = %d", cmd);
				} else {
					ut64 baddr = r_config_get_i (core->config, "bin.laddr");
					r_socket_read_block (c, ptr, cmd);
					ptr[cmd] = 0;
					ut32 perm = R_PERM_R;
					if (flg & R_PERM_W) {
						perm |= R_PERM_W;
					}
					if (r_core_file_open (core, (const char *)ptr, perm, 0)) {
						int fd = r_io_fd_get_current (core->io);
						r_core_bin_load (core, NULL, baddr);
						r_io_map_add (core->io, fd, perm, 0, 0, r_io_fd_size (core->io, fd));
						if (core->io->desc) {
							pipefd = fd;
						} else {
							pipefd = -1;
						}
						R_LOG_INFO ("(flags: %d) len: %d filename: '%s'", flg, cmd, ptr);
					} else {
						pipefd = -1;
						R_LOG_ERROR ("Cannot open file (%s)", ptr);
						r_socket_close (c);
						if (r_config_get_i (core->config, "rap.loop")) {
							R_LOG_INFO ("rap: waiting for new connection");
							r_socket_free (c);
							goto reaccept;
						}
						goto out_of_function; //XXX: Close connection and goto accept
					}
				}
				buf[0] = RAP_PACKET_OPEN | RAP_PACKET_REPLY;
				r_write_be32 (buf + 1, pipefd);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				R_FREE (ptr);
				break;
			case RAP_PACKET_READ: {
				/* Read requested length and validate */
				r_socket_read_block (c, (ut8 *)&buf, 4);
				i = r_read_be32 (buf);
				if (i < 0) {
					R_LOG_ERROR ("rap: invalid read length %d", i);
					r_socket_close (c);
					goto out_of_function;
				}
				if (i > RAP_PACKET_MAX) {
					i = RAP_PACKET_MAX;
				}
				/* Ensure core block buffer is large enough */
				if (i > core->blocksize) {
					r_core_block_size (core, i);
				}
				r_core_block_read (core);
				/* Prevent size overflow on allocation */
				if (SZT_ADD_OVFCHK ((size_t)i, 5)) {
					R_LOG_ERROR ("rap: size overflow for read length %d", i);
					r_socket_close (c);
					goto out_of_function;
				}
				ptr = malloc ((size_t)i + 5);
				if (!ptr) {
					R_LOG_ERROR ("rap: cannot allocate %zu bytes for read", (size_t)i + 5);
					r_socket_close (c);
					goto out_of_function;
				}
				ptr[0] = RAP_PACKET_READ | RAP_PACKET_REPLY;
				r_write_be32 (ptr + 1, i);
				memcpy (ptr + 5, core->block, i);
				r_socket_write (c, ptr, (size_t)i + 5);
				r_socket_flush (c);
				R_FREE (ptr);
				}
				break;
			case RAP_PACKET_CMD:
				{
				char *cmd = NULL, *cmd_output = NULL;
				char bufr[8], *bufw = NULL;
				ut32 cmd_len = 0;
				int i;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				i = r_read_be32 (bufr);
				if (i > 0 && i < RAP_PACKET_MAX) {
					if ((cmd = malloc (i + 1))) {
						r_socket_read_block (c, (ut8*)cmd, i);
						cmd[i] = '\0';
						bool scr_interactive = r_config_get_b (core->config, "scr.interactive");
						r_config_set_b (core->config, "scr.interactive", false);
						cmd_output = r_core_cmd_str (core, cmd);
						r_config_set_b (core->config, "scr.interactive", scr_interactive);
						free (cmd);
					} else {
						R_LOG_ERROR ("rap: cannot malloc");
					}
				} else {
					R_LOG_INFO ("rap: invalid length '%d'", i);
				}
				/* write */
				if (cmd_output) {
					cmd_len = strlen (cmd_output) + 1;
				} else {
					cmd_output = strdup ("");
					cmd_len = 0;
				}
#if DEMO_SERVER_SENDS_CMD_TO_CLIENT
				static R_TH_LOCAL bool once = true;
				/* TODO: server can reply a command request to the client only here */
				if (once) {
					const char *cmd = "pd 4";
					int cmd_len = strlen (cmd) + 1;
					ut8 *b = malloc (cmd_len + 5);
					b[0] = RAP_PACKET_CMD;
					r_write_be32 (b + 1, cmd_len);
					strcpy ((char *)b+ 5, cmd);
					r_socket_write (c, b, 5 + cmd_len);
					r_socket_flush (c);

					/* read response */
					r_socket_read_block (c, b, 5);
					if (b[0] == (RAP_PACKET_CMD | RAP_PACKET_REPLY)) {
						ut32 n = r_read_be32 (b + 1);
						R_LOG_DEBUG ("REPLY %d", n);
						if (n > 0) {
							ut8 *res = calloc (1, n);
							r_socket_read_block (c, res, n);
							R_LOG_DEBUG ("RESPONSE(%s)", (const char *)res);
							free (res);
						}
					}
					r_socket_flush (c);
					free (b);
					once = false;
				}
#endif
				bufw = malloc (cmd_len + 5);
				bufw[0] = (ut8) (RAP_PACKET_CMD | RAP_PACKET_REPLY);
				r_write_be32 (bufw + 1, cmd_len);
				memcpy (bufw + 5, cmd_output, cmd_len);
				r_socket_write (c, bufw, cmd_len+5);
				r_socket_flush (c);
				free (bufw);
				free (cmd_output);
				}
				break;
			case RAP_PACKET_WRITE: {
				/* Read write length and validate */
				r_socket_read_block (c, buf, 4);
				x = r_read_at_be32 (buf, 0);
				if ((int)x < 0 || x > RAP_PACKET_MAX) {
					R_LOG_ERROR ("rap: invalid write length %llu", (unsigned long long)x);
					r_socket_close (c);
					goto out_of_function;
				}
				int wlen = (int)x;
				ptr = malloc (wlen);
				if (!ptr) {
					R_LOG_ERROR ("rap: write malloc failed for %d bytes", wlen);
					r_socket_close (c);
					goto out_of_function;
				}
				r_socket_read_block (c, ptr, wlen);
				int ret = r_core_write_at (core, core->addr, ptr, wlen);
				buf[0] = RAP_PACKET_WRITE | RAP_PACKET_REPLY;
				r_write_be32 (buf + 1, ret);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				R_FREE (ptr);
				break;
			}
			case RAP_PACKET_SEEK:
				r_socket_read_block (c, buf, 9);
				x = r_read_at_be64 (buf, 1);
				if (buf[0] == 2) {
					if (core->io->desc) {
						x = r_io_fd_size (core->io, core->io->desc->fd);
					} else {
						x = 0;
					}
				} else {
					if (buf[0] == 0) {
						r_core_seek (core, x, true); //buf[0]);
					}
					x = core->addr;
				}
				buf[0] = RAP_PACKET_SEEK | RAP_PACKET_REPLY;
				r_write_be64 (buf + 1, x);
				r_socket_write (c, buf, 9);
				r_socket_flush (c);
				break;
			case RAP_PACKET_CLOSE:
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				i = r_read_be32 (buf);
				{
				//FIXME: Use r_socket_close
				int ret = close (i);
				r_write_be32 (buf + 1, ret);
				buf[0] = RAP_PACKET_CLOSE | RAP_PACKET_REPLY;
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				}
				break;
			default:
				if (cmd == 'G') {
					// silly http emulation over rap://
					char line[256] = {0};
					r_socket_read_block (c, (ut8*)line, sizeof (line));
					if (!r_str_ncpy (line, "ET /cmd/", 8)) {
						char *cmd = line + 8;
						char *http = strstr (cmd, "HTTP");
						if (http) {
							*http = 0;
							http--;
							if (*http == ' ') {
								*http = 0;
							}
						}
						r_str_uri_decode (cmd);
						char *res = r_core_cmd_str (core, cmd);
						if (res) {
							r_socket_printf (c, "HTTP/1.0 %d %s\r\n%s"
									"Connection: close\r\nContent-Length: %d\r\n\r\n",
									200, "OK", "", -1); // strlen (res));
							r_socket_write (c, res, strlen (res));
							free (res);
						}
						r_socket_flush (c);
						r_socket_close (c);
					}
				} else {
					R_LOG_ERROR ("[rap] unknown command 0x%02x", cmd);
					r_socket_close (c);
					R_FREE (ptr);
				}
				if (r_config_get_i (core->config, "rap.loop")) {
					R_LOG_INFO ("rap: waiting for new connection");
					r_socket_free (c);
					goto reaccept;
				}
				goto out_of_function;
			}
		}
		R_LOG_INFO ("client: disconnected");
		r_socket_free (c);
	}
out_of_function:
	r_cons_break_pop (core->cons);
	return false;
}

#if 0
R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf = malloc (len);
	if (!buf) {
		R_LOG_ERROR ("Cannot allocate blocksize");
		return false;
	}
	while (from < to) {
		ut64 delta = to-from;
		if (delta < len) {
			len = (int)delta;
		}
		if (!r_io_read_at (core->io, from, buf, len)) {
			R_LOG_ERROR ("RCoreSearchCb: Cannot read at 0x%"PFMT64x, from);
			break;
		}
		for (ret = 0; ret < len;) {
			int done = cb (core, from, buf+ret, len-ret);
			if (done < 1) { /* interrupted */
				free (buf);
				return false;
			}
			ret += done;
		}
		from += len;
	}
	free (buf);
	return true;
}
#endif

R_API char *r_core_editor(const RCore *core, const char *file, const char *str) {
	const bool interactive = r_cons_is_interactive (core->cons);
	const char *editor = r_config_get (core->config, "cfg.editor");
	char *name = NULL, *ret = NULL;
	int fd;

	if (!interactive) {
		return NULL;
	}
	bool readonly = false;
	bool tempfile = false;
	if (file && *file != '*') {
		name = strdup (file);
		fd = r_sandbox_open (file, O_RDWR, 0644);
		if (fd == -1) {
			fd = r_sandbox_open (file, O_RDWR | O_CREAT, 0644);
			if (fd == -1) {
				fd = r_sandbox_open (file, O_RDONLY, 0644);
				readonly = true;
			}
		}
	} else {
		tempfile = true;
		fd = r_file_mkstemp (file, &name);
	}
	if (fd == -1) {
		free (name);
		return NULL;
	}
	if (readonly) {
		R_LOG_INFO ("Opening in read-only");
	} else {
		if (str) {
			const size_t str_len = strlen (str);
			if (write (fd, str, str_len) != str_len) {
				close (fd);
				free (name);
				return NULL;
			}
		}
	}
	close (fd);

	if (name && (R_STR_ISEMPTY (editor) || !strcmp (editor, "-"))) {
		RCons *cons = core->cons;
		void *tmp = cons->cb_editor;
		cons->cb_editor = NULL;
		r_cons_editor (cons, name, NULL);
		cons->cb_editor = tmp;
	} else {
		if (editor && name) {
			char *escaped_name = r_str_escape_sh (name);
			r_sys_cmdf ("%s \"%s\"", editor, escaped_name);
			free (escaped_name);
		}
	}
	size_t len = 0;
	ret = name? r_file_slurp (name, &len): 0;
	if (ret) {
		if (len && ret[len - 1] == '\n') {
			ret[len - 1] = 0; // chop
		}
		if (tempfile) {
			r_file_rm (name);
		}
	}
	free (name);
	return ret;
}

/* weak getters */
R_API RCons *r_core_get_cons(RCore *core) {
	return core->cons;
}

R_API RConfig *r_core_get_config(RCore *core) {
	return core->config;
}

R_API RBin *r_core_get_bin(RCore *core) {
	return core->bin;
}

R_API RBuffer *r_core_syscallf(RCore *core, const char *name, const char *fmt, ...) {
	char str[1024];
	RBuffer *buf;
	va_list ap;
	va_start (ap, fmt);

	vsnprintf (str, sizeof (str), fmt, ap);
	buf = r_core_syscall (core, name, str);

	va_end (ap);
	return buf;
}

R_API RBuffer *r_core_syscall(RCore *core, const char *name, const char *args) {
	RBuffer *b = NULL;
	char code[1024];

	// arch check
	const char *arch = R_UNWRAP5 (core, anal, arch, session, name);
	if (arch && strcmp (arch, "x86")) {
		R_LOG_ERROR ("architecture not yet supported!");
		return 0;
	}

	int num = r_syscall_get_num (core->anal->syscall, name);
	/* FIXME: hack for r_syscall_get_num() returning 128 instead of 0 for x86.
	 * this is currently held together with duct tape and hope */
	if (num == 128) {
		num = 0;
	}

	//bits check
	switch (core->rasm->config->bits) {
	case 32:
		if (strcmp (name, "setup") && !num ) {
			R_LOG_ERROR ("syscall not found!");
			return 0;
		}
		break;
	case 64:
		if (strcmp (name, "read") && !num) {
			R_LOG_ERROR ("syscall not found!");
			return 0;
		}
		break;
	default:
		R_LOG_ERROR ("syscall not found!");
		return 0;
	}

	snprintf (code, sizeof (code),
			"sc@syscall(%d);\n"
			"main@global(0,1024) { sc(%s);\n"
			":int3\n"
			"}\n", num, args);
	r_egg_reset (core->egg);
	// TODO: setup arch/bits/os?
	r_egg_load (core->egg, code, 0);

	if (!r_egg_compile (core->egg)) {
		R_LOG_ERROR ("Cannot compile");
	}
	if (!r_egg_assemble (core->egg)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
	}
	if ((b = r_egg_get_bin (core->egg))) {
#if 0
		if (b->length > 0) {
			for (i = 0; i < b->length; i++) {
				r_cons_printf ("%02x", b->buf[i]);
			}
			r_cons_printf ("\n");
		}
#endif
	}
	return b;
}

R_API RCoreAutocomplete *r_core_autocomplete_add(RCoreAutocomplete *parent, const char* cmd, int type, bool lock) {
	R_RETURN_VAL_IF_FAIL (parent && cmd, NULL);
	if (type < 0 || type >= R_CORE_AUTOCMPLT_END) {
		return NULL;
	}
	RCoreAutocomplete *autocmpl = R_NEW0 (RCoreAutocomplete);
	// TODO: use rlist or so
	RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds + 1) * sizeof (RCoreAutocomplete*));
	if (!updated) {
		free (autocmpl);
		return NULL;
	}
	parent->subcmds = updated;
	parent->subcmds[parent->n_subcmds] = autocmpl;
	parent->n_subcmds++;
	autocmpl->cmd = strdup (cmd);
	autocmpl->locked = lock;
	autocmpl->type = type;
	autocmpl->length = strlen (cmd);
	return autocmpl;
}

R_API void r_core_autocomplete_free(RCoreAutocomplete *obj) {
	if (obj) {
		int i;
		for (i = 0; i < obj->n_subcmds; i++) {
			r_core_autocomplete_free (obj->subcmds[i]);
			obj->subcmds[i] = NULL;
		}
		free (obj->subcmds);
		free (obj->cmd);
		free (obj);
	}
}

R_API RCoreAutocomplete *r_core_autocomplete_find(RCoreAutocomplete *parent, const char* cmd, bool exact) {
	R_RETURN_VAL_IF_FAIL (parent && cmd, NULL);
	size_t len = strlen (cmd);
	int i;
	for (i = 0; i < parent->n_subcmds; i++) {
		if (exact && len != parent->subcmds[i]->length) {
			continue;
		}
		if (!strncmp (cmd, parent->subcmds[i]->cmd, len)) {
			return parent->subcmds[i];
		}
	}
	return NULL;
}

R_API bool r_core_autocomplete_remove(RCoreAutocomplete *parent, const char* cmd) {
	R_RETURN_VAL_IF_FAIL (parent && cmd, false);
	int i, j;
	for (i = 0; i < parent->n_subcmds; i++) {
		RCoreAutocomplete *ac = parent->subcmds[i];
		if (ac->locked) {
			continue;
		}
		// if (!strncmp (parent->subcmds[i]->cmd, cmd, parent->subcmds[i]->length)) {
		if (r_str_glob (ac->cmd, cmd)) {
			for (j = i + 1; j < parent->n_subcmds; j++) {
				parent->subcmds[j - 1] = parent->subcmds[j];
				parent->subcmds[j] = NULL;
			}
			r_core_autocomplete_free (ac);
			RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds - 1) * sizeof (RCoreAutocomplete*));
			if (!updated && (parent->n_subcmds - 1) > 0) {
				R_LOG_INFO ("Something really bad has happen.. this should never ever happen");
				return false;
			}
			parent->subcmds = updated;
			parent->n_subcmds--;
			i--;
		}
	}
	return false;
}

/* Config helper function for RTable */
R_API RTable *r_core_table_new(RCore *core, const char *title) {
	int maxcol = r_config_get_i (core->config, "cfg.table.maxcol");
	bool wrap = r_config_get_b (core->config, "cfg.table.wrap");
	const char *format = r_config_get (core->config, "cfg.table.format");
	RTable *table = r_table_new (title);
	table->cons = core->cons;
	// ut16 mode = SHOW_FANCY | SHOW_HEADER;
	ut16 mode = SHOW_HEADER;
	if (!strcmp (format, "fancy")) {
		mode = SHOW_FANCY | SHOW_HEADER;
	} else if (!strcmp (format, "simple")) {
		mode = 0;
	} else if (r_str_startswith (format, "ascii")) {
		mode = SHOW_FANCY | SHOW_HEADER;
	} else if (!strcmp (format, "csv")) {
		mode = SHOW_CSV;
	} else if (!strcmp (format, "tsv")) {
		mode = SHOW_TSV;
	} else if (!strcmp (format, "r2")) {
		mode = SHOW_R2;
	} else if (!strcmp (format, "json")) {
		mode = SHOW_JSON;
	} else if (!strcmp (format, "sql")) {
		mode = SHOW_SQL;
	}
	table->showMode = mode;
	table->maxColumnWidth = maxcol;
	table->wrapColumns = wrap;
	return table;
}

/* Config helper function for PJ json encodings */
R_API PJ *r_core_pj_new(RCore *core) {
	const char *se = r_config_get (core->config, "cfg.json.str");
	const char *ne = r_config_get (core->config, "cfg.json.num");
	PJEncodingNum number_encoding = PJ_ENCODING_NUM_DEFAULT;
	PJEncodingStr string_encoding = PJ_ENCODING_STR_DEFAULT;

	if (r_str_startswith (ne, "str")) {
		number_encoding = PJ_ENCODING_NUM_STR;
	} else if (strstr (ne, "hex")) {
		number_encoding = PJ_ENCODING_NUM_HEX;
	}
	if (!strcmp (se, "base64")) {
		string_encoding = PJ_ENCODING_STR_BASE64;
	} else if (!strcmp (se, "hex")) {
		string_encoding = PJ_ENCODING_STR_HEX;
	} else if (!strcmp (se, "array")) {
		string_encoding = PJ_ENCODING_STR_ARRAY;
	} else if (!strcmp (se, "strip")) {
		string_encoding = PJ_ENCODING_STR_STRIP;
	}
	return pj_new_with_encoding (string_encoding, number_encoding);
}

static void channel_stop(void *u) {
	// RCore *core = (RCore *)u;
	RThreadChannelPromise *promise = (RThreadChannelPromise*)u;
	promise->tc->responses = NULL;
	r_th_lock_leave (promise->tc->lock);
#if 0
	r_th_lock_free (promise->tc->lock);
#endif
	promise->tc->lock = NULL;
//	r_th_channel_promise_free (promise);
#if 0
	r_th_channel_free (core->chan);
	core->chan = NULL;
#endif
}

// reentrant version of RCore.cmd()
R_API char *r_core_cmd_str_r(RCore *core, const char *cmd) {
	if (r_str_startswith (cmd, "::")) {
		return NULL;
	}
	if (!core->chan) {
		core->chan = r_th_channel_new (thchan_handler, core);
	}
	RThreadChannelMessage *message = r_th_channel_message_new (core->chan, (const ut8*)cmd, strlen (cmd) + 1);
	RThreadChannelPromise *promise = r_th_channel_query (core->chan, message);
	r_cons_break_push (core->cons, channel_stop, promise);
	RThreadChannelMessage *response = r_th_channel_promise_wait (promise);
	char *res = NULL;
	if (response) {
		res = response->msg? strdup ((const char *)response->msg): NULL;
	}
	// r_cons_printf ("%s", response->msg);
	r_th_channel_message_free (message);
	r_th_channel_promise_free (promise);
	if (response && message != response) {
		r_th_channel_message_free (response);
	}
	r_cons_break_pop (core->cons);
	return res;
}
