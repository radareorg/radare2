/* radare - LGPL - Copyright 2009-2026 - pancake, nibble */
/* Autoname analysis plugin: automatically names functions based on references */

#define R_LOG_ORIGIN "anal.autoname"

#include <r_anal.h>
#include <r_core.h>

static const char *blacklist[] = {
	"0x", "*", "func.", "\\", "fcn.0", "plt", "assert",
	"__stack_chk_guard", "__stderrp", "__stdinp", "__stdoutp",
	"_DefaultRuneLocale"
};

static bool blacklisted_word(const char *name) {
	if (!*name || *name == ';') {
		return true;
	}
	if (r_str_startswith (name, "arg")) {
		return true;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (blacklist); i++) {
		if (strstr (name, blacklist[i])) {
			return true;
		}
	}
	return false;
}

static bool is_valid_function_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const char *p = name;
	while (*p) {
		if (!IS_PRINTABLE (*p)) {
			return false;
		}
		p++;
	}
	if (r_str_startswith (name, "str.") ||
			r_str_startswith (name, "func.") ||
			r_str_startswith (name, "fcn.")) {
		return false;
	}
	return !blacklisted_word (name);
}

static inline ut64 cmpstrings(const void *a) {
	return r_str_hash64 (a);
}

// Fast path: use xrefs/flags to derive a function name
static char *autoname_fast(RAnal *anal, RAnalFunction *fcn, int mode) {
	RList *names = r_list_newf (free);
	if (!names) {
		return NULL;
	}
	RAnalRef *ref;
	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			const int type = ref->type & R_ANAL_REF_TYPE_MASK;
			switch (type) {
			case R_ANAL_REF_TYPE_CODE:
			case R_ANAL_REF_TYPE_CALL:
			case R_ANAL_REF_TYPE_ICOD:
			case R_ANAL_REF_TYPE_JUMP:
				break;
			default:
				continue;
			}
			// use flag bind to look up the flag at reference address
			RFlagItem *f = anal->flb.get_at
				? anal->flb.get_at (anal->flb.f, ref->addr, false)
				: NULL;
			if (!f) {
				continue;
			}
			const char *name = f->name;
			if (blacklisted_word (name)) {
				continue;
			}
			const char *last_dot = r_str_rchr (name, NULL, '.');
			const char *base_name = last_dot ? last_dot + 1 : name;
			char *filtered = r_name_filter_dup (base_name);
			if (filtered) {
				r_list_append (names, r_str_newf ("auto.sub.%s", filtered));
				free (filtered);
			}
		}
	}
	if (!blacklisted_word (fcn->name)) {
		char *filtered = r_name_filter_dup (fcn->name);
		if (filtered) {
			r_list_append (names, filtered);
		}
	}
	RVecAnalRef_free (refs);

	char *final_name = NULL;
	r_list_uniq_inplace (names, cmpstrings);
	if (mode == 'l') {
		RListIter *iter;
		char *n;
		r_list_foreach (names, iter, n) {
			if (anal->coreb.cmd) {
				char *line = r_str_newf ("?e %s", n);
				anal->coreb.cmd (anal->coreb.core, line);
				free (line);
			}
		}
	} else {
		RListIter *iter;
		char *n;
		char *best_name = NULL;
		r_list_foreach (names, iter, n) {
			if (is_valid_function_name (n)) {
				if (!best_name || strlen (n) < strlen (best_name)) {
					free (best_name);
					best_name = strdup (n);
				}
			}
		}
		if (!best_name) {
			const char *first_name = r_list_first (names);
			if (first_name) {
				best_name = strdup (first_name);
			}
		}
		final_name = best_name;
	}
	r_list_free (names);
	return final_name;
}

// Slow path: use emulation (pdsfq) to resolve more string references
static char *autoname_slow(RAnal *anal, RAnalFunction *fcn, int mode) {
	if (!anal->coreb.cmdStr) {
		return autoname_fast (anal, fcn, mode);
	}
	void *core = anal->coreb.core;
	RList *names = r_list_newf (free);
	if (!names) {
		return NULL;
	}
	if (!blacklisted_word (fcn->name)) {
		char *filtered = r_name_filter_dup (fcn->name);
		if (filtered) {
			r_list_append (names, filtered);
		}
	}
	char *bestname = NULL;
	char *fd_cmd = r_str_newf ("fd @ 0x%08"PFMT64x, fcn->addr);
	char *fd = anal->coreb.cmdStr (core, fd_cmd);
	free (fd_cmd);
	if (!fd) {
		fd = strdup ("");
	}
	if (r_str_startswith (fd, "sym.") && !r_str_startswith (fd, "sym.func.")) {
		r_str_trim (fd);
		char *filtered = r_name_filter_dup (fd);
		if (filtered) {
			r_list_append (names, filtered);
			bestname = strdup (filtered);
		}
	}
	free (fd);

	// disable colors for pdsfq output
	int scr_color = anal->coreb.cfgGetI
		? anal->coreb.cfgGetI (core, "scr.color")
		: 0;
	if (anal->coreb.cmd) {
		anal->coreb.cmd (core, "e scr.color=0");
	}
	char *pdsfq_cmd = r_str_newf ("pdsfq @ 0x%08"PFMT64x, fcn->addr);
	char *pdsfq = anal->coreb.cmdStr (core, pdsfq_cmd);
	free (pdsfq_cmd);
	if (anal->coreb.cmd) {
		char *restore = r_str_newf ("e scr.color=%d", scr_color);
		anal->coreb.cmd (core, restore);
		free (restore);
	}

	if (!pdsfq) {
		pdsfq = strdup ("");
	}
	RList *strings = r_str_split_list (pdsfq, "\n", 0);
	char *name;
	RListIter *iter;
	r_list_foreach (strings, iter, name) {
		r_str_trim (name);
		char *fcn0 = strstr (name, "fcn.0");
		if (fcn0) {
			*fcn0 = 0;
		}
		if (blacklisted_word (name)) {
			continue;
		}
		char *bra = strchr (name, '[');
		if (bra) {
			r_str_cpy (name, bra + 1);
		} else {
			char *dot = strchr (name, '.');
			if (dot) {
				name = dot + 1;
			}
		}
		if (*name) {
			char *filtered = r_name_filter_dup (name);
			if (filtered) {
				r_list_append (names, strdup (filtered));
				free (filtered);
			}
		}
	}
	r_list_free (strings);
	free (pdsfq);

	bool use_getopt = false;
	r_list_uniq_inplace (names, cmpstrings);
	r_list_foreach (names, iter, name) {
		if (mode == 'l') {
			if (anal->coreb.cmd) {
				char *line = r_str_newf ("?e %s", name);
				anal->coreb.cmd (core, line);
				free (line);
			}
		}
		if (strstr (name, "getopt") || strstr (name, "optind")) {
			use_getopt = true;
		} else if (r_str_startswith (name, "reloc.")) {
			name += 6;
		} else if (r_str_startswith (name, "sym.imp.")) {
			name += 4;
		} else if (r_str_startswith (name, "sym.")) {
			name += 4;
		} else if (r_str_startswith (name, "imp.")) {
			name += 4;
		}
		if (!bestname) {
			bestname = strdup (name);
		}
		if (mode == 's') {
			if (anal->coreb.cmd) {
				char *line = r_str_newf ("?e %s", name);
				anal->coreb.cmd (core, line);
				free (line);
			}
		}
	}
	r_list_free (names);

	if (use_getopt) {
		if (bestname && !strcmp (bestname, "main")) {
			return bestname;
		}
		free (bestname);
		return strdup ("main_args");
	}
	if (bestname) {
		if (r_str_startswith (bestname, "sym.") || r_str_startswith (bestname, "imp.")) {
			char *bn = r_str_newf ("sym.%s", bestname);
			if (r_str_startswith (bestname, "sym.")) {
				return bestname;
			}
			free (bestname);
			return bn;
		}
		char *ret;
		if (r_str_startswith (bestname, "sub.")) {
			ret = r_str_newf ("%s_%"PFMT64x, bestname, fcn->addr);
		} else {
			ret = r_str_newf ("sub.%s_%"PFMT64x, bestname, fcn->addr);
		}
		free (bestname);
		return ret;
	}
	return NULL;
}

// Main autoname dispatcher: choose fast or slow based on anal.slow config
static char *autoname_fcn(RAnal *anal, RAnalFunction *fcn, int mode) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	bool is_slow = anal->coreb.cfgGetB
		? anal->coreb.cfgGetB (anal->coreb.core, "anal.slow")
		: false;
	if (is_slow) {
		return autoname_slow (anal, fcn, mode);
	}
	return autoname_fast (anal, fcn, mode);
}

// Rename all functions that start with fcn.* or sym.func.*
static void autoname_all(RAnal *anal) {
	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, it, fcn) {
		if (!r_str_startswith (fcn->name, "fcn.") && !r_str_startswith (fcn->name, "sym.func.")) {
			continue;
		}
		char *name = autoname_fcn (anal, fcn, 0);
		if (!name) {
			continue;
		}
		// rename the flag via flag bind
		if (anal->flb.f) {
			RFlagItem *item = anal->flb.get
				? anal->flb.get (anal->flb.f, fcn->name)
				: NULL;
			if (item) {
				// use corebind cmd to rename flag properly
				if (anal->coreb.cmd) {
					char *cmd = r_str_newf ("fr %s %s", fcn->name, name);
					anal->coreb.cmd (anal->coreb.core, cmd);
					free (cmd);
				}
			}
		}
		free (fcn->name);
		fcn->name = name;
	}
}

// Read .gopclntab section to recover go function names
static void autoname_golang(RAnal *anal) {
	if (!anal->coreb.cmdStr || !anal->coreb.core) {
		R_LOG_ERROR ("This plugin requires an attached RCore");
		return;
	}
	void *core = anal->coreb.core;
	// Use the corebind cmd to find sections
	char *sections = anal->coreb.cmdStr (core, "iSq~.gopclntab");
	if (R_STR_ISEMPTY (sections)) {
		free (sections);
		R_LOG_ERROR ("Could not find .gopclntab section");
		return;
	}
	// Parse the section info: vaddr size vsize name
	char *line = sections;
	r_str_trim (line);
	char *sp = strchr (line, ' ');
	if (!sp) {
		free (sections);
		R_LOG_ERROR ("Could not parse .gopclntab section info");
		return;
	}
	ut64 gopclntab = r_num_get (NULL, line);
	free (sections);
	if (!gopclntab || gopclntab == UT64_MAX) {
		R_LOG_ERROR ("Could not find .gopclntab section");
		return;
	}

	int ptr_size = anal->config->bits / 8;
	ut64 offset = gopclntab + 2 * ptr_size;
	ut64 size_offset = gopclntab + 3 * ptr_size;
	ut8 temp_size[4] = {0};
	if (!anal->iob.read_at (anal->iob.io, size_offset, temp_size, 4)) {
		return;
	}
	ut32 size = r_read_le32 (temp_size);
	int num_syms = 0;
	if (anal->flb.push_fs) {
		anal->flb.push_fs (anal->flb.f, R_FLAGS_FS_SYMBOLS);
	}
	while (offset < gopclntab + size) {
		ut8 temp_delta[4] = {0};
		ut8 temp_func_addr[4] = {0};
		ut8 temp_func_name[4] = {0};
		if (!anal->iob.read_at (anal->iob.io, offset + ptr_size, temp_delta, 4)) {
			break;
		}
		ut32 delta = r_read_le32 (temp_delta);
		ut64 func_offset = gopclntab + delta;
		if (!anal->iob.read_at (anal->iob.io, func_offset, temp_func_addr, 4) ||
			!anal->iob.read_at (anal->iob.io, func_offset + ptr_size, temp_func_name, 4)) {
			break;
		}
		ut32 func_addr = r_read_le32 (temp_func_addr);
		ut32 func_name_offset = r_read_le32 (temp_func_name);
		ut8 func_name[64] = {0};
		anal->iob.read_at (anal->iob.io, gopclntab + func_name_offset, func_name, 63);
		if (func_name[0] == 0xff) {
			break;
		}
		r_name_filter ((char *)func_name, 0);
		char *flagname = r_str_newf ("sym.go.%s", func_name);
		if (flagname) {
			if (anal->flb.set) {
				anal->flb.set (anal->flb.f, flagname, func_addr, 1);
			}
			free (flagname);
		}
		offset += 2 * ptr_size;
		num_syms++;
	}
	if (anal->flb.pop_fs) {
		anal->flb.pop_fs (anal->flb.f);
	}
	if (num_syms) {
		R_LOG_INFO ("Found %d symbols and saved them at sym.go.*", num_syms);
	} else {
		R_LOG_ERROR ("Found no symbols");
	}
}

static char *autonamecmd(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, "autoname")) {
		return NULL;
	}
	static RCoreHelpMessage help_msg = {
		"Usage:", "a:autoname", "[subcmd]",
		"a:autoname", "", "autoname function at current offset",
		"a:autoname", " all", "autoname all fcn.*/sym.func.* functions",
		"a:autoname", " golang", "recover function names from .gopclntab",
		"a:autoname", " noreturn", "propagate noreturn to callers",
		"a:autoname", " list", "list candidate names for function at current offset",
		NULL
	};
	const char *arg = input + 8;
	while (*arg == ' ') {
		arg++;
	}

	if (*arg == '?') {
		if (anal->coreb.help && anal->coreb.core) {
			anal->coreb.help (anal->coreb.core, help_msg);
		}
		return strdup ("");
	}

	if (!*arg) {
		// autoname function at current address
		ut64 addr = anal->coreb.numGet
			? anal->coreb.numGet (anal->coreb.core, "$$")
			: 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
		if (fcn) {
			char *name = autoname_fcn (anal, fcn, 'v');
			if (name) {
				char *res = r_str_newf ("'0x%08"PFMT64x"'afnq %s", fcn->addr, name);
				free (name);
				return res;
			}
			return strdup ("");
		}
		R_LOG_ERROR ("No function at 0x%08"PFMT64x, addr);
		return strdup ("");
	}

	if (r_str_startswith (arg, "fcn ")) {
		// "autoname fcn <addr> <mode>" - internal API for r_core_anal_fcn_autoname
		const char *p = arg + 4;
		while (*p == ' ') {
			p++;
		}
		ut64 addr = r_num_get (NULL, p);
		const char *sp = strchr (p, ' ');
		int mode = (sp && sp[1] && sp[1] != '0') ? sp[1] : 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
		if (fcn) {
			char *name = autoname_fcn (anal, fcn, mode);
			return name ? name : strdup ("");
		}
		return strdup ("");
	}
	if (r_str_startswith (arg, "all")) {
		autoname_all (anal);
		return strdup ("");
	}
	if (r_str_startswith (arg, "golang")) {
		autoname_golang (anal);
		return strdup ("");
	}
	if (r_str_startswith (arg, "noreturn")) {
		// delegate to the existing core command
		if (anal->coreb.cmd) {
			anal->coreb.cmd (anal->coreb.core, "aanr");
		}
		return strdup ("");
	}
	if (r_str_startswith (arg, "list")) {
		ut64 addr = anal->coreb.numGet
			? anal->coreb.numGet (anal->coreb.core, "$$")
			: 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
		if (fcn) {
			free (autoname_fcn (anal, fcn, 'l'));
		} else {
			R_LOG_ERROR ("No function at 0x%08"PFMT64x, addr);
		}
		return strdup ("");
	}

	// unknown subcommand, show help
	if (anal->coreb.help && anal->coreb.core) {
		anal->coreb.help (anal->coreb.core, help_msg);
	}
	return strdup ("");
}

RAnalPlugin r_anal_plugin_autoname = {
	.meta = {
		.name = "autoname",
		.author = "pancake",
		.desc = "Automatic function naming based on references and emulation",
		.license = "LGPL3",
	},
	.cmd = autonamecmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_autoname,
	.version = R2_VERSION
};
#endif
