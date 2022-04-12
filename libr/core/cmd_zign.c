/* radare - LGPL - Copyright 2009-2021 - pancake, nibble */

#include <r_core.h>
#include <r_anal.h>
#include <r_sign.h>
#include <r_list.h>
#include <r_cons.h>
#include <r_util.h>

static const char *help_msg_z[] = {
	"Usage:", "z[*j-aof/cs] [args] ", "# Manage zignatures",
	"z", "", "show zignatures",
	"z.", "", "find matching zignatures in current offset",
	"zb", "[?][n=5]", "search for best match",
	"zd", "zignature", "diff current function and signature",
	"z*", "", "show zignatures in radare format",
	"zq", "", "show zignatures in quiet mode",
	"zj", "", "show zignatures in json format",
	"zk", "", "show zignatures in sdb format",
	"z-", "zignature", "delete zignature",
	"z-", "*", "delete all zignatures",
	"za", "[?]", "add zignature",
	"zg", "", "generate zignatures (alias for zaF)",
	"zo", "[?]", "manage zignature files",
	"zf", "[?]", "manage FLIRT signatures",
	"z/", "[?]", "search zignatures",
	"zc", "[?]", "compare current zignspace zignatures with another one",
	"zs", "[?]", "manage zignspaces",
	"zi", "", "show zignatures matching information",
	NULL
};

static const char *help_msg_zb[] = {
	"Usage:", "zb[r?] [args]", "# search for closest matching signatures",
	"zb ", "[n]", "find n closest matching zignatures to function at current offset",
	"zbr ", "zigname [n]", "search for n most similar functions to zigname",
	NULL
};

static const char *help_msg_z_slash[] = {
	"Usage:", "z/[f*] ", "# Search signatures (see 'e?search' for options)",
	"z/ ", "", "search zignatures on range and flag matches",
	"z/f ", "", "zignature search on known functions",
	"z/* ", "", "search zignatures on range and output radare commands",
	NULL
};

static const char *help_msg_za[] = {
	"Usage:", "za[fFM?] [args] ", "# Add zignature",
	"za ", "zigname type params", "add zignature",
	"zac ", "", "Compute collisions between signatures",
	"zaf ", "[fcnname] [zigname]", "create zignature for function",
	"zaF ", "", "generate zignatures for all functions",
	"zaM ", "", "Same as zaF but merge signatures of same name",
	"za?? ", "", "show extended help",
	NULL
};

static const char *help_msg_zf[] = {
	"Usage:", "zf[dsz] filename ", "# Manage FLIRT signatures",
	"zfd ", "filename", "open FLIRT file and dump",
	"zfs ", "filename", "open FLIRT file and scan",
	"zfs ", "/path/**.sig", "recursively search for FLIRT files and scan them (see dir.depth)",
	"zfz ", "filename", "open FLIRT file and get sig commands (zfz flirt_file > zignatures.sig)",
	NULL
};

static const char *help_msg_zo[] = {
	"Usage:", "zo[zs] filename ", "# Manage zignature files (see dir.zigns)",
	"zo ", "filename", "load zinatures from sdb file",
	"zoz ", "filename", "load zinatures from gzipped sdb file",
	"zos ", "filename", "save zignatures to sdb file (merge if file exists)",
	NULL
};

static const char *help_msg_zs[] = {
	"Usage:", "zs[+-*] [namespace] ", "# Manage zignspaces",
	"zs", "", "display zignspaces",
	"zs ", "zignspace", "select zignspace",
	"zs ", "*", "select all zignspaces",
	"zs-", "zignspace", "delete zignspace",
	"zs-", "*", "delete all zignspaces",
	"zs+", "zignspace", "push previous zignspace and set",
	"zs-", "", "pop to the previous zignspace",
	"zsr ", "newname", "rename selected zignspace",
	NULL
};

static const char *help_msg_zc[] = {
	"Usage:", "zc[n!] other_space ", "# Compare zignspaces, match >= threshold (e zign.diff.*)",
	"zc", " other_space", "compare all current space with other_space",
	"zcn", " other_space", "compare current space with zigns with same name on other_space",
	"zcn!", " other_space", "same as above but show the ones not matching",
	NULL
};

static bool addGraphZign(RCore *core, const char *name, RList *args) {
	RSignGraph graph = { .cc = -1, .nbbs = -1, .edges = -1, .ebbs = -1, .bbsum = 0 };

	char *ptr;
	RListIter *iter;
	r_list_foreach (args, iter, ptr) {
		if (r_str_startswith (ptr, "cc=")) {
			graph.cc = atoi (ptr + 3);
		} else if (r_str_startswith (ptr, "nbbs=")) {
			graph.nbbs = atoi (ptr + 5);
		} else if (r_str_startswith (ptr, "edges=")) {
			graph.edges = atoi (ptr + 6);
		} else if (r_str_startswith (ptr, "ebbs=")) {
			graph.ebbs = atoi (ptr + 5);
		} else if (r_str_startswith (ptr, "bbsum=")) {
			graph.bbsum = atoi (ptr + 6);
		} else {
			return false;
		}
	}
	return r_sign_add_graph (core->anal, name, graph);
}

static inline bool za_add(RCore *core, const char *input) {
	char *args = r_str_trim_dup (input + 1);
	if (!args) {
		return false;
	}

	char *name = strtok (args, " ");
	char *stype = strtok (NULL, " ");
	char *sig = strtok (NULL, "");

	if (!stype || !sig || stype[1] != '\0') {
		eprintf ("Invalid input\n");
		free (args);
		return false;
	}
	char t = *stype;

	RList *lst = NULL;
	bool ret = false;
	switch (t) {
	case R_SIGN_BYTES:
		ret = r_sign_add_bytes (core->anal, name, sig);
		break;
	case R_SIGN_ANAL:
		ret = r_sign_add_anal (core->anal, name, sig);
		break;
	case R_SIGN_GRAPH:
		lst = r_str_split_list (sig, " ", 0);
		ret = addGraphZign (core, name, lst);
		break;
	case R_SIGN_COMMENT:
		ret = r_sign_add_comment (core->anal, name, sig);
		break;
	case R_SIGN_NAME:
		ret = r_sign_add_name (core->anal, name, sig);
		break;
	case R_SIGN_TYPES:
		ret = r_sign_add_types (core->anal, name, sig);
		break;
	case R_SIGN_OFFSET:
		{
			ut64 offset = r_num_get (core->num, sig);
			ret = r_sign_add_addr (core->anal, name, offset);
		}
		break;
	case R_SIGN_REFS:
		lst = r_str_split_list (sig, " ", 0);
		r_sign_add_refs (core->anal, name, lst);
		break;
	case R_SIGN_XREFS:
		lst = r_str_split_list (sig, " ", 0);
		r_sign_add_xrefs (core->anal, name, lst);
		break;
	case R_SIGN_VARS:
		r_sign_add_vars (core->anal, name, sig);
		break;
	case R_SIGN_BBHASH:
		ret = r_sign_add_hash (core->anal, name, t, sig, strlen (sig));
		break;
	default:
		eprintf ("error: unknown zignature type\n");
	}
	r_list_free (lst);
	free (args);
	return ret;
}

static int cmdAdd(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (*input) {
	case ' ': // "za"
		return za_add (core, input);
	case 'f': // "zaf"
		{
			char *args = r_str_trim_dup (input + 1);
			int n = r_str_word_set0 (args);

			if (n > 2) {
				eprintf ("Usage: zaf [fcnname] [zigname]\n");
				free (args);
				return false;
			}

			RAnalFunction *fcni = NULL;
			const char *zigname = (n == 2)? r_str_word_get0 (args, 1): NULL;
			if (n > 0) {
				fcni = r_anal_get_function_byname (core->anal, r_str_word_get0 (args, 0));
			} else {
				fcni = r_anal_get_function_at (core->anal, core->offset);
			}
			if (fcni) {
				r_sign_add_func (core->anal, fcni, zigname);
			}

			free (args);
			if (!fcni) {
				eprintf ("Could not find function");
				return false;
			}
		}
		break;
	case 'c': // "zac"
		r_cons_break_push (NULL, NULL);
		r_sign_resolve_collisions (core->anal);
		r_cons_break_pop ();
		break;
	case 'F': // "zaF"
	{
		int count = r_sign_all_functions (core->anal, false);
		eprintf ("generated zignatures: %d\n", count);
		break;
	}
	case 'M': // "zaM"
	{
		int count = r_sign_all_functions (core->anal, true);
		eprintf ("generated zignatures: %d\n", count);
		break;
	}
	case '?':
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			r_cons_printf ("Adding Zignatures (examples and documentation)\n\n"
				"Zignature types:\n"
				"  a: bytes pattern, r2 creates mask from analysis\n"
				"  b: bytes pattern\n"
				"  c: base64 comment\n"
				"  n: real function name\n"
				"  g: graph metrics\n"
				"  o: original offset\n"
				"  r: references\n"
				"  x: cross references\n"
				"  h: bbhash (hashing of fcn basic blocks)\n"
				"  v: vars (and args)\n"
				"Bytes patterns:\n"
				"  bytes can contain '..' (dots) to specify a binary mask\n\n"
				"Graph metrics:\n"
				"  cc:    cyclomatic complexity\n"
				"  edges: number of edges\n"
				"  nbbs:  number of basic blocks\n"
				"  ebbs:  number of end basic blocks\n\n"
				"Examples:\n"
				"  za foo b 558bec..e8........\n"
				"  za foo a e811223344\n"
				"  za foo g cc=2 nbbs=3 edges=3 ebbs=1\n"
				"  za foo g nbbs=3 edges=3\n"
				"  za foo v b-32 b-48 b-64\n"
				"  za foo o 0x08048123\n"
				"  za foo c this is a comment (base64?)\n"
				"  za foo r sym.imp.strcpy sym.imp.sprintf sym.imp.strlen\n"
				"  za foo h 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\n");
		} else {
			r_core_cmd_help (core, help_msg_za);
		}
		break;
	default:
		eprintf ("Usage: za[fF?] [args]\n");
		return false;
	}

	return true;
}

static int cmdOpen(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (*input) {
	case ' ':
		if (input[1]) {
			return r_sign_load (core->anal, input + 1, false);
		}
		eprintf ("Usage: zo filename\n");
		return false;
	case 's':
		if (input[1] == ' ' && input[2]) {
			return r_sign_save (core->anal, input + 2);
		}
		eprintf ("Usage: zos filename\n");
		return false;
	case 'z':
		if (input[1] == ' ' && input[2]) {
			return r_sign_load_gz (core->anal, input + 2, false);
		}
		eprintf ("Usage: zoz filename\n");
		return false;
	case '?':
		r_core_cmd_help (core, help_msg_zo);
		break;
	default:
		eprintf ("Usage: zo[zs] filename\n");
		return false;
	}

	return true;
}

static int cmdSpace(void *data, const char *input) {
	RCore *core = (RCore *) data;
	RSpaces *zs = &core->anal->zign_spaces;

	switch (*input) {
	case '+':
		if (!input[1]) {
			eprintf ("Usage: zs+zignspace\n");
			return false;
		}
		char *sp = r_str_trim_dup (input + 1);
		if (sp) {
			r_spaces_push (zs, sp);
			free (sp);
		}
		break;
	case 'r':
		if (input[1] != ' ' || !input[2]) {
			eprintf ("Usage: zsr newname\n");
			return false;
		}
		r_spaces_rename (zs, NULL, input + 2);
		break;
	case '-':
		if (input[1] == '\x00') {
			r_spaces_pop (zs);
		} else if (input[1] == '*') {
			r_spaces_unset (zs, NULL);
		} else {
			r_spaces_unset (zs, input + 1);
		}
		break;
	case 'j':
	case '*':
	case '\0':
		spaces_list (zs, input[0]);
		break;
	case ' ':
		if (!input[1]) {
			eprintf ("Usage: zs zignspace\n");
			return false;
		}
		r_spaces_set (zs, input + 1);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_zs);
		break;
	default:
		eprintf ("Usage: zs[+-*] [namespace]\n");
		return false;
	}

	return true;
}

static int cmdFlirt(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (*input) {
	case 'd':
		// TODO
		if (input[1] != ' ') {
			eprintf ("Usage: zfd filename\n");
			return false;
		}
		r_sign_flirt_dump (core->anal, input + 2);
		break;
	case 's':
		// TODO
		if (input[1] != ' ') {
			eprintf ("Usage: zfs filename\n");
			return false;
		}
		int depth = r_config_get_i (core->config, "dir.depth");
		char *file;
		RListIter *iter;
		RList *files = r_file_glob (input + 2, depth);
		r_list_foreach (files, iter, file) {
			r_sign_flirt_scan (core->anal, file);
		}
		r_list_free (files);
		break;
	case 'z':
		// TODO
		break;
	case '?':
		r_core_cmd_help (core, help_msg_zf);
		break;
	default:
		eprintf ("Usage: zf[dsz] filename\n");
		return false;
	}
	return true;
}

struct ctxSearchCB {
	RCore *core;
	bool bytes_only;
	bool rad;
	int collisions;
	int newfuncs;
	int count;
	int bytes_count;
	int graph_count;
	int offset_count;
	int refs_count;
	int types_count;
	int bbhash_count;
	int next_count;
};

static void apply_name(RCore *core, RAnalFunction *fcn, RSignItem *it, bool rad) {
	r_return_if_fail (core && fcn && it && it->name);
	const char *name = it->realname? it->realname: it->name;
	if (rad) {
		char *tmp = r_name_filter2 (name);
		if (tmp) {
			r_cons_printf ("\"afn %s @ 0x%08" PFMT64x "\"\n", tmp, fcn->addr);
			free (tmp);
		}
		return;
	}
	RFlagItem *flag = r_flag_get (core->flags, fcn->name);
	if (flag && flag->space && strcmp (flag->space->name, R_FLAGS_FS_FUNCTIONS)) {
		r_flag_rename (core->flags, flag, name);
	}
	r_anal_function_rename (fcn, name);
	if (core->anal->cb.on_fcn_rename) {
		core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, name);
	}
}

static void apply_flag(RCore *core, RSignItem *it, ut64 addr, int size, int count, const char *prefix, bool rad) {
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	char *name = r_str_newf ("%s.%s.%s_%d", zign_prefix, prefix, it->name, count);
	if (name) {
		if (rad) {
			char *tmp = r_name_filter2 (name);
			if (tmp) {
				r_cons_printf ("f %s %d @ 0x%08" PFMT64x "\n", tmp, size, addr);
				free (tmp);
			}
		} else {
			r_flag_set (core->flags, name, addr, size);
		}
		free (name);
	}
}

static int searchBytesHitCB(RSignItem *it, RSearchKeyword *kw, ut64 addr, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *)user;
	RAnalFunction *fcn = r_anal_get_fcn_in (ctx->core->anal, addr, 0);
	if (!fcn) {
		r_core_af (ctx->core, addr, NULL, false);
		fcn = r_anal_get_fcn_in (ctx->core->anal, addr, 0);
		ctx->newfuncs++;
		ctx->count++;
	}
	apply_flag (ctx->core, it, addr, kw->keyword_length, kw->count, "bytes", ctx->rad);
	if (ctx->bytes_only) {
		if (fcn) {
			char *tmp = NULL;
			apply_name (ctx->core, fcn, it, ctx->rad);
			if (it->types && (tmp = r_str_newf ("%s;", it->types))) { // apply types
				r_anal_str_to_fcn (ctx->core->anal, fcn, tmp);
				free (tmp);
			}
			if (it->vars) {
				r_anal_function_set_var_prot (fcn, it->vars);
			}
		}
		ctx->bytes_count++;
	}
	return 1;
}

static int fcnMatchCB(RSignItem *it, RAnalFunction *fcn, RSignType *types, void *user, RList *col) {
	r_return_val_if_fail (types && *types != R_SIGN_END, 1);
	struct ctxSearchCB *ctx = (struct ctxSearchCB *)user;
	ut64 sz = r_anal_function_realsize (fcn);
	RSignType t;
	bool collides = false;
	if (!col || !r_list_empty (col)) {
		// NULL col implies collision computation err, so assume collides
		collides = true;
		ctx->collisions++;
	}
	int i = 0;
	while ((t = types[i++]) != R_SIGN_END) {
		const char *prefix = NULL;
		switch (t) {
		case R_SIGN_BYTES:
			ctx->bytes_count++;
			prefix = "bytes_func";
			break;
		case R_SIGN_GRAPH:
			prefix = "graph";
			ctx->graph_count++;
			break;
		case R_SIGN_OFFSET:
			prefix = "offset";
			ctx->offset_count++;
			break;
		case R_SIGN_REFS:
			prefix = "refs";
			ctx->refs_count++;
			break;
		case R_SIGN_TYPES:
			prefix = "types";
			ctx->types_count++;
			break;
		case R_SIGN_BBHASH:
			prefix = "bbhash";
			ctx->bbhash_count++;
			break;
		case R_SIGN_NEXT:
			prefix = "next";
			ctx->next_count++;
			break;
		default:
			r_warn_if_reached ();
			break;
		}
		if (prefix) {
			char *tmp = NULL;
			if (collides && (tmp = r_str_newf ("%s_collision", prefix))) {
				apply_flag (ctx->core, it, fcn->addr, sz, ctx->count, tmp, ctx->rad);
				free (tmp);
			} else {
				apply_flag (ctx->core, it, fcn->addr, sz, ctx->count, prefix, ctx->rad);
			}
			ctx->count++;
		}
	}

	if (!collides) {
		char *tmp = NULL;
		apply_name (ctx->core, fcn, it, ctx->rad);
		if (it->types && (tmp = r_str_newf ("%s;", it->types))) { // apply types
			r_anal_str_to_fcn (ctx->core->anal, fcn, tmp);
			free (tmp);
		}
		if (it->vars) {
			r_anal_function_set_var_prot (fcn, it->vars);
		}
	}
	return 1;
}

static bool searchRange(RCore *core, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;
	int minsz = r_config_get_i (core->config, "zign.minsz");

	if (!buf) {
		return false;
	}
	RSignSearch *ss = r_sign_search_new ();
	ss->search->align = r_config_get_i (core->config, "search.align");
	r_sign_search_init (core->anal, ss, minsz, searchBytesHitCB, ctx);

	r_cons_break_push (NULL, NULL);
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_is_breaked ()) {
			retval = false;
			break;
		}
		rlen = R_MIN (core->blocksize, to - at);
		if (!r_io_is_valid_offset (core->io, at, 0)) {
			retval = false;
			break;
		}
		(void)r_io_read_at (core->io, at, buf, rlen);
		if (r_sign_search_update (core->anal, ss, &at, buf, rlen) == -1) {
			eprintf ("search: update read error at 0x%08" PFMT64x "\n", at);
			retval = false;
			break;
		}
	}
	r_cons_break_pop ();
	free (buf);
	r_sign_search_free (ss);

	return retval;
}

static void search_add_to_types(RCore *c, RSignSearchMetrics *sm, RSignType t, const char *str, unsigned int *i) {
	unsigned int count = *i;
	r_return_if_fail (count < sizeof (sm->stypes) / sizeof (RSignType) - 1);
	if (r_config_get_i (c->config, str)) {
		sm->stypes[count++] = t;
		sm->stypes[count] = 0;
		*i = count;
	}
}

static bool fill_search_metrics(RSignSearchMetrics *sm, RCore *c, void *user) {
	unsigned int i = 0;
	sm->stypes[0] = R_SIGN_END;
	search_add_to_types (c, sm, R_SIGN_BYTES, "zign.bytes", &i);
	search_add_to_types (c, sm, R_SIGN_GRAPH, "zign.graph", &i);
	search_add_to_types (c, sm, R_SIGN_OFFSET, "zign.offset", &i);
	search_add_to_types (c, sm, R_SIGN_REFS, "zign.refs", &i);
	search_add_to_types (c, sm, R_SIGN_BBHASH, "zign.hash", &i);
	search_add_to_types (c, sm, R_SIGN_TYPES, "zign.types", &i);
#if 0
	// untested
	search_add_to_types(c, sm, R_SIGN_VARS, "zign.vars", &i);
#endif
	sm->mincc = r_config_get_i (c->config, "zign.mincc");
	sm->minsz = r_config_get_i (c->config, "zign.minsz");
	sm->anal = c->anal;
	sm->cb = fcnMatchCB;
	sm->user = user;
	return (i > 0);
}

static void print_ctx_hits(struct ctxSearchCB *ctx) {
	int prints = 0;
	if (ctx->newfuncs) {
		eprintf ("New functions:  %d\n", ctx->newfuncs);
	}
	if (ctx->collisions) {
		eprintf ("collisions:  %d\n", ctx->collisions);
	}
	if (ctx->bytes_count) {
		eprintf ("bytes:  %d\n", ctx->bytes_count);
		prints++;
	}
	if (ctx->graph_count) {
		eprintf ("graph:  %d\n", ctx->graph_count);
		prints++;
	}
	if (ctx->offset_count) {
		eprintf ("offset: %d\n", ctx->offset_count);
		prints++;
	}
	if (ctx->refs_count) {
		eprintf ("refs:   %d\n", ctx->refs_count);
		prints++;
	}
	if (ctx->types_count) {
		eprintf ("types:  %d\n", ctx->types_count);
		prints++;
	}
	if (ctx->bbhash_count) {
		eprintf ("bbhash: %d\n", ctx->bbhash_count);
		prints++;
	}
	if (ctx->next_count) {
		eprintf ("next: %d\n", ctx->next_count);
		prints++;
	}
	if (prints > 1) {
		eprintf ("total:  %d\n", ctx->count);
	}
}

static bool search(RCore *core, bool rad, bool only_func) {
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	struct ctxSearchCB ctx;
	memset (&ctx, 0, sizeof (struct ctxSearchCB));
	ctx.rad = rad;
	ctx.core = core;

	RSignSearchMetrics sm;
	bool metsearch = fill_search_metrics (&sm, core, (void *)&ctx);
	if (!metsearch) {
		eprintf ("No zign types enabled\n");
		return false;
	}
	if (sm.stypes[0] == R_SIGN_BYTES && sm.stypes[1] == R_SIGN_END) {
		ctx.bytes_only = true;
	}

	// Bytes search
	if (r_config_get_i (core->config, "zign.bytes") && !only_func) {
		const char *mode = r_config_get (core->config, "search.in");
		RList *list = r_core_get_boundaries_prot (core, -1, mode, "search");
		if (!list) {
			return false;
		}
		RListIter *iter;
		RIOMap *map;
		r_list_foreach (list, iter, map) {
			eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
			searchRange (core, r_io_map_begin (map), r_io_map_end (map), rad, &ctx);
		}
		r_list_free (list);
	}

	// Function search
	if (!ctx.bytes_only) {
		eprintf ("[+] searching function metrics\n");
		r_sign_metric_search (core->anal, &sm);
	}

	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}
	print_ctx_hits (&ctx);
	return ctx.count > 0? true: false;
}

static void print_possible_matches(RList *list, bool json, RCore *core) {
	RListIter *itr;
	RSignCloseMatch *row;
	if (json) {
		PJ *pj = core->anal->coreb.pjWithEncoding (core);
		pj_a (pj);
		r_list_foreach (list, itr, row) {
			pj_o (pj);
			pj_ks (pj, "name", row->item->name);
			pj_kd (pj, "similarity", row->score);
			pj_kd (pj, "byte similarity", row->bscore);
			pj_kd (pj, "graph similarity", row->gscore);
			pj_end (pj);
		}
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		r_list_foreach (list, itr, row) {
			// total score
			if (row->bscore > 0.0 && row->gscore > 0.0) {
				r_cons_printf ("%02.5lf  ", row->score);
			}
			if (row->bscore > 0.0) {
				r_cons_printf ("%02.5lf B  ", row->bscore);
			}
			if (row->gscore > 0.0) {
				r_cons_printf ("%02.5lf G  ", row->gscore);
			}
			r_cons_printf (" %s\n", row->item->name);
		}
	}
}

static RSignItem *item_frm_signame(RAnal *a, const char *signame) {
	// example zign|*|sym.unlink_blk
	const RSpace *space = r_spaces_current (&a->zign_spaces);
	char *k = r_str_newf ("zign|%s|%s", space? space->name: "*", signame);
	char *value = sdb_querys (a->sdb_zigns, NULL, 0, k);
	if (!value) {
		free (k);
		return NULL;
	}

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		free (k);
		free (value);
		return NULL;
	}

	if (!r_sign_deserialize (a, it, k, value)) {
		r_sign_item_free (it);
		it = NULL;
	}
	free (k);
	free (value);
	return it;
}

static double get_zb_threshold(RCore *core) {
	const char *th = r_config_get (core->config, "zign.threshold");
	double thresh = r_num_get_float (NULL, th);
	if (thresh < 0.0 || thresh > 1.0) {
		eprintf ("Invalid zign.threshold %s, using 0.0\n", th);
		thresh = 0.0;
	}
	return thresh;
}

static bool bestmatch_fcn(RCore *core, const char *input, bool json) {
	r_return_val_if_fail (input && core, false);

	char *argv = r_str_new (input);
	if (!argv) {
		return false;
	}

	int count = 5;
	char *zigname = strtok (argv, " ");
	if (!zigname) {
		eprintf ("Need a signature\n");
		free (argv);
		return false;
	}
	char *cs = strtok (NULL, " ");
	if (cs) {
		if ((count = atoi (cs)) <= 0) {
			free (argv);
			eprintf ("Invalid count\n");
			return false;
		}
		if (strtok (NULL, " ")) {
			free (argv);
			eprintf ("Too many parameters\n");
			return false;
		}
	}
	RSignItem *it = item_frm_signame (core->anal, zigname);
	if (!it) {
		eprintf ("Couldn't get signature for %s\n", zigname);
		free (argv);
		return false;
	}
	free (argv);

	if (!r_config_get_i (core->config, "zign.bytes")) {
		r_sign_bytes_free (it->bytes);
		it->bytes = NULL;
	}
	if (!r_config_get_i (core->config, "zign.graph")) {
		r_sign_graph_free (it->graph);
		it->graph = NULL;
	}

	double thresh = get_zb_threshold (core);
	RList *list = r_sign_find_closest_fcn (core->anal, it, count, thresh);
	r_sign_item_free (it);

	if (list) {
		print_possible_matches (list, json, core);
		r_list_free (list);
		return true;
	}
	return false;
}

static bool bestmatch_sig(RCore *core, const char *input, bool json) {
	r_return_val_if_fail (input && core, false);
	int count = 5;
	if (!R_STR_ISEMPTY (input)) {
		count = atoi (input);
		if (count <= 0) {
			eprintf ("[!!] invalid number %s\n", input);
			return false;
		}
	}

	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function at 0x%08" PFMT64x "\n", core->offset);
		return false;
	}

	RSignItem *item = r_sign_item_new ();
	if (!item) {
		return false;
	}

	if (r_config_get_i (core->config, "zign.bytes")) {
		r_sign_addto_item (core->anal, item, fcn, R_SIGN_BYTES);
		RSignBytes *b = item->bytes;
		int minsz = r_config_get_i (core->config, "zign.minsz");
		if (b && b->size < minsz) {
			eprintf ("Warning: Function signature is too small (%d < %d) See e zign.minsz \n", b->size, minsz);
		}
	}
	if (r_config_get_i (core->config, "zign.graph")) {
		r_sign_addto_item (core->anal, item, fcn, R_SIGN_GRAPH);
	}

	double th = get_zb_threshold (core);
	bool found = false;
	if (item->graph || item->bytes) {
		r_cons_break_push (NULL, NULL);
		RList *list = r_sign_find_closest_sig (core->anal, item, count, th);
		if (list) {
			found = true;
			print_possible_matches (list, json, core);
			r_list_free (list);
		}
		r_cons_break_pop ();
	} else {
		eprintf ("Warning: no signatures types available for testing\n");
	}

	r_sign_item_free (item);
	return found;
}

static bool bestmatch(void *data, const char *input) {
	r_return_val_if_fail (data && input, false);
	bool json = false;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'r':
		input++;
		if (*input == 'j') {
			input++;
			json = true;
		}
		return bestmatch_fcn (core, input, json);
	case 'j':
		json = true;
		/* fallthrough */
	case ' ':
		input++;
		/* fallthrough */
	case '\x00':
		return bestmatch_sig (core, input, json);
	case '?':
	default:
		r_core_cmd_help (core, help_msg_zb);
		return false;
	}
}

static bool _sig_bytediff_cb(RLevBuf *va, RLevBuf *vb, ut32 ia, ut32 ib) {
	RSignBytes *a = (RSignBytes *)va->buf;
	RSignBytes *b = (RSignBytes *)vb->buf;

	if ((a->bytes[ia] & a->mask[ia]) == (b->bytes[ib] & b->mask[ib])) {
		return false;
	}
	return true;
}

#define lines_addbytesmask(l, sig, index, add, col) \
	l.bytes = r_str_appendf (l.bytes, " %s%s%02x%s", r_str_get (col), r_str_get (add), sig->bytes[index], col? Color_RESET: ""); \
	l.mask = r_str_appendf (l.mask, " %s%s%02x%s", r_str_get (col), r_str_get (add), sig->mask[index], col? Color_RESET: ""); \
	l.land = r_str_appendf (l.land, " %s%s%02x%s", r_str_get (col), r_str_get (add), sig->bytes[index] & sig->mask[index], col?Color_RESET: ""); \
	index++;

#define lines_addblnk(l) \
	l.bytes = r_str_append (l.bytes, "    "); \
	l.mask = r_str_append (l.mask, "    "); \
	l.land = r_str_append (l.land, "    ");

#define freelines(x) \
	free (x.bytes); \
	free (x.mask); \
	free (x.land); \
	memset (&x, 0, sizeof (x));

static void print_zig_diff(RCore *c, RSignBytes *ab, RSignBytes *bb, RLevOp *ops) {
	struct lines {
		char *mask, *bytes, *land;
	} al, bl;
	memset (&al, 0, sizeof (al));
	memset (&bl, 0, sizeof (bl));

	char *colsub, *coladd, *coldel;
	colsub = coladd = coldel = NULL;
	if (r_config_get_b (c->config, "scr.color")) {
		coldel = "\x1b[1;31m";
		coladd = "\x1b[1;32m";
		colsub = "\x1b[1;33m";
	}

	int i, ia, ib, iastart, ibstart;
	ia = ib = iastart = ibstart = 0;
	bool printb = false;
	for (i = 0; ops[i] != LEVEND; i++) {
		switch (ops[i]) {
		case LEVNOP:
			// lines_addbytesmask macro does ia++ so test must before
			if (!printb && (ab->bytes[ia] != bb->bytes[ib] || ab->mask[ia] != bb->mask[ib])) {
				printb = true;
			}
			lines_addbytesmask (al, ab, ia, " ", (const char *)NULL);
			lines_addbytesmask (bl, bb, ib, " ", (const char *)NULL);
			break;
		case LEVSUB:
			lines_addbytesmask (al, ab, ia, " ", colsub);
			lines_addbytesmask (bl, bb, ib, "^", colsub);
			printb = true;
			break;
		case LEVADD:
			lines_addblnk (al);
			lines_addbytesmask (bl, bb, ib, "+", coladd);
			printb = true;
			break;
		case LEVDEL:
			lines_addbytesmask (al, ab, ia, "-", coldel);
			lines_addblnk (bl);
			printb = true;
			break;
		default:
			r_warn_if_reached ();
			freelines (al);
			freelines (bl);
			return;
		}
		// when alloc fails
		if (!(al.bytes && al.mask && al.land && bl.bytes && bl.mask && bl.land)) {
			freelines (al);
			freelines (bl);
			return;
		}

		if (i % 16 == 15 || ops[i + 1] == LEVEND) {
			if (i > 16) {
				r_cons_printf ("\n");
			}
			r_cons_printf ("Fnc cmp   0x%04x %s\n", iastart, al.land);
			if (printb) {
				r_cons_printf ("Sig cmp   0x%04x %s\n", ibstart, bl.land);
			}
			r_cons_printf ("Fnc Mask  0x%04x %s\n", iastart, al.mask);
			if (printb) {
				r_cons_printf ("Sig Mask  0x%04x %s\n", ibstart, bl.mask);
			}
			r_cons_printf ("Fnc Bytes 0x%04x %s\n", iastart, al.bytes);
			if (printb) {
				r_cons_printf ("Sig Bytes 0x%04x %s\n", ibstart, bl.bytes);
			} else {
				r_cons_printf ("== Signature was same ==\n");
			}
			freelines (al);
			freelines (bl);
			iastart = ia;
			ibstart = ib;
			printb = false;
		}
	}
}
#undef lines_addbytesmask
#undef lines_addblnk
#undef freelines

static bool diff_zig(void *data, const char *input) {
	r_return_val_if_fail (data && input, false);
	RCore *core = (RCore *)data;

	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function at 0x%08" PFMT64x "\n", core->offset);
		return false;
	}

	char *argv = r_str_new (input);
	if (!argv) {
		return false;
	}

	char *zigname = strtok (argv, " ");
	if (!zigname) {
		eprintf ("Need a signature\n");
		free (argv);
		return false;
	}

	if (strtok (NULL, " ")) {
		eprintf ("too many arguments");
		free (argv);
		return false;
	}

	RSignItem *it = item_frm_signame (core->anal, zigname);
	if (!it) {
		eprintf ("Couldn't get signature for %s\n", zigname);
		free (argv);
		return false;
	}
	free (argv);

	if (!it->bytes) {
		eprintf ("Signature %s missing bytes\n", it->name);
		return false;
	}

	RLevBuf b;
	b.buf = it->bytes;
	b.len = it->bytes->size;

	RSignItem *fit = r_sign_item_new ();
	if (!fit) {
		r_sign_item_free (it);
		return false;
	}
	r_sign_addto_item (core->anal, fit, fcn, R_SIGN_BYTES);

	RLevBuf a;
	a.buf = fit->bytes;
	a.len = fit->bytes->size;

	RLevOp *ops = NULL;

	if (r_diff_levenshtein_path (&a, &b, UT32_MAX, _sig_bytediff_cb, &ops) < 0) {
		eprintf ("Diff failed\n");
	} else {
		print_zig_diff (core, fit->bytes, it->bytes, ops);
	}

	free (ops);
	r_sign_item_free (fit);
	r_sign_item_free (it);
	return false;
}

static int cmdCompare(void *data, const char *input) {
	int result = true;
	RCore *core = (RCore *)data;
	const char *raw_bytes_thresh = r_config_get (core->config, "zign.diff.bthresh");
	const char *raw_graph_thresh = r_config_get (core->config, "zign.diff.gthresh");
	RSignOptions *options = r_sign_options_new (raw_bytes_thresh, raw_graph_thresh);

	switch (*input) {
	case ' ':
		if (!input[1]) {
			eprintf ("Usage: zc other_space\n");
			result = false;
			break;
		}
		result = r_sign_diff (core->anal, options, input + 1);
		break;
	case 'n':
		switch (input[1]) {
		case ' ':
			if (!input[2]) {
				eprintf ("Usage: zcn other_space\n");
				result = false;
				break;
			}
			result = r_sign_diff_by_name (core->anal, options, input + 2, false);
			break;
		case '!':
			if (input[2] != ' ' || !input[3]) {
				eprintf ("Usage: zcn! other_space\n");
				result = false;
				break;
			}
			result = r_sign_diff_by_name (core->anal, options, input + 3, true);
			break;
		default:
			eprintf ("Usage: zcn! other_space\n");
			result = false;
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_zc);
		break;
	default:
		eprintf ("Usage: zc[?n!] other_space\n");
		result = false;
	}

	r_sign_options_free (options);

	return result;
}

static int cmdCheck(void *data, const char *input) {
	RCore *core = (RCore *) data;
	struct ctxSearchCB ctx;
	memset (&ctx, 0, sizeof (struct ctxSearchCB));
	ctx.rad = input[0] == '*';
	ctx.core = core;

	RSignSearchMetrics sm;
	if (!fill_search_metrics (&sm, core, (void *)&ctx)) {
		eprintf ("Nothing to search for\n");
		return 0;
	}

	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	if (ctx.rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	eprintf ("[+] searching function metrics\n");
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);
	if (fcn) {
		r_cons_break_push (NULL, NULL);
		r_sign_fcn_match_metrics (&sm, fcn);
		r_cons_break_pop ();
	} else {
		eprintf ("No function at 0x%08" PFMT64x "\n", core->offset);
	}

	if (ctx.rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	print_ctx_hits (&ctx);
	return ctx.count;
}

static int cmdSearch(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case 0:
	case '*': // "z/*"
		return search (core, input[0] == '*', false);
	case 'f': // "z/f"
		switch (input[1]) {
		case 0:
		case '*':
			return search (core, input[1] == '*', true);
		default:
			eprintf ("Usage: z/[f*]\n");
			return false;
		}
	case '?':
		r_core_cmd_help (core, help_msg_z_slash);
		break;
	default:
		eprintf ("Usage: z/[f*]\n");
		return false;
	}
	return true;
}

static int cmdInfo(void *data, const char *input) {
	if (!data || !input) {
		return false;
	}
	RCore *core = (RCore *) data;
	r_flag_space_push (core->flags, R_FLAGS_FS_SIGNS);
	r_flag_list (core->flags, *input, input[0] ? input + 1: "");
	r_flag_space_pop (core->flags);
	return true;
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *) data;
	const char *arg = input + 1;

	switch (*input) {
	case '\0':
	case '*': // "z*"
	case 'q': // "zq"
	case 'j': // "zj"
		r_sign_list (core->anal, *input);
		break;
	case 'k': // "zk"
		r_core_cmd0 (core, "k anal/zigns/*");
		break;
	case '-': // "z-"
		r_sign_delete (core->anal, arg);
		break;
	case '.': // "z."
		return cmdCheck (data, arg);
	case 'b': // "zb"
		return bestmatch (data, arg);
	case 'd': // "zb"
		return diff_zig (data, arg);
	case 'o': // "zo"
		return cmdOpen (data, arg);
	case 'g': // "zg"
		return cmdAdd (data, "F");
	case 'a': // "za"
		return cmdAdd (data, arg);
	case 'f': // "zf"
		return cmdFlirt (data, arg);
	case '/': // "z/"
		return cmdSearch (data, arg);
	case 'c': // "zc"
		return cmdCompare (data, arg);
	case 's': // "zs"
		return cmdSpace (data, arg);
	case 'i': // "zi"
		return cmdInfo (data, arg);
	case '?': // "z?"
		r_core_cmd_help (core, help_msg_z);
		break;
	default:
		r_core_cmd_help (core, help_msg_z);
		return false;
	}

	return true;
}
