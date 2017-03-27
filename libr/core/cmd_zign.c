/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_core.h>
#include <r_anal.h>
#include <r_sign.h>
#include <r_list.h>
#include <r_cons.h>
#include <r_util.h>

static bool addFcnBytes(RCore *core, RAnalFunction *fcn, const char *name) {
	ut8 *buf = NULL;
	int fcnlen = 0, len = 0;
	int minzlen = r_config_get_i (core->config, "zign.min");
	int maxzlen = r_config_get_i (core->config, "zign.max");
	bool retval = true;

	fcnlen = r_anal_fcn_realsize (fcn);

	if (fcnlen < minzlen) {
		eprintf ("warn: omitting %s zignature is too small. Length is %d. Check zign.min.\n",
			fcn->name, fcnlen);
		retval = false;
		goto exit_function;
	}

	len = R_MIN (fcnlen, maxzlen);

	buf = malloc (len);

	if (r_io_read_at (core->io, fcn->addr, buf, len) != len) {
		eprintf ("error: cannot read at 0x%08"PFMT64x"\n", fcn->addr);
		retval = false;
		goto exit_function;
	}

	retval = r_sign_add_anal (core->anal, name, len, buf, fcn->addr);

exit_function:
	free (buf);

	return retval;
}

static bool addFcnGraph(RCore *core, RAnalFunction *fcn, const char *name) {
	RSignGraph graph;

	graph.cc = r_anal_fcn_cc (fcn);
	graph.nbbs = r_list_length (fcn->bbs);
	graph.edges = r_anal_fcn_count_edges (fcn, &graph.ebbs);

	return r_sign_add_graph (core->anal, name, graph);
}

static bool addFcnZign(RCore *core, RAnalFunction *fcn, const char *name) {
	char *zigname = NULL;
	bool retval = true;
	int curspace = core->anal->zign_spaces.space_idx;

	if (name) {
		zigname = r_str_new (name);
	} else {
		if (curspace != -1) {
			zigname = r_str_newf ("%s.", core->anal->zign_spaces.spaces[curspace]);
		}
		zigname = r_str_appendf (zigname, "%s", fcn->name);
	}

	if (!addFcnGraph (core, fcn, zigname)) {
		eprintf ("error: could not add graph zignature for fcn %s\n", fcn->name);
		retval = false;
		goto exit_function;
	}
	if (!addFcnBytes (core, fcn, zigname)) {
		eprintf ("error: could not add anal zignature for fcn %s\n", fcn->name);
		retval = false;
		goto exit_function;
	}

exit_function:
	free (zigname);

	return retval;
}

static bool parseGraphMetrics(const char *args0, int nargs, RSignGraph *graph) {
	const char *ptr = NULL;
	int i = 0;
	bool retval = true;

	graph->cc = -1;
	graph->nbbs = -1;
	graph->edges = -1;
	graph->ebbs = -1;

	for (i = 0; i < nargs; i++) {
		ptr = r_str_word_get0 (args0, i);
		if (r_str_startswith (ptr, "cc=")) {
			graph->cc = atoi (ptr + 3);
		} else if (r_str_startswith (ptr, "nbbs=")) {
			graph->nbbs = atoi (ptr + 5);
		} else if (r_str_startswith (ptr, "edges=")) {
			graph->edges = atoi (ptr + 6);
		} else if (r_str_startswith (ptr, "ebbs=")) {
			graph->ebbs = atoi (ptr + 5);
		} else {
			retval = false;
			break;
		}
	}

	return retval;
}

static bool addGraphZign(RCore *core, const char *name, const char *args0, int nargs) {
	RSignGraph graph;

	if (!parseGraphMetrics (args0, nargs, &graph)) {
		eprintf ("error: invalid arguments\n");
		return false;
	}

	return r_sign_add_graph (core->anal, name, graph);
}

static bool addBytesZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	const char *hexbytes = NULL;
	ut8 *mask = NULL, *bytes = NULL;
	int size = 0, blen = 0;
	bool retval = true;

	if (nargs != 1) {
		eprintf ("error: invalid syntax\n");
		retval = false;
		goto exit_function;
	}

	hexbytes = r_str_word_get0 (args0, 0);
	blen = strlen (hexbytes) + 4;
	bytes = malloc (blen);
	mask = malloc (blen);

	size = r_hex_str2binmask (hexbytes, bytes, mask);
	if (size <= 0) {
		eprintf ("error: cannot parse hexpairs\n");
		retval = false;
		goto exit_function;
	}

	switch (type) {
	case R_SIGN_BYTES:
		retval = r_sign_add_bytes (core->anal, name, size, bytes, mask);
		break;
	case R_SIGN_ANAL:
		retval = r_sign_add_anal (core->anal, name, size, bytes, 0);
		break;
	}

exit_function:
	free (bytes);
	free (mask);

	return retval;
}

static bool addZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	switch (type) {
	case R_SIGN_BYTES:
	case R_SIGN_ANAL:
		return addBytesZign (core, name, type, args0, nargs);
	case R_SIGN_GRAPH:
		return addGraphZign (core, name, args0, nargs);
	default:
		eprintf ("error: unknown zignature type\n");
	}

	return false;
}

static int cmdAdd(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case ' ':
		{
			const char *zigname = NULL, *args0 = NULL;
			char *args = NULL;
			int type = 0, n = 0;
			bool retval = true;

			args = r_str_new (input + 1);
			n = r_str_word_set0 (args);

			if (n < 3) {
				eprintf ("usage: za zigname type params\n");
				retval = false;
				goto exit_case_manual;
			}

			zigname = r_str_word_get0 (args, 0);
			type = r_str_word_get0 (args, 1)[0];
			args0 = r_str_word_get0 (args, 2);

			if (!addZign (core, zigname, type, args0, n - 2)) {
				eprintf ("error: cannot add zignature\n");
				retval = false;
				goto exit_case_manual;
			}

exit_case_manual:
			free (args);
			return retval;
		}
		break;
	case 'f':
		{
			RAnalFunction *fcni = NULL;
			RListIter *iter = NULL;
			const char *fcnname = NULL, *zigname = NULL;
			char *args = NULL;
			int n = 0;
			bool retval = true;

			args = r_str_new (r_str_trim_const (input + 1));
			n = r_str_word_set0 (args);

			if (n > 2) {
				eprintf ("usage: zaf [fcnname] [zigname]\n");
				retval = false;
				goto exit_case_fcn;
			}

			switch (n) {
			case 2:
				zigname = r_str_word_get0 (args, 1);
			case 1:
				fcnname = r_str_word_get0 (args, 0);
			}

			r_cons_break_push (NULL, NULL);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if ((!fcnname && core->offset == fcni->addr) ||
					(fcnname && !strcmp (fcnname, fcni->name))) {
					if (!addFcnZign (core, fcni, zigname)) {
						eprintf ("error: could not add zignature for fcn %s\n", fcni->name);
					}
					break;
				}
			}
			r_cons_break_pop ();

exit_case_fcn:
			free (args);
			return retval;
		}
		break;
	case 'F':
		{
			RAnalFunction *fcni = NULL;
			RListIter *iter = NULL;
			int count = 0;

			r_cons_break_push (NULL, NULL);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (!addFcnZign (core, fcni, NULL)) {
					eprintf ("error: could not add zignature for fcn %s\n", fcni->name);
					continue;
				}
				count++;
			}
			r_cons_break_pop ();
			eprintf ("generated zignatures: %d\n", count);
		}
		break;
	case '?':
		if (input[1] == '?') {
			r_cons_printf ("Adding Zignatures (examples and documentation)\n\n"
				"Zignature types:\n"
				"  b: bytes pattern\n"
				"  a: bytes pattern (anal mask)\n"
				"  g: graph metrics\n\n"
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
				"  za foo g nbbs=3 edges=3\n");
		} else {
			const char *help_msg[] = {
				"Usage:", "za[fF?] [args] ", "# Add zignature",
				"za ", "zigname type params", "add zignature",
				"zaf ", "[fcnname] [zigname]", "create zignature for function",
				"zaF ", "", "generate zignatures for all functions",
				"za?? ", "", "show extended help",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: za[fF?] [args]\n");
		return false;
	}

	return true;
}

static bool loadGzSdb(RAnal *a, const char *filename) {
	ut8 *buf = NULL;
	int size = 0;
	char *tmpfile = NULL;
	bool retval = true;

	if (!r_file_exists (filename)) {
		eprintf ("error: file %s does not exist\n", filename);
		retval = false;
		goto exit_function;
	}

	if (!(buf = r_file_gzslurp (filename, &size, 0))) {
		eprintf ("error: cannot decompress file\n");
		retval = false;
		goto exit_function;
	}

	if (!(tmpfile = r_file_temp ("r2zign"))) {
		eprintf ("error: cannot create temp file\n");
		retval = false;
		goto exit_function;
	}

	if (!r_file_dump (tmpfile, buf, size, 0)) {
		eprintf ("error: cannot dump file\n");
		retval = false;
		goto exit_function;
	}

	if (!r_sign_load (a, tmpfile)) {
		eprintf ("error: cannot load file\n");
		retval = false;
		goto exit_function;
	}

	if (!r_file_rm (tmpfile)) {
		eprintf ("error: cannot delete temp file\n");
		retval = false;
		goto exit_function;
	}

exit_function:
	free (buf);
	free (tmpfile);

	return retval;
}

static int cmdFile(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case ' ':
		{
			const char *filename;

			if (input[1] != '\x00') {
				filename = input + 1;
				return r_sign_load (core->anal, filename);
			} else {
				eprintf ("usage: zo filename\n");
				return false;
			}
		}
		break;
	case 's':
		{
			const char *filename;

			if (input[1] == ' ' && input[2] != '\x00') {
				filename = input + 2;
				return r_sign_save (core->anal, filename);
			} else {
				eprintf ("usage: zos filename\n");
				return false;
			}
		}
		break;
	case 'z':
		{
			const char *filename = NULL;

			if (input[1] == ' ' && input[2] != '\x00') {
				filename = input + 2;
			} else {
				eprintf ("usage: zoz filename\n");
				return false;
			}

			return loadGzSdb (core->anal, filename);
		}
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "zo[zs] filename ", "# Manage zignature files",
				"zo ", "filename", "load zinatures from sdb file",
				"zoz ", "filename", "load zinatures from gzipped sdb file",
				"zos ", "filename", "save zignatures to sdb file",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: zo[zs] filename\n");
		return false;
	}

	return true;
}

static int cmdSpace(void *data, const char *input) {
	RCore *core = (RCore *) data;
	RSpaces *zs = &core->anal->zign_spaces;

	switch (*input) {
	case '+':
		if (input[1] != '\x00') {
			r_space_push (zs, input + 1);
		} else {
			eprintf ("usage: zs+zignspace\n");
			return false;
		}
		break;
	case 'r':
		if (input[1] == ' ' && input[2] != '\x00') {
			r_space_rename (zs, NULL, input + 2);
		} else {
			eprintf ("usage: zsr newname\n");
			return false;
		}
		break;
	case '-':
		if (input[1] == '\x00') {
			r_space_pop (zs);
		} else if (input[1] == '*') {
			r_space_unset (zs, NULL);
		} else {
			r_space_unset (zs, input+1);
		}
		break;
	case 'j':
	case '*':
	case '\0':
		r_space_list (zs, input[0]);
		break;
	case ' ':
		if (input[1] != '\x00') {
			r_space_set (zs, input + 1);
		} else {
			eprintf ("usage: zs zignspace\n");
			return false;
		}
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "zs[+-*] [namespace] ", "# Manage zignspaces",
				"zs", "", "display zignspaces",
				"zs ", "zignspace", "select zignspace",
				"zs ", "*", "select all zignspaces",
				"zs-", "zignspace", "delete zignspace",
				"zs-", "*", "delete all zignspaces",
				"zs+", "zignspace", "push previous zignspace and set",
				"zs-", "", "pop to the previous zignspace",
				"zsr ", "newname", "rename selected zignspace",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: zs[+-*] [namespace]\n");
		return false;
	}

	return true;
}

static int cmdFlirt(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case 'd':
		// TODO
		if (input[1] != ' ') {
			eprintf ("usage: zfd filename\n");
			return false;
		}
		r_sign_flirt_dump (core->anal, input + 2);
		break;
	case 's':
		// TODO
		if(input[1] != ' ') {
			eprintf ("usage: zfs filename\n");
			return false;
		}
		r_sign_flirt_scan (core->anal, input + 2);
		break;
	case 'z':
		// TODO
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "zf[dsz] filename ", "# Manage FLIRT signatures",
				"zfd ", "filename", "open FLIRT file and dump",
				"zfs ", "filename", "open FLIRT file and scan",
				"zfz ", "filename", "open FLIRT file and get sig commands (zfz flirt_file > zignatures.sig)",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: zf[dsz] filename\n");
		return false;
	}

	return true;
}


struct ctxSearchCB {
	RCore *core;
	bool rad;
	int count;
};

static void addFlag(RCore *core, RSignItem *it, ut64 addr, int size, int count, const char* prefix, bool rad) {
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	char *name;

	name = r_str_newf ("%s.%s.%s_%d", zign_prefix, prefix, it->name, count);

	if (rad) {
		r_cons_printf ("f %s %d @ 0x%08"PFMT64x"\n", name, size, addr);
	} else {
		r_flag_set(core->flags, name, addr, size);
	}

	free(name);
}

static int graphMatchCB(RSignItem *it, RAnalFunction *fcn, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *) user;

	// TODO(nibble): use one counter per metric zign instead of ctx->count
	addFlag (ctx->core, it, fcn->addr, r_anal_fcn_realsize (fcn), ctx->count, "graph", ctx->rad);
	ctx->count++;

	return 1;
}

static int searchHitCB(RSearchKeyword *kw, RSignItem *it, ut64 addr, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *) user;

	addFlag (ctx->core, it, addr, kw->keyword_length, kw->count, "bytes", ctx->rad);
	ctx->count++;

	return 1;
}

static bool searchRange(RCore *core, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	RSignSearch *ss;
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;

	ss = r_sign_search_new ();
	ss->search->align = r_config_get_i (core->config, "search.align");
	r_sign_search_init (core->anal, ss, searchHitCB, ctx);

	r_cons_break_push (NULL, NULL);
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_is_breaked ()) {
			retval = false;
			break;
		}
		rlen = R_MIN (core->blocksize, to - at);
		if (!r_io_read_at (core->io, at, buf, rlen)) {
			retval = false;
			break;
		}
		if (r_sign_search_update (core->anal, ss, &at, buf, rlen) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			retval = false;
			break;
		}
	}
	r_cons_break_pop ();

	free (buf);
	r_sign_search_free (ss);

	return retval;
}

static bool search(RCore *core, bool rad) {
	struct ctxSearchCB graph_match_ctx = { core, rad, 0 };
	struct ctxSearchCB bytes_search_ctx = { core, rad, 0 };
	RList *list;
	RListIter *iter;
	RAnalFunction *fcni = NULL;
	RIOMap *map;
	bool retval = true;
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	const char *mode = r_config_get (core->config, "search.in");
	ut64 sin_from = UT64_MAX, sin_to = UT64_MAX;
	int hits = 0;

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	list = r_core_get_boundaries_prot (core, R_IO_EXEC | R_IO_WRITE | R_IO_READ, mode, &sin_from, &sin_to);
	if (list) {
		r_list_foreach (list, iter, map) {
			eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", map->from, map->to);
			retval &= searchRange (core, map->from, map->to, rad, &bytes_search_ctx);
		}
		r_list_free (list);
	} else {
		eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", sin_from, sin_to);
		retval = searchRange (core, sin_from, sin_to, rad, &bytes_search_ctx);
	}

	// Graph search
	eprintf ("[+] searching function metrics\n");
	r_cons_break_push (NULL, NULL);
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (r_cons_is_breaked ()) {
			break;
		}
		r_sign_match_graph (core->anal, fcni, graphMatchCB, &graph_match_ctx);
	}
	r_cons_break_pop ();

	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static int cmdSearch(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case '\x00':
	case '*':
		return search (core, input[0] == '*');
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "z/[*] ", "# Search signatures (see 'e?search' for options)",
				"z/ ", "", "search zignatures on range and flag matches",
				"z/* ", "", "search zignatures on range and output radare commands",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: z/[*]\n");
		return false;
	}

	return true;
}

static int cmdCheck(void *data, const char *input) {
	RCore *core = (RCore *) data;
	RSignSearch *ss;
	RListIter *iter;
	RAnalFunction *fcni = NULL;
	ut64 at = core->offset;
	bool retval = true;
	bool rad = input[0] == '*';
	struct ctxSearchCB bytes_search_ctx = { core, rad, 0 };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0 };
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	int hits = 0;

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", at, at + core->blocksize);
	ss = r_sign_search_new ();
	r_sign_search_init (core->anal, ss, searchHitCB, &bytes_search_ctx);
	if (r_sign_search_update (core->anal, ss, &at, core->block, core->blocksize) == -1) {
		eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
		retval = false;
	}
	r_sign_search_free (ss);

	// Graph search
	eprintf ("[+] searching function metrics\n");
	r_cons_break_push (NULL, NULL);
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (fcni->addr == core->offset) {
			r_sign_match_graph (core->anal, fcni, graphMatchCB, &graph_match_ctx);
			break;
		}
	}
	r_cons_break_pop ();

	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case '\0':
	case '*':
	case 'j':
		r_sign_list (core->anal, input[0]);
		break;
	case '-':
		r_sign_delete (core->anal, input + 1);
		break;
	case 'o':
		return cmdFile (data, input + 1);
	case 'a':
		return cmdAdd (data, input + 1);
	case 'f':
		return cmdFlirt (data, input + 1);
	case '/':
		return cmdSearch (data, input + 1);
	case 'c':
		return cmdCheck (data, input + 1);
	case 's':
		return cmdSpace (data, input + 1);
	case '?':
		{
			const char* help_msg[] = {
				"Usage:", "z[*j-aof/cs] [args] ", "# Manage zignatures",
				"z", "", "show zignagures",
				"z*", "", "show zignatures in radare format",
				"zj", "", "show zignatures in json format",
				"z-", "zignature", "delete zignature",
				"z-", "*", "delete all zignatures",
				"za", "[?]", "add zignature",
				"zo", "[?]", "manage zignature files",
				"zf", "[?]", "manage FLIRT signatures",
				"z/", "[?]", "search zignatures",
				"zc", "", "check zignatures at address",
				"zs", "[?]", "manage zignspaces",
				NULL
			};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: z[*j-aof/cs] [args]\n");
		return false;
	}

	return true;
}
