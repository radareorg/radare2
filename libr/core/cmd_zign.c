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
	bool retval = true;
	int maxsz = r_config_get_i (core->config, "zign.maxsz");

	fcnlen = r_anal_fcn_realsize (fcn);
	len = R_MIN (fcnlen, maxsz);

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

static bool addFcnRefs(RCore *core, RAnalFunction *fcn, const char *name) {
	RList *refs;
	bool retval = true;

	refs = r_sign_fcn_refs (core->anal, fcn);
	if (!refs) {
		return false;
	}

	retval = r_sign_add_refs (core->anal, name, refs);

	r_list_free (refs);

	return retval;
}

static void addFcnZign(RCore *core, RAnalFunction *fcn, const char *name) {
	char *zigname = NULL;
	int curspace = core->anal->zign_spaces.space_idx;

	if (name) {
		zigname = r_str_new (name);
	} else {
		if (curspace != -1) {
			zigname = r_str_newf ("%s.", core->anal->zign_spaces.spaces[curspace]);
		}
		zigname = r_str_appendf (zigname, "%s", fcn->name);
	}

	addFcnGraph (core, fcn, zigname);
	addFcnBytes (core, fcn, zigname);
	addFcnRefs (core, fcn, zigname);
	r_sign_add_offset (core->anal, zigname, fcn->addr);

	free (zigname);
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

static bool addOffsetZign(RCore *core, const char *name, const char *args0, int nargs) {
	const char *offstr = NULL;
	ut64 offset = UT64_MAX;

	if (nargs != 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	offstr = r_str_word_get0 (args0, 0);
	offset = r_num_get (core->num, offstr);

	return r_sign_add_offset (core->anal, name, offset);
}

static bool addRefsZign(RCore *core, const char *name, const char *args0, int nargs) {
	RList *refs = NULL;
	int i = 0;
	bool retval = true;

	if (nargs < 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	refs = r_list_newf ((RListFree) free);
	for (i = 0; i < nargs; i++) {
		r_list_append (refs, r_str_new (r_str_word_get0 (args0, i)));
	}

	retval = r_sign_add_refs (core->anal, name, refs);

	r_list_free (refs);

	return retval;
}

static bool addZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	switch (type) {
	case R_SIGN_BYTES:
	case R_SIGN_ANAL:
		return addBytesZign (core, name, type, args0, nargs);
	case R_SIGN_GRAPH:
		return addGraphZign (core, name, args0, nargs);
	case R_SIGN_OFFSET:
		return addOffsetZign (core, name, args0, nargs);
	case R_SIGN_REFS:
		return addRefsZign (core, name, args0, nargs);
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
					addFcnZign (core, fcni, zigname);
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
				addFcnZign (core, fcni, NULL);
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
				"  g: graph metrics\n"
				"  o: original offset\n"
				"  r: references\n\n"
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
				"  za foo o 0x08048123\n"
				"  za foo r sym.imp.strcpy sym.imp.sprintf sym.imp.strlen\n");
		} else {
			const char *help_msg[] = {
				"Usage:", "za[fF?] [args] ", "# Добавление подписи",
				"za ", "zigname type params", "Добавить подпись",
				"zaf ", "[fcnname] [zigname]", "Создать подпись для функции",
				"zaF ", "", "Генерировать подписи для всех функций",
				"za?? ", "", "Показать расширенную справку",
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
				"Usage:", "zo[zs] filename ", "# Управление файлами подписи",
				"zo ", "filename", "Загрузить подписи из файла sdb",
				"zoz ", "filename", "Загрузить подписи из файла sdb",
				"zos ", "filename", "Загрузить подписи в файл sdb (объединить, если файл существует)",
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
				"Usage:", "zs[+-*] [namespace] ", "#Управление zignspaces",
				"zs", "", "Показать zignspaces",
				"zs ", "zignspace", "Выбрать zignspace",
				"zs ", "*", "Выбрать все zignspaces",
				"zs-", "zignspace", "Удалить zignspace",
				"zs-", "*", "Удалить все zignspaces",
				"zs+", "zignspace", "Вставить предыдущий zignspace и установить",
				"zs-", "", "Извлечь предыдущий zignspace",
				"zsr ", "newname", "Переименовать выбранные zignspace",
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
				"Usage:", "zf[dsz] filename ", "# Управление подписями FLIRT",
				"zfd ", "filename", "Открыть FLIRT-файл и дамп",
				"zfs ", "filename", "Открыть файл FLIRT и отсканировать",
				"zfz ", "filename", "Открыть файл FLIRT и получить команды sig (zfz flirt_file> zignatures.sig)",
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
	const char *prefix;
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

static int searchHitCB(RSignItem *it, RSearchKeyword *kw, ut64 addr, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *) user;

	addFlag (ctx->core, it, addr, kw->keyword_length, kw->count, ctx->prefix, ctx->rad);
	ctx->count++;

	return 1;
}

static int fcnMatchCB(RSignItem *it, RAnalFunction *fcn, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *) user;

	// TODO(nibble): use one counter per metric zign instead of ctx->count
	addFlag (ctx->core, it, fcn->addr, r_anal_fcn_realsize (fcn), ctx->count, ctx->prefix, ctx->rad);
	ctx->count++;

	return 1;
}

static bool searchRange(RCore *core, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	RSignSearch *ss;
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;

	int minsz = r_config_get_i (core->config, "zign.minsz");

	ss = r_sign_search_new ();
	ss->search->align = r_config_get_i (core->config, "search.align");
	r_sign_search_init (core->anal, ss, minsz, searchHitCB, ctx);

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
	RList *list;
	RListIter *iter;
	RAnalFunction *fcni = NULL;
	RIOMap *map;
	bool retval = true;
	ut64 sin_from = UT64_MAX, sin_to = UT64_MAX;
	int hits = 0;

	struct ctxSearchCB bytes_search_ctx = { core, rad, 0, "bytes" };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0, "graph" };
	struct ctxSearchCB offset_match_ctx = { core, rad, 0, "offset" };
	struct ctxSearchCB refs_match_ctx = { core, rad, 0, "refs" };

	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	int mincc = r_config_get_i (core->config, "zign.mincc");
	const char *mode = r_config_get (core->config, "search.in");
	bool useBytes = r_config_get_i (core->config, "zign.bytes");
	bool useGraph = r_config_get_i (core->config, "zign.graph");
	bool useOffset = r_config_get_i (core->config, "zign.offset");
	bool useRefs = r_config_get_i (core->config, "zign.refs");

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	if (useBytes) {
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
	}

	// Function search
	if (useGraph || useOffset || useRefs) {
		eprintf ("[+] searching function metrics\n");
		r_cons_break_push (NULL, NULL);
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (useGraph) {
				r_sign_match_graph (core->anal, fcni, mincc, fcnMatchCB, &graph_match_ctx);
			}
			if (useOffset) {
				r_sign_match_offset (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
			}
			if (useRefs){
				r_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
			}
		}
		r_cons_break_pop ();
	}

	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count +
		offset_match_ctx.count + refs_match_ctx.count;
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
				"Usage:", "z/[*] ", "# Поиск подписей (см. 'e?Search' для опций)",
				"z/ ", "", "Искать zignatures в диапазоне и совпадениях флагов",
				"z/* ", "", "Поиск zignatures в диапозоне и вывод radare команд",
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
	int hits = 0;

	struct ctxSearchCB bytes_search_ctx = { core, rad, 0, "bytes" };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0, "graph" };
	struct ctxSearchCB offset_match_ctx = { core, rad, 0, "offset" };
	struct ctxSearchCB refs_match_ctx = { core, rad, 0, "refs" };

	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	int minsz = r_config_get_i (core->config, "zign.minsz");
	int mincc = r_config_get_i (core->config, "zign.mincc");
	bool useBytes = r_config_get_i (core->config, "zign.bytes");
	bool useGraph = r_config_get_i (core->config, "zign.graph");
	bool useOffset = r_config_get_i (core->config, "zign.offset");
	bool useRefs = r_config_get_i (core->config, "zign.refs");

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	if (useBytes) {
		eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", at, at + core->blocksize);
		ss = r_sign_search_new ();
		r_sign_search_init (core->anal, ss, minsz, searchHitCB, &bytes_search_ctx);
		if (r_sign_search_update (core->anal, ss, &at, core->block, core->blocksize) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			retval = false;
		}
		r_sign_search_free (ss);
	}

	// Function search
	if (useGraph || useOffset || useRefs) {
		eprintf ("[+] searching function metrics\n");
		r_cons_break_push (NULL, NULL);
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (fcni->addr == core->offset) {
				if (useGraph) {
					r_sign_match_graph (core->anal, fcni, mincc, fcnMatchCB, &graph_match_ctx);
				}
				if (useOffset) {
					r_sign_match_offset (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
				}
				if (useRefs){
					r_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
				}
				break;
			}
		}
		r_cons_break_pop ();
	}

	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		if (!r_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count +
		offset_match_ctx.count + refs_match_ctx.count;
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
				"Usage:", "z[*j-aof/cs] [args] ", "# Управление zignatures",
				"z", "", "Показать zignagures",
				"z*", "", "Показать zignatures в формате radare",
				"zj", "", "Показать zignatures в формате json",
				"z-", "zignature", "Удалить zignature",
				"z-", "*", "Удалить все zignatures",
				"za", "[?]", "Добавить zignature",
				"zo", "[?]", "Управление файлами zignature",
				"zf", "[?]", "Управление FLIRT signatures",
				"z/", "[?]", "Поиск zignatures",
				"zc", "", "Проверка zignatures по адресу",
				"zs", "[?]", "Управление zignspaces",
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
