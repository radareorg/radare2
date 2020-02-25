/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

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

static const char *help_msg_z_slash[] = {
	"Usage:", "z/[*] ", "# Search signatures (see 'e?search' for options)",
	"z/ ", "", "search zignatures on range and flag matches",
	"z/* ", "", "search zignatures on range and output radare commands",
	NULL
};

static const char *help_msg_za[] = {
	"Usage:", "za[fF?] [args] ", "# Add zignature",
	"za ", "zigname type params", "add zignature",
	"zaf ", "[fcnname] [zigname]", "create zignature for function",
	"zaF ", "", "generate zignatures for all functions",
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

static void cmd_zign_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, z);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, z/, z_slash);
	DEFINE_CMD_DESCRIPTOR (core, za);
	DEFINE_CMD_DESCRIPTOR (core, zf);
	DEFINE_CMD_DESCRIPTOR (core, zo);
	DEFINE_CMD_DESCRIPTOR (core, zs);
	DEFINE_CMD_DESCRIPTOR (core, zc);
}

static bool addFcnHash(RCore *core, RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (core && fcn && name, false);
	return r_sign_add_bb_hash (core->anal, fcn, name);
}

static bool addFcnBytes(RCore *core, RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (core && fcn && name, false);
	int maxsz = r_config_get_i (core->config, "zign.maxsz");
	int fcnlen = r_anal_function_realsize (fcn);
	int len = R_MIN (core->io->addrbytes * fcnlen, maxsz);

	ut8 *buf = malloc (len);
	if (!buf) {
		return false;
	}

	bool retval = false;
	if (r_io_is_valid_offset (core->io, fcn->addr, 0)) {
		(void)r_io_read_at (core->io, fcn->addr, buf, len);
		retval = r_sign_add_anal (core->anal, name, len, buf, fcn->addr);
	} else {
		eprintf ("error: cannot read at 0x%08"PFMT64x"\n", fcn->addr);
	}
	free (buf);
	return retval;
}

static bool addFcnGraph(RCore *core, RAnalFunction *fcn, const char *name) {
	RSignGraph graph = {
		.cc = r_anal_fcn_cc (core->anal, fcn),
		.nbbs = r_list_length (fcn->bbs)
	};
	// XXX ebbs doesnt gets initialized if calling this from inside the struct
	graph.edges = r_anal_fcn_count_edges (fcn, &graph.ebbs);
	graph.bbsum = r_anal_function_realsize (fcn);
	return r_sign_add_graph (core->anal, name, graph);
}

static bool addFcnXRefs(RCore *core, RAnalFunction *fcn, const char *name) {
	bool retval = false;
	RList *xrefs = r_sign_fcn_xrefs (core->anal, fcn);
	if (xrefs) {
		retval = r_sign_add_xrefs (core->anal, name, xrefs);
		r_list_free (xrefs);
	}
	return retval;
}

static bool addFcnRefs(RCore *core, RAnalFunction *fcn, const char *name) {
	RList *refs = r_sign_fcn_refs (core->anal, fcn);
	if (!refs) {
		return false;
	}
	bool retval = r_sign_add_refs (core->anal, name, refs);
	r_list_free (refs);
	return retval;
}

static bool addFcnVars(RCore *core, RAnalFunction *fcn, const char *name) {
	RList *vars = r_sign_fcn_vars (core->anal, fcn);
	if (!vars) {
		return false;
	}
	bool retval = r_sign_add_vars (core->anal, name, vars);
	r_list_free (vars);
	return retval;
}

static bool addFcnTypes(RCore *core, RAnalFunction *fcn, const char *name) {
	RList *types = r_sign_fcn_types (core->anal, fcn);
	if (!types) {
		return false;
	}
	bool retval = r_sign_add_types (core->anal, name, types);
	r_list_free (types);
	return retval;
}

#if 0
static char *getFcnComments(RCore *core, RAnalFunction *fcn) {
	// XXX this is slow as hell on big binaries
	char *r = r_core_cmd_strf (core, "CCf* @ 0x%08"PFMT64x, fcn->addr);
	if (r && *r) {
		return r;
	}
	//
	return NULL;
}
#endif

static void addFcnZign(RCore *core, RAnalFunction *fcn, const char *name) {
	char *ptr = NULL;
	char *zignspace = NULL;
	char *zigname = NULL;
	const RSpace *curspace = r_spaces_current (&core->anal->zign_spaces);
	int len = 0;

	if (name) {
		zigname = r_str_new (name);
	} else {
		// If the user has set funtion names containing a single ':' then we assume
		// ZIGNSPACE:FUNCTION, and for now we only support the 'zg' command
		if ((ptr = strchr (fcn->name, ':')) != NULL) {
			len = ptr - fcn->name;
			zignspace = r_str_newlen (fcn->name, len);
			r_spaces_push (&core->anal->zign_spaces, zignspace);
		} else if (curspace) {
			zigname = r_str_newf ("%s:", curspace->name);
		}
		zigname = r_str_appendf (zigname, "%s", fcn->name);
	}

	addFcnGraph (core, fcn, zigname);
	addFcnBytes (core, fcn, zigname);
	addFcnXRefs (core, fcn, zigname);
	addFcnRefs (core, fcn, zigname);
	addFcnVars (core, fcn, zigname);
	addFcnTypes (core, fcn, zigname);
	addFcnHash (core, fcn, zigname);
	if (strcmp (zigname, fcn->name)) {
		r_sign_add_name (core->anal, zigname, fcn->name);
	}
/*
	XXX this is very slow and poorly tested
	char *comments = getFcnComments (core, fcn);
	if (comments) {
		r_sign_add_comment (core->anal, zigname, comments);
	}
*/
	r_sign_add_addr (core->anal, zigname, fcn->addr);

	free (zigname);
	if (zignspace) {
		r_spaces_pop (&core->anal->zign_spaces);
		free (zignspace);
	}
}

static bool parseGraphMetrics(const char *args0, int nargs, RSignGraph *graph) {
	const char *ptr = NULL;
	int i = 0;

	graph->cc = -1;
	graph->nbbs = -1;
	graph->edges = -1;
	graph->ebbs = -1;
	graph->bbsum = 0;

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
		} else if (r_str_startswith (ptr, "bbsum=")) {
			graph->bbsum = atoi (ptr + 6);
		} else {
			return false;
		}
	}
	return true;
}

static bool addCommentZign(RCore *core, const char *name, const char *args0, int nargs) {
	const char *comment = args0;
	return r_sign_add_comment (core->anal, name, comment);
}

static bool addNameZign(RCore *core, const char *name, const char *args0, int nargs) {
	const char *realname = r_str_word_get0 (args0, 0);
	return r_sign_add_name (core->anal, name, realname);
}

static bool addGraphZign(RCore *core, const char *name, const char *args0, int nargs) {
	RSignGraph graph = {0};
	if (!parseGraphMetrics (args0, nargs, &graph)) {
		eprintf ("error: invalid arguments\n");
		return false;
	}
	return r_sign_add_graph (core->anal, name, graph);
}

static bool addHashZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	if (!args0) {
		return false;
	}
	int len = strlen (args0);
	if (!len) {
		return false;
	}
	return r_sign_add_hash (core->anal, name, type, args0, len);
}

static bool addBytesZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	const char *hexbytes = NULL;
	ut8 *mask = NULL, *bytes = NULL, *sep = NULL;
	int size = 0, blen = 0;
	bool retval = true;

	if (nargs != 1) {
		eprintf ("error: invalid syntax\n");
		retval = false;
		goto out;
	}

	hexbytes = r_str_word_get0 (args0, 0);
	if ((sep = (ut8*) strchr (hexbytes, ':'))) {
		blen = sep - (ut8*) hexbytes;
		if (!blen || (blen & 1) || strlen ((char*) ++sep) != blen) {
			eprintf ("error: cannot parse hexpairs\n");
			retval = false;
			goto out;
		}
		bytes = calloc (1, blen + 1);
		mask = calloc (1, blen + 1);
		memcpy (bytes, hexbytes, blen);
		memcpy (mask, sep, blen);
		size = r_hex_str2bin ((char*) bytes, bytes);
		if (size != blen / 2 || r_hex_str2bin ((char*) mask, mask) != size) {
			eprintf ("error: cannot parse hexpairs\n");
			retval = false;
			goto out;
		}
	} else {
		blen = strlen (hexbytes) + 4;
		bytes = malloc (blen);
		mask = malloc (blen);

		size = r_hex_str2binmask (hexbytes, bytes, mask);
		if (size <= 0) {
			eprintf ("error: cannot parse hexpairs\n");
			retval = false;
			goto out;
		}
	}

	switch (type) {
	case R_SIGN_BYTES:
		retval = r_sign_add_bytes (core->anal, name, size, bytes, mask);
		break;
	case R_SIGN_ANAL:
		retval = r_sign_add_anal (core->anal, name, size, bytes, 0);
		break;
	}

out:
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

	return r_sign_add_addr (core->anal, name, offset);
}

static bool addRefsZign(RCore *core, const char *name, const char *args0, int nargs) {
	int i = 0;
	if (nargs < 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	RList *refs = r_list_newf ((RListFree) free);
	for (i = 0; i < nargs; i++) {
		r_list_append (refs, r_str_new (r_str_word_get0 (args0, i)));
	}

	bool retval = r_sign_add_refs (core->anal, name, refs);
	r_list_free (refs);
	return retval;
}

static bool addXRefsZign(RCore *core, const char *name, const char *args0, int nargs) {
	int i = 0;
	if (nargs < 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	RList *refs = r_list_newf ((RListFree) free);
	for (i = 0; i < nargs; i++) {
		r_list_append (refs, r_str_new (r_str_word_get0 (args0, i)));
	}

	bool retval = r_sign_add_xrefs (core->anal, name, refs);
	r_list_free (refs);
	return retval;
}

static bool addVarsZign(RCore *core, const char *name, const char *args0, int nargs) {
	int i = 0;
	if (nargs < 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	RList *vars = r_list_newf ((RListFree) free);
	for (i = 0; i < nargs; i++) {
		r_list_append (vars, r_str_new (r_str_word_get0 (args0, i)));
	}

	bool retval = r_sign_add_vars (core->anal, name, vars);
	r_list_free (vars);
	return retval;
}

static bool addTypesZign(RCore *core, const char *name, const char *args0, int nargs) {
       int i = 0;
       if (nargs < 1) {
               eprintf ("error: invalid syntax\n");
               return false;
       }

       RList *types = r_list_newf ((RListFree) free);
       for (i = 0; i < nargs; i++) {
               r_list_append (types, r_str_new (r_str_word_get0 (args0, i)));
       }

       bool retval = r_sign_add_types (core->anal, name, types);
       r_list_free (types);
       return retval;
}

static bool addZign(RCore *core, const char *name, int type, const char *args0, int nargs) {
	switch (type) {
	case R_SIGN_BYTES:
	case R_SIGN_ANAL:
		return addBytesZign (core, name, type, args0, nargs);
	case R_SIGN_GRAPH:
		return addGraphZign (core, name, args0, nargs);
	case R_SIGN_COMMENT:
		return addCommentZign (core, name, args0, nargs);
	case R_SIGN_NAME:
		return addNameZign (core, name, args0, nargs);
	case R_SIGN_OFFSET:
		return addOffsetZign (core, name, args0, nargs);
	case R_SIGN_REFS:
		return addRefsZign (core, name, args0, nargs);
	case R_SIGN_XREFS:
		return addXRefsZign (core, name, args0, nargs);
	case R_SIGN_VARS:
		return addVarsZign (core, name, args0, nargs);
	case R_SIGN_TYPES:
		return addTypesZign (core, name, args0, nargs);
	case R_SIGN_BBHASH:
		return addHashZign (core, name, type, args0, nargs);
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
				goto out_case_manual;
			}

			zigname = r_str_word_get0 (args, 0);
			type = r_str_word_get0 (args, 1)[0];
			args0 = r_str_word_get0 (args, 2);

			if (!addZign (core, zigname, type, args0, n - 2)) {
				retval = false;
				goto out_case_manual;
			}

out_case_manual:
			free (args);
			return retval;
		}
		break;
	case 'f': // "zaf"
		{
			RAnalFunction *fcni = NULL;
			RListIter *iter = NULL;
			const char *fcnname = NULL, *zigname = NULL;
			char *args = NULL;
			int n = 0;
			bool retval = true;

			args = r_str_new (r_str_trim_head_ro (input + 1));
			n = r_str_word_set0 (args);

			if (n > 2) {
				eprintf ("usage: zaf [fcnname] [zigname]\n");
				retval = false;
				goto out_case_fcn;
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

out_case_fcn:
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
			// TODO #7967 help refactor: move to detail
			r_cons_printf ("Adding Zignatures (examples and documentation)\n\n"
				"Zignature types:\n"
				"  a: bytes pattern (anal mask)\n"
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
		eprintf ("usage: za[fF?] [args]\n");
		return false;
	}

	return true;
}

static int cmdOpen(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case ' ':
		if (input[1]) {
			return r_sign_load (core->anal, input + 1);
		}
		eprintf ("usage: zo filename\n");
		return false;
	case 's':
		if (input[1] == ' ' && input[2]) {
			return r_sign_save (core->anal, input + 2);
		}
		eprintf ("usage: zos filename\n");
		return false;
	case 'z':
		if (input[1] == ' ' && input[2]) {
			return r_sign_load_gz (core->anal, input + 2);
		}
		eprintf ("usage: zoz filename\n");
		return false;
	case '?':
		r_core_cmd_help (core, help_msg_zo);
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
		if (!input[1]) {
			eprintf ("usage: zs+zignspace\n");
			return false;
		}
		r_spaces_push (zs, input + 1);
		break;
	case 'r':
		if (input[1] != ' ' || !input[2]) {
			eprintf ("usage: zsr newname\n");
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
			eprintf ("usage: zs zignspace\n");
			return false;
		}
		r_spaces_set (zs, input + 1);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_zs);
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
		if (input[1] != ' ') {
			eprintf ("usage: zfs filename\n");
			return false;
		}
		int depth = r_config_get_i (core->config, "dir.depth");
		char *file;
		RListIter *iter;
		RList *files = r_file_globsearch (input + 2, depth);
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

static bool __fcnstrValidField(char *field, int i) {
	char *arg_number = r_str_newf ("%d", i);
	int is_ret = strcmp (field, "ret");
	int is_args = strcmp (field, "args");
	int is_arg = strcmp (field, "arg");
	int is_arg_number = strcmp (field, arg_number);

	free (arg_number);

	return !(is_ret && is_args && is_arg && is_arg_number);
}

static char *__types_list_to_fcnstr(RList *types) {
	char *type_kv = NULL, *k = NULL, *v = NULL;
	char *field = NULL, *name = NULL, *rettype = NULL;
	char *arg = NULL, *ret = NULL;
	int nargs = 0, i = 0, j = 0;
	RList *args = r_list_new ();
	RListIter *iter;

	r_list_foreach (types, iter, type_kv) {
		k = strtok (type_kv, "=");
		v = strtok (NULL, "\0");

		strtok (k, ".");
		name = strtok (NULL, ".");
		field = strtok (NULL, ".");

		while (!__fcnstrValidField (field, i) && field) {
			name = field;
			field = strtok (NULL, ".");
		}

		if (!strcmp (field, "args")) {
			nargs = atoi (v);
		} else if (!strcmp (field, "ret")) {
			rettype = strdup (v);
		} else {
			if (i < nargs) {
				arg = strdup (v);
				for (j = 0; j < strlen (arg); j++) {
					if (arg[j] == ',') {
						arg[j] = ' ';
					}
				}
				r_list_append (args, r_str_ndup (arg + 1,
					strlen (arg) - 2));
				free (arg);
			}
			i++;
		}
	}

	if (!rettype) {
		rettype = strdup ("void"); // workaround for "afs" bug
	}

	ret = r_str_newf ("%s %s(", rettype, name);

	r_list_foreach (args, iter, arg) {
		if (iter != r_list_tail (args)) {
			ret = r_str_newf ("%s%s, ", ret, arg);
		}
	}

	ret = (r_list_length (args) > 0)
		? r_str_newf ("%s%s);", ret, (char *)r_list_get_top (args))
		: r_str_newf ("%s);", ret);

	r_list_free (args);
	free (rettype);
	return ret;
}

static void addFlag(RCore *core, RSignItem *it, ut64 addr, int size, int count, const char* prefix, bool rad) {
	RAnalFunction *fcn = NULL;
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	char *name = NULL;

	if (it->types) {
		char *fcnstr = __types_list_to_fcnstr (it->types);
		char *fcnstr_copy = strdup (fcnstr);
		fcn = r_anal_get_fcn_in (core->anal, it->addr, 0);
		if (fcn) {
			char *arg = strtok (fcnstr_copy, "(");
			r_str_trim_tail (arg);
			const char *fcn_name = strrchr (arg, ' ');
			// __setFunctionName() ; cmd_anal.c:2535 ; Expand into R_API function
			free (fcn->name);
			fcn->name = strdup (fcn_name + 1);
			if (core->anal->cb.on_fcn_rename) {
				core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, fcn->name);
			}
			r_anal_str_to_fcn (core->anal, fcn, fcnstr);
		}
		if (fcnstr_copy) {
			free (fcnstr_copy);
		}
		free (fcnstr);
	}
	name = r_name_filter2 (r_str_newf ("%s.%s.%s_%d", zign_prefix, prefix, it->name, count));
	if (name) {
		if (rad) {
			r_cons_printf ("f %s %d @ 0x%08"PFMT64x"\n", name, size, addr);
			if (it->realname) {
				r_cons_printf ("\"afn %s @ 0x%08"PFMT64x"\"\n", it->realname, addr); // XXX command injection
			}
		} else {
			r_flag_set (core->flags, name, addr, size);
		}
		free (name);
	}
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
	addFlag (ctx->core, it, fcn->addr, r_anal_function_realsize (fcn), ctx->count, ctx->prefix, ctx->rad);
	ctx->count++;
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
	r_sign_search_init (core->anal, ss, minsz, searchHitCB, ctx);

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

static bool searchRange2(RCore *core, RSignSearch *ss, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;

	if (!buf) {
		return false;
	}
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
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			retval = false;
			break;
		}
	}
	r_cons_break_pop ();
	free (buf);

	return retval;
}

static bool search(RCore *core, bool rad, bool only_func) {
	RList *list;
	RListIter *iter;
	RAnalFunction *fcni = NULL;
	RIOMap *map;
	bool retval = true;
	int hits = 0;

	struct ctxSearchCB bytes_search_ctx = { core, rad, 0, "bytes" };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0, "graph" };
	struct ctxSearchCB offset_match_ctx = { core, rad, 0, "offset" };
	struct ctxSearchCB refs_match_ctx = { core, rad, 0, "refs" };
	struct ctxSearchCB hash_match_ctx = { core, rad, 0, "bbhash" };
	struct ctxSearchCB types_match_ctx = { core, rad, 0, "types" };

	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	int mincc = r_config_get_i (core->config, "zign.mincc");
	const char *mode = r_config_get (core->config, "search.in");
	bool useBytes = r_config_get_i (core->config, "zign.bytes");
	bool useGraph = r_config_get_i (core->config, "zign.graph");
	bool useOffset = r_config_get_i (core->config, "zign.offset");
	bool useRefs = r_config_get_i (core->config, "zign.refs");
	bool useHash = r_config_get_i (core->config, "zign.hash");
	bool useTypes = r_config_get_i (core->config, "zign.types");
	int maxsz = r_config_get_i (core->config, "zign.maxsz");

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	if (useBytes && !only_func) {
		list = r_core_get_boundaries_prot (core, -1, mode, "search");
		if (!list) {
			return false;
		}
		r_list_foreach (list, iter, map) {
			eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", map->itv.addr, r_itv_end (map->itv));
			retval &= searchRange (core, map->itv.addr, r_itv_end (map->itv), rad, &bytes_search_ctx);
		}
		r_list_free (list);
	}

	// Function search
	// TODO (oxcabe): Refactor big conditional
	if (useGraph || useOffset || useRefs || useHash || (useBytes && only_func) || useTypes) {
		eprintf ("[+] searching function metrics\n");
		r_cons_break_push (NULL, NULL);
		int count = 0;

		RSignSearch *ss = NULL;

		if (useBytes && only_func) {
			ss = r_sign_search_new ();
			ss->search->align = r_config_get_i (core->config, "search.align");
			int minsz = r_config_get_i (core->config, "zign.minsz");
			r_sign_search_init (core->anal, ss, minsz, searchHitCB, &bytes_search_ctx);
		}

		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (useGraph) {
				r_sign_match_graph (core->anal, fcni, mincc, fcnMatchCB, &graph_match_ctx);
			}
			if (useOffset) {
				r_sign_match_addr (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
			}
			if (useRefs) {
				r_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
			}
			if (useHash) {
				r_sign_match_hash (core->anal, fcni, fcnMatchCB, &hash_match_ctx);
			}
			if (useBytes && only_func) {
				eprintf ("Matching func %d / %d (hits %d)\n", count, r_list_length (core->anal->fcns), bytes_search_ctx.count);
				int fcnlen = r_anal_function_realsize (fcni);
				int len = R_MIN (core->io->addrbytes * fcnlen, maxsz);
				retval &= searchRange2 (core, ss, fcni->addr, fcni->addr + len, rad, &bytes_search_ctx);
			}
			if (useTypes) {
				r_sign_match_types (core->anal, fcni, fcnMatchCB, &types_match_ctx);
			}
			count ++;
#if 0
TODO: add useXRefs, useName
#endif
		}
		r_cons_break_pop ();
		r_sign_search_free (ss);
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
		offset_match_ctx.count + refs_match_ctx.count + hash_match_ctx.count + types_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static int cmdCompare(void *data, const char *input) {
	int result = true;
	RCore *core = (RCore *) data;
	const char *raw_bytes_thresh = r_config_get (core->config, "zign.diff.bthresh");
	const char *raw_graph_thresh = r_config_get (core->config, "zign.diff.gthresh");
	RSignOptions *options = r_sign_options_new (raw_bytes_thresh, raw_graph_thresh);

	switch (*input) {
	case ' ':
		if (!input[1]) {
			eprintf ("usage: zc other_space\n");
			result = false;
			break;
		}
		result = r_sign_diff (core->anal, options, input + 1);
		break;
	case 'n':
		switch (input[1]) {
		case ' ':
			if (!input[2]) {
				eprintf ("usage: zcn other_space\n");
				result = false;
				break;
			}
			result = r_sign_diff_by_name (core->anal, options, input + 2, false);
			break;
		case '!':
			if (input[2] != ' ' || !input[3]) {
				eprintf ("usage: zcn! other_space\n");
				result = false;
				break;
			}
			result = r_sign_diff_by_name (core->anal, options, input + 3, true);
			break;
		default:
			eprintf ("usage: zcn! other_space\n");
			result = false;
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_zc);
		break;
	default:
		eprintf ("usage: zc[?n!] other_space\n");
		result = false;
	}

	r_sign_options_free (options);

	return result;
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
	struct ctxSearchCB hash_match_ctx = { core, rad, 0, "bbhash" };
	struct ctxSearchCB types_match_ctx = { core, rad, 0, "types" };

	const char *zign_prefix = r_config_get (core->config, "zign.prefix");
	int minsz = r_config_get_i (core->config, "zign.minsz");
	int mincc = r_config_get_i (core->config, "zign.mincc");
	bool useBytes = r_config_get_i (core->config, "zign.bytes");
	bool useGraph = r_config_get_i (core->config, "zign.graph");
	bool useOffset = r_config_get_i (core->config, "zign.offset");
	bool useRefs = r_config_get_i (core->config, "zign.refs");
	bool useHash = r_config_get_i (core->config, "zign.hash");
	bool useTypes = r_config_get_i (core->config, "zign.types");

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
	if (useGraph || useOffset || useRefs || useHash || useTypes) {
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
					r_sign_match_addr (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
				}
				if (useRefs){
					r_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
				}
				if (useHash){
					r_sign_match_hash (core->anal, fcni, fcnMatchCB, &hash_match_ctx);
				}
				if (useTypes) {
					r_sign_match_types (core->anal, fcni, fcnMatchCB, &types_match_ctx);
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
		offset_match_ctx.count + refs_match_ctx.count + hash_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static int cmdSearch(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case 0:
	case '*':
		return search (core, input[0] == '*', false);
	case 'f':
		switch (input[1]) {
		case 0:
		case '*':
			return search (core, input[1] == '*', true);
		default:
			eprintf ("usage: z/[f*]\n");
			return false;
		}
	case '?':
		r_core_cmd_help (core, help_msg_z_slash);
		break;
	default:
		eprintf ("usage: z/[*]\n");
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

	switch (*input) {
	case '\0':
	case '*':
	case 'q':
	case 'j':
		r_sign_list (core->anal, input[0]);
		break;
	case 'k':
		r_core_cmd0 (core, "k anal/zigns/*");
		break;
	case '-':
		r_sign_delete (core->anal, input + 1);
		break;
	case '.': // "z."
		return cmdCheck (data, input + 1);
	case 'o': // "zo"
		return cmdOpen (data, input + 1);
	case 'g': // "zg"
		return cmdAdd (data, "F");
	case 'a': // "za"
		return cmdAdd (data, input + 1);
	case 'f': // "zf"
		return cmdFlirt (data, input + 1);
	case '/': // "z/"
		return cmdSearch (data, input + 1);
	case 'c': // "zc"
		return cmdCompare (data, input + 1);
	case 's': // "zs"
		return cmdSpace (data, input + 1);
	case 'i': // "zi"
		return cmdInfo (data, input + 1);
	case '?': // "z?"
		r_core_cmd_help (core, help_msg_z);
		break;
	default:
		r_core_cmd_help (core, help_msg_z);
		return false;
	}

	return true;
}
