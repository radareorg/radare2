/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_core.h>
#include <r_anal.h>
#include <r_sign.h>
#include <r_list.h>
#include <r_cons.h>

static bool zignAddFcn(RCore *core, RAnalFunction *fcn, int type, int minzlen, int maxzlen) {
	int fcnlen = 0, len = 0;
	ut8 *buf = NULL, *mask = NULL;
	bool retval = true;

	fcnlen = r_anal_fcn_realsize (fcn);

	if (fcnlen < minzlen) {
		eprintf ("warn: omitting %s zignature is too small. Length is %d. Check zign.min.\n",
			fcn->name, fcnlen);
		retval = false;
		goto exit_func;
	}

	len = R_MIN (fcnlen, maxzlen);

	buf = malloc (len);

	if (r_io_read_at (core->io, fcn->addr, buf, len) != len) {
		eprintf ("error: cannot read at 0x%08"PFMT64x"\n", fcn->addr);
		retval = false;
		goto exit_func;
	}

	switch (type) {
	case R_SIGN_EXACT:
		mask = malloc (len);
		memset (mask, 0xff, len);
		retval = r_sign_add (core->anal, R_SIGN_EXACT, fcn->name, len, buf, mask);
		break;
	case R_SIGN_ANAL:
		retval = r_sign_add_anal (core->anal, fcn->name, len, buf);
		break;
	}

exit_func:
	free (buf);
	free (mask);

	return retval;
}

static bool zignAddHex(RCore *core, const char *name, int type, const char *hexbytes) {
	ut8 *mask = NULL, *bytes = NULL;
	int size = 0, blen = 0;
	bool retval = true;

	blen = strlen (hexbytes) + 4;
	bytes = malloc (blen);
	mask = malloc (blen);

	size = r_hex_str2binmask (hexbytes, bytes, mask);
	if (size <= 0) {
		retval = false;
		goto exit_func;
	}

	switch (type) {
	case R_SIGN_EXACT:
		retval = r_sign_add (core->anal, type, name, size, bytes, mask);
		break;
	case R_SIGN_ANAL:
		retval = r_sign_add_anal (core->anal, name, size, bytes);
		break;
	}

exit_func:
	free (bytes);
	free (mask);

	return retval;
}

static int zignAddAnal(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case ' ':
		{
			const char *name = NULL, *hexbytes = NULL;
			char *args = NULL;
			int n = 0;

			args = r_str_new (input + 1);
			n = r_str_word_set0(args);

			if (n != 2) {
				eprintf ("usage: zaa name bytes\n");
				return false;
			}

			name = r_str_word_get0(args, 0);
			hexbytes = r_str_word_get0(args, 1);

			if (!zignAddHex (core, name, R_SIGN_ANAL, hexbytes)) {
				eprintf ("error: cannot add zignature\n");
			}

			free (args);
		}
		break;
	case 'f':
		{
			RAnalFunction *fcni = NULL;
			RListIter *iter = NULL;
			const char *name = NULL;
			int minzlen = r_config_get_i (core->config, "zign.min");
			int maxzlen = r_config_get_i (core->config, "zign.max");

			if (input[1] != ' ') {
				eprintf ("usage: zaaf name\n");
				return false;
			}

			name = input + 2;

			r_cons_break_push (NULL, NULL);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (r_str_cmp (name, fcni->name, strlen (name))) {
					if (!zignAddFcn (core, fcni, R_SIGN_ANAL, minzlen, maxzlen)) {
						eprintf ("error: could not add zignature for fcn %s\n", fcni->name);
					}
					break;
				}
			}
			r_cons_break_pop ();
		}
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "zaa[f] [args] ", "# Create anal zignature",
				"zaa ", "name bytes", "create anal zignature",
				"zaaf ", "[name]", "create anal zignature for function (use function name if name is not given)",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: zaa[f] [args]\n");
	}

	return true;
}

static int zignAddExact(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case ' ':
		{
			const char *name = NULL, *hexbytes = NULL;
			char *args = NULL;
			int n = 0;

			args = r_str_new (input + 1);
			n = r_str_word_set0(args);

			if (n != 2) {
				eprintf ("usage: zae name bytes\n");
				return false;
			}

			name = r_str_word_get0(args, 0);
			hexbytes = r_str_word_get0(args, 1);

			if (!zignAddHex (core, name, R_SIGN_EXACT, hexbytes)) {
				eprintf ("error: cannot add zignature\n");
			}

			free (args);
		}
		break;
	case 'f':
		{
			RAnalFunction *fcni = NULL;
			RListIter *iter = NULL;
			const char *name = NULL;
			int minzlen = r_config_get_i (core->config, "zign.min");
			int maxzlen = r_config_get_i (core->config, "zign.max");

			if (input[1] != ' ') {
				eprintf ("usage: zaef name\n");
				return false;
			}

			name = input + 2;

			r_cons_break_push (NULL, NULL);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (r_str_cmp (name, fcni->name, strlen (name))) {
					if (!zignAddFcn (core, fcni, R_SIGN_EXACT, minzlen, maxzlen)) {
						eprintf ("error: could not add zignature for fcn %s\n", fcni->name);
					}
					break;
				}
			}
			r_cons_break_pop ();
		}
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "zae[f] [args] ", "# Create anal zignature",
				"zae ", "name bytes", "create anal zignature",
				"zaef ", "[name]", "create anal zignature for function (use function name if name is not given)",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: zae[f] [args]\n");
	}

	return true;
}

static int zignAdd(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case 'a':
		return zignAddAnal (data, input + 1);
	case 'e':
		return zignAddExact (data, input + 1);
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "za[aemg] [args] ", "# Add zignature",
				"zaa", "[?]", "add anal zignature",
				"zae", "[?]", "add exact-match zignature",
				"zam ", "name params", "add metric zignature (e.g. zm foo bbs=10 calls=printf,exit)",
				"zaga ", "zignspace [file]", "generate anal zignatures for all functions (and save in file)",
				"zage ", "zignspace [file]", "generate exact-match zignatures for all functions (and save in file)",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: za[aemg] [args]\n");
	}

	return true;
}

static int zignLoad(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case '?':
	{
		const char *help_msg[] = {
			"Usage:", "zo[dz] [args] ", "# Load zignatures from file",
			"zo ", "filename", "load zignatures from file",
			"zod ", "filename", "load zinatures from sdb file",
			"zoz ", "filename", "load zinagures from gzip file",
			NULL};
		r_core_cmd_help (core, help_msg);
	}
	break;
	default:
		eprintf ("usage: zo[dz] [args]\n");
	}

	return true;
}

static int zignSpace(void *data, const char *input) {
	RCore *core = (RCore *) data;
	RSpaces *zs = &core->anal->zign_spaces;

	switch (*input) {
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
	case '+':
		if (input[1] != '\x00') {
			r_space_push (zs, input + 1);
		} else {
			eprintf ("Usage: zs+zignspace\n");
		}
		break;
	case 'r':
		if (input[1] == ' ' && input[2] != '\x00') {
			r_space_rename (zs, NULL, input + 2);
		} else {
			eprintf ("Usage: zsr newname\n");
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
			eprintf ("Usage: zs zignspace\n");
		}
		break;
	default:
		{
			int i, count = 0;

			for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
				if (!zs->spaces[i]) {
					continue;
				}
				r_cons_printf ("%02d %c %s\n", count,
						(i == zs->space_idx)? '*': ' ',
						zs->spaces[i]);
				count++;
			}
		}
	}

	return true;
}

static int zignFlirt(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
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
	}

	return true;
}

struct ctxSearchCB {
	RCore *core;
	bool rad;
};

static int zignSearchHitCB(RSearchKeyword *kw, RSignItem *it, ut64 addr, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *) user;
	RConfig *cfg = ctx->core->config;
	RAnal *a = ctx->core->anal;
	const char *zign_prefix = r_config_get (cfg, "zign.prefix");
	char *name;

	if (it->space == -1) {
		name = r_str_newf ("%s.%s_%d", zign_prefix, it->name, kw->count);
	} else {
		name = r_str_newf ("%s.%s.%s_%d", zign_prefix,
			a->zign_spaces.spaces[it->space], it->name, kw->count);
	}

	if (ctx->rad) {
		r_cons_printf ("f %s %d @ 0x%08"PFMT64x"\n", name, kw->keyword_length, addr);
	} else {
		r_flag_set(ctx->core->flags, name, addr, kw->keyword_length);
	}

	free(name);

	return 1;
}

static bool zignSearchRange(RCore *core, ut64 from, ut64 to, bool rad) {
	RSignSearch *ss;
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;
	struct ctxSearchCB ctx = { core, rad };

	ss = r_sign_search_new ();
	r_sign_search_init(core->anal, ss, zignSearchHitCB, &ctx);

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

static bool zignDoSearch(RCore *core, ut64 from, ut64 to, bool rad) {
	RList *list;
	RListIter *iter;
	RIOMap *map;
	bool search_all = false;
	bool retval = true;
	const char *zign_prefix = r_config_get (core->config, "zign.prefix");

	if (rad) {
		r_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!r_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	if (from == 0 && to == 0) {
		search_all = true;
	} else if (to <= from) {
		eprintf ("error: invalid rage 0x%08"PFMT64x"-0x%08"PFMT64x"\n", from, to);
		retval = false;
		goto exit_func;
	}

	if (search_all) {
		list = r_core_get_boundaries_ok (core);
		if (!list) {
			eprintf ("error: invalid map boundaries\n");
			retval = false;
			goto exit_func;
		}
		r_list_foreach (list, iter, map) {
			eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", map->from, map->to);
			retval &= zignSearchRange (core, map->from, map->to, rad);
		}
		r_list_free (list);
	} else {
		eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", from, to);
		retval = zignSearchRange (core, from, to, rad);
	}

exit_func:
	if (rad) {
		r_cons_printf ("fs-\n");
	} else {
		r_flag_space_pop (core->flags);
	}

	return retval;
}

static int zignSearch(void *data, const char *input) {
	RCore *core = (RCore *) data;

	switch (*input) {
	case '\x00':
	case ' ':
	case '*':
		{
			ut64 from = 0, to = 0;
			char *args = NULL;
			int n = 0;
			bool retval = true;

			if (input[0]) {
				args = r_str_new (input + 1);
				r_str_trim_head (args);
				n = r_str_word_set0(args);
			} else {
				n = 0;
			}

			switch (n) {
			case 2:
				from = r_num_math (core->num, r_str_word_get0(args, 0));
				to = r_num_math (core->num, r_str_word_get0(args, 1));
				break;
			case 1:
				from = core->offset;
				to = r_num_math (core->num, r_str_word_get0(args, 0));
				break;
			case 0:
				break;
			default:
				eprintf ("usage: z/[*] [from] [to]\n");
				retval = false;
				goto exit_case;
			}

			retval = zignDoSearch(core, from, to, input[0] == '*');

exit_case:
			free (args);

			return retval;
		}
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "z/[*] [from] [to] ", "# Search signatures",
				"z/ ", "[from] [to]", "search zignatures on range and flag matches",
				"z/* ", "[from] [to]", "search zignatures on range and output radare commands",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: z/[*] [from] [to]\n");
	}

	return true;
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
		return zignLoad (data, input + 1);
	case 'a':
		return zignAdd (data, input + 1);
	case 'f':
		return zignFlirt (data, input + 1);
	case '/':
		return zignSearch (data, input + 1);
	case 'c':
		break;
	case 's':
		return zignSpace (data, input + 1);
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
				"zo", "[?]", "load zignatures from file",
				"zf", "[?]", "manage FLIRT signatures",
				"z/", "[?]", "search zignatures",
				"zc", "", "check zignatures at address",
				"zs", "[?]", "manage zignspaces",
				"NOTE:", "", "bytes can contain '..' (dots) to specify a binary mask",
				NULL
			};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("usage: z[*j-aof/cs] [args]\n");
	}

	return true;
}
