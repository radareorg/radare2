/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include "r_anal.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_list.h"
#include "r_sign.h"

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

	switch (type) {
	case R_SIGN_EXACT:
		retval = r_sign_add (core->anal, type, name, size, bytes, mask);
		break;
	case R_SIGN_ANAL:
		retval = r_sign_add_anal (core->anal, name, size, bytes);
		break;
	}

	free (bytes);
	free (mask);

	return retval;
}

static int zignAddAnal(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
		break;
	}

	return true;
}

static int zignAddExact(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
		break;
	}

	return true;
}

static int zignAdd(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
				"zam ", "name param", "add metric zignature (e.g. zm foo bbs=10 calls=printf,exit)",
				"zaga ", "zignspace [file]", "generate anal zignatures for all functions (and save in file)",
				"zage ", "zignspace [file]", "generate exact-match zignatures for all functions (and save in file)",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		break;
	}

	return true;
}

static int zignLoad(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
		break;
	}

	return true;
}

static int zignSpace(void *data, const char *input) {
	RCore *core = (RCore *)data;
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
		break;
	}

	return true;
}

static int zignFlirt(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
		break;
	}

	return true;
}

static int zignSearch(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (*input) {
	case ' ':
		break;
	case '*':
		break;
	case '?':
		{
			const char *help_msg[] = {
				"Usage:", "z/[*] [ini] [end] ", "# Search signatures",
				"z/ ", "[ini] [end]", "search zignatures on range and flag matches",
				"z/* ", "[ini] [end]", "search zignatures on range and output radare commands",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		break;
	}

	return true;
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;

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
		break;
	}

	return true;
}
