/* radare - LGPL - Copyright 2009-2022 - pancake */

#define R_LOG_ORIGIN "cmdapi"
#include <r_core.h>
#include "ht_pp.h"

/*!
 * Number of sub-commands to show as options when displaying the help of a
 * command. When a command has more options than MAX_CHILDREN_SHOW, `?` is shown
 * instead.
 *
 * Example with MAX_CHILDREN_SHOW=3:
 * w -> wa
 *   -> wb
 *   -> wc
 *
 * When doing `?`, you would see:
 * w[abc]
 *
 * If there is also:
 *   -> wd
 * you would see:
 * w[?]
 */
#define MAX_CHILDREN_SHOW 7

static const RCmdDescHelp not_defined_help = {
	.usage = "Usage not defined",
	.summary = "Help summary not defined",
	.description = "Help description not defined.",
};

static const RCmdDescHelp root_help = {
	.usage = "[.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...",
	.description = "",
};

static R_TH_LOCAL int value = 0;

#define NCMDS (sizeof (cmd->cmds)/sizeof (*cmd->cmds))
R_LIB_VERSION (r_cmd);

static bool cmd_desc_set_parent(RCmdDesc *cd, RCmdDesc *parent) {
	r_return_val_if_fail (cd && !cd->parent, false);
	if (parent) {
		cd->parent = parent;
		r_pvector_push (&parent->children, cd);
		parent->n_children++;
	}
	return true;
}

static void cmd_desc_unset_parent(RCmdDesc *cd) {
	r_return_if_fail (cd && cd->parent);
	RCmdDesc *parent = cd->parent;
	r_pvector_remove_data (&parent->children, cd);
	parent->n_children--;
	cd->parent = NULL;
}

static bool cmd_desc_remove_from_ht_cmds(RCmd *cmd, RCmdDesc *cd) {
	void **it_cd;
	bool res = ht_pp_delete (cmd->ht_cmds, cd->name);
	r_return_val_if_fail (res, false);
	r_cmd_desc_children_foreach (cd, it_cd) {
		RCmdDesc *child_cd = *it_cd;
		cmd_desc_remove_from_ht_cmds (cmd, child_cd);
	}
	return res;
}

static void cmd_desc_free(RCmdDesc *cd) {
	if (!cd) {
		return;
	}

	r_pvector_clear (&cd->children);
	free (cd->name);
	free (cd);
}

static RCmdDesc *create_cmd_desc(RCmd *cmd, RCmdDesc *parent, RCmdDescType type, const char *name, const RCmdDescHelp *help, bool ht_insert) {
	RCmdDesc *res = R_NEW0 (RCmdDesc);
	if (!res) {
		return NULL;
	}
	res->type = type;
	res->name = strdup (name);
	if (!res->name) {
		goto err;
	}
	res->n_children = 0;
	res->help = help? help: &not_defined_help;
	r_pvector_init (&res->children, (RPVectorFree)cmd_desc_free);
	if (ht_insert && !ht_pp_insert (cmd->ht_cmds, name, res)) {
		goto err;
	}
	cmd_desc_set_parent (res, parent);
	return res;
err:
	cmd_desc_free (res);
	return NULL;
}

static void alias_freefn(HtPPKv *kv) {
	char *k = kv->key;
	RCmdAliasVal *v = kv->value;

	free (v->data);
	free (k);
	free (v);
}

static void *alias_dupkey(const void *k) {
	return strdup ((const char *)k);
}

static void *alias_dupvalue(const void *v_void) {
	RCmdAliasVal *v = (RCmdAliasVal *)v_void;
	RCmdAliasVal *vcopy = R_NEW (RCmdAliasVal);
	if (!vcopy) {
		return NULL;
	}
	ut8 *data = malloc (v->sz);
	if (!data) {
		free (vcopy);
		return NULL;
	}
	vcopy->is_data = v->is_data;
	vcopy->is_str = v->is_str;
	vcopy->sz = v->sz;
	vcopy->data = data;
	memcpy (vcopy->data, v->data, v->sz);

	return vcopy;
}

static ut32 alias_calcsizeK(const void *k) {
	return strlen ((const char *)k);
}

static ut32 alias_calcsizeV(const void *v) {
	return ((RCmdAliasVal *)v)->sz;
}

static int alias_cmp(const void *k1, const void *k2) {
	return strcmp ((const char *)k1, (const char *)k2);
}

static ut32 alias_hashfn(const void *k_in) {
	/* djb2 algorithm by Dan Bernstein */
	ut32 hash = 5381;
	ut8 c;
	const char *k = k_in;

	while (*k) {
		c = *k++;
		/* hash * 33 + c */
		hash += (hash << 5) + c;
	}

	return hash;
}

R_API void r_cmd_alias_init(RCmd *cmd) {
	HtPPOptions opt = {0};
	opt.cmp = alias_cmp;
	opt.hashfn = alias_hashfn;
	opt.dupkey = alias_dupkey;
	opt.dupvalue = alias_dupvalue;
	opt.calcsizeK = alias_calcsizeK;
	opt.calcsizeV = alias_calcsizeV;
	opt.freefn = alias_freefn;

	cmd->aliases = ht_pp_new_opt (&opt);
}

R_API RCmd *r_cmd_new(void) {
	int i;
	RCmd *cmd = R_NEW0 (RCmd);
	if (!cmd) {
		return cmd;
	}
	cmd->lcmds = r_list_new ();
	for (i = 0; i < NCMDS; i++) {
		cmd->cmds[i] = NULL;
	}
	cmd->nullcallback = cmd->data = NULL;
	cmd->ht_cmds = ht_pp_new0 ();
	cmd->root_cmd_desc = create_cmd_desc (cmd, NULL, R_CMD_DESC_TYPE_ARGV, "", &root_help, true);
	r_core_plugin_init (cmd);
	r_cmd_macro_init (&cmd->macro);
	r_cmd_alias_init (cmd);
	return cmd;
}

R_API RCmd *r_cmd_free(RCmd *cmd) {
	int i;
	if (!cmd) {
		return NULL;
	}
	ht_up_free (cmd->ts_symbols_ht);
	r_cmd_alias_free (cmd);
	r_cmd_macro_fini (&cmd->macro);
	ht_pp_free (cmd->ht_cmds);
	// dinitialize plugin commands
	r_core_plugin_fini (cmd);
	r_list_free (cmd->plist);
	r_list_free (cmd->lcmds);
	for (i = 0; i < NCMDS; i++) {
		if (cmd->cmds[i]) {
			R_FREE (cmd->cmds[i]);
		}
	}
	cmd_desc_free (cmd->root_cmd_desc);
	free (cmd);
	return NULL;
}

R_API RCmdDesc *r_cmd_get_root(RCmd *cmd) {
	return cmd->root_cmd_desc;
}

R_API RCmdDesc *r_cmd_get_desc(RCmd *cmd, const char *cmd_identifier) {
	r_return_val_if_fail (cmd && cmd_identifier, NULL);
	char *cmdid = strdup (cmd_identifier);
	char *end_cmdid = cmdid + strlen (cmdid);
	RCmdDesc *res = NULL;
	bool is_exact_match = true;
	// match longer commands first
	while (*cmdid) {
		RCmdDesc *cd = ht_pp_find (cmd->ht_cmds, cmdid, NULL);
		if (cd) {
			switch (cd->type) {
			case R_CMD_DESC_TYPE_ARGV:
				if (!is_exact_match) {
					break;
				}
				// fallthrough
			case R_CMD_DESC_TYPE_GROUP:
				// fallthrough
			case R_CMD_DESC_TYPE_OLDINPUT:
				res = cd;
				goto out;
			case R_CMD_DESC_TYPE_INNER:
				break;
			}
		}
		is_exact_match = false;
		*(--end_cmdid) = '\0';
	}
out:
	free (cmdid);
	return res;
}

// This struct exists to store the index during hashtable foreach.
typedef struct {
	const char **keys;
	size_t current_key;
} AliasKeylist;

static bool get_keys(void *keylist_in, const void *k, const void *v) {
	AliasKeylist *keylist = keylist_in;
	keylist->keys[keylist->current_key++] = (const char *)k;
	return true;
}

R_API const char **r_cmd_alias_keys(RCmd *cmd) {
	AliasKeylist keylist;

	keylist.keys = R_NEWS (const char *, cmd->aliases->count);
	if (!keylist.keys) {
		return NULL;
	}

	keylist.current_key = 0;
	ht_pp_foreach (cmd->aliases, get_keys, &keylist);

	// We don't need to return a count - it's already in cmd->aliases.
	return keylist.keys;
}

R_API void r_cmd_alias_free(RCmd *cmd) {
	ht_pp_free (cmd->aliases);
	cmd->aliases = NULL;
}

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k) {
	return ht_pp_delete(cmd->aliases, k);
}

R_API int r_cmd_alias_set_cmd(RCmd *cmd, const char *k, const char *v) {
	RCmdAliasVal val;
	val.data = (ut8 *)v;
	if (!val.data) {
		return 1;
	}
	val.sz = strlen (v) + 1;
	val.is_str = true;
	val.is_data = false;

	return ht_pp_update (cmd->aliases, k, &val);
}

R_API int r_cmd_alias_set_str(RCmd *cmd, const char *k, const char *v) {
	RCmdAliasVal val;
	val.data = (ut8 *)strdup (v);
	if (!val.data) {
		return 1;
	}
	val.is_str = true;
	val.is_data = true;

	/* No trailing newline */
	int len = strlen (v);
	while (len-- > 0) {
		if (v[len] == '\r' || v[len] == '\n') {
			val.data[len] = '\0';
		} else {
			break;
		}
	}
	// len is strlen()-1 now
	val.sz = len + 2;

	int ret = ht_pp_update (cmd->aliases, k, &val);
	free (val.data);
	return ret;
}

R_API int r_cmd_alias_set_raw(RCmd *cmd, const char *k, const ut8 *v, int sz) {
	int i;

	if (sz < 1) {
		return 1;
	}

	RCmdAliasVal val;
	val.data = malloc (sz);
	if (!val.data) {
		return 1;
	}

	memcpy (val.data, v, sz);
	val.sz = sz;

	/* If it's a string already, we speed things up later by checking now */
	const ut8 *firstnull = NULL;
	bool is_binary = false;
	for (i = 0; i < sz; i++) {
		/* \0 before expected -> not string */
		if (v[i] == '\0') {
			firstnull = &v[i];
			break;
		}

		/* Non-ascii character -> not string */
		if (!IS_PRINTABLE(v[i]) && !IS_WHITECHAR(v[i])) {
			is_binary = true;
			break;
		}
	}

	if (firstnull == &v[sz-1] && !is_binary) {
		/* Data is already a string */
		val.is_str = true;
	} else if (!firstnull && !is_binary) {
		/* Data is an unterminated string */
		val.sz++;
		ut8 *data = realloc (val.data, val.sz);
		if (!data) {
			free (val.data);
			return 1;
		}
		val.data = data;
		val.data[val.sz - 1] = '\0';
		val.is_str = true;
	} else {
		/* Data has nulls or non-ascii, not a string */
		val.is_str = false;
	}

	val.is_data = true;

	if (val.is_str) {
		/* No trailing newline */
		int len = val.sz - 1;
		while (len-- > 0) {
			if (v[len] == '\r' || v[len] == '\n') {
				val.data[len] = '\0';
			} else {
				break;
			}
		}
		// len is strlen()-1 now
		val.sz = len + 2;
	}

	int ret = ht_pp_update (cmd->aliases, k, &val);
	free (val.data);
	return ret;
}

R_API RCmdAliasVal *r_cmd_alias_get(RCmd *cmd, const char *k) {
	r_return_val_if_fail (cmd && cmd->aliases && k, NULL);
	return ht_pp_find (cmd->aliases, k, NULL);
}

static ut8 *alias_append_internal(int *out_szp, const RCmdAliasVal *first, const ut8 *second, int second_sz) {
	ut8* out;
	int out_sz;

	/* If appending to a string, always overwrite the trailing \0 */
	int bytes_from_first = first->is_str
		? first->sz - 1
		: first->sz;

	out_sz = bytes_from_first + second_sz;
	out = malloc (out_sz);
	if (!out) {
		return NULL;
	}

	/* Copy full buffer if raw bytes. Stop before \0 if string. */
	memcpy (out, first->data, bytes_from_first);
	/* Always copy all bytes from second, including trailing \0 */
	memcpy (out+bytes_from_first, second, second_sz);

	if (out_sz) {
		*out_szp = out_sz;
	}
	return out;
}

R_API int r_cmd_alias_append_str(RCmd *cmd, const char *k, const char *a) {
	RCmdAliasVal *v_old = r_cmd_alias_get (cmd, k);
	if (v_old) {
		if (!v_old->is_data) {
			return 1;
		}
		int new_len = 0;
		ut8* new = alias_append_internal (&new_len, v_old, (ut8 *)a, strlen (a) + 1);
		if (!new) {
			return 1;
		}
		r_cmd_alias_set_raw (cmd, k, new, new_len);
		free (new);
	} else {
		r_cmd_alias_set_str (cmd, k, a);
	}
	return 0;
}

R_API int r_cmd_alias_append_raw(RCmd *cmd, const char *k, const ut8 *a, int sz) {
	RCmdAliasVal *v_old = r_cmd_alias_get (cmd, k);
	if (v_old) {
		if (!v_old->is_data) {
			return 1;
		}
		int new_len = 0;
		ut8 *new = alias_append_internal (&new_len, v_old, a, sz);
		if (!new) {
			return 1;
		}
		r_cmd_alias_set_raw (cmd, k, new, new_len);
		free (new);
	} else {
		r_cmd_alias_set_raw (cmd, k, a, sz);
	}
	return 0;
}

/* Returns a new copy of v->data. If !v->is_str, hex escaped */
R_API char *r_cmd_alias_val_strdup(RCmdAliasVal *v) {
	if (v->is_str) {
		return strdup ((char *)v->data);
	}
	return r_str_escape_raw (v->data, v->sz);
}

/* Returns a new copy of v->data. If !v->is_str, b64 encoded. */
R_API char *r_cmd_alias_val_strdup_b64(RCmdAliasVal *v) {
	if (v->is_str) {
		return strdup ((char *)v->data);
	}

	return r_base64_encode_dyn ((char *)v->data, v->sz);
}

R_API void r_cmd_set_data(RCmd *cmd, void *data) {
	cmd->data = data;
}

R_API bool r_cmd_add(RCmd *c, const char *cmd, RCmdCb cb) {
	int idx = (ut8)cmd[0];
	RCmdItem *item = c->cmds[idx];
	if (!item) {
		item = R_NEW0 (RCmdItem);
		c->cmds[idx] = item;
	}
	strncpy (item->cmd, cmd, sizeof (item->cmd)-1);
	item->callback = cb;
	return true;
}

R_API void r_cmd_del(RCmd *cmd, const char *command) {
	int idx = (ut8)command[0];
	R_FREE (cmd->cmds[idx]);
}

#if SHELLFILTER
static char *r_cmd_filter_special(const char *input) {
	char *s = strdup (input);
	// XXX workaround to call macros with quotes
	if (*s == '(') {
		return s;
	}
	r_str_trim_args (s);
	return s;
}
#endif

R_API int r_cmd_call(RCmd *cmd, const char *input) {
	struct r_cmd_item_t *c;
	int ret = -1;
	RListIter *iter;
	RCorePlugin *cp;
	r_return_val_if_fail (cmd && input, -1);
	if (!*input) {
		if (cmd->nullcallback) {
			ret = cmd->nullcallback (cmd->data);
		}
	} else {
		char *nstr = NULL;
		RCmdAliasVal *v = r_cmd_alias_get (cmd, input);
		if (v && v->is_data) {
			char *v_str = r_cmd_alias_val_strdup (v);
			r_cons_strcat (v_str);
			free (v_str);
			return true;
		}
		r_list_foreach (cmd->plist, iter, cp) {
			if (cp->call && cp->call (cmd->data, input)) {
				free (nstr);
				return true;
			}
		}
		if (!*input) {
			free (nstr);
			return -1;
		}
		c = cmd->cmds[((ut8)input[0]) & 0xff];
		if (c && c->callback) {
			if (*input) {
#if SHELLFILTER
				char *s = r_cmd_filter_special (input + 1);
				ret = c->callback (cmd->data, s);
				free (s);
#else
				ret = c->callback (cmd->data, input + 1);
#endif
			} else {
				ret = c->callback (cmd->data, "");
			}
		} else {
			ret = -1;
		}
		free (nstr);
	}
	return ret;
}

static RCmdStatus int2cmdstatus(int v) {
	if (v == -2) {
		return R_CMD_STATUS_EXIT;
	} else if (v < 0) {
		return R_CMD_STATUS_ERROR;
	} else {
		return R_CMD_STATUS_OK;
	}
}

R_API RCmdStatus r_cmd_call_parsed_args(RCmd *cmd, RCmdParsedArgs *args) {
	RCmdStatus res = R_CMD_STATUS_INVALID;

	// As old RCorePlugin do not register new commands in RCmd, we have no
	// way of knowing if one of those is able to handle the input, so we
	// have to pass the input to all of them before looking into the
	// RCmdDesc tree
	RListIter *iter;
	RCorePlugin *cp;
	char *exec_string = r_cmd_parsed_args_execstr (args);
	r_list_foreach (cmd->plist, iter, cp) {
		if (cp->call && cp->call (cmd->data, exec_string)) {
			res = R_CMD_STATUS_OK;
			break;
		}
	}
	R_FREE (exec_string);
	if (res == R_CMD_STATUS_OK) {
		return res;
	}

	RCmdDesc *cd = r_cmd_get_desc (cmd, r_cmd_parsed_args_cmd (args));
	if (!cd) {
		return R_CMD_STATUS_INVALID;
	}

	res = R_CMD_STATUS_INVALID;
	switch (cd->type) {
	case R_CMD_DESC_TYPE_GROUP:
		if (!cd->d.group_data.exec_cd) {
			break;
		}
		cd = cd->d.group_data.exec_cd;
		// fallthrough
	case R_CMD_DESC_TYPE_ARGV:
		if (cd->d.argv_data.cb) {
			res = cd->d.argv_data.cb (cmd->data, args->argc, (const char **)args->argv);
		}
		break;
	case R_CMD_DESC_TYPE_OLDINPUT:
		exec_string = r_cmd_parsed_args_execstr (args);
		res = int2cmdstatus (cd->d.oldinput_data.cb (cmd->data, exec_string + strlen (cd->name)));
		R_FREE (exec_string);
		break;
	default:
		res = R_CMD_STATUS_INVALID;
		R_LOG_ERROR ("RCmdDesc type not handled");
		break;
	}
	return res;
}

static void fill_children_chars(RStrBuf *sb, RCmdDesc *cd) {
	if (cd->help->options) {
		r_strbuf_append (sb, cd->help->options);
		return;
	}

	RStrBuf csb;
	r_strbuf_init (&csb);

	void **it;
	r_cmd_desc_children_foreach (cd, it) {
		RCmdDesc *child = *(RCmdDesc **)it;
		if (r_str_startswith (child->name, cd->name) && strlen (child->name) == strlen (cd->name) + 1) {
			r_strbuf_appendf (&csb, "%c", child->name[strlen (cd->name)]);
		}
	}

	if (r_strbuf_is_empty (&csb) || r_strbuf_length (&csb) >= MAX_CHILDREN_SHOW) {
		r_strbuf_fini (&csb);
		r_strbuf_set (&csb, "?");
	}

	if (!cd->n_children || r_cmd_desc_has_handler (cd)) {
		r_strbuf_prepend (&csb, "[");
		r_strbuf_append (&csb, "]");
	} else {
		r_strbuf_prepend (&csb, "<");
		r_strbuf_append (&csb, ">");
	}
	char *tmp = r_strbuf_drain_nofree (&csb);
	r_strbuf_append (sb, tmp);
	free (tmp);
}

static bool show_children_shortcut(RCmdDesc *cd) {
	return cd->n_children || cd->help->options || cd->type == R_CMD_DESC_TYPE_OLDINPUT;
}

static void fill_usage_strbuf(RStrBuf *sb, RCmdDesc *cd, bool use_color) {
	RCons *cons = r_cons_singleton ();
	const char *pal_label_color = use_color? cons->context->pal.label: "",
		   *pal_args_color = use_color? cons->context->pal.args: "",
		   *pal_input_color = use_color? cons->context->pal.input: "",
		   *pal_help_color = use_color? cons->context->pal.help: "",
		   *pal_reset = use_color? cons->context->pal.reset: "";

	r_strbuf_appendf (sb, "%sUsage: %s", pal_label_color, pal_reset);
	if (cd->help->usage) {
		r_strbuf_appendf (sb, "%s%s%s", cd->help->usage, pal_args_color, pal_reset);
	} else {
		r_strbuf_appendf (sb, "%s%s", pal_input_color, cd->name);
		if (show_children_shortcut (cd)) {
			r_strbuf_append (sb, pal_reset);
			fill_children_chars (sb, cd);
		}
		if (R_STR_ISNOTEMPTY (cd->help->args_str)) {
			r_strbuf_appendf (sb, "%s%s%s", pal_args_color, cd->help->args_str, pal_reset);
		}
	}
	if (cd->help->summary) {
		r_strbuf_appendf (sb, "   %s# %s%s", pal_help_color, cd->help->summary, pal_reset);
	}
	r_strbuf_append (sb, "\n");
}

static size_t calc_padding_len(RCmdDesc *cd) {
	size_t name_len = strlen (cd->name);
	size_t args_len = 0;
	size_t children_length = 0;
	if (show_children_shortcut (cd)) {
		RStrBuf sb;
		r_strbuf_init (&sb);
		fill_children_chars (&sb, cd);
		children_length += r_strbuf_length (&sb);
		r_strbuf_fini (&sb);
	}
	if (R_STR_ISNOTEMPTY (cd->help->args_str)) {
		args_len = strlen (cd->help->args_str);
	}
	return name_len + args_len + children_length;
}

static size_t update_max_len(RCmdDesc *cd, size_t max_len) {
	size_t val = calc_padding_len (cd);
	return val > max_len? val: max_len;
}

static void print_child_help(RStrBuf *sb, RCmdDesc *cd, size_t max_len, bool use_color) {
	size_t str_len = calc_padding_len (cd);
	int padding = str_len < max_len? max_len - str_len: 0;
	const char *cd_summary = r_str_get (cd->help->summary);

	RCons *cons = r_cons_singleton ();
	const char *pal_args_color = use_color? cons->context->pal.args: "",
		   *pal_opt_color = use_color? cons->context->pal.reset: "",
		   *pal_help_color = use_color? cons->context->pal.help: "",
		   *pal_input_color = use_color? cons->context->pal.input: "",
		   *pal_reset = use_color? cons->context->pal.reset: "";

	r_strbuf_appendf (sb, "| %s%s", pal_input_color, cd->name);
	if (show_children_shortcut (cd)) {
		r_strbuf_append (sb, pal_opt_color);
		fill_children_chars (sb, cd);
	}
	if (R_STR_ISNOTEMPTY (cd->help->args_str)) {
		r_strbuf_appendf (sb, "%s%s", pal_args_color, cd->help->args_str);
	}
	r_strbuf_appendf (sb, " %*s%s# %s%s\n", padding, "", pal_help_color, cd_summary, pal_reset);
}

static char *argv_group_get_help(RCmd *cmd, RCmdDesc *cd, bool use_color) {
	RStrBuf *sb = r_strbuf_new (NULL);
	fill_usage_strbuf (sb, cd, use_color);

	void **it_cd;
	size_t max_len = 0;

	r_cmd_desc_children_foreach (cd, it_cd) {
		RCmdDesc *child = *(RCmdDesc **)it_cd;
		max_len = update_max_len (child, max_len);
	}

	r_cmd_desc_children_foreach (cd, it_cd) {
		RCmdDesc *child = *(RCmdDesc **)it_cd;
		print_child_help (sb, child, max_len, use_color);
	}
	return r_strbuf_drain (sb);
}

static char *argv_get_help(RCmd *cmd, RCmdDesc *cd, RCmdParsedArgs *a, size_t detail, bool use_color) {
	RCons *cons = r_cons_singleton ();
	const char *pal_help_color = use_color? cons->context->pal.help: "",
		   *pal_input_color = use_color? cons->context->pal.input: "",
		   *pal_label_color = use_color? cons->context->pal.label: "",
		   *pal_reset = use_color? cons->context->pal.reset: "";

	RStrBuf *sb = r_strbuf_new (NULL);

	fill_usage_strbuf (sb, cd, use_color);

	switch (detail) {
	case 1:
		return r_strbuf_drain (sb);
	case 2:
		if (cd->help->description) {
			r_strbuf_appendf (sb, "\n%s\n", cd->help->description);
		}
		if (cd->help->examples) {
			r_strbuf_appendf (sb, "\n%sExamples:%s\n", pal_label_color, pal_reset);
			const RCmdDescExample *it = cd->help->examples;
			while (it->example) {
				r_strbuf_appendf (sb, "| %s%s%s %s# %s%s\n", pal_input_color,
					it->example, pal_reset, pal_help_color, it->comment, pal_reset);
				it++;
			}
		}
		return r_strbuf_drain (sb);
	default:
		r_strbuf_free (sb);
		return NULL;
	}
}

static char *oldinput_get_help(RCmd *cmd, RCmdDesc *cd, RCmdParsedArgs *a) {
	const char *s = NULL;
	r_cons_push ();
	RCmdStatus status = r_cmd_call_parsed_args (cmd, a);
	if (status == R_CMD_STATUS_OK) {
		r_cons_filter ();
		s = r_cons_get_buffer ();
	}
	char *res = strdup (r_str_get (s));
	r_cons_pop ();
	return res;
}

R_API char *r_cmd_get_help(RCmd *cmd, RCmdParsedArgs *args, bool use_color) {
	char *cmdid = strdup (r_cmd_parsed_args_cmd (args));
	char *cmdid_p = cmdid + strlen (cmdid) - 1;
	size_t detail = 0;
	while (cmdid_p >= cmdid && *cmdid_p == '?') {
		*cmdid_p = '\0';
		cmdid_p--;
		detail++;
	}

	if (detail == 0) {
		// there should be at least one `?`
		free (cmdid);
		return NULL;
	}

	RCmdDesc *cd = cmdid_p >= cmdid? r_cmd_get_desc (cmd, cmdid): r_cmd_get_root (cmd);
	free (cmdid);
	if (!cd || !cd->help) {
		return NULL;
	}

	switch (cd->type) {
	case R_CMD_DESC_TYPE_GROUP:
		if (detail > 1 && cd->d.group_data.exec_cd) {
			cd = cd->d.group_data.exec_cd;
		}
		// fallthrough
	case R_CMD_DESC_TYPE_ARGV:
		if (detail == 1 && !r_pvector_empty (&cd->children)) {
			if (args->argc > 1) {
				return NULL;
			}
			return argv_group_get_help (cmd, cd, use_color);
		}
		return argv_get_help (cmd, cd, args, detail, use_color);
	case R_CMD_DESC_TYPE_OLDINPUT:
		return oldinput_get_help (cmd, cd, args);
	case R_CMD_DESC_TYPE_INNER:
		r_warn_if_reached ();
		return NULL;
	}
	return NULL;
}

/** macro.c **/

R_API RCmdMacroItem *r_cmd_macro_item_new(void) {
	return R_NEW0 (RCmdMacroItem);
}

R_API void r_cmd_macro_item_free(RCmdMacroItem *item) {
	if (item) {
		free (item->name);
		free (item->args);
		free (item->code);
		free (item);
	}
}

R_API void r_cmd_macro_init(RCmdMacro *mac) {
	mac->counter = 0;
	mac->_brk_value = 0;
	mac->brk_value = &mac->_brk_value;
	mac->cb_printf = (void *)printf;
	mac->num = NULL;
	mac->user = NULL;
	mac->cmd = NULL;
	mac->macros = r_list_newf ((RListFree)r_cmd_macro_item_free);
}

R_API void r_cmd_macro_fini(RCmdMacro *mac) {
	r_list_free (mac->macros);
	mac->macros = NULL;
}

// XXX add support single line function definitions
// XXX add support for single name multiple nargs macros
R_API bool r_cmd_macro_add(RCmdMacro *mac, const char *oname) {
	struct r_cmd_macro_item_t *macro;
	char *name, *args = NULL;
	//char buf[R_CMD_MAXLEN];
	RCmdMacroItem *m;
	bool macro_update = false;
	RListIter *iter;
	char *pbody;
	// char *bufp;
	char *ptr;
	int lidx;

	if (!*oname) {
		r_cmd_macro_list (mac, 0);
		return false;
	}

	name = strdup (oname);
	if (!name) {
		return false;
	}

	pbody = strchr (name, ';');
	if (!pbody) {
		R_LOG_ERROR ("Invalid macro body");
		free (name);
		return false;
	}
	*pbody = '\0';
	pbody++;

	if (*name && name[1] && name[strlen (name)-1]==')') {
		R_LOG_ERROR ("missing macro body?");
		free (name);
		return false;
	}

	macro = NULL;
	ptr = strchr (name, ' ');
	if (ptr) {
		*ptr = '\0';
		args = ptr +1;
	}
	macro_update = false;
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (name, m->name)) {
			macro = m;
			// keep macro->name
			free (macro->code);
			free (macro->args);
			macro_update = true;
			break;
		}
	}
	if (ptr) {
		*ptr = ' ';
	}
	if (!macro) {
		macro = r_cmd_macro_item_new ();
		if (!macro) {
			free (name);
			return false;
		}
		macro->name = strdup (name);
	}

	macro->codelen = (pbody[0])? strlen (pbody)+2 : 4096;
	macro->code = (char *)malloc (macro->codelen);
	*macro->code = '\0';
	macro->nargs = 0;
	if (!args) {
		args = "";
	}
	macro->args = strdup (args);
	ptr = strchr (macro->name, ' ');
	if (ptr) {
		*ptr = '\0';
		macro->nargs = r_str_word_set0 (ptr+1);
	}

	for (lidx = 0; pbody[lidx]; lidx++) {
		if (pbody[lidx] == ';') {
			pbody[lidx] = '\n';
		} else if (pbody[lidx] == ')' && pbody[lidx - 1] == '\n') {
			pbody[lidx] = '\0';
		}
	}
	strncpy (macro->code, pbody, macro->codelen);
	macro->code[macro->codelen-1] = 0;
	if (macro_update == false) {
		r_list_append (mac->macros, macro);
	}
	free (name);
	return true;
}

R_API bool r_cmd_macro_rm(RCmdMacro *mac, const char *_name) {
	r_return_val_if_fail (mac && _name, false);
	RListIter *iter;
	RCmdMacroItem *m;
	char *name = strdup (_name);
	if (!name) {
		return false;
	}
	char *ptr = strchr (name, ')');
	if (ptr) {
		*ptr = '\0';
	}
	bool ret = false;
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (m->name, name)) {
			r_list_delete (mac->macros, iter);
			R_LOG_DEBUG ("Macro '%s' removed", name);
			ret = true;
			break;
		}
	}
	free (name);
	return ret;
}

static void macro_meta(RCmdMacro *mac) {
	RCmdMacroItem *m;
	int j;
	RListIter *iter;
	r_list_foreach (mac->macros, iter, m) {
		mac->cb_printf ("\"(%s %s; ", m->name, m->args);
		for (j = 0; m->code[j]; j++) {
			if (m->code[j] == '\n') {
				mac->cb_printf (";");
			} else {
				mac->cb_printf ("%c", m->code[j]);
			}
		}
		mac->cb_printf (")\"\n");
	}
}
// TODO: use mac->cb_printf which is r_cons_printf at the end
R_API void r_cmd_macro_list(RCmdMacro *mac, int mode) {
	if (mode == '*') {
		macro_meta (mac);
		return;
	}
	if (mode == 'j') {
		R_LOG_ERROR ("TODO: JSON output for macros");
		return;
	}
	RCmdMacroItem *m;
	int j, idx = 0;
	RListIter *iter;
	r_list_foreach (mac->macros, iter, m) {
		mac->cb_printf ("%d (%s %s; ", idx, m->name, m->args);
		for (j = 0; m->code[j]; j++) {
			if (m->code[j] == '\n') {
				mac->cb_printf ("; ");
			} else {
				mac->cb_printf ("%c", m->code[j]);
			}
		}
		mac->cb_printf (")\n");
		idx++;
	}
}


#if 0
(define name value
  f $0 @ $1)

(define loop cmd
  loop:
  ? $0 == 0
  ?? .loop:
  )

.(define patata 3)
#endif

R_API int r_cmd_macro_cmd_args(RCmdMacro *mac, const char *ptr, const char *args, int nargs) {
	int i, j;
	char *pcmd, cmd[R_CMD_MAXLEN];
	const char *arg = args;

	for (*cmd = i = j = 0; j < R_CMD_MAXLEN && ptr[j]; i++,j++) {
		if (ptr[j]=='$') {
			if (ptr[j+1]>='0' && ptr[j+1]<='9') {
				int wordlen;
				int w = ptr[j+1]-'0';
				const char *word = r_str_word_get0 (arg, w);
				if (word && *word) {
					wordlen = strlen (word);
					if ((i + wordlen + 1) >= sizeof (cmd)) {
						return -1;
					}
					memcpy (cmd+i, word, wordlen+1);
					i += wordlen-1;
					j++;
				} else {
					R_LOG_ERROR ("Undefined argument %d", w);
				}
			} else if (ptr[j+1]=='@') {
				char off[32];
				int offlen;
				offlen = snprintf (off, sizeof (off), "%d",
					mac->counter);
				if ((i + offlen + 1) >= sizeof (cmd)) {
					return -1;
				}
				memcpy (cmd+i, off, offlen+1);
				i += offlen-1;
				j++;
			} else {
				cmd[i] = ptr[j];
				cmd[i + 1] = '\0';
			}
		} else {
			cmd[i] = ptr[j];
			cmd[i + 1] = '\0';
		}
	}
	for (pcmd = cmd; *pcmd && (*pcmd == ' ' || *pcmd == '\t'); pcmd++) {
		;
	}
	//eprintf ("-pre %d\n", (int)mac->num->value);
	int xx = (*pcmd==')')? 0: mac->cmd (mac->user, pcmd);
	//eprintf ("-pos %p %d\n", mac->num, (int)mac->num->value);
	return xx;
}

R_API char *r_cmd_macro_label_process(RCmdMacro *mac, RCmdMacroLabel *labels, int *labels_n, char *ptr) {
	int i;
	for (; *ptr == ' '; ptr++) {
		;
	}
	if (ptr[strlen (ptr) - 1]==':' && !strchr (ptr, ' ')) {
		/* label detected */
		if (ptr[0] == '.') {
		//	eprintf("---> GOTO '%s'\n", ptr+1);
			/* goto */
			for (i = 0; i < *labels_n; i++) {
			//	eprintf("---| chk '%s'\n", labels[i].name);
				if (!strcmp (ptr + 1, labels[i].name)) {
					return labels[i].ptr;
				}
			}
			return NULL;
			/* conditional goto */
		} else if (ptr[0]=='?' && ptr[1]=='!' && ptr[2] != '?') {
			if (mac->num && mac->num->value != 0) {
				char *label = ptr + 3;
				for (; *label == ' ' || *label == '.'; label++) {
					;
				}
				// eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for (i = 0; i < *labels_n; i++) {
					if (!strcmp (label, labels[i].name)) {
						return labels[i].ptr;
					}
				}
				return NULL;
			}
			/* conditional goto */
		} else if (ptr[0] == '?' && ptr[1] == '?' && ptr[2] != '?') {
			if (mac->num->value == 0) {
				char *label = ptr + 3;
				for (; label[0] == ' ' || label[0] == '.'; label++) {
					;
				}
				//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for (i = 0; i < *labels_n; i++) {
					if (!strcmp (label, labels[i].name)) {
						return labels[i].ptr;
					}
				}
				return NULL;
			}
		} else {
			for (i = 0; i < *labels_n; i++) {
		//	eprintf("---| chk '%s'\n", labels[i].name);
				if (!strcmp (ptr + 1, labels[i].name)) {
					i = 0;
					break;
				}
			}
			/* Add label */
		//	eprintf("===> ADD LABEL(%s)\n", ptr);
			if (i == 0) {
				strncpy (labels[*labels_n].name, ptr, 64);
				labels[*labels_n].ptr = ptr+strlen (ptr)+1;
				*labels_n = *labels_n + 1;
			}
		}
		ptr += strlen (ptr) + 1;
	}
	return ptr;
}

/* TODO: add support for spaced arguments */
static R_TH_LOCAL int macro_level = 0;
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name) {
	char *args;
	int nargs = 0;
	char *str, *ptr, *ptr2;
	RListIter *iter;
	RCmdMacroItem *m;
	/* labels */
	int labels_n = 0;
	struct r_cmd_macro_label_t labels[MACRO_LABELS];

	str = strdup (name);
	if (!str) {
		r_sys_perror ("strdup");
		return false;
	}
	ptr = strchr (str, ')');
	if (!ptr) {
		R_LOG_ERROR ("Missing end ')' parenthesis");
		free (str);
		return false;
	} else {
		*ptr = '\0';
	}

	args = strchr (str, ' ');
	if (args) {
		*args = '\0';
		args++;
		nargs = r_str_word_set0 (args);
	}

	macro_level++;
	if (macro_level > MACRO_LIMIT) {
		R_LOG_ERROR ("Maximum macro recursivity reached");
		macro_level--;
		free (str);
		return 0;
	}
	ptr = strchr (str, ';');
	if (ptr) {
		*ptr = 0;
	}

	r_cons_break_push (NULL, NULL);
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (str, m->name)) {
			char *ptr = m->code;
			char *end = strchr (ptr, '\n');
			if (m->nargs != 0 && nargs != m->nargs) {
				R_LOG_ERROR ("Macro '%s' expects %d args, not %d", m->name, m->nargs, nargs);
				macro_level--;
				free (str);
				r_cons_break_pop ();
				return false;
			}
			mac->brk = 0;
			do {
				if (end) {
					*end = '\0';
				}
				if (r_cons_is_breaked ()) {
					R_LOG_INFO ("Interrupted at (%s)", ptr);
					if (end) {
						*end = '\n';
					}
					free (str);
					r_cons_break_pop ();
					return false;
				}
				r_cons_flush ();
				/* Label handling */
				ptr2 = r_cmd_macro_label_process (mac, &(labels[0]), &labels_n, ptr);
				if (!ptr2) {
					R_LOG_ERROR ("Oops. invalid label name");
					break;
				} else if (ptr != ptr2) {
					ptr = ptr2;
					if (end) {
						*end = '\n';
					}
					end = strchr (ptr, '\n');
					continue;
				}
				/* Command execution */
				if (*ptr) {
					mac->num->value = value;
					int r = r_cmd_macro_cmd_args (mac, ptr, args, nargs);
					// TODO: handle quit? r == 0??
					// quit, exits the macro. like a break
					value = mac->num->value;
					if (r < 0) {
						free (str);
						r_cons_break_pop ();
						return r;
					}
				}
				if (end) {
					*end = '\n';
					ptr = end + 1;
				} else {
					macro_level --;
					free (str);
					goto out_clean;
				}

				/* Fetch next command */
				end = strchr (ptr, '\n');
			} while (!mac->brk);
			if (mac->brk) {
				macro_level--;
				free (str);
				goto out_clean;
			}
		}
	}
	R_LOG_ERROR ("No macro named '%s'", str);
	macro_level--;
	free (str);
out_clean:
	r_cons_break_pop ();
	return true;
}

R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value) {
	mac->brk = 1;
	mac->brk_value = NULL;
	mac->_brk_value = (ut64)r_num_math (mac->num, value);
	if (value && *value) {
		mac->brk_value = &mac->_brk_value;
	}
	return 0;
}

/* RCmdParsedArgs */

R_API RCmdParsedArgs *r_cmd_parsed_args_new(const char *cmd, int n_args, char **args) {
	r_return_val_if_fail (cmd && n_args >= 0, NULL);
	RCmdParsedArgs *res = R_NEW0 (RCmdParsedArgs);
	res->has_space_after_cmd = true;
	res->argc = n_args + 1;
	res->argv = R_NEWS0 (char *, res->argc);
	res->argv[0] = strdup (cmd);
	int i;
	for (i = 1; i < res->argc; i++) {
		res->argv[i] = strdup (args[i - 1]);
	}
	return res;
}

R_API RCmdParsedArgs *r_cmd_parsed_args_newcmd(const char *cmd) {
	return r_cmd_parsed_args_new (cmd, 0, NULL);
}

R_API RCmdParsedArgs *r_cmd_parsed_args_newargs(int n_args, char **args) {
	return r_cmd_parsed_args_new ("", n_args, args);
}

R_API void r_cmd_parsed_args_free(RCmdParsedArgs *a) {
	if (!a) {
		return;
	}

	int i;
	for (i = 0; i < a->argc; i++) {
		free (a->argv[i]);
	}
	free (a->argv);
	free (a);
}

static void free_array(char **arr, int n) {
	int i;
	for (i = 0; i < n; i++) {
		free (arr[i]);
	}
	free (arr);
}

R_API bool r_cmd_parsed_args_setargs(RCmdParsedArgs *a, int n_args, char **args) {
	r_return_val_if_fail (a && a->argv && a->argv[0], false);
	char **tmp = R_NEWS0 (char *, n_args + 1);
	if (!tmp) {
		return false;
	}
	tmp[0] = strdup (a->argv[0]);
	int i;
	for (i = 1; i < n_args + 1; i++) {
		tmp[i] = strdup (args[i - 1]);
		if (!tmp[i]) {
			goto err;
		}
	}
	free_array (a->argv, a->argc);
	a->argv = tmp;
	a->argc = n_args + 1;
	return true;
err:
	free_array (tmp, n_args + 1);
	return false;
}

R_API bool r_cmd_parsed_args_setcmd(RCmdParsedArgs *a, const char *cmd) {
	r_return_val_if_fail (a && a->argv && a->argv[0], false);
	char *tmp = strdup (cmd);
	if (!tmp) {
		return false;
	}
	free (a->argv[0]);
	a->argv[0] = tmp;
	return true;
}

static void parsed_args_iterateargs(RCmdParsedArgs *a, RStrBuf *sb) {
	int i;
	for (i = 1; i < a->argc; i++) {
		if (i > 1) {
			r_strbuf_append (sb, " ");
		}
		r_strbuf_append (sb, a->argv[i]);
	}
}

R_API char *r_cmd_parsed_args_argstr(RCmdParsedArgs *a) {
	r_return_val_if_fail (a && a->argv && a->argv[0], NULL);
	RStrBuf *sb = r_strbuf_new ("");
	parsed_args_iterateargs (a, sb);
	return r_strbuf_drain (sb);
}

R_API char *r_cmd_parsed_args_execstr(RCmdParsedArgs *a) {
	r_return_val_if_fail (a && a->argv && a->argv[0], NULL);
	RStrBuf *sb = r_strbuf_new (a->argv[0]);
	if (a->argc > 1 && a->has_space_after_cmd) {
		r_strbuf_append (sb, " ");
	}
	parsed_args_iterateargs (a, sb);
	return r_strbuf_drain (sb);
}

R_API const char *r_cmd_parsed_args_cmd(RCmdParsedArgs *a) {
	r_return_val_if_fail (a && a->argv && a->argv[0], NULL);
	return a->argv[0];
}

/* RCmdDescriptor */

// R2_580 - deprecate
static RCmdDesc *argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help, bool ht_insert) {
	RCmdDesc *res = create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_ARGV, name, help, ht_insert);
	if (!res) {
		return NULL;
	}

	res->d.argv_data.cb = cb;
	return res;
}

// R2_580 - deprecate
R_API RCmdDesc *r_cmd_desc_argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help) {
	r_return_val_if_fail (cmd && parent && name, NULL);
	return argv_new (cmd, parent, name, cb, help, true);
}

// R2_580 - deprecate
R_API RCmdDesc *r_cmd_desc_inner_new(RCmd *cmd, RCmdDesc *parent, const char *name, const RCmdDescHelp *help) {
	r_return_val_if_fail (cmd && parent && name, NULL);
	return create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_INNER, name, help, false);
}

// R2_580 - deprecate
R_API RCmdDesc *r_cmd_desc_group_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help, const RCmdDescHelp *group_help) {
	r_return_val_if_fail (cmd && parent && name, NULL);
	RCmdDesc *res = create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_GROUP, name, group_help, true);
	if (!res) {
		return NULL;
	}
	RCmdDesc *exec_cd = NULL;
	if (cb && help) {
		exec_cd = argv_new (cmd, res, name, cb, help, false);
		if (!exec_cd) {
			r_cmd_desc_remove (cmd, res);
			return NULL;
		}
	}

	res->d.group_data.exec_cd = exec_cd;
	return res;
}

// R2_580 - deprecate
R_API RCmdDesc *r_cmd_desc_oldinput_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdCb cb, const RCmdDescHelp *help) {
	r_return_val_if_fail (cmd && parent && name && cb, NULL);
	RCmdDesc *res = create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_OLDINPUT, name, help, true);
	if (!res) {
		return NULL;
	}
	res->d.oldinput_data.cb = cb;
	return res;
}

R_API RCmdDesc *r_cmd_desc_parent(RCmdDesc *cd) {
	r_return_val_if_fail (cd, NULL);
	return cd->parent;
}

R_API bool r_cmd_desc_has_handler(RCmdDesc *cd) {
	r_return_val_if_fail (cd, false);
	switch (cd->type) {
	case R_CMD_DESC_TYPE_ARGV:
		return cd->d.argv_data.cb;
	case R_CMD_DESC_TYPE_OLDINPUT:
		return cd->d.oldinput_data.cb;
	case R_CMD_DESC_TYPE_INNER:
		return false;
	case R_CMD_DESC_TYPE_GROUP:
		return cd->d.group_data.exec_cd && r_cmd_desc_has_handler (cd->d.group_data.exec_cd);
	}
	return false;
}

R_API bool r_cmd_desc_remove(RCmd *cmd, RCmdDesc *cd) {
	r_return_val_if_fail (cmd && cd, false);
	if (cd->parent) {
		cmd_desc_unset_parent (cd);
	}
	cmd_desc_remove_from_ht_cmds (cmd, cd);
	cmd_desc_free (cd);
	return true;
}
