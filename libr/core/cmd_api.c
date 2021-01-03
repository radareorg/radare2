/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_cmd.h>
#include <r_util.h>
#include <stdio.h>
#include <r_cons.h>
#include <r_cmd.h>
#include <r_util.h>

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

static int value = 0;

#define NCMDS (sizeof (cmd->cmds)/sizeof(*cmd->cmds))
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

static void cmd_desc_remove_from_ht_cmds(RCmd *cmd, RCmdDesc *cd) {
	void **it_cd;
	bool res = ht_pp_delete (cmd->ht_cmds, cd->name);
	r_return_if_fail (res);
	r_cmd_desc_children_foreach (cd, it_cd) {
		RCmdDesc *child_cd = *it_cd;
		cmd_desc_remove_from_ht_cmds (cmd, child_cd);
	}
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

R_API void r_cmd_alias_init(RCmd *cmd) {
	cmd->aliases.count = 0;
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
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

R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz) {
	if (sz) {
		*sz = cmd->aliases.count;
	}
	return cmd->aliases.keys;
}

R_API void r_cmd_alias_free (RCmd *cmd) {
	int i; // find
	for (i = 0; i < cmd->aliases.count; i++) {
		free (cmd->aliases.keys[i]);
		free (cmd->aliases.values[i]);
	}
	cmd->aliases.count = 0;
	R_FREE (cmd->aliases.keys);
	R_FREE (cmd->aliases.values);
	free (cmd->aliases.remote);
}

R_API bool r_cmd_alias_del (RCmd *cmd, const char *k) {
	int i; // find
	for (i = 0; i < cmd->aliases.count; i++) {
		if (!k || !strcmp (k, cmd->aliases.keys[i])) {
			R_FREE (cmd->aliases.values[i]);
			cmd->aliases.count--;
			if (cmd->aliases.count > 0) {
				if (i > 0) {
					free (cmd->aliases.keys[i]);
					cmd->aliases.keys[i] = cmd->aliases.keys[0];
					free (cmd->aliases.values[i]);
					cmd->aliases.values[i] = cmd->aliases.values[0];
				}
				memmove (cmd->aliases.values,
					cmd->aliases.values + 1,
					cmd->aliases.count * sizeof (void*));
				memmove (cmd->aliases.keys,
					cmd->aliases.keys + 1,
					cmd->aliases.count * sizeof (void*));
			}
			return true;
		}
	}
	return false;
}

// XXX: use a hashtable or any other standard data structure
R_API int r_cmd_alias_set(RCmd *cmd, const char *k, const char *v, int remote) {
	void *tofree = NULL;
	if (!strncmp (v, "base64:", 7)) {
		ut8 *s = r_base64_decode_dyn (v + 7, -1);
		if (s) {
			tofree = s;
			v = (const char *)s;
		}
	}
	int i;
	for (i = 0; i < cmd->aliases.count; i++) {
		int matches = !strcmp (k, cmd->aliases.keys[i]);
		if (matches) {
			free (cmd->aliases.values[i]);
			cmd->aliases.values[i] = strdup (v);
			free (tofree);
			return 1;
		}
	}

	i = cmd->aliases.count++;
	char **K = (char **)realloc (cmd->aliases.keys,
				     sizeof (char *) * cmd->aliases.count);
	if (K) {
		cmd->aliases.keys = K;
		int *R = (int *)realloc (cmd->aliases.remote,
				sizeof (int) * cmd->aliases.count);
		if (R) {
			cmd->aliases.remote = R;
			char **V = (char **)realloc (cmd->aliases.values,
					sizeof (char *) * cmd->aliases.count);
			if (V) {
				cmd->aliases.values = V;
				cmd->aliases.keys[i] = strdup (k);
				cmd->aliases.values[i] = strdup (v);
				cmd->aliases.remote[i] = remote;
			}
		}
	}
	free (tofree);
	return 0;
}

R_API const char *r_cmd_alias_get(RCmd *cmd, const char *k, int remote) {
	int matches, i;
	if (!cmd || !k) {
		return NULL;
	}
	for (i = 0; i < cmd->aliases.count; i++) {
		matches = 0;
		if (remote) {
			if (cmd->aliases.remote[i]) {
				matches = !strncmp (k, cmd->aliases.keys[i],
					strlen (cmd->aliases.keys[i]));
			}
		} else {
			matches = !strcmp (k, cmd->aliases.keys[i]);
		}
		if (matches) {
			return cmd->aliases.values[i];
		}
	}
	return NULL;
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
		const char *ji = r_cmd_alias_get (cmd, input, 1);
		if (ji) {
			if (*ji == '$') {
				r_cons_strcat (ji + 1);
				return true;
			} else {
				nstr = r_str_newf ("=!%s", input);
				input = nstr;
			}
		}
		r_list_foreach (cmd->plist, iter, cp) {
			if (cp->call (cmd->data, input)) {
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
			const char *inp = (*input)? input + 1: "";
			ret = c->callback (cmd->data, inp);
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
		R_LOG_ERROR ("RCmdDesc type not handled\n");
		break;
	}
	return res;
}

static size_t strlen0(const char *s) {
	return s? strlen (s): 0;
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
		args_len = strlen0 (cd->help->args_str);
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
	if (!item) {
		return;
	}
	free (item->name);
	free (item->args);
	free (item->code);
	free (item);
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
	int macro_update;
	RListIter *iter;
	char *pbody;
	// char *bufp;
	char *ptr;
	int lidx;

	if (!*oname) {
		r_cmd_macro_list (mac);
		return false;
	}

	name = strdup (oname);
	if (!name) {
		return false;
	}

	pbody = strchr (name, ';');
	if (!pbody) {
		eprintf ("Invalid macro body\n");
		free (name);
		return false;
	}
	*pbody = '\0';
	pbody++;

	if (*name && name[1] && name[strlen (name)-1]==')') {
		eprintf ("r_cmd_macro_add: missing macro body?\n");
		free (name);
		return false;
	}

	macro = NULL;
	ptr = strchr (name, ' ');
	if (ptr) {
		*ptr='\0';
		args = ptr +1;
	}
	macro_update = 0;
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (name, m->name)) {
			macro = m;
			// keep macro->name
			free (macro->code);
			free (macro->args);
			macro_update = 1;
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
	if (ptr != NULL) {
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
	if (macro_update == 0) {
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
			eprintf ("Macro '%s' removed.\n", name);
			ret = true;
			break;
		}
	}
	free (name);
	return ret;
}

// TODO: use mac->cb_printf which is r_cons_printf at the end
R_API void r_cmd_macro_list(RCmdMacro *mac) {
	RCmdMacroItem *m;
	int j, idx = 0;
	RListIter *iter;
	r_list_foreach (mac->macros, iter, m) {
		mac->cb_printf ("%d (%s %s; ", idx, m->name, m->args);
		for (j=0; m->code[j]; j++) {
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

// TODO: use mac->cb_printf which is r_cons_printf at the end
R_API void r_cmd_macro_meta(RCmdMacro *mac) {
	RCmdMacroItem *m;
	int j;
	RListIter *iter;
	r_list_foreach (mac->macros, iter, m) {
		mac->cb_printf ("(%s %s, ", m->name, m->args);
		for (j=0; m->code[j]; j++) {
			if (m->code[j] == '\n') {
				mac->cb_printf ("; ");
			} else {
				mac->cb_printf ("%c", m->code[j]);
			}
		}
		mac->cb_printf (")\n");
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

	for (*cmd=i=j=0; j<R_CMD_MAXLEN && ptr[j]; i++,j++) {
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
					eprintf ("Undefined argument %d\n", w);
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
				cmd[i+1] = '\0';
			}
		} else {
			cmd[i] = ptr[j];
			cmd[i+1] = '\0';
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
		} else
		/* conditional goto */
		if (ptr[0]=='?' && ptr[1]=='!' && ptr[2] != '?') {
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
		} else
		/* conditional goto */
		if (ptr[0] == '?' && ptr[1] == '?' && ptr[2] != '?') {
			if (mac->num->value == 0) {
				char *label = ptr + 3;
				for (; label[0] == ' ' || label[0] == '.'; label++) {
					;
				}
				//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for (i=0; i<*labels_n; i++) {
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
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name) {
	char *args;
	int nargs = 0;
	char *str, *ptr, *ptr2;
	RListIter *iter;
	static int macro_level = 0;
	RCmdMacroItem *m;
	/* labels */
	int labels_n = 0;
	struct r_cmd_macro_label_t labels[MACRO_LABELS];

	str = strdup (name);
	if (!str) {
		perror ("strdup");
		return false;
	}
	ptr = strchr (str, ')');
	if (!ptr) {
		eprintf ("Missing end ')' parenthesis.\n");
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
		eprintf ("Maximum macro recursivity reached.\n");
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
				eprintf ("Macro '%s' expects %d args, not %d\n", m->name, m->nargs, nargs);
				macro_level --;
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
					eprintf ("Interrupted at (%s)\n", ptr);
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
					eprintf ("Oops. invalid label name\n");
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
	eprintf ("No macro named '%s'\n", str);
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
	res->argv[0] = strdup(cmd);
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

static RCmdDesc *argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help, bool ht_insert) {
	RCmdDesc *res = create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_ARGV, name, help, ht_insert);
	if (!res) {
		return NULL;
	}

	res->d.argv_data.cb = cb;
	return res;
}

R_API RCmdDesc *r_cmd_desc_argv_new(RCmd *cmd, RCmdDesc *parent, const char *name, RCmdArgvCb cb, const RCmdDescHelp *help) {
	r_return_val_if_fail (cmd && parent && name, NULL);
	return argv_new (cmd, parent, name, cb, help, true);
}

R_API RCmdDesc *r_cmd_desc_inner_new(RCmd *cmd, RCmdDesc *parent, const char *name, const RCmdDescHelp *help) {
	r_return_val_if_fail (cmd && parent && name, NULL);
	return create_cmd_desc (cmd, parent, R_CMD_DESC_TYPE_INNER, name, help, false);
}

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
