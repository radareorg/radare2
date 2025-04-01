/* radare - LGPL - Copyright 2009-2024 - pancake */

#define R_LOG_ORIGIN "cmdapi"
#include <r_core.h>
#include <sdb/ht_pp.h>

#define NCMDS (sizeof (cmd->cmds) / sizeof (*cmd->cmds))

static void alias_freefn(HtPPKv *kv) {
	if (kv) {
		char *k = kv->key;
		RCmdAliasVal *v = kv->value;
		free (v->data);
		free (k);
		free (v);
	}
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
	cmd->lcmds = r_list_new ();
	for (i = 0; i < NCMDS; i++) {
		cmd->cmds[i] = NULL;
	}
	cmd->nullcallback = cmd->data = NULL;
	cmd->ht_cmds = ht_pp_new0 ();
	// cmd->root_cmd_desc = create_cmd_desc (cmd, NULL, R_CMD_DESC_TYPE_ARGV, "", &root_help, true);
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
	// cmd_desc_free (cmd->root_cmd_desc);
	free (cmd);
	return NULL;
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
	AliasKeylist keylist = {
		.current_key = 0,
		.keys = R_NEWS (const char *, cmd->aliases->count)
	};
	if (!keylist.keys) {
		return NULL;
	}
	ht_pp_foreach (cmd->aliases, get_keys, &keylist);
	// We don't need to return a count - it's already in cmd->aliases.
	return keylist.keys;
}

R_API void r_cmd_alias_free(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
	ht_pp_free (cmd->aliases);
	cmd->aliases = NULL;
}

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k) {
	R_RETURN_VAL_IF_FAIL (cmd && k, false);
	return ht_pp_delete (cmd->aliases, k);
}

R_API bool r_cmd_alias_set_cmd(RCmd *cmd, const char *k, const char *v) {
	R_RETURN_VAL_IF_FAIL (cmd && k && v, false);
	RCmdAliasVal val;
	val.data = (ut8 *)v;
	if (!val.data) {
		return true;
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
		if (!IS_PRINTABLE (v[i]) && !IS_WHITECHAR (v[i])) {
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
	R_RETURN_VAL_IF_FAIL (cmd && cmd->aliases && k, NULL);
	return ht_pp_find (cmd->aliases, k, NULL);
}

static ut8 *alias_append_internal(int *out_szp, const RCmdAliasVal *first, const ut8 *second, int second_sz) {
	/* If appending to a string, always overwrite the trailing \0 */
	const int bytes_from_first = first->is_str
		? first->sz - 1
		: first->sz;

	const int out_sz = bytes_from_first + second_sz;
	ut8 *out = malloc (out_sz);
	if (!out) {
		return NULL;
	}

	/* Copy full buffer if raw bytes. Stop before \0 if string. */
	memcpy (out, first->data, bytes_from_first);
	/* Always copy all bytes from second, including trailing \0 */
	memcpy (out + bytes_from_first, second, second_sz);

	if (out_sz) {
		*out_szp = out_sz;
	}
	return out;
}

R_API bool r_cmd_alias_append_str(RCmd *cmd, const char *k, const char *a) {
	R_RETURN_VAL_IF_FAIL (cmd && k && a, 1);
	RCmdAliasVal *v_old = r_cmd_alias_get (cmd, k);
	if (v_old) {
		if (!v_old->is_data) {
			return true;
		}
		int new_len = 0;
		ut8* new = alias_append_internal (&new_len, v_old, (ut8 *)a, strlen (a) + 1);
		if (!new) {
			return true;
		}
		r_cmd_alias_set_raw (cmd, k, new, new_len);
		free (new);
	} else {
		r_cmd_alias_set_str (cmd, k, a);
	}
	return false;
}

R_API bool r_cmd_alias_append_raw(RCmd *cmd, const char *k, const ut8 *a, int sz) {
	RCmdAliasVal *v_old = r_cmd_alias_get (cmd, k);
	if (v_old) {
		if (!v_old->is_data) {
			return false;
		}
		int new_len = 0;
		ut8 *new = alias_append_internal (&new_len, v_old, a, sz);
		if (new) {
			r_cmd_alias_set_raw (cmd, k, new, new_len);
			free (new);
		}
	} else {
		r_cmd_alias_set_raw (cmd, k, a, sz);
	}
	return true;
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
	return r_base64_encode_dyn ((const ut8*)v->data, v->sz);
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
	R_RETURN_VAL_IF_FAIL (cmd && input, -1);
	if (!*input) {
		if (cmd->nullcallback) {
			ret = cmd->nullcallback (cmd->data);
		}
	} else {
		char *nstr = NULL;
		RCmdAliasVal *v = r_cmd_alias_get (cmd, input);
		if (v && v->is_data) {
			char *v_str = r_cmd_alias_val_strdup (v);
			r_cons_print (v_str);
			free (v_str);
			return true;
		}
		r_list_foreach (cmd->plist, iter, cp) {
			/// XXX the plugin call have no plugin context!! we cant have multiple plugins here
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
		R_LOG_ERROR ("Invalid macro body in '%s'", name);
		free (name);
		return false;
	}
	*pbody = '\0';
	pbody++;

	if (*name && name[1] && name[strlen (name) - 1] == ')') {
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
	R_RETURN_VAL_IF_FAIL (mac && _name, false);
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
	RCmdMacroItem *m;
	int j, idx = 0;
	RListIter *iter;
	if (mode == '*') {
		macro_meta (mac);
		return;
	}
	if (mode == 'j') {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "cmd", "(j");
		pj_ka (pj, "macros");
		r_list_foreach (mac->macros, iter, m) {
			pj_o (pj);
			pj_ks (pj, "name", m->name);
			pj_ks (pj, "args", m->args);
			pj_ks (pj, "cmds", r_str_trim_head_ro (m->code));
			pj_end (pj);
			idx++;
		}

		pj_end (pj);
		pj_end (pj);

		char *s = pj_drain (pj);
		mac->cb_printf ("%s\n", s);
		free (s);
		return;
	}
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
		if (ptr[j] == '$') {
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
			} else if (ptr[j + 1] == '@') {
				char off[32];
				int offlen;
				offlen = snprintf (off, sizeof (off), "%d",
					mac->counter);
				if ((i + offlen + 1) >= sizeof (cmd)) {
					return -1;
				}
				memcpy (cmd + i, off, offlen + 1);
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
	int xx = (*pcmd == ')')? 0: mac->cmd (mac->user, pcmd);
	//eprintf ("-pos %p %d\n", mac->num, (int)mac->num->value);
	return xx;
}

R_API char *r_cmd_macro_label_process(RCmdMacro *mac, RCmdMacroLabel *labels, int *labels_n, char *ptr) {
	int i;
	for (; *ptr == ' '; ptr++) {
		;
	}
	if (ptr[strlen (ptr) - 1] == ':' && !strchr (ptr, ' ')) {
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
		} else if (ptr[0] == '?' && ptr[1] == '!' && ptr[2] != '?') {
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
				labels[*labels_n].ptr = ptr + strlen (ptr) + 1;
				*labels_n = *labels_n + 1;
			}
		}
		ptr += strlen (ptr) + 1;
	}
	return ptr;
}

R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name) {
	char *ptr2;
	RListIter *iter;
	RCmdMacroItem *m;

	/* labels */
	int labels_n = 0;
	struct r_cmd_macro_label_t labels[MACRO_LABELS];

	char *str = strdup (name);
	if (!str) {
		r_sys_perror ("strdup");
		return false;
	}
	char *ptr = strchr (str, ')');
	if (!ptr) {
		R_LOG_ERROR ("Missing end ')' parenthesis in '%s'", str);
		free (str);
		return false;
	} else {
		*ptr = '\0';
	}

	int nargs = 0;
	char *args = strchr (str, ' ');
	if (args) {
		*args = '\0';
		args++;
		nargs = r_str_word_set0 (args);
	}

	mac->macro_level++;
	if (mac->macro_level > MACRO_LIMIT) {
		R_LOG_ERROR ("Maximum macro recursivity reached");
		mac->macro_level--;
		free (str);
		return 0;
	}
	ptr = strchr (str, ';');
	if (ptr) {
		*ptr = 0;
	}

	int Gvalue = 0;
	r_cons_break_push (NULL, NULL);
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (str, m->name)) {
			char *ptr = m->code;
			char *end = strchr (ptr, '\n');
			if (m->nargs != 0 && nargs != m->nargs) {
				R_LOG_ERROR ("Macro '%s' expects %d args, not %d", m->name, m->nargs, nargs);
				mac->macro_level--;
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
					mac->num->value = Gvalue;
					int r = r_cmd_macro_cmd_args (mac, ptr, args, nargs);
					// TODO: handle quit? r == 0??
					// quit, exits the macro. like a break
					Gvalue = mac->num->value;
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
					mac->macro_level--;
					free (str);
					goto out_clean;
				}

				/* Fetch next command */
				end = strchr (ptr, '\n');
			} while (!mac->brk);
			if (mac->brk) {
				mac->macro_level--;
				free (str);
				goto out_clean;
			}
		}
	}
	R_LOG_ERROR ("No macro named '%s'", str);
	mac->macro_level--;
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
