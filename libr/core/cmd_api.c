/* radare - LGPL - Copyright 2009-2025 - pancake */

#define R_LOG_ORIGIN "cmdapi"
#include <r_core.h>
#include <r_core_priv.h>
#include <sdb/ht_pp.h>

#define NCMDS (sizeof (cmd->cmds) / sizeof (*cmd->cmds))

typedef struct {
	RCmdCtxCb callback;
	void *user;
	char *name;
	ut64 id;
	size_t active;
	bool registered;
} RCmdHandler;

typedef struct r_cmd_private_t RCmdPrivate;

typedef struct r_cmd_handler_call_t {
	struct r_cmd_handler_call_t *next;
	RCmdHandler *handler;
	RCmdPrivate *owner;
	R_TH_TID tid;
#if HAVE_TH_LOCAL
	struct r_cmd_handler_call_t *previous;
#endif
} RCmdHandlerCall;

typedef struct r_cmd_execution_t {
	struct r_cmd_execution_t *next;
	RCmdPrivate *owner;
	R_TH_TID tid;
#if HAVE_TH_LOCAL
	struct r_cmd_execution_t *previous;
#endif
} RCmdExecution;

struct r_cmd_private_t {
	RThreadLock *handlers_lock;
	RThreadCond *handlers_idle;
	RThreadLock *aliases_lock;
	RList *handlers;
	RCmdHandlerCall *handler_calls;
	RCmdExecution *executions;
	ut64 handler_id;
	size_t active_calls;
	size_t registry_ops;
	bool closing;
	bool finalizing;
};

#if HAVE_TH_LOCAL
static R_TH_LOCAL RCmdHandlerCall *current_handler_call;
static R_TH_LOCAL RCmdExecution *current_execution;
#endif

static void cmd_handler_free(void *value);

static bool cmd_is_dispatch_thread(const RCmdPrivate *priv) {
#if HAVE_TH_LOCAL
	RCmdHandlerCall *call;
	for (call = current_handler_call; call; call = call->previous) {
		if (call->owner == priv) {
			return true;
		}
	}
#else
	const R_TH_TID self = r_th_self ();
	RCmdHandlerCall *call;
	for (call = priv->handler_calls; call; call = call->next) {
		if (r_th_tid_equal (call->tid, self)) {
			return true;
		}
	}
#endif
	return false;
}

static bool cmd_is_execution_thread(const RCmdPrivate *priv) {
#if HAVE_TH_LOCAL
	RCmdExecution *execution;
	for (execution = current_execution; execution; execution = execution->previous) {
		if (execution->owner == priv) {
			return true;
		}
	}
#else
	const R_TH_TID self = r_th_self ();
	RCmdExecution *execution;
	for (execution = priv->executions; execution; execution = execution->next) {
		if (r_th_tid_equal (execution->tid, self)) {
			return true;
		}
	}
#endif
	return false;
}

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
	ut8 *data = malloc (v->sz);
	if (!data) {
		return NULL;
	}
	RCmdAliasVal *vcopy = R_NEW (RCmdAliasVal);
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

R_API RCmd *r_cmd_new(void *data) {
	RCmd *cmd = R_NEW0 (RCmd);
	RCmdPrivate *priv = R_NEW0 (RCmdPrivate);
	priv->handlers_lock = r_th_lock_new (false);
	priv->handlers_idle = r_th_cond_new ();
	priv->aliases_lock = r_th_lock_new (false);
	if (!priv->handlers_lock || !priv->handlers_idle || !priv->aliases_lock) {
		r_th_lock_free (priv->handlers_lock);
		r_th_cond_free (priv->handlers_idle);
		r_th_lock_free (priv->aliases_lock);
		free (priv);
		free (cmd);
		return NULL;
	}
	priv->handlers = r_list_newf (cmd_handler_free);
	cmd->priv = priv;
	cmd->data = data;
	cmd->handlers = r_trie_new (NULL);
	// cmd->root_cmd_desc = create_cmd_desc (cmd, NULL, R_CMD_DESC_TYPE_ARGV, "", &root_help, true);
	r_cmd_macro_init (&cmd->macro);
	r_cmd_alias_init (cmd);
	return cmd;
}

static void cmd_handler_free(void *value) {
	RCmdHandler *handler = value;
	free (handler->name);
	free (handler);
}

R_API void r_cmd_free(RCmd *cmd) {
	int i;
	if (!cmd) {
		return;
	}
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	if (cmd_is_execution_thread (priv)) {
		r_th_lock_leave (priv->handlers_lock);
		R_LOG_ERROR ("Cannot free a command registry from one of its command callbacks");
		return;
	}
	if (priv->closing) {
		r_th_lock_leave (priv->handlers_lock);
		R_LOG_ERROR ("Command registry is already being freed");
		return;
	}
	priv->closing = true;
	while (priv->active_calls || priv->registry_ops) {
		r_th_cond_wait (priv->handlers_idle, priv->handlers_lock);
	}
	r_th_lock_leave (priv->handlers_lock);
	r_core_plugins_fini (cmd);
	r_th_lock_enter (priv->handlers_lock);
	priv->finalizing = true;
	while (priv->registry_ops) {
		r_th_cond_wait (priv->handlers_idle, priv->handlers_lock);
	}
	r_trie_free (cmd->handlers);
	r_list_free (priv->handlers);
	r_th_lock_leave (priv->handlers_lock);
	ht_up_free (cmd->ts_symbols_ht);
	r_cmd_alias_free (cmd);
	r_cmd_macro_fini (&cmd->macro);
	for (i = 0; i < NCMDS; i++) {
		if (cmd->cmds[i]) {
			R_FREE (cmd->cmds[i]);
		}
	}
	// cmd_desc_free (cmd->root_cmd_desc);
	r_th_cond_free (priv->handlers_idle);
	r_th_lock_free (priv->handlers_lock);
	r_th_lock_free (priv->aliases_lock);
	free (priv);
	free (cmd);
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
	R_RETURN_VAL_IF_FAIL (cmd, NULL);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	AliasKeylist keylist = {
		.current_key = 0,
		.keys = R_NEWS (const char *, cmd->aliases->count)
	};
	if (!keylist.keys) {
		r_th_lock_leave (priv->aliases_lock);
		return NULL;
	}
	ht_pp_foreach (cmd->aliases, get_keys, &keylist);
	r_th_lock_leave (priv->aliases_lock);
	return keylist.keys;
}

R_API void r_cmd_alias_free(RCmd *cmd) {
	R_RETURN_IF_FAIL (cmd);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	ht_pp_free (cmd->aliases);
	cmd->aliases = NULL;
	r_th_lock_leave (priv->aliases_lock);
}

R_API bool r_cmd_alias_del(RCmd *cmd, const char *k) {
	R_RETURN_VAL_IF_FAIL (cmd && k, false);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	const bool deleted = ht_pp_delete (cmd->aliases, k);
	r_th_lock_leave (priv->aliases_lock);
	return deleted;
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
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	const bool updated = ht_pp_update (cmd->aliases, k, &val);
	r_th_lock_leave (priv->aliases_lock);
	return updated;
}

static int cmd_alias_set_str_unlocked(RCmd *cmd, const char *k, const char *v) {
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

R_API int r_cmd_alias_set_str(RCmd *cmd, const char *k, const char *v) {
	R_RETURN_VAL_IF_FAIL (cmd && k && v, 1);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	const int ret = cmd_alias_set_str_unlocked (cmd, k, v);
	r_th_lock_leave (priv->aliases_lock);
	return ret;
}

static int cmd_alias_set_raw_unlocked(RCmd *cmd, const char *k, const ut8 *v, int sz) {
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

R_API int r_cmd_alias_set_raw(RCmd *cmd, const char *k, const ut8 *v, int sz) {
	R_RETURN_VAL_IF_FAIL (cmd && k && v, 1);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	const int ret = cmd_alias_set_raw_unlocked (cmd, k, v, sz);
	r_th_lock_leave (priv->aliases_lock);
	return ret;
}

R_API RCmdAliasVal *r_cmd_alias_get(RCmd *cmd, const char *k) {
	R_RETURN_VAL_IF_FAIL (cmd && cmd->aliases && k, NULL);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	RCmdAliasVal *value = ht_pp_find (cmd->aliases, k, NULL);
	r_th_lock_leave (priv->aliases_lock);
	return value;
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
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	RCmdAliasVal *v_old = ht_pp_find (cmd->aliases, k, NULL);
	if (v_old) {
		if (!v_old->is_data) {
			r_th_lock_leave (priv->aliases_lock);
			return true;
		}
		int new_len = 0;
		ut8 *new = alias_append_internal (&new_len, v_old, (ut8 *)a, strlen (a) + 1);
		if (!new) {
			r_th_lock_leave (priv->aliases_lock);
			return true;
		}
		cmd_alias_set_raw_unlocked (cmd, k, new, new_len);
		free (new);
	} else {
		cmd_alias_set_str_unlocked (cmd, k, a);
	}
	r_th_lock_leave (priv->aliases_lock);
	return false;
}

R_API bool r_cmd_alias_append_raw(RCmd *cmd, const char *k, const ut8 *a, int sz) {
	R_RETURN_VAL_IF_FAIL (cmd && k && a, false);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	RCmdAliasVal *v_old = ht_pp_find (cmd->aliases, k, NULL);
	if (v_old) {
		if (!v_old->is_data) {
			r_th_lock_leave (priv->aliases_lock);
			return false;
		}
		int new_len = 0;
		ut8 *new = alias_append_internal (&new_len, v_old, a, sz);
		if (new) {
			cmd_alias_set_raw_unlocked (cmd, k, new, new_len);
			free (new);
		}
	} else {
		cmd_alias_set_raw_unlocked (cmd, k, a, sz);
	}
	r_th_lock_leave (priv->aliases_lock);
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

static char *cmd_alias_data_strdup(RCmd *cmd, const char *key, bool *found) {
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->aliases_lock);
	RCmdAliasVal *value = cmd->aliases? ht_pp_find (cmd->aliases, key, NULL): NULL;
	*found = value && value->is_data;
	char *copy = *found? r_cmd_alias_val_strdup (value): NULL;
	r_th_lock_leave (priv->aliases_lock);
	return copy;
}

R_API void r_cmd_set_data(RCmd *cmd, void *data) {
	cmd->data = data;
}

R_API bool r_cmd_register(RCmd *cmd, const char *name, RCmdCtxCb callback, void *handler_user) {
	R_RETURN_VAL_IF_FAIL (cmd && name && callback, false);
	RStrs key = r_strs_from (name);
	if (r_strs_empty (key)) {
		return false;
	}
	RCmdHandler *handler = R_NEW0 (RCmdHandler);
	handler->callback = callback;
	handler->user = handler_user;
	handler->name = strdup (name);
	if (!handler->name) {
		free (handler);
		return false;
	}
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	const bool inserted = !priv->closing && !r_trie_find (cmd->handlers, key)
		&& r_trie_insert (cmd->handlers, key, handler)
		&& r_list_append (priv->handlers, handler);
	if (inserted) {
		handler->id = ++priv->handler_id;
		handler->registered = true;
	} else if (r_trie_find (cmd->handlers, key) == handler) {
		r_trie_take (cmd->handlers, key);
	}
	r_th_lock_leave (priv->handlers_lock);
	if (!inserted) {
		cmd_handler_free (handler);
	}
	return inserted;
}

static bool cmd_handler_matches(const RCmdHandler *handler, const char *name, bool prefix, ut64 cutoff) {
	return handler->id <= cutoff && (prefix
		? r_str_startswith (handler->name, name)
		: !strcmp (handler->name, name));
}

static bool cmd_handlers_active(RCmdPrivate *priv, const char *name, bool prefix, ut64 cutoff) {
	RListIter *iter;
	RCmdHandler *handler;
	r_list_foreach (priv->handlers, iter, handler) {
		if (handler->active && cmd_handler_matches (handler, name, prefix, cutoff)) {
			return true;
		}
	}
	return false;
}

static void cmd_handlers_sweep(RCmdPrivate *priv) {
	RListIter *iter;
	RListIter *next;
	RCmdHandler *handler;
	r_list_foreach_safe (priv->handlers, iter, next, handler) {
		if (!handler->registered && !handler->active) {
			r_list_delete (priv->handlers, iter);
		}
	}
}

static void cmd_registry_op_end(RCmdPrivate *priv) {
	cmd_handlers_sweep (priv);
	priv->registry_ops--;
	r_th_cond_signal_all (priv->handlers_idle);
}

R_API bool r_cmd_unregister(RCmd *cmd, const char *name) {
	R_RETURN_VAL_IF_FAIL (cmd && name, false);
	RStrs key = r_strs_from (name);
	if (r_strs_empty (key)) {
		return false;
	}
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	const bool finalizing = priv->finalizing;
	if (finalizing || cmd_is_dispatch_thread (priv)) {
		r_th_lock_leave (priv->handlers_lock);
		if (!finalizing) {
			R_LOG_ERROR ("Cannot unregister commands from a registered command handler");
		}
		return false;
	}
	priv->registry_ops++;
	const ut64 cutoff = priv->handler_id;
	RCmdHandler *handler = r_trie_take (cmd->handlers, key);
	const bool removed = handler != NULL;
	if (handler) {
		handler->registered = false;
	}
	while (cmd_handlers_active (priv, name, false, cutoff)) {
		r_th_cond_wait (priv->handlers_idle, priv->handlers_lock);
	}
	cmd_registry_op_end (priv);
	r_th_lock_leave (priv->handlers_lock);
	return removed;
}

R_API size_t r_cmd_unregister_prefix(RCmd *cmd, const char *prefix) {
	R_RETURN_VAL_IF_FAIL (cmd && prefix, 0);
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	const bool finalizing = priv->finalizing;
	if (finalizing || cmd_is_dispatch_thread (priv)) {
		r_th_lock_leave (priv->handlers_lock);
		if (!finalizing) {
			R_LOG_ERROR ("Cannot unregister commands from a registered command handler");
		}
		return 0;
	}
	priv->registry_ops++;
	const ut64 cutoff = priv->handler_id;
	const size_t removed = r_trie_delete_prefix (cmd->handlers, r_strs_from (prefix));
	RListIter *iter;
	RCmdHandler *handler;
	r_list_foreach (priv->handlers, iter, handler) {
		if (handler->registered && cmd_handler_matches (handler, prefix, true, cutoff)) {
			handler->registered = false;
		}
	}
	while (cmd_handlers_active (priv, prefix, true, cutoff)) {
		r_th_cond_wait (priv->handlers_idle, priv->handlers_lock);
	}
	cmd_registry_op_end (priv);
	r_th_lock_leave (priv->handlers_lock);
	return removed;
}

typedef struct {
	RList *names;
} RCmdNames;

static bool cmd_collect_name(RStrs name, void *value, void *user) {
	(void)value;
	RCmdNames *snapshot = user;
	char *copy = r_strs_tostring (name);
	if (!copy || !r_list_append (snapshot->names, copy)) {
		free (copy);
		return false;
	}
	return true;
}

R_API bool r_cmd_foreach_prefix(const RCmd *cmd, const char *prefix, RCmdForeachCb callback, void *user) {
	R_RETURN_VAL_IF_FAIL (cmd && prefix && callback, false);
	RCmdNames snapshot = {
		.names = r_list_newf (free)
	};
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	bool visited = r_trie_foreach_prefix (cmd->handlers, r_strs_from (prefix), cmd_collect_name, &snapshot);
	r_th_lock_leave (priv->handlers_lock);
	RListIter *iter;
	char *name;
	r_list_foreach (snapshot.names, iter, name) {
		if (!visited || !callback (r_strs_from (name), user)) {
			visited = false;
			break;
		}
	}
	r_list_free (snapshot.names);
	return visited;
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

static RCmdResult cmd_result(RCmdAction action, st64 status) {
	return (RCmdResult) {
		.action = action,
		.status = status
	};
}

static RCmdResult cmd_result_from_legacy(int status) {
	return cmd_result (status == -2? R_CMD_ACTION_QUIT: R_CMD_ACTION_CONTINUE, status);
}

static int cmd_result_to_legacy(RCmdResult result) {
	return result.action == R_CMD_ACTION_CONTINUE
		? (int)R_CLAMP (result.status, (st64)ST32_MIN, (st64)ST32_MAX)
		: result.action == R_CMD_ACTION_QUIT? -2: -1;
}

static const char *cmd_decode_escape(const char *src, const char *end, char **dst) {
	if (src >= end) {
		*(*dst)++ = '\\';
		return src;
	}
	ut8 ch = *src++;
	switch (ch) {
	case 'a': ch = '\a'; break;
	case 'b': ch = '\b'; break;
	case 'e': ch = 0x1b; break;
	case 'f': ch = '\f'; break;
	case 'n': ch = '\n'; break;
	case 'r': ch = '\r'; break;
	case 's': ch = ' '; break;
	case 't': ch = '\t'; break;
	case 'v': ch = '\v'; break;
	case 'x': {
		ut8 value = 0;
		if (end - src >= 2 && r_hex_to_byte (&value, src[0]) && r_hex_to_byte (&value, src[1])) {
			*(*dst)++ = value;
			return src + 2;
		}
		return src;
	}
	default:
		if (IS_OCTAL (ch)) {
			ut8 value = ch - '0';
			int i;
			for (i = 0; i < 2 && src < end && IS_OCTAL (*src); i++, src++) {
				value = (value * 8) + (*src - '0');
			}
			ch = value;
		}
		break;
	}
	*(*dst)++ = ch;
	return src;
}

/* Rebuilds context arguments with shared quote and escape decoding. */
static bool cmd_context_parse_args(RCmdContext *context, RStrs rest) {
	RVecRStrs_fini (&context->args);
	free (context->args_storage);
	context->args_storage = NULL;
	char *storage = malloc (r_strs_len (rest) + 1);
	if (!storage) {
		return false;
	}
	context->args_storage = storage;
	const char *src = rest.a;
	char *dst = storage;
	while (src < rest.b) {
		while (src < rest.b && isspace ((ut8)*src)) {
			src++;
		}
		if (src == rest.b) {
			break;
		}
		char quote = 0;
		char *begin = dst;
		while (src < rest.b) {
			char ch = *src;
			if (!quote && isspace ((ut8)ch)) {
				break;
			}
			src++;
			if (ch == '\\') {
				src = cmd_decode_escape (src, rest.b, &dst);
				continue;
			}
			if (ch == '\'' || ch == '"') {
				if (!quote) {
					quote = ch;
					continue;
				}
				if (quote == ch) {
					quote = 0;
					continue;
				}
			}
			*dst++ = ch;
		}
		RStrs *arg = RVecRStrs_emplace_back (&context->args);
		if (!arg) {
			return false;
		}
		*arg = r_strs_new (begin, dst);
	}
	*dst = 0;
	return true;
}

static void cmd_context_free(RCmdContext *context) {
	if (context) {
		RVecRStrs_fini (&context->args);
		free (context->args_storage);
		free (context);
	}
}

static RCons *cmd_legacy_capture_begin(RCmd *cmd, RCmdContext *parent) {
	RCons *cons = parent
		? parent->cons
		: cmd->get_cons? cmd->get_cons (cmd->data): cmd->cons;
	if (!cmd->cons || !cons || cons == cmd->cons) {
		return NULL;
	}
	r_cons_push (cmd->cons);
	cmd->cons->context->cmd_str_depth++;
	if (parent) {
		parent->cons = cmd->cons;
	}
	return cons;
}

static void cmd_legacy_capture_end(RCmd *cmd, RCmdContext *parent, RCons *cons) {
	if (parent) {
		parent->cons = cons;
	}
	cmd->cons->context->cmd_str_depth--;
	r_cons_filter (cmd->cons);
	r_cons_merge_output (cons, cmd->cons);
	r_cons_pop (cmd->cons);
	r_cons_echo (cmd->cons, NULL);
}

static RCmdHandler *cmd_handler_pin(RCmd *cmd, RStrs lookup, size_t *matched, RCmdHandlerCall *call) {
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	RCmdHandler *handler = priv->closing? NULL: r_trie_find_longest_prefix (cmd->handlers, lookup, matched);
	if (handler && !*matched) {
		// empty names are rejected at register, never pin a zero-length match
		R_WARN_IF_REACHED ();
		handler = NULL;
	}
	if (handler) {
		handler->active++;
		call->handler = handler;
		call->owner = priv;
		call->tid = r_th_self ();
		call->next = priv->handler_calls;
		priv->handler_calls = call;
	}
	r_th_lock_leave (priv->handlers_lock);
	return handler;
}

static void cmd_handler_unpin(RCmd *cmd, RCmdHandlerCall *call) {
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	RCmdHandlerCall **link = &priv->handler_calls;
	while (*link && *link != call) {
		link = &(*link)->next;
	}
	if (!*link || !call->handler->active) {
		R_WARN_IF_REACHED ();
		r_th_lock_leave (priv->handlers_lock);
		return;
	}
	*link = call->next;
	call->handler->active--;
	if (!call->handler->active) {
		r_th_cond_signal_all (priv->handlers_idle);
	}
	r_th_lock_leave (priv->handlers_lock);
}

static RCmdResult cmd_call_registered(RCmd *cmd, RCmdContext *parent, RStrs input, bool verbatim) {
	RStrs lookup = input;
	RCmdContext *context = NULL;
	const char *parsed_from = NULL;
	RCmdResult result = cmd_result (R_CMD_ACTION_UNHANDLED, 127);
	while (!r_strs_empty (lookup)) {
		size_t matched = 0;
		RCmdHandlerCall call = { 0 };
		RCmdHandler *handler = cmd_handler_pin (cmd, lookup, &matched, &call);
		if (!handler) {
			break;
		}
		if (!context) {
			context = R_NEW0 (RCmdContext);
			context->parent = parent;
			context->cmd = cmd;
			context->cons = parent
				? parent->cons
				: cmd->get_cons? cmd->get_cons (cmd->data): cmd->cons;
			context->user = cmd->data;
			context->remaining_depth = parent? parent->remaining_depth: 0;
			context->verbatim = verbatim;
		}
		const char *sub_end = input.a + matched;
		while (sub_end < input.b && !isspace ((ut8)*sub_end)) {
			sub_end++;
		}
		if (parsed_from != sub_end) {
			if (!cmd_context_parse_args (context, r_strs_new (sub_end, input.b))) {
				cmd_handler_unpin (cmd, &call);
				result = cmd_result (R_CMD_ACTION_ABORT, 2);
				break;
			}
			parsed_from = sub_end;
		}
		context->subcmd = r_strs_new (input.a + matched, sub_end);
		context->handler_user = handler->user;
#if HAVE_TH_LOCAL
		call.previous = current_handler_call;
		current_handler_call = &call;
#endif
		RCmdResult handler_result = handler->callback (context);
#if HAVE_TH_LOCAL
		current_handler_call = call.previous;
#endif
		cmd_handler_unpin (cmd, &call);
		if (handler_result.action != R_CMD_ACTION_UNHANDLED) {
			result = handler_result;
			break;
		}
		lookup.b = lookup.a + matched - 1;
	}
	cmd_context_free (context);
	return result;
}

static bool cmd_execution_begin(RCmd *cmd, RCmdExecution *execution) {
	RCmdPrivate *priv = cmd->priv;
	r_th_lock_enter (priv->handlers_lock);
	if (priv->closing) {
		r_th_lock_leave (priv->handlers_lock);
		return false;
	}
	execution->owner = priv;
	execution->tid = r_th_self ();
	execution->next = priv->executions;
	priv->executions = execution;
	priv->active_calls++;
#if HAVE_TH_LOCAL
	execution->previous = current_execution;
	current_execution = execution;
#endif
	r_th_lock_leave (priv->handlers_lock);
	return true;
}

static void cmd_execution_end(RCmd *cmd, RCmdExecution *execution) {
	RCmdPrivate *priv = cmd->priv;
#if HAVE_TH_LOCAL
	current_execution = execution->previous;
#endif
	r_th_lock_enter (priv->handlers_lock);
	RCmdExecution **link = &priv->executions;
	while (*link && *link != execution) {
		link = &(*link)->next;
	}
	if (!*link || !priv->active_calls) {
		R_WARN_IF_REACHED ();
		r_th_lock_leave (priv->handlers_lock);
		return;
	}
	*link = execution->next;
	priv->active_calls--;
	r_th_cond_signal_all (priv->handlers_idle);
	r_th_lock_leave (priv->handlers_lock);
}

R_IPI RCmdResult r_cmd_call_result(RCmd *cmd, RCmdContext *parent, const char *input, bool verbatim) {
	RCmdResult result = cmd_result (R_CMD_ACTION_UNHANDLED, 127);
	RCmdExecution execution = { 0 };
	if (!cmd_execution_begin (cmd, &execution)) {
		return result;
	}
	RCore *core = cmd->data;
	RCons *capture = NULL;
	if (!*input) {
		if (!cmd->nullcallback) {
			goto beach;
		}
		capture = cmd_legacy_capture_begin (cmd, parent);
		result = cmd_result_from_legacy (cmd->nullcallback (cmd->data));
		goto beach;
	}
	bool alias_found = false;
	char *alias = cmd_alias_data_strdup (cmd, input, &alias_found);
	if (alias_found) {
		if (!alias) {
			result = cmd_result (R_CMD_ACTION_ABORT, 1);
			goto beach;
		}
		RCons *cons = parent
			? parent->cons
			: cmd->get_cons? cmd->get_cons (cmd->data): cmd->cons;
		r_cons_print (cons, alias);
		free (alias);
		result = cmd_result_from_legacy (true);
		goto beach;
	}
	result = cmd_call_registered (cmd, parent, r_strs_from (input), verbatim);
	if (result.action != R_CMD_ACTION_UNHANDLED) {
		goto beach;
	}
	capture = cmd_legacy_capture_begin (cmd, parent);
	RListIter *iter;
	if (cmd->libstore) {
		RCorePluginSession *cps;
		r_list_foreach (cmd->libstore->plugins, iter, cps) {
			RCorePlugin *plugin = cps->plugin;
			if (plugin->call && plugin->call (cps, input)) {
				result = cmd_result_from_legacy (true);
				goto beach;
			}
		}
	}
	RCmdItem *item = cmd->cmds[(ut8)input[0]];
	if (item && item->callback) {
		result = cmd_result_from_legacy (item->callback (cmd->data, input + 1));
		goto beach;
	}
	if (core && core->sdb) {
		const char *suggestion = sdb_const_get (core->sdb, input, NULL);
		if (suggestion) {
			R_LOG_INFO ("%s", suggestion);
		}
	}
beach:
	if (capture) {
		cmd_legacy_capture_end (cmd, parent, capture);
	}
	cmd_execution_end (cmd, &execution);
	return result;
}

R_API int r_cmd_call(RCmd *cmd, const char *input) {
	R_RETURN_VAL_IF_FAIL (cmd && input, -1);
	return cmd_result_to_legacy (r_cmd_call_result (cmd, NULL, input, false));
}

R_IPI int r_cmd_call_context(RCmd *cmd, RCmdContext *parent, const char *input, bool verbatim) {
	return cmd_result_to_legacy (r_cmd_call_result (cmd, parent, input, verbatim));
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
	R_RETURN_IF_FAIL (mac);
	mac->counter = 0;
	mac->_brk_value = 0;
	mac->brk_value = &mac->_brk_value;
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
		char *list = r_cmd_macro_list (mac, 0);
		eprintf ("%s\n", list); // TODO: return char *?
		free (list);
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
		args = ptr + 1;
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

	macro->codelen = (pbody[0])? strlen (pbody) + 2 : 4096;
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
		macro->nargs = r_str_word_set0 (ptr + 1);
	}

	for (lidx = 0; pbody[lidx]; lidx++) {
		if (pbody[lidx] == ';') {
			pbody[lidx] = '\n';
		} else if (pbody[lidx] == ')' && pbody[lidx - 1] == '\n') {
			pbody[lidx] = '\0';
		}
	}
	strncpy (macro->code, pbody, macro->codelen);
	macro->code[macro->codelen - 1] = 0;
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

static char *macro_meta(RCmdMacro *mac) {
	RCmdMacroItem *m;
	int j;
	RListIter *iter;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (mac->macros, iter, m) {
		r_strbuf_appendf (sb, "\"(%s %s; ", m->name, m->args);
		for (j = 0; m->code[j]; j++) {
			if (m->code[j] == '\n') {
				r_strbuf_append (sb, ";");
			} else {
				r_strbuf_appendf (sb, "%c", m->code[j]);
			}
		}
		r_strbuf_append (sb, ")\"\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_cmd_macro_list(RCmdMacro *mac, int mode) {
	RCmdMacroItem *m;
	int j, idx = 0;
	RListIter *iter;
	if (mode == '*') {
		return macro_meta (mac);
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
		return pj_drain (pj);
	}

	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (mac->macros, iter, m) {
		r_strbuf_appendf (sb, "%d (%s %s; ", idx, m->name, m->args);
		for (j = 0; m->code[j]; j++) {
			if (m->code[j] == '\n') {
				r_strbuf_append (sb, "; ");
			} else {
				r_strbuf_appendf (sb, "%c", m->code[j]);
			}
		}
		r_strbuf_append (sb, ")\n");
		idx++;
	}
	return r_strbuf_drain (sb);
}
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
	RCore *core = (RCore *)mac->user;
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
	r_cons_break_push (core->cons, NULL, NULL);
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (str, m->name)) {
			char *ptr = m->code;
			char *end = strchr (ptr, '\n');
			if (m->nargs != 0 && nargs != m->nargs) {
				R_LOG_ERROR ("Macro '%s' expects %d args, not %d", m->name, m->nargs, nargs);
				mac->macro_level--;
				free (str);
				r_cons_break_pop (core->cons);
				return false;
			}
			mac->brk = 0;
			do {
				if (end) {
					*end = '\0';
				}
				if (r_cons_is_breaked (core->cons)) {
					R_LOG_INFO ("Interrupted at (%s)", ptr);
					if (end) {
						*end = '\n';
					}
					free (str);
					r_cons_break_pop (core->cons);
					return false;
				}
				r_cons_flush (core->cons);
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
						r_cons_break_pop (core->cons);
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
	r_cons_break_pop (core->cons);
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
