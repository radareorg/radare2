/* radare - LGPL - Copyright 2006-2022 - pancake */

#include "r_config.h"

R_API RConfigNode* r_config_node_new(const char *name, const char *value) {
	R_RETURN_VAL_IF_FAIL (name && *name && value, NULL);
	RConfigNode *node = R_NEW0 (RConfigNode);
	if (R_LIKELY (node)) {
		node->name = strdup (name);
		node->value = strdup (r_str_get (value));
		node->flags = CN_RW | CN_STR;
		node->i_value = r_num_get (NULL, value);
		node->options = NULL;
	}
	return node;
}

R_API char *r_config_node_tostring(RConfigNode *node) {
	return (node && node->name)? strdup (node->name): NULL;
}

R_API void r_config_node_purge_options(RConfigNode *node) {
	R_RETURN_IF_FAIL (node);
	if (node->options) {
		r_list_purge (node->options);
	} else {
		node->options = r_list_newf (free);
	}
}

R_API void r_config_node_add_option(RConfigNode *node, const char *option) {
	R_RETURN_IF_FAIL (node && option);
	if (!node->options) {
		node->options = r_list_newf (free);
	}
	r_list_append (node->options, strdup (option));
}

R_API RConfigNode* r_config_node_clone(RConfigNode *n) {
	R_RETURN_VAL_IF_FAIL (n, NULL);
	RConfigNode *cn = R_NEW0 (RConfigNode);
	if (R_LIKELY (cn)) {
		cn->name = strdup (n->name);
		cn->desc = n->desc ? strdup (n->desc) : NULL;
		cn->value = strdup (r_str_get (n->value));
		cn->i_value = n->i_value;
		cn->flags = n->flags;
		cn->setter = n->setter;
		cn->options = n->options? r_list_clone (n->options, NULL): NULL;
	}
	return cn;
}

R_API void r_config_node_free(void *n) {
	RConfigNode *node = (RConfigNode *)n;
	if (R_LIKELY (node)) {
		free (node->name);
		free (node->desc);
		free (node->value);
		r_list_free (node->options);
		free (node);
	}
}

static void config_print_value_json(RConfig *cfg, PJ *pj, RConfigNode *node) {
	R_RETURN_IF_FAIL (cfg && node);
	const char *val = node->value;
	if (!val) {
		val = "0";
	}
	char *sval = r_str_escape (val);
	if (r_config_node_is_bool (node) || r_config_node_is_int (node)) {
		if (r_str_startswith (val, "0x")) {
			ut64 n = r_num_get (NULL, val);
			if (pj) {
				pj_n (pj, n);
			} else {
				cfg->cb_printf ("%"PFMT64d, n);
			}
		} else if (r_str_isnumber (val) || (*val /* HACK */ && r_str_is_bool (val))) {
			if (pj) {
				if (r_str_is_bool (val)) {
					pj_b (pj, val);
				} else if (r_str_isnumber (val)) {
					ut64 n = r_num_get (NULL, val);
					pj_n (pj, n);
				} else {
					pj_s (pj, val);
				}
			} else {
				cfg->cb_printf ("%s", val);  // TODO: always use true/false for bool json str
			}
		} else {
			if (pj) {
				pj_s (pj, sval);
			} else {
				cfg->cb_printf ("\"%s\"", sval);
			}
		}
	} else {
		if (pj) {
			pj_s (pj, sval);
		} else {
			cfg->cb_printf ("\"%s\"", sval);
		}
	}
	free (sval);
}

static void config_print_node(RConfig *cfg, RConfigNode *node, PJ *pj, const char *pfx, const char *sfx, bool verbose) {
	R_RETURN_IF_FAIL (cfg && node && pfx && sfx);
	char *option;
	RListIter *iter;

	if (pj) {
		if (verbose) {
			pj_o (pj);
			pj_ks (pj, "name", node->name);
			pj_ks (pj, "value", node->name);
			pj_ks (pj, "type", r_config_node_type (node));
			pj_k (pj, "value");
			config_print_value_json (cfg, pj, node);
			if (R_STR_ISNOTEMPTY (node->desc)) {
				pj_ks (pj, "desc", node->desc);
			}
			pj_kb (pj, "ro", r_config_node_is_ro (node));
			if (node->options && !r_list_empty (node->options)) {
				pj_ka (pj, "options");
				r_list_foreach (node->options, iter, option) {
					pj_s (pj, option);
				}
				pj_end (pj);
			}
			pj_end (pj);
		} else {
			pj_k (pj, node->name);
			config_print_value_json (cfg, pj, node);
		}
	} else {
		if (verbose) {
			cfg->cb_printf ("%s%s = %s%s %s; %s", pfx,
				node->name, node->value, sfx,
				r_config_node_is_ro (node) ? "(ro)" : "",
				node->desc);
			if (node->options && !r_list_empty (node->options)) {
				bool isFirst = true;
				cfg->cb_printf ("[");
				r_list_foreach (node->options, iter, option) {
					if (isFirst) {
						isFirst = false;
					} else {
						cfg->cb_printf (", ");
					}
					cfg->cb_printf ("%s", option);
				}
				cfg->cb_printf ("]");
			}
			cfg->cb_printf ("\n");
		} else {
			cfg->cb_printf ("%s%s = %s%s\n", pfx,
				node->name, node->value, sfx);
		}
	}
}

R_API void r_config_list(RConfig *cfg, const char *str, int rad) {
	R_RETURN_IF_FAIL (cfg);
	RConfigNode *node;
	RListIter *iter;
	const char *sfx = "";
	const char *pfx = "";
	int len = 0;
	bool found, verbose = false;
	PJ *pj = NULL;

	if (!IS_NULLSTR (str)) {
		str = r_str_trim_head_ro (str);
		len = strlen (str);
		if (len > 0 && (str[0] == 'j' || str[0] == 'J')) {
			str++;
			len--;
			rad = 'J';
		}
		if (len > 0 && str[0] == ' ') {
			str++;
			len--;
		}
		if (R_STR_ISEMPTY (str)) {
			str = NULL;
			len = 0;
		}
	}
	if (rad == 'j' || rad == 'J') {
		pj = pj_new ();
	}

	switch (rad) {
	case 1:
		pfx = "'e ";
		sfx = "";
	/* fallthrou */
	case 0:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				config_print_node (cfg, node, NULL, pfx, sfx, verbose);
			}
		}
		break;
	case 'r':
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				if (r_str_startswith (node->name, "bin.laddr")) {
					continue;
				}
				if (r_str_startswith (node->name, "dir.")) {
					continue;
				}
				config_print_node (cfg, node, NULL, "'e ", "", verbose);
			}
		}
		break;
	case 2:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				cfg->cb_printf ("%20s: %s\n", node->name, r_str_get (node->desc));
			}
		}
		break;
	case 3:
		found = false;
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strcmp (str, node->name)))) {
				found = true;
				cfg->cb_printf ("%s\n", r_str_get (node->desc));
				break;
			}
		}
		if (!found) {
			cfg->cb_printf ("Key not found. Try e??%s\n", str);
		}
		break;
	case 's':
		if (str && *str) {
			r_list_foreach (cfg->nodes, iter, node) {
				char *space = strdup (node->name);
				char *dot = strchr (space, '.');
				if (dot) {
					*dot = 0;
				}
				if (!strcmp (str, space)) {
					cfg->cb_printf ("%s\n", dot + 1);
				}
				free (space);
			}
		} else {
			char *oldSpace = NULL;
			r_list_foreach (cfg->nodes, iter, node) {
				char *space = strdup (node->name);
				char *dot = strchr (space, '.');
				if (dot) {
					*dot = 0;
				}
				if (oldSpace) {
					if (!strcmp (space, oldSpace)) {
						free (space);
						continue;
					}
					free (oldSpace);
					oldSpace = space;
				} else {
					oldSpace = space;
				}
				cfg->cb_printf ("%s\n", space);
			}
			free (oldSpace);
		}
		break;
	case 'v':
		verbose = true;
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				config_print_node (cfg, node, NULL, pfx, sfx, verbose);
			}
		}
		break;
	case 'q':
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				cfg->cb_printf ("%s\n", node->name);
			}
		}
		break;
	case 'J':
		verbose = true;
		/* fallthrou */
	case 'j':
		if (verbose) {
			pj_a (pj);
		} else {
			pj_o (pj);
		}
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				if (!str || !strncmp (str, node->name, len)) {
					config_print_node (cfg, node, pj, pfx, sfx, verbose);
				}
			}
		}
		pj_end (pj);
		break;
	}
	if (pj) {
		char *s = pj_drain (pj);
		cfg->cb_printf ("%s\n", s);
		free (s);
	}
}

R_API RConfigNode* r_config_node_get(RConfig *cfg, const char *name) {
	R_RETURN_VAL_IF_FAIL (cfg && name, NULL);
	return ht_pp_find (cfg->ht, name, NULL);
}

R_API const char* r_config_get(RConfig *cfg, const char *name) {
	R_RETURN_VAL_IF_FAIL (cfg && name, NULL);
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (node->getter) {
			node->getter (cfg->user, node);
		}
		if (r_config_node_is_bool (node)) {
			return r_str_bool (r_str_is_true (node->value));
		}
		return node->value;
	} else {
		R_LOG_WARN ("Variable '%s' not found", name);
	}
	return NULL;
}

R_API bool r_config_toggle(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (!node) {
		return false;
	}
	if (!r_config_node_is_bool (node)) {
		R_LOG_ERROR ("Not a boolean variable '%s'", name);
		return false;
	}
	if (r_config_node_is_ro (node)) {
		R_LOG_ERROR ("Key is readonly '%s'", name);
		return false;
	}
	(void)r_config_set_b (cfg, name, !node->i_value);
	return true;
}

R_API bool r_config_get_b(RConfig *cfg, const char *name) {
	return r_config_get_i (cfg, name) != 0;
}

R_API ut64 r_config_get_i(RConfig *cfg, const char *name) {
	R_RETURN_VAL_IF_FAIL (cfg, 0ULL);
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (node->getter) {
			node->getter (cfg->user, node);
		}
		if (node->i_value) {
			return node->i_value;
		}
		if (!strcmp (node->value, "false")) {
			return 0;
		}
		if (!strcmp (node->value, "true")) {
			return 1;
		}
		return (ut64) r_num_math (cfg->num, node->value);
	}
	return 0ULL;
}

R_API const char* r_config_node_type(RConfigNode *node) {
	R_RETURN_VAL_IF_FAIL (node, "");

	if (r_config_node_is_bool (node)) {
		return "bool";
	}
	if (r_config_node_is_str (node)) {
		return "str";
	}
	if (r_config_node_is_int (node)) {
		if (!strncmp (node->value, "0x", 2)) {
			return "addr";
		}
		return "int";
	}
	return "";
}

R_API RConfigNode* r_config_set_cb(RConfig *cfg, const char *name, const char *value, RConfigCallback cb) {
	RConfigNode *node = r_config_set (cfg, name, value);
	if (node && (node->setter = cb)) {
		(void)cb (cfg->user, node);
	}
	return node;
}

R_API RConfigNode* r_config_set_i_cb(RConfig *cfg, const char *name, int ivalue, RConfigCallback cb) {
	RConfigNode *node = r_config_set_i (cfg, name, ivalue);
	if (node && (node->setter = cb)) {
		if (!node->setter (cfg->user, node)) {
			return NULL;
		}
	}
	return node;
}

R_API RConfigNode* r_config_set_b_cb(RConfig *cfg, const char *name, bool ivalue, RConfigCallback cb) {
	RConfigNode *node = r_config_set_b (cfg, name, ivalue);
	if (node && (node->setter = cb)) {
		if (!node->setter (cfg->user, node)) {
			return NULL;
		}
	}
	return node;
}

static inline bool is_true_or_false(const char *s) {
	return s && (!r_str_casecmp (s, "true") || !r_str_casecmp (s, "false"));
}

/* TODO: reduce number of strdups here */
R_API RConfigNode* r_config_set(RConfig *cfg, const char *name, const char *value) {
	char *ov = NULL;
	ut64 oi;
	R_RETURN_VAL_IF_FAIL (cfg && cfg->ht, NULL);
	R_RETURN_VAL_IF_FAIL (!IS_NULLSTR (name), NULL);
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (r_config_node_is_ro (node)) {
			R_LOG_ERROR ("Key '%s' is readonly", name);
			return node;
		}
		oi = node->i_value;
		if (node->value) {
			ov = strdup (node->value);
			if (!ov) {
				return node;
			}
		} else {
			node->value = strdup ("");
		}
		R_DIRTY_SET (cfg);
		if (r_config_node_is_bool (node)) {
			bool b = r_str_is_true (value);
			node->i_value = b;
			char *value = strdup (r_str_bool (b));
			if (value) {
				free (node->value);
				node->value = value;
			}
		} else {
			if (!value) {
				free (node->value);
				node->value = strdup ("");
				node->i_value = 0;
			} else {
				if (node->value == value) {
					goto beach;
				}
				free (node->value);
				node->value = strdup (value);
				if (isdigit (*value) || (value[0] == '-' && isdigit (value[1]))) {
					if (strchr (value, '/')) {
						node->i_value = r_num_get (cfg->num, value);
					} else {
						node->i_value = r_num_math (cfg->num, value);
					}
				} else {
					node->i_value = 0;
				}
				node->flags |= CN_INT;
			}
		}
	} else { // Create a new RConfigNode
		oi = UT64_MAX;
		if (!cfg->lock) {
			node = r_config_node_new (name, value);
			if (R_LIKELY (node)) {
				if (is_true_or_false (value)) {
					node->flags |= CN_BOOL;
					node->i_value = r_str_is_true (value)? 1: 0;
				}
				ht_pp_insert (cfg->ht, node->name, node);
				r_list_append (cfg->nodes, node);
			} else {
				R_LOG_ERROR ("unable to create a new RConfigNode");
			}
		} else {
			R_LOG_ERROR ("variable '%s' not found", name);
		}
	}

	if (node && node->setter) {
		if (!node->setter (cfg->user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free (node->value);
			node->value = strdup (r_str_get (ov));
			if (ov) {
				free (ov);
			}
			return NULL;
		}
	}
beach:
	free (ov);
	return node;
}

/* r_config_desc takes a RConfig and a name,
 * r_config_node_desc takes a RConfigNode
 * Both set and return node->desc */
R_API RConfigNode *r_config_desc(RConfig *cfg, const char *name, const char *desc) {
	RConfigNode *node = r_config_node_get (cfg, name);
	return r_config_node_desc (node, desc);
}

R_API RConfigNode* r_config_node_desc(RConfigNode *node, const char *desc) {
	R_RETURN_VAL_IF_FAIL (node, NULL);
	if (desc) {
		free (node->desc);
		node->desc = strdup (desc);
	}
	return node;
}

R_API bool r_config_rm(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		R_DIRTY_SET (cfg);
		ht_pp_delete (cfg->ht, node->name);
		r_list_delete_data (cfg->nodes, node);
		return true;
	}
	return false;
}

R_API void r_config_node_value_format_i(char *buf, size_t buf_size, const ut64 i, RConfigNode * R_NULLABLE node) {
	if (node && r_config_node_is_bool (node)) {
		r_str_ncpy (buf, r_str_bool ((int) i), buf_size);
		return;
	}
	if (i < 1024) {
		snprintf (buf, buf_size, "%" PFMT64d, i);
	} else {
		snprintf (buf, buf_size, "0x%08" PFMT64x, i);
	}
}

R_API RConfigNode* r_config_set_b(RConfig *cfg, const char *name, bool b) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (!r_config_node_is_ro (node)) {
			if (r_config_node_is_bool (node)) {
				return r_config_set (cfg, name, r_str_bool (b));
			}
		}
		R_LOG_WARN ("This node is not boolean");
		R_RETURN_VAL_IF_FAIL (false, NULL);
		// return NULL;
	}
	node = r_config_node_new (name, r_str_bool (b));
	if (!node) {
		return NULL;
	}
	node->flags = CN_RW | CN_BOOL;
	node->i_value = b;
	ht_pp_insert (cfg->ht, node->name, node);
	if (cfg->nodes) {
		r_list_append (cfg->nodes, node);
	}
	return node;
}

R_API RConfigNode* r_config_set_i(RConfig *cfg, const char *name, const ut64 i) {
	char buf[128], *ov = NULL;
	R_RETURN_VAL_IF_FAIL (cfg && name, NULL);
	RConfigNode *node = r_config_node_get (cfg, name);
	R_DIRTY_SET (cfg);
	if (node) {
		if (r_config_node_is_ro (node)) {
			node = NULL;
			goto beach;
		}
		ov = node->value;
		r_config_node_value_format_i (buf, sizeof (buf), i, NULL);
		node->value = strdup (buf);
		if (!node->value) {
			node = NULL;
			goto beach;
		}
		node->i_value = i;
	} else {
		if (!cfg->lock) {
			r_config_node_value_format_i (buf, sizeof (buf), i, NULL);
			node = r_config_node_new (name, buf);
			if (!node) {
				node = NULL;
				goto beach;
			}
			node->flags = CN_RW | CN_INT;
			node->i_value = i;
			ht_pp_insert (cfg->ht, node->name, node);
			if (cfg->nodes) {
				r_list_append (cfg->nodes, node);
			}
		} else {
			R_LOG_ERROR ("Cannot create a new '%s' key because config is locked", name);
		}
	}

	if (node && node->setter) {
		ut64 oi = node->i_value;
		int ret = node->setter (cfg->user, node);
		if (!ret) {
			node->i_value = oi;
			free (node->value);
			node->value = ov? ov: strdup ("");
			ov = NULL;
		}
	}
beach:
	free (ov);
	return node;
}

static void eval_config_string(RConfig *cfg, char *name) {
	if (!*name) {
		return;
	}
	char *eq = strchr (name, '=');
	if (eq) {
		*eq++ = 0;
		r_str_trim (name);
		r_str_trim (eq);
		if (*name) {
			(void) r_config_set (cfg, name, eq);
		}
	} else {
		if (r_str_endswith (name, ".") && !r_str_endswith (name, "..")) {
			r_config_list (cfg, name, 0);
		} else {
			const char *v = r_config_get (cfg, name);
			if (v) {
				cfg->cb_printf ("%s\n", v);
			} else {
				R_LOG_ERROR ("Invalid config key %s", name);
			}
		}
	}
}

R_API bool r_config_eval(RConfig *cfg, const char *str, bool many) {
	R_RETURN_VAL_IF_FAIL (cfg && str, false);

	char *s = r_str_trim_dup (str);

	if (!*s || !strcmp (s, "help")) { // 580 wtf is help here
		r_config_list (cfg, NULL, 0);
		free (s);
		return false;
	}

	if (*s == '-') {
		r_config_rm (cfg, s + 1);
		free (s);
		return false;
	}
	if (many) {
		RList *list = r_str_split_list (s, ":", 0);
		RListIter *iter;
		char *name;
		r_list_foreach (list, iter, name) {
			eval_config_string (cfg, name);
		}
		free (s);
		return true;
	}
	eval_config_string (cfg, s);
	free (s);
	return true;
}

static int cmp(RConfigNode *a, RConfigNode *b) {
	return strcmp (a->name, b->name);
}

R_API void r_config_lock(RConfig *cfg, bool lock) {
	r_list_sort (cfg->nodes, (RListComparator) cmp);
	cfg->lock = lock;
}

R_API bool r_config_readonly(RConfig *cfg, const char *key) {
	RConfigNode *n = r_config_node_get (cfg, key);
	if (n) {
		n->flags |= CN_RO;
		return true;
	}
	return false;
}

R_API RConfig* r_config_new(void *user) {
	RConfig *cfg = R_NEW0 (RConfig);
	if (!cfg) {
		return NULL;
	}
	cfg->ht = ht_pp_new0 ();
	cfg->nodes = r_list_newf ((RListFree)r_config_node_free);
	if (!cfg->nodes) {
		R_FREE (cfg);
		return NULL;
	}
	cfg->user = user;
	cfg->num = NULL;
	cfg->lock = false;
	cfg->cb_printf = (void *) printf;
	R_DIRTY_SET (cfg);
	return cfg;
}

R_API RConfig* r_config_clone(RConfig *cfg) {
	RListIter *iter;
	RConfigNode *node;
	RConfig *c = r_config_new (cfg->user);
	if (!c) {
		return NULL;
	}
	r_list_foreach (cfg->nodes, iter, node) {
		RConfigNode *nn = r_config_node_clone (node);
		ht_pp_insert (c->ht, node->name, nn);
		r_list_append (c->nodes, nn);
	}
	c->lock = cfg->lock;
	c->cb_printf = cfg->cb_printf;
	R_DIRTY_SET (c);
	return c;
}

R_API void r_config_free(RConfig *cfg) {
	if (R_LIKELY (cfg)) {
		cfg->nodes->free = r_config_node_free; // damn
		r_list_free (cfg->nodes);
		ht_pp_free (cfg->ht);
		free (cfg);
	}
}

R_API void r_config_visual_hit_i(RConfig *cfg, const char *name, int delta) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node && r_config_node_is_int (node)) {
		(void)r_config_set_i (cfg, name, r_config_get_i (cfg, name) + delta);
	}
}

R_API void r_config_bump(RConfig *cfg, const char *key) {
	char *orig = strdup (r_config_get (cfg, key));
	if (R_LIKELY (orig)) {
		r_config_set (cfg, key, orig);
		free (orig);
	}
}

R_API void r_config_serialize(RConfig * R_NONNULL config, Sdb * R_NONNULL db) {
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (config->nodes, iter, node) {
		sdb_set (db, node->name, node->value, 0);
	}
}

static bool load_config_cb(void *user, const char *k, const char *v) {
	RConfig *config = user;
	RConfigNode *node = r_config_node_get (config, k);
	if (R_LIKELY (node)) {
		r_config_set (config, k, v);
	}
	return true;
}

R_API bool r_config_unserialize(RConfig * R_NONNULL config, Sdb * R_NONNULL db, char ** R_NULLABLE err) {
	R_RETURN_VAL_IF_FAIL (config && db, false);
	*err = NULL;
	sdb_foreach (db, load_config_cb, config);
	return *err == NULL;
}
