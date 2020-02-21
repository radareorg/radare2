/* radare - LGPL - Copyright 2006-2019 - pancake */

#include "r_config.h"

R_API RConfigNode* r_config_node_new(const char *name, const char *value) {
	r_return_val_if_fail (name && *name && value, NULL);
	RConfigNode *node = R_NEW0 (RConfigNode);
	if (!node) {
		return NULL;
	}
	node->name = strdup (name);
	node->value = strdup (value? value: "");
	node->flags = CN_RW | CN_STR;
	node->i_value = r_num_get (NULL, value);
	node->options = r_list_new ();
	return node;
}

R_API RConfigNode* r_config_node_clone(RConfigNode *n) {
	r_return_val_if_fail (n, NULL);
	RConfigNode *cn = R_NEW0 (RConfigNode);
	if (!cn) {
		return NULL;
	}
	cn->name = strdup (n->name);
	cn->desc = n->desc? strdup (n->desc): NULL;
	cn->value = strdup (n->value? n->value: "");
	cn->i_value = n->i_value;
	cn->flags = n->flags;
	cn->setter = n->setter;
	cn->options = r_list_clone (n->options);
	return cn;
}

R_API void r_config_node_free(void *n) {
	r_return_if_fail (n);
	RConfigNode *node = (RConfigNode *)n;
	if (!node) {
		return;
	}
	free (node->name);
	free (node->desc);
	free (node->value);
	r_list_free (node->options);
	free (node);
}

static void config_print_value_json(RConfig *cfg, RConfigNode *node) {
	r_return_if_fail (cfg && node);
	const char *val = node->value;
	if (!val) {
		val = "0";
	}
	char *sval = r_str_escape (val);
	if (r_config_node_is_bool (node) || r_config_node_is_int (node)) {
		if (!strncmp (val, "0x", 2)) {
			ut64 n = r_num_get (NULL, val);
			cfg->cb_printf ("%"PFMT64d, n);
		} else if (r_str_isnumber (val) || (*val /* HACK */ && r_str_is_bool (val))) {
			cfg->cb_printf ("%s", val);  // TODO: always use true/false for bool json str
		} else {
			cfg->cb_printf ("\"%s\"", sval);
		}
	} else {
		cfg->cb_printf ("\"%s\"", sval);
	}
	free (sval);
}

static void config_print_node(RConfig *cfg, RConfigNode *node, const char *pfx, const char *sfx, bool verbose, bool json) {
	r_return_if_fail (cfg && node && pfx && sfx);
	char *option;
	bool isFirst;
	RListIter *iter;
	char *es = NULL;

	if (json) {
		if (verbose) {
			cfg->cb_printf ("{");
			cfg->cb_printf ("\"name\":\"%s\",", node->name);
			cfg->cb_printf ("\"value\":");
			config_print_value_json (cfg, node);
			cfg->cb_printf (",\"type\":\"%s\",", r_config_node_type (node));
			es = r_str_escape (node->desc);
			if (es) {
				cfg->cb_printf ("\"desc\":\"%s\",", es);
				free (es);
			}
			cfg->cb_printf ("\"ro\":%s", r_str_bool (r_config_node_is_ro (node)));
			if (!r_list_empty (node->options)) {
				isFirst = true;
				cfg->cb_printf (",\"options\":[");
				r_list_foreach (node->options, iter, option) {
					es = r_str_escape (option);
					if (es) {
						if (isFirst) {
							isFirst = false;
						} else {
							cfg->cb_printf (",");
						}
						cfg->cb_printf ("\"%s\"", es);
						free (es);
					}
				}
				cfg->cb_printf ("]");
			}
			cfg->cb_printf ("}");
		} else {
			cfg->cb_printf ("\"%s\":", node->name);
			config_print_value_json (cfg, node);
		}
	} else {
		if (verbose) {
			cfg->cb_printf ("%s%s = %s%s %s; %s", pfx,
				node->name, node->value, sfx, 
				r_config_node_is_ro (node) ? "(ro)" : "",
				node->desc);
			if (!r_list_empty (node->options)) {
				isFirst = true;
				cfg->cb_printf(" [");
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
	r_return_if_fail (cfg);
	RConfigNode *node;
	RListIter *iter;
	const char *sfx = "";
	const char *pfx = "";
	int len = 0;
	bool verbose = false;
	bool json = false;
	bool isFirst = false;

	if (!IS_NULLSTR (str)) {
		str = r_str_trim_head_ro (str);
		len = strlen (str);
		if (len > 0 && str[0] == 'j') {
			str++;
			len--;
			json = true;
			rad = 'J';
		}
		if (len > 0 && str[0] == ' ') {
			str++;
			len--;
		}
		if (strlen (str) == 0) {
			str = NULL;
			len = 0;
		}
	}

	switch (rad) {
	case 1:
		pfx = "\"e ";
		sfx = "\"";
	/* fallthrou */
	case 0:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				config_print_node (cfg, node, pfx, sfx, verbose, json);
			}
		}
		break;
	case 2:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				if (!str || !strncmp (str, node->name, len)) {
					cfg->cb_printf ("%20s: %s\n", node->name,
						node->desc? node->desc: "");
				}
			}
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
				config_print_node (cfg, node, pfx, sfx, verbose, json);
			}
		}
		break;
	case 'q':
		r_list_foreach (cfg->nodes, iter, node) {
			cfg->cb_printf ("%s\n", node->name);
		}
		break;
	case 'J':
		verbose = true;
	/* fallthrou */
	case 'j':
		isFirst = true;
		if (verbose) {
			cfg->cb_printf ("[");
		} else {
			cfg->cb_printf ("{");
		}
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len)))) {
				if (!str || !strncmp (str, node->name, len)) {
					if (isFirst) {
						isFirst = false;
					} else {
						cfg->cb_printf (",");
					}
					config_print_node (cfg, node, pfx, sfx, verbose, true);
				}
			}
		}
		if (verbose) {
			cfg->cb_printf ("]\n");
		} else {
			cfg->cb_printf ("}\n");
		}
		break;
	}
}

R_API RConfigNode* r_config_node_get(RConfig *cfg, const char *name) {
	r_return_val_if_fail (cfg && name, NULL);
	return ht_pp_find (cfg->ht, name, NULL);
}

R_API bool r_config_set_getter(RConfig *cfg, const char *key, RConfigCallback cb) {
	r_return_val_if_fail (cfg && key, false);
	RConfigNode *node = r_config_node_get (cfg, key);
	if (node) {
		node->getter = cb;
		return true;
	}
	return false;
}

R_API bool r_config_set_setter(RConfig *cfg, const char *key, RConfigCallback cb) {
	RConfigNode *node = r_config_node_get (cfg, key);
	if (node) {
		node->setter = cb;
		return true;
	}
	return false;
}

R_API const char* r_config_get(RConfig *cfg, const char *name) {
	r_return_val_if_fail (cfg && name, NULL);
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
		eprintf ("r_config_get: variable '%s' not found\n", name);
	}
	return NULL;
}

R_API bool r_config_toggle(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node && r_config_node_is_bool (node)) {
		(void)r_config_set_i (cfg, name, !node->i_value);
		return true;
	}
	return false;
}

R_API ut64 r_config_get_i(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (node->getter) {
			node->getter (cfg->user, node);
		}
		if (node->i_value || !strcmp (node->value, "false")) {
			return node->i_value;
		}
		if (!strcmp (node->value, "true")) {
			return 1;
		}
		return (ut64) r_num_math (cfg->num, node->value);
	}
	return (ut64) 0LL;
}

R_API const char* r_config_node_type(RConfigNode *node) {
	r_return_val_if_fail (node, "");

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
		if (!cb (cfg->user, node)) {
			return NULL;
		}
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

/* TODO: reduce number of strdups here */
R_API RConfigNode* r_config_set(RConfig *cfg, const char *name, const char *value) {
	RConfigNode *node = NULL;
	char *ov = NULL;
	ut64 oi;

	r_return_val_if_fail (cfg && cfg->ht, NULL);
	r_return_val_if_fail (!IS_NULLSTR (name), NULL);

	node = r_config_node_get (cfg, name);
	if (node) {
		if (r_config_node_is_ro (node)) {
			eprintf ("(error: '%s' config key is read only)\n", name);
			return node;
		}
		oi = node->i_value;
		if (node->value) {
			ov = strdup (node->value);
			if (!ov) {
				goto beach;
			}
		} else {
			free (node->value);
			node->value = strdup ("");
		}
		if (r_config_node_is_bool (node)) {
			bool b = *value && r_str_is_true (value);
			node->i_value = b? 1: 0;
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
				if (IS_DIGIT (*value) || (value[0] == '-' && IS_DIGIT (value[1]))) {
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
			if (node) {
				if (value && *value && r_str_is_bool (value)) {
					node->flags |= CN_BOOL;
					node->i_value = r_str_is_true (value)? 1: 0;
				}
				ht_pp_insert (cfg->ht, node->name, node);
				r_list_append (cfg->nodes, node);
			} else {
				eprintf ("r_config_set: unable to create a new RConfigNode\n");
			}
		} else {
			eprintf ("r_config_set: variable '%s' not found\n", name);
		}
	}

	if (node && node->setter) {
		if (!node->setter (cfg->user, node)) {
			if (oi != UT64_MAX) {
				node->i_value = oi;
			}
			free (node->value);
			node->value = strdup (ov? ov: "");
			free (ov);
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
R_API const char* r_config_desc(RConfig *cfg, const char *name, const char *desc) {
	RConfigNode *node = r_config_node_get (cfg, name);
	return r_config_node_desc (node, desc);
}

R_API const char* r_config_node_desc(RConfigNode *node, const char *desc) {
	r_return_val_if_fail (node, NULL);
	if (desc) {
		free (node->desc);
		node->desc = strdup (desc);
	}
	return node->desc;
}

R_API bool r_config_rm(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		ht_pp_delete (cfg->ht, node->name);
		r_list_delete_data (cfg->nodes, node);
		return true;
	}
	return false;
}

R_API void r_config_node_value_format_i(char *buf, size_t buf_size, const ut64 i, R_NULLABLE RConfigNode *node) {
	if (node && r_config_node_is_bool (node)) {
		r_str_ncpy (buf, r_str_bool ((int) i), buf_size);
		return;
	}
	if (i < 1024) {
		snprintf (buf, buf_size, "%" PFMT64d "", i);
	} else {
		snprintf (buf, buf_size, "0x%08" PFMT64x "", i);
	}
}

R_API RConfigNode* r_config_set_i(RConfig *cfg, const char *name, const ut64 i) {
	char buf[128], *ov = NULL;
	r_return_val_if_fail (cfg && name, NULL);
	RConfigNode *node = r_config_node_get (cfg, name);
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
			eprintf ("(locked: no new keys can be created (%s))\n", name);
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

static void __evalString(RConfig *cfg, char *name) {
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
		if (r_str_endswith (name, ".")) {
			r_config_list (cfg, name, 0);
		} else {
			const char *v = r_config_get (cfg, name);
			if (v) {
				cfg->cb_printf ("%s\n", v);
			} else {
				eprintf ("Invalid config key %s\n", name);
			}
		}
	}
}

R_API bool r_config_eval(RConfig *cfg, const char *str, bool many) {
	r_return_val_if_fail (cfg && str, false);

	char *s = r_str_trim_dup (str);

	if (!*s || !strcmp (s, "help")) {
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
		// space separated list of k=v k=v,..
		// if you want to use spaces go for base64 or e.
		RList *list = r_str_split_list (s, ",", 0);
		RListIter *iter;
		char *name;
		r_list_foreach (list, iter, name) {
			__evalString (cfg, name);
		}
		free (s);
		return true;
	}
	__evalString (cfg, s);
	free (s);
	return true;
}

static int cmp(RConfigNode *a, RConfigNode *b) {
	return strcmp (a->name, b->name);
}

R_API void r_config_lock(RConfig *cfg, int l) {
	r_list_sort (cfg->nodes, (RListComparator) cmp);
	cfg->lock = l;
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
	cfg->lock = 0;
	cfg->cb_printf = (void *) printf;
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
	return c;
}

R_API void r_config_free(RConfig *cfg) {
	if (cfg) {
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
	if (orig) {
		r_config_set (cfg, key, orig);
		free (orig);
	}
}

R_API void r_config_serialize(R_NONNULL RConfig *config, R_NONNULL Sdb *db) {
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (config->nodes, iter, node) {
		sdb_set (db, node->name, node->value, 0);
	}
}

static int load_config_cb(void *user, const char *k, const char *v) {
	RConfig *config = user;
	RConfigNode *node = r_config_node_get (config, k);
	if (!node) {
		return 1;
	}
	r_config_set (config, k, v);
	return 1;
}

R_API bool r_config_unserialize(R_NONNULL RConfig *config, R_NONNULL Sdb *db, R_NULLABLE char **err) {
	sdb_foreach (db, load_config_cb, config);
	return true;
}
