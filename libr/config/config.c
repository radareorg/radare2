/* radare - LGPL - Copyright 2006-2014 - pancake */

#include "r_config.h"
#include "r_util.h" // r_str_hash, r_str_chop, ...

R_API RConfigNode* r_config_node_new(const char *name, const char *value) {
	RConfigNode *node;
	if (!name || !*name)
		return NULL;
	node = R_NEW0 (RConfigNode);
	if (!node) return NULL;
	node->name = strdup (name);
	node->hash = r_str_hash (name);
	node->value = strdup (value? value: "");
	node->flags = CN_RW | CN_STR;
	node->i_value = r_num_get (NULL, value);;
	return node;
}

R_API RConfigNode *r_config_node_clone (RConfigNode *n) {
	RConfigNode *cn = R_NEW0 (RConfigNode);
	cn->name = strdup (n->name);
	cn->desc = n->desc? strdup (n->desc): NULL;
	cn->hash = n->hash;
	cn->value = strdup (n->value? n->value: "");
	cn->i_value = n->i_value;
	cn->flags = n->flags;
	cn->setter = n->setter;
	return cn;
}

R_API void r_config_node_free (void *n) {
	RConfigNode *node = (RConfigNode*)n;
	if (!node) return;
	free (node->name);
	free (node->desc);
	free (node->value);
	free (node);
}

R_API void r_config_list(RConfig *cfg, const char *str, int rad) {
	RConfigNode *node;
	RListIter *iter;
	const char *sfx = "";
	const char *pfx = "";
	int len = 0;

	if (!strnull (str)) {
		str = r_str_chop_ro (str);
		len = strlen (str);
	}
	switch (rad) {
	case 1:
		pfx = "\"e ";
		sfx = "\"";
	case 0:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len))))
				cfg->printf ("%s%s = %s%s\n", pfx,
					node->name, node->value, sfx);
		}
		break;
	case 2:
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len))))
				if (!str || !strncmp (str, node->name, len))
					cfg->printf ("%20s: %s\n", node->name,
						node->desc?node->desc:"");
		}
		break;
	case 'j':
		cfg->printf ("{");
		r_list_foreach (cfg->nodes, iter, node) {
			if (!str || (str && (!strncmp (str, node->name, len))))
				if (!str || !strncmp (str, node->name, len)) {
					const char *val = node->value;
					if (node->flags & CN_BOOL || node->flags & CN_INT || node->flags & CN_OFFT) {
						if (!val) val = "0";
						cfg->printf ("\"%s\":%s",
							node->name, val);
					} else
						cfg->printf ("\"%s\":\"%s\"",
							node->name, val);
					if (iter->n)
						cfg->printf (",");
				}
		}
		cfg->printf ("}\n");
		break;
	}
}

R_API RConfigNode *r_config_node_get(RConfig *cfg, const char *name) {
	if (strnull (name))
		return NULL;
	return r_hashtable_lookup (cfg->ht, r_str_hash (name));
}

R_API int r_config_set_getter (RConfig *cfg, const char *key, RConfigCallback cb) {
	RConfigNode *node = r_config_node_get (cfg, key);
	if (node) {
		node->getter = cb;
		return 1;
	}
	return 0;
}

R_API int r_config_set_setter (RConfig *cfg, const char *key, RConfigCallback cb) {
	RConfigNode *node = r_config_node_get (cfg, key);
	if (node) {
		node->setter = cb;
		return 1;
	}
	return 0;
}

R_API const char *r_config_get(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (node->getter)
			node->getter (cfg->user, node);
		cfg->last_notfound = 0;
		if (node->flags & CN_BOOL)
			return (const char *)
				(((!strcmp ("true", node->value))
				  || (!strcmp ("1", node->value)))?
				  (const char *)"true":"false"); // XXX (char*)1 is ugly
		return node->value;
	} else eprintf ("r_config_get: variable '%s' not found\n", name);
	cfg->last_notfound = 1;
	return NULL;
}

// rename to toggle?
R_API int r_config_swap(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node && node->flags & CN_BOOL) {
		r_config_set_i (cfg, name, !node->i_value);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API ut64 r_config_get_i(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		if (node->getter)
			node->getter (cfg->user, node);
		if (node->i_value != 0 || !strcmp (node->value, "false"))
			return node->i_value;
		return (ut64)r_num_math (cfg->num, node->value);
	}
	return (ut64)0LL;
}

R_API RConfigNode *r_config_set_cb(RConfig *cfg, const char *name, const char *value, RConfigCallback cb) {
	RConfigNode *node = r_config_set (cfg, name, value);
	if (node && (node->setter = cb))
		if (!cb (cfg->user, node))
			return NULL;
	return node;
}

R_API RConfigNode *r_config_set_i_cb(RConfig *cfg, const char *name, int ivalue, RConfigCallback cb) {
	RConfigNode *node = r_config_set_i (cfg, name, ivalue);
	if (node && (node->setter = cb))
		if (!node->setter (cfg->user, node))
			return NULL;
	return node;
}

/* TODO: reduce number of strdups here */
R_API RConfigNode *r_config_set(RConfig *cfg, const char *name, const char *value) {
	RConfigNode *node;
	char *ov = NULL;
	ut64 oi;
	if (!cfg || strnull (name))
		return NULL;
	node = r_config_node_get (cfg, name);
	// TODO: store old value somewhere..
	if (node) {
		if (node->flags & CN_RO) {
			eprintf ("(error: '%s' config key is read only)\n", name);
			return node;
		}
		oi = node->i_value;
		if (node->value)
			ov = strdup (node->value);
		else node->value = strdup ("");
		free (node->value);
		if (node->flags & CN_BOOL) {
			int b = (!strcmp (value,"true") || !strcmp (value,"1"));
			node->i_value = (ut64)(b==0)?0:1;
			node->value = strdup (b?"true":"false");
		} else {
			if (value == NULL) {
				node->value = strdup ("");
				node->i_value = 0;
			} else {
				node->value = strdup (value);
				if (*value>='0' && *value<='9') {
					if (strchr (value, '/'))
						node->i_value = r_num_get (cfg->num, value);
					else node->i_value = r_num_math (cfg->num, value);
				} else node->i_value = 0;
				node->flags |= CN_INT;
			}
		}
	} else { // Create a new RConfigNode
		oi = UT64_MAX;
		if (!cfg->lock) {
			node = r_config_node_new (name, value);
			if (node) {
				if (value && (!strcmp (value, "true") || !strcmp (value, "false"))) {
					node->flags |= CN_BOOL;
					node->i_value = (!strcmp (value, "true"))? 1: 0;
				}
				if (cfg->ht) {
					r_hashtable_insert (cfg->ht, node->hash, node);
					r_list_append (cfg->nodes, node);
					cfg->n_nodes++;
				}
			} else
				eprintf ("r_config_set: unable to create a new RConfigNode\n");
		} else eprintf ("r_config_set: variable '%s' not found\n", name);
	}

	if (node && node->setter) {
		int ret = node->setter (cfg->user, node);
		if (ret == R_FALSE) {
			if (oi != UT64_MAX)
				node->i_value = oi;
			free (node->value);
			node->value = strdup (ov ? ov : "");
			free (ov);
			return NULL;
		}
	}
	free (ov);
	return node;
}

/* r_config_desc takes a RConfig and a name,
 * r_config_node_desc takes a RConfigNode
 * Both set and return node->desc */
R_API const char *r_config_desc(RConfig *cfg, const char *name, const char *desc) {
	RConfigNode *node = r_config_node_get (cfg, name);
	return r_config_node_desc (node, desc);
}

R_API const char *r_config_node_desc(RConfigNode *node, const char *desc) {
	if (node) {
		if (desc) {
			free (node->desc);
			node->desc = strdup (desc);
		}
		return node->desc;
	}
	return NULL;
}

R_API int r_config_rm(RConfig *cfg, const char *name) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		r_hashtable_remove (cfg->ht, node->hash);
		r_list_delete_data (cfg->nodes, node);
		cfg->n_nodes--;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API RConfigNode *r_config_set_i(RConfig *cfg, const char *name, const ut64 i) {
	char buf[128], *ov = NULL;
	RConfigNode *node = r_config_node_get (cfg, name);

	if (node) {
		if (node->flags & CN_RO)
			return NULL;
		if (node->value) {
			ov = strdup (node->value);
			free (node->value);
		}
		if (node->flags & CN_BOOL) {
			node->value = strdup (r_str_bool(i));
		} else {
			snprintf (buf, sizeof (buf)-1, "%"PFMT64d, i);
			node->value = strdup (buf);
		}
		//node->flags = CN_RW | CN_INT;
		node->i_value = i;
	} else {
		if (!cfg->lock) {
			if (i<1024) snprintf (buf, sizeof (buf), "%"PFMT64d"", i);
			else snprintf (buf, sizeof (buf), "0x%08"PFMT64x"", i);
			node = r_config_node_new (name, buf);
			if (!node) return NULL;
			node->flags = CN_RW | CN_OFFT;
			node->i_value = i;
			if (cfg->ht) r_hashtable_insert (cfg->ht, node->hash, node);
			if (cfg->nodes) {
				r_list_append (cfg->nodes, node);
				cfg->n_nodes++;
			}
		} else eprintf ("(locked: no new keys can be created (%s))\n", name);
	}

	if (node && node->setter) {
		ut64 oi = node->i_value;
		int ret = node->setter (cfg->user, node);
		if (ret == R_FALSE) {
			node->i_value = oi;
			free (node->value);
			node->value = strdup (ov? ov: "");
		}
	}
	free (ov);
	return node;
}

R_API int r_config_eval(RConfig *cfg, const char *str) {
	char *ptr, *a, *b, name[1024];
	unsigned int len;
	if (!str || !cfg) return R_FALSE;
	len = strlen (str)+1;
	if (len >= sizeof (name))
		return R_FALSE;
	memcpy (name, str, len);
	str = r_str_chop (name);

	if (str == NULL)
		return R_FALSE;

	if (str[0]=='\0' || !strcmp (str, "help")) {
		r_config_list (cfg, NULL, 0);
		return R_FALSE;
	}

	if (str[0]=='-') {
		r_config_rm (cfg, str+1);
		return R_FALSE;
	}

	ptr = strchr (str, '=');
	if (ptr) {
		/* set */
		ptr[0]='\0';
		a = r_str_chop (name);
		b = r_str_chop (ptr+1);
		r_config_set (cfg, a, b);
	} else {
		char *foo = r_str_chop (name);
		if (foo[strlen(foo)-1]=='.') {
			r_config_list (cfg, name, 0);
			return R_FALSE;
		} else {
			/* get */
			const char *str = r_config_get(cfg, foo);
			if (str)
				cfg->printf ("%s\n",
					(((int)(size_t)str)==1)?"true":str);
		}
	}
	return R_TRUE;
}

static int cmp(RConfigNode *a, RConfigNode *b) {
	return strcmp (a->name, b->name);
}

R_API void r_config_lock(RConfig *cfg, int l) {
	r_list_sort (cfg->nodes, (RListComparator)cmp);
	cfg->lock = l;
}

R_API int r_config_readonly (RConfig *cfg, const char *key) {
	RConfigNode *n = r_config_node_get (cfg, key);
	if (!n) return R_FALSE;
	n->flags |= CN_RO;
	return R_TRUE;
}

R_API RConfig *r_config_new(void *user) {
	RConfig *cfg = R_NEW (RConfig);
	if (cfg) {
		cfg->ht = r_hashtable_new ();
		cfg->nodes = r_list_new ();
		cfg->nodes->free = r_config_node_free;
		cfg->user = user;
		cfg->num = NULL;
		cfg->n_nodes = 0;
		cfg->lock = 0;
		cfg->printf = (void *)printf;
	}
	return cfg;
}

R_API RConfig *r_config_clone (RConfig *cfg) {
	RListIter *iter;
	RConfigNode *node;
	RConfig *c = r_config_new (cfg->user);
	r_list_foreach (cfg->nodes, iter, node) {
		RConfigNode *nn = r_config_node_clone (node);
		r_hashtable_insert (c->ht, node->hash, nn);
		r_list_append (c->nodes, nn);
		c->n_nodes++;
	}
	c->lock = cfg->lock;
	c->printf = cfg->printf;
	return c;
}

R_API int r_config_free(RConfig *cfg) {
	if (!cfg) return 0;
	cfg->nodes->free = r_config_node_free; // damn
	r_list_free (cfg->nodes);
	r_hashtable_free (cfg->ht);
	free (cfg);
	return 0;
}

R_API void r_config_visual_hit_i(RConfig *cfg, const char *name, int delta) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node && (node->flags & CN_INT || node->flags & CN_OFFT))
		r_config_set_i (cfg, name, r_config_get_i (cfg, name)+delta);
}
