/* radare - LGPL - Copyright 2006-2021 - pancake */

#include <r_config.h>

// this is internal no need to make it public
typedef struct r_config_holder_t {
	ut32 flags;
	char *key;
	union {
		ut64 num;
		char *str;
	} data;
} RConfigHolder;

static void r_config_holder_free(RConfigHolder *hc) {
	if (hc) {
		free (hc->key);
		if (hc->flags & CN_STR) {
			free (hc->data.str);
		}
		free (hc);
	}
}

static RConfigHolder *node_to_holder(RConfigNode *node) {
	RConfigHolder *hc = R_NEW0 (RConfigHolder);
	if (hc) {
		hc->key = strdup (node->name);
		hc->flags = node->flags;
		if (node->flags & CN_STR) {
			hc->data.str = strdup (node->value);
		} else {
			hc->data.num = node->i_value;
		}
	}
	return hc;
}

R_API bool r_config_hold(RConfigHold *h, ...) {
	r_return_val_if_fail (h, false);
	va_list ap;
	char *key;
	va_start (ap, h);
	while ((key = va_arg (ap, char *))) {
		RConfigNode *node = r_config_node_get (h->cfg, key);
		r_return_val_if_fail (node, false);
		r_list_append (h->list, node_to_holder (node));
	}
	va_end (ap);
	return true;
}

R_API RConfigHold* r_config_hold_new(RConfig *cfg) {
	r_return_val_if_fail (cfg, NULL);
	RConfigHold *hold = R_NEW0 (RConfigHold);
	if (hold) {
		hold->list = r_list_newf ((RListFree)r_config_holder_free);
		hold->cfg = cfg;
		return hold;
	}
	return NULL;
}

R_API void r_config_hold_restore(RConfigHold *h) {
	r_return_if_fail (h);
	RListIter *iter;
	RConfigHolder *hc;
	RConfig *cfg = h->cfg;
	r_list_foreach (h->list, iter, hc) {
		if (hc->flags & CN_STR)	{
			(void)r_config_set (cfg, hc->key, hc->data.str);
		} else {
			(void)r_config_set_i (cfg, hc->key, hc->data.num);
		}
	}
}

R_API void r_config_hold_free(RConfigHold *h) {
	if (h) {
		r_list_free (h->list);
		free (h);
	}
}
