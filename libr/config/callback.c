/* radare - LGPL - Copyright 2006-2020 - pancake */

#include "r_config.h"

static bool r_config_setter_q(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_q) = node->i_value;
	return true;
}

static bool r_config_setter_i(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_i) = node->i_value;
	return true;
}

static bool r_config_setter_s(void *data) {
	RConfigNode *node = data;
	if (!node->value || !*node->value) {
		free (*node->cb_ptr_s);
		*node->cb_ptr_s = NULL;
	} else {
		*node->cb_ptr_s = r_str_dup (*node->cb_ptr_s, node->value);
	}
	return true;
}

R_API bool r_config_set_setter_q(RConfig *cfg, const char *name, ut64 *ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_q = ptr;
		node->setter = (void *) &r_config_setter_q;
		return true;
	}
	return false;
}

R_API bool r_config_set_setter_i(RConfig *cfg, const char *name, int *ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_i = ptr;
		node->setter = (void *) &r_config_setter_i;
		return true;
	}
	return false;
}

R_API bool r_config_set_setter_s(RConfig *cfg, const char *name, char * *ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_s = ptr;
		node->setter = (void *) &r_config_setter_s;
		return true;
	}
	return false;
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
