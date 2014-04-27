/* radare - LGPL - Copyright 2006-2011 pancake<nopcode.org> */

#include "r_config.h"

// XXX spaguetti code lives here
static int r_config_callback_q(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_q) = node->i_value;
	return R_TRUE;
}

static int r_config_callback_i(void *data) {
	RConfigNode *node = data;
	*(node->cb_ptr_i) = node->i_value;
	return R_TRUE;
}

static int r_config_callback_s(void *data) {
	RConfigNode *node = data;
	if (!node->value || !*node->value) {
		free (*node->cb_ptr_s);
		*node->cb_ptr_s = NULL;
	} else *node->cb_ptr_s = r_str_dup (*node->cb_ptr_s, node->value);
	return R_TRUE;
}

R_API int r_config_set_callback_q(RConfig *cfg, const char *name, ut64 *ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_q = ptr;
		node->callback = (void *)&r_config_callback_q;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_config_set_callback_i(RConfig *cfg, const char *name, int *ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_i = ptr;
		node->callback = (void *)&r_config_callback_i;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_config_set_callback_s(RConfig *cfg, const char *name, char **ptr) {
	RConfigNode *node = r_config_node_get (cfg, name);
	if (node) {
		node->cb_ptr_s = ptr;
		node->callback = (void *)&r_config_callback_s;
		return R_TRUE;
	}
	return R_FALSE;
}
