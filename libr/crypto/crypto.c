/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#include "r_crypto.h"
#include "../config.h"

static struct r_crypto_plugin_t *crypto_static_plugins[] = 
	{ R_CRYPTO_STATIC_PLUGINS };

R_API struct r_crypto_t *r_crypto_init(struct r_crypto_t *cry, int hard)
{
	int i;
	if (cry) {
		cry->key = NULL;
		cry->iv = NULL;
		cry->key_len = 0;
		cry->user = NULL;
		if (hard) {
			// first call initializes the output_* variables
			r_crypto_get_output(cry);
			INIT_LIST_HEAD(&cry->handlers);
			for(i=0;crypto_static_plugins[i];i++)
				r_crypto_add(cry, crypto_static_plugins[i]);
		}
	}
	return cry;
}

R_API int r_crypto_add(struct r_crypto_t *cry, struct r_crypto_plugin_t *h)
{
	// add a check ?
	list_add_tail(&(h->list), &(cry->handlers));
	return R_TRUE;
}

R_API int r_crypto_del(struct r_crypto_t *cry, struct r_crypto_plugin_t *h)
{
	list_del(&(h->list));
	return R_TRUE;
}

R_API struct r_crypto_t *r_crypto_new()
{
	struct r_crypto_t *cry = R_NEW(struct r_crypto_t);
	return r_crypto_init(cry, R_TRUE);
}

R_API struct r_crypto_t *r_crypto_as_new(struct r_crypto_t *cry)
{
	struct r_crypto_t *c = R_NEW(struct r_crypto_t);
	if (c != NULL) {
		r_crypto_init(c, R_FALSE); // soft init
		memcpy(&c->handlers, &cry->handlers, sizeof(cry->handlers));
	}
	return c;
}

R_API struct r_crypto_t *r_crypto_free(struct r_crypto_t *cry)
{
	// TODO: call the destructor function of the plugin to destory the *user pointer if needed
	// TODO: free plugins
	free(cry->output);
	free(cry->key);
	free(cry->iv);
	free(cry);
	return NULL;
}

R_API int r_crypto_use(struct r_crypto_t *cry, const char *algo)
{
	int ret = R_FALSE;
	struct list_head *pos;
	list_for_each_prev(pos, &cry->handlers) {
		struct r_crypto_plugin_t *h = list_entry(pos, struct r_crypto_plugin_t, list);
		if (h->use(algo)) {
			cry->h = h;
			cry->key_len = h->get_key_size(cry);
			cry->key = malloc(cry->key_len);
			break;
		}
	}
	return ret;
}

R_API int r_crypto_set_key(struct r_crypto_t *cry, const ut8* key, int mode, int direction)
{
	int ret = R_FALSE;
	if (cry->h && cry->h->set_key)
		ret = cry->h->set_key(cry, key, mode, direction);
	return ret;
}

R_API int r_crypto_get_key_size(struct r_crypto_t *cry)
{
	int ret = 0;
	if (cry->h && cry->h->get_key_size)
		ret = cry->h->get_key_size(cry);
	return ret;
}

R_API int r_crypto_set_iv(struct r_crypto_t *cry, const ut8 *iv)
{
	int ret = R_FALSE;
	if (cry->h && cry->h->set_iv)
		ret = cry->h->set_iv(cry, iv);
	return ret;
}

// return the number of bytes written in the output buffer
R_API int r_crypto_update(struct r_crypto_t *cry, ut8 *buf, int len)
{
	int olen = 0; // length of output bytes
	if (cry->h && cry->h->update)
		olen = cry->h->update(cry, buf, len);
	return olen;
}

R_API int r_crypto_final(struct r_crypto_t *cry, ut8 *buf, int len)
{
	// TODO: same as update()
	int olen = 0; // length of output bytes
	if (cry->h && cry->h->final)
		olen = cry->h->final(cry, buf, len);
	return olen;
}

// append data to the output buffer
// TODO: internal api?? used from plugins?
R_API int r_crypto_append(struct r_crypto_t *cry, const ut8 *buf, int len)
{
	if (cry->output_len+len > cry->output_size) {
		cry->output_size += 4096 + len;
		cry->output = realloc(cry->output, cry->output_size);
	}
	memcpy(cry->output + cry->output_len, buf, len);
	cry->output_len += len;
	return cry->output_len;
}

// NOTE: Passes ownership of buffer, coz other is freed
R_API ut8 *r_crypto_get_output(struct r_crypto_t *cry)
{
	ut8 *buf = cry->output;
	// free the buffer
	cry->output_size = 4096;
	cry->output = malloc(4096);
	cry->output_len = 0;
	return buf;
}
