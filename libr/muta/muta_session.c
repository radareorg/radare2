/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_muta.h>

R_API void r_muta_session_free(RMutaSession *R_NULLABLE ms) {
	if (ms) {
		if (ms->h->fini) {
			ms->h->fini (ms);
		}
		free (ms->subtype);
		r_muta_result_free (ms->result);
		free (ms->result);
		free (ms->key);
		free (ms->iv);
		free (ms->plugin_data);
		free (ms);
	}
}
R_API bool r_muta_session_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!ms->h || !ms->h->set_key) {
		return true;
	}
	ms->key_len = keylen;
	ms->key = calloc (1, ms->key_len);
	return ms->h->set_key (ms, key, keylen, mode, direction);
}

R_API int r_muta_session_get_key_size(RMutaSession *ms) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	return (ms->h && ms->h->get_key_size)? ms->h->get_key_size (ms): 0;
}

R_API bool r_muta_session_set_iv(RMutaSession *ms, const ut8 *iv, int ivlen) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	RMutaSessionSetIVCallback set_iv = R_UNWRAP3 (ms, h, set_iv);
	return set_iv? set_iv (ms, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
R_API bool r_muta_session_update(RMutaSession *ms, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (ms, 0);
	RMutaSessionUpdateCallback update = R_UNWRAP3 (ms, h, update);
	return update? update (ms, buf, len): 0;
}

R_API RMutaSession *r_muta_session_new(RMuta *muta, RMutaPlugin *cp) {
	R_RETURN_VAL_IF_FAIL (muta && cp, NULL);
	RMutaSession *ms = R_NEW0 (RMutaSession);
	ms->h = cp;
	ms->c = muta;
	ms->result = R_NEW0 (RMutaResult);
	return ms;
}

R_API bool r_muta_session_set_subtype(RMutaSession *ms, const char *subtype) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	free ((void *)ms->subtype);
	ms->subtype = strdup (subtype);
	return true;
}
R_API bool r_muta_session_end(RMutaSession *ms, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	return (ms->h && ms->h->end)? ms->h->end (ms, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use r_buf here
R_API int r_muta_session_append(RMutaSession *ms, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (ms && ms->result && buf, -1);
	if (ms->result->output_len + len > ms->result->output_size) {
		ms->result->output_size += 4096 + len;
		ms->result->output = realloc (ms->result->output, ms->result->output_size);
	}
	memcpy (ms->result->output + ms->result->output_len, buf, len);
	ms->result->output_len += len;
	return ms->result->output_len;
}

R_API ut8 *r_muta_session_get_output(RMutaSession *ms, int *size) {
	R_RETURN_VAL_IF_FAIL (ms && ms->result, NULL);
	if (ms->result->output_size < 1) {
		return NULL;
	}
	ut8 *buf = calloc (1, ms->result->output_size);
	if (!buf) {
		return NULL;
	}
	if (size) {
		*size = ms->result->output_len;
		memcpy (buf, ms->result->output, *size);
	} else {
		size_t newlen = 4096;
		ut8 *newbuf = realloc (buf, newlen);
		if (newbuf) {
			buf = newbuf;
			ms->result->output = newbuf;
			ms->result->output_len = 0;
			ms->result->output_size = newlen;
		} else {
			R_FREE (buf);
		}
	}
	return buf;
}

// Decode input string using the provided charset decode function
R_API ut8 *r_muta_session_decode_string(RMutaSession *ms, const ut8 *input, int len, RMutaDecodeCallback decode_fn, void *decode_ctx) {
	R_RETURN_VAL_IF_FAIL (ms && input && decode_fn, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	int pos = 0;
	while (pos < len) {
		ut8 *tmp = NULL;
		int consumed = 0;
		int olen = decode_fn (decode_ctx, input + pos, len - pos, &tmp, &consumed);
		if (olen > 0 && tmp) {
			r_strbuf_append_n (sb, (const char *)tmp, olen);
			free (tmp);
		}
		if (consumed < 1) {
			consumed = 1;
		}
		pos += consumed;
	}
	return (ut8 *)r_strbuf_drain (sb);
}
