/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_muta.h>

R_API void r_muta_session_free(RMutaSession *R_NULLABLE cj) {
	if (cj) {
		if (cj->h->fini) {
			cj->h->fini (cj);
		}
		free (cj->output);
		free (cj->key);
		free (cj->iv);
		free (cj);
	}
}
R_API bool r_muta_session_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!cj->h || !cj->h->set_key) {
		return true;
	}
	cj->key_len = keylen;
	cj->key = calloc (1, cj->key_len);
	return cj->h->set_key (cj, key, keylen, mode, direction);
}

R_API int r_muta_session_get_key_size(RMutaSession *cj) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	return (cj->h && cj->h->get_key_size)? cj->h->get_key_size (cj): 0;
}

R_API bool r_muta_session_set_iv(RMutaSession *cj, const ut8 *iv, int ivlen) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	RMutaSessionSetIVCallback set_iv = R_UNWRAP3 (cj, h, set_iv);
	return set_iv? set_iv (cj, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
R_API bool r_muta_session_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj, 0);
	RMutaSessionUpdateCallback update = R_UNWRAP3 (cj, h, update);
	return update? update (cj, buf, len): 0;
}

R_API RMutaSession *r_muta_session_new(RMuta *cry, RMutaPlugin *cp) {
	R_RETURN_VAL_IF_FAIL (cry && cp, NULL);
	RMutaSession *cj = R_NEW0 (RMutaSession);
	cj->h = cp;
	cj->c = cry;
	return cj;
}

R_API bool r_muta_session_set_subtype(RMutaSession *cj, const char *subtype) {
	R_RETURN_VAL_IF_FAIL (cj, false);
	free ((void *)cj->subtype);
	cj->subtype = strdup (subtype);
	return true;
}
R_API bool r_muta_session_end(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	return (cj->h && cj->h->end)? cj->h->end (cj, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use r_buf here
R_API int r_muta_session_append(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, -1);
	if (cj->output_len + len > cj->output_size) {
		cj->output_size += 4096 + len;
		cj->output = realloc (cj->output, cj->output_size);
	}
	memcpy (cj->output + cj->output_len, buf, len);
	cj->output_len += len;
	return cj->output_len;
}

R_API ut8 *r_muta_session_get_output(RMutaSession *cj, int *size) {
	R_RETURN_VAL_IF_FAIL (cj, NULL);
	if (cj->output_size < 1) {
		return NULL;
	}
	ut8 *buf = calloc (1, cj->output_size);
	if (!buf) {
		return NULL;
	}
	if (size) {
		*size = cj->output_len;
		memcpy (buf, cj->output, *size);
	} else {
		size_t newlen = 4096;
		ut8 *newbuf = realloc (buf, newlen);
		if (newbuf) {
			buf = newbuf;
			cj->output = newbuf;
			cj->output_len = 0;
			cj->output_size = newlen;
		} else {
			R_FREE (buf);
		}
	}
	return buf;
}

// Decode input string using the provided charset decode function
R_API ut8 *r_muta_session_decode_string(RMutaSession *session, const ut8 *input, int len, RMutaDecodeCallback decode_fn, void *decode_ctx) {
	R_RETURN_VAL_IF_FAIL (session && input && decode_fn, NULL);
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
