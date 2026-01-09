/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_muta.h>

static ut8 *_hash_hmac(RMutaBind *mb, const char *algo, const ut8 *buf, int buflen, const ut8 *key, int keylen, int *outlen) {
	R_RETURN_VAL_IF_FAIL (mb && mb->muta && algo && buf && key && outlen, NULL);
	if (keylen <= 0 || buflen <= 0) {
		return NULL;
	}
	RMutaSession *hmac = mb->muta_use (mb->muta, algo);
	if (!hmac) {
		return NULL;
	}
	if (!mb->muta_session_set_key (hmac, key, keylen, 0, 0)) {
		mb->muta_session_free (hmac);
		return NULL;
	}
	if (mb->muta_session_end (hmac, buf, buflen) == 0) {
		mb->muta_session_free (hmac);
		return NULL;
	}
	ut8 *digest = mb->muta_session_get_output (hmac, outlen);
	mb->muta_session_free (hmac);
	return digest;
}

static ut8 *_hash(RMutaBind *mb, const char *algo, const ut8 *buf, int buflen, int *outlen) {
	R_RETURN_VAL_IF_FAIL (mb && mb->muta && algo && buf && outlen, NULL);
	if (buflen <= 0) {
		return NULL;
	}
	RMutaSession *hash = mb->muta_use (mb->muta, algo);
	if (!hash) {
		return NULL;
	}
	if (mb->muta_session_end (hash, buf, buflen) == 0) {
		mb->muta_session_free (hash);
		return NULL;
	}
	ut8 *digest = mb->muta_session_get_output (hash, outlen);
	mb->muta_session_free (hash);
	return digest;
}

static bool _text_output(RMutaBind *mb, const char *algo) {
	R_RETURN_VAL_IF_FAIL (mb && mb->muta && algo, false);
	RMutaPlugin *p = r_muta_find (mb->muta, algo);
	return p ? p->text_output : false;
}

R_API void r_muta_bind(RMuta *muta, RMutaBind *bnd) {
	R_RETURN_IF_FAIL (muta && bnd);
	bnd->muta = muta;
	bnd->muta_use = (RMutaUse)r_muta_use;
	bnd->muta_session_set_key = (RMutaSessionSetKey)r_muta_session_set_key;
	bnd->muta_session_set_iv = (RMutaSessionSetIV)r_muta_session_set_iv;
	bnd->muta_session_end = (RMutaSessionEnd)r_muta_session_end;
	bnd->muta_session_get_output = (RMutaSessionGetOutput)r_muta_session_get_output;
	bnd->muta_session_free = (RMutaSessionFree)r_muta_session_free;
	bnd->hash_hmac = _hash_hmac;
	bnd->hash = _hash;
	bnd->text_output = _text_output;
}
