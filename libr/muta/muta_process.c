/* radare - LGPL - Copyright 2026 - pancake */

#include <r_muta.h>

R_API void r_muta_result_free(RMutaResult *res) {
	if (res) {
		free (res->output);
		free (res->hex);
	}
}

R_API RMutaResult r_muta_process_simple(RMuta *cry, const char *algo, const ut8 *data, int len) {
	return r_muta_process (cry, algo, data, len, NULL, 0, NULL, 0, 0);
}

R_API RMutaResult r_muta_process(RMuta *cry, const char *algo, const ut8 *data, int len, const ut8 *key, int key_len, const ut8 *iv, int iv_len, int direction) {
	RMutaResult res = { 0 };

	if (!cry || !algo || !data || len < 1) {
		return res;
	}

	RMutaSession *session = r_muta_use (cry, algo);
	if (!session) {
		return res;
	}

	// Set key if provided
	if (key) {
		if (!r_muta_session_set_key (session, key, key_len, 0, direction)) {
			r_muta_session_free (session);
			return res;
		}

		// Set IV if provided
		if (iv) {
			if (!r_muta_session_set_iv (session, iv, iv_len)) {
				r_muta_session_free (session);
				return res;
			}
		}
	}

	// Process data - use end () if available, otherwise update ()
	if (session->h->end) {
		session->h->end (session, data, len);
	} else {
		r_muta_session_update (session, data, len);
	}

	// Copy result from session
	if (session->result) {
		res = *session->result;
		res.success = (res.output != NULL || res.entropy != 0.0);

		// Detach result from session so it doesn't get freed
		session->result->output = NULL;
		session->result->hex = NULL;
	}

	r_muta_session_free (session);

	return res;
}
