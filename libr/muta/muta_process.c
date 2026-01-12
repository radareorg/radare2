/* radare - LGPL - Copyright 2026 - pancake */

#include <r_muta.h>

/**
 * Free RMutaResult structure and all allocated resources
 */
R_API void r_muta_result_free(RMutaResult *res) {
	if (res) {
		free (res->output);
		free (res->hex);
	}
}
// AITODO : this function takes too many paramters, will be good to have 2 versions of it one wrapper the other , because most use cases wont require the optional parameters. create the new function and update the callers accordingly
/**
 * Unified processing function for all muta operations.
 * Handles entropy, hashing, encryption/decryption in one function.
 *
 * All parameters except cry, algo, and data are optional (can be NULL/0).
 * The function automatically determines whether to use update() or end().
 * Output must be freed by caller using r_muta_result_free().
 *
 * Parameters:
 *   cry: RMuta context (required)
 *   algo: Algorithm name like "md5", "aes", "entropy" (required)
 *   data: Input data to process (required)
 *   len: Length of input data (required)
 *   key: Encryption/decryption key (optional, NULL if not needed)
 *   key_len: Length of key (ignored if key is NULL)
 *   iv: Initialization vector (optional, NULL if not needed)
 *   iv_len: Length of IV (ignored if iv is NULL)
 *   direction: R_CRYPTO_DIR_ENCRYPT, R_CRYPTO_DIR_DECRYPT, or R_CRYPTO_DIR_HASH
 *
 * Returns: RMutaResult with success flag set appropriately
 *
 * Examples:
 *   // Simple entropy
 *   RMutaResult res = r_muta_process(cry, "entropy", data, len, NULL, 0, NULL, 0, 0);
 *   if (res.success) {
 *       printf("Entropy: %f\n", res.entropy);
 *   }
 *   r_muta_result_free(&res);
 *
 *   // Hash
 *   RMutaResult res = r_muta_process(cry, "md5", data, len, NULL, 0, NULL, 0, 0);
 *   if (res.success) {
 *       // res.output contains binary hash
 *       // res.output_len contains hash length
 *   }
 *   r_muta_result_free(&res);
 *
 *   // Encryption
 *   RMutaResult res = r_muta_process(cry, "aes", plaintext, plaintext_len,
 *                                     key, keylen, iv, ivlen, R_CRYPTO_DIR_ENCRYPT);
 *   if (res.success) {
 *       // res.output contains ciphertext
 *   }
 *   r_muta_result_free(&res);
 */
R_API RMutaResult r_muta_process(RMuta *cry, const char *algo, const ut8 *data, int len,
		const ut8 *key, int key_len, const ut8 *iv, int iv_len, int direction) {
	RMutaResult res = {0};

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

	// Process data - use end() if available, otherwise update()
	if (session->h->end) {
		session->h->end (session, data, len);
	} else {
		r_muta_session_update (session, data, len);
	}

	// Collect entropy value if present
	res.entropy = session->entropy;

	// Get binary output
	res.output = r_muta_session_get_output (session, &res.output_len);
	res.success = (res.output != NULL || res.entropy != 0.0);

	r_muta_session_free (session);

	return res;
}
