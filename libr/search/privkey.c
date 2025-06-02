// From RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox
// Integrated and refactored by jvoisin and spelissier
// Updated by Sylvain Pelissier 2024

#include <r_search.h>
#include <r_muta/r_ed25519.h>

/* The minimal length to perform a search is the sizes of
the sequence tag, the minimal length of the sequence,
the version marker and the minimal key length. */
#define PRIVKEY_SEARCH_MIN_LENGTH (1 + 1 + 4 + 1)

#define ED25519_SEARCH_MIN_LENGTH ED25519_PRIVKEY_LENGTH

/*Baby BER parser, just good enough for private keys.

This is not robust to errors in the memory image, but if we added
some entropy testing and intelligent guessing, it could be made to be.

Parses a single field of the key, beginning at start.  Each field
consists of a type, a length, and a value.  Puts the type of field
into type, the number of bytes into len, and returns a pointer to
the beginning of the value. */
static const ut8 *parse_next_field(const ut8 *start, ut32 *len) {
	*len = 0;
	if (!(start[1] & 0x80)) {
		*len = (ut32)start[1];
		return start + 2;
	}
	int i;
	const int lensize = start[1] & 0x7f;
	for (i = 0; i < lensize; i++) {
		*len = (*len << 8) | start[2 + i];
	}
	return start + 2 + lensize;
}

/* Check if `start` points to an ensemble of BER fields
with the format as a private key syntax. We check only the first
three fields of the key */
static int check_fields(const ut8 *start) {
#define KEY_MAX_LEN 26000
	ut32 field_len = 0;
	// Sequence field
	const ut8 *ptr = parse_next_field (start, &field_len);
	if (!field_len || field_len > KEY_MAX_LEN) {
		return false;
	}

	// Version field
	ptr = parse_next_field (ptr, &field_len);
	if (field_len != 1) {
		return false;
	}
	ptr = ptr + field_len;
	ptr = parse_next_field (ptr, &field_len);

	if (!field_len || field_len > KEY_MAX_LEN) {
		return false;
	}

	return true;
}

// Finds and return index of a private key:
// As defined in RFC 3447 for RSA, as defined in RFC 5915 for
// elliptic curves and as defined in 7 of RFC 8410 for SafeCurves
R_IPI int search_asn1_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (s && buf, -1);
	int i, k, max, index, t;
	RListIter *iter;
	RSearchKeyword *kw;
	const size_t old_nhits = s->nhits;
	const ut8 rsa_versionmarker[] = { 0x02, 0x01, 0x00, 0x02 };
	const ut8 ecc_versionmarker[] = { 0x02, 0x01, 0x01, 0x04 };
	const ut8 safecurves_versionmarker[] = { 0x02, 0x01, 0x00, 0x30 };

	if (len < PRIVKEY_SEARCH_MIN_LENGTH) {
		return -1;
	}

	r_list_foreach (s->kws, iter, kw) {
		// Iteration until the remaining length is too small to contain a key.
		for (i = 2; i < len - PRIVKEY_SEARCH_MIN_LENGTH; i++) {
			if (memcmp (buf + i, rsa_versionmarker, sizeof (rsa_versionmarker)) &&
				memcmp (buf + i, ecc_versionmarker, sizeof (ecc_versionmarker)) &&
				memcmp (buf + i, safecurves_versionmarker, sizeof (safecurves_versionmarker))) {
				continue;
			}

			index = -1;
			// Going backward maximum up to 5 characters.
			if (i < 5) {
				max = i;
			} else {
				max = 5;
			}
			for (k = i - 2; k >= i - max; k--) {
				if (buf[k] == 0x30) { // The sequence identifier is 0x30
					index = k;
					break;
				}
			}

			if (index == -1) {
				continue;
			}

			if (check_fields (buf + index)) {
				parse_next_field(buf + index, &kw->keyword_length);
				t = r_search_hit_new (s, kw, from + index);
				if (t > 1) {
						return s->nhits - old_nhits;

				}
			}
		}
	}
	return -1;
}

// Finds and return index of a private key matching a given public key.
R_IPI int search_raw_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (s && buf, -1);
	int t, i;
	RSearchKeyword *kw;
	RListIter *iter;
	const size_t old_nhits = s->nhits;
	ut8 public_key[ED25519_PUBKEY_LENGTH] = { 0 };
	ut8 private_key[ED25519_PRIVKEY_LENGTH] = { 0 };
	ut8 public_key_target[ED25519_PUBKEY_LENGTH] = { 0 };

	if (len < ED25519_SEARCH_MIN_LENGTH) {
		return -1;
	}

	r_hex_str2bin ((char *)s->data, public_key_target);

	r_list_foreach (s->kws, iter, kw) {
		for (i = 0; i < len - ED25519_SEARCH_MIN_LENGTH; i++) {
			ed25519_create_keypair (buf + i, private_key, public_key);
			if (!memcmp (public_key, public_key_target, ED25519_PUBKEY_LENGTH)) {
				t = r_search_hit_new (s, kw, from + i);
				if (t > 1) {
					return s->nhits - old_nhits;
				}
			}
		}
	}
	return -1;
}
