// From RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox
// Integrated and refactored by jvoisin and spelissier

#include <r_search.h>

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
	} else {
		int i;
		const int lensize = start[1] & 0x7f;
		for (i = 0; i < lensize; i++) {
			*len = (*len << 8) | start[2 + i];
		}
		return start + 2 + lensize;
	}
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
R_API int r_search_privkey_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	int i, k, max, index;
	const ut8 rsa_versionmarker[] = { 0x02, 0x01, 0x00, 0x02 };
	const ut8 ecc_versionmarker[] = { 0x02, 0x01, 0x01, 0x04 };
	const ut8 safecurves_versionmarker[] = { 0x02, 0x01, 0x00, 0x30 };

	if (len < sizeof (rsa_versionmarker)) {
		return -1;
	}

	for (i = 2; i < len - sizeof (rsa_versionmarker); i++) {
		if (memcmp (&buf[i], rsa_versionmarker, sizeof (rsa_versionmarker)) && 
		memcmp (&buf[i], ecc_versionmarker, sizeof (ecc_versionmarker)) &&
		memcmp (&buf[i], safecurves_versionmarker, sizeof (safecurves_versionmarker))) {
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
			return index;
		}
	}
	return -1;
}
