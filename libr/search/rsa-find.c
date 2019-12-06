// RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox
// Integrated and refactored by jvoisin and spelissier

#include <r_search.h>

/*Baby BER parser, just good enough for RSA keys.

This is not robust to errors in the memory image, but if we added
some entropy testing and intelligent guessing, it could be made to be.

Parses a single field of the key, beginning at start.  Each field
consists of a type, a length, and a value.  Puts the type of field
into type, the number of bytes into len, and returns a pointer to
the beginning of the value. */
static const ut8 *parse_next_rsa_field(const ut8 *start, ut32 *len) {
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
with the format as a RSA private key syntax
as defined in A.1.2 of RFC 3447. We check only the first 
three fields of the key */
static int check_rsa_fields(const ut8 *start) {
#define KEY_MAX_LEN 26000
	ut32 len = 0;
	// skip sequence field
	const ut8 *ptr = parse_next_rsa_field (start, &len);

	if (!len || len > KEY_MAX_LEN) {
		return false;
	}

	ptr = parse_next_rsa_field (ptr, &len);
	if (ptr[len] != 2) {
		return false;
	}
	if (!len || len > KEY_MAX_LEN) {
		return false;
	}
	ptr = ptr + len;
	ptr = parse_next_rsa_field (ptr, &len);

	if (!len || len > KEY_MAX_LEN) {
		return false;
	}

	return true;
}

// Finds and return index of private RSA key
R_API int r_search_rsa_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	unsigned int i, index;
	int k;
	const ut8 versionmarker[] = { 0x02, 0x01, 0x00, 0x02 };
	ut8 max;

	if (len < sizeof (versionmarker)) {
		return -1;
	}

	for (i = 2; i < len - sizeof (versionmarker); i++) {
		if (memcmp (&buf[i], versionmarker, sizeof (versionmarker))) {
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
			if (buf[k] == '0') { // The sequence identifier is '0'
				index = k;
				break;
			}
		}

		if (index == -1) {
			continue;
		}

		if (check_rsa_fields (buf + index)) {
			return index;
		}
	}
	return -1;
}
