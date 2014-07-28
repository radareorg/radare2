// RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox
// Integrated and refactored by jvoisin

#include <r_search.h>

/*Baby BER parser, just good enough for RSA keys.

This is not robust to errors in the memory image, but if we added
some entropy testing and intelligent guessing, it could be made to be.

Parses a single field of the key, beginning at start.  Each field
consists of a type, a length, and a value.  Puts the type of field
into type, the number of bytes into len, and returns a pointer to
the beginning of the value. */
static const ut8* parse_next_rsa_field(const ut8* start, ut32 *len) {
	*len = 0;
	if (!(start[1] & 128)) {
		len = (ut32*)(start + 1);
		return start + 2;
	} else {
		int i;
		const int lensize = start[1] & 127;
		for (i=0; i < lensize; i++)
			*len = (*len << 8) | start[2+i];
		return start + 2 + lensize;
	}
}

// Check if `start` points to an ensemble of BER fields
static int check_rsa_fields(const ut8* start) {
#define NB_PRIV_FIELDS 10
	ut32 len = 0;
	int i;
	ut8 const* ptr = start;

	ptr = parse_next_rsa_field (start, &len); // skip sequence field

	if (!len || len > 1024)
		return R_FALSE;

	for (i = 0; i < NB_PRIV_FIELDS; i++)
		if (!(ptr = parse_next_rsa_field (ptr, &len)))
			return R_FALSE;

	return R_TRUE;
}

// Finds and return index of private RSA key
R_API int r_search_rsa_update(void* s, ut64 from, const ut8 *buf, int len) {
	unsigned int i, k, index;
	const ut8 versionmarker[] = {0x02, 0x01, 0x00, 0x02};

	for (i = 0; i < len - sizeof (versionmarker); i++) {
		if (memcmp (&buf[i], versionmarker, sizeof (versionmarker)))
			continue;   

		index = 0;
		for (k=i; k != 0 && k > i - 20; k--) {
			if (buf[k] == '0'){ // The sequence identifier is '0'
				index = k;
				break;
			}
		}

		if (!index)
			continue;

		if (check_rsa_fields(buf + index))
			return i;
	}
	return -1;
}
