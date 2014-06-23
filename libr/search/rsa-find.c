// RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox
// Integrated by jvoisin

#include <r_search.h>

#define NB_PRIVATES_FIELDS 10
#define NB_PUBLIC_FIELDS 3

/*Baby BER parser, just good enough for RSA keys.

This is not robust to errors in the memory image, but if we added
some entropy testing and intelligent guessing, it could be made to be.

Parses a single field of the key, beginning at start.  Each field
consists of a type, a length, and a value.  Puts the type of field
into type, the number of bytes into len, and returns a pointer to
the beginning of the value. */
static ut8* parse_next_rsa_field(const ut8* start, ut32 *type, ut32 *len) {
	ut8 *val = malloc(1);
	*type = start[0];
	*len  = 0;
	if (!(start[1] & 0x80)) {
		*len = start[1];
		*val = start[2];
	} else {
		int i;
		const int lensize = start[1] & 0x7F;
		for (i=0; i < lensize; i++)
			*len = (*len << 8) | start[2+i];
		*val = start[2+lensize];
	}
	return val;
}

static int check_rsa_fields(const ut8* start, int nbfields) {
	ut32 len = 0, type;
	int i;
	ut8 const* ptr = start;
	ptr = parse_next_rsa_field (ptr, &type, &len); // skip sequence field
	if (!len || len > 1024)
		return R_FALSE;
	for (i = 0; i < nbfields; i++)
		if (!(ptr = parse_next_rsa_field (ptr, &type, &len)))
			return R_FALSE;
	return R_TRUE;
}

// Returns a pointer to the beginning of a BER-encoded key by working
// backwards from the given memory map offset, looking for the
// sequence identifier (this is not completely safe)
static int find_rsa_key_start(const ut8 *map, int offset) {
	int k;
	for (k = offset; k >= 0 && k > offset-20; k--)
		if (map[k] == 0x30)
			return k;
	return 0;
}

// Finds and prints private (or private and public) keys in the memory
// map by searching for given target pattern
R_API int r_search_rsa_update(void* s, ut64 from, const ut8 *buf, int len) {
	unsigned int i, index;
	const ut8 versionmarker[4] = {0x02, 0x01, 0x00, 0x02};
	for (i = 0; i < len - sizeof (versionmarker); i++) {
		if (memcmp (&buf[i], versionmarker, sizeof (versionmarker)))
			continue;   

		index = find_rsa_key_start (buf, i);
		if (!index)
			continue;
		const ut8* key = buf + index;

		if (check_rsa_fields(key, NB_PRIVATES_FIELDS)) {
			printf("FOUND PRIVATE KEY AT %x\n", (ut32)(key-buf));
			return i;
		} else if (check_rsa_fields(key, NB_PUBLIC_FIELDS)) {
			printf("FOUND PUBLIC KEY AT %x\n", (ut32)(key-buf));
			return i;
		}
	}
	return -1;
}
