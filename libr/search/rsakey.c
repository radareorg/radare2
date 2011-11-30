// RSAKeyFinder 1.0 (2008-07-18)
// By Nadia Heninger and J. Alex Halderman
// Contribution to r2 by @santitox

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <err.h>

#include <r_search.h>

// XXX perror and exit are not portable
#ifdef __FreeBSD__
#include <err.h>
#else
#define err(x,y) { perror(y); exit(x); }
#endif


// Baby BER parser, just good enough for RSA keys.
//
// This is not robust to errors in the memory image, but if we added
// some entropy testing and intelligent guessing, it could be made to be.
//
// Parses a single field of the key, beginning at start.  Each field
// consists of a type, a length, and a value.  Puts the type of field
// into type, the number of bytes into len, and returns a pointer to
// the beginning of the value.
ut8* r_parse_next(ut8* start, ut32 *type, ut32 *len) {
	ut8 *val = NULL;
	*type = start[0]; 
	*len  = 0;
	if ((start[1] & 0x80) == 0) {
		*len = start[1];
		*val = start[2];
	} else {
		int i;
		int lensize = start[1] & 0x7F;
		for (i=0; i < lensize; i++)
			*len = (*len << 8) | start[2+i];    
		*val = start[2+lensize];
	}
	return val;
}

// Sets output to a string displaying len bytes from buffer
void r_output_bytes(ut8* buffer, int len, char* output) {
	char *output_aux;
	int i,j;
	for (i=0; i<len; i++) {
		char tmp[4];
		snprintf(tmp, sizeof(tmp), "%02x ",buffer[i]);
		for (j=0;j<4;j++)
			*output++ = tmp[j];
		if ((i < len-1) && i % 16 == 15) *output++ = '\n';
	}
	*output = '\n';
	output = output_aux;
}

// Field names in private and public keys
char *private_fields[10] = {"version", "modulus", "publicExponent",
	"privateExponent","prime1","prime2",
	"exponent1", "exponent2","coefficient", ""};
char *public_fields[3] = {"modulus", "publicExponent", ""};

// Sets output to a string listing the fields from a BER-encoded
// record, beginning at start, with the fields named according to the
// array of strings (returns true iff a valid encoding was found)
boolt r_print_fields(ut8* start, char *fields[], char *output) {
	ut32 len=0, type;
	int i;
	output = NULL;
	start = r_parse_next (start,&type,&len); // skip sequence field
	for (i = 0; fields[i] != ""; i++) {
		start = r_parse_next (start,&type,&len);
		if (start == NULL || len == 0 || len > 1000)
			return R_FALSE;
		//XXX: spagueti?
		// XXX asprintf is not portable
		asprintf(&output, "%s = \n", fields[i]);
		r_output_bytes (start,len,output);
		start += len;
	}

	return R_TRUE;
}

// Returns a pointer to the beginning of a BER-encoded key by working
// backwards from the given memory map offset, looking for the
// sequence identifier (this is not completely safe)
ut8 *r_find_key_start(ut8 *map, int offset) {
	int k;
	for (k = offset; k >= 0 && k > offset-20; k--)
		if (map[k] == 0x30)
			return &map[k];
	return NULL;
}

// Finds and prints private (or private and public) keys in the memory
// map by searching for given target pattern
void r_find_keys(ut8 *image, int isize, ut8 *target, int target_size, boolt find_public) {
	int i;
	for (i = 0; i < isize - target_size; i++) {
		if (memcmp(&image[i], target, target_size))
			continue;   

		ut8 *key = r_find_key_start(image, i);
		if (!key)
			continue;

		char *output;
		if (r_print_fields(key,private_fields,output)) {
			printf("FOUND PRIVATE KEY AT %x\n", (ut32)(key-image));
			printf("%s\n",output);
		}  else if (find_public &&
				r_print_fields(key,public_fields,output)) {
			printf("FOUND PUBLIC KEY AT %x\n", (ut32)(key-image));
			printf("%s\n",output);
		}
	}
}

// Memory maps filename and return a pointer on success, setting len
// to the length of the file (does not return on error)
ut8 *r_map_file(char *filename, ut32 *len) {
	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		errx(1, "image open failed");

	struct stat st;
	if (fstat(fd, &st) != 0)
		errx(1, "image fstat failed");

	ut8 *map;
	map = (ut8*)mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		errx(1, "image mmap failed");

	*len = st.st_size;
	return map;
}

// Returns a decoded byte from a file of hex values, ignoring whitespace
int r_get_hex_byte(int fd) {
	for (;;) {
		char a[3];
		if (read(fd, &a[0], 1) < 1)
			break;
		if ((a[0] >= '0' && a[0] <= '9') || (a[0] >= 'a' && a[0] <= 'f')) {
			if (read(fd, &a[1], 1) < 1)
				break;
			a[2] = '\0';
			return strtol(a,NULL,16);
		}
	}
	return -1;
}

// Reads hexadecimal bytes from filename and returns a byte array
// containing these values, setting len to the number of bytes (does not
// return on error)
ut8 *r_read_modulus(char *filename, ut32 *len) {
	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		err(1, "modulus open failed");

	struct stat st;
	if (fstat(fd, &st) != 0)
		err(1, "modulus fstat failed");

	ut8 *modulus = (ut8 *)malloc(st.st_size);
	for (*len=0; ;*len++) {
		int c = r_get_hex_byte(fd);
		if (c == -1)
			break;
		modulus[*len] = c;
	}

	close(fd);
	return modulus;
}

void r_usage() {
	fprintf(stderr, "USAGE: rsakeyfind MEMORY-IMAGE [MODULUS-FILE]\n"
			"Locates BER-encoded RSA private keys in MEMORY-IMAGE.\n"
			"If MODULUS-FILE is specified, it will locate private and public keys"
			"matching the hex-encoded modulus read from this file.\n");
}

#if TEST
int main(int argc, char *argv[]) {
	ut32 ilen;
	ut8 *image;
	if (argc < 2 || argc > 3) {
		r_usage();
		exit(1);
	}
	image = r_map_file(argv[1], &ilen); 
	if (argc == 3) {
		// method 1: searching for modulus
		ut32 mlen;
		ut8 *modulus = r_read_modulus(argv[2], &mlen);
		r_find_keys(image, ilen, modulus, mlen, R_TRUE);
	} else {
		// method 2: searching for versionmarker
		ut8 versionmarker[4] = {0x02, 0x01, 0x00, 0x02};
		r_find_keys(image, ilen, versionmarker, sizeof(versionmarker), R_FALSE);
	}
	return 0;
}
#endif
