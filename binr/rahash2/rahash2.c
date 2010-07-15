#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <r_hash.h>
#include <r_util.h>

static int do_hash(const char *algo, const ut8 *buf, int len, int bsize, int rad) {
	struct r_hash_t *ctx;
	const ut8 *c;
	int i, j, dlen;
	ut64 algobit = r_hash_name_to_bits (algo);

	if (algobit == R_HASH_NONE) {
		fprintf(stderr, "Invalid hashing algorithm specified\n");
		return 1;
	}
	if (bsize>len)
		bsize = len;
	ctx = r_hash_new (R_TRUE, algobit);
	/* iterate over all algorithm bits */
	for (i=1; i<0x800000; i<<=1) {
		if (algobit & i) {
			dlen = r_hash_calculate (ctx, algobit&i, buf, len);
			if (dlen) {
				c = ctx->digest;
				if (rad) {
					printf ("e file.%s=", r_hash_name(i));
					for (j=0;j<dlen;j++)
						printf ("%02x", c[j]);
					printf ("\n");
				} else {
					printf ("%s: ", r_hash_name (i));
					for(j=0;j<dlen;j++)
						printf ("%02x", c[j]);
					printf ("\n");
				}
			}
		}
	} 
	r_hash_free (ctx);
	return 0;
}

static int do_help(int line) {
	printf ("Usage: rahash2 [-rV] [-b bsize] [-a algo] [-s str] [file] ...\n");
	if (line) return 0;
	printf (
	" -a algo     comma separated list of algorithms (default is 'sha1')\n"
	" -b bsize    specify the size of the block\n"
	" -s string   hash this string instead of files\n"
	" -r          output radare commands\n"
	" -V          show version information\n"
	"Supported algorithms: md4, md5, sha1, sha256, sha384, sha512, crc16,\n"
	"    crc32, xor, xorpair, parity, mod255, hamdist, entropy, pcprint\n");
	return 0;
}

int main(int argc, char **argv) {
	char *algo = "md5,sha1"; /* default hashing algorithm */
	const ut8 *buf = NULL;
	int c, buf_len = 0;
	int bsize = 0;
	int rad = 0;
	int ret = 0;

	while ((c = getopt (argc, argv, "rVa:s:b:h")) != -1) {
		switch (c) {
		case 'r':
			rad = 1;
			break;
		case 'a':
			algo = optarg;
			break;
		case 'b':
			bsize = (int)r_num_math (NULL, optarg);
			break;
		case 's':
			buf = (const ut8*) optarg;
			buf_len = strlen (optarg);
			break;
		case 'V':
			printf ("rahash2 v"R2_VERSION"\n");
			return 0;
		case 'h':
			return do_help (0);
		}
	}
	if (optind<argc)
		buf = (const ut8*)r_file_slurp (argv[optind], &buf_len);
	if (buf == NULL)
		do_help(1);
	else ret = do_hash (algo, buf, buf_len, bsize, rad);
	return ret;
}
