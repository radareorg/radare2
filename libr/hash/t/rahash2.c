#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <r_hash.h>
#include <r_util.h>

static int do_hash(const char *algo, const ut8 *buf, int len, int bsize)
{
	struct r_hash_t ctx;
	const ut8 *c;
	int i, j, dlen;
	ut64 algobit = r_hash_name_to_bits (algo);
	if (algobit == R_HASH_NONE) {
		fprintf(stderr, "Invalid hashing algorithm specified\n");
		return 1;
	}
	if (bsize>len)
		bsize = len;

	//r_hash_state_init(&ctx, R_HASH_ALL);
	r_hash_init(&ctx, algobit);

	/* iterate over all algorithm bits */
	for(i=1;i<0xf00000;i<<=1) {
		if (algobit & i) {
			dlen = r_hash_calculate(&ctx, algobit&i, buf, len);
			if (dlen) {
				c = ctx.digest;
				printf("%s: ", r_hash_name(i));
				for(j=0;j<dlen;j++)
					printf("%02x", c[j]);
				printf("\n");
			}
		}
	}
	return 0;
}

static int do_help(int line)
{
	printf("Usage: rahash2 [-b bsize] [-a algo] [-s str] [file] ...\n");
	if (line) return 0;
	printf(
	" -a algo     hashing algorithm to use (md4, md5, crc32, sha1, ...)\n"
	" -b bsize    specify the size of the block\n"
	" -s string   hash this string instead of files\n"
	" -V          show version information\n");
	return 0;
}

int main(int argc, char **argv)
{
	char *algo = "md5"; /* default hashing algorithm */
	const ut8 *buf = NULL;
	int c, buf_len = 0;
	int bsize = 0;

	while ((c = getopt(argc, argv, "Va:s:b:h")) != -1) {
		switch( c ) {
		case 'a':
			algo = optarg;
			break;
		case 'b':
			bsize = (int)r_num_math(NULL, optarg);
			break;
		case 's':
			buf = (ut8*) optarg;
			buf_len = strlen(optarg);
			break;
		case 'V':
			printf("rahash2 v"VERSION"\n");
			return 0;
		case 'h':
			return do_help(1);
		}
	}
	if (optind<argc)
		buf = (const ut8*)r_file_slurp(argv[optind], &buf_len);

	if (buf == NULL) {
		do_help(0);
		return 1;
	}

	return do_hash(algo, buf, buf_len, bsize);
}
