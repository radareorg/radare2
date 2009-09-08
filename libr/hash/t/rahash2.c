#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <r_hash.h>
#include <r_util.h>

static int do_hash(const char *algo, const ut8 *buf, int len, int bsize)
{
	struct r_hash_t ctx;
	const ut8 *c;
	int i;
	ut64 algobit = r_hash_name_to_bits (algo);
	if (algobit == R_HASH_NONE) {
		fprintf(stderr, "Invalid hashing algorithm specified\n");
		return 1;
	}
	if (bsize>len)
		bsize = len;

	r_hash_state_init(&ctx, R_HASH_ALL);
	//r_hash_state_init(&ctx, algobit);
	/* TODO: Loop here for blocks */
	if (algobit & R_HASH_MD4) {
		c = r_hash_state_md4(&ctx, buf, len);
		printf("MD4: ");
		for(i=0;i<R_HASH_SIZE_MD4;i++) { printf("%02x", c[i]); }
		printf("\n");
	}
	if (algobit & R_HASH_MD5) {
		c = r_hash_state_md5(&ctx, buf, len);
		printf("MD5: ");
		for(i=0;i<R_HASH_SIZE_MD5;i++) { printf("%02x", c[i]); }
		printf("\n");
	}
	return 0;
}

static int do_help(int line)
{
	printf("Usage: rahash2 [-b bsize] [-a algo] [-s str] [file] ...\n");
	if (line) return 0;
	printf(
	" -a algo     Hashing algorithm to use (md5, crc32, ...)\n"
	" -b bsize    Specify the size of the block\n"
	" -s string   Hash this string instead of files\n");
	return 0;
}

int main(int argc, char **argv)
{
	char *algo = "md5"; /* default hashing algorithm */
	const ut8 *buf = NULL;
	int c, buf_len = 0;
	int bsize = 0;

	while ((c = getopt(argc, argv, "a:s:b:h")) != -1)
	{
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
		case 'h':
			return do_help(1);
		}
	}
	if (optind<argc)
		buf = r_file_slurp(argv[optind], &buf_len);

	if (buf == NULL) {
		do_help(0);
		return 1;
	}

	return do_hash(algo, buf, buf_len, bsize);
}
