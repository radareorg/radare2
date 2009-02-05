#include <r_diff.h>

static int count = 0;

static int cb(struct r_diff_t *d, void *user,
	struct r_diff_op_t *op)
{
	int i;

	if (count) {
		count++;
		return 1;
	}
	printf("0x%08llx ", op->a_off);
	for(i = 0;i<op->a_len;i++)
		printf("%02x", op->a_buf[i]);
	printf(" => ");
	for(i = 0;i<op->b_len;i++)
		printf("%02x", op->b_buf[i]);
	printf(" 0x%08llx\n", op->b_off);
	return 1;
}

static int show_help(int line)
{
	printf("Usage: radiff2 [-nd] [file] [file]\n");
	if (!line) printf(
		"  -c   :  count of changes\n"
		"  -d   :  use delta diffing\n");
	return 1;
}

int main(int argc, char **argv)
{
	struct r_diff_t d;
	int c, delta = 0;
	char *file, *file2;
	u8 *bufa, *bufb;
	u32 sza, szb;

	if (argc<3)
		return show_help(0);

	while ((c = getopt(argc, argv, "cd")) != -1) {
		switch(c) {
		case 'c':
			count = 1;
			break;
		case 'd':
			delta = 1;
			break;
		default:
			return show_help(1);
		}
	}
	
	if (optind+2<argc)
		return show_help(0);

	file = argv[optind];
	file2 = argv[optind+1];

	bufa = r_file_slurp(file, &sza);
	bufb = r_file_slurp(file2, &szb);
	if (bufa == NULL || bufb == NULL) {
		fprintf(stderr, "Error slurping source files\n");
		return 1;
	}

	r_diff_init(&d, 0LL, 0LL);
	r_diff_set_delta(&d, delta);
	r_diff_set_callback(&d, &cb, NULL);
	r_diff_buffers(&d, bufa, sza, bufb, szb);

	if (count)
		printf("%d\n", count-1);

	return 0;
}
