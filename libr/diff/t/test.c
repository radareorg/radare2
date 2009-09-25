#include <r_diff.h>

int cb(struct r_diff_t *d, void *user, struct r_diff_op_t *op)
{
	int i;

	printf(" 0x%08llx  ", op->a_off);
	for(i = 0;i<op->a_len;i++)
		printf("%02x", op->a_buf[i]);
	printf(" => ");
	for(i = 0;i<op->b_len;i++)
		printf("%02x", op->b_buf[i]);
	printf("  0x%08llx\n", op->b_off);
	return 1;
}

int test_equal()
{
	struct r_diff_t d;
	char *bufa = "helloworld";
	char *bufb = "heprswarld";

	printf("Diffing '%s' vs '%s'\n", bufa, bufb);
	r_diff_init(&d, 0, 0);
	r_diff_set_delta(&d, 0);
	r_diff_set_callback(&d, &cb, NULL);
	r_diff_buffers(&d, (ut8*)bufa, strlen(bufa), (ut8*)bufb, strlen((char*)bufb));
	return 1;
}

int test_diff()
{
	struct r_diff_t d;
	char *bufa = "hello";
	char *bufb = "hellpworld";

	printf("Truncated diffing '%s' vs '%s'\n", bufa, bufb);
	r_diff_init(&d, 0, 0);
	r_diff_set_delta(&d, 0);
	r_diff_set_callback(&d, &cb, NULL);
	r_diff_buffers(&d, (ut8*)bufa, strlen(bufa), (ut8*)bufb, strlen(bufb));
	return 1;
}

int test_delta()
{
	struct r_diff_t d;
	char *bufa = "hello";
	char *bufb = "heprpworld";

	printf("Delta diffing '%s' vs '%s'\n", bufa, bufb);
	r_diff_init(&d, 0, 0);
	r_diff_set_delta(&d, 1);
	r_diff_set_callback(&d, &cb, NULL);
	r_diff_buffers(&d, (ut8*)bufa, strlen(bufa), (ut8*)bufb, strlen(bufb));
	return 1;
}

int test_distance()
{
	char *bufa = "hello";
	char *bufb = "heprpworld";
	ut32 distance = 0;
	double similarity = 0;

	printf("Similarity: '%s' vs '%s'\n", bufa, bufb);
	r_diff_buffers_distance(NULL, (ut8*)bufa, strlen(bufa), (ut8*)bufb, strlen(bufb),
		&distance, &similarity);
	printf("Levenshtein distance = %i\nSimilarity = %f\n",
			distance, similarity);
	return 1;
}

int test_lines(char *file1, char *file2)
{
	int ret;
	char *b1, *b2;
	int s1, s2;

	b1 = r_file_slurp(file1, &s1);
	b2 = r_file_slurp(file2, &s2);
	ret = r_diff_lines(file1, b1, s1, file2, b2, s2);
	printf("Differences: %d\n", ret);
	return ret;
}

int main()
{
	test_equal();
	printf("--\n");
	test_equal();
	printf("--\n");
	test_diff();
	printf("--\n");
	test_delta();
	printf("--\n");
	test_distance();
	printf("--\n");
	test_lines("file1", "file2");


	return 0;
}
