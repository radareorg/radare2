/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_util.h>

ut64 num_callback(void *userptr, const char *str, int *ok)
{
	if (!strcmp(str, "foo")) {
		*ok=1;
		return 11;
	}
	*ok = 0;
	return 0;
}

int test_num(struct r_num_t *num, const char *str, ut64 okvalue)
{
	ut64 ret;
	printf("        %"PFMT64d" == ", okvalue);
 	ret = r_num_math(num, str);
	printf("%"PFMT64d"  \t; %s", ret, str);
	if (ret == okvalue) printf("\r ok\n");
	else printf("\rFAIL\n");
}

int main()
{
	struct r_num_t num;
	num.callback = &num_callback;
	num.userptr = NULL;

#if 1
	test_num(&num, "33", 33);
	test_num(&num, "0x24", 36);
	test_num(&num, "44o", 0x24);
	test_num(&num, "foo", 11);
	test_num(&num, "1+2", 3);
	test_num(&num, "3+3*2", 12);
	test_num(&num, "3+(3*2)", 9);
	test_num(&num, "(3*2)+3", 9);
	test_num(&num, "(3*2)+(3*2)", 12);
	test_num(&num, "3+(3*2+(4*2))", 17);
	test_num(&num, "8/2+(9*2)+(4*2)+(23+(43-18))", 78);
	test_num(&num, "8+(9*2)", 26);
	test_num(&num, "8/2+(9*2)", 22);
#endif
	test_num(&num, "(9*2)+(4*2)", 26);

	return 0;
}
