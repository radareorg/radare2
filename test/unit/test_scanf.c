#include <r_util.h>
#include "minunit.h"

bool test_r_str_scanf(void) {
	char what[3] = {0};
	char who[8] = {0};
	int res = r_str_scanf ("Hello World", "%.s %.s", sizeof (what), what, sizeof (who), who);
	mu_assert_streq (what, "He", "truncated string in custom scanf failed");
	mu_assert_streq (who, "World", "truncated string in custom scanf failed");
	mu_assert_eq (res, 2, "return value for scanf failed");

	strcpy (what, "tr");
	strcpy (who, "trash");
	res = r_str_scanf ("Hello World", "%s %s", what, who);
	mu_assert_streq (what, "", "string scanf fails if no length provided");
	mu_assert_streq (who, "", "string scanf fails if no length given");
	mu_assert_eq (res, 0, "return value for scanf failed");

	ut64 bignum = 0;
	res = r_str_scanf ("0x120000023b2d8000", "0x%Lx", &bignum);
	mu_assert_eq (0x120000023b2d8000, bignum, "portable ut64 scanf failed");
	mu_assert_eq (res, 1, "return value for scanf failed");

#if 0
	// XXX the 0x%08Lx syntax is not supported by r_str_scanf, but it does for libc's scanf .. uncomment this test when implemented
	bignum = 0;
	res = r_str_scanf ("0x000000023b2d8000", "0x%08Lx", &bignum);
	mu_assert_eq (0x23b2d8000, bignum, "portable ut64 scanf failed");
	mu_assert_eq (res, 1, "return value for scanf failed");
#endif

	mu_end;
}

bool test_r_str_scanf_pointer(void) {
	size_t a;
	void *b;
	char *s = r_str_newf ("%p %p\n", &test_r_str_scanf, &test_r_str_scanf_pointer);
	int res = r_str_scanf (s, "%p %p", &a, &b);
	free (s);
	mu_assert_eq (a, &test_r_str_scanf, "sizet pointer comparison");
	mu_assert_eq (b, &test_r_str_scanf_pointer, "second sizet pointer comparison");
	mu_assert_eq (res, 2, "return value for scanf failed");

	mu_end;
}

bool test_r_str_scanf_scanset(void) {
	char msg0[32];
	char msg1[32];
	char *s = r_str_newf ("Hello World ITS OVER\nAGAIN");
	int res = r_str_scanf (s, "%.s %*s %.[^\n]", sizeof (msg0), &msg0, sizeof (msg1), &msg1);
	free (s);
	mu_assert_streq (msg0, "Hello", "first word");
	mu_assert_streq (msg1, "ITS OVER", "the rest until newline");
	mu_assert_eq (res, 2, "return value for scanf failed");

	const char ptr[] = "map0 map1 8048 tmp0 tmp1 thename\n";
	char name[32];
	char perms[32];
	char region1[32];
	ut64 offset;
	strcpy (region1, "0x");
	res = r_str_scanf (ptr, "%.s %.s %Lx %*s %*s %.[^\n]",
			sizeof (region1) - 2, region1 + 2,
			sizeof (perms), perms,
			&offset,
			sizeof (name), name);
	mu_assert_streq (name, "thename", "name fails");
	mu_assert_streq (perms, "map1", "2nd arg");
	mu_assert_streq (region1, "0xmap0", "1st arg");
	mu_assert_eq (offset, 0x8048, "return value for scanf failed");
	mu_assert_eq (res, 4, "return value for scanf failed");

	mu_end;
}

bool test_r_str_scanf_other(void) {
	short half;
	int res = r_str_scanf ("fa82", "%hx", &half);
	mu_assert_eq (half, -1406, "half check");
	mu_assert_eq (res, 1, "return value for scanf failed");
	res = sscanf ("fa82", "%hx", &half);
	mu_assert_eq (half, -1406, "half check");
	mu_assert_eq (res, 1, "return value for scanf failed");
	res = r_str_scanf ("1234", "%hx", &half);
	mu_assert_eq (half, 0x1234, "half check");
	mu_assert_eq (res, 1, "return value for scanf failed");
	mu_end;
}

bool test_r_str_scanf_procstat(void) {
	char no_str[128];
	unsigned long no_lui;
	long int no_li;
	int no_num;
	int p_nice;
	int p_num_threads;
	unsigned int p_flag;
	int p_sid;
	int p_s_name;
	int p_pid;
	int p_ppid;
	int p_pgrp;
	const char *fmt = "%d %.s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %d %d";
	const char *buff = "70735 (apache2) S 1833 1833 1833 0 -1 4194624 223 0 0 0 0 0 0 0 20 0 1 0 13243950 225329152 72 18446744073709551615 1 1 0 0 0 0 0 16781314 134235881 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
	int ret = r_str_scanf (buff, fmt, &p_pid,
			sizeof (no_str), no_str,
			&p_s_name, &p_ppid, &p_pgrp, &no_num, &no_num,
			&p_sid, &p_flag, &no_lui, &no_lui, &no_lui,
			&no_lui, &no_lui, &no_lui, &no_li, &no_li,
			&no_li, &p_nice, &p_num_threads);
	mu_assert_eq (ret, 20, "return value for scanf failed");
	mu_assert_streq (no_str, "(apache2)", "process name");

	const char *fmt2 = "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %d %d";
	int res = sscanf (buff, fmt2, &p_pid, no_str,
			&p_s_name, &p_ppid, &p_pgrp, &no_num, &no_num,
			&p_sid, &p_flag, &no_lui, &no_lui, &no_lui,
			&no_lui, &no_lui, &no_lui, &no_li, &no_li,
			&no_li, &p_nice, &p_num_threads);
	mu_assert_eq (res, 20, "return value for scanf failed");
	mu_assert_streq (no_str, "(apache2)", "process name");

	mu_end;
}

bool test_r_str_scanf_iomaps(void) {
	ut64 addr0, addr1;
	char perm[8];
	char name[32];
	const char fmt[] = "0x%Lx - 0x%Lx %.s %.s";
	const char str[] = "0x8048000 - 0x9284955085 r-x hello";
	int res = r_str_scanf (str, fmt, &addr0, &addr1, sizeof (perm), perm, sizeof (name), name);
	mu_assert_eq (res, 4, "return value for scanf failed");
	mu_assert_eq (addr0, 0x8048000, "addr0 fail");
	mu_assert_eq (addr1, 0x9284955085, "addr1 fail");
	mu_assert_streq (perm, "r-x", "perm fail");
	mu_assert_streq (name, "hello", "name fail");

	const char fmt2[] = "0x%"PFMT64x" - 0x%"PFMT64x" %s %s";
	res = sscanf (str, fmt2, &addr0, &addr1, perm, name);
	mu_assert_eq (res, 4, "return value for scanf failed");
	mu_assert_eq (addr0, 0x8048000, "addr0 fail");
	mu_assert_eq (addr1, 0x9284955085, "addr1 fail");
	mu_assert_streq (perm, "r-x", "perm fail");
	mu_assert_streq (name, "hello", "name fail");

	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_str_scanf);
	mu_run_test (test_r_str_scanf_pointer);
	mu_run_test (test_r_str_scanf_scanset);
	mu_run_test (test_r_str_scanf_other);
	mu_run_test (test_r_str_scanf_procstat);
	mu_run_test (test_r_str_scanf_iomaps);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
