#include <stdio.h>
#include "r_util.h"


void check(const char *exp, const char *act, const char *desc) {
	if (strcmp(exp, act) == 0)
		printf("\x1b[34m[+][%s]\x1b[39;49m test passed\n", desc);
	else
		printf("\x1b[31m[-][%s]\x1b[39;49m test failed (actual = %s\x1b[39;49m, expected = %s\x1b[39;49m)\n", desc, act, exp);
}

void check_n(const char *exp, const char *act, int len, const char *desc) {
	if (strncmp(exp, act, len) == 0)
		printf("\x1b[34m[+][%s]\x1b[39;49m test passed\n", desc);
	else
		printf("\x1b[31m[-][%s]\x1b[39;49m test failed (actual = %s\x1b[39;49m, expected = %s\x1b[39;49m)\n", desc, act, exp);
}

void check_int(int exp, int act, const char *desc) {
	if (exp == act)
		printf("\x1b[34m[+][%s]\x1b[39;49m test passed\n", desc);
	else
		printf("\x1b[31m[-][%s]\x1b[39;49m test failed (actual = %d\x1b[39;49m, expected = %d\x1b[39;49m)\n", desc, act, exp);
}

void check_array(int *exp, int *act, int len, const char *desc) {
	int i, err_found = 0;
	for (i = 0; i < len; ++i) {
		if (exp[i] != act[i]) {
			printf("\x1b[31m[-][%s]\x1b[39;49m test failed element %d (actual = %d\x1b[39;49m, expected = %d\x1b[39;49m)\n", desc, i, act[i], exp[i]);
			err_found = 1;
		}
	}
	if (!err_found)
		printf("\x1b[34m[+][%s]\x1b[39;49m test passed\n", desc);
	else
		printf("\x1b[31m[-][%s]\x1b[39;49m test failed\n", desc);
}

int main(int argc, char *argv[]) {
	char head[] = " a";
	char tail[] = "a ";
	char head_tail[] = " a ";

	check ("a", r_str_trim_head(head), "trim head \" a\"");
	check ("a", r_str_trim_tail(tail), "trim tail \"a \"");
	check ("a", r_str_trim_head_tail(head_tail), "trim head tail \" a \"");

	char *crop =
		"This is the first line\n"
		"This is the second\n"
		"\n"
		"And this is the last\n";
	char *crop_exp =
		"is is the se\n"
		"\n"
		"d this is th\n";
	check (crop_exp, r_str_crop(crop, 2, 1, 14, 10), "crop text");
	check ("", r_str_crop(NULL, 2, 1, 14, 10), "crop NULL");

	char dst[256];
	char src[] = "This is my text";
	r_str_ncpy(dst, src, 4);
	check ("This", dst, "r_str_ncpy");
	dst[0] = '\0';
	r_str_ncpy(dst, src, 100);
	check ("This is my text", dst, "r_str_ncpy (n > src length)");

	strcpy(dst, "This is a $hell < fin.txt");
	r_str_sanitize(dst);
	check("This is a _hell _ fin.txt", dst, "r_str_sanitize");

	strcpy(dst, "\x1b[30mHel\x1b[28mlo");
	check("lo", r_str_ansi_chrn(dst, 4), "r_str_ansi_chrn");

	check_int(5, r_str_ansi_len(dst), "r_str_ansi_len 1");
	strcpy(dst, "Hello");
	check_int(5, r_str_ansi_len(dst), "r_str_ansi_len 2");
	strcpy(dst, "\x1b[30m");
	check_int(0, r_str_ansi_len(dst), "r_str_ansi_len 3");

	strcpy(dst, "Hello");
	check_int(5, r_str_ansi_chop(dst, -1, 5), "r_str_ansi_chop (normal string)");
	check("Hello", dst, "r_str_ansi_chop (normal string)(str)");
	strcpy(dst, "Hello");
	check_int(2, r_str_ansi_chop(dst, -1, 2), "r_str_ansi_chop 2 (normal string)");
	check("He", dst, "r_str_ansi_chop 2 (normal string)(str)");
	strcpy(dst, "Hello");
	check_int(0, r_str_ansi_chop(dst, -1, 0), "r_str_ansi_chop 3 (normal string)");
	check("", dst, "r_str_ansi_chop 3 (normal string)(str)");

	strcpy(dst, "\x1b[30mHel\x1b[29mlo");
	check_int(0, r_str_ansi_chop(dst, -1, 0), "r_str_ansi_chop 1");
	check("", dst, "r_str_ansi_chop 1 (str)");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo");
	check_int(7, r_str_ansi_chop(dst, -1, 2), "r_str_ansi_chop 2");
	check("\x1b[30mHe", dst, "r_str_ansi_chop 2 (str)");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo");
	check_int(8, r_str_ansi_chop(dst, -1, 3), "r_str_ansi_chop 3");
	check("\x1b[30mHel", dst, "r_str_ansi_chop 3 (str)");

	char *orig;
	int *cpos;
	strcpy(dst, "Hello");
	check_int(5, r_str_ansi_filter(dst, NULL, NULL, -1), "r_str_ansi_filter (normal string)");
	check("Hello", dst, "r_str_ansi_filter (normal string(str)");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo\x1b[28m");
	check_int(5, r_str_ansi_filter(dst, NULL, NULL, -1), "r_str_ansi_filter");
	check("Hello", dst, "r_str_ansi_filter (str)");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo\x1b[28m");
	check_int(3, r_str_ansi_filter(dst, NULL, NULL, 8), "r_str_ansi_filter (length)");
	check_n("Hel", dst, 3, "r_str_ansi_filter (length)(str)");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo\x1b[28m");
	r_str_ansi_filter(dst, &orig, NULL, -1);
	check("\x1b[30mHel\x1b[29mlo\x1b[28m", orig, "r_str_ansi_filter out orig");
	strcpy(dst, "\x1b[30mHel\x1b[29mlo\x1b[28m");
	int res = r_str_ansi_filter(dst, NULL, &cpos, -1);
	check_int(5, res, "r_str_ansi_filter res");
	int exp_cpos[] = {5, 6, 7, 13, 14};
	check_array(exp_cpos, cpos, res, "r_str_ansi_filter cpos");

	char clean[256];
	char *str = malloc(256);
	strcpy(str, "\x1b[30mHell\x1b[32mo\nIt'\x1b[33ms a test\n");
	strcpy(clean, "Hello\nIt's a test\n");
	int thunk[] = {5, 6, 7, 8, 14, 15, 16, 17, 18, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	char *res_s = r_str_replace_thunked (str, clean, thunk, 18, "est", "\x1b[31mest\x1b[39;49m", 1);
	check("\x1b[30mHell\x1b[32mo\nIt'\x1b[33ms a t\x1b[31mest\x1b[39;49m\n", res_s, "r_str_replace_thunked");

	int l;
	strcpy(str, "\x1b[30mHell\x1b[32mo\nIt'\x1b[33ms an hell\n");
	l = r_str_ansi_filter (str, &orig, &cpos, 0);
	res_s = r_str_replace_thunked(orig, str, cpos, l, "ell", "\x1b[31mell\x1b[39;49m", 1);
	check("\x1b[30mH\x1b[31mell\x1b[39;49mo\nIt'\x1b[33ms an h\x1b[31mell\x1b[39;49m\n", res_s, "r_str_ansi_filter + replace_thunked");

	crop =
		"\x1b[30mThis is the \x1b[34mfirst line\n"
		"\x1b[32mThis \x1b[31mis the\x1b[39;49m second\n"
		"\n"
		"And this is the \x1b[32mlast\n";
	crop_exp =
		"\x1b[30m\x1b[34m\x1b[32mis \x1b[31mis the\x1b[39;49m se\n"
		"\n"
		"d this is th\n";
	check(crop_exp, r_str_ansi_crop(crop, 2, 1, 14, 10), "r_str_ansi_crop");

	return 0;
}
