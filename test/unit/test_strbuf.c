#include <r_util.h>
#include "minunit.h"

bool test_r_strbuf_slice(void) {
	RStrBuf *sa = r_strbuf_new ("foo,bar,cow");
	r_strbuf_slice (sa, 2, 4); // should be from/to instead of from/len ?
	char *a = r_strbuf_drain (sa);
	mu_assert_streq (a, "o,ba", "slicing fails");
	free (a);

	mu_end;
}

bool test_r_strbuf_append(void) {
	RStrBuf *sa = r_strbuf_new ("foo");
	r_strbuf_append (sa, "bar");
	r_strbuf_prepend (sa, "pre");
	char *a = r_strbuf_drain (sa);
	mu_assert_streq (a, "prefoobar", "append+prepend");
	free (a);

	mu_end;
}

bool test_r_strbuf_strong_string(void) {
	// small string
	RStrBuf *sa = r_strbuf_new ("");
	r_strbuf_set (sa, "food");
	mu_assert_eq (r_strbuf_length (sa), 4, "r_strbuf_set:food");
	mu_assert_eq (sa->len, 4, "len of string");
	// ptrlen not used here
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_set (sa, "food");
	char *drained = r_strbuf_drain (sa);
	mu_assert_streq (drained, "food", "drained string");
	free (drained);

	// long string
	sa = r_strbuf_new ("");
	r_strbuf_set (sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	mu_assert_eq (r_strbuf_length (sa), 46, "length from api");
	mu_assert_eq (sa->len, 46, "len of string");
	mu_assert_eq (sa->ptrlen, 47, "ptrlen of string");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_set (sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	drained = r_strbuf_drain (sa);
	mu_assert_streq (drained, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", "drained string");
	free (drained);

	mu_end;
}

bool test_r_strbuf_strong_binary(void) {
	RStrBuf *sa = r_strbuf_new ("");
	bool res = r_strbuf_setbin (sa, (const ut8 *)"food", 4);
	mu_assert ("setbin success", res);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), (const ut8 *)"food", 4, "small binary data");
	mu_assert_eq (sa->len, 4, "len of binary data");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setbin (sa, (const ut8 *)"food", 4);
	char *drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"food", 4, "drained binary data");
	free (drained);

	sa = r_strbuf_new ("");
	res = r_strbuf_setbin (sa, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	mu_assert ("setbin success", res);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "big binary data");
	mu_assert_eq (sa->len, 46, "len of binary data");
	mu_assert_eq (sa->ptrlen, 47, "ptrlen of binary data");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setbin (sa, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained binary data");
	free (drained);

	mu_end;
}

bool test_r_strbuf_weak_string(void) {
	// small string
	char *myptr = "food";
	RStrBuf *sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, -1);
	mu_assert_eq (r_strbuf_length (sa), 4, "length from api");
	mu_assert_eq (sa->len, 4, "len of string");
	mu_assert_eq (sa->ptrlen, 5, "len of string + 0");
	mu_assert_ptreq (r_strbuf_get (sa), myptr, "weak ptr");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, -1);
	char *drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"food", 4, "drained weak string");
	free (drained);

	// long string
	myptr = "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER";
	sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, -1);
	mu_assert_eq (r_strbuf_length (sa), 46, "length from api");
	mu_assert_eq (sa->len, 46, "len of string");
	mu_assert_eq (sa->ptrlen, 47, "len of string + 0");
	mu_assert_ptreq (r_strbuf_get (sa), myptr, "weak ptr");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, -1);
	drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained weak string");
	free (drained);

	mu_end;
}

bool test_r_strbuf_weak_binary(void) {
	char *myptr = "food";
	RStrBuf *sa = r_strbuf_new ("");
	bool res = r_strbuf_setptr (sa, myptr, 4);
	mu_assert ("setbin success", res);
	mu_assert_ptreq (r_strbuf_get (sa), myptr, "weak ptr");
	mu_assert_eq (sa->len, 4, "len of binary data");
	mu_assert_eq (sa->ptrlen, 4, "ptrlen of binary data");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, 4);
	char *drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"food", 4, "drained binary data");
	free (drained);

	myptr = "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER";
	sa = r_strbuf_new ("");
	res = r_strbuf_setptr (sa, myptr, 46);
	mu_assert ("setbin success", res);
	mu_assert_ptreq (r_strbuf_get (sa), myptr, "weak ptr");
	mu_assert_eq (sa->len, 46, "len of binary data");
	mu_assert_eq (sa->ptrlen, 46, "ptrlen of binary data");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	r_strbuf_setptr (sa, myptr, 46);
	drained = r_strbuf_drain (sa);
	mu_assert_memeq ((const ut8 *)drained, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "drained binary data");
	free (drained);

	mu_end;
}

bool test_r_strbuf_setbin(void) {
	RStrBuf *sa = r_strbuf_new ("");
	r_strbuf_setbin (sa, (const ut8 *)"inbuffffffff", 5);
	mu_assert_streq (r_strbuf_get (sa), "inbuf", "setbin str with size");
	mu_assert_eq (r_strbuf_length (sa), 5, "len from api");

	ut8 *buf = malloc(46); // alloc this on the heap to help valgrind and asan detect overflows
	memcpy (buf, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	r_strbuf_setbin (sa, buf, 46);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), buf, 46, "long binary");
	free (buf);
	mu_assert_eq (r_strbuf_get (sa)[46], 0, "still null terminated");
	mu_assert_eq (r_strbuf_length (sa), 46, "len from api");
	mu_assert_eq (sa->ptrlen, 46 + 1, "ptrlen");

	// reallocation
	buf = malloc (46 * 2);
	memcpy (buf, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFERVERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46 * 2);
	r_strbuf_setbin (sa, buf, 46 * 2);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), buf, 46 * 2, "long binary");
	free (buf);
	mu_assert_eq (r_strbuf_get (sa)[46 * 2], 0, "still null terminated");
	mu_assert_eq (r_strbuf_length (sa), 46 * 2, "len from api");
	mu_assert_eq (sa->ptrlen, 46 * 2 + 1, "ptrlen");

	r_strbuf_free (sa);
	mu_end;
}

bool test_r_strbuf_set(void) {
	RStrBuf sb;
	r_strbuf_init (&sb);
	const char *s = r_strbuf_set (&sb, "I have packed only the essentials");
	mu_assert_notnull (s, "set return notnull");
	mu_assert_ptreq (s, r_strbuf_get (&sb), "set return");
	mu_assert_streq (r_strbuf_get (&sb), "I have packed only the essentials", "set");
	r_strbuf_fini (&sb);
	mu_end;
}

bool test_r_strbuf_setf(void) {
	RStrBuf sb;
	r_strbuf_init (&sb);
	const char *s = r_strbuf_setf (&sb, "One %s for hydration", "water");
	mu_assert_notnull (s, "setf return notnull");
	mu_assert_ptreq (s, r_strbuf_get (&sb), "setf return");
	mu_assert_streq (r_strbuf_get (&sb), "One water for hydration", "setf");
	r_strbuf_fini (&sb);
	mu_end;
}

bool test_r_strbuf_initf(void) {
	RStrBuf sb;
	const char *s = r_strbuf_initf (&sb, "hmmst, %s was that audial occurence? %d", "wat", 42);
	mu_assert_notnull (s, "initf return notnull");
	mu_assert_ptreq (s, r_strbuf_get (&sb), "initf return");
	mu_assert_streq (r_strbuf_get (&sb), "hmmst, wat was that audial occurence? 42", "initf");
	r_strbuf_fini (&sb);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_strbuf_append);
	mu_run_test (test_r_strbuf_strong_string);
	mu_run_test (test_r_strbuf_strong_binary);
	mu_run_test (test_r_strbuf_weak_string);
	mu_run_test (test_r_strbuf_weak_binary);
	mu_run_test (test_r_strbuf_slice);
	mu_run_test (test_r_strbuf_setbin);
	mu_run_test (test_r_strbuf_set);
	mu_run_test (test_r_strbuf_setf);
	mu_run_test (test_r_strbuf_initf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
