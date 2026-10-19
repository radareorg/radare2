#include <r_util.h>
#include "minunit.h"

// long-form length-of-length that claims more length octets than the buffer
// holds: with a 3 byte buffer and two length octets the parser used to read
// buffer[3], one past the end.
bool test_asn1_longform_length_oob(void) {
	ut8 *buf = malloc (3);
	buf[0] = 0x30; // SEQUENCE
	buf[1] = 0x82; // long form, two length octets
	buf[2] = 0x00;
	RASN1Object *o = r_asn1_object_parse (buf, buf, 3, 0);
	mu_assert_null (o, "long-form length with more octets than the buffer holds must be rejected");
	r_asn1_object_free (o);
	free (buf);
	mu_end;
}

// bitstring whose declared content starts exactly at the end of the buffer:
// the unused-bits byte (sector[0]) used to be read one past the end.
bool test_asn1_bitstring_sector_oob(void) {
	ut8 *buf = malloc (3);
	buf[0] = 0x23; // BITSTRING
	buf[1] = 0x81; // long form, one length octet
	buf[2] = 0x01; // length 1, so the content byte lands past the buffer
	RASN1Object *o = r_asn1_object_parse (buf, buf, 3, 0);
	mu_assert_notnull (o, "truncated bitstring should still parse without reading past the buffer");
	r_asn1_object_free (o);
	free (buf);
	mu_end;
}

bool test_asn1_bitstring_tostring(void) {
	const int modes[] = { 0, 't', 'j', 'q' };
	ut32 length;
	for (length = 0; length <= 1; length++) {
		ut8 *buf = malloc (3 + length);
		mu_assert_notnull (buf, "allocate bitstring");
		buf[0] = TAG_BITSTRING;
		buf[1] = 1 + length;
		buf[2] = 0;
		if (length) {
			buf[3] = 0xff;
		}
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (modes); i++) {
			RAsn1 *asn1 = r_asn1_new (buf, 3 + length, modes[i]);
			mu_assert_notnull (asn1, "parse bitstring");
			char *first = r_asn1_tostring (asn1);
			mu_assert_notnull (first, "print bitstring");
			mu_assert_eq (asn1->root->length, length, "printing must preserve the content length");
			char *second = r_asn1_tostring (asn1);
			mu_assert_streq (second, first, "repeated printing must preserve the output");
			mu_assert_eq (asn1->root->length, length, "repeated printing must preserve the content length");
			free (first);
			free (second);
			r_asn1_free (asn1);
		}
		free (buf);
	}
	mu_end;
}

bool test_asn1_empty_boolean_tostring(void) {
	const int modes[] = { 0, 't', 'j', 'q' };
	ut8 *buf = malloc (3);
	buf[0] = TAG_BOOLEAN;
	buf[1] = 0x81;
	buf[2] = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (modes); i++) {
		RAsn1 *asn1 = r_asn1_new (buf, 3, modes[i]);
		mu_assert_notnull (asn1, "parse empty boolean");
		char *output = r_asn1_tostring (asn1);
		mu_assert_notnull (output, "print empty boolean");
		mu_assert_null (strstr (output, "true"), "empty boolean has no true value");
		mu_assert_null (strstr (output, "false"), "empty boolean has no false value");
		free (output);
		r_asn1_free (asn1);
	}
	free (buf);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_asn1_longform_length_oob);
	mu_run_test (test_asn1_bitstring_sector_oob);
	mu_run_test (test_asn1_bitstring_tostring);
	mu_run_test (test_asn1_empty_boolean_tostring);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
