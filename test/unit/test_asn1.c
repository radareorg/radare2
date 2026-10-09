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

int all_tests(void) {
	mu_run_test (test_asn1_longform_length_oob);
	mu_run_test (test_asn1_bitstring_sector_oob);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
