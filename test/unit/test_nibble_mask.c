#include <r_util.h>
#include "minunit.h"

bool test_r_hex_str2binmask_dot_nibbles(void) {
	ut8 keyword[16];
	ut8 mask[16];
	
	// Test 1: "41..42" - should parse to keyword=[0x41, 0x00, 0x42], mask=[0xff, 0x00, 0xff]
	// Note: .. represents a full byte wildcard (2 nibbles)
	memset(keyword, 0, sizeof(keyword));
	memset(mask, 0, sizeof(mask));
	int len = r_hex_str2binmask ("41..42", keyword, mask);
	mu_assert_eq (len, 3, "41..42 should produce 3-byte keyword");
	mu_assert_eq (keyword[0], 0x41, "Keyword byte 0 should be 0x41");
	mu_assert_eq (keyword[1], 0x00, "Keyword byte 1 should be 0x00");
	mu_assert_eq (keyword[2], 0x42, "Keyword byte 2 should be 0x42");
	mu_assert_eq (mask[0], 0xff, "Mask byte 0 should be 0xff");
	mu_assert_eq (mask[1], 0x00, "Mask byte 1 should be 0x00 (wildcard)");
	mu_assert_eq (mask[2], 0xff, "Mask byte 2 should be 0xff");
	
	// Test 2: "41.42" - single dot masks one nibble (5 nibbles = 3 bytes with nibble flag)
	memset(keyword, 0, sizeof(keyword));
	memset(mask, 0, sizeof(mask));
	len = r_hex_str2binmask ("41.42", keyword, mask);
	mu_assert_eq (len, -3, "41.42 should produce 3-byte keyword with nibble flag");
	mu_assert_eq (keyword[0], 0x41, "Keyword byte 0 should be 0x41");
	mu_assert_eq (keyword[1], 0x04, "Keyword byte 1 should be 0x04");
	mu_assert_eq (keyword[2], 0x20, "Keyword byte 2 should be 0x20");
	mu_assert_eq (mask[0], 0xff, "Mask byte 0 should be 0xff");
	mu_assert_eq (mask[1], 0x0f, "Mask byte 1 should be 0x0f");
	mu_assert_eq (mask[2], 0xf0, "Mask byte 2 should be 0xf0");
	
	// Test 3: "41" - classic hex string
	memset(keyword, 0, sizeof(keyword));
	memset(mask, 0, sizeof(mask));
	len = r_hex_str2binmask ("41", keyword, mask);
	mu_assert_eq (len, 1, "41 should produce 1-byte keyword");
	mu_assert_eq (keyword[0], 0x41, "Keyword byte 0 should be 0x41");
	mu_assert_eq (mask[0], 0xff, "Mask byte 0 should be 0xff");
	
	// Test 4: "4142" - standard hex string
	memset(keyword, 0, sizeof(keyword));
	memset(mask, 0, sizeof(mask));
	len = r_hex_str2binmask ("4142", keyword, mask);
	mu_assert_eq (len, 2, "4142 should produce 2-byte keyword");
	mu_assert_eq (keyword[0], 0x41, "Keyword byte 0 should be 0x41");
	mu_assert_eq (keyword[1], 0x42, "Keyword byte 1 should be 0x42");
	mu_assert_eq (mask[0], 0xff, "Mask byte 0 should be 0xff");
	mu_assert_eq (mask[1], 0xff, "Mask byte 1 should be 0xff");
	
	mu_end;
}

bool test_r_hex_str2binmask_question_nibbles(void) {
	ut8 keyword[3] = {0};
	ut8 mask[3] = {0};
	int len = r_hex_str2binmask ("0x3? 0x?5 0x88", keyword, mask);
	mu_assert_eq (len, 3, "prefixed wildcard length");
	mu_assert_memeq (keyword, (const ut8 *)"\x30\x05\x88", 3, "prefixed wildcard bytes");
	mu_assert_memeq (mask, (const ut8 *)"\xf0\x0f\xff", 3, "prefixed wildcard masks");
	len = r_hex_str2binmask ("?", keyword, mask);
	mu_assert_eq (len, -1, "single wildcard is an odd nibble");
	mu_assert_eq (keyword[0], 0, "single wildcard byte");
	mu_assert_eq (mask[0], 0, "single wildcard mask");
	mu_end;
}

bool test_r_hex_str2binmask_invalid(void) {
	ut8 keyword[3] = {0};
	ut8 mask[3] = {0};
	mu_assert_eq (r_hex_str2binmask ("31..gg", keyword, mask), 0, "reject invalid masked hex");
	mu_assert_eq (r_hex_str2binmask ("?z", keyword, mask), 0, "reject invalid masked nibble");
	mu_assert_eq (r_hex_str2binmask ("", keyword, mask), 0, "reject empty hex");
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_hex_str2binmask_dot_nibbles);
	mu_run_test (test_r_hex_str2binmask_question_nibbles);
	mu_run_test (test_r_hex_str2binmask_invalid);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
