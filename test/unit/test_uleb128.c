#include <r_util.h>
#include <r_io.h>
#include <stdlib.h>
#include "minunit.h"

bool test_uleb128_small(void) {
	int len;
	ut8 *data = r_uleb128_encode (0xbeef, &len);
	mu_assert_eq (len, 3, "uleb128 encoded should be 3 bytes");
	mu_assert_memeq (data, (ut8 *)"\xef\xfd\x02", 3, "right bytes");

	ut64 val;
	r_uleb128 (data, len, &val, NULL);
	mu_assert_eq (val, 0xbeef, "uleb128 decoded");

	r_uleb128_decode (data, &len, &val);
	mu_assert_eq (val, 0xbeef, "uleb128 decoded");
	free (data);

	RBuffer *b = r_buf_new_with_bytes ((ut8 *)"\xef\xfd\x02", 3);
	int r = r_buf_uleb128 (b, &val);
	mu_assert_eq (r, 3, "buf_uleb128 decode worked");
	mu_assert_eq (val, 0xbeef, "buf_uleb128 right val");
	r_buf_free (b);
	mu_end;
}

bool test_sleb128_small(void) {
	st64 val;
	const ut8 *data = (const ut8 *)"\xd3\xc2\x7c";
	val = r_sleb128 (&data, data + 3);
	mu_assert_eq (val, -0xdead, "sleb128 decoded");

	RBuffer *b = r_buf_new_with_bytes ((ut8 *)"\xd3\xc2\x7c", 3);
	int r = r_buf_sleb128 (b, &val);
	mu_assert_eq (r, 3, "buf_sleb128 decode worked");
	mu_assert_eq (val, -0xdead, "buf_sleb128 right val");
	r_buf_free (b);

	mu_end;
}

bool test_uleb128_big(void) {
	int len;
	ut8 *data = r_uleb128_encode (9019283812387, &len);
	mu_assert_eq (len, 7, "uleb128 encoded should be 7 bytes");
	mu_assert_memeq (data, (ut8 *)"\xa3\xe0\xd4\xb9\xbf\x86\x02", 7, "right bytes");

	ut64 val;
	r_uleb128 (data, len, &val, NULL);
	mu_assert_eq (val, 9019283812387, "uleb128 decoded");

	r_uleb128_decode (data, &len, &val);
	mu_assert_eq (val, 9019283812387, "uleb128 decoded");
	free (data);

	RBuffer *b = r_buf_new_with_bytes ((ut8 *)"\xa3\xe0\xd4\xb9\xbf\x86\x02", 7);
	int r = r_buf_uleb128 (b, &val);
	mu_assert_eq (r, 7, "buf_uleb128 decode worked");
	mu_assert_eq (val, 9019283812387, "buf_uleb128 right val");
	r_buf_free (b);
	mu_end;
}

bool test_sleb128_big(void) {
	st64 val;
	const ut8 *data = (ut8 *)"\xdd\x9f\xab\xc6\xc0\xf9\x7d";
	val = r_sleb128 (&data, data + 7);
	mu_assert_eq (val, -9019283812387, "sleb128 decoded");

	RBuffer *b = r_buf_new_with_bytes ((ut8 *)"\xdd\x9f\xab\xc6\xc0\xf9\x7d", 7);
	int r = r_buf_sleb128 (b, &val);
	mu_assert_eq (r, 7, "buf_sleb128 decode worked");
	mu_assert_eq (val, -9019283812387, "buf_sleb128 right val");
	r_buf_free (b);

	mu_end;
}

bool test_leb128_correctness(void) {
	st64 val;
	const ut8 *data = (ut8 *)"\xc5\x00";
	const ut8 *buf = r_leb128 (data, 2, &val);
	mu_assert_eq (val, 69, "leb128 decoded");
	mu_assert_eq (buf, data + 2, "leb128 decoded");
	mu_end;
}

int all_tests() {
	mu_run_test (test_uleb128_small);
	mu_run_test (test_sleb128_small);
	mu_run_test (test_uleb128_big);
	mu_run_test (test_sleb128_big);
	mu_run_test (test_leb128_correctness);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
