#include <r_muta.h>
#include <r_muta/charset.h>
#include "minunit.h"

static bool test_sha2_unaligned_input(void) {
	const struct {
		const char *name;
		const char *digest;
	} algorithms[] = {
		{ "sha256", "e075f2f51cad23d0537186cfcd50f911ea954f9c2e32a437f45327f1b7899bbb" },
		{ "sha384", "3ce716af185561a09c41f48feae39232fd5fe96210778fc5b774a61d06990364026d10bea8c8a892f840bed42dfadc13" },
		{ "sha512", "b7828faae9bc9fa289a07a1be3f87cdc473014ea2697e5b1365b1b862b5c304c61390cbb795bfdd5ea67dd3f72ecf0976c27765729d2da5e630abca196ab29b8" },
	};
	ut8 input[263];
	memset (input, 'A', sizeof (input));
	RMuta *muta = r_muta_new ();
	size_t i, offset;
	for (i = 0; i < R_ARRAY_SIZE (algorithms); i++) {
		for (offset = 0; offset < 8; offset++) {
			RMutaResult result = r_muta_process_simple (muta, algorithms[i].name, input + offset, 256);
			mu_assert ("hash succeeds", result.success);
			mu_assert_streq (result.hex, algorithms[i].digest, "SHA-2 digest at every alignment");
			r_muta_result_free (&result);
		}
	}
	r_muta_free (muta);
	mu_end;
}

static bool test_new_free_lifecycle(void) {
	// The default plugin list registers the "null" plugin twice;
	// the rejected duplicate must be freed, not leaked (caught by LSan).
	RMuta *muta = r_muta_new ();
	mu_assert_notnull (muta, "r_muta_new");
	mu_assert_notnull (r_muta_find (muta, "null"), "null plugin registered");
	RMutaSession *s = r_muta_use (muta, "null");
	mu_assert_notnull (s, "null plugin session");
	r_muta_session_free (s);
	r_muta_free (muta);
	mu_end;
}

static bool test_strict_charset_table(void) {
	const RMutaCharsetMap table[] = {
		{ "A", { 0x80 }, 1 },
		{ "AB", { 0x81, 0x82 }, 2 },
		{ "A", { 0xff }, 1 },
		{ "é", { 0xe0 }, 1 },
		{ "?", { 0xe6 }, 1 },
		{ "\\", { 0x01 }, 1 },
		{ "n", { 0x02 }, 1 },
		{ NULL, { 0 }, 0 },
	};
	const ut8 input[] = "ABAé?\\n";
	const ut8 expected[] = { 0x81, 0x82, 0x80, 0xe0, 0xe6, 0x01, 0x02 };
	ut8 *out = NULL;
	int consumed = 0;
	int len = r_muta_charset_encode_strict (input, sizeof (input) - 1, &out, &consumed, table);
	mu_assert_eq (len, sizeof (expected), "longest match and UTF-8 output length");
	mu_assert_eq (consumed, sizeof (input) - 1, "complete input consumed");
	mu_assert_memeq (out, expected, len, "first duplicate wins and escapes remain literal");
	free (out);
	len = r_muta_charset_encode_strict (input, 0, &out, &consumed, table);
	mu_assert_eq (len, 0, "empty input succeeds");
	mu_assert_eq (consumed, 0, "empty input consumption");
	free (out);
	const ut8 invalid[][4] = {
		{ 'A', 'Z', 0, 0 },
		{ 'A', 0, 'A', 0 },
		{ 'A', 0xc0, 0x80, 0 },
		{ 'A', 0xed, 0xa0, 0x80 },
		{ 'A', 0xf4, 0x90, 0x80 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (invalid); i++) {
		len = r_muta_charset_encode_strict (invalid[i], sizeof (invalid[i]), &out, &consumed, table);
		mu_assert_eq (len, -1, "unmappable, NUL and malformed UTF-8 fail");
		mu_assert_eq (consumed, 1, "failure offset follows valid prefix");
		mu_assert_null (out, "no partial result on failure");
	}
	ut8 repeated[129];
	memset (repeated, 'A', sizeof (repeated));
	len = r_muta_charset_encode_strict (repeated, sizeof (repeated), &out, &consumed, table);
	mu_assert_eq (len, sizeof (repeated), "output grows across buffer boundaries");
	for (i = 0; i < sizeof (repeated); i++) {
		mu_assert_eq (out[i], 0x80, "grown output contents");
	}
	free (out);
	mu_end;
}

static bool test_pokered_encode(void) {
	RMuta *muta = r_muta_new ();
	RMutaSession *ms = r_muta_use (muta, "pokered");
	mu_assert_notnull (ms, "pokered session");
	mu_assert ("pokered supports strict encoding", ms->h->encode);
	const ut8 input[] = "A<LINE>Bé?'d-";
	const ut8 expected[] = { 0x80, 0x4f, 0x81, 0xe0, 0xe6, 0xbb, 0x7f };
	ut8 *out = NULL;
	int consumed = 0;
	int len = ms->h->encode (ms, input, sizeof (input) - 1, &out, &consumed);
	mu_assert_eq (len, sizeof (expected), "pokered output length");
	mu_assert_eq (consumed, sizeof (input) - 1, "pokered complete input");
	mu_assert_memeq (out, expected, len, "UTF-8, controls, contractions and canonical hyphen");
	free (out);
	len = ms->h->encode (ms, (const ut8 *)"A☃", 4, &out, &consumed);
	mu_assert_eq (len, -1, "unmappable character fails");
	mu_assert_eq (consumed, 1, "pokered failure offset");
	mu_assert_null (out, "pokered failure discards prefix");
	len = ms->h->encode (ms, input, 0, &out, &consumed);
	mu_assert_eq (len, 0, "empty literal after failure succeeds");
	free (out);
	r_muta_session_free (ms);
	r_muta_free (muta);
	mu_end;
}

static bool test_literal_encoders(void) {
	const struct {
		const char *name;
		const char *input;
		int len;
		const char *hex;
	} cases[] = {
		{ "ebcdic37", "ABé?", 5, "c1c2516f" },
		{ "ebcdic37", "A\0B", 3, "c100c2" },
		{ "ebcdic37", "[]^~\n", 5, "babbb0a125" },
		{ "ebcdic37", "\\n", 2, "e095" },
		{ "ebcdic37", "", 0, "" },
		{ "base64", "A", 1, "51513d3d" },
		{ "base64", "AB", 2, "5155493d" },
		{ "base64", "ABC", 3, "51554a44" },
		{ "base64", "A\0B", 3, "51514243" },
		{ "base64", "\xff", 1, "2f773d3d" },
		{ "base64", "", 0, "" },
	};
	RMuta *muta = r_muta_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RMutaSession *ms = r_muta_use (muta, cases[i].name);
		mu_assert_notnull (ms, "encoder session");
		mu_assert ("strict encoder capability", ms->h->encode);
		int repeat;
		for (repeat = 0; repeat < 2; repeat++) {
			ut8 *out = NULL;
			int consumed = 0;
			int len = ms->h->encode (ms, (const ut8 *)cases[i].input, cases[i].len, &out, &consumed);
			mu_assert ("encoding succeeds", len >= 0);
			mu_assert_eq (consumed, cases[i].len, "complete input consumption");
			char *hex = len? r_hex_bin2strdup (out, len): strdup ("");
			mu_assert_streq (hex, cases[i].hex, "independent literal bytes");
			free (hex);
			free (out);
		}
		r_muta_session_free (ms);
	}
	RMutaSession *ms = r_muta_use (muta, "ebcdic37");
	ut8 *out = NULL;
	int consumed = 0;
	int len = ms->h->encode (ms, (const ut8 *)"A☃", 4, &out, &consumed);
	mu_assert_eq (len, -1, "CP37 rejects unmappable codepoints");
	mu_assert_eq (consumed, 1, "CP37 failure offset");
	mu_assert_null (out, "CP37 discards partial output");
	len = ms->h->encode (ms, (const ut8 *)"A\xc3", 2, &out, &consumed);
	mu_assert_eq (len, -1, "CP37 rejects truncated UTF-8");
	mu_assert_eq (consumed, 1, "truncated UTF-8 error offset");
	mu_assert_null (out, "truncated UTF-8 discards partial output");
	r_muta_session_free (ms);
	r_muta_free (muta);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_new_free_lifecycle);
	mu_run_test (test_sha2_unaligned_input);
	mu_run_test (test_strict_charset_table);
	mu_run_test (test_pokered_encode);
	mu_run_test (test_literal_encoders);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
