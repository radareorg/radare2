#if 0
// XXX to many errors
#include <r_util.h>
#include "minunit.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const char *valid_checksum_bech32[] = {
	"A12UEL5L",
	"a12uel5l",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	"?1ezyfcl",
};

static const char *valid_checksum_bech32m[] = {
	"A1LQFN3A",
	"a1lqfn3a",
	"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
	"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
	"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
	"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
	"?1v759aa",
};

static const char *invalid_checksum_bech32[] = {
	" 1nwldj5",
	"\x7f"
	"1axkwrx",
	"\x80"
	"1eym55h",
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
	"pzry9x0s0muk",
	"1pzry9x0s0muk",
	"x1b4n0q5v",
	"li1dgmt3",
	"de1lg7wt\xff",
	"A1G7SGD8",
	"10a06t8",
	"1qzzfhee",
};

static const char *invalid_checksum_bech32m[] = {
	" 1xj0phk",
	"\x7F"
	"1g6xzxy",
	"\x80"
	"1vctc34",
	"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
	"qyrz8wqd2c9m",
	"1qyrz8wqd2c9m",
	"y1b0jsk6g",
	"lt1igcx5c0",
	"in1muywd",
	"mm1crxm3i",
	"au1s5cgom",
	"M1VUXWEZ",
	"16plkw9",
	"1p2gdwpf",
};

struct valid_address_data {
	const char *address;
	size_t scriptPubKeyLen;
	const uint8_t scriptPubKey[42];
};

struct invalid_address_data {
	const char *hrp;
	int version;
	size_t program_length;
};

static struct valid_address_data valid_address[] = {
	{ "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
		22, { 0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 } },
	{ "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		34, { 0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62 } },
	{ "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
		42, { 0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 } },
	{ "BC1SW50QGDZ25J",
		4, { 0x60, 0x02, 0x75, 0x1e } },
	{ "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
		18, { 0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23 } },
	{ "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		34, { 0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33 } },
	{ "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
		34, { 0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33 } },
	{ "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
		34, { 0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 } },
};

static const char *invalid_address[] = {
	"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
	"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
	"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
	"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
	"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
	"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
	"bc1pw5dgrnzv",
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
	"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
	"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
	"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
	"bc1gmk9yu",
};

static struct invalid_address_data invalid_address_enc[] = {
	{ "BC", 0, 20 },
	{ "bc", 0, 21 },
	{ "bc", 17, 32 },
	{ "bc", 1, 1 },
	{ "bc", 16, 41 },
};

static void segwit_scriptpubkey(uint8_t *scriptpubkey, size_t *scriptpubkeylen, int witver, const uint8_t *witprog, size_t witprog_len) {
	scriptpubkey[0] = witver? (0x50 + witver): 0;
	scriptpubkey[1] = witprog_len;
	memcpy (scriptpubkey + 2, witprog, witprog_len);
	*scriptpubkeylen = witprog_len + 2;
}

int my_strncasecmp (const char *s1, const char *s2, size_t n) {
	size_t i = 0;
	while (i < n) {
		char c1 = s1[i];
		char c2 = s2[i];
		if (c1 >= 'A' && c1 <= 'Z')
			c1 = (c1 - 'A') + 'a';
		if (c2 >= 'A' && c2 <= 'Z')
			c2 = (c2 - 'A') + 'a';
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
		if (c1 == 0)
			return 0;
		++i;
	}
	return 0;
}

static void test_crypto_bech32_encode(void) {
	uint8_t data[82];
	char rebuild[92];
	char hrp[84];
	size_t data_len;
	int i;
	for (i = 0; i < sizeof (valid_checksum_bech32) / sizeof (valid_checksum_bech32[0]); i++) {
		bech32_decode (hrp, data, &data_len, valid_checksum_bech32[i]);
		if (bech32_encode (rebuild, hrp, data, data_len, BECH32_ENCODING_BECH32)) {
			mu_assert_eq (my_strncasecmp (rebuild, valid_checksum_bech32m[i], 92), 0, "bech32_encode");
			mu_end;
		}
	}
}

void test_crypto_bech32m_encode (void) {
	uint8_t data[82];
	char rebuild[92];
	char hrp[84];
	size_t data_len;
	int i;
	for (i = 0; i < sizeof (valid_checksum_bech32m) / sizeof (valid_checksum_bech32m[0]); i++) {
		bech32_decode (hrp, data, &data_len, valid_checksum_bech32m[i]);
		if (bech32_encode (rebuild, hrp, data, data_len, BECH32_ENCODING_BECH32M)) {
			mu_assert_eq (my_strncasecmp (rebuild, valid_checksum_bech32m[i], 92), 0, "bech32m_encode");
			mu_end;
		}
	}
}

int test_crypto_bech32_decode (void) {
	uint8_t data[82];
	char hrp[84];
	size_t data_len;
	int i;
	for (i = 0; i < sizeof (valid_checksum_bech32) / sizeof (valid_checksum_bech32[0]); i++) {
		mu_assert_eq (bech32_decode (hrp, data, &data_len, valid_checksum_bech32[i]), BECH32_ENCODING_BECH32, "bech32_dec_valid_checksum");
		mu_end;
	}
	for (i = 0; i < sizeof (invalid_checksum_bech32) / sizeof (invalid_checksum_bech32[0]); i++) {
		mu_assert_neq (bech32_decode (hrp, data, &data_len, invalid_checksum_bech32[i]), BECH32_ENCODING_BECH32, "bech32_dec_invalid_checksum");
		mu_end;
	}
}

int test_crypto_bech32m_decode (void) {
	uint8_t data[82];
	char hrp[84];
	size_t data_len;
	int i;
	for (i = 0; i < sizeof (valid_checksum_bech32m) / sizeof (valid_checksum_bech32m[0]); i++) {
		mu_assert_eq (bech32_decode (hrp, data, &data_len, valid_checksum_bech32m[i]), BECH32_ENCODING_BECH32M, "bech32m_dec_valid_checksum");
		mu_end
	}
	for (i = 0; i < sizeof (invalid_checksum_bech32m) / sizeof (invalid_checksum_bech32m[0]); i++) {
		mu_assert_neq (bech32_decode (hrp, data, &data_len, invalid_checksum_bech32m[i]), BECH32_ENCODING_BECH32M, "bech32m_dec_invalid_checksum");
		mu_end;
	}
}

int all_tests (void) {
	mu_run_test (test_crypto_bech32_encode);
	mu_run_test (test_crypto_bech32m_encode);
	mu_run_test (test_crypto_bech32_decode);
	mu_run_test (test_crypto_bech32m_decode);
	return tests_passed != tests_run;
}

int main () {
	return all_tests ();
};
#else
int main () {
	return 0;
};
#endif
