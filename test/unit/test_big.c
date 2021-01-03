#include <r_util.h>
#include "minunit.h"

static bool test_r_big_from_to_int(void) {
	RNumBig *a = r_big_new ();

	mu_assert_eq (0, r_big_to_int (a), "Failed r_big_to_int");

	r_big_from_int (a, 0xffff);
	mu_assert_eq (0xffff, r_big_to_int (a), "Failed r_big_from_int");

	r_big_from_int (a, -0x7fff);
	mu_assert_eq (-0x7fff, r_big_to_int (a), "Failed r_big_from_int");

	r_big_free (a);
	mu_end;
}

static bool test_r_big_from_to_hexstr(void) {
	RNumBig *a = r_big_new ();
	char *str;

	r_big_from_hexstr (a, "0xffff");
	mu_assert_eq (0xffff, r_big_to_int (a), "Failed r_big_from_hexstr");

	str = r_big_to_hexstr (a);
	mu_assert_streq_free (str, "0xffff", "Failed r_big_to_hexstr");

	r_big_from_hexstr (a, "-0x7fff");
	mu_assert_eq (-0x7fff, r_big_to_int (a), "Failed r_big_from_hexstr");

	str = r_big_to_hexstr (a);
	mu_assert_streq_free (str, "-0x7fff", "Failed r_big_to_hexstr");

	r_big_free (a);
	mu_end;
}

static bool test_r_big_assign(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();

	r_big_from_int (a, 0xffff);
	r_big_assign (b, a);
	mu_assert_eq (0xffff, r_big_to_int (b), "Failed r_big_assign");

	r_big_from_int (a, -0x7fff);
	r_big_assign (b, a);
	mu_assert_eq (-0x7fff, r_big_to_int (b), "Failed r_big_assign");

	r_big_free (a);
	r_big_free (b);
	mu_end;
}

static bool test_r_big_cmp(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();

	r_big_from_int (b, 0);
	r_big_from_int (a, 1);
	mu_assert_eq (1, r_big_cmp (a, b), "Failed r_big_cmp");
	mu_assert_eq (-1, r_big_cmp (b, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (a, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (b, b), "Failed r_big_cmp");

	r_big_from_hexstr (b, "0xffffffffffffffff");
	mu_assert_eq (-1, r_big_cmp (a, b), "Failed r_big_cmp");
	mu_assert_eq (1, r_big_cmp (b, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (a, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (b, b), "Failed r_big_cmp");

	r_big_from_int (b, 0);
	r_big_from_int (a, -1);
	mu_assert_eq (-1, r_big_cmp (a, b), "Failed r_big_cmp");
	mu_assert_eq (1, r_big_cmp (b, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (a, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (b, b), "Failed r_big_cmp");

	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	mu_assert_eq (1, r_big_cmp (a, b), "Failed r_big_cmp");
	mu_assert_eq (-1, r_big_cmp (b, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (a, a), "Failed r_big_cmp");
	mu_assert_eq (0, r_big_cmp (b, b), "Failed r_big_cmp");

	r_big_from_hexstr (a, "-0x7fffffffffffffff");
	r_big_from_hexstr (b, "0xffffffffffffffff");
	mu_assert_eq (-1, r_big_cmp (a, b), "Failed r_big_cmp");
	mu_assert_eq (1, r_big_cmp (b, a), "Failed r_big_cmp");

	r_big_free (a);
	r_big_free (b);
	mu_end;
}

static bool test_r_big_add(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_int (a, 1);
	r_big_from_int (b, -1);
	r_big_add (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_add");
	r_big_add (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_add");

	r_big_from_hexstr (a, "-0x7fffffffffffffff");
	r_big_from_hexstr (b, "0x7fffffffffffffff");
	r_big_add (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_add");
	r_big_add (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_add");

	r_big_from_hexstr (a, "-0x7fffffffffffffff");
	r_big_assign (b, a);
	r_big_add (c, a, b);
	r_big_from_hexstr (b, "-0xfffffffffffffffe");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_add");

	r_big_from_hexstr (a, "0xffffffffffffffff");
	r_big_assign (b, a);
	r_big_add (c, a, b);
	r_big_from_hexstr (b, "0x1fffffffffffffffe");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_add");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_sub(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_int (a, 1);
	r_big_from_int (b, 1);
	r_big_sub (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");
	r_big_sub (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");

	r_big_from_int (a, 1);
	r_big_from_int (b, -1);
	r_big_sub (c, a, b);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_sub");
	r_big_sub (c, b, a);
	mu_assert_eq (-2, r_big_to_int (c), "Failed r_big_sub");

	r_big_from_int (a, -1);
	r_big_from_int (b, -1);
	r_big_sub (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");
	r_big_sub (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");

	r_big_from_hexstr (a, "0x7fffffffffffffff");
	r_big_from_hexstr (b, "0x7fffffffffffffff");
	r_big_sub (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");
	r_big_sub (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");

	r_big_from_hexstr (a, "0x7fffffffffffffff");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_sub (c, a, b);
	r_big_from_hexstr (b, "0xfffffffffffffffe");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_sub");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_sub (c, b, a);
	r_big_from_hexstr (b, "-0xfffffffffffffffe");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_sub");

	r_big_from_hexstr (a, "-0x7fffffffffffffff");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_sub (c, a, b);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");
	r_big_sub (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_sub");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_mul(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_int (a, 2);
	r_big_from_int (b, -2);
	r_big_mul (c, a, b);
	mu_assert_eq (-4, r_big_to_int (c), "Failed r_big_mul");
	r_big_mul (c, b, a);
	mu_assert_eq (-4, r_big_to_int (c), "Failed r_big_mul");

	r_big_from_int (a, 2);
	r_big_assign (b, a);
	r_big_mul (c, a, b);
	mu_assert_eq (4, r_big_to_int (c), "Failed r_big_mul");
	r_big_mul (c, b, a);
	mu_assert_eq (4, r_big_to_int (c), "Failed r_big_mul");

	r_big_from_int (a, -2);
	r_big_assign (b, a);
	r_big_mul (c, a, b);
	mu_assert_eq (4, r_big_to_int (c), "Failed r_big_mul");
	r_big_mul (c, b, a);
	mu_assert_eq (4, r_big_to_int (c), "Failed r_big_mul");

	r_big_from_hexstr (a, "0x7fffffffffffffff");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_mul (c, a, b);
	r_big_from_hexstr (b, "-0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_mul (c, b, a);
	r_big_from_hexstr (b, "-0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");

	r_big_from_hexstr (a, "0x7fffffffffffffff");
	r_big_from_hexstr (b, "0x7fffffffffffffff");
	r_big_mul (c, a, b);
	r_big_from_hexstr (b, "0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");
	r_big_from_hexstr (b, "0x7fffffffffffffff");
	r_big_mul (c, b, a);
	r_big_from_hexstr (b, "0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");

	r_big_from_hexstr (a, "-0x7fffffffffffffff");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_mul (c, a, b);
	r_big_from_hexstr (b, "0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");
	r_big_from_hexstr (b, "-0x7fffffffffffffff");
	r_big_mul (c, b, a);
	r_big_from_hexstr (b, "0x3fffffffffffffff0000000000000001");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_mul");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_div(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_int (a, 2);
	r_big_from_int (b, -2);
	r_big_div (c, a, b);
	mu_assert_eq (-1, r_big_to_int (c), "Failed r_big_div");
	r_big_div (c, b, a);
	mu_assert_eq (-1, r_big_to_int (c), "Failed r_big_div");

	r_big_from_int (a, 4);
	r_big_from_int (b, 2);
	r_big_div (c, a, b);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_div");
	r_big_div (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_div");

	r_big_from_int (a, -3);
	r_big_from_int (b, -2);
	r_big_div (c, a, b);
	mu_assert_eq (1, r_big_to_int (c), "Failed r_big_div");
	r_big_div (c, b, a);
	mu_assert_eq (0, r_big_to_int (c), "Failed r_big_div");

	r_big_from_hexstr (a, "0x7fffffffffffffff");
	r_big_from_int (b, 5);
	r_big_div (c, a, b);
	r_big_from_hexstr (b, "0x1999999999999999");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_div");

	r_big_from_hexstr (a, "0x8000000000000000");
	r_big_from_int (b, 0x8000);
	r_big_div (c, a, b);
	r_big_from_hexstr (b, "0x1000000000000");
	mu_assert_eq (0, r_big_cmp (c, b), "Failed r_big_div");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_divmod(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();
	RNumBig *d = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_from_hexstr (b, "0x10001");
	r_big_divmod (c, d, a, b);
	r_big_from_hexstr (a, "0x731fcef828307acb02fc9564f9becbba9abb542678af918aea5ee380998e1980817fc9827c82a3491f23ca779d6aa19d3255723e3edb0c176b689294cad1fb49a9b08320c2153ef9a114c8439abffd69c5abffe8c858a7fcf0260ca8a5625863121e99526c8f126bf89196777556b8fc77e54fa8de91d3d84b71159a3416c6e3aecf93e62dc1656158e93a1186f10e9dc59d28db5346cb5ef6df9da59476d71945c2169635559694cdb5c1767f493ba9a33a5dc888985ae4e6cd0bffe29357c4117ad7734d0071c91748b58c02c76d8511522a34b06177e47800c194a0669aa59d505396dd470e87988caac45b8ac35588bdbf5498b30ead09bdb9755ced");
	mu_assert_eq (0, r_big_cmp (c, a), "Failed r_big_divmod");
	mu_assert_eq (57372, r_big_to_int (d), "Failed r_big_divmod");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	r_big_free (d);
	mu_end;
}

static bool test_r_big_mod(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_from_hexstr (b, "0x10001");
	r_big_mod (c, a, b);
	mu_assert_eq (57372, r_big_to_int (c), "Failed r_big_mod");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_and(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_from_hexstr (b, "0x8a1712798b2575df7ae8419ad4b43e0df66c4d2af6a327fc78ffe78b9a15dc2b9630167bfc6ca4f7958ba5073a31c0e06da3d7d0db3fac9a33546f3a62a3a2d20992da45141ed267e91e86308ab14ec027580eaa29719592b9e3a354f2135d87cebf6bfe9acf3b85deb9bb098804ce681a979b68a84594b08dd699afc7511f6790e61365f7de17df954b9a865ec840eca9cabf849b5df4d14adb31eabfb27b8f6144f18907026d41a61b59f72a5f689f8aeca79d0e5272cd2f7ba12620826fa36e3eb8d0b2c90dd76a7dda85dfd3ccad1193f50354e6e74fdbc62c1a765fe6515b2142ad1e16d9b0c914d7e345b2b40ef91f7f10b60806a850c1bccafdd080ac");
	r_big_and (c, a, b);
	r_big_from_hexstr (b, "0x2000211832020db78c000008420040966644c20c482023878e9c58b1804900a92000202440404c38008a1032220000041a284909119089233546d38402282120092084104160006e00e00100201080003100480084110109822a044b2025d854a812b7000c13a810ab98b0908040e4010818308280090200d40010b41101a6210a20225c1861302944a92824000008c800aae0018001481421a108032106b800040500803024940240a0924001f28928ae401000640624d0131a00420822a03683ea8c020410cc10811c8849853400c1093310250862045cbc42810605b2200132140a51014c980811443410402140048134810100006201040800214400008");
	mu_assert_eq (0, r_big_cmp (b, c), "Failed r_big_and");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_or(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_from_hexstr (b, "0x8a1712798b2575df7ae8419ad4b43e0df66c4d2af6a327fc78ffe78b9a15dc2b9630167bfc6ca4f7958ba5073a31c0e06da3d7d0db3fac9a33546f3a62a3a2d20992da45141ed267e91e86308ab14ec027580eaa29719592b9e3a354f2135d87cebf6bfe9acf3b85deb9bb098804ce681a979b68a84594b08dd699afc7511f6790e61365f7de17df954b9a865ec840eca9cabf849b5df4d14adb31eabfb27b8f6144f18907026d41a61b59f72a5f689f8aeca79d0e5272cd2f7ba12620826fa36e3eb8d0b2c90dd76a7dda85dfd3ccad1193f50354e6e74fdbc62c1a765fe6515b2142ad1e16d9b0c914d7e345b2b40ef91f7f10b60806a850c1bccafdd080ac");
	r_big_or (c, a, b);
	r_big_from_hexstr (b, "0xfb37527fff2df7ff7fefd9fbdfb7ff7df67defebfef72ffe7bffefdfff1fff2f9f305f7bfe6dbfffd7efed9f7ff3ffe7fff3f7d3fb3feefa777fffff7fe7e6dbadfafed5553ed36fe91eef78ebb3dee9e75dcfbee971f5d7b9e3ffdef21bfdc7eebfebff9fef7fffdefdbf098bceee7b3af7dfeeae7fb6fa9fdff9afcff1fffff5f753f5f7ff97ffbf4b9afedfcad5eefdfafffcff7ffef5caffb5efbfbe7b9f7ddffdd94febefebe65bdfff6afffaffdeeca79fee72f3fd6ffbf3eeee937ff76f3ef8feb6fbbfdfeb7dded5ffd3fced7fd7ff87def6ef4fffe73d9f77ffff5d7ff5f2ef3edffbfeef14d7f347ffbeeefd1f7f12fe0fa7e858ebfffbfff3bdad");
	mu_assert_eq (0, r_big_cmp (b, c), "Failed r_big_or");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_xor(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_from_hexstr (b, "0x8a1712798b2575df7ae8419ad4b43e0df66c4d2af6a327fc78ffe78b9a15dc2b9630167bfc6ca4f7958ba5073a31c0e06da3d7d0db3fac9a33546f3a62a3a2d20992da45141ed267e91e86308ab14ec027580eaa29719592b9e3a354f2135d87cebf6bfe9acf3b85deb9bb098804ce681a979b68a84594b08dd699afc7511f6790e61365f7de17df954b9a865ec840eca9cabf849b5df4d14adb31eabfb27b8f6144f18907026d41a61b59f72a5f689f8aeca79d0e5272cd2f7ba12620826fa36e3eb8d0b2c90dd76a7dda85dfd3ccad1193f50354e6e74fdbc62c1a765fe6515b2142ad1e16d9b0c914d7e345b2b40ef91f7f10b60806a850c1bccafdd080ac");
	r_big_xor (c, a, b);
	r_big_from_hexstr (b, "0xf937506e7c0dd724072fd9fb5b97fb749019a3cb3a752dc603162a54e71b6f250d305d79ba69bb3c57e74c9c5dd3ffe7be5173436a26e668442b92c73fc564c9ad68f6945128d3690910ef68e9b2d6e9e44dcb3ee130e5c721c15f9a4019a042a43ec08f9f2e457ed444340083cae03b2a765ce6867f26da929ff8a48ee1e59de55551d0367984fd2b01087c9fcad5627df051fce77fea7488e5a56f8dae101f7d9fadd14ce9a6abc251d6db6ae0d26d5408a69fe83291b06eca53eace1155f40700503e96bab31ee36c16516780bce16f44ce858e70cf0a3423158f17a4dd5d6cd4b24a2ecb327e6e0094b243fdaaeeb50c3702ee0fa1c848ab7ff9ebb3bda5");
	mu_assert_eq (0, r_big_cmp (b, c), "Failed r_big_xor");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_inc(void) {
	RNumBig *a = r_big_new ();

	r_big_from_int (a, -1);
	r_big_inc (a);
	mu_assert_eq (0, r_big_to_int (a), "Failed r_big_inc");
	r_big_inc (a);
	mu_assert_eq (1, r_big_to_int (a), "Failed r_big_inc");

	r_big_free (a);
	mu_end;
}

static bool test_r_big_dec(void) {
	RNumBig *a = r_big_new ();

	r_big_from_int (a, 1);
	r_big_dec (a);
	mu_assert_eq (0, r_big_to_int (a), "Failed r_big_dec");
	r_big_dec (a);
	mu_assert_eq (-1, r_big_to_int (a), "Failed r_big_dec");

	r_big_free (a);
	mu_end;
}

static bool test_r_big_is_zero(void) {
	RNumBig *a = r_big_new ();

	r_big_from_int (a, 1);
	r_big_dec (a);
	mu_assert_eq (1, r_big_is_zero (a), "Failed r_big_is_zero");
	r_big_dec (a);
	mu_assert_eq (0, r_big_is_zero (a), "Failed r_big_is_zero");

	r_big_free (a);
	mu_end;
}

static bool test_r_big_lshift(void) {
	RNumBig *a = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_lshift (c, a, 1023);
	r_big_from_hexstr (a, "0x3990210bfb94517dbee3cc30c791e2bcb33af770e66b051d3df4e6efbe8759874d80258123028fe5e13674cdb3f11f83e9f95249d88ca5793bbffefeaeb3630dd27d1668a29b0087700734ac3181cc14e18ae2ca6420b82acc117e6759057ee2b540d5b882f0bf7d857ec78485e717299870e3c7171d59350fa4b085a4d87d7d3ad9a15ae0d3c9915f25497d60814ac76a1d773c3e110f52e11f4a42990e35c80e6dae2c25f5e5f532254796205fdd796f720081733071bea0d8f96677499d2bb49f74771239df64c488e66a5c29b8263f6b9dc36d4b1422f7f29ccab0fd9d861bfaf873986ef5e7538a21a883278f702609a4092c03d3b00c3561998b319e848000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	mu_assert_eq (0, r_big_cmp (c, a), "Failed r_big_lshift");

	r_big_free (a);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_rshift(void) {
	RNumBig *a = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab7105e17efb0afd8f090bce2e5330e1c78e2e3ab26a1f49610b49b0fafa75b342b5c1a79322be4a92fac102958ed43aee787c221ea5c23e9485321c6b901cdb5c584bebcbea644a8f2c40bfbaf2dee40102e660e37d41b1f2ccee933a57693ee8ee2473bec98911ccd4b853704c7ed73b86da962845efe5399561fb3b0c37f5f0e730ddebcea7144351064f1ee04c1348125807a760186ac33316633d09");
	r_big_rshift (c, a, 1023);
	r_big_from_hexstr (a, "0xe640842fee5145f6fb8f30c31e478af2ccebddc399ac1474f7d39bbefa1d661d360096048c0a3f9784d9d336cfc47e0fa7e54927623295e4eefffbfabacd8c3749f459a28a6c021dc01cd2b0c6073053862b8b299082e0ab3045f99d6415fb8ad50356e20bc2fdf615fb1e12179c5ca661c38f1c5c7564d43e92c2169361f5f4");
	mu_assert_eq (0, r_big_cmp (c, a), "Failed r_big_rshift");

	r_big_free (a);
	r_big_free (c);
	mu_end;
}

static bool test_r_big_powm(void) {
	RNumBig *a = r_big_new ();
	RNumBig *b = r_big_new ();
	RNumBig *c = r_big_new ();
	RNumBig *m = r_big_new ();

	r_big_from_int (a, 3);
	r_big_from_int (b, 4);
	r_big_from_int (m, 7);
	r_big_powm (c, a, b, m);
	mu_assert_eq (4, r_big_to_int (c), "Failed r_big_powm");

	r_big_free (a);
	r_big_free (b);
	r_big_free (c);
	r_big_free (m);
	mu_end;
}

static bool test_r_big_isqrt(void) {
	RNumBig *a = r_big_new ();
	RNumBig *c = r_big_new ();

	r_big_from_int (a, 4);
	r_big_isqrt (c, a);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_int (a, 5);
	r_big_isqrt (c, a);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_int (a, 6);
	r_big_isqrt (c, a);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_int (a, 7);
	r_big_isqrt (c, a);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_int (a, 8);
	r_big_isqrt (c, a);
	mu_assert_eq (2, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_int (a, 9);
	r_big_isqrt (c, a);
	mu_assert_eq (3, r_big_to_int (c), "Failed r_big_isqrt");

	r_big_from_hexstr (a, "0x73204217f728a2fb7dc798618f23c5796675eee1ccd60a3a7be9cddf7d0eb30e9b004b0246051fcbc26ce99b67e23f07d3f2a493b1194af2777ffdfd5d66c61ba4fa2cd14536010ee00e695863039829c315c594c84170559822fcceb20afdc56a81ab");
	r_big_isqrt (c, a);
	r_big_from_hexstr (a, "0xabacc3be640aee406684e32261e8d2ea2cd09a9441904e3213a1d93732f4774876b8136dab7f5e579338ac82cc96b7651f8");
	mu_assert_eq (0, r_big_cmp (c, a), "Failed r_big_isqrt");

	r_big_free (a);
	r_big_free (c);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_big_from_to_int);
	mu_run_test (test_r_big_from_to_hexstr);
	mu_run_test (test_r_big_assign);
	mu_run_test (test_r_big_cmp);
	mu_run_test (test_r_big_add);
	mu_run_test (test_r_big_sub);
	mu_run_test (test_r_big_mul);
	mu_run_test (test_r_big_div);
	mu_run_test (test_r_big_divmod);
	mu_run_test (test_r_big_mod);
	mu_run_test (test_r_big_and);
	mu_run_test (test_r_big_or);
	mu_run_test (test_r_big_xor);
	mu_run_test (test_r_big_inc);
	mu_run_test (test_r_big_dec);
	mu_run_test (test_r_big_is_zero);
	mu_run_test (test_r_big_lshift);
	mu_run_test (test_r_big_rshift);
	mu_run_test (test_r_big_powm);
	mu_run_test (test_r_big_isqrt);
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
