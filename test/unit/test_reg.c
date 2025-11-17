#include <r_reg.h>
#include <r_util/r_cfloat.h>
#include <r_endian.h>
#include <math.h>
#include <string.h>
#include "minunit.h"

static int mu_assert_double_close(double actual, double expected, double eps, const char *message) {
	double diff = fabs (actual - expected);
	char buf[MU_BUF_SIZE];
	snprintf (buf, sizeof (buf), "%s: expected %.16f, got %.16f (diff %.16f)", message, expected, actual, diff);
	mu_assert (buf, diff <= eps);
	return MU_PASSED;
}

#if !R2_NO_LONG_DOUBLE
static int mu_assert_longdouble_close(long double actual, long double expected, long double eps, const char *message) {
	long double diff = fabsl (actual - expected);
	char buf[MU_BUF_SIZE];
	snprintf (buf, sizeof (buf), "%s: expected %.19Lf, got %.19Lf (diff %.19Lf)", message, expected, actual, diff);
	mu_assert (buf, diff <= eps);
	return MU_PASSED;
}
#endif

bool test_r_reg_set_name(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_alias_setname (reg, R_REG_ALIAS_PC, "eip");
	const char *name = r_reg_alias_getname (reg, R_REG_ALIAS_PC);
	mu_assert_streq (name, "eip", "PC register alias is eip");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_set_profile_string(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg, "=PC eip");
	const char *name = r_reg_alias_getname (reg, R_REG_ALIAS_PC);
	mu_assert_streq (name, "eip", "PC register alias is eip");

	mu_assert_eq (r_reg_set_profile_string (reg, "gpr eax .32 24 0"),
		true, "define eax register");

	mu_assert_eq (r_reg_setv (reg, "eax", 1234),
		true, "set eax register value to 1234");

	ut64 value = r_reg_getv (reg, "eax");
	mu_assert_eq (value, 1234, "get eax register value");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get_value_gpr(void) {
	ut64 value;

	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	// force little endian
	reg->endian = R_SYS_ENDIAN_LITTLE;

	r_reg_set_profile_string (reg, "=A0 eax\n\
		gpr eax .32 0 0\n\
		gpr	ax	.16	0	0\n\
		gpr	ah	.8	1	0\n\
		gpr	al	.8	0	0\n\
		gpr	ebx	.32	40	0\n\
		gpr	bx	.16	40	0\n\
		gpr	bh	.8	41	0\n\
		gpr	bl	.8	40	0");

	mu_assert_eq (r_reg_setv (reg, "eax", 0x01234567),
		true, "set eax register value to 0x01234567");

	value = r_reg_getv (reg, "eax");
	mu_assert_eq (value, 0x01234567, "get eax register value");

	value = r_reg_getv (reg, "ax");
	mu_assert_eq (value, 0x4567, "get ax register value");

	value = r_reg_getv (reg, "ah");
	mu_assert_eq (value, 0x45, "get ah register value");

	value = r_reg_getv (reg, "al");
	mu_assert_eq (value, 0x67, "get al register value");

	mu_assert_eq (r_reg_setv (reg, "ebx", 0x89ab0000),
		true, "set ebx register value to 0x89ab0000");

	value = r_reg_getv (reg, "ebx");
	mu_assert_eq (value, 0x89ab0000, "get ebx register value");

	mu_assert_eq (r_reg_setv (reg, "bh", 0xcd),
		true, "set bh register value to 0xcd");

	mu_assert_eq (r_reg_setv (reg, "bl", 0xef),
		true, "set bh register value to 0xef");

	value = r_reg_getv (reg, "bx");
	mu_assert_eq (value, 0xcdef, "get bx register value");

	// force little endian
	reg->endian = R_SYS_ENDIAN_BIG;
	value = r_reg_getv (reg, "ax");
	mu_assert_eq (value, 26437, "get big endian ax register value");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get_value_flag(void) {
	RRegItem *r;
	ut64 value;

	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg,
		"gpr	eflags	.32	0		0	c1p.a.zstido.n.rv\n\
		gpr		flags	.16	0		0\n\
		gpr		cf		.1	.0	0	carry\n\
		gpr		pf		.1	.2	0	parity\n\
		gpr		af		.1	.4	0	adjust\n\
		gpr		zf		.1	.6	0	zero\n\
		gpr		sf		.1	.7	0	sign\n\
		gpr		tf		.1	.8	0	trap\n\
		gpr		if		.1	.9	0	interrupt\n\
		gpr		df		.1	.10	0	direction\n\
		gpr		of		.1	.11	0	overflow");

	r = r_reg_get (reg, "eflags", R_REG_TYPE_FLG);
	r_reg_set_value (reg, r, 0x00000346);

	value = r_reg_getv (reg, "cf");
	mu_assert_eq (value, 0, "get cf flag value");

	value = r_reg_getv (reg, "pf");
	mu_assert_eq (value, 1, "get pf flag value");

	value = r_reg_getv (reg, "af");
	mu_assert_eq (value, 0, "get af flag value");

	value = r_reg_getv (reg, "zf");
	mu_assert_eq (value, 1, "get zf flag value");

	value = r_reg_getv (reg, "sf");
	mu_assert_eq (value, 0, "get sf flag value");

	value = r_reg_getv (reg, "tf");
	mu_assert_eq (value, 1, "get tf flag value");

	value = r_reg_getv (reg, "df");
	mu_assert_eq (value, 0, "get df flag value");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get(void) {
	RRegItem *r;

	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	bool success = r_reg_set_profile_string (reg,
		"gpr	eax		.32	24	0\n\
		fpu		sf0		.32	304	0\n\
		vec128		xmm0	.64	160	4"); // XXX xmm0 is 128 not .64
	mu_assert_eq (success, true, "define eax, sf0 and xmm0 register");

	r = r_reg_get (reg, "sf0", R_REG_TYPE_FPU);
	mu_assert_streq (r->name, "sf0", "found sf0 as R_REG_TYPE_FPU");
	mu_assert_eq (r->type, R_REG_TYPE_FPU, "sf0 type is R_REG_TYPE_FPU");

	r = r_reg_get (reg, "xmm0", R_REG_TYPE_VEC128);
	mu_assert_streq (r->name, "xmm0", "found xmm0 as R_REG_TYPE_VEC128");
	mu_assert_eq (r->type, R_REG_TYPE_VEC128, "xmm0 type is R_REG_TYPE_VEC128");

	r = r_reg_get (reg, "xmm0", -1);
	mu_assert_streq (r->name, "xmm0", "found xmm0");
	mu_assert_eq (r->type, R_REG_TYPE_VEC128, "xmm0 type is R_REG_TYPE_VEC128");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get_list(void) {
	RList *l;
	int mask;

	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	bool success = r_reg_set_profile_string (reg,
		"gpr		eax		.32	24	0\n\
		fpu			sf0		.32	304	0\n\
		vec128		xmm0	.64	160	4");
	mu_assert_eq (success, true, "define eax, sf0 and xmm0 register");

	mask = ((int)1 << R_REG_TYPE_VEC128);
	mu_assert_eq ((reg->regset[R_REG_TYPE_VEC128].maskregstype & mask), mask,
		"xmm0 stored as R_REG_TYPE_FPU");

	l = r_reg_get_list (reg, R_REG_TYPE_VEC128);
	mu_assert_eq (r_list_length (l), 1, "sf0 and xmm0 stored as R_REG_TYPE_FPU");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_get_pack(void) {
	RRegItem *r;
	ut64 value;

	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	/// XXX xmm0h and l should be of size 64 not 128!!
	r_reg_set_profile_string (reg,
		"vec128    xmm0	.128	0	16\n\
		vec128    xmm0h	.64		0	8\n\
		vec128    xmm0l	.64		8	8\n\
		vec128    xmm1	.128	16	16\n\
		vec128    xmm1h	.64		16	8\n\
		vec128    xmm1l	.64		24	8");

	r = r_reg_get (reg, "xmm0", R_REG_TYPE_VEC128);
	r_reg_set_pack (reg, r, 0, 64, 0x0011223344556677);
	value = r_reg_get_pack (reg, r, 0, 64);
	mu_assert_eq (value, 0x0011223344556677,
		"get xmm0 value at index 0 and bitsize 64");

	value = r_reg_get_pack (reg, r, 0, 32);
	mu_assert_eq (value, 0x44556677,
		"get xmm0 value at index 1 and bitsize 32");

	r_reg_set_pack (reg, r, 2, 32, 0xdeadbeef);
	value = r_reg_get_pack (reg, r, 2, 32);
	mu_assert_eq (value, 0xdeadbeef,
		"get xmm0 value at index 2 and bitsize 32");

	r = r_reg_get (reg, "xmm1", R_REG_TYPE_VEC128);
	r_reg_set_pack (reg, r, 1, 64, 0x8899aabbccddeeff);
	r = r_reg_get (reg, "xmm1l", R_REG_TYPE_VEC128);
	value = r_reg_get_pack (reg, r, 0, 32);
	mu_assert_eq (value, 0xccddeeff,
		"get xmm1l value at index 0 and bitsize 32");

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_cfloat_scalar(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	// Test float (32-bit) and double (64-bit) in same profile
	r_reg_set_profile_string (reg,
		"=A0 f0\n"
		"fpu f0 .32 0 0\n"
		"fpu d0 .64 32 0");
	RRegItem *f0 = r_reg_get (reg, "f0", R_REG_TYPE_FPU);
	mu_assert_notnull (f0, "f0 register defined");

	r_reg_set_float (reg, f0, 3.14159f);
	float val_f = r_reg_get_float (reg, f0);
	mu_assert ("float round-trip", fabsf (val_f - 3.14159f) < 0.0001f);

	RRegItem *d0 = r_reg_get (reg, "d0", R_REG_TYPE_FPU);
	mu_assert_notnull (d0, "d0 register defined");

	r_reg_set_double (reg, d0, 2.718281828);
	double val_d = r_reg_get_double (reg, d0);
	mu_assert ("double round-trip", fabs (val_d - 2.718281828) < 0.0000001);

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_cfloat_x87(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	// Test x87 80-bit
	r_reg_set_profile_string (reg,
		"=A0 st0\n"
		"fpu st0 .80 0 0");
	RRegItem *st0 = r_reg_get (reg, "st0", R_REG_TYPE_FPU);
	mu_assert_notnull (st0, "st0 register defined");

	long double test_val = 1.234567890123456789L;
	r_reg_set_longdouble (reg, st0, test_val);
	long double val_ld = r_reg_get_longdouble (reg, st0);

	// x87 has more precision than double, but cfloat uses double internally
	mu_assert ("x87 80-bit round-trip", fabsl (val_ld - test_val) < 0.00001L);

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_cfloat_endian(void) {
	RReg *reg_le = r_reg_new ();
	RReg *reg_be = r_reg_new ();
	mu_assert_notnull (reg_le, "r_reg_new () failed for LE");
	mu_assert_notnull (reg_be, "r_reg_new () failed for BE");

	reg_le->endian = R_SYS_ENDIAN_LITTLE;
	reg_be->endian = R_SYS_ENDIAN_BIG;

	r_reg_set_profile_string (reg_le,
		"=A0 d0\n"
		"fpu d0 .64 0 0");
	r_reg_set_profile_string (reg_be,
		"=A0 d0\n"
		"fpu d0 .64 0 0");

	RRegItem *d0_le = r_reg_get (reg_le, "d0", R_REG_TYPE_FPU);
	RRegItem *d0_be = r_reg_get (reg_be, "d0", R_REG_TYPE_FPU);

	double test_val = 3.141592653589793;
	r_reg_set_double (reg_le, d0_le, test_val);
	r_reg_set_double (reg_be, d0_be, test_val);

	// Both should retrieve the same value
	double val_le = r_reg_get_double (reg_le, d0_le);
	double val_be = r_reg_get_double (reg_be, d0_be);

	mu_assert ("LE retrieves correct value", fabs (val_le - test_val) < 0.0000001);
	mu_assert ("BE retrieves correct value", fabs (val_be - test_val) < 0.0000001);

	// Bytes should be swapped
	ut8 *bytes_le = reg_le->regset[d0_le->arena].arena->bytes;
	ut8 *bytes_be = reg_be->regset[d0_be->arena].arena->bytes;
	bool swapped = true;
	for (int i = 0; i < 8; i++) {
		if (bytes_le[i] != bytes_be[7 - i]) {
			swapped = false;
			break;
		}
	}
	mu_assert ("Bytes are properly swapped between LE and BE", swapped);

	r_reg_free (reg_le);
	r_reg_free (reg_be);
	mu_end;
}

bool test_r_reg_cfloat_half(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	// Test binary16 (half precision)
	r_reg_set_profile_string (reg,
		"=A0 h0\n"
		"fpu h0 .16 0 0");
	RRegItem *h0 = r_reg_get (reg, "h0", R_REG_TYPE_FPU);
	mu_assert_notnull (h0, "h0 register defined");

	// Half precision has limited range/precision
	r_reg_set_float (reg, h0, 1.5f);
	float val_h = r_reg_get_float (reg, h0);
	mu_assert ("half precision round-trip", fabsf (val_h - 1.5f) < 0.01f);

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_cfloat_x87_real(void) {
	RReg *reg_le = r_reg_new ();
	RReg *reg_be = r_reg_new ();
	mu_assert_notnull (reg_le, "r_reg_new () failed for LE");
	mu_assert_notnull (reg_be, "r_reg_new () failed for BE");

	reg_le->endian = R_SYS_ENDIAN_LITTLE;
	reg_be->endian = R_SYS_ENDIAN_BIG;

	// Test x87 80-bit with explicit endianness
	r_reg_set_profile_string (reg_le,
		"=A0 st0\n"
		"fpu st0 .80 0 0");
	r_reg_set_profile_string (reg_be,
		"=A0 st0\n"
		"fpu st0 .80 0 0");

	RRegItem *st0_le = r_reg_get (reg_le, "st0", R_REG_TYPE_FPU);
	RRegItem *st0_be = r_reg_get (reg_be, "st0", R_REG_TYPE_FPU);
	mu_assert_notnull (st0_le, "st0_le register defined");
	mu_assert_notnull (st0_be, "st0_be register defined");

	// Test round-trip for LE
	long double test_val = 3.141592653589793238L;
	r_reg_set_longdouble (reg_le, st0_le, test_val);
	long double val_ld = r_reg_get_longdouble (reg_le, st0_le);
	mu_assert ("x87 80-bit LE round-trip", fabsl (val_ld - test_val) < 0.0000001L);

	// Test round-trip for BE
	r_reg_set_longdouble (reg_be, st0_be, test_val);
	val_ld = r_reg_get_longdouble (reg_be, st0_be);
	mu_assert ("x87 80-bit BE round-trip", fabsl (val_ld - test_val) < 0.0000001L);

	// Verify bytes are swapped between LE and BE
	ut8 *bytes_le = reg_le->regset[st0_le->arena].arena->bytes;
	ut8 *bytes_be = reg_be->regset[st0_be->arena].arena->bytes;
	bool swapped = true;
	for (int i = 0; i < 10; i++) {
		if (bytes_le[i] != bytes_be[9 - i]) {
			swapped = false;
			break;
		}
	}
	mu_assert ("x87 bytes properly swapped between LE and BE", swapped);

	r_reg_free (reg_le);
	r_reg_free (reg_be);
	mu_end;
}

bool test_r_reg_cfloat_128(void) {
	RReg *reg_le = r_reg_new ();
	RReg *reg_be = r_reg_new ();
	mu_assert_notnull (reg_le, "r_reg_new () failed for LE");
	mu_assert_notnull (reg_be, "r_reg_new () failed for BE");

	reg_le->endian = R_SYS_ENDIAN_LITTLE;
	reg_be->endian = R_SYS_ENDIAN_BIG;

	// Test binary128 (quadruple precision)
	r_reg_set_profile_string (reg_le,
		"=A0 q0\n"
		"fpu q0 .128 0 0");
	r_reg_set_profile_string (reg_be,
		"=A0 q0\n"
		"fpu q0 .128 0 0");

	RRegItem *q0_le = r_reg_get (reg_le, "q0", R_REG_TYPE_FPU);
	RRegItem *q0_be = r_reg_get (reg_be, "q0", R_REG_TYPE_FPU);
	mu_assert_notnull (q0_le, "q0_le register defined");
	mu_assert_notnull (q0_be, "q0_be register defined");

	// Test round-trip
	double test_val = 2.718281828459045;
	r_reg_set_double (reg_le, q0_le, test_val);
	double val_d = r_reg_get_double (reg_le, q0_le);
	mu_assert ("binary128 LE round-trip", fabs (val_d - test_val) < 0.0000001);

	r_reg_set_double (reg_be, q0_be, test_val);
	val_d = r_reg_get_double (reg_be, q0_be);
	mu_assert ("binary128 BE round-trip", fabs (val_d - test_val) < 0.0000001);

	// Verify bytes are swapped
	ut8 *bytes_le = reg_le->regset[q0_le->arena].arena->bytes;
	ut8 *bytes_be = reg_be->regset[q0_be->arena].arena->bytes;
	bool swapped = true;
	for (int i = 0; i < 16; i++) {
		if (bytes_le[i] != bytes_be[15 - i]) {
			swapped = false;
			break;
		}
	}
	mu_assert ("binary128 bytes properly swapped between LE and BE", swapped);

	r_reg_free (reg_le);
	r_reg_free (reg_be);
	mu_end;
}

bool test_r_reg_cfloat_256(void) {
	RReg *reg_le = r_reg_new ();
	mu_assert_notnull (reg_le, "r_reg_new () failed for LE");

	reg_le->endian = R_SYS_ENDIAN_LITTLE;

	// Test binary256 (octuple precision)
	r_reg_set_profile_string (reg_le,
		"=A0 o0\n"
		"fpu o0 .256 0 0");

	RRegItem *o0_le = r_reg_get (reg_le, "o0", R_REG_TYPE_FPU);
	mu_assert_notnull (o0_le, "o0_le register defined");

	// Test round-trip
	double test_val = 1.41421356237309504880168872420969807856967L;
	r_reg_set_double (reg_le, o0_le, test_val);
	double val_d = r_reg_get_double (reg_le, o0_le);
	mu_assert ("binary256 round-trip", fabs (val_d - test_val) < 0.0000001);

	// Verify register size is correct
	mu_assert_eq (o0_le->size, 256, "o0 register is 256 bits");

	r_reg_free (reg_le);
	mu_end;
}

bool test_r_cfloat_multiword_io(void) {
	const struct {
		RCFloatProfile profile;
		const char *name;
	} cases[] = {
		{ R_CFLOAT_PROFILE_X87_80, "x87_80" },
		{ R_CFLOAT_PROFILE_BINARY96, "binary96" },
		{ R_CFLOAT_PROFILE_BINARY128, "binary128" },
		{ R_CFLOAT_PROFILE_BINARY256, "binary256" },
	};

	ut8 pattern[32];
	ut8 roundtrip[32];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		size_t be;
		for (be = 0; be < 2; be++) {
			RCFloatProfile profile = cases[i].profile;
			profile.big_endian = be != 0;
			const int bits = profile.sign_bits + profile.exp_bits + profile.mant_bits;
			const size_t bytes = (bits + 7) / 8;
			size_t j;
			for (j = 0; j < bytes; j++) {
				pattern[j] = (ut8) ((i * 37) ^ (be * 0x55) ^ (j * 13) ^ 0xA5);
			}
			RCFloatValue value;
			char message[MU_BUF_SIZE];
			snprintf (message, sizeof (message), "%s %s parse_ex", cases[i].name, be? "BE": "LE");
			mu_assert (message, r_cfloat_parse_ex (pattern, bytes, &profile, &value));
			snprintf (message, sizeof (message), "%s %s write_ex", cases[i].name, be? "BE": "LE");
			memset (roundtrip, 0, sizeof (roundtrip));
			mu_assert (message, r_cfloat_write_ex (&value, &profile, roundtrip, bytes));
			snprintf (message, sizeof (message), "%s %s round-trip", cases[i].name, be? "BE": "LE");
			mu_assert (message, !memcmp (pattern, roundtrip, bytes));
		}
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_reg_set_name);
	mu_run_test (test_r_reg_set_profile_string);
	mu_run_test (test_r_reg_cfloat_scalar);
	mu_run_test (test_r_reg_cfloat_x87);
	mu_run_test (test_r_reg_cfloat_x87_real);
	mu_run_test (test_r_reg_cfloat_128);
	mu_run_test (test_r_reg_cfloat_256);
	mu_run_test (test_r_cfloat_multiword_io);
	mu_run_test (test_r_reg_cfloat_endian);
	mu_run_test (test_r_reg_cfloat_half);
	mu_run_test (test_r_reg_get_value_gpr);
	mu_run_test (test_r_reg_get_value_flag);
	mu_run_test (test_r_reg_get);
	mu_run_test (test_r_reg_get_list);
	mu_run_test (test_r_reg_get_pack);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
