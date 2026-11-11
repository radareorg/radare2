#include <r_reg.h>
#include <r_util/r_str.h>
#include <r_util/r_cfloat.h>
#include <r_util/r_mem.h>
#include <r_endian.h>
#include <math.h>
#include <string.h>
#include "minunit.h"

#if 0
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

bool test_r_reg_nibbles(void) {
	RReg *reg = r_reg_new ();
	reg->endian = R_SYS_ENDIAN_LITTLE;
	mu_assert ("nibble profile", r_reg_set_profile_string (reg,
		"gpr word .16 0 0\n"
		"gpr low .4 .0 0\n"
		"gpr high .4 .4 0\n"
		"gpr last .4 .12 0\n"));
	mu_assert ("write word", r_reg_setv (reg, "word", 0xa5c3));
	mu_assert_eq (r_reg_getv (reg, "low"), 3, "low nibble");
	mu_assert_eq (r_reg_getv (reg, "high"), 12, "high nibble at bit offset");
	mu_assert_eq (r_reg_getv (reg, "last"), 10, "last arena nibble");
	mu_assert ("write high", r_reg_setv (reg, "high", 0x1d));
	mu_assert_eq (r_reg_getv (reg, "word"), 0xa5d3, "mask value and preserve neighbors");
	mu_assert ("write last", r_reg_setv (reg, "last", 7));
	mu_assert_eq (r_reg_getv (reg, "word"), 0x75d3, "write last arena nibble");
	mu_assert ("clear low", r_reg_setv (reg, "low", 0));
	mu_assert_eq (r_reg_getv (reg, "word"), 0x75d0, "clear only selected nibble");
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

bool test_r_reg_set_endian(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");
	r_reg_set_profile_string (reg, "gpr	xer	.32	0	0\ngpr	ca	.1	3.5	0\n");
	r_reg_set_endian (reg, R_SYS_ENDIAN_BIG);
	r_reg_setv (reg, "xer", 0x20000000);
	mu_assert_eq (r_reg_getv (reg, "ca"), 1, "big endian flag reads its xer bit");
	r_reg_setv (reg, "ca", 0);
	mu_assert_eq (r_reg_getv (reg, "xer"), 0, "big endian flag writes its xer bit");
	r_reg_set_endian (reg, R_SYS_ENDIAN_LITTLE);
	r_reg_setv (reg, "xer", 0x20000000);
	mu_assert_eq (r_reg_getv (reg, "ca"), 1, "flag follows the register back to little endian");
	r_reg_free (reg);

	reg = r_reg_new ();
	r_reg_set_endian (reg, R_SYS_ENDIAN_BIG);
	r_reg_set_profile_string (reg, "gpr	xer	.32	0	0\ngpr	ca	.1	3.5	0\n");
	r_reg_setv (reg, "xer", 0x20000000);
	mu_assert_eq (r_reg_getv (reg, "ca"), 1, "profile parsed under big endian mirrors its flags");
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

bool test_r_reg_x87_multi_offset(void) {
	// Mimics the real user_fpregs_struct layout: st0-st7 are .80 regs
	// at 16-byte intervals starting at offset 32 bytes into the arena.
	// This tests that arena sizing, byte access, and longdouble
	// round-trip all work for .80 regs at non-zero offsets.
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg,
		"=A0 st0\n"
		"fpu cwd .16 0 0\n"
		"fpu swd .16 2 0\n"
		"fpu ftw .16 4 0\n"
		"fpu fop .16 6 0\n"
		"fpu frip .64 8 0\n"
		"fpu frdp .64 16 0\n"
		"fpu mxcsr .32 24 0\n"
		"fpu mxcr_mask .32 28 0\n"
		"fpu st0 .80 32 0\n"
		"fpu st1 .80 48 0\n"
		"fpu st2 .80 64 0\n"
		"fpu st3 .80 80 0\n"
		"fpu st4 .80 96 0\n"
		"fpu st5 .80 112 0\n"
		"fpu st6 .80 128 0\n"
		"fpu st7 .80 144 0\n");

	r_reg_fit_arena (reg);

	// Arena must cover st7 at offset 144, size 10 bytes = 154 bytes minimum
	RRegArena *arena = reg->regset[R_REG_TYPE_FPU].arena;
	mu_assert_notnull (arena, "FPU arena exists");
	mu_assert ("arena >= 154 bytes", arena->size >= 154);

	// Round-trip longdouble for each st register at its real offset
	const char *names[] = { "st0","st1","st2","st3","st4","st5","st6","st7" };
	long double vals[] = { 1.0L, 2.0L, 3.0L, 4.0L, 5.0L, 6.0L, 7.0L, 8.0L };
	int i;
	for (i = 0; i < 8; i++) {
		RRegItem *ri = r_reg_get (reg, names[i], R_REG_TYPE_FPU);
		mu_assert_notnull (ri, names[i]);
		r_reg_set_longdouble (reg, ri, vals[i]);
	}
	for (i = 0; i < 8; i++) {
		RRegItem *ri = r_reg_get (reg, names[i], R_REG_TYPE_FPU);
		long double got = r_reg_get_longdouble (reg, ri);
		char msg[64];
		snprintf (msg, sizeof (msg), "%s round-trip", names[i]);
		mu_assert (msg, fabsl (got - vals[i]) < 0.0001L);
	}

	// Verify raw byte access for .80 at non-zero offset
	RRegItem *st7 = r_reg_get (reg, "st7", R_REG_TYPE_FPU);
	mu_assert_notnull (st7, "st7 lookup");
	mu_assert_eq (st7->size, 80, "st7 is 80 bits");
	mu_assert_eq (BITS2BYTES (st7->offset), 144, "st7 offset is 144 bytes");
	ut8 bytes[10];
	mu_assert_true (r_reg_get_value_bytes (reg, st7, bytes, sizeof (bytes)), "read x87 bytes");
	mu_assert_false (r_mem_is_zero (bytes, sizeof (bytes)), "st7 contains data");
	r_unref (st7);

	// Write all st regs, then verify no cross-contamination
	for (i = 0; i < 8; i++) {
		RRegItem *ri = r_reg_get (reg, names[i], R_REG_TYPE_FPU);
		r_reg_set_longdouble (reg, ri, 0.0L);
	}
	RRegItem *st0 = r_reg_get (reg, "st0", R_REG_TYPE_FPU);
	r_reg_set_longdouble (reg, st0, 42.0L);
	// st1 should still be 0
	RRegItem *st1 = r_reg_get (reg, "st1", R_REG_TYPE_FPU);
	long double st1_val = r_reg_get_longdouble (reg, st1);
	mu_assert ("st1 not contaminated by st0 write", fabsl (st1_val) < 0.0001L);

	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_vector_bank(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new");
	mu_assert ("vector bank profile", r_reg_set_profile_string (reg,
		"fpu v[2] .384 0 48\n"
		"fpu p[2] .48 $ 6\n"));
	r_reg_set_endian (reg, R_SYS_ENDIAN_BIG);
	mu_assert ("write last vector chunk", r_reg_setv (reg, "v1[5]", 0x123456789abcdef0ULL));
	mu_assert ("write partial predicate chunk", r_reg_setv (reg, "p0[0]", 0x123456789abcULL));
	mu_assert_eq (r_reg_getv (reg, "p0[0]"), 0x123456789abcULL, "48-bit predicate round trip");
	RRegItem *slice = r_reg_get (reg, "p0[0]", -1);
	mu_assert_notnull (slice, "predicate slice");
	mu_assert_eq (slice->packed_size, 48, "slice preserves packed access");
	mu_assert_eq (r_reg_get_pack (reg, slice, 0, 0), 0x123456789abcULL, "default predicate packing");
	r_unref (slice);
	slice = r_reg_get (reg, "v1[5]", -1);
	mu_assert_notnull (slice, "vector slice");
	mu_assert_eq (slice->packed_size, 64, "slice limits packed access to its size");
	mu_assert_eq (r_reg_get_pack (reg, slice, 0, 0), 0x123456789abcdef0ULL, "default vector packing");
	r_unref (slice);
	RRegItem *vec = r_reg_get (reg, "v1", -1);
	mu_assert_notnull (vec, "vector materialized");
	mu_assert_eq (r_reg_get_pack (reg, vec, 5, 64), 0x123456789abcdef0ULL, "last quadword");
	mu_assert_eq (r_reg_get_pack (reg, vec, 20, 16), 0xdef0, "least-significant lane of last chunk");
	mu_assert ("write packed lane", r_reg_set_pack (reg, vec, 20, 16, 0xbeef));
	mu_assert_eq (r_reg_getv (reg, "v1[5]"), 0x123456789abcbeefULL, "packed lane aliases chunk");
	mu_assert ("reject negative lane", !r_reg_set_pack (reg, vec, -1, 64, 0));
	mu_assert ("reject out-of-range slice", !r_reg_get (reg, "v1[6]", -1));
	mu_assert_eq (r_list_length (r_reg_get_list (reg, R_REG_TYPE_ALL)), 2, "slices stay out of register lists");
	r_unref (vec);
	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_vector_alias_endian(void) {
	RReg *reg = r_reg_new ();
	r_reg_set_endian (reg, R_SYS_ENDIAN_BIG);
	mu_assert ("vector alias profile", r_reg_set_profile_string (reg,
		"fpu b0 .8 0 0\n"
		"fpu h0 .16 0 0\n"
		"fpu s0 .32 0 0\n"
		"fpu d0 .64 0 0\n"
		"fpu last .32 88 0\n"
		"fpu z[2] .384 0 48\n"
		"fpu fpcr .32 $ 0\n"));
	int phase;
	for (phase = 0; phase < 3; phase++) {
		r_reg_set_endian (reg, phase == 1? R_SYS_ENDIAN_LITTLE: R_SYS_ENDIAN_BIG);
		mu_assert ("write vector chunk", r_reg_setv (reg, "z0[0]", 0x123456789abcdef0ULL));
		mu_assert_eq (r_reg_getv (reg, "b0"), 0xf0, "byte aliases low vector bits");
		mu_assert_eq (r_reg_getv (reg, "h0"), 0xdef0, "halfword aliases low vector bits");
		mu_assert_eq (r_reg_getv (reg, "s0"), 0x9abcdef0, "word aliases low vector bits");
		mu_assert_eq (r_reg_getv (reg, "d0"), 0x123456789abcdef0ULL, "doubleword alias stays in place");
		mu_assert ("write word", r_reg_setv (reg, "s0", 0x11223344));
		mu_assert ("write halfword", r_reg_setv (reg, "h0", 0xaabb));
		mu_assert ("write byte", r_reg_setv (reg, "b0", 0xcc));
		mu_assert_eq (r_reg_getv (reg, "z0[0]"), 0x123456781122aaccULL, "alias writes preserve upper bits");
		mu_assert ("write final vector chunk", r_reg_setv (reg, "z1[5]", 0x0123456789abcdefULL));
		mu_assert_eq (r_reg_getv (reg, "last"), 0x89abcdef, "alias in final bank chunk");
		mu_assert ("write final alias", r_reg_setv (reg, "last", 0xaabbccdd));
		mu_assert_eq (r_reg_getv (reg, "z1[5]"), 0x01234567aabbccddULL, "final alias write");
		RRegItem *control = r_reg_get (reg, "fpcr", -1);
		mu_assert_notnull (control, "control register outside vector bank");
		mu_assert_eq (control->offset, 96 * 8, "unrelated scalar offset stays unchanged");
		r_unref (control);
	}
	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_vbank(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	// Fixed regs, including a bracketed name, plus lazy argument/local banks
	bool success = r_reg_set_profile_string (reg,
		"=A0 r0\n"
		"gpr pc .32 0 0\n"
		"gpr m[0] .32 $ 0\n"
		"gpr r[4] .32 $ 0\n"
		"gpr l[256] .32 $ 0\n");
	mu_assert_eq (success, true, "vbank profile parses");

	// Only fixed regs are materialized before lookup; vbanks are declared
	mu_assert_eq (r_list_length (reg->regset[R_REG_TYPE_GPR].regs), 2,
		"no vregs materialized up front");
	mu_assert_eq (RVecRegVBank_length (&reg->regset[R_REG_TYPE_GPR].vbanks),
		2, "two vbanks declared");
	mu_assert_notnull (r_reg_get (reg, "m[0]", R_REG_TYPE_GPR),
		"bracketed fixed register is not parsed as a vbank");

	// Lazy materialization on lookup
	RRegItem *l5 = r_reg_get (reg, "l5", R_REG_TYPE_GPR);
	mu_assert_notnull (l5, "l5 materialized");
	mu_assert_streq (l5->name, "l5", "l5 name correct");
	mu_assert_eq (l5->size, 32, "l5 size from vbank");
	mu_assert_eq (l5->offset, 64 + 4 * 32 + 5 * 32,
		"l5 offset = $ + 5*32 bits");
	mu_assert_eq (l5->index, 2 + 4 + 5, "l5 index reserves previous vbank");
	int l5_index = l5->index;
	int l5_offset = l5->offset;
	RRegItem *l6 = r_reg_get (reg, "l6", R_REG_TYPE_GPR);
	mu_assert_notnull (l6, "l6 materialized");
	mu_assert_eq (l6->index, 2 + 4 + 6, "l6 index reserves previous vbank");
	mu_assert ("vbank items get distinct register indices", l5->index != l6->index);
	RRegItem *l1i = r_reg_index_get (reg, 2 + 4 + 1);
	mu_assert_notnull (l1i, "l1 index materialized");
	mu_assert_streq (l1i->name, "l1", "l1 index resolves back to l1");
	mu_assert_eq (l1i->index, 2 + 4 + 1, "unmaterialized vbank index resolves");
	RRegItem *r0 = r_reg_get (reg, "r0", R_REG_TYPE_GPR);
	mu_assert_notnull (r0, "r0 materialized");
	RRegItem *l1 = r_reg_get (reg, "l1", R_REG_TYPE_GPR);
	mu_assert_notnull (l1, "l1 materialized");
	mu_assert_eq (l5_index, 2 + 4 + 5,
		"materializing earlier vbank slots keeps l5 index stable");
	RRegItem *l5i = r_reg_index_get (reg, l5_index);
	mu_assert_notnull (l5i, "l5 index resolves");
	mu_assert_streq (l5i->name, "l5", "l5 index resolves back to l5");
	mu_assert_eq (l5i->offset, l5_offset, "l5 index resolves correct offset");
	RRegItem *l6i = r_reg_index_get (reg, l6->index);
	mu_assert_notnull (l6i, "l6 index resolves");
	mu_assert_streq (l6i->name, "l6", "l6 index resolves back to l6");

	// Round-trip value via arena
	r_reg_fit_arena (reg);
	mu_assert_eq (r_reg_setv (reg, "l5", 0xdeadbeef), true, "setv l5");
	mu_assert_eq (r_reg_getv (reg, "l5"), 0xdeadbeef, "getv l5");
	mu_assert_eq (r_reg_setv (reg, "l7", 0), true, "setv l7 zero");
	mu_assert_eq (r_reg_getv (reg, "l7"), 0, "unset vbank reads as zero");

	// Second lookup resolves the same virtual slot
	RRegItem *l5b = r_reg_get (reg, "l5", R_REG_TYPE_GPR);
	mu_assert_notnull (l5b, "second lookup returns l5");
	mu_assert_ptreq (l5, l5b, "second lookup hits cached item");
	mu_assert_eq (l5b->index, l5_index, "second lookup returns same index");
	mu_assert_eq (l5b->offset, l5_offset, "second lookup returns same offset");

	// Out-of-range index returns NULL
	mu_assert_null (r_reg_get (reg, "l256", R_REG_TYPE_GPR),
		"index >= count is rejected");
	// Leading zero canonicalization
	mu_assert_null (r_reg_get (reg, "l05", R_REG_TYPE_GPR),
		"leading-zero name is rejected");
	// Non-numeric suffix
	mu_assert_null (r_reg_get (reg, "lx", R_REG_TYPE_GPR),
		"non-numeric suffix is rejected");

	// Clone preserves vbanks
	RReg *clone = r_reg_clone (reg);
	mu_assert_notnull (clone, "clone");
	RRegItem *cl9 = r_reg_get (clone, "l9", R_REG_TYPE_GPR);
	mu_assert_notnull (cl9, "vbank survived clone");
	mu_assert_eq (cl9->offset, 64 + 4 * 32 + 9 * 32, "cloned vbank offset correct");

	RReg *dup = r_reg_new ();
	mu_assert_notnull (dup, "duplicate vbank test reg");
	success = r_reg_set_profile_string (dup,
		"=A0 r0\n"
		"gpr r[2] .32 0 0\n"
		"gpr r[3] .32 $ 0\n"
		"gpr l0 .32 $ 0\n"
		"gpr l[4] .32 $ 0\n");
	mu_assert_eq (success, true, "duplicate vbank profile parses");
	mu_assert_eq (RVecRegVBank_length (&dup->regset[R_REG_TYPE_GPR].vbanks),
		1, "duplicate and conflicting vbank definitions are ignored");
	mu_assert_null (r_reg_get (dup, "r2", R_REG_TYPE_GPR),
		"duplicate vbank does not extend the first range");
	mu_assert_null (r_reg_get (dup, "l1", R_REG_TYPE_GPR),
		"ignored vbank does not materialize new registers");

	r_reg_free (dup);
	r_reg_free (clone);
	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_clone(void) {
	RReg *reg = r_reg_new ();
	mu_assert_notnull (reg, "r_reg_new () failed");

	r_reg_set_profile_string (reg, "=PC eip\n"
		"gpr eax .32 0 0\n"
		"fpu v[4] .64 1024 0\n");

	RRegItem *v1 = r_reg_get (reg, "v1", R_REG_TYPE_FPU);
	mu_assert_notnull (v1, "v1 exists before clone");
	mu_assert_eq (v1->type, R_REG_TYPE_FPU, "v1 type is R_REG_TYPE_FPU before clone");
	int v1_index = v1->index;

	RReg *clone = r_reg_clone (reg);
	mu_assert_notnull (clone, "r_reg_clone () failed");

	const char *name = r_reg_alias_getname (clone, R_REG_ALIAS_PC);
	mu_assert_streq (name, "eip", "PC register alias is eip in clone");

	RRegItem *r = r_reg_get (clone, "eax", -1);
	mu_assert_notnull (r, "eax exists in clone");
	mu_assert_eq (r->size, 32, "eax size is 32 in clone");

	RRegItem *cv1 = r_reg_get (clone, "v1", R_REG_TYPE_FPU);
	mu_assert_notnull (cv1, "v1 exists in clone");
	mu_assert_eq (cv1->type, R_REG_TYPE_FPU, "v1 type is R_REG_TYPE_FPU in clone");
	mu_assert_eq (cv1->index, v1_index, "v1 keeps vbank index in clone");
	RRegItem *cv1i = r_reg_index_get (clone, v1_index);
	mu_assert_notnull (cv1i, "v1 index resolves in clone");
	mu_assert_streq (cv1i->name, "v1", "v1 index resolves back to v1 in clone");

	r_reg_free (reg);
	r_reg_free (clone);
	mu_end;
}

bool test_r_reg_profile_to_cc(void) {
	RReg *reg = r_reg_new ();
	mu_assert_null (r_reg_profile_to_cc (reg), "missing result register");
	r_reg_alias_setname (reg, R_REG_ALIAS_R0, "r0");
	char *cc = r_reg_profile_to_cc (reg);
	mu_assert_streq (cc, "r0 reg()", "no argument registers");
	free (cc);
	int i;
	for (i = 0; i < 10; i++) {
		char *name = r_str_newf ("r%d", i + 1);
		r_reg_alias_setname (reg, R_REG_ALIAS_A0 + i, name);
		free (name);
		if (i == 4) {
			cc = r_reg_profile_to_cc (reg);
			mu_assert_streq (cc, "r0 reg(r1, r2, r3, r4, r5)", "BPF fifth argument");
			free (cc);
		}
	}
	cc = r_reg_profile_to_cc (reg);
	mu_assert_streq (cc, "r0 reg(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10)", "all argument roles");
	free (cc);
	r_reg_free (reg);
	mu_end;
}

bool test_r_reg_wide_access(void) {
	const int widths[] = {128, 256, 384, 512, 1024, 2048};
	int endian, width, i, operation;
	for (endian = 0; endian < 2; endian++) {
		for (width = 0; width < R_ARRAY_SIZE (widths); width++) {
			RReg *reg = r_reg_new ();
			r_reg_set_endian (reg, endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE);
			const int len = widths[width] / 8;
			char *profile = r_str_newf ("fpu before .64 0 0\nfpu wide .%d 8 .64\nfpu after .64 %d 0\n", widths[width], len + 8);
			mu_assert_true (r_reg_set_profile_string (reg, profile), "wide profile");
			mu_assert_true (r_reg_hasbits_check (reg, widths[width]), "track wide register size");
			free (profile);
			RRegItem *item = r_reg_get (reg, "wide", -1);
			ut8 bytes[256], result[256];
			for (i = 0; i < len; i += 8) {
				r_write_ble64 (bytes + i, 0x1122334455667788ULL + i, endian);
			}
			r_reg_setv (reg, "before", 0xaabb);
			r_reg_setv (reg, "after", 0xccdd);
			mu_assert_true (r_reg_set_value_bytes (reg, item, bytes, len), "write all register bytes");
			mu_assert_true (r_reg_get_value_bytes (reg, item, result, len), "read all register bytes");
			mu_assert_memeq (result, bytes, len, "byte round trip preserves arena layout");
			mu_assert_eq (r_reg_get_value (reg, item), 0x1122334455667788ULL, "scalar read returns low chunk");
			RRegArena *arena = reg->regset[item->arena].arena;
			const int arena_size = arena->size;
			arena->size = 8 + len - 1;
			mu_assert_false (r_reg_get_value_bytes (reg, item, result, len), "truncated wide read rejected");
			mu_assert_memeq (result, bytes, len, "failed wide read preserves output");
			mu_assert_false (r_reg_set_value (reg, item, 0), "truncated scalar write rejected");
			arena->size = arena_size;
			mu_assert_false (r_reg_get_value_bytes (reg, item, result, len - 1), "reject short output buffer");
			mu_assert_memeq (result, bytes, len, "failed read leaves buffer unchanged");
			mu_assert_false (r_reg_set_value_bytes (reg, item, bytes, len - 1), "reject short input buffer");
			mu_assert_false (r_reg_set_value_bytes (reg, item, bytes, len + 1), "reject oversized input buffer");
			for (operation = 0; operation < 3; operation++) {
				r_reg_arena_push (reg);
				mu_assert_true (r_reg_get_value_bytes (reg, item, result, len), "read snapshot without materializing");
				mu_assert_true (reg->regset[item->arena].arena->shared, "read preserves shared snapshot");
				memset (result, 0, len);
				if (operation == 0) {
					mu_assert_true (r_reg_set_value_bytes (reg, item, result, len), "byte write materializes snapshot");
				} else if (operation == 1) {
					mu_assert_true (r_reg_set_pack (reg, item, 0, 1, 1), "predicate write materializes snapshot");
				} else {
					mu_assert_true (r_reg_set_value (reg, item, 0x42), "scalar write materializes wide snapshot");
					for (i = 0; i < len / 8; i++) {
						mu_assert_eq (r_reg_get_pack (reg, item, i, 64), i? 0: 0x42, "scalar write clears every upper chunk");
					}
				}
				mu_assert_false (reg->regset[item->arena].arena->shared, "write owns its storage");
				r_reg_arena_pop (reg);
				mu_assert_true (r_reg_get_value_bytes (reg, item, result, len), "read restored snapshot");
				mu_assert_memeq (result, bytes, len, "snapshot is unchanged by register write");
			}
			item->ro = true;
			memset (result, 0, len);
			mu_assert_true (r_reg_set_value_bytes (reg, item, result, len), "read-only byte write is a no-op");
			mu_assert_true (r_reg_set_pack (reg, item, 0, 64, 0), "read-only packed write is a no-op");
			mu_assert_true (r_reg_get_value_bytes (reg, item, result, len), "read read-only register");
			mu_assert_memeq (result, bytes, len, "read-only register unchanged");
			mu_assert_eq (r_reg_getv (reg, "before"), 0xaabb, "preceding register intact");
			mu_assert_eq (r_reg_getv (reg, "after"), 0xccdd, "following register intact");
			r_unref (item);
			r_reg_free (reg);
		}
	}
	mu_end;
}

bool test_r_reg_checked_lanes(void) {
	int endian, bits, index, bit, i;
	for (endian = 0; endian < 2; endian++) {
		RReg *reg = r_reg_new ();
		r_reg_set_endian (reg, endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE);
		mu_assert_true (r_reg_set_profile_string (reg, "fpu pred .136 8 .1\n"), "predicate with partial final chunk");
		RRegItem *item = r_reg_get (reg, "pred", -1);
		ut8 canonical[17], raw[17], expected[17], actual[17];
		for (i = 0; i < sizeof (canonical); i++) {
			canonical[i] = 0x31 + 7 * i;
		}
		r_write_ble64 (raw, r_read_le64 (canonical), endian);
		r_write_ble64 (raw + 8, r_read_le64 (canonical + 8), endian);
		raw[16] = canonical[16];
		for (bits = 1; bits <= 64; bits++) {
			for (index = 0; index < item->size / bits; index++) {
				mu_assert_true (r_reg_set_value_bytes (reg, item, raw, sizeof (raw)), "initialize lane data");
				ut64 want = 0, value = 0;
				for (bit = 0; bit < bits; bit++) {
					const int pos = index * bits + bit;
					want |= (ut64)((canonical[pos / 8] >> (pos & 7)) & 1) << bit;
				}
				mu_assert_true (r_reg_get_pack_checked (reg, item, index, bits, &value), "read valid lane");
				mu_assert_eq (value, want, "lane agrees with logical bit numbering");
				mu_assert_eq (r_reg_get_pack (reg, item, index, bits), want, "legacy getter uses checked path");
				memcpy (expected, canonical, sizeof (expected));
				for (bit = 0; bit < bits; bit++) {
					const int pos = index * bits + bit;
					expected[pos / 8] ^= 1U << (pos & 7);
				}
				mu_assert_true (r_reg_set_pack (reg, item, index, bits, ~want), "write lane including chunk boundaries");
				mu_assert_true (r_reg_get_value_bytes (reg, item, actual, sizeof (actual)), "inspect entire register after lane write");
				mu_assert_eq (r_read_ble64 (actual, endian), r_read_le64 (expected), "write preserves neighbors in first chunk");
				mu_assert_eq (r_read_ble64 (actual + 8, endian), r_read_le64 (expected + 8), "write preserves neighbors in second chunk");
				mu_assert_eq (actual[16], expected[16], "write preserves partial final chunk");
			}
		}
		mu_assert_true (r_reg_set_value (reg, item, 0), "clear predicate register");
		ut64 value = 0x1234;
		mu_assert_true (r_reg_get_pack_checked (reg, item, 135, 0, &value), "default one-bit predicate access");
		mu_assert_eq (value, 0, "valid zero is successful");
		mu_assert_true (r_reg_set_pack (reg, item, 135, 0, 1), "write final predicate bit");
		mu_assert_eq (r_reg_getv (reg, "pred[2]"), 0x80, "predicate bit aliases partial chunk");
		const int invalid[][2] = {{-1, 1}, {136, 1}, {INT_MAX, 64}, {0, -1}, {0, 65}, {0, 128}, {0, INT_MAX}};
		for (i = 0; i < R_ARRAY_SIZE (invalid); i++) {
			value = 0x1234;
			mu_assert_false (r_reg_get_pack_checked (reg, item, invalid[i][0], invalid[i][1], &value), "invalid lane rejected");
			mu_assert_eq (value, 0x1234, "failed lane read leaves output unchanged");
			mu_assert_false (r_reg_set_pack (reg, item, invalid[i][0], invalid[i][1], 0), "invalid lane write rejected");
			mu_assert_eq (r_reg_getv (reg, "pred[2]"), 0x80, "invalid write preserves register");
		}
		item->packed_size = 136;
		mu_assert_false (r_reg_get_pack_checked (reg, item, 0, 0, &value), "oversized default is not clamped");
		RRegItem invalid_item = *item;
		invalid_item.arena = R_REG_TYPE_LAST;
		mu_assert_false (r_reg_get_pack_checked (reg, &invalid_item, 0, 1, &value), "invalid arena rejected");
		invalid_item = *item;
		invalid_item.offset = INT_MAX - 7;
		mu_assert_false (r_reg_get_value_bytes (reg, &invalid_item, actual, sizeof (actual)), "large offset rejected without overflow");
		invalid_item.offset = -1;
		mu_assert_false (r_reg_set_value_bytes (reg, &invalid_item, raw, sizeof (raw)), "unbacked register rejected");
		RRegArena *arena = reg->regset[item->arena].arena;
		const int size = arena->size;
		arena->size = 9;
		mu_assert_false (r_reg_get_pack_checked (reg, item, 0, 1, &value), "truncated register rejected even for first lane");
		mu_assert_false (r_reg_set_pack (reg, item, 0, 1, 0), "truncated arena write rejected");
		arena->size = size;
		r_unref (item);
		r_reg_free (reg);
	}
	mu_end;
}

bool test_r_reg_value_hex(void) {
	const char *profile = "fpu partial .80 0 0\nfpu wide .384 16 0\nfpu huge .2048 64 0\n";
	int endian;
	for (endian = 0; endian < 2; endian++) {
		RReg *reg = r_reg_new ();
		mu_assert_true (r_reg_set_profile_string (reg, profile), "hex profile");
		reg->endian = endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
		RRegItem *wide = r_reg_get (reg, "wide", R_REG_TYPE_ALL);
		mu_assert_true (r_reg_set_pack (reg, wide, 0, 64, 0x0123456789abcdefULL), "low lane");
		mu_assert_true (r_reg_set_pack (reg, wide, 5, 64, 0xfedcba9876543210ULL), "high lane");
		char *hex = r_reg_get_value_hex (reg, wide);
		mu_assert_streq_free (hex,
			"0xfedcba987654321000000000000000000000000000000000000000000000000000000000000000000123456789abcdef",
			"384-bit hexadecimal follows logical lane order");
		RRegItem *partial = r_reg_get (reg, "partial", R_REG_TYPE_ALL);
		mu_assert_true (r_reg_set_pack (reg, partial, 0, 64, 0x0123456789abcdefULL), "partial register low chunk");
		mu_assert_true (r_reg_set_pack (reg, partial, 4, 16, 0xabcd), "partial register high chunk");
		mu_assert_streq_free (r_reg_get_value_hex (reg, partial), "0xabcd0123456789abcdef", "partial final chunk");
		RRegItem *huge = r_reg_get (reg, "huge", R_REG_TYPE_ALL);
		mu_assert_true (r_reg_set_pack (reg, huge, 31, 64, 1), "2048-bit high lane");
		mu_assert_true (r_reg_set_pack (reg, huge, 0, 64, 0x22), "2048-bit low lane");
		char *zeros = r_str_pad (NULL, 0, '0', 480);
		char *expected = r_str_newf ("0x0000000000000001%s0000000000000022", zeros);
		mu_assert_streq_free (r_reg_get_value_hex (reg, huge), expected, "hexadecimal is not truncated by a fixed buffer");
		r_reg_arena_push (reg);
		mu_assert_true (r_reg_set_value_hex (reg, huge, "0Xabc"), "odd uppercase-prefixed literal");
		mu_assert_eq (r_reg_get_pack (reg, huge, 0, 64), 0xabc, "short literal sets low bits");
		mu_assert_eq (r_reg_get_pack (reg, huge, 31, 64), 0, "short literal clears high bits");
		mu_assert_true (r_reg_set_value_hex (reg, huge, expected), "full 2048-bit write");
		mu_assert_streq_free (r_reg_get_value_hex (reg, huge), expected, "full-width round trip");
		r_reg_arena_pop (reg);
		mu_assert_streq_free (r_reg_get_value_hex (reg, huge), expected, "snapshot remains intact");
		free (expected);
		free (zeros);
		mu_assert_true (r_reg_set_value_hex (reg, partial, "abcd0123456789abcdef"), "partial chunk without prefix");
		mu_assert_eq (r_reg_get_pack (reg, partial, 4, 16), 0xabcd, "partial high chunk written in target byte order");
		const char *invalid[] = { "", "0x", "0x100000000000000000000", "0x123g", "0x12 34", "-1", "0x1+2" };
		int i;
		for (i = 0; i < R_ARRAY_SIZE (invalid); i++) {
			mu_assert_false (r_reg_set_value_hex (reg, partial, invalid[i]), "reject invalid hexadecimal");
			mu_assert_streq_free (r_reg_get_value_hex (reg, partial), "0xabcd0123456789abcdef", "invalid write is atomic");
		}
		partial->ro = true;
		mu_assert_true (r_reg_set_value_hex (reg, partial, "0"), "read-only write is a successful no-op");
		mu_assert_streq_free (r_reg_get_value_hex (reg, partial), "0xabcd0123456789abcdef", "read-only value preserved");
		RRegArena *arena = reg->regset[wide->arena].arena;
		const int saved_size = arena->size;
		arena->size = 63;
		mu_assert_null (r_reg_get_value_hex (reg, wide), "reject truncated storage");
		mu_assert_false (r_reg_set_value_hex (reg, wide, "0"), "reject truncated write");
		arena->size = saved_size;
		wide->offset++;
		mu_assert_null (r_reg_get_value_hex (reg, wide), "reject unaligned storage");
		mu_assert_false (r_reg_set_value_hex (reg, wide, "0"), "reject unaligned write");
		wide->offset = INT_MAX - 7;
		mu_assert_null (r_reg_get_value_hex (reg, wide), "reject overflowing extent");
		r_unref (wide);
		r_unref (partial);
		r_unref (huge);
		r_reg_free (reg);
	}
	mu_end;
}

bool test_r_reg_next_diff_bounds(void) {
	RReg *reg = r_reg_new ();
	mu_assert_true (r_reg_set_profile_string (reg,
		"vec128@fpu first .128 8 0\nvec512@fpu last .512 24 0\n"), "diff profile");
	RRegItem *first = r_reg_get (reg, "first", R_REG_TYPE_ALL);
	RRegItem *last = r_reg_get (reg, "last", R_REG_TYPE_ALL);
	ut8 previous[88] = {0};
	mu_assert_true (r_reg_set_pack (reg, first, 1, 64, 1), "upper 128-bit change");
	mu_assert_true (r_reg_set_pack (reg, last, 7, 64, 2), "upper 512-bit change");
	mu_assert_ptreq (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, sizeof (previous), NULL, 64), first, "first full-width change");
	mu_assert_ptreq (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, sizeof (previous), first, 64), last, "next full-width change");
	mu_assert_null (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, sizeof (previous), last, 64), "end of changes");
	mu_assert_null (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, 23, NULL, 64), "short comparison buffer");
	mu_assert_null (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, 87, first, 64), "short upper register");
	RRegArena *arena = reg->regset[R_REG_TYPE_FPU].arena;
	const int saved_size = arena->size;
	arena->size = 23;
	mu_assert_null (r_reg_next_diff (reg, R_REG_TYPE_FPU, previous, sizeof (previous), NULL, 64), "short current arena");
	arena->size = saved_size;
	r_unref (first);
	r_unref (last);
	r_reg_free (reg);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_reg_value_hex);
	mu_run_test (test_r_reg_next_diff_bounds);
	mu_run_test (test_r_reg_wide_access);
	mu_run_test (test_r_reg_checked_lanes);
	mu_run_test (test_r_reg_profile_to_cc);
	mu_run_test (test_r_reg_x87_multi_offset);
	mu_run_test (test_r_reg_vbank);
	mu_run_test (test_r_reg_vector_bank);
	mu_run_test (test_r_reg_vector_alias_endian);
	mu_run_test (test_r_reg_clone);
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
	mu_run_test (test_r_reg_nibbles);
	mu_run_test (test_r_reg_get_value_flag);
	mu_run_test (test_r_reg_set_endian);
	mu_run_test (test_r_reg_get);
	mu_run_test (test_r_reg_get_list);
	mu_run_test (test_r_reg_get_pack);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
