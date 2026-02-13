/* radare2 - LGPL - Copyright 2020-2026 - pancake */

#include <r_util.h>
#include "minunit.h"

int test_ut8_add_overflow(void) {
	ut8 res;
	mu_assert_true (r_add_overflow_ut8 (250, 32, &res), "ut8 add overflow: 250+32");
	mu_assert_false (r_add_overflow_ut8 (250, 5, &res), "ut8 add no overflow: 250+5");
	mu_assert_eq (res, 255, "ut8 add result: 250+5=255");
	mu_assert_false (r_add_overflow_ut8 (0, 0, &res), "ut8 add: 0+0");
	mu_assert_eq (res, 0, "ut8 add result: 0+0=0");
	mu_assert_false (r_add_overflow_ut8 (100, 50, &res), "ut8 add: 100+50");
	mu_assert_eq (res, 150, "ut8 add result: 100+50=150");
	mu_assert_true (r_add_overflow_ut8 (UT8_MAX, 1, &res), "ut8 add overflow: max+1");
	mu_assert_false (r_add_overflow_ut8 (UT8_MAX, 0, &res), "ut8 add: max+0");
	mu_assert_eq (res, UT8_MAX, "ut8 add result: max+0=max");
	mu_end;
}

int test_st8_add_overflow(void) {
	st8 res;
	mu_assert_true (r_add_overflow_st8 (ST8_MAX, 1, &res), "st8 add overflow: max+1");
	mu_assert_false (r_add_overflow_st8 (ST8_MAX, 0, &res), "st8 add: max+0");
	mu_assert_eq (res, ST8_MAX, "st8 add result: max+0=max");
	mu_assert_true (r_add_overflow_st8 (ST8_MIN, -1, &res), "st8 add underflow: min-1");
	mu_assert_false (r_add_overflow_st8 (ST8_MIN, 0, &res), "st8 add: min+0");
	mu_assert_eq (res, ST8_MIN, "st8 add result: min+0=min");
	mu_assert_false (r_add_overflow_st8 (-50, 100, &res), "st8 add: -50+100");
	mu_assert_eq (res, 50, "st8 add result: -50+100=50");
	mu_assert_false (r_add_overflow_st8 (50, -100, &res), "st8 add: 50-100");
	mu_assert_eq (res, -50, "st8 add result: 50-100=-50");
	mu_assert_false (r_add_overflow_st8 (-10, 20, &res), "st8 add: -10+20");
	mu_assert_eq (res, 10, "st8 add result: -10+20=10");
	mu_end;
}

int test_ut16_add_overflow(void) {
	ut16 res;
	mu_assert_false (r_add_overflow_ut16 (ST16_MAX, 2, &res), "ut16 add: st16_max+2 fits in ut16");
	mu_assert_eq (res, (ut16)ST16_MAX + 2, "ut16 add result correct");
	mu_assert_true (r_add_overflow_ut16 (UT16_MAX, 1, &res), "ut16 add overflow: max+1");
	mu_assert_false (r_add_overflow_ut16 (0, UT16_MAX, &res), "ut16 add: 0+max");
	mu_assert_eq (res, UT16_MAX, "ut16 add result: 0+max=max");
	mu_assert_true (r_add_overflow_ut16 (UT16_MAX - 10, 20, &res), "ut16 add overflow: near max");
	mu_end;
}

int test_st16_add_overflow(void) {
	st16 res;
	mu_assert_true (r_add_overflow_st16 (ST16_MAX, 2, &res), "st16 add overflow: max+2");
	mu_assert_true (r_add_overflow_st16 (ST16_MAX - 2, 4, &res), "st16 add overflow: max-2+4");
	mu_assert_true (r_add_overflow_st16 (1, ST16_MAX, &res), "st16 add overflow: 1+max");
	mu_assert_true (r_add_overflow_st16 (ST16_MIN, -1, &res), "st16 add underflow: min-1");
	mu_assert_false (r_add_overflow_st16 (-10, 20, &res), "st16 add: -10+20");
	mu_assert_eq (res, 10, "st16 add result: -10+20=10");
	mu_assert_false (r_add_overflow_st16 (0, 0, &res), "st16 add: 0+0");
	mu_assert_eq (res, 0, "st16 add result: 0+0=0");
	mu_end;
}

int test_ut32_add_overflow(void) {
	ut32 res;
	mu_assert_true (r_add_overflow_ut32 (UT32_MAX, 1, &res), "ut32 add overflow: max+1");
	mu_assert_false (r_add_overflow_ut32 (UT32_MAX, 0, &res), "ut32 add: max+0");
	mu_assert_eq (res, UT32_MAX, "ut32 add result: max+0=max");
	mu_assert_false (r_add_overflow_ut32 (1000000, 2000000, &res), "ut32 add: 1M+2M");
	mu_assert_eq (res, 3000000, "ut32 add result: 1M+2M=3M");
	mu_end;
}

int test_st32_add_overflow(void) {
	st32 res;
	mu_assert_true (r_add_overflow_st32 (ST32_MAX, 1, &res), "st32 add overflow: max+1");
	mu_assert_true (r_add_overflow_st32 (ST32_MIN, -1, &res), "st32 add underflow: min-1");
	mu_assert_true (r_add_overflow_st32 (ST32_MIN, -20, &res), "st32 add underflow: min-20");
	mu_assert_false (r_add_overflow_st32 (-10, 20, &res), "st32 add: -10+20");
	mu_assert_eq (res, 10, "st32 add result: -10+20=10");
	mu_end;
}

int test_ut64_add_overflow(void) {
	ut64 res;
	mu_assert_true (r_add_overflow_ut64 (UT64_MAX, 1, &res), "ut64 add overflow: max+1");
	mu_assert_false (r_add_overflow_ut64 (UT64_MAX, 0, &res), "ut64 add: max+0");
	mu_assert_eq (res, UT64_MAX, "ut64 add result: max+0=max");
	mu_assert_false (r_add_overflow_ut64 (1, 1, &res), "ut64 add: 1+1");
	mu_assert_eq (res, 2, "ut64 add result: 1+1=2");
	mu_end;
}

int test_st64_add_overflow(void) {
	st64 res;
	mu_assert_true (r_add_overflow_st64 (ST64_MAX, 1, &res), "st64 add overflow: max+1");
	mu_assert_true (r_add_overflow_st64 (ST64_MIN, -1, &res), "st64 add underflow: min-1");
	mu_assert_true (r_add_overflow_st64 (ST64_MIN, -20, &res), "st64 add underflow: min-20");
	mu_assert_false (r_add_overflow_st64 (-10, 20, &res), "st64 add: -10+20");
	mu_assert_eq (res, 10, "st64 add result: -10+20=10");
	mu_end;
}

int test_ut8_sub_overflow(void) {
	ut8 res;
	mu_assert_true (r_sub_overflow_ut8 (10, 20, &res), "ut8 sub underflow: 10-20");
	mu_assert_false (r_sub_overflow_ut8 (20, 10, &res), "ut8 sub: 20-10");
	mu_assert_eq (res, 10, "ut8 sub result: 20-10=10");
	mu_assert_false (r_sub_overflow_ut8 (0, 0, &res), "ut8 sub: 0-0");
	mu_assert_eq (res, 0, "ut8 sub result: 0-0=0");
	mu_assert_true (r_sub_overflow_ut8 (0, 1, &res), "ut8 sub underflow: 0-1");
	mu_end;
}

int test_st8_sub_overflow(void) {
	st8 res;
	mu_assert_false (r_sub_overflow_st8 (10, 20, &res), "st8 sub: 10-20");
	mu_assert_eq (res, -10, "st8 sub result: 10-20=-10");
	mu_assert_true (r_sub_overflow_st8 (ST8_MIN, 1, &res), "st8 sub underflow: min-1");
	mu_assert_true (r_sub_overflow_st8 (ST8_MAX, -1, &res), "st8 sub overflow: max-(-1)");
	mu_assert_false (r_sub_overflow_st8 (-10, -20, &res), "st8 sub: -10-(-20)");
	mu_assert_eq (res, 10, "st8 sub result: -10-(-20)=10");
	mu_end;
}

int test_ut16_sub_overflow(void) {
	ut16 res;
	mu_assert_true (r_sub_overflow_ut16 (10, 210, &res), "ut16 sub underflow: 10-210");
	mu_assert_true (r_sub_overflow_ut16 (10, 11, &res), "ut16 sub underflow: 10-11");
	mu_assert_false (r_sub_overflow_ut16 (11, 10, &res), "ut16 sub: 11-10");
	mu_assert_eq (res, 1, "ut16 sub result: 11-10=1");
	mu_assert_false (r_sub_overflow_ut16 (10, 10, &res), "ut16 sub: 10-10");
	mu_assert_eq (res, 0, "ut16 sub result: 10-10=0");
	mu_end;
}

int test_st16_sub_overflow(void) {
	st16 res;
	mu_assert_false (r_sub_overflow_st16 (10, 210, &res), "st16 sub: 10-210 (signed ok)");
	mu_assert_eq (res, -200, "st16 sub result: 10-210=-200");
	mu_assert_true (r_sub_overflow_st16 (ST16_MIN, 210, &res), "st16 sub underflow: min-210");
	mu_assert_false (r_sub_overflow_st16 (10, -210, &res), "st16 sub: 10-(-210)");
	mu_assert_eq (res, 220, "st16 sub result: 10-(-210)=220");
	mu_assert_false (r_sub_overflow_st16 (10, 10, &res), "st16 sub: 10-10");
	mu_assert_eq (res, 0, "st16 sub result: 10-10=0");
	mu_assert_true (r_sub_overflow_st16 (ST16_MIN, 11, &res), "st16 sub underflow: min-11");
	mu_assert_false (r_sub_overflow_st16 (10, 11, &res), "st16 sub: 10-11");
	mu_assert_eq (res, -1, "st16 sub result: 10-11=-1");
	mu_end;
}

int test_ut8_mul_overflow(void) {
	ut8 res;
	mu_assert_true (r_mul_overflow_ut8 (16, 32, &res), "ut8 mul overflow: 16*32");
	mu_assert_false (r_mul_overflow_ut8 (16, 2, &res), "ut8 mul: 16*2");
	mu_assert_eq (res, 32, "ut8 mul result: 16*2=32");
	mu_assert_false (r_mul_overflow_ut8 (0, 255, &res), "ut8 mul: 0*255");
	mu_assert_eq (res, 0, "ut8 mul result: 0*255=0");
	mu_assert_false (r_mul_overflow_ut8 (1, 255, &res), "ut8 mul: 1*255");
	mu_assert_eq (res, 255, "ut8 mul result: 1*255=255");
	mu_assert_true (r_mul_overflow_ut8 (2, 200, &res), "ut8 mul overflow: 2*200");
	mu_end;
}

int test_st8_mul_overflow(void) {
	st8 res;
	mu_assert_true (r_mul_overflow_st8 (16, 100, &res), "st8 mul overflow: 16*100");
	mu_assert_false (r_mul_overflow_st8 (16, 1, &res), "st8 mul: 16*1");
	mu_assert_eq (res, 16, "st8 mul result: 16*1=16");
	mu_assert_false (r_mul_overflow_st8 (-2, 2, &res), "st8 mul: -2*2");
	mu_assert_eq (res, -4, "st8 mul result: -2*2=-4");
	mu_assert_false (r_mul_overflow_st8 (-1, 1, &res), "st8 mul: -1*1");
	mu_assert_eq (res, -1, "st8 mul result: -1*1=-1");
	mu_assert_false (r_mul_overflow_st8 (1, -1, &res), "st8 mul: 1*-1");
	mu_assert_eq (res, -1, "st8 mul result: 1*-1=-1");
	mu_assert_false (r_mul_overflow_st8 (2, -2, &res), "st8 mul: 2*-2");
	mu_assert_eq (res, -4, "st8 mul result: 2*-2=-4");
	mu_assert_false (r_mul_overflow_st8 (-1, -2, &res), "st8 mul: -1*-2");
	mu_assert_eq (res, 2, "st8 mul result: -1*-2=2");
	mu_assert_false (r_mul_overflow_st8 (-2, -1, &res), "st8 mul: -2*-1");
	mu_assert_eq (res, 2, "st8 mul result: -2*-1=2");
	mu_assert_true (r_mul_overflow_st8 (-16, 100, &res), "st8 mul overflow: -16*100");
	mu_assert_true (r_mul_overflow_st8 (100, -16, &res), "st8 mul overflow: 100*-16");
	mu_assert_false (r_mul_overflow_st8 (3, -16, &res), "st8 mul: 3*-16");
	mu_assert_eq (res, -48, "st8 mul result: 3*-16=-48");
	mu_assert_false (r_mul_overflow_st8 (-1, 0, &res), "st8 mul: -1*0");
	mu_assert_eq (res, 0, "st8 mul result: -1*0=0");
	mu_assert_false (r_mul_overflow_st8 (1, 0, &res), "st8 mul: 1*0");
	mu_assert_eq (res, 0, "st8 mul result: 1*0=0");
	mu_assert_true (r_mul_overflow_st8 (ST8_MIN, -1, &res), "st8 mul overflow: min*-1");
	mu_end;
}

int test_ut16_mul_overflow(void) {
	ut16 res;
	mu_assert_true (r_mul_overflow_ut16 (1000, 1000, &res), "ut16 mul overflow: 1000*1000");
	mu_assert_false (r_mul_overflow_ut16 (100, 100, &res), "ut16 mul: 100*100");
	mu_assert_eq (res, 10000, "ut16 mul result: 100*100=10000");
	mu_assert_false (r_mul_overflow_ut16 (0, UT16_MAX, &res), "ut16 mul: 0*max");
	mu_assert_eq (res, 0, "ut16 mul result: 0*max=0");
	mu_end;
}

int test_st16_mul_overflow(void) {
	st16 res;
	mu_assert_true (r_mul_overflow_st16 (ST16_MIN, -1, &res), "st16 mul overflow: min*-1");
	mu_assert_false (r_mul_overflow_st16 (100, -100, &res), "st16 mul: 100*-100");
	mu_assert_eq (res, -10000, "st16 mul result: 100*-100=-10000");
	mu_assert_true (r_mul_overflow_st16 (ST16_MAX, 2, &res), "st16 mul overflow: max*2");
	mu_end;
}

int test_ut32_mul_overflow(void) {
	ut32 res;
	mu_assert_true (r_mul_overflow_ut32 (UT32_MAX, 2, &res), "ut32 mul overflow: max*2");
	mu_assert_false (r_mul_overflow_ut32 (1000, 1000, &res), "ut32 mul: 1000*1000");
	mu_assert_eq (res, 1000000, "ut32 mul result: 1000*1000=1000000");
	mu_assert_false (r_mul_overflow_ut32 (0, UT32_MAX, &res), "ut32 mul: 0*max");
	mu_assert_eq (res, 0, "ut32 mul result: 0*max=0");
	mu_end;
}

int test_st32_mul_overflow(void) {
	st32 res;
	mu_assert_true (r_mul_overflow_st32 (ST32_MIN, -1, &res), "st32 mul overflow: min*-1");
	mu_assert_false (r_mul_overflow_st32 (1000, -1000, &res), "st32 mul: 1000*-1000");
	mu_assert_eq (res, -1000000, "st32 mul result: 1000*-1000=-1000000");
	mu_assert_true (r_mul_overflow_st32 (ST32_MAX, 2, &res), "st32 mul overflow: max*2");
	mu_end;
}

int test_ut64_mul_overflow(void) {
	ut64 res;
	mu_assert_true (r_mul_overflow_ut64 (UT64_MAX, 2, &res), "ut64 mul overflow: max*2");
	mu_assert_false (r_mul_overflow_ut64 (1000000, 1000000, &res), "ut64 mul: 1M*1M");
	mu_assert_eq (res, 1000000000000ULL, "ut64 mul result: 1M*1M=1T");
	mu_assert_false (r_mul_overflow_ut64 (0, UT64_MAX, &res), "ut64 mul: 0*max");
	mu_assert_eq (res, 0, "ut64 mul result: 0*max=0");
	mu_end;
}

int test_st64_mul_overflow(void) {
	st64 res;
	mu_assert_true (r_mul_overflow_st64 (ST64_MIN, -1, &res), "st64 mul overflow: min*-1");
	mu_assert_false (r_mul_overflow_st64 (1000000, -1000000, &res), "st64 mul: 1M*-1M");
	mu_assert_eq (res, -1000000000000LL, "st64 mul result: 1M*-1M=-1T");
	mu_assert_true (r_mul_overflow_st64 (ST64_MAX, 2, &res), "st64 mul overflow: max*2");
	mu_end;
}

int test_ut8_div_overflow(void) {
	mu_assert_true (r_div_overflow_ut8 (100, 0), "ut8 div by zero");
	mu_assert_false (r_div_overflow_ut8 (100, 1), "ut8 div: 100/1");
	mu_assert_false (r_div_overflow_ut8 (0, 1), "ut8 div: 0/1");
	mu_end;
}

int test_st8_div_overflow(void) {
	mu_assert_true (r_div_overflow_st8 (100, 0), "st8 div by zero");
	mu_assert_true (r_div_overflow_st8 (ST8_MIN, -1), "st8 div overflow: min/-1");
	mu_assert_false (r_div_overflow_st8 (ST8_MAX, -1), "st8 div: max/-1");
	mu_assert_false (r_div_overflow_st8 (-100, 1), "st8 div: -100/1");
	mu_end;
}

int test_ut16_div_overflow(void) {
	mu_assert_true (r_div_overflow_ut16 (100, 0), "ut16 div by zero");
	mu_assert_false (r_div_overflow_ut16 (100, 1), "ut16 div: 100/1");
	mu_end;
}

int test_st16_div_overflow(void) {
	mu_assert_true (r_div_overflow_st16 (100, 0), "st16 div by zero");
	mu_assert_true (r_div_overflow_st16 (ST16_MIN, -1), "st16 div overflow: min/-1");
	mu_assert_false (r_div_overflow_st16 (ST16_MAX, -1), "st16 div: max/-1");
	mu_end;
}

int test_ut32_div_overflow(void) {
	mu_assert_true (r_div_overflow_ut32 (100, 0), "ut32 div by zero");
	mu_assert_false (r_div_overflow_ut32 (100, 1), "ut32 div: 100/1");
	mu_end;
}

int test_st32_div_overflow(void) {
	mu_assert_true (r_div_overflow_st32 (100, 0), "st32 div by zero");
	mu_assert_true (r_div_overflow_st32 (ST32_MIN, -1), "st32 div overflow: min/-1");
	mu_assert_false (r_div_overflow_st32 (ST32_MAX, -1), "st32 div: max/-1");
	mu_end;
}

int test_ut64_div_overflow(void) {
	mu_assert_true (r_div_overflow_ut64 (100, 0), "ut64 div by zero");
	mu_assert_false (r_div_overflow_ut64 (100, 1), "ut64 div: 100/1");
	mu_end;
}

int test_st64_div_overflow(void) {
	mu_assert_true (r_div_overflow_st64 (100, 0), "st64 div by zero");
	mu_assert_true (r_div_overflow_st64 (ST64_MIN, -1), "st64 div overflow: min/-1");
	mu_assert_false (r_div_overflow_st64 (ST64_MAX, -1), "st64 div: max/-1");
	mu_end;
}

int test_size_t_add_overflow(void) {
	size_t res;
	mu_assert_true (r_add_overflow_size_t (SIZE_MAX, 1, &res), "size_t add overflow: max+1");
	mu_assert_false (r_add_overflow_size_t (SIZE_MAX, 0, &res), "size_t add: max+0");
	mu_assert_eq (res, SIZE_MAX, "size_t add result: max+0=max");
	mu_assert_false (r_add_overflow_size_t (100, 200, &res), "size_t add: 100+200");
	mu_assert_eq (res, 300, "size_t add result: 100+200=300");
	mu_end;
}

int test_size_t_sub_overflow(void) {
	size_t res;
	mu_assert_true (r_sub_overflow_size_t (10, 20, &res), "size_t sub underflow: 10-20");
	mu_assert_false (r_sub_overflow_size_t (20, 10, &res), "size_t sub: 20-10");
	mu_assert_eq (res, 10, "size_t sub result: 20-10=10");
	mu_assert_false (r_sub_overflow_size_t (0, 0, &res), "size_t sub: 0-0");
	mu_assert_eq (res, 0, "size_t sub result: 0-0=0");
	mu_end;
}

int test_size_t_mul_overflow(void) {
	size_t res;
	mu_assert_true (r_mul_overflow_size_t (SIZE_MAX, 2, &res), "size_t mul overflow: max*2");
	mu_assert_false (r_mul_overflow_size_t (1000, 1000, &res), "size_t mul: 1000*1000");
	mu_assert_eq (res, 1000000, "size_t mul result: 1000*1000=1000000");
	mu_assert_false (r_mul_overflow_size_t (0, SIZE_MAX, &res), "size_t mul: 0*max");
	mu_assert_eq (res, 0, "size_t mul result: 0*max=0");
	mu_end;
}

int test_boundary_signed_unsigned(void) {
	ut8 ures8;
	st8 sres8;
	ut16 ures16;
	st16 sres16;
	ut32 ures32;
	st32 sres32;
	ut64 ures64;
	st64 sres64;

	mu_assert_false (r_add_overflow_ut8 (127, 1, &ures8), "ut8 can hold 128");
	mu_assert_eq (ures8, 128, "ut8 128 correct");
	mu_assert_true (r_add_overflow_st8 (127, 1, &sres8), "st8 overflow at 128");

	mu_assert_false (r_add_overflow_ut16 (32767, 1, &ures16), "ut16 can hold 32768");
	mu_assert_eq (ures16, 32768, "ut16 32768 correct");
	mu_assert_true (r_add_overflow_st16 (32767, 1, &sres16), "st16 overflow at 32768");

	mu_assert_false (r_add_overflow_ut32 (2147483647, 1, &ures32), "ut32 can hold 2147483648");
	mu_assert_eq (ures32, 2147483648U, "ut32 2147483648 correct");
	mu_assert_true (r_add_overflow_st32 (2147483647, 1, &sres32), "st32 overflow at 2147483648");

	mu_assert_false (r_add_overflow_ut64 (9223372036854775807ULL, 1, &ures64), "ut64 can hold max st64 + 1");
	mu_assert_true (r_add_overflow_st64 (9223372036854775807LL, 1, &sres64), "st64 overflow at max+1");

	mu_end;
}

int test_negative_boundary(void) {
	st8 sres8;
	st16 sres16;
	st32 sres32;
	st64 sres64;

	mu_assert_false (r_sub_overflow_st8 (-127, 1, &sres8), "st8 can hold -128");
	mu_assert_eq (sres8, ST8_MIN, "st8 min correct");
	mu_assert_true (r_sub_overflow_st8 (ST8_MIN, 1, &sres8), "st8 underflow at min-1");

	mu_assert_false (r_sub_overflow_st16 (-32767, 1, &sres16), "st16 can hold -32768");
	mu_assert_eq (sres16, ST16_MIN, "st16 min correct");
	mu_assert_true (r_sub_overflow_st16 (ST16_MIN, 1, &sres16), "st16 underflow at min-1");

	mu_assert_false (r_sub_overflow_st32 (-2147483647, 1, &sres32), "st32 can hold min");
	mu_assert_eq (sres32, ST32_MIN, "st32 min correct");
	mu_assert_true (r_sub_overflow_st32 (ST32_MIN, 1, &sres32), "st32 underflow at min-1");

	mu_assert_false (r_sub_overflow_st64 (-9223372036854775807LL, 1, &sres64), "st64 can hold min");
	mu_assert_eq (sres64, ST64_MIN, "st64 min correct");
	mu_assert_true (r_sub_overflow_st64 (ST64_MIN, 1, &sres64), "st64 underflow at min-1");

	mu_end;
}

#if R_HAVE_BUILTIN_OVERFLOW || (!defined(_MSC_VER) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
int test_generic_overflow(void) {
	ut8 ures8;
	ut16 ures16;
	ut32 ures32;
	ut64 ures64;

	mu_assert_true (r_add_overflow (UT8_MAX, 1, &ures8), "generic ut8 add overflow");
	mu_assert_false (r_add_overflow (100, 50, &ures8), "generic ut8 add no overflow");
	mu_assert_eq (ures8, 150, "generic ut8 add result correct");

	mu_assert_true (r_sub_overflow (10, 20, &ures8), "generic ut8 sub underflow");
	mu_assert_false (r_sub_overflow (20, 10, &ures8), "generic ut8 sub no underflow");
	mu_assert_eq (ures8, 10, "generic ut8 sub result correct");

	mu_assert_true (r_mul_overflow (UT8_MAX, 2, &ures8), "generic ut8 mul overflow");
	mu_assert_false (r_mul_overflow (10, 10, &ures8), "generic ut8 mul no overflow");
	mu_assert_eq (ures8, 100, "generic ut8 mul result correct");

	mu_assert_true (r_add_overflow (UT16_MAX, 1, &ures16), "generic ut16 add overflow");
	mu_assert_true (r_add_overflow (UT32_MAX, 1, &ures32), "generic ut32 add overflow");
	mu_assert_true (r_add_overflow (UT64_MAX, 1, &ures64), "generic ut64 add overflow");

	mu_end;
}
#endif

int all_tests(void) {
	mu_run_test (test_ut8_add_overflow);
	mu_run_test (test_st8_add_overflow);
	mu_run_test (test_ut16_add_overflow);
	mu_run_test (test_st16_add_overflow);
	mu_run_test (test_ut32_add_overflow);
	mu_run_test (test_st32_add_overflow);
	mu_run_test (test_ut64_add_overflow);
	mu_run_test (test_st64_add_overflow);

	mu_run_test (test_ut8_sub_overflow);
	mu_run_test (test_st8_sub_overflow);
	mu_run_test (test_ut16_sub_overflow);
	mu_run_test (test_st16_sub_overflow);

	mu_run_test (test_ut8_mul_overflow);
	mu_run_test (test_st8_mul_overflow);
	mu_run_test (test_ut16_mul_overflow);
	mu_run_test (test_st16_mul_overflow);
	mu_run_test (test_ut32_mul_overflow);
	mu_run_test (test_st32_mul_overflow);
	mu_run_test (test_ut64_mul_overflow);
	mu_run_test (test_st64_mul_overflow);

	mu_run_test (test_ut8_div_overflow);
	mu_run_test (test_st8_div_overflow);
	mu_run_test (test_ut16_div_overflow);
	mu_run_test (test_st16_div_overflow);
	mu_run_test (test_ut32_div_overflow);
	mu_run_test (test_st32_div_overflow);
	mu_run_test (test_ut64_div_overflow);
	mu_run_test (test_st64_div_overflow);

	mu_run_test (test_size_t_add_overflow);
	mu_run_test (test_size_t_sub_overflow);
	mu_run_test (test_size_t_mul_overflow);

	mu_run_test (test_boundary_signed_unsigned);
	mu_run_test (test_negative_boundary);

#if R_HAVE_BUILTIN_OVERFLOW || (!defined(_MSC_VER) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L)
	mu_run_test (test_generic_overflow);
#endif

	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
