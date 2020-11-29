#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "pcode.h"
#include "sysregs.h"
#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"

//-----------------------------------------------------------------------------
// registers
//-----------------------------------------------------------------------------

// regMap[0][?][?] uses SP for R31
// regMap[1][?][?] uses ZR for R31
static const Register regMap[2][11][32] = {
	{
		{
		REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
		REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
		REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
		REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WSP,
		},{
		REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
		REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
		REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
		REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_SP
		},{
		REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
		REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
		REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
		REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_V31
		},{
		REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
		REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
		REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
		REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_B31
		},{
		REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
		REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
		REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
		REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_H31
		},{
		REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
		REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
		REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
		REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31
		},{
		REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
		REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
		REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
		REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_D31
		},{
		REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
		REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
		REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
		REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31
		},{
		REG_Z0,  REG_Z1,  REG_Z2,  REG_Z3,  REG_Z4,  REG_Z5,  REG_Z6,  REG_Z7,
		REG_Z8,  REG_Z9,  REG_Z10, REG_Z11, REG_Z12, REG_Z13, REG_Z14, REG_Z15,
		REG_Z16, REG_Z17, REG_Z18, REG_Z19, REG_Z20, REG_Z21, REG_Z22, REG_Z23,
		REG_Z24, REG_Z25, REG_Z26, REG_Z27, REG_Z28, REG_Z29, REG_Z30, REG_Z31
		},{
		REG_P0,  REG_P1,  REG_P2,  REG_P3,  REG_P4,  REG_P5,  REG_P6,  REG_P7,
		REG_P8,  REG_P9,  REG_P10, REG_P11, REG_P12, REG_P13, REG_P14, REG_P15,
		REG_P16, REG_P17, REG_P18, REG_P19, REG_P20, REG_P21, REG_P22, REG_P23,
		REG_P24, REG_P25, REG_P26, REG_P27, REG_P28, REG_P29, REG_P30, REG_P31
		},{
		REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
		REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
		REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
		REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31
		},
	},{
		{
		REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
		REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
		REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
		REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WZR,
		},{
		REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
		REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
		REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
		REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_XZR,
		},{
		REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
		REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
		REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
		REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_VZR,
		},{
		REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
		REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
		REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
		REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_BZR,
		},{
		REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
		REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
		REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
		REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_HZR,
		},{
		REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
		REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
		REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
		REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_SZR,
		},{
		REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
		REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
		REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
		REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_DZR,
		},{
		REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
		REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
		REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
		REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_QZR
		},{
		REG_Z0,  REG_Z1,  REG_Z2,  REG_Z3,  REG_Z4,  REG_Z5,  REG_Z6,  REG_Z7,
		REG_Z8,  REG_Z9,  REG_Z10, REG_Z11, REG_Z12, REG_Z13, REG_Z14, REG_Z15,
		REG_Z16, REG_Z17, REG_Z18, REG_Z19, REG_Z20, REG_Z21, REG_Z22, REG_Z23,
		REG_Z24, REG_Z25, REG_Z26, REG_Z27, REG_Z28, REG_Z29, REG_Z30, REG_Z31
		},{
		REG_P0,  REG_P1,  REG_P2,  REG_P3,  REG_P4,  REG_P5,  REG_P6,  REG_P7,
		REG_P8,  REG_P9,  REG_P10, REG_P11, REG_P12, REG_P13, REG_P14, REG_P15,
		REG_P16, REG_P17, REG_P18, REG_P19, REG_P20, REG_P21, REG_P22, REG_P23,
		REG_P24, REG_P25, REG_P26, REG_P27, REG_P28, REG_P29, REG_P30, REG_P31
		},{
		REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
		REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
		REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
		REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31
		}
	}
};

/* first coordinate into regMap */
#define REGSET_SP 0
#define REGSET_ZR 1

/* second coordinate into regMap */
#define REG_W_BASE 0
#define REG_X_BASE 1
#define REG_V_BASE 2
#define REG_B_BASE 3
#define REG_H_BASE 4
#define REG_S_BASE 5
#define REG_D_BASE 6
#define REG_Q_BASE 7
#define REG_Z_BASE 8
#define REG_P_BASE 9
#define REG_PF_BASE 10

/* third coordinate into regMap is [0,31] */

int table_wbase_xbase[2] = {REG_W_BASE, REG_X_BASE};

#define REG(SP_OR_ZR, REG_BASE, REG_NUM, DSIZE, ESIZE) \
	REG_CONSTRUCT(DSIZE, ESIZE, regMap[SP_OR_ZR][REG_BASE][REG_NUM])
	//regMap[SP_OR_ZR][REG_BASE][REG_NUM]

/* prefetch operation */
const char *prfop_lookup(unsigned prfop)
{
	switch(prfop) {
		case 0b00000: return "pldl1keep";
		case 0b00001: return "pldl1strm";
		case 0b00010: return "pldl2keep";
		case 0b00011: return "pldl2strm";
		case 0b00100: return "pldl3keep";
		case 0b00101: return "pldl3strm";
		case 0b00110: return "#6";
		case 0b00111: return "#7";
		case 0b01000: return "plil1keep";
		case 0b01001: return "plil1strm";
		case 0b01010: return "plil2keep";
		case 0b01011: return "plil2strm";
		case 0b01100: return "plil3keep";
		case 0b01101: return "plil3strm";
		case 0b01110: return "#14";
		case 0b01111: return "#15";
		case 0b10000: return "pstl1keep";
		case 0b10001: return "pstl1strm";
		case 0b10010: return "pstl2keep";
		case 0b10011: return "pstl2strm";
		case 0b10100: return "pstl3keep";
		case 0b10101: return "pstl3strm";
		case 0b10110: return "#22";
		case 0b10111: return "#23";
		case 0b11000: return "#24";
		case 0b11001: return "#25";
		case 0b11010: return "#26";
		case 0b11011: return "#27";
		case 0b11100: return "#28";
		case 0b11101: return "#29";
		case 0b11110: return "#30";
		case 0b11111: return "#31";
		default: return "error";
	}
}

/* prefetch operation */
const char *prfop_lookup_4(unsigned prfop)
{
	switch(prfop) {
		case 0b0000: return "pldl1keep";
		case 0b0001: return "pldl1strm";
		case 0b0010: return "pldl2keep";
		case 0b0011: return "pldl2strm";
		case 0b0100: return "pldl3keep";
		case 0b0101: return "pldl3strm";
		case 0b0110: return "#6";
		case 0b0111: return "#7";
		case 0b1000: return "pstl1keep";
		case 0b1001: return "pstl1strm";
		case 0b1010: return "pstl2keep";
		case 0b1011: return "pstl2strm";
		case 0b1100: return "pstl3keep";
		case 0b1101: return "pstl3strm";
		case 0b1110: return "#14";
		case 0b1111: return "#15";
		default: return "error";
	}
}

const char *pattern_lookup(unsigned pattern, unsigned uimm5)
{
	switch(pattern & 0x1f) {
		case 0b00000: return "pow2";
		case 0b00001: return "vl1";
		case 0b00010: return "vl2";
		case 0b00011: return "vl3";
		case 0b00100: return "vl4";
		case 0b00101: return "vl5";
		case 0b00110: return "vl6";
		case 0b00111: return "vl7";
		case 0b01000: return "vl8";
		case 0b01001: return "vl16";
		case 0b01010: return "vl32";
		case 0b01011: return "vl64";
		case 0b01100: return "vl128";
		case 0b01101: return "vl256";
		case 0b11101: return "mul4";
		case 0b11110: return "mul3";
		case 0b11111: return "all";
		default: return "error";
	}
}

//-----------------------------------------------------------------------------
// arrangement specifiers and lookups (usually fills in a ".<T>", ".<Ta>", "<.Tb>")
//-----------------------------------------------------------------------------

typedef struct _arrangement_spec
{
	unsigned data_sz;
	unsigned elem_sz;
} arrangement_spec;

#define _ARR_SPEC_RESERVED {.data_sz=0, .elem_sz=0}
#define _1B {.data_sz=1,.elem_sz=1}
#define _1H {.data_sz=1,.elem_sz=2}
#define _1S {.data_sz=1,.elem_sz=4}
#define _1D {.data_sz=1,.elem_sz=8}
#define _1Q {.data_sz=1,.elem_sz=16}
#define _2B {.data_sz=2,.elem_sz=1}
#define _2H {.data_sz=2,.elem_sz=2}
#define _2S {.data_sz=2,.elem_sz=4}
#define _2D {.data_sz=2,.elem_sz=8}
#define _2Q {.data_sz=2,.elem_sz=16}
#define _4B {.data_sz=4,.elem_sz=1}
#define _4H {.data_sz=4,.elem_sz=2}
#define _4S {.data_sz=4,.elem_sz=4}
#define _4D {.data_sz=4,.elem_sz=8}
#define _4Q {.data_sz=4,.elem_sz=16}
#define _8B {.data_sz=8,.elem_sz=1}
#define _8H {.data_sz=8,.elem_sz=2}
#define _8S {.data_sz=8,.elem_sz=4}
#define _8D {.data_sz=8,.elem_sz=8}
#define _8Q {.data_sz=8,.elem_sz=16}
#define _16B {.data_sz=16,.elem_sz=1}
#define _16H {.data_sz=16,.elem_sz=2}
#define _16S {.data_sz=16,.elem_sz=4}
#define _16D {.data_sz=16,.elem_sz=8}
#define _16Q {.data_sz=16,.elem_sz=16}

/* arrangement specifiers
0000 x SEE Advanced SIMD modified immediate
0001 0 8B
0001 1 16B
001x 0 4H
001x 1 8H
01xx 0 2S
01xx 1 4S
1xxx x RESERVED
*/
arrangement_spec arr_spec_method0(uint32_t imm5, uint32_t Q)
{
	if(Q==0) {
		if(imm5 & 1) return (arrangement_spec)_8B;
		if(imm5 & 2) return (arrangement_spec)_4H;
		if(imm5 & 4) return (arrangement_spec)_2S;
	}
	else {
		if(imm5 & 1) return (arrangement_spec)_16B;
		if(imm5 & 2) return (arrangement_spec)_8H;
		if(imm5 & 4) return (arrangement_spec)_4S;
		if(imm5 & 8) return (arrangement_spec)_2D;
	}
	return (arrangement_spec)_ARR_SPEC_RESERVED;
}

arrangement_spec arr_spec_method1(unsigned key)
{
	//if((key & 0b01111) == 0b00000) return (arrangement_spec)_ARR_SPEC_RESERVED;	// x0000 RESERVED
	if((key & 0b00001) == 0b00001) return (arrangement_spec)_1B;					// xxxx1 B
	if((key & 0b00011) == 0b00010) return (arrangement_spec)_1H;					// xxx10 H
	if((key & 0b00111) == 0b00100) return (arrangement_spec)_1S;					// xx100 S
	if((key & 0b01111) == 0b01000) return (arrangement_spec)_1D;					// x1000 D
	if((key & 0b11111) == 0b10000) return (arrangement_spec)_1Q;					// 10000 Q
	return (arrangement_spec)_ARR_SPEC_RESERVED;
}

arrangement_spec arr_spec_method2(unsigned immh)
{
																	// 0000 SEE Advanced SIMD modified immediate
	if(immh==1) return (arrangement_spec)_8H;						// 0001 8H
	if((immh & 0b1110) == 0b0010) return (arrangement_spec)_4S;		// 001x 4S
	if((immh & 0b1100) == 0b0100) return (arrangement_spec)_2D;		// 01xx 2D
	return (arrangement_spec)_ARR_SPEC_RESERVED;					// 1xxx RESERVED
}

arrangement_spec arr_spec_method3(unsigned immh, unsigned q)
{
	switch((immh<<1)|q) {
														// 0000 x SEE Advanced SIMD modified immediate
		case 0b00010: return (arrangement_spec)_8B;		// 0001 0 8B
		case 0b00011: return (arrangement_spec)_16B;	// 0001 1 16B
		case 0b00100:
		case 0b00110: return (arrangement_spec)_4H;		// 001x 0 4H
		case 0b00101:
		case 0b00111: return (arrangement_spec)_8H;		// 001x 1 8H
		case 0b01000:
		case 0b01010:
		case 0b01100:
		case 0b01110: return (arrangement_spec)_2S;		// 01xx 0 2S
		case 0b01001:
		case 0b01011:
		case 0b01101:
		case 0b01111: return (arrangement_spec)_4S;		// 01xx 1 4S
		case 0b10001:
		case 0b10011:
		case 0b10101:
		case 0b10111:
		case 0b11001:
		case 0b11011:
		case 0b11101:
		case 0b11111: return (arrangement_spec)_2D;
		default: break;									// 1xxx 1 RESERVED
	}
	return (arrangement_spec)_ARR_SPEC_RESERVED;
}

arrangement_spec arr_spec_method4(unsigned imm5, unsigned q)
{
	unsigned key = (imm5<<1)|q;
	//if((key & 0b011110) == 0b000000) return RESERVED;					// x0000 x RESERVED
	if((key & 0b000011) == 0b000010) return (arrangement_spec)_8B;		// xxxx1 0 8B
	if((key & 0b000011) == 0b000011) return (arrangement_spec)_16B;		// xxxx1 1 16B
	if((key & 0b000111) == 0b000100) return (arrangement_spec)_4H;		// xxx10 0 4H
	if((key & 0b000111) == 0b000101) return (arrangement_spec)_8H;		// xxx10 1 8H
	if((key & 0b001111) == 0b001000) return (arrangement_spec)_2S;		// xx100 0 2S
	if((key & 0b001111) == 0b001001) return (arrangement_spec)_4S;		// xx100 1 4S
	//if((key & 0b011111) == 0b010000) return RESERVED;					// x1000 0 RESERVED
	if((key & 0b011111) == 0b010001) return (arrangement_spec)_2D;		// x1000 1 2D
	return (arrangement_spec)_ARR_SPEC_RESERVED;
}

arrangement_spec table_1s_1d[2] = {_1S, _1D};
arrangement_spec table_2s_4s[2] = {_2S, _4S};
arrangement_spec table_2s_2d[2] = {_2S, _2D};
arrangement_spec table_2h_4h[2] = {_2H, _4H};
arrangement_spec table_4h_8h[2] = {_4H, _8H};
arrangement_spec table_4s_2d[2] = {_4S, _2D};
arrangement_spec table_8b_16b[2] = {_8B, _16B};
arrangement_spec table_1b_1h_1s_1d[4] = {_1B, _1H, _1S, _1D};
arrangement_spec table_1h_2s_4d_8q[4] = {_1H, _2S, _4D, _8Q};
arrangement_spec table_1d_1b_1h_1s[4] = {_1D, _1B, _1H, _1S};
arrangement_spec table_r_1h_1s_1d[4] = {_ARR_SPEC_RESERVED, _1H, _1S, _1D};
arrangement_spec table_2s_r_4s_2d[4] = {_2S, _ARR_SPEC_RESERVED, _4S, _2D};
arrangement_spec table_2s_4s_r_2d[4] = {_2S, _4S, _ARR_SPEC_RESERVED, _2D};
arrangement_spec table_8h_4s_2d_1q[4] = {_8H, _4S, _2D, _1Q};
arrangement_spec table_4h_8h_2s_4s_1d_2d_r_r[8] = {_4H, _8H, _2S, _4S, _1D, _2D, _ARR_SPEC_RESERVED, _ARR_SPEC_RESERVED};
arrangement_spec table_8b_16b_4h_8h_2s_4s_1d_2d[8] = {_8B, _16B, _4H, _8H, _2S, _4S, _1D, _2D};
arrangement_spec table16_r_b_h_s_d[16] = {_ARR_SPEC_RESERVED, _1B, _1H, _1H, _1S, _1S, _1S, _1S, _1D, _1D, _1D, _1D, _1D, _1D, _1D, _1D};

//-----------------------------------------------------------------------------
// element size (usually to fill in a ".<Ts>")
//-----------------------------------------------------------------------------

unsigned size_spec_method0(uint8_t /*bit*/ a, uint8_t /*bit(6)*/ b)
{
	if(a == 0) {
		if((b & 0x20) == 0) return 4;
		if((b & 0x30) == 0x20) return 2;
		if((b & 0x38) == 0x30) return 1;
		if((b & 0x3C) == 0x38) return 1;
		if((b & 0x3E) == 0x3C) return 1;
		return 0;
	}
	else {
		return 8;
	}
}

unsigned size_spec_method1(unsigned imm13)
{
	unsigned key = (((imm13>>12)&1) << 6) | (imm13 & 0b111111);

	if((key & 0b1100000) == 0b0000000) return 4;			// 0 0xxxxx	S
	if((key & 0b1110000) == 0b0100000) return 2;			// 0 10xxxx	H
	if((key & 0b1111000) == 0b0110000) return 1;			// 0 110xxx	B
	if((key & 0b1111100) == 0b0111000) return 1;			// 0 1110xx	B
	if((key & 0b1111110) == 0b0111100) return 1;			// 0 11110x	B
	//if((key & 0b1111111) == 0b0111110) return "RESERVED";	// 0 111110	RESERVED
	//if((key & 0b1111111) == 0b0111111) return "RESERVED";	// 0 111111	RESERVED
	if((key & 0b1000000) == 0b1000000) return 8;			// 1 xxxxxx	D
	return 0;
}

unsigned size_spec_method3(int x)
{
	if((x & 0b01111) == 0b00000) return 0;					// x0000 RESERVED
	if((x & 0b00001) == 0b00001) return 1;					// xxxx1 B
	if((x & 0b00011) == 0b00010) return 2;					// xxx10 H
	if((x & 0b00111) == 0b00100) return 4;					// xx100 S
	if((x & 0b01111) == 0b01000) return 8;					// x1000 D
	return 0;
}

unsigned table_s_d[2] = {4, 8};
unsigned table_b_d_h_s[4] = {1, 8, 2, 4};
unsigned table_b_h_s_d[4] = {1, 2, 4, 8};
unsigned table_d_b_h_s[4] = {8, 1, 2, 4};
unsigned table_r_h_s_d[4] = {0, 2, 4, 8};
unsigned table_r_s_d_r[4] = {0, 4, 8, 0};

//-----------------------------------------------------------------------------
// other tables
//-----------------------------------------------------------------------------


enum Condition table_cond[16] = {COND_EQ, COND_NE, COND_CS, COND_CC, COND_MI, COND_PL, COND_VS, COND_VC, COND_HI, COND_LS, COND_GE, COND_LT, COND_GT, COND_LE, COND_AL, COND_NV};
enum Condition table_cond_neg[16] = {COND_NE, COND_EQ, COND_CC, COND_CS, COND_PL, COND_MI, COND_VC, COND_VS, COND_LS, COND_HI, COND_LT, COND_GE, COND_LE, COND_GT, COND_NV, COND_AL};

float table_imm8_to_float[256] = {
	2.000000000000000000e+00, 2.125000000000000000e+00, 2.250000000000000000e+00, 2.375000000000000000e+00,
	2.500000000000000000e+00, 2.625000000000000000e+00, 2.750000000000000000e+00, 2.875000000000000000e+00,
	3.000000000000000000e+00, 3.125000000000000000e+00, 3.250000000000000000e+00, 3.375000000000000000e+00,
	3.500000000000000000e+00, 3.625000000000000000e+00, 3.750000000000000000e+00, 3.875000000000000000e+00,
	4.000000000000000000e+00, 4.250000000000000000e+00, 4.500000000000000000e+00, 4.750000000000000000e+00,
	5.000000000000000000e+00, 5.250000000000000000e+00, 5.500000000000000000e+00, 5.750000000000000000e+00,
	6.000000000000000000e+00, 6.250000000000000000e+00, 6.500000000000000000e+00, 6.750000000000000000e+00,
	7.000000000000000000e+00, 7.250000000000000000e+00, 7.500000000000000000e+00, 7.750000000000000000e+00,
	8.000000000000000000e+00, 8.500000000000000000e+00, 9.000000000000000000e+00, 9.500000000000000000e+00,
	1.000000000000000000e+01, 1.050000000000000000e+01, 1.100000000000000000e+01, 1.150000000000000000e+01,
	1.200000000000000000e+01, 1.250000000000000000e+01, 1.300000000000000000e+01, 1.350000000000000000e+01,
	1.400000000000000000e+01, 1.450000000000000000e+01, 1.500000000000000000e+01, 1.550000000000000000e+01,
	1.600000000000000000e+01, 1.700000000000000000e+01, 1.800000000000000000e+01, 1.900000000000000000e+01,
	2.000000000000000000e+01, 2.100000000000000000e+01, 2.200000000000000000e+01, 2.300000000000000000e+01,
	2.400000000000000000e+01, 2.500000000000000000e+01, 2.600000000000000000e+01, 2.700000000000000000e+01,
	2.800000000000000000e+01, 2.900000000000000000e+01, 3.000000000000000000e+01, 3.100000000000000000e+01,
	1.250000000000000000e-01, 1.328125000000000000e-01, 1.406250000000000000e-01, 1.484375000000000000e-01,
	1.562500000000000000e-01, 1.640625000000000000e-01, 1.718750000000000000e-01, 1.796875000000000000e-01,
	1.875000000000000000e-01, 1.953125000000000000e-01, 2.031250000000000000e-01, 2.109375000000000000e-01,
	2.187500000000000000e-01, 2.265625000000000000e-01, 2.343750000000000000e-01, 2.421875000000000000e-01,
	2.500000000000000000e-01, 2.656250000000000000e-01, 2.812500000000000000e-01, 2.968750000000000000e-01,
	3.125000000000000000e-01, 3.281250000000000000e-01, 3.437500000000000000e-01, 3.593750000000000000e-01,
	3.750000000000000000e-01, 3.906250000000000000e-01, 4.062500000000000000e-01, 4.218750000000000000e-01,
	4.375000000000000000e-01, 4.531250000000000000e-01, 4.687500000000000000e-01, 4.843750000000000000e-01,
	5.000000000000000000e-01, 5.312500000000000000e-01, 5.625000000000000000e-01, 5.937500000000000000e-01,
	6.250000000000000000e-01, 6.562500000000000000e-01, 6.875000000000000000e-01, 7.187500000000000000e-01,
	7.500000000000000000e-01, 7.812500000000000000e-01, 8.125000000000000000e-01, 8.437500000000000000e-01,
	8.750000000000000000e-01, 9.062500000000000000e-01, 9.375000000000000000e-01, 9.687500000000000000e-01,
	1.000000000000000000e+00, 1.062500000000000000e+00, 1.125000000000000000e+00, 1.187500000000000000e+00,
	1.250000000000000000e+00, 1.312500000000000000e+00, 1.375000000000000000e+00, 1.437500000000000000e+00,
	1.500000000000000000e+00, 1.562500000000000000e+00, 1.625000000000000000e+00, 1.687500000000000000e+00,
	1.750000000000000000e+00, 1.812500000000000000e+00, 1.875000000000000000e+00, 1.937500000000000000e+00,
	-2.000000000000000000e+00, -2.125000000000000000e+00, -2.250000000000000000e+00, -2.375000000000000000e+00,
	-2.500000000000000000e+00, -2.625000000000000000e+00, -2.750000000000000000e+00, -2.875000000000000000e+00,
	-3.000000000000000000e+00, -3.125000000000000000e+00, -3.250000000000000000e+00, -3.375000000000000000e+00,
	-3.500000000000000000e+00, -3.625000000000000000e+00, -3.750000000000000000e+00, -3.875000000000000000e+00,
	-4.000000000000000000e+00, -4.250000000000000000e+00, -4.500000000000000000e+00, -4.750000000000000000e+00,
	-5.000000000000000000e+00, -5.250000000000000000e+00, -5.500000000000000000e+00, -5.750000000000000000e+00,
	-6.000000000000000000e+00, -6.250000000000000000e+00, -6.500000000000000000e+00, -6.750000000000000000e+00,
	-7.000000000000000000e+00, -7.250000000000000000e+00, -7.500000000000000000e+00, -7.750000000000000000e+00,
	-8.000000000000000000e+00, -8.500000000000000000e+00, -9.000000000000000000e+00, -9.500000000000000000e+00,
	-1.000000000000000000e+01, -1.050000000000000000e+01, -1.100000000000000000e+01, -1.150000000000000000e+01,
	-1.200000000000000000e+01, -1.250000000000000000e+01, -1.300000000000000000e+01, -1.350000000000000000e+01,
	-1.400000000000000000e+01, -1.450000000000000000e+01, -1.500000000000000000e+01, -1.550000000000000000e+01,
	-1.600000000000000000e+01, -1.700000000000000000e+01, -1.800000000000000000e+01, -1.900000000000000000e+01,
	-2.000000000000000000e+01, -2.100000000000000000e+01, -2.200000000000000000e+01, -2.300000000000000000e+01,
	-2.400000000000000000e+01, -2.500000000000000000e+01, -2.600000000000000000e+01, -2.700000000000000000e+01,
	-2.800000000000000000e+01, -2.900000000000000000e+01, -3.000000000000000000e+01, -3.100000000000000000e+01,
	-1.250000000000000000e-01, -1.328125000000000000e-01, -1.406250000000000000e-01, -1.484375000000000000e-01,
	-1.562500000000000000e-01, -1.640625000000000000e-01, -1.718750000000000000e-01, -1.796875000000000000e-01,
	-1.875000000000000000e-01, -1.953125000000000000e-01, -2.031250000000000000e-01, -2.109375000000000000e-01,
	-2.187500000000000000e-01, -2.265625000000000000e-01, -2.343750000000000000e-01, -2.421875000000000000e-01,
	-2.500000000000000000e-01, -2.656250000000000000e-01, -2.812500000000000000e-01, -2.968750000000000000e-01,
	-3.125000000000000000e-01, -3.281250000000000000e-01, -3.437500000000000000e-01, -3.593750000000000000e-01,
	-3.750000000000000000e-01, -3.906250000000000000e-01, -4.062500000000000000e-01, -4.218750000000000000e-01,
	-4.375000000000000000e-01, -4.531250000000000000e-01, -4.687500000000000000e-01, -4.843750000000000000e-01,
	-5.000000000000000000e-01, -5.312500000000000000e-01, -5.625000000000000000e-01, -5.937500000000000000e-01,
	-6.250000000000000000e-01, -6.562500000000000000e-01, -6.875000000000000000e-01, -7.187500000000000000e-01,
	-7.500000000000000000e-01, -7.812500000000000000e-01, -8.125000000000000000e-01, -8.437500000000000000e-01,
	-8.750000000000000000e-01, -9.062500000000000000e-01, -9.375000000000000000e-01, -9.687500000000000000e-01,
	-1.000000000000000000e+00, -1.062500000000000000e+00, -1.125000000000000000e+00, -1.187500000000000000e+00,
	-1.250000000000000000e+00, -1.312500000000000000e+00, -1.375000000000000000e+00, -1.437500000000000000e+00,
	-1.500000000000000000e+00, -1.562500000000000000e+00, -1.625000000000000000e+00, -1.687500000000000000e+00,
	-1.750000000000000000e+00, -1.812500000000000000e+00, -1.875000000000000000e+00, -1.937500000000000000e+00
};

const char *reg_lookup_c[16] = {
	"c0",  "c1",  "c2",  "c3",  "c4",  "c5",  "c6",  "c7", "c8",  "c9",  "c10",
	"c11", "c12", "c13", "c14", "c15"
};

#define ABCDEFGH ((dec->a<<7)|(dec->b<<6)|(dec->c<<5)|(dec->d<<4)|(dec->e<<3)|(dec->f<<2)|(dec->g<<1)|dec->h)
#define IMMR dec->immr
#define IMMS dec->imms
#define INDEX dec->index

/* register operand macros */
#define ADD_OPERAND_REG(REGSET, BASE, REGNUM) \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, 0, 0); \
	i++;

#define ADD_OPERAND_REG_SZ(REGSET, BASE, REGNUM, DSIZE, ESIZE) \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, DSIZE, ESIZE); \
	i++;

#define ADD_OPERAND_BT ADD_OPERAND_REG(REGSET_ZR, REG_B_BASE, dec->t);

#define ADD_OPERAND_DA ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->a);
#define ADD_OPERAND_DD ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
#define ADD_OPERAND_DN ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->n);
#define ADD_OPERAND_DM ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->m);
#define ADD_OPERAND_DT ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->t);
#define ADD_OPERAND_DT1 ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->t);
#define ADD_OPERAND_DT2 ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->t2);

#define ADD_OPERAND_HA ADD_OPERAND_REG(REGSET_ZR, REG_H_BASE, dec->a);
#define ADD_OPERAND_HD ADD_OPERAND_REG(REGSET_ZR, REG_H_BASE, dec->d);
#define ADD_OPERAND_HN ADD_OPERAND_REG(REGSET_ZR, REG_H_BASE, dec->n);
#define ADD_OPERAND_HM ADD_OPERAND_REG(REGSET_ZR, REG_H_BASE, dec->m);
#define ADD_OPERAND_HT ADD_OPERAND_REG(REGSET_ZR, REG_H_BASE, dec->t);

#define ADD_OPERAND_QA ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->a);
#define ADD_OPERAND_QD ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->d);
#define ADD_OPERAND_QDN ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->n);
#define ADD_OPERAND_QN ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->n);
#define ADD_OPERAND_QM ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->m);
#define ADD_OPERAND_QS ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->s);
#define ADD_OPERAND_QT ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->t);
#define ADD_OPERAND_QT1 ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->t);
#define ADD_OPERAND_QT2 ADD_OPERAND_REG(REGSET_ZR, REG_Q_BASE, dec->t2);

#define ADD_OPERAND_SA ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->a);
#define ADD_OPERAND_SD ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->d);
#define ADD_OPERAND_SN ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->n);
#define ADD_OPERAND_SM ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->m);
#define ADD_OPERAND_ST ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->t);
#define ADD_OPERAND_ST1 ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->t);
#define ADD_OPERAND_ST2 ADD_OPERAND_REG(REGSET_ZR, REG_S_BASE, dec->t2);

#define ADD_OPERAND_WA ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->a);
#define ADD_OPERAND_WD ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->d);
#define ADD_OPERAND_WDN ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->dn);
#define ADD_OPERAND_WN ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->n);
#define ADD_OPERAND_WM ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->m);
#define ADD_OPERAND_WS ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->s);
#define ADD_OPERAND_WT ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->t);;
#define ADD_OPERAND_WT1 ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->t);
#define ADD_OPERAND_WT2 ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, dec->t2);

#define ADD_OPERAND_WS_PLUS_1 ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, (dec->s+1)%32);
#define ADD_OPERAND_WT_PLUS_1 ADD_OPERAND_REG(REGSET_ZR, REG_W_BASE, (dec->t+1)%32);

#define ADD_OPERAND_WD_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->d);
#define ADD_OPERAND_WN_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->n);
#define ADD_OPERAND_WM_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->m);
#define ADD_OPERAND_WT_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->n);

#define ADD_OPERAND_XA ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->a);
#define ADD_OPERAND_XD ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->d);
#define ADD_OPERAND_XDN ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->Rdn);
#define ADD_OPERAND_XN ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->n);
#define ADD_OPERAND_XM ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->m);
#define ADD_OPERAND_XS ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->s);
#define ADD_OPERAND_XT ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->t);
#define ADD_OPERAND_XT1 ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->t);
#define ADD_OPERAND_XT2 ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, dec->t2);

#define ADD_OPERAND_XS_PLUS_1 ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, (dec->s+1)%32);
#define ADD_OPERAND_XT_PLUS_1 ADD_OPERAND_REG(REGSET_ZR, REG_X_BASE, (dec->t+1)%32);

#define ADD_OPERAND_XD_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->d);
#define ADD_OPERAND_XN_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->n);
#define ADD_OPERAND_XDN_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->n);
#define ADD_OPERAND_XM_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->m);
#define ADD_OPERAND_XT_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->t);
#define ADD_OPERAND_XT2_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->t2);

#define ADD_OPERAND_ZD ADD_OPERAND_REG(REGSET_ZR, REG_Z_BASE, dec->d);
#define ADD_OPERAND_ZM ADD_OPERAND_REG(REGSET_ZR, REG_Z_BASE, dec->m);
#define ADD_OPERAND_ZN ADD_OPERAND_REG(REGSET_ZR, REG_Z_BASE, dec->n);
#define ADD_OPERAND_ZT ADD_OPERAND_REG(REGSET_ZR, REG_Z_BASE, dec->t);
#define ADD_OPERAND_ZDA

#define ADD_OPERAND_PRED_REG(REGNUM) \
	ADD_OPERAND_REG(REGSET_ZR, REG_P_BASE, REGNUM);

#define ADD_OPERAND_PRED_REG_ESIZE(REGNUM, ELEM_SZ) \
	ADD_OPERAND_REG_SZ(REGSET_ZR, REG_P_BASE, REGNUM, 0, ELEM_SZ);

#define ADD_OPERAND_PRED_REG_QUAL(REGNUM, QUALIFIER) \
	ADD_OPERAND_REG(REGSET_ZR, REG_P_BASE, REGNUM); \
	dec->operands[i-1].pred_qual = QUALIFIER;

/* register indirect adder */
#define ADD_OPERAND_MEM_REG(REGSET, BASE, REGNUM) \
	dec->operands[i].operandClass = MEM_REG; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, 0, 0); \
	i++

#define ADD_OPERAND_MEM_WA ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->a);
#define ADD_OPERAND_MEM_WD ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->d);
#define ADD_OPERAND_MEM_WDN ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->n);
#define ADD_OPERAND_MEM_WN ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->n);
#define ADD_OPERAND_MEM_WM ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->m);
#define ADD_OPERAND_MEM_WS ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->s);
#define ADD_OPERAND_MEM_WT ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->t);
#define ADD_OPERAND_MEM_WT1 ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->t);
#define ADD_OPERAND_MEM_WT2 ADD_OPERAND_MEM_REG(REGSET_ZR, REG_W_BASE, dec->t2);

#define ADD_OPERAND_MEM_WN_SP ADD_OPERAND_MEM_REG(REGSET_SP, REG_W_BASE, dec->n);

#define ADD_OPERAND_MEM_XA ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->a);
#define ADD_OPERAND_MEM_XD ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->d);
#define ADD_OPERAND_MEM_XDN ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->n);
#define ADD_OPERAND_MEM_XN ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->n);
#define ADD_OPERAND_MEM_XM ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->m);
#define ADD_OPERAND_MEM_XS ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->s);
#define ADD_OPERAND_MEM_XT ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->t);
#define ADD_OPERAND_MEM_XT1 ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->t);
#define ADD_OPERAND_MEM_XT2 ADD_OPERAND_MEM_REG(REGSET_ZR, REG_X_BASE, dec->t2);

#define ADD_OPERAND_MEM_XN_SP ADD_OPERAND_MEM_REG(REGSET_SP, REG_X_BASE, dec->n);

/* general register indirect + offset adder */
#define ADD_OPERAND_MEM_REG_OFFSET(REGSET, BASE, REGNUM, OFFSET) \
	dec->operands[i].operandClass = MEM_OFFSET; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, 0, 0); \
	dec->operands[i].immediate = OFFSET; \
	dec->operands[i].signedImm = 1; \
	i++;

#define ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET, BASE, REGNUM, OFFSET, DSIZE, ESIZE) \
	dec->operands[i].operandClass = MEM_OFFSET; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, DSIZE, ESIZE); \
	dec->operands[i].immediate = OFFSET; \
	dec->operands[i].signedImm = 1; \
	i++;

#define ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET, BASE, REGNUM, OFFSET) \
	ADD_OPERAND_MEM_REG_OFFSET(REGSET, BASE, REGNUM, OFFSET); \
	dec->operands[i-1].mul_vl = 1;

/* general mem post index */
#define ADD_OPERAND_MEM_POST_INDEX(REGSET, BASE, REGNUM, OFFSET) \
	dec->operands[i].operandClass = MEM_POST_IDX; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, 0, 0); \
	dec->operands[i].immediate = OFFSET; \
	dec->operands[i].signedImm = 1;

/* mem pre index */
#define ADD_OPERAND_MEM_PRE_INDEX(REGSET, BASE, REGNUM, OFFSET) \
	dec->operands[i].operandClass = MEM_PRE_IDX; \
	dec->operands[i].reg[0] = REG(REGSET, BASE, REGNUM, 0, 0); \
	dec->operands[i].immediate = OFFSET; \
	dec->operands[i].signedImm = 1;

/* mem extended, like:
	ldrb w3, [x27, x18, lsl #0x0] */
#define ADD_OPERAND_MEM_EXTENDED(BASE, REGNUM0, REGNUM1) \
	dec->operands[i].operandClass = MEM_EXTENDED; \
	dec->operands[i].reg[0] = REG(REGSET_SP, REG_X_BASE, REGNUM0, 0, 0); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, BASE, REGNUM1, 0, 0); \
	i++;

#define ADD_OPERAND_XN_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->n);
#define ADD_OPERAND_XM_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->m);
#define ADD_OPERAND_XT_SP ADD_OPERAND_REG(REGSET_SP, REG_X_BASE, dec->t);

#define ADD_OPERAND_WD_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->d);
#define ADD_OPERAND_WN_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->n);
#define ADD_OPERAND_WM_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->m);
#define ADD_OPERAND_WT_SP ADD_OPERAND_REG(REGSET_SP, REG_W_BASE, dec->n);

#define ADD_OPERAND_MEM_EXTENDED_SZ(BASE0, REGNUM0, BASE1, REGNUM1, ELEM_SZ) \
	dec->operands[i].operandClass = MEM_EXTENDED; \
	dec->operands[i].reg[0] = REG(REGSET_SP, BASE0, REGNUM0, 0, ELEM_SZ); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, BASE1, REGNUM1, 0, ELEM_SZ); \
	i++;

#define ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(BASE0, REGNUM0, SZ0, BASE1, REGNUM1, SZ1, SHIFT_TYPE, SHIFT_AMT, SHIFT_USED) \
	dec->operands[i].operandClass = MEM_EXTENDED; \
	dec->operands[i].reg[0] = REG(REGSET_SP, BASE0, REGNUM0, 0, SZ0); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, BASE1, REGNUM1, 0, SZ1); \
	dec->operands[i].shiftType = SHIFT_TYPE; \
	dec->operands[i].shiftValue = SHIFT_AMT; \
	dec->operands[i].shiftValueUsed = SHIFT_USED; \
	i += 1;

/* general immediate operand adder */
#define ADD_OPERAND_IMMEDIATE32(VALUE, SIGNED) \
	dec->operands[i].operandClass = IMM32; \
	dec->operands[i].signedImm = SIGNED; \
	dec->operands[i].immediate = VALUE; \
	i++;

#define ADD_OPERAND_IMMEDIATE64(VALUE, SIGNED) \
	dec->operands[i].operandClass = IMM64; \
	dec->operands[i].signedImm = SIGNED; \
	dec->operands[i].immediate = VALUE; \
	i++;

#define ADD_OPERAND_FLOAT32(VALUE) \
	dec->operands[i].operandClass = FIMM32; \
	*(float *)&(dec->operands[i].immediate) = VALUE; \
	i++;

#define ADD_OPERAND_CONST ADD_OPERAND_IMMEDIATE64(const_, 0)
#define ADD_OPERAND_FBITS ADD_OPERAND_IMMEDIATE32(fbits, 0)
#define ADD_OPERAND_FIMM ADD_OPERAND_FLOAT32(fimm)
#define ADD_OPERAND_UIMM32 ADD_OPERAND_IMMEDIATE32(imm, 0)
#define ADD_OPERAND_IMM32 ADD_OPERAND_IMMEDIATE32(imm, 1)
#define ADD_OPERAND_UIMM64 ADD_OPERAND_IMMEDIATE64(imm, 0)
#define ADD_OPERAND_IMM64 ADD_OPERAND_IMMEDIATE64(imm, 1)
#define ADD_OPERAND_IMM0 ADD_OPERAND_IMMEDIATE32(0, 0)
#define ADD_OPERAND_IMM1 ADD_OPERAND_IMMEDIATE32(imm1, 0)
#define ADD_OPERAND_IMM2 ADD_OPERAND_IMMEDIATE32(imm2, 0)
#define ADD_OPERAND_IMM6 ADD_OPERAND_IMMEDIATE32(imm6, 0)
#define ADD_OPERAND_IMM8 ADD_OPERAND_IMMEDIATE32(imm8, 0)
#define ADD_OPERAND_LSB ADD_OPERAND_IMMEDIATE32(lsb, 0)
#define ADD_OPERAND_NZCV ADD_OPERAND_IMMEDIATE32(dec->nzcv, 0)
#define ADD_OPERAND_ROTATE ADD_OPERAND_IMMEDIATE32(rotate, 0)
#define ADD_OPERAND_WIDTH ADD_OPERAND_IMMEDIATE32(width, 0)

//#define SEXT4(x) (x & 0x

/* string immediate (like "mul #0x12") */
#define ADD_OPERAND_STR_IMM(STRING, VALUE) \
	dec->operands[i].operandClass = STR_IMM; \
	dec->operands[i].immediate = VALUE; \
	dec->operands[i].signedImm = 0; \
	strcpy(dec->operands[i].name, STRING); \
	i++;

/* specialized immediate operands */
#define ADD_OPERAND_NAME(VALUE) \
	dec->operands[i].operandClass = NAME; \
	strcpy(dec->operands[i].name, VALUE); \
	i++;

#define ADD_OPERAND_VA
#define ADD_OPERAND_VD
#define ADD_OPERAND_VN
#define ADD_OPERAND_VN_PLUS_1
#define ADD_OPERAND_VN_PLUS_2
#define ADD_OPERAND_VN_PLUS_3
#define ADD_OPERAND_VM
#define ADD_OPERAND_VT

/* multi reg stuff, like {v0.b, v1.b} */
#define ADD_OPERAND_MULTIREG_1(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i].operandClass = MULTI_REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_BASE, REGNUM, DSIZE, ESIZE); \
	i++;

#define ADD_OPERAND_MULTIREG_2(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i].operandClass = MULTI_REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_BASE, REGNUM, DSIZE, ESIZE); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, REG_BASE, (REGNUM+1)%32, DSIZE, ESIZE); \
	i++;

#define ADD_OPERAND_MULTIREG_3(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i].operandClass = MULTI_REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_BASE, REGNUM, DSIZE, ESIZE); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, REG_BASE, (REGNUM+1)%32, DSIZE, ESIZE); \
	dec->operands[i].reg[2] = REG(REGSET_ZR, REG_BASE, (REGNUM+2)%32, DSIZE, ESIZE); \
	i++;

#define ADD_OPERAND_MULTIREG_4(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i].operandClass = MULTI_REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_BASE, REGNUM, DSIZE, ESIZE); \
	dec->operands[i].reg[1] = REG(REGSET_ZR, REG_BASE, (REGNUM+1)%32, DSIZE, ESIZE); \
	dec->operands[i].reg[2] = REG(REGSET_ZR, REG_BASE, (REGNUM+2)%32, DSIZE, ESIZE); \
	dec->operands[i].reg[3] = REG(REGSET_ZR, REG_BASE, (REGNUM+3)%32, DSIZE, ESIZE); \
	i++;

#define ADD_OPERAND_MULTIREG_1_INDEXED(REG_BASE, DSIZE, ESIZE, REGNUM); \
	ADD_OPERAND_MULTIREG_1(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i-1].indexUsed = 1; \
	dec->operands[i-1].index = dec->index;

#define ADD_OPERAND_MULTIREG_2_INDEXED(REG_BASE, DSIZE, ESIZE, REGNUM); \
	ADD_OPERAND_MULTIREG_2(REG_BASE, DSIZE, ESIZE, REGNUM); \
	dec->operands[i-1].indexUsed = 1; \
	dec->operands[i-1].index = dec->index;

#define ADD_OPERAND_MULTIREG_3_INDEXED(REG_BASE, DSIZE, ESIZE, REGNUM); \
	ADD_OPERAND_MULTIREG_3(REG_BASE, DSIZE, ESIZE, REGNUM) \
	dec->operands[i-1].indexUsed = 1; \
	dec->operands[i-1].index = dec->index;

#define ADD_OPERAND_MULTIREG_4_INDEXED(REG_BASE, DSIZE, ESIZE, REGNUM); \
	ADD_OPERAND_MULTIREG_4(REG_BASE, DSIZE, ESIZE, REGNUM) \
	dec->operands[i-1].indexUsed = 1; \
	dec->operands[i-1].index = dec->index;

/* v register plus ARRANGEMENT specifier: {1,2,4,8,16} x {b,h,s,d,q} */
#define ADD_OPERAND_REG_T(BASE, ARR_SPEC, REGNUM) \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, BASE, REGNUM, ARR_SPEC.data_sz, ARR_SPEC.elem_sz); \
	i++;

#define ADD_OPERAND_VREG_T(ARR_SPEC, REGNUM) \
	ADD_OPERAND_REG_T(REG_V_BASE, ARR_SPEC, REGNUM)

#define ADD_OPERAND_VREG_TA(REGNUM) ADD_OPERAND_VREG_T(arr_spec_a, REGNUM)
#define ADD_OPERAND_VREG_TB(REGNUM) ADD_OPERAND_VREG_T(arr_spec_b, REGNUM)
#define ADD_OPERAND_VREG_TS(REGNUM) ADD_OPERAND_VREG_T(arr_spec_s, REGNUM)

#define ADD_OPERAND_VREG_T_INDEXED(ARR_SPEC, REGNUM, INDEX) \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_V_BASE, REGNUM, ARR_SPEC.data_sz, ARR_SPEC.elem_sz); \
	dec->operands[i].index = INDEX; \
	dec->operands[i].indexUsed = 1; \
	i++;

#define ADD_OPERAND_ZREG_T_INDEXED(ARR_SPEC, REGNUM, INDEX) \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_Z_BASE, REGNUM, ARR_SPEC.data_sz, ARR_SPEC.elem_sz); \
	dec->operands[i].index = INDEX; \
	dec->operands[i].indexUsed = 1; \
	i++;

#define ADD_OPERAND_ZREG_T(ARR_SPEC, REGNUM) \
	ADD_OPERAND_REG_T(REG_Z_BASE, ARR_SPEC, REGNUM)

/* v register plus ELEMENT SIZE specifier: {b,h,s,d,q} */
#define ADD_OPERAND_VREG_ESIZE(ELEM_SZ, REGNUM); \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_V_BASE, REGNUM, 0, ELEM_SZ); \
	i++;

#define ADD_OPERAND_ZREG_ESIZE(ELEM_SZ, REGNUM); \
	dec->operands[i].operandClass = REG; \
	dec->operands[i].reg[0] = REG(REGSET_ZR, REG_Z_BASE, REGNUM, 0, ELEM_SZ); \
	i++;

#define ADD_OPERAND_VREG_ESIZE_INDEXED(ELEM_SZ, REGNUM, INDEX_VALUE) \
	ADD_OPERAND_VREG_ESIZE(ELEM_SZ, REGNUM); \
	dec->operands[i-1].index = INDEX_VALUE; \
	dec->operands[i-1].indexUsed = 1;

#define ADD_OPERAND_ZREG_ESIZE_INDEXED(ELEM_SZ, REGNUM, INDEX_VALUE) \
	ADD_OPERAND_ZREG_ESIZE(ELEM_SZ, REGNUM); \
	dec->operands[i-1].index = INDEX_VALUE; \
	dec->operands[i-1].indexUsed = 1;

#define ADD_OPERAND_VREG_TA_INDEXED(REGNUM,INDEX) ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz_a,REGNUM,INDEX)
#define ADD_OPERAND_VREG_TB_INDEXED(REGNUM,INDEX) ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz_b,REGNUM,INDEX)
#define ADD_OPERAND_VREG_TS_INDEXED(REGNUM,INDEX) ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz_s,REGNUM,INDEX)

#define ADD_OPERAND_COND \
	dec->operands[i].operandClass = CONDITION; \
	dec->operands[i].reg[0] = table_cond[dec->condition]; \
	i++;

#define ADD_OPERAND_COND_NEG \
	dec->operands[i].operandClass = CONDITION; \
	dec->operands[i].reg[0] = table_cond_neg[dec->condition]; \
	i++;

#define ADD_OPERAND_IMMR
#define ADD_OPERAND_IMMS
#define ADD_OPERAND_INDEX

#define ADD_OPERAND_LABEL \
	dec->operands[i].operandClass = LABEL; \
	dec->operands[i].immediate = eaddr; \
	i++;

#define ADD_OPERAND_SYSTEMREG \
	ccp_tmp = get_system_register_name_decomposed(dec->sys_op0, dec->sys_op1, dec->sys_crn, dec->sys_crm, dec->sys_op2); \
	if(ccp_tmp[0] != '\0') { \
		dec->operands[i].operandClass = SYS_REG; \
		dec->operands[i].reg[0] = ((dec->sys_op0<<14)|(dec->sys_op1<<11)|(dec->sys_crn<<7)|(dec->sys_crm<<3)|dec->sys_op2); \
		i++; \
	} \
	else { \
		dec->operands[i].operandClass = IMPLEMENTATION_SPECIFIC; \
		dec->operands[i].reg[0] = dec->sys_op0; \
		dec->operands[i].reg[1] = dec->sys_op1; \
		dec->operands[i].reg[2] = dec->sys_crn; \
		dec->operands[i].reg[3] = dec->sys_crm; \
		dec->operands[i].reg[4] = dec->sys_op2; \
		i++; \
	} \

#define ADD_OPERAND_PATTERN \
	if(dec->pattern>0b1101 && dec->pattern<0b11101) { \
		ADD_OPERAND_IMMEDIATE32(dec->pattern, 0); \
	} \
	else { \
		ADD_OPERAND_NAME(pattern_lookup(dec->pattern, dec->imm)); \
	}

//-----------------------------------------------------------------------------
// register base lookups
//-----------------------------------------------------------------------------

unsigned rwwwx_0123x_reg(int x, int r)
{
	if((x & 0b01111) == 0b00000) return 0;			// x0000 RESERVED
	if((x & 0b00001) == 0b00001) return REG_W_BASE;	// xxxx1 W
	if((x & 0b00011) == 0b00010) return REG_W_BASE;	// xxx10 W
	if((x & 0b00111) == 0b00100) return REG_W_BASE;	// xx100 W
	if((x & 0b01111) == 0b01000) return REG_X_BASE;	// x1000 X
	return 0;
}

unsigned rbhsdq_5bit_reg(unsigned key)
{
	//if((key & 0b01111) == 0b00000) return 0;			// x0000 RESERVED
	if(key == 0) return 0;								// x0000 RESERVED
	if((key & 0b00001) == 0b00001) return REG_B_BASE;	// xxxx1 B
	if((key & 0b00011) == 0b00010) return REG_H_BASE;	// xxx10 H
	if((key & 0b00111) == 0b00100) return REG_S_BASE;	// xx100 S
	if((key & 0b01111) == 0b01000) return REG_D_BASE;	// xx100 D
	if((key & 0b11111) == 0b10000) return REG_Q_BASE;	// xx100 Q
	return 0;
}

unsigned wwwx_0123_reg(unsigned size)
{
	if(size == 0b11) return REG_X_BASE;
	return REG_W_BASE;
}

unsigned sd_01_reg(int v)
{
	switch(v & 1) {
		case 0: return REG_S_BASE;
		case 1: return REG_D_BASE;
	}
	return 0;
}

// <V><d>, <V><n>, <V><m>
unsigned bhsd_0123_reg(int v)
{
	switch(v & 3) {
		case 0: return REG_B_BASE;
		case 1: return REG_H_BASE;
		case 2: return REG_S_BASE;
		case 3: return REG_D_BASE;
	}
	return 0;
}

unsigned rsdr_0123_reg(int v)
{
	switch(v & 3) {
		case 1: return REG_S_BASE;
		case 2: return REG_D_BASE;
	}
	return 0;
}

unsigned hsdr_0123_reg(int v)
{
	switch(v & 3) {
		case 0: return REG_H_BASE;
		case 1: return REG_S_BASE;
		case 2: return REG_D_BASE;
		default: return 0;
	}
}

unsigned rhsd_0123_reg(int v)
{
	if(v == 1) return REG_H_BASE;
	if(v == 2) return REG_S_BASE;
	return 0;
}

unsigned rhsd_0123x_reg(int v)
{
	//if(x & 0xE == 0) return 0;		// 000x
	if((v & 0xE) == 2) return REG_H_BASE;	// 001x
	if((v & 0xC) == 4) return REG_S_BASE;	// 01xx
	if((v & 0x8) == 8) return REG_D_BASE;	// 1xxx
	return 0;
}

unsigned rbhsd_0123x_reg(int v)
{														// 0000 RESERVED
	if(v == 1) return REG_B_BASE;					// 0001 B
	if((v & 0b1110) == 0b0010) return REG_H_BASE;	// 001x H
	if((v & 0b1100) == 0b0100) return REG_S_BASE;	// 01xx S
	if((v & 0b1000) == 0b1000) return REG_D_BASE;	// 1xxx D
	return 0;
}

unsigned rhsdr_0123x_reg(int v)
{
	if(v == 1) return REG_H_BASE;
	if((v & 0b1110) == 0b0010) return REG_S_BASE;
	if((v & 0b1100) == 0b0100) return REG_D_BASE;
	return 0;
}

#define OPTIONAL_SHIFT_AMOUNT \
			if(!(dec->shift_type==1 && dec->shift_amount==0)) { \
				dec->operands[i-1].shiftType = dec->shift_type; \
				dec->operands[i-1].shiftValue = dec->shift_amount; \
				dec->operands[i-1].shiftValueUsed = 1; \
			} \
			else { \
				dec->operands[i-1].shiftValueUsed = 0; \
			}

#define OPTIONAL_EXTEND_AMOUNT(SPECIAL_LSL) \
			dec->operands[i-1].shiftType = dec->extend_type; \
			dec->operands[i-1].shiftValue = dec->shift; \
			if(dec->option == SPECIAL_LSL) { \
				if(dec->shift) { \
					dec->operands[i-1].shiftType = ShiftType_LSL; \
					dec->operands[i-1].shiftValueUsed = 1; \
				} \
				else \
					dec->operands[i-1].shiftType = ShiftType_NONE; \
			} \
			else { \
				dec->operands[i-1].shiftValueUsed = dec->shift ? 1 : 0; \
			}

#define OPTIONAL_EXTEND_AMOUNT_0 \
			dec->operands[i-1].shiftType = dec->extend_type; \
			dec->operands[i-1].shiftValue = 0; \
			dec->operands[i-1].shiftValueUsed = dec->S ? 1 : 0;

#define OPTIONAL_EXTEND_LSL0 \
			if(dec->S) { \
				dec->operands[i-1].shiftType = ShiftType_LSL; \
				dec->operands[i-1].shiftValue = 0; \
				dec->operands[i-1].shiftValueUsed = 1; \
			} \
			else \
				dec->operands[i-1].shiftType = ShiftType_NONE; \

#define OPTIONAL_EXTEND_AMOUNT_32(EXCEPTIONAL_REG) \
			ShiftType st = DecodeRegExtend(dec->option); \
			if(st == ShiftType_UXTW) { \
				if(EXCEPTIONAL_REG==31 && dec->imm3 != 0) { \
					st = ShiftType_LSL; \
				} \
			} \
			dec->operands[i-1].shiftType = st; \
			dec->operands[i-1].shiftValue = dec->shift; \
			if(dec->shift) { \
				dec->operands[i-1].shiftValueUsed = 1; \
			} \

#define OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR0 \
			ShiftType st = DecodeRegExtend(dec->option); \
			if(dec->Rn==31 && dec->option == 3) { \
				st = ShiftType_LSL; \
				if(dec->imm3 == 0) \
					st = ShiftType_NONE; \
			} \
			if(st != ShiftType_NONE) { \
				dec->operands[i-1].shiftType = st; \
				dec->operands[i-1].shiftValue = dec->shift; \
				dec->operands[i-1].shiftValueUsed = 1; \
			} \
			if(!dec->shift) { \
				dec->operands[i-1].shiftValueUsed = 0; \
			}

#define OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR1 \
			ShiftType st = DecodeRegExtend(dec->option); \
			if((dec->Rd==31 || dec->Rn==31) && dec->option == 3) { \
				st = ShiftType_LSL; \
				if(dec->imm3 == 0) \
					st = ShiftType_NONE; \
			} \
			if(st != ShiftType_NONE) { \
				dec->operands[i-1].shiftType = st; \
				dec->operands[i-1].shiftValue = dec->shift; \
				dec->operands[i-1].shiftValueUsed = 1; \
			} \
			if(!dec->shift) { \
				dec->operands[i-1].shiftValueUsed = 0; \
			}

#define LAST_OPERAND_SHIFT(SHIFT_TYPE, SHIFT_VALUE) \
	dec->operands[i-1].shiftType = SHIFT_TYPE; \
	dec->operands[i-1].shiftValue = SHIFT_VALUE; \
	dec->operands[i-1].shiftValueUsed = 1;

#define LAST_OPERAND_LSL_12 LAST_OPERAND_SHIFT(ShiftType_LSL, 12)

#define ADD_OPERAND_OPTIONAL_PATTERN_MUL \
	{ \
		bool print_mul = dec->imm != 1; \
		bool print_pattern = print_mul || dec->pattern != 0x1f; \
		if(print_pattern) { \
			ADD_OPERAND_PATTERN; \
		} \
		if(print_mul) { \
			ADD_OPERAND_STR_IMM("mul", dec->imm); \
		} \
	}

#define ADD_OPERAND_OPTIONAL_PATTERN \
	if(dec->pattern != 0x1f) { \
		ADD_OPERAND_PATTERN; \
	}

/* convert the result of pcode execution to a human-friendly list of operands */
int decode_scratchpad(context *ctx, Instruction *dec)
{
	arrangement_spec arr_spec = _1B;
	const char *ccp_tmp;

	/* index of operand array, as it's built */
	int i = 0;

	/* populate operation */
	dec->operation = enc_to_oper(dec->encoding);

	/* default to 0 operands */
	memset(&(dec->operands), 0, sizeof(dec->operands));

	switch(dec->encoding) {
		case ENC_AUTIA1716_HI_HINTS:
		case ENC_AUTIASP_HI_HINTS:
		case ENC_AUTIAZ_HI_HINTS:
		case ENC_AUTIB1716_HI_HINTS:
		case ENC_AUTIBSP_HI_HINTS:
		case ENC_AUTIBZ_HI_HINTS:
		case ENC_AXFLAG_M_PSTATE:
		case ENC_CFINV_M_PSTATE:
		case ENC_CSDB_HI_HINTS:
		case ENC_DGH_HI_HINTS:
		case ENC_DRPS_64E_BRANCH_REG:
		case ENC_ERETAA_64E_BRANCH_REG:
		case ENC_ERETAB_64E_BRANCH_REG:
		case ENC_ERET_64E_BRANCH_REG:
		case ENC_ESB_HI_HINTS:
		case ENC_NOP_HI_HINTS:
		case ENC_PACIA1716_HI_HINTS:
		case ENC_PACIASP_HI_HINTS:
		case ENC_PACIAZ_HI_HINTS:
		case ENC_PACIB1716_HI_HINTS:
		case ENC_PACIBSP_HI_HINTS:
		case ENC_PACIBZ_HI_HINTS:
		case ENC_PSSBB_ONLY_BARRIERS:
		case ENC_RETAA_64E_BRANCH_REG:
		case ENC_RETAB_64E_BRANCH_REG:
		case ENC_SB_ONLY_BARRIERS:
		case ENC_SEVL_HI_HINTS:
		case ENC_SEV_HI_HINTS:
		case ENC_SSBB_ONLY_BARRIERS:
		case ENC_WFE_HI_HINTS:
		case ENC_WFI_HI_HINTS:
		case ENC_XAFLAG_M_PSTATE:
		case ENC_XPACLRI_HI_HINTS:
		case ENC_YIELD_HI_HINTS:
		case ENC_SETFFR_F_:
		{
			//
			break;
		}
		case ENC_PSB_HC_HINTS:
		case ENC_TSB_HC_HINTS:
		{
			ADD_OPERAND_NAME("csync");
			break;
		}
		case ENC_LDR_B_LDST_IMMPRE:
		case ENC_STR_B_LDST_IMMPRE:
		{
			// SYNTAX: <Bt>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_B_LDST_REGOFF:
		case ENC_STR_B_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Bt>, [<Xn|SP>, (<Wm>|<Xm>),<extend>{<amount>}]
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			if(dec->option & 1) {
				OPTIONAL_EXTEND_AMOUNT_32(3);
			}
			else {
				OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR1;
			}
			if(dec->S) {
				OPTIONAL_EXTEND_AMOUNT_0
			}
			break;
		}
		case ENC_LDR_BL_LDST_REGOFF:
		case ENC_STR_BL_LDST_REGOFF:
		{
			// SYNTAX: <Bt>, [<Xn|SP>,<Xm>{, LSL #0}]
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_LSL0;
			break;
		}
		case ENC_LDR_B_LDST_IMMPOST:
		case ENC_STR_B_LDST_IMMPOST:
		{
			// SYNTAX: <Bt>, [<Xn|SP>], #<simm>
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_B_LDST_POS:
		case ENC_STR_B_LDST_POS:
		{
			// SYNTAX: <Bt>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDUR_B_LDST_UNSCALED:
		case ENC_STUR_B_LDST_UNSCALED:
		{
			// SYNTAX: <Bt>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_BT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_MOVI_ASIMDIMM_D_DS: // display as hex
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Dd>, #<imm64>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->rd);
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_D_FLOATIMM: // display as float
		{
			float fimm = table_imm8_to_float[dec->imm8];
			// SYNTAX: <Dd>, #<fimm>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_FABS_D_FLOATDP1:
		case ENC_FMOV_D_FLOATDP1:
		case ENC_FNEG_D_FLOATDP1:
		case ENC_FRINT32X_D_FLOATDP1:
		case ENC_FRINT32Z_D_FLOATDP1:
		case ENC_FRINT64X_D_FLOATDP1:
		case ENC_FRINT64Z_D_FLOATDP1:
		case ENC_FRINTA_D_FLOATDP1:
		case ENC_FRINTI_D_FLOATDP1:
		case ENC_FRINTM_D_FLOATDP1:
		case ENC_FRINTN_D_FLOATDP1:
		case ENC_FRINTP_D_FLOATDP1:
		case ENC_FRINTX_D_FLOATDP1:
		case ENC_FRINTZ_D_FLOATDP1:
		case ENC_FSQRT_D_FLOATDP1:
		{
			// SYNTAX: <Dd>,<Dn>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_DN;
			// SYNTAX-END
			break;
		}
		case ENC_FADD_D_FLOATDP2:
		case ENC_FDIV_D_FLOATDP2:
		case ENC_FMAXNM_D_FLOATDP2:
		case ENC_FMAX_D_FLOATDP2:
		case ENC_FMINNM_D_FLOATDP2:
		case ENC_FMIN_D_FLOATDP2:
		case ENC_FMUL_D_FLOATDP2:
		case ENC_FNMUL_D_FLOATDP2:
		case ENC_FSUB_D_FLOATDP2:
		{
			// SYNTAX: <Dd>,<Dn>,<Dm>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_DN;
			ADD_OPERAND_DM;
			// SYNTAX-END
			break;
		}
		case ENC_FMADD_D_FLOATDP3:
		case ENC_FMSUB_D_FLOATDP3:
		case ENC_FNMADD_D_FLOATDP3:
		case ENC_FNMSUB_D_FLOATDP3:
		{
			// SYNTAX: <Dd>,<Dn>,<Dm>,<Da>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_DN;
			ADD_OPERAND_DM;
			ADD_OPERAND_DA;
			// SYNTAX-END
			break;
		}
		case ENC_FCSEL_D_FLOATSEL:
		{
			// SYNTAX: <Dd>,<Dn>,<Dm>,<cond>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_DN;
			ADD_OPERAND_DM;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_DH_FLOATDP1:
		{
			// SYNTAX: <Dd>,<Hn>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_HN;
			// SYNTAX-END
			break;
		}
		case ENC_SADDV_R_P_Z_:
		case ENC_UADDV_R_P_Z_:
		{
			unsigned elem_sz = dec->esize/8;
			// SYNTAX: <Dd>,<Pg>,<Zn>.<Ts>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_DS_FLOATDP1:
		{
			// SYNTAX: <Dd>,<Sn>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_SN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_D32_FLOAT2INT:
		case ENC_UCVTF_D32_FLOAT2INT:
		{
			// SYNTAX: <Dd>,<Wn>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_D32_FLOAT2FIX:
		case ENC_UCVTF_D32_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Dd>,<Wn>, #<fbits>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_WN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_D64_FLOAT2INT:
		case ENC_SCVTF_D64_FLOAT2INT:
		case ENC_UCVTF_D64_FLOAT2INT:
		{
			// SYNTAX: <Dd>,<Xn>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_D64_FLOAT2FIX:
		case ENC_UCVTF_D64_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Dd>,<Xn>, #<fbits>
			ADD_OPERAND_REG(REGSET_ZR, REG_D_BASE, dec->d);
			ADD_OPERAND_XN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_DZ_FLOATCMP:
		case ENC_FCMP_DZ_FLOATCMP:
		{
			// SYNTAX: <Dn>, #0.0
			ADD_OPERAND_DN;
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_D_FLOATCMP:
		case ENC_FCMP_D_FLOATCMP:
		{
			// SYNTAX: <Dn>,<Dm>
			ADD_OPERAND_DN;
			ADD_OPERAND_DM;
			// SYNTAX-END
			break;
		}
		case ENC_FCCMPE_D_FLOATCCMP:
		case ENC_FCCMP_D_FLOATCCMP:
		{
			// SYNTAX: <Dn>,<Dm>, #<nzcv>,<cond>
			ADD_OPERAND_DN;
			ADD_OPERAND_DM;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_LDP_D_LDSTPAIR_PRE:
		case ENC_STP_D_LDSTPAIR_PRE:
		{
			// SYNTAX: <Dt1>,<Dt2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_DT1;
			ADD_OPERAND_DT2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_D_LDSTPAIR_POST:
		case ENC_STP_D_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Dt1>,<Dt2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_DT1;
			ADD_OPERAND_DT2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDNP_D_LDSTNAPAIR_OFFS:
		case ENC_LDP_D_LDSTPAIR_OFF:
		case ENC_STNP_D_LDSTNAPAIR_OFFS:
		case ENC_STP_D_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Dt1>,<Dt2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_DT1;
			ADD_OPERAND_DT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_D_LDST_IMMPRE:
		case ENC_STR_D_LDST_IMMPRE:
		{
			// SYNTAX: <Dt>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_DT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_D_LDST_REGOFF:
		case ENC_STR_D_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Dt>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_DT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDR_D_LDST_IMMPOST:
		case ENC_STR_D_LDST_IMMPOST:
		{
			// SYNTAX: <Dt>, [<Xn|SP>], #<simm>
			ADD_OPERAND_DT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_D_LDST_POS:
		case ENC_STR_D_LDST_POS:
		{
			// SYNTAX: <Dt>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_DT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDUR_D_LDST_UNSCALED:
		case ENC_STUR_D_LDST_UNSCALED:
		{
			// SYNTAX: <Dt>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_DT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_D_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: <Dt>,<label>
			ADD_OPERAND_DT;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_H_FLOATIMM:
		{
			float fimm = table_imm8_to_float[dec->imm8];
			// SYNTAX: <Hd>, #<fimm>
			ADD_OPERAND_HD;
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_HD_FLOATDP1:
		{
			// SYNTAX: <Hd>,<Dn>
			ADD_OPERAND_HD;
			ADD_OPERAND_DN;
			// SYNTAX-END
			break;
		}
		case ENC_FABS_H_FLOATDP1:
		case ENC_FCVTAS_ASISDMISCFP16_R:
		case ENC_FCVTAU_ASISDMISCFP16_R:
		case ENC_FCVTMS_ASISDMISCFP16_R:
		case ENC_FCVTMU_ASISDMISCFP16_R:
		case ENC_FCVTNS_ASISDMISCFP16_R:
		case ENC_FCVTNU_ASISDMISCFP16_R:
		case ENC_FCVTPS_ASISDMISCFP16_R:
		case ENC_FCVTPU_ASISDMISCFP16_R:
		case ENC_FCVTZS_ASISDMISCFP16_R:
		case ENC_FCVTZU_ASISDMISCFP16_R:
		case ENC_FMOV_H_FLOATDP1:
		case ENC_FNEG_H_FLOATDP1:
		case ENC_FRECPE_ASISDMISCFP16_R:
		case ENC_FRECPX_ASISDMISCFP16_R:
		case ENC_FRINTA_H_FLOATDP1:
		case ENC_FRINTI_H_FLOATDP1:
		case ENC_FRINTM_H_FLOATDP1:
		case ENC_FRINTN_H_FLOATDP1:
		case ENC_FRINTP_H_FLOATDP1:
		case ENC_FRINTX_H_FLOATDP1:
		case ENC_FRINTZ_H_FLOATDP1:
		case ENC_FRSQRTE_ASISDMISCFP16_R:
		case ENC_FSQRT_H_FLOATDP1:
		case ENC_SCVTF_ASISDMISCFP16_R:
		case ENC_UCVTF_ASISDMISCFP16_R:
		{
			// SYNTAX: <Hd>,<Hn>
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			// SYNTAX-END
			break;
		}
		case ENC_FCMEQ_ASISDMISCFP16_FZ:
		case ENC_FCMGE_ASISDMISCFP16_FZ:
		case ENC_FCMGT_ASISDMISCFP16_FZ:
		case ENC_FCMLE_ASISDMISCFP16_FZ:
		case ENC_FCMLT_ASISDMISCFP16_FZ:
		{
			// SYNTAX: <Hd>,<Hn>, #0.0
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FABD_ASISDSAMEFP16_ONLY:
		case ENC_FACGE_ASISDSAMEFP16_ONLY:
		case ENC_FACGT_ASISDSAMEFP16_ONLY:
		case ENC_FADD_H_FLOATDP2:
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY:
		case ENC_FCMGE_ASISDSAMEFP16_ONLY:
		case ENC_FCMGT_ASISDSAMEFP16_ONLY:
		case ENC_FDIV_H_FLOATDP2:
		case ENC_FMAXNM_H_FLOATDP2:
		case ENC_FMAX_H_FLOATDP2:
		case ENC_FMINNM_H_FLOATDP2:
		case ENC_FMIN_H_FLOATDP2:
		case ENC_FMULX_ASISDSAMEFP16_ONLY:
		case ENC_FMUL_H_FLOATDP2:
		case ENC_FNMUL_H_FLOATDP2:
		case ENC_FRECPS_ASISDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY:
		case ENC_FSUB_H_FLOATDP2:
		{
			// SYNTAX: <Hd>,<Hn>,<Hm>
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			ADD_OPERAND_HM;
			// SYNTAX-END
			break;
		}
		case ENC_FMADD_H_FLOATDP3:
		case ENC_FMSUB_H_FLOATDP3:
		case ENC_FNMADD_H_FLOATDP3:
		case ENC_FNMSUB_H_FLOATDP3:
		{
			// SYNTAX: <Hd>,<Hn>,<Hm>,<Ha>
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			ADD_OPERAND_HM;
			ADD_OPERAND_HA;
			// SYNTAX-END
			break;
		}
		case ENC_FCSEL_H_FLOATSEL:
		{
			// SYNTAX: <Hd>,<Hn>,<Hm>,<cond>
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			ADD_OPERAND_HM;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_ASISDELEM_RH_H:
		case ENC_FMLS_ASISDELEM_RH_H:
		case ENC_FMULX_ASISDELEM_RH_H:
		case ENC_FMUL_ASISDELEM_RH_H:
		{
			// SYNTAX: <Hd>,<Hn>,<Vm>.H[<index>]
			ADD_OPERAND_HD;
			ADD_OPERAND_HN;
			ADD_OPERAND_VREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_BFCVT_BS_FLOATDP1:
		case ENC_FCVT_HS_FLOATDP1:
		{
			// SYNTAX: <Hd>,<Sn>
			ADD_OPERAND_HD;
			ADD_OPERAND_SN;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_H32_FLOAT2INT:
		case ENC_SCVTF_H32_FLOAT2INT:
		case ENC_UCVTF_H32_FLOAT2INT:
		{
			// SYNTAX: <Hd>,<Wn>
			ADD_OPERAND_HD;
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_H32_FLOAT2FIX:
		case ENC_UCVTF_H32_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Hd>,<Wn>, #<fbits>
			ADD_OPERAND_HD;
			ADD_OPERAND_WN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_H64_FLOAT2INT:
		case ENC_SCVTF_H64_FLOAT2INT:
		case ENC_UCVTF_H64_FLOAT2INT:
		{
			// SYNTAX: <Hd>,<Xn>
			ADD_OPERAND_HD;
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_H64_FLOAT2FIX:
		case ENC_UCVTF_H64_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Hd>,<Xn>, #<fbits>
			ADD_OPERAND_HD;
			ADD_OPERAND_XN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_HZ_FLOATCMP:
		case ENC_FCMP_HZ_FLOATCMP:
		{
			// SYNTAX: <Hn>, #0.0
			ADD_OPERAND_HN;
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_H_FLOATCMP:
		case ENC_FCMP_H_FLOATCMP:
		{
			// SYNTAX: <Hn>,<Hm>
			ADD_OPERAND_HN;
			ADD_OPERAND_HM;
			// SYNTAX-END
			break;
		}
		case ENC_FCCMPE_H_FLOATCCMP:
		case ENC_FCCMP_H_FLOATCCMP:
		{
			// SYNTAX: <Hn>,<Hm>, #<nzcv>,<cond>
			ADD_OPERAND_HN;
			ADD_OPERAND_HM;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_LDR_H_LDST_IMMPRE:
		case ENC_STR_H_LDST_IMMPRE:
		{
			// SYNTAX: <Ht>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_HT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_H_LDST_REGOFF: // 16-fsreg,LDR-16-fsreg (size == 01 && opc == 01)
		case ENC_STR_H_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Ht>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_HT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDR_H_LDST_IMMPOST:
		case ENC_STR_H_LDST_IMMPOST:
		{
			// SYNTAX: <Ht>, [<Xn|SP>], #<simm>
			ADD_OPERAND_HT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_H_LDST_POS:
		case ENC_STR_H_LDST_POS:
		{
			// SYNTAX: <Ht>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_HT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDUR_H_LDST_UNSCALED:
		case ENC_STUR_H_LDST_UNSCALED:
		{
			// SYNTAX: <Ht>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_HT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_CMPLE_CMPGE_P_P_ZZ_:
		case ENC_CMPLO_CMPHI_P_P_ZZ_:
		case ENC_CMPLS_CMPHS_P_P_ZZ_:
		case ENC_CMPLT_CMPGT_P_P_ZZ_:
		case ENC_FACLE_FACGE_P_P_ZZ_:
		case ENC_FACLT_FACGT_P_P_ZZ_:
		case ENC_FCMLE_FCMGE_P_P_ZZ_:
		case ENC_FCMLT_FCMGT_P_P_ZZ_:
		{
			unsigned elem_sz = table_b_d_h_s[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pg>/Z,<Zm>.<Ts>,<Zn>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCMEQ_P_P_Z0_:
		case ENC_FCMGE_P_P_Z0_:
		case ENC_FCMGT_P_P_Z0_:
		case ENC_FCMLE_P_P_Z0_:
		case ENC_FCMLT_P_P_Z0_:
		case ENC_FCMNE_P_P_Z0_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pg>/Z,<Zn>.<Ts>, #0.0
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_CMPEQ_P_P_ZI_:
		case ENC_CMPGE_P_P_ZI_:
		case ENC_CMPGT_P_P_ZI_:
		case ENC_CMPHI_P_P_ZI_:
		case ENC_CMPHS_P_P_ZI_:
		case ENC_CMPLE_P_P_ZI_:
		case ENC_CMPLO_P_P_ZI_:
		case ENC_CMPLS_P_P_ZI_:
		case ENC_CMPLT_P_P_ZI_:
		case ENC_CMPNE_P_P_ZI_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pg>/Z,<Zn>.<Ts>, #<imm>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_CMPEQ_P_P_ZZ_:
		case ENC_CMPGE_P_P_ZZ_:
		case ENC_CMPGT_P_P_ZZ_:
		case ENC_CMPHI_P_P_ZZ_:
		case ENC_CMPHS_P_P_ZZ_:
		case ENC_CMPNE_P_P_ZZ_:
		case ENC_FACGE_P_P_ZZ_:
		case ENC_FACGT_P_P_ZZ_:
		case ENC_FCMEQ_P_P_ZZ_:
		case ENC_FCMGE_P_P_ZZ_:
		case ENC_FCMGT_P_P_ZZ_:
		case ENC_FCMNE_P_P_ZZ_:
		case ENC_FCMUO_P_P_ZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pg>/Z,<Zn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_CMPEQ_P_P_ZW_:
		case ENC_CMPGE_P_P_ZW_:
		case ENC_CMPGT_P_P_ZW_:
		case ENC_CMPHI_P_P_ZW_:
		case ENC_CMPHS_P_P_ZW_:
		case ENC_CMPLE_P_P_ZW_:
		case ENC_CMPLO_P_P_ZW_:
		case ENC_CMPLS_P_P_ZW_:
		case ENC_CMPLT_P_P_ZW_:
		case ENC_CMPNE_P_P_ZW_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pg>/Z,<Zn>.<Ts>,<Zm>.D
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(8, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_REV_P_P_:
		{
			unsigned elem_sz = dec->esize / 8;
			// SYNTAX: <Pd>.<Ts>,<Pn>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_TRN1_P_PP_:
		case ENC_TRN2_P_PP_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pn>.<Ts>,<Pm>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, elem_sz);
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_UZP1_P_PP_:
		case ENC_UZP2_P_PP_:
		case ENC_ZIP1_P_PP_:
		case ENC_ZIP2_P_PP_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>,<Pn>.<Ts>,<Pm>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, elem_sz);
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_WHILELE_P_P_RR_:
		case ENC_WHILELO_P_P_RR_:
		case ENC_WHILELS_P_P_RR_:
		case ENC_WHILELT_P_P_RR_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = dec->sf ? REG_X_BASE : REG_W_BASE;
			unsigned rm_base = rn_base;
			// SYNTAX: <Pd>.<Ts>,<R><n>,<R><m>
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_PTRUE_P_S_:
		case ENC_PTRUES_P_S_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pd>.<Ts>{,<pattern>}
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, elem_sz);
			ADD_OPERAND_OPTIONAL_PATTERN;
			// SYNTAX-END
			break;
		}
		case ENC_PFALSE_P_:
		case ENC_RDFFR_P_F_:
		{
			// SYNTAX: <Pd>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			// SYNTAX-END
			break;
		}
		case ENC_SEL_P_P_PP_:
		{
			// SYNTAX: <Pd>.B,<Pg>,<Pn>.B,<Pm>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, 1);
			// SYNTAX-END
			break;
		}
		case ENC_BRKA_P_P_P_:
		case ENC_BRKB_P_P_P_:
		{
			char pred_qual = dec->M ? 'm' : 'z';
			// SYNTAX: <Pd>.B,<Pg>/<ZM>,<Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, pred_qual);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_SEL_P_P_PP_:
		{
			// SYNTAX: <Pd>.B,<Pg>/M,<Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_RDFFR_P_P_F_:
		case ENC_RDFFRS_P_P_F_:
		{
			// SYNTAX: <Pd>.B,<Pg>/Z
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			// SYNTAX-END
			break;
		}
		case ENC_MOVS_ANDS_P_P_PP_Z:
		case ENC_MOV_AND_P_P_PP_Z:
		case ENC_NOTS_EORS_P_P_PP_Z:
		case ENC_NOT_EOR_P_P_PP_Z:
		case ENC_BRKAS_P_P_P_Z:
		case ENC_BRKBS_P_P_P_Z:
		{
			// SYNTAX: <Pd>.B,<Pg>/Z,<Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_AND_P_P_PP_Z:
		case ENC_ANDS_P_P_PP_Z:
		case ENC_BIC_P_P_PP_Z:
		case ENC_BICS_P_P_PP_Z:
		case ENC_BRKPA_P_P_PP_:
		case ENC_BRKPAS_P_P_PP_:
		case ENC_BRKPB_P_P_PP_:
		case ENC_BRKPBS_P_P_PP_:
		case ENC_EOR_P_P_PP_Z:
		case ENC_EORS_P_P_PP_Z:
		case ENC_NAND_P_P_PP_Z:
		case ENC_NANDS_P_P_PP_Z:
		case ENC_NOR_P_P_PP_Z:
		case ENC_NORS_P_P_PP_Z:
		case ENC_ORN_P_P_PP_Z:
		case ENC_ORNS_P_P_PP_Z:
		case ENC_ORR_P_P_PP_Z:
		case ENC_ORRS_P_P_PP_Z:
		{
			// SYNTAX: <Pd>.B,<Pg>/Z,<Pn>.B,<Pm>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, 1);
			// SYNTAX-END
			break;
		}
		case ENC_MOVS_ORRS_P_P_PP_Z:
		case ENC_MOV_ORR_P_P_PP_Z:
		{
			// SYNTAX: <Pd>.B,<Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 1);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PUNPKHI_P_P_:
		case ENC_PUNPKLO_P_P_:
		{
			// SYNTAX: <Pd>.H,<Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->d, 2);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_BRKN_P_P_PP_:
		case ENC_BRKNS_P_P_PP_:
		{
			// SYNTAX: <Pdm>.B,<Pg>/Z,<Pn>.B,<Pdm>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdm, 1);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdm, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PNEXT_P_P_P_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Pdn>.<Ts>,<Pg>,<Pdn>.<Ts>
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdn, elem_sz);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdn, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_PFIRST_P_P_P_:
		{
			// SYNTAX: <Pdn>.B,<Pg>,<Pdn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdn, 1);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_PRED_REG_ESIZE(dec->Pdn, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PTEST_P_P_:
		{
			// SYNTAX: <Pg>,<Pn>.B
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_WRFFR_F_P_:
		{
			// SYNTAX: <Pn>.B
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_P_BI_:
		case ENC_STR_P_BI_:
		{
			signed imm = dec->imm;
			// SYNTAX: <Pt>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_PRED_REG(dec->t);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3:
		case ENC_SHA512H_QQV_CRYPTOSHA512_3:
		{
			arrangement_spec arr_spec_2d = _2D;
			// SYNTAX: <Qd>,<Qn>,<Vm>.2D
			ADD_OPERAND_QD;
			ADD_OPERAND_QN;
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SHA256H2_QQV_CRYPTOSHA3:
		case ENC_SHA256H_QQV_CRYPTOSHA3:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Qd>,<Qn>,<Vm>.4S
			ADD_OPERAND_QD;
			ADD_OPERAND_QN;
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SHA1C_QSV_CRYPTOSHA3:
		case ENC_SHA1M_QSV_CRYPTOSHA3:
		case ENC_SHA1P_QSV_CRYPTOSHA3:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Qd>,<Sn>,<Vm>.4S
			ADD_OPERAND_QD;
			ADD_OPERAND_SN;
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_Q_LDSTPAIR_PRE:
		case ENC_STP_Q_LDSTPAIR_PRE:
		{
			// SYNTAX: <Qt1>,<Qt2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_QT1;
			ADD_OPERAND_QT2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_Q_LDSTPAIR_POST:
		case ENC_STP_Q_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Qt1>,<Qt2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_QT1;
			ADD_OPERAND_QT2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS:
		case ENC_LDP_Q_LDSTPAIR_OFF:
		case ENC_STNP_Q_LDSTNAPAIR_OFFS:
		case ENC_STP_Q_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Qt1>,<Qt2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_QT1;
			ADD_OPERAND_QT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_Q_LDST_IMMPRE:
		case ENC_STR_Q_LDST_IMMPRE:
		{
			// SYNTAX: <Qt>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_QT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_Q_LDST_REGOFF:
		case ENC_STR_Q_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Qt>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_QT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDR_Q_LDST_IMMPOST:
		case ENC_STR_Q_LDST_IMMPOST:
		{
			// SYNTAX: <Qt>, [<Xn|SP>], #<simm>
			ADD_OPERAND_QT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_Q_LDST_POS:
		case ENC_STR_Q_LDST_POS:
		{
			// SYNTAX: <Qt>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_QT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDUR_Q_LDST_UNSCALED:
		case ENC_STUR_Q_LDST_UNSCALED:
		{
			// SYNTAX: <Qt>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_QT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_Q_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: <Qt>,<label>
			ADD_OPERAND_QT;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_LASTA_R_P_Z_:
		case ENC_LASTB_R_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rd_base = wwwx_0123_reg(dec->size);
			// SYNTAX: <R><d>,<Pg>,<Zn>.<Ts>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_CLASTA_R_P_Z_:
		case ENC_CLASTB_R_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rdn_base = wwwx_0123_reg(dec->size);
			// SYNTAX: <R><dn>,<Pg>,<R><dn>,<Zm>.<Ts>
			ADD_OPERAND_REG(REGSET_ZR, rdn_base, dec->Rdn);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_REG(REGSET_ZR, rdn_base, dec->Rdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_CTERMEQ_RR_:
		case ENC_CTERMNE_RR_:
		{
			unsigned rn_base = dec->sz ? REG_X_BASE : REG_W_BASE;
			unsigned rm_base = rn_base;
			// SYNTAX: <R><n>,<R><m>
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_TBNZ_ONLY_TESTBRANCH:
		case ENC_TBZ_ONLY_TESTBRANCH:
		{
			uint64_t imm = dec->bit_pos;
			unsigned rt_base = dec->datasize == 32 ? REG_W_BASE : REG_X_BASE;
			uint64_t eaddr = dec->offset;
			// SYNTAX: <R><t>, #<imm>,<label>
			ADD_OPERAND_REG(REGSET_ZR, rt_base, dec->Rt);
			ADD_OPERAND_UIMM32;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_S_FLOATIMM:
		{
			float fimm = table_imm8_to_float[dec->imm8];
			// SYNTAX: <Sd>, #<fimm>
			ADD_OPERAND_SD;
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_SD_FLOATDP1:
		{
			// SYNTAX: <Sd>,<Dn>
			ADD_OPERAND_SD;
			ADD_OPERAND_DN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_SH_FLOATDP1:
		{
			// SYNTAX: <Sd>,<Hn>
			ADD_OPERAND_SD;
			ADD_OPERAND_HN;
			// SYNTAX-END
			break;
		}
		case ENC_FABS_S_FLOATDP1:
		case ENC_FMOV_S_FLOATDP1:
		case ENC_FNEG_S_FLOATDP1:
		case ENC_FRINT32X_S_FLOATDP1:
		case ENC_FRINT32Z_S_FLOATDP1:
		case ENC_FRINT64X_S_FLOATDP1:
		case ENC_FRINT64Z_S_FLOATDP1:
		case ENC_FRINTA_S_FLOATDP1:
		case ENC_FRINTI_S_FLOATDP1:
		case ENC_FRINTM_S_FLOATDP1:
		case ENC_FRINTN_S_FLOATDP1:
		case ENC_FRINTP_S_FLOATDP1:
		case ENC_FRINTX_S_FLOATDP1:
		case ENC_FRINTZ_S_FLOATDP1:
		case ENC_FSQRT_S_FLOATDP1:
		case ENC_SHA1H_SS_CRYPTOSHA2:
		{
			// SYNTAX: <Sd>,<Sn>
			ADD_OPERAND_SD;
			ADD_OPERAND_SN;
			// SYNTAX-END
			break;
		}
		case ENC_FADD_S_FLOATDP2:
		case ENC_FDIV_S_FLOATDP2:
		case ENC_FMAXNM_S_FLOATDP2:
		case ENC_FMAX_S_FLOATDP2:
		case ENC_FMINNM_S_FLOATDP2:
		case ENC_FMIN_S_FLOATDP2:
		case ENC_FMUL_S_FLOATDP2:
		case ENC_FNMUL_S_FLOATDP2:
		case ENC_FSUB_S_FLOATDP2:
		{
			// SYNTAX: <Sd>,<Sn>,<Sm>
			ADD_OPERAND_SD;
			ADD_OPERAND_SN;
			ADD_OPERAND_SM;
			// SYNTAX-END
			break;
		}
		case ENC_FMADD_S_FLOATDP3:
		case ENC_FMSUB_S_FLOATDP3:
		case ENC_FNMADD_S_FLOATDP3:
		case ENC_FNMSUB_S_FLOATDP3:
		{
			// SYNTAX: <Sd>,<Sn>,<Sm>,<Sa>
			ADD_OPERAND_SD;
			ADD_OPERAND_SN;
			ADD_OPERAND_SM;
			ADD_OPERAND_SA;
			// SYNTAX-END
			break;
		}
		case ENC_FCSEL_S_FLOATSEL:
		{
			// SYNTAX: <Sd>,<Sn>,<Sm>,<cond>
			ADD_OPERAND_SD;
			ADD_OPERAND_SN;
			ADD_OPERAND_SM;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_S32_FLOAT2INT:
		case ENC_SCVTF_S32_FLOAT2INT:
		case ENC_UCVTF_S32_FLOAT2INT:
		{
			// SYNTAX: <Sd>,<Wn>
			ADD_OPERAND_SD;
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_S32_FLOAT2FIX:
		case ENC_UCVTF_S32_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Sd>,<Wn>, #<fbits>
			ADD_OPERAND_SD;
			ADD_OPERAND_WN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_S64_FLOAT2INT:
		case ENC_UCVTF_S64_FLOAT2INT:
		{
			// SYNTAX: <Sd>,<Xn>
			ADD_OPERAND_SD;
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_SCVTF_S64_FLOAT2FIX:
		case ENC_UCVTF_S64_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Sd>,<Xn>, #<fbits>
			ADD_OPERAND_SD;
			ADD_OPERAND_XN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_SZ_FLOATCMP:
		case ENC_FCMP_SZ_FLOATCMP:
		{
			// SYNTAX: <Sn>, #0.0
			ADD_OPERAND_SN;
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FCMPE_S_FLOATCMP:
		case ENC_FCMP_S_FLOATCMP:
		{
			// SYNTAX: <Sn>,<Sm>
			ADD_OPERAND_SN;
			ADD_OPERAND_SM;
			// SYNTAX-END
			break;
		}
		case ENC_FCCMPE_S_FLOATCCMP:
		case ENC_FCCMP_S_FLOATCCMP:
		{
			// SYNTAX: <Sn>,<Sm>, #<nzcv>,<cond>
			ADD_OPERAND_SN;
			ADD_OPERAND_SM;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_LDP_S_LDSTPAIR_PRE:
		case ENC_STP_S_LDSTPAIR_PRE:
		{
			// SYNTAX: <St1>,<St2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_ST1;
			ADD_OPERAND_ST2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_S_LDSTPAIR_POST:
		case ENC_STP_S_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <St1>,<St2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_ST1;
			ADD_OPERAND_ST2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDNP_S_LDSTNAPAIR_OFFS:
		case ENC_LDP_S_LDSTPAIR_OFF:
		case ENC_STNP_S_LDSTNAPAIR_OFFS:
		case ENC_STP_S_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <St1>,<St2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_ST1;
			ADD_OPERAND_ST2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_S_LDST_IMMPRE:
		case ENC_STR_S_LDST_IMMPRE:
		{
			// SYNTAX: <St>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_ST;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_S_LDST_REGOFF:
		case ENC_STR_S_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <St>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_ST;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDR_S_LDST_IMMPOST:
		case ENC_STR_S_LDST_IMMPOST:
		{
			// SYNTAX: <St>, [<Xn|SP>], #<simm>
			ADD_OPERAND_ST;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_S_LDST_POS:
		case ENC_STR_S_LDST_POS:
		{
			// SYNTAX: <St>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_ST;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDUR_S_LDST_UNSCALED:
		case ENC_STUR_S_LDST_UNSCALED:
		{
			// SYNTAX: <St>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_ST;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDR_S_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: <St>,<label>
			ADD_OPERAND_ST;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_ANDV_R_P_Z_:
		case ENC_EORV_R_P_Z_:
		case ENC_FADDV_V_P_Z_:
		case ENC_FMAXNMV_V_P_Z_:
		case ENC_FMAXV_V_P_Z_:
		case ENC_FMINNMV_V_P_Z_:
		case ENC_FMINV_V_P_Z_:
		case ENC_LASTA_V_P_Z_:
		case ENC_LASTB_V_P_Z_:
		case ENC_ORV_R_P_Z_:
		case ENC_SMAXV_R_P_Z_:
		case ENC_SMINV_R_P_Z_:
		case ENC_UMAXV_R_P_Z_:
		case ENC_UMINV_R_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rd_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <V><d>,<Pg>,<Zn>.<Ts>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_ASISDMISC_R:
		case ENC_FCVTAU_ASISDMISC_R:
		case ENC_FCVTMS_ASISDMISC_R:
		case ENC_FCVTMU_ASISDMISC_R:
		case ENC_FCVTNS_ASISDMISC_R:
		case ENC_FCVTNU_ASISDMISC_R:
		case ENC_FCVTPS_ASISDMISC_R:
		case ENC_FCVTPU_ASISDMISC_R:
		case ENC_FCVTZS_ASISDMISC_R:
		case ENC_FCVTZU_ASISDMISC_R:
		case ENC_FRECPE_ASISDMISC_R:
		case ENC_FRECPX_ASISDMISC_R:
		case ENC_FRSQRTE_ASISDMISC_R:
		case ENC_SCVTF_ASISDMISC_R:
		case ENC_UCVTF_ASISDMISC_R:
		{
			unsigned rn_base = sd_01_reg(dec->sz);
			unsigned rd_base = sd_01_reg(dec->sz);
			// SYNTAX: <V><d>,<V><n>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_ABS_ASISDMISC_R:
		case ENC_NEG_ASISDMISC_R:
		case ENC_SQABS_ASISDMISC_R:
		case ENC_SQNEG_ASISDMISC_R:
		case ENC_SUQADD_ASISDMISC_R:
		case ENC_USQADD_ASISDMISC_R:
		{
			unsigned rn_base = bhsd_0123_reg(dec->size);
			unsigned rd_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <V><d>,<V><n>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_CMEQ_ASISDMISC_Z:
		case ENC_CMGE_ASISDMISC_Z:
		case ENC_CMGT_ASISDMISC_Z:
		case ENC_CMLE_ASISDMISC_Z:
		case ENC_CMLT_ASISDMISC_Z:
		{
			unsigned rn_base = bhsd_0123_reg(dec->size);
			unsigned rd_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <V><d>,<V><n>, #0
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_IMMEDIATE32(0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_FCMEQ_ASISDMISC_FZ:
		case ENC_FCMGE_ASISDMISC_FZ:
		case ENC_FCMGT_ASISDMISC_FZ:
		case ENC_FCMLE_ASISDMISC_FZ:
		case ENC_FCMLT_ASISDMISC_FZ:
		{
			unsigned rn_base = sd_01_reg(dec->sz);
			unsigned rd_base = sd_01_reg(dec->sz);
			// SYNTAX: <V><d>,<V><n>, #0.0
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_ASISDSHF_C:
		case ENC_FCVTZU_ASISDSHF_C:
		case ENC_SCVTF_ASISDSHF_C:
		case ENC_UCVTF_ASISDSHF_C:
		{
			uint64_t fbits = dec->fracbits;
			unsigned rn_base = rhsd_0123x_reg(dec->immh);
			unsigned rd_base = rhsd_0123x_reg(dec->immh);
			// SYNTAX: <V><d>,<V><n>, #<fbits>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_SHL_ASISDSHF_R:
		case ENC_SLI_ASISDSHF_R:
		case ENC_SQSHLU_ASISDSHF_R:
		case ENC_SQSHL_ASISDSHF_R:
		case ENC_SRI_ASISDSHF_R:
		case ENC_SRSHR_ASISDSHF_R:
		case ENC_SRSRA_ASISDSHF_R:
		case ENC_SSHR_ASISDSHF_R: // 0F080400
		case ENC_SSRA_ASISDSHF_R:
		case ENC_UQSHL_ASISDSHF_R:
		case ENC_URSHR_ASISDSHF_R:
		case ENC_URSRA_ASISDSHF_R:
		case ENC_USHR_ASISDSHF_R:
		case ENC_USRA_ASISDSHF_R:
		{
			unsigned shift = dec->shift;
			unsigned rd_base, rn_base;
			switch(dec->encoding) {
				case ENC_UQSHL_ASISDSHF_R:
				case ENC_SQSHLU_ASISDSHF_R:
				case ENC_SQSHL_ASISDSHF_R:
					rn_base = rbhsd_0123x_reg(dec->immh);
					rd_base = rbhsd_0123x_reg(dec->immh);
					break;
				default:
					rn_base = rd_base = REG_D_BASE;
			}
			// SYNTAX: <V><d>,<V><n>, #<shift>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_ADD_ASISDSAME_ONLY:
		case ENC_CMEQ_ASISDSAME_ONLY:
		case ENC_CMGE_ASISDSAME_ONLY:
		case ENC_CMGT_ASISDSAME_ONLY:
		case ENC_CMHI_ASISDSAME_ONLY:
		case ENC_CMHS_ASISDSAME_ONLY:
		case ENC_CMTST_ASISDSAME_ONLY:
		case ENC_SQADD_ASISDSAME_ONLY:
		case ENC_SQDMULH_ASISDSAME_ONLY:
		case ENC_SQRDMLAH_ASISDSAME2_ONLY:
		case ENC_SQRDMLSH_ASISDSAME2_ONLY:
		case ENC_SQRDMULH_ASISDSAME_ONLY:
		case ENC_SQRSHL_ASISDSAME_ONLY:
		case ENC_SQSHL_ASISDSAME_ONLY:
		case ENC_SQSUB_ASISDSAME_ONLY:
		case ENC_SRSHL_ASISDSAME_ONLY:
		case ENC_SSHL_ASISDSAME_ONLY:
		case ENC_SUB_ASISDSAME_ONLY:
		case ENC_UQADD_ASISDSAME_ONLY:
		case ENC_UQRSHL_ASISDSAME_ONLY:
		case ENC_UQSHL_ASISDSAME_ONLY:
		case ENC_UQSUB_ASISDSAME_ONLY:
		case ENC_URSHL_ASISDSAME_ONLY:
		case ENC_USHL_ASISDSAME_ONLY:
		{
			unsigned rn_base = bhsd_0123_reg(dec->size);
			unsigned rd_base = bhsd_0123_reg(dec->size);
			unsigned rm_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <V><d>,<V><n>,<V><m>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FACGE_ASISDSAME_ONLY:
		case ENC_FABD_ASISDSAME_ONLY:
		case ENC_FACGT_ASISDSAME_ONLY:
		case ENC_FCMEQ_ASISDSAME_ONLY:
		case ENC_FCMGE_ASISDSAME_ONLY:
		case ENC_FCMGT_ASISDSAME_ONLY:
		case ENC_FMULX_ASISDSAME_ONLY:
		case ENC_FRSQRTS_ASISDSAME_ONLY:
		case ENC_FRECPS_ASISDSAME_ONLY:
		{
			unsigned rn_base = sd_01_reg(dec->sz);
			unsigned rd_base = sd_01_reg(dec->sz);
			unsigned rm_base = sd_01_reg(dec->sz);
			// SYNTAX: <V><d>,<V><n>,<V><m>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_ASISDELEM_R_SD:
		case ENC_FMLS_ASISDELEM_R_SD:
		case ENC_FMULX_ASISDELEM_R_SD:
		case ENC_FMUL_ASISDELEM_R_SD:
		{
			unsigned rn_base = sd_01_reg(dec->sz);
			unsigned rd_base = sd_01_reg(dec->sz);
			unsigned elem_sz = table_s_d[dec->sz];
			// SYNTAX: <V><d>,<V><n>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SQDMULH_ASISDELEM_R:
		case ENC_SQRDMLAH_ASISDELEM_R:
		case ENC_SQRDMLSH_ASISDELEM_R:
		case ENC_SQRDMULH_ASISDELEM_R:
		{
			unsigned rd_base = rhsd_0123_reg(dec->size);
			unsigned rn_base = rhsd_0123_reg(dec->size);
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <V><d>,<V><n>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_ADDP_ASISDPAIR_ONLY:
		{
			unsigned rd_base = REG_D_BASE;
			arrangement_spec arr_spec = _2D;
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FADDP_ASISDPAIR_ONLY_SD:
		{
			unsigned rd_base = dec->sz ? REG_D_BASE : REG_S_BASE;
			arr_spec = table_2s_2d[dec->sz];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_ADDV_ASIMDALL_ONLY:
		{
			unsigned rd_base = bhsd_0123_reg(dec->size);
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H:
		case ENC_FMAXP_ASISDPAIR_ONLY_H:
		case ENC_FMINNMP_ASISDPAIR_ONLY_H:
		case ENC_FMINP_ASISDPAIR_ONLY_H:
		case ENC_FADDP_ASISDPAIR_ONLY_H:
		{
			unsigned rd_base = REG_H_BASE;
			arr_spec = (arrangement_spec)_2H;
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMAXP_ASISDPAIR_ONLY_SD:
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMINP_ASISDPAIR_ONLY_SD:
		{
			unsigned rd_base = sd_01_reg(dec->sz);
			arrangement_spec arr_spec = table_2s_2d[dec->sz];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMAXNMV_ASIMDALL_ONLY_H:
		case ENC_FMAXV_ASIMDALL_ONLY_H:
		case ENC_FMINNMV_ASIMDALL_ONLY_H:
		case ENC_FMINV_ASIMDALL_ONLY_H:
		{
			unsigned rd_base = REG_H_BASE;
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}

		case ENC_FMAXNMV_ASIMDALL_ONLY_SD:
		case ENC_FMAXV_ASIMDALL_ONLY_SD:
		case ENC_FMINNMV_ASIMDALL_ONLY_SD:
		case ENC_FMINV_ASIMDALL_ONLY_SD:
		{
			unsigned rd_base = REG_S_BASE;
			arrangement_spec arr_spec = _4S;
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_UADDLV_ASIMDALL_ONLY:
		case ENC_SADDLV_ASIMDALL_ONLY:
		{
			unsigned rd_base = hsdr_0123_reg(dec->size);
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_UMAXV_ASIMDALL_ONLY:
		case ENC_UMINV_ASIMDALL_ONLY:
		case ENC_SMAXV_ASIMDALL_ONLY:
		case ENC_SMINV_ASIMDALL_ONLY:
		{
			unsigned rd_base = bhsd_0123_reg(dec->size);
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			// SYNTAX: <V><d>,<Vn>.<T>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_DUP_ASISDONE_ONLY:
		{
			unsigned rd_base = rbhsdq_5bit_reg(dec->imm5);
			arrangement_spec arr_spec = arr_spec_method1(dec->imm5);
			arr_spec.data_sz = 0;
			// SYNTAX: <V><d>,<Vn>.<T>[<index>]
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_T_INDEXED(arr_spec, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_DUP_ASISDONE_ONLY:
		{
			unsigned rd_base = bhsd_0123_reg(dec->size);
			unsigned elem_sz = table_b_d_h_s[dec->size];
			// SYNTAX: <V><d>,<Vn>.<Ts>[<index>]
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_CLASTA_V_P_Z_:
		case ENC_CLASTB_V_P_Z_:
		case ENC_FADDA_V_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rdn_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <V><dn>,<Pg>,<V><dn>,<Zm>.<Ts>
			ADD_OPERAND_REG(REGSET_ZR, rdn_base, dec->Vdn);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_REG(REGSET_ZR, rdn_base, dec->Vdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SQDMLAL_ASISDDIFF_ONLY:
		case ENC_SQDMLSL_ASISDDIFF_ONLY:
		case ENC_SQDMULL_ASISDDIFF_ONLY:
		{
			unsigned rd_base = rsdr_0123_reg(dec->size);
			unsigned rn_base = bhsd_0123_reg(dec->size);
			unsigned rm_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <Va><d>,<Vb><n>,<Vb><m>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SQDMLAL_ASISDELEM_L:
		case ENC_SQDMLSL_ASISDELEM_L:
		case ENC_SQDMULL_ASISDELEM_L:
		{
			unsigned rd_base = rsdr_0123_reg(dec->size);
			unsigned rn_base = bhsd_0123_reg(dec->size);
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Va><d>,<Vb><n>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SQXTN_ASISDMISC_N:
		case ENC_UQXTN_ASISDMISC_N:
		case ENC_SQXTUN_ASISDMISC_N:
		{
			unsigned rd_base = bhsd_0123_reg(dec->size);
			unsigned rn_base = hsdr_0123_reg(dec->size);
			// SYNTAX: <Vb><d>,<Va><n>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;

		}
		case ENC_FCVTXN_ASISDMISC_N:
		{
			unsigned rd_base = REG_S_BASE;
			unsigned rn_base = REG_D_BASE;
			// SYNTAX: <Vb><d>,<Va><n>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SQRSHRN_ASISDSHF_N:
		case ENC_SQRSHRUN_ASISDSHF_N:
		case ENC_SQSHRN_ASISDSHF_N:
		case ENC_SQSHRUN_ASISDSHF_N:
		case ENC_UQRSHRN_ASISDSHF_N:
		case ENC_UQSHRN_ASISDSHF_N:
		{
			unsigned shift = dec->shift;
			unsigned rd_base = rbhsd_0123x_reg(dec->immh);
			unsigned rn_base = rhsdr_0123x_reg(dec->immh);
			// SYNTAX: <Vb><d>,<Va><n>, #<shift>
			ADD_OPERAND_REG(REGSET_ZR, rd_base, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_AESD_B_CRYPTOAES:
		case ENC_AESE_B_CRYPTOAES:
		case ENC_AESIMC_B_CRYPTOAES:
		case ENC_AESMC_B_CRYPTOAES:
		{
			arrangement_spec arr_spec_16b = _16B;
			// SYNTAX: <Vd>.16B,<Vn>.16B
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_BCAX_VVV16_CRYPTO4:
		case ENC_EOR3_VVV16_CRYPTO4:
		{
			arrangement_spec arr_spec_16b = _16B;
			// SYNTAX: <Vd>.16B,<Vn>.16B,<Vm>.16B,<Va>.16B
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->m);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->a);
			// SYNTAX-END
			break;
		}
		case ENC_MOVI_ASIMDIMM_D2_D: // display as int
		{
			uint64_t imm = dec->imm;
			arrangement_spec arr_spec_2d = _2D;
			// SYNTAX: <Vd>.2D, #<imm64>
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->rd);
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_ASIMDIMM_D2_D: // display as float
		{
			float fimm = table_imm8_to_float[ABCDEFGH];
			arrangement_spec arr_spec_2d = _2D;
			// SYNTAX: <Vd>.2D, #<fimm>
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->rd);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2:
		{
			arrangement_spec arr_spec_2d = _2D;
			// SYNTAX: <Vd>.2D,<Vn>.2D
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_RAX1_VVV2_CRYPTOSHA512_3:
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3:
		{
			arrangement_spec arr_spec_2d = _2D;
			// SYNTAX: <Vd>.2D,<Vn>.2D,<Vm>.2D
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_XAR_VVV2_CRYPTO3_IMM6:
		{
			arrangement_spec arr_spec_2d = _2D;
			uint64_t imm6 = dec->imm6;
			// SYNTAX: <Vd>.2D,<Vn>.2D,<Vm>.2D, #<imm6>
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_2d, dec->m);
			ADD_OPERAND_IMM6;
			// SYNTAX-END
			break;
		}
		case ENC_SMMLA_ASIMDSAME2_G:
		case ENC_UMMLA_ASIMDSAME2_G:
		case ENC_USMMLA_ASIMDSAME2_G:
		{
			arrangement_spec arr_spec_4s = _4S;
			arrangement_spec arr_spec_16b = _16B;
			// SYNTAX: <Vd>.4S,<Vn>.16B,<Vm>.16B
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_16b, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SHA1SU1_VV_CRYPTOSHA2:
		case ENC_SHA256SU0_VV_CRYPTOSHA2:
		case ENC_SM4E_VV4_CRYPTOSHA512_2:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Vd>.4S,<Vn>.4S
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SHA1SU0_VVV_CRYPTOSHA3:
		case ENC_SHA256SU1_VVV_CRYPTOSHA3:
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3:
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3:
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Vd>.4S,<Vn>.4S,<Vm>.4S
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SM3SS1_VVV4_CRYPTO4:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Vd>.4S,<Vn>.4S,<Vm>.4S,<Va>.4S
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->n);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->m);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->a);
			// SYNTAX-END
			break;
		}
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2:
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2:
		{
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Vd>.4S,<Vn>.4S,<Vm>.S[<imm2>]
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(4, dec->m, dec->imm2);
			// SYNTAX-END
			break;
		}
		case ENC_BFMMLA_ASIMDSAME2_E:
		{
			arrangement_spec arr_spec_8h = _8H;
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: <Vd>.4S,<Vn>.8H,<Vm>.8H
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->d);
			ADD_OPERAND_VN;
			ADD_OPERAND_VREG_T(arr_spec_8h, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_MOVI_ASIMDIMM_M_SM: // "shifting ones" around
		case ENC_MVNI_ASIMDIMM_M_SM: // 32-bit shifting ones (cmode == 110x)
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec = table_2s_4s[dec->Q];
			// SYNTAX: <Vd>.<T>, #<imm8>, MSL #<amount>
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			dec->operands[1].shiftType = ShiftType_MSL;
			dec->operands[1].shiftValue = (dec->cmode & 1) ? 16 : 8;
			dec->operands[1].shiftValueUsed = 1;
			break;
		}
		case ENC_MOVI_ASIMDIMM_N_B:
		{
			arrangement_spec arr_spec = table_8b_16b[dec->Q];
			uint64_t imm8 = dec->imm & 0xFF;
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #0}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			break;
		}
		case ENC_ORR_ASIMDIMM_L_SL:
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec = table_2s_4s[dec->Q];
			int AMOUNT = 8*((dec->cmode>>1) & 0b11);
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}
			break;
		}
		case ENC_ORR_ASIMDIMM_L_HL:
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			int AMOUNT = (dec->cmode & 2) ? 8 : 0;
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}
			break;
		}

		case ENC_MOVI_ASIMDIMM_L_HL: // 16-bit shifted immediate (op == 0 && cmode == 10x0)
		case ENC_MVNI_ASIMDIMM_L_HL: // 16-bit shifted immediate (cmode == 10x0)
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			unsigned AMOUNT = (dec->cmode & 0b10)<<2;
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}
			break;
		}
		// IFORM: MVNI_advsimd
		case ENC_MVNI_ASIMDIMM_L_SL: // cmode == '0xx0' (32-bit shifted immediate)
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec = table_2s_4s[dec->Q];
			unsigned AMOUNT = (dec->cmode & 0b0110)<<2;
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}
			break;
		}
		case ENC_BIC_ASIMDIMM_L_HL:
		case ENC_BIC_ASIMDIMM_L_SL:
		{
			uint64_t imm8 = ABCDEFGH;
			arrangement_spec arr_spec;
			unsigned AMOUNT = 0;
			if((dec->cmode & 0b1101) == 0b1001) { // 16-bit (cmode == 10x1)
				arr_spec = table_4h_8h[dec->Q];
				AMOUNT = (dec->cmode & 0b10) << 2;
			}
			else if((dec->cmode & 0b1001) == 0b0001) { // 32-bit (cmode == 0xx1)
				arr_spec = table_2s_4s[dec->Q];
				AMOUNT = (dec->cmode & 0b110) << 2;
			}

			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END

			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}

			break;
		}

		// IFORM: MOVI_advsimd
		case ENC_MOVI_ASIMDIMM_L_SL: // op == '0' && cmode == '0xx0' (32-bit shifted immediate)
		{
			uint64_t imm8 = ABCDEFGH;
			unsigned AMOUNT = (dec->cmode & 0b110) << 2;
			arrangement_spec arr_spec = table_2s_4s[dec->Q];
			// SYNTAX: <Vd>.<T>, #<imm8>{, LSL #<amount>}
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_IMM8;
			// SYNTAX-END
			if(AMOUNT) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, AMOUNT);
			}

			break;
		}
		case ENC_FMOV_ASIMDIMM_H_H:
		{
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			float fimm = table_imm8_to_float[ABCDEFGH];
			// SYNTAX: <Vd>.<T>, #<fimm>
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_ASIMDIMM_S_S:
		{
			arrangement_spec arr_spec = table_2s_4s[dec->Q];
			float fimm = table_imm8_to_float[ABCDEFGH];
			// SYNTAX: <Vd>.<T>, #<fimm>
			ADD_OPERAND_VREG_T(arr_spec, dec->rd);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_DUP_ASIMDINS_DR_R:
		{
			arrangement_spec arr_spec = arr_spec_method4(dec->imm5, dec->Q);
			unsigned rn_base = rwwwx_0123x_reg(dec->imm5, dec->Rn);
			// SYNTAX: <Vd>.<T>,<R><n>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FABS_ASIMDMISCFP16_R:
		case ENC_FNEG_ASIMDMISCFP16_R:
		case ENC_FSQRT_ASIMDMISCFP16_R:
		case ENC_SCVTF_ASIMDMISCFP16_R:
		case ENC_UCVTF_ASIMDMISCFP16_R:
		case ENC_FCVTAS_ASIMDMISCFP16_R:
		case ENC_FCVTAU_ASIMDMISCFP16_R:
		case ENC_FCVTMS_ASIMDMISCFP16_R:
		case ENC_FCVTMU_ASIMDMISCFP16_R:
		case ENC_FCVTNS_ASIMDMISCFP16_R:
		case ENC_FCVTNU_ASIMDMISCFP16_R:
		case ENC_FCVTPS_ASIMDMISCFP16_R:
		case ENC_FCVTPU_ASIMDMISCFP16_R:
		case ENC_FCVTZS_ASIMDMISCFP16_R:
		case ENC_FCVTZU_ASIMDMISCFP16_R:
		case ENC_FRECPE_ASIMDMISCFP16_R:
		case ENC_FRINTA_ASIMDMISCFP16_R:
		case ENC_FRINTI_ASIMDMISCFP16_R:
		case ENC_FRINTM_ASIMDMISCFP16_R:
		case ENC_FRINTN_ASIMDMISCFP16_R:
		case ENC_FRINTP_ASIMDMISCFP16_R:
		case ENC_FRINTX_ASIMDMISCFP16_R:
		case ENC_FRINTZ_ASIMDMISCFP16_R:
		case ENC_FRSQRTE_ASIMDMISCFP16_R:
		{
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FRINT64Z_ASIMDMISC_R:
		case ENC_FRINT64X_ASIMDMISC_R:
		case ENC_FRINTM_ASIMDMISC_R:
		case ENC_FRINTI_ASIMDMISC_R:
		case ENC_FRECPE_ASIMDMISC_R:
		case ENC_FRINTN_ASIMDMISC_R:
		case ENC_FABS_ASIMDMISC_R:
		case ENC_SCVTF_ASIMDMISC_R:
		case ENC_UCVTF_ASIMDMISC_R:
		case ENC_FCVTNS_ASIMDMISC_R:
		case ENC_FCVTZU_ASIMDMISC_R:
		{
			arrangement_spec arr_spec = table_2s_4s_r_2d[(dec->sz<<1)|dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_ABS_ASIMDMISC_R:
		case ENC_CLS_ASIMDMISC_R:
		case ENC_CLZ_ASIMDMISC_R:
		case ENC_CNT_ASIMDMISC_R:
		case ENC_NEG_ASIMDMISC_R:
		case ENC_NOT_ASIMDMISC_R:
		case ENC_REV16_ASIMDMISC_R:
		case ENC_REV32_ASIMDMISC_R:
		case ENC_REV64_ASIMDMISC_R:
		case ENC_SQABS_ASIMDMISC_R:
		case ENC_SQNEG_ASIMDMISC_R:
		case ENC_USQADD_ASIMDMISC_R:
		case ENC_SUQADD_ASIMDMISC_R:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ORR_ASIMDSAME_ONLY:
		case ENC_MVN_NOT_ASIMDMISC_R:
		case ENC_RBIT_ASIMDMISC_R:
		{
			arr_spec = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTMS_ASIMDMISC_R:
		case ENC_FCVTMU_ASIMDMISC_R:
		case ENC_FCVTNU_ASIMDMISC_R:
		case ENC_FCVTPS_ASIMDMISC_R:
		case ENC_FCVTPU_ASIMDMISC_R:
		case ENC_FCVTZS_ASIMDMISC_R:
		case ENC_FNEG_ASIMDMISC_R:
		case ENC_FRINT32X_ASIMDMISC_R:
		case ENC_FRINT32Z_ASIMDMISC_R:
		case ENC_FRINTA_ASIMDMISC_R:
		case ENC_FRINTP_ASIMDMISC_R:
		case ENC_FRINTX_ASIMDMISC_R:
		case ENC_FRINTZ_ASIMDMISC_R:
		case ENC_FRSQRTE_ASIMDMISC_R:
		case ENC_FSQRT_ASIMDMISC_R:
		case ENC_FCVTAS_ASIMDMISC_R:
		case ENC_FCVTAU_ASIMDMISC_R:
		case ENC_URECPE_ASIMDMISC_R:
		case ENC_URSQRTE_ASIMDMISC_R:
		{
			arrangement_spec arr_spec = table_2s_4s_r_2d[(dec->sz<<1) | dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCMEQ_ASIMDMISC_FZ:
		case ENC_FCMGE_ASIMDMISC_FZ:
		case ENC_FCMGT_ASIMDMISC_FZ:
		case ENC_FCMLE_ASIMDMISC_FZ:
		case ENC_FCMLT_ASIMDMISC_FZ:
		{
			arrangement_spec arr_spec = table_2s_4s_r_2d[(dec->sz<<1) | dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>, #0.0
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FCMEQ_ASIMDMISCFP16_FZ: // half precision variant
		case ENC_FCMGE_ASIMDMISCFP16_FZ:
		case ENC_FCMGT_ASIMDMISCFP16_FZ:
		case ENC_FCMLE_ASIMDMISCFP16_FZ:
		case ENC_FCMLT_ASIMDMISCFP16_FZ:
		{
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>, #0.0
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_CMEQ_ASIMDMISC_Z:
		case ENC_CMGE_ASIMDMISC_Z:
		case ENC_CMGT_ASIMDMISC_Z:
		case ENC_CMLE_ASIMDMISC_Z:
		case ENC_CMLT_ASIMDMISC_Z:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>, #0
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_IMMEDIATE32(0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_ASIMDSHF_C:
		case ENC_FCVTZU_ASIMDSHF_C:
		case ENC_SCVTF_ASIMDSHF_C:
		case ENC_UCVTF_ASIMDSHF_C:
		{
			arrangement_spec arr_spec = arr_spec_method3(dec->immh, dec->Q);
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Vd>.<T>,<Vn>.<T>, #<fbits>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_SHL_ASIMDSHF_R:
		case ENC_SLI_ASIMDSHF_R:
		case ENC_SQSHLU_ASIMDSHF_R:
		case ENC_SQSHL_ASIMDSHF_R:
		case ENC_SRI_ASIMDSHF_R:
		case ENC_SRSHR_ASIMDSHF_R:
		case ENC_SRSRA_ASIMDSHF_R:
		case ENC_SSHR_ASIMDSHF_R:
		case ENC_SSRA_ASIMDSHF_R:
		case ENC_UQSHL_ASIMDSHF_R:
		case ENC_URSHR_ASIMDSHF_R:
		case ENC_URSRA_ASIMDSHF_R:
		case ENC_USHR_ASIMDSHF_R:
		case ENC_USRA_ASIMDSHF_R:
		{
			unsigned shift = dec->shift;
			arrangement_spec arr_spec = arr_spec_method3(dec->immh, dec->Q);
			// SYNTAX: <Vd>.<T>,<Vn>.<T>, #<shift>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_FABD_ASIMDSAME_ONLY:
		case ENC_FABD_ASIMDSAMEFP16_ONLY:
		case ENC_FACGE_ASIMDSAME_ONLY:
		case ENC_FACGE_ASIMDSAMEFP16_ONLY:
		case ENC_FACGT_ASIMDSAME_ONLY:
		case ENC_FACGT_ASIMDSAMEFP16_ONLY:
		case ENC_FADDP_ASIMDSAME_ONLY:
		case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		case ENC_FADD_ASIMDSAME_ONLY:
		case ENC_FADD_ASIMDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASIMDSAME_ONLY:
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGE_ASIMDSAME_ONLY:
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGT_ASIMDSAME_ONLY:
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY:
		case ENC_FDIV_ASIMDSAME_ONLY:
		case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNMP_ASIMDSAME_ONLY:
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNM_ASIMDSAME_ONLY:
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXP_ASIMDSAME_ONLY:
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAX_ASIMDSAME_ONLY:
		case ENC_FMAX_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNMP_ASIMDSAME_ONLY:
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNM_ASIMDSAME_ONLY:
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMINP_ASIMDSAME_ONLY:
		case ENC_FMINP_ASIMDSAMEFP16_ONLY:
		case ENC_FMIN_ASIMDSAME_ONLY:
		case ENC_FMIN_ASIMDSAMEFP16_ONLY:
		case ENC_FMLA_ASIMDSAME_ONLY:
		case ENC_FMLA_ASIMDSAMEFP16_ONLY:
		case ENC_FMLS_ASIMDSAME_ONLY:
		case ENC_FMLS_ASIMDSAMEFP16_ONLY:
		case ENC_FMULX_ASIMDSAME_ONLY:
		case ENC_FMULX_ASIMDSAMEFP16_ONLY:
		case ENC_FMUL_ASIMDSAME_ONLY:
		case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		case ENC_FRECPS_ASIMDSAME_ONLY:
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASIMDSAME_ONLY:
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY:
		case ENC_FSUB_ASIMDSAME_ONLY:
		case ENC_FSUB_ASIMDSAMEFP16_ONLY:
		{
			if(dec->esize <= 16) // half precision
				arr_spec = table_4h_8h[dec->Q];
			else { // single, double precision
				arr_spec = table_2s_4s_r_2d[(dec->sz<<1) | dec->Q];
			}

			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_T(arr_spec, dec->m);
			// SYNTAX-END
			break;
		}

		case ENC_ADDP_ASIMDSAME_ONLY:
		case ENC_ADD_ASIMDSAME_ONLY:
		case ENC_AND_ASIMDSAME_ONLY:
		case ENC_BIF_ASIMDSAME_ONLY:
		case ENC_BIT_ASIMDSAME_ONLY:
		case ENC_BSL_ASIMDSAME_ONLY:
		case ENC_CMEQ_ASIMDSAME_ONLY:
		case ENC_CMGE_ASIMDSAME_ONLY:
		case ENC_CMGT_ASIMDSAME_ONLY:
		case ENC_CMHI_ASIMDSAME_ONLY:
		case ENC_CMHS_ASIMDSAME_ONLY:
		case ENC_CMTST_ASIMDSAME_ONLY:
		case ENC_EOR_ASIMDSAME_ONLY:
		case ENC_MLA_ASIMDSAME_ONLY:
		case ENC_MLS_ASIMDSAME_ONLY:
		case ENC_MUL_ASIMDSAME_ONLY:
		case ENC_PMUL_ASIMDSAME_ONLY:
		case ENC_SABA_ASIMDSAME_ONLY:
		case ENC_SABD_ASIMDSAME_ONLY:
		case ENC_SHADD_ASIMDSAME_ONLY:
		case ENC_SHSUB_ASIMDSAME_ONLY:
		case ENC_SMAXP_ASIMDSAME_ONLY:
		case ENC_SMAX_ASIMDSAME_ONLY:
		case ENC_SMINP_ASIMDSAME_ONLY:
		case ENC_SMIN_ASIMDSAME_ONLY:
		case ENC_SQADD_ASIMDSAME_ONLY:
		case ENC_SQDMULH_ASIMDSAME_ONLY:
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY:
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY:
		case ENC_SQRDMULH_ASIMDSAME_ONLY:
		case ENC_SQRSHL_ASIMDSAME_ONLY:
		case ENC_SQSHL_ASIMDSAME_ONLY:
		case ENC_SQSUB_ASIMDSAME_ONLY:
		case ENC_SRHADD_ASIMDSAME_ONLY:
		case ENC_SRSHL_ASIMDSAME_ONLY:
		case ENC_SSHL_ASIMDSAME_ONLY:
		case ENC_SUB_ASIMDSAME_ONLY:
		case ENC_TRN1_ASIMDPERM_ONLY:
		case ENC_TRN2_ASIMDPERM_ONLY:
		case ENC_UABA_ASIMDSAME_ONLY:
		case ENC_UABD_ASIMDSAME_ONLY:
		case ENC_UHADD_ASIMDSAME_ONLY:
		case ENC_UHSUB_ASIMDSAME_ONLY:
		case ENC_UMAXP_ASIMDSAME_ONLY:
		case ENC_UMAX_ASIMDSAME_ONLY:
		case ENC_UMINP_ASIMDSAME_ONLY:
		case ENC_UMIN_ASIMDSAME_ONLY:
		case ENC_UQADD_ASIMDSAME_ONLY:
		case ENC_UQRSHL_ASIMDSAME_ONLY:
		case ENC_UQSHL_ASIMDSAME_ONLY:
		case ENC_UQSUB_ASIMDSAME_ONLY:
		case ENC_URHADD_ASIMDSAME_ONLY:
		case ENC_URSHL_ASIMDSAME_ONLY:
		case ENC_USHL_ASIMDSAME_ONLY:
		case ENC_UZP1_ASIMDPERM_ONLY:
		case ENC_UZP2_ASIMDPERM_ONLY:
		case ENC_ZIP1_ASIMDPERM_ONLY:
		case ENC_ZIP2_ASIMDPERM_ONLY:
		case ENC_ORR_ASIMDSAME_ONLY:
		{
			if(dec->encoding == ENC_ORR_ASIMDSAME_ONLY)
				arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[dec->Q];
			else
				arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[dec->size*2 + dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_T(arr_spec, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ORN_ASIMDSAME_ONLY:
		case ENC_BIC_ASIMDSAME_ONLY:
		{
			arrangement_spec arr_spec = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<T>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_T(arr_spec, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_EXT_ASIMDEXT_ONLY:
		{
			arrangement_spec arr_spec = table_8b_16b[dec->Q];
			uint64_t const_ = dec->imm4;
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<T>, #<const>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_T(arr_spec, dec->m);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_FCADD_ASIMDSAME2_C:
		case ENC_FCMLA_ASIMDSAME2_C:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			uint64_t rotate;
			if(dec->encoding == ENC_FCADD_ASIMDSAME2_C)
				rotate = dec->rot ? 270 : 90;
			else
				rotate = 90*dec->rot;
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<T>, #<rotate>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_T(arr_spec, dec->m);
			ADD_OPERAND_ROTATE;
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_ASIMDELEM_R_SD:
		case ENC_FMLS_ASIMDELEM_R_SD:
		case ENC_FMULX_ASIMDELEM_R_SD:
		case ENC_FMUL_ASIMDELEM_R_SD:
		{
			arrangement_spec arr_spec = table_2s_r_4s_2d[(dec->Q<<1) | dec->sz];
			unsigned elem_sz = table_s_d[dec->sz];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_MLA_ASIMDELEM_R:
		case ENC_MLS_ASIMDELEM_R:
		case ENC_MUL_ASIMDELEM_R:
		case ENC_SQDMULH_ASIMDELEM_R:
		case ENC_SQRDMLAH_ASIMDELEM_R:
		case ENC_SQRDMLSH_ASIMDELEM_R:
		case ENC_SQRDMULH_ASIMDELEM_R:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			unsigned elem_sz = table_r_h_s_d[dec->size];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FCMLA_ASIMDELEM_C_H:
		case ENC_FCMLA_ASIMDELEM_C_S:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1)|dec->Q];
			unsigned elem_sz = table_r_h_s_d[dec->size];
			uint64_t rotate = 90*dec->rot;
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.<Ts>[<index>], #<rotate>
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			ADD_OPERAND_ROTATE;
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_ASIMDELEM_RH_H:
		case ENC_FMLS_ASIMDELEM_RH_H:
		case ENC_FMULX_ASIMDELEM_RH_H:
		case ENC_FMUL_ASIMDELEM_RH_H:
		{
			arrangement_spec arr_spec = table_4h_8h[dec->Q];
			// SYNTAX: <Vd>.<T>,<Vn>.<T>,<Vm>.H[<index>]
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_T(arr_spec, dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_DUP_ASIMDINS_DV_V:
		{
			arrangement_spec arr_spec = arr_spec_method4(dec->imm5, dec->Q);
			unsigned elem_sz = size_spec_method3(dec->imm5);
			// SYNTAX: <Vd>.<T>,<Vn>.<Ts>[<index>]
			ADD_OPERAND_VREG_T(arr_spec, dec->d);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SADALP_ASIMDMISC_P:
		case ENC_SADDLP_ASIMDMISC_P:
		case ENC_UADALP_ASIMDMISC_P:
		case ENC_UADDLP_ASIMDMISC_P:
		{
			arrangement_spec arr_spec_a = table_4h_8h_2s_4s_1d_2d_r_r[(dec->size<<1)|dec->Q];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_BFDOT_ASIMDELEM_E:
		{
			arrangement_spec arr_spec_2h = _2H;
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.2H[<index>]
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_T(arr_spec_2h, dec->m);
			ADD_OPERAND_INDEX;
			// SYNTAX-END
			break;
		}
		case ENC_SDOT_ASIMDELEM_D:
		case ENC_SUDOT_ASIMDELEM_D:
		case ENC_UDOT_ASIMDELEM_D:
		case ENC_USDOT_ASIMDELEM_D:
		{
			arrangement_spec arr_spec_4b = _4B;
			arrangement_spec arr_spec_a = table_2s_4s[dec->Q];
			arrangement_spec arr_spec_b = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.4B[<index>]
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_T_INDEXED(arr_spec_4b, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FMLSL2_ASIMDSAME_F:
		case ENC_FMLAL2_ASIMDSAME_F:
		{
			arrangement_spec arr_spec_a = table_2s_4s[dec->Q];
			arrangement_spec arr_spec_b = table_2h_4h[dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_TB(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_BFDOT_ASIMDSAME2_D:
		case ENC_FMLAL_ASIMDSAME_F:
		case ENC_FMLSL_ASIMDSAME_F:
		{
			arrangement_spec arr_spec_a = table_2s_4s[dec->Q];
			arrangement_spec arr_spec_b = table_2h_4h[dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_TB(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SDOT_ASIMDSAME2_D:
		case ENC_UDOT_ASIMDSAME2_D:
		case ENC_USDOT_ASIMDSAME2_D:
		{
			arrangement_spec arr_spec_a = table_2s_4s[dec->Q];
			arrangement_spec arr_spec_b = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_TB(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMLAL2_ASIMDELEM_LH:
		case ENC_FMLAL_ASIMDELEM_LH:
		case ENC_FMLSL2_ASIMDELEM_LH:
		case ENC_FMLSL_ASIMDELEM_LH:
		{
			arrangement_spec arr_spec_a = table_2s_4s[dec->Q];
			arrangement_spec arr_spec_b = table_2h_4h[dec->Q];
			// SYNTAX: <Vd>.<Ta>,<Vn>.<Tb>,<Vm>.H[<index>]
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_TBL_ASIMDTBL_L4_4:
		case ENC_TBX_ASIMDTBL_L4_4:
		{
			arrangement_spec arr_spec_a = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,{<Vn>.16B,<Vn+1>.16B,<Vn+2>.16B,<Vn+3>.16B},<Vm>.<Ta>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_MULTIREG_4(REG_V_BASE, 16, 1, dec->n);
			ADD_OPERAND_VREG_TA(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_TBL_ASIMDTBL_L3_3:
		case ENC_TBX_ASIMDTBL_L3_3:
		{
			arrangement_spec arr_spec_a = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,{<Vn>.16B,<Vn+1>.16B,<Vn+2>.16B},<Vm>.<Ta>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, 16, 1, dec->n);
			ADD_OPERAND_VREG_TA(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_TBL_ASIMDTBL_L2_2:
		case ENC_TBX_ASIMDTBL_L2_2:
		{
			arrangement_spec arr_spec_a = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,{<Vn>.16B,<Vn+1>.16B},<Vm>.<Ta>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_MULTIREG_2(REG_V_BASE, 16, 1, dec->n);
			ADD_OPERAND_VREG_TA(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_TBL_ASIMDTBL_L1_1:
		case ENC_TBX_ASIMDTBL_L1_1:
		{
			arrangement_spec arr_spec_a = table_8b_16b[dec->Q];
			// SYNTAX: <Vd>.<Ta>,{<Vn>.16B},<Vm>.<Ta>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_MULTIREG_1(REG_V_BASE, 16, 1, dec->n);
			ADD_OPERAND_VREG_TA(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_INS_ASIMDINS_IV_V:
		case ENC_MOV_INS_ASIMDINS_IV_V:
		{
			unsigned elem_sz = size_spec_method3(dec->imm5);

			uint64_t INDEX1=0, INDEX2=0;
			if((dec->imm5 & 1) == 1) {
				INDEX1 = (dec->imm5>>1) & 15;
				INDEX2 = (dec->imm4>>0) & 15;
			}
			if((dec->imm5 & 3) == 2) {
				INDEX1 = (dec->imm5>>2) & 7;
				INDEX2 = (dec->imm4>>1) & 7;
			}
			if((dec->imm5 & 7) == 4) {
				INDEX1 = (dec->imm5>>3) & 3;
				INDEX2 = (dec->imm4>>2) & 3;
			}
			if((dec->imm5 & 15) == 8) {
				INDEX1 = (dec->imm5>>4) & 1;
				INDEX2 = (dec->imm4>>3) & 1;
			}

			// SYNTAX: <Vd>.<Ts>[<index1>],<Vn>.<Ts>[<index2>]
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->d, dec->dst_index);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->n, dec->src_index);
			// SYNTAX-END
			break;
		}
		case ENC_INS_ASIMDINS_IR_R:
		case ENC_MOV_INS_ASIMDINS_IR_R:
		{
			unsigned rn_base = rwwwx_0123x_reg(dec->imm5, dec->Rn);
			unsigned elem_sz = size_spec_method3(dec->imm5);
			// SYNTAX: <Vd>.<Ts>[<index>],<R><n>
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->d, dec->index);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_V64I_FLOAT2INT:
		{
			// SYNTAX: <Vd>.D[1],<Xn>
			ADD_OPERAND_VREG_ESIZE_INDEXED(8, dec->d, 1);
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_MOVN_32_MOVEWIDE:
		case ENC_MOV_MOVZ_32_MOVEWIDE:
		{
			int32_t imm = dec->imm << (dec->hw*16);
			if(dec->encoding == ENC_MOV_MOVN_32_MOVEWIDE)
				imm ^= 0xFFFFFFFF;

			// SYNTAX: <Wd>, #<imm32>
			ADD_OPERAND_WD;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_MOVK_32_MOVEWIDE:
		case ENC_MOVN_32_MOVEWIDE:
		case ENC_MOVZ_32_MOVEWIDE:
		{
			uint64_t imm = dec->imm & 0xFFFFFFFF;
			// SYNTAX: <Wd>, #<imm32>{, LSL #<shift>}
			ADD_OPERAND_WD;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			if(dec->hw) {
				dec->operands[1].shiftType = ShiftType_LSL;
				dec->operands[1].shiftValue = 16;
				dec->operands[1].shiftValueUsed = 1;
			}
			break;
		}
		case ENC_BFC_BFM_32M_BITFIELD: // 32-bit (sf == 0 && N == 0)
		{
			unsigned lsb = 32 - IMMR;
			unsigned width = IMMS+1;
			// SYNTAX: <Wd>, #<lsb>, #<width>
			ADD_OPERAND_WD;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_32D_FLOAT2INT:
		case ENC_FCVTAU_32D_FLOAT2INT:
		case ENC_FCVTMS_32D_FLOAT2INT:
		case ENC_FCVTMU_32D_FLOAT2INT:
		case ENC_FCVTNS_32D_FLOAT2INT:
		case ENC_FCVTNU_32D_FLOAT2INT:
		case ENC_FCVTPS_32D_FLOAT2INT:
		case ENC_FCVTPU_32D_FLOAT2INT:
		case ENC_FCVTZS_32D_FLOAT2INT:
		case ENC_FCVTZU_32D_FLOAT2INT:
		case ENC_FJCVTZS_32D_FLOAT2INT:
		{
			// SYNTAX: <Wd>,<Dn>
			ADD_OPERAND_WD;
			ADD_OPERAND_DN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_32D_FLOAT2FIX:
		case ENC_FCVTZU_32D_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Wd>,<Dn>, #<fbits>
			ADD_OPERAND_WD;
			ADD_OPERAND_DN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_32H_FLOAT2INT:
		case ENC_FCVTAU_32H_FLOAT2INT:
		case ENC_FCVTMS_32H_FLOAT2INT:
		case ENC_FCVTMU_32H_FLOAT2INT:
		case ENC_FCVTNS_32H_FLOAT2INT:
		case ENC_FCVTNU_32H_FLOAT2INT:
		case ENC_FCVTPS_32H_FLOAT2INT:
		case ENC_FCVTPU_32H_FLOAT2INT:
		case ENC_FCVTZS_32H_FLOAT2INT:
		case ENC_FCVTZU_32H_FLOAT2INT:
		case ENC_FMOV_32H_FLOAT2INT:
		{
			// SYNTAX: <Wd>,<Hn>
			ADD_OPERAND_WD;
			ADD_OPERAND_HN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_32H_FLOAT2FIX:
		case ENC_FCVTZU_32H_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Wd>,<Hn>, #<fbits>
			ADD_OPERAND_WD;
			ADD_OPERAND_HN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_32S_FLOAT2INT:
		case ENC_FCVTAU_32S_FLOAT2INT:
		case ENC_FCVTMS_32S_FLOAT2INT:
		case ENC_FCVTMU_32S_FLOAT2INT:
		case ENC_FCVTNS_32S_FLOAT2INT:
		case ENC_FCVTNU_32S_FLOAT2INT:
		case ENC_FCVTPS_32S_FLOAT2INT:
		case ENC_FCVTPU_32S_FLOAT2INT:
		case ENC_FCVTZS_32S_FLOAT2INT:
		case ENC_FCVTZU_32S_FLOAT2INT:
		case ENC_FMOV_32S_FLOAT2INT:
		{
			// SYNTAX: <Wd>,<Sn>
			ADD_OPERAND_WD;
			ADD_OPERAND_SN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_32S_FLOAT2FIX:
		case ENC_FCVTZU_32S_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Wd>,<Sn>, #<fbits>
			ADD_OPERAND_WD;
			ADD_OPERAND_SN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_SMOV_ASIMDINS_W_W:
		case ENC_UMOV_ASIMDINS_W_W:
		{
			unsigned elem_sz = dec->esize/8;
			// SYNTAX: <Wd>,<Vn>.<Ts>[<index>]
			ADD_OPERAND_WD;
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_UMOV_ASIMDINS_W_W:
		{
			// SYNTAX: <Wd>,<Vn>.S[<index>]
			ADD_OPERAND_WD;
			ADD_OPERAND_VREG_ESIZE_INDEXED(4, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ORR_32_LOG_SHIFT:
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY:
		case ENC_NGC_SBC_32_ADDSUB_CARRY:
		{
			// SYNTAX: <Wd>,<Wm>
			ADD_OPERAND_WD;
			ADD_OPERAND_WM;
			// SYNTAX-END
			break;
		}
		case ENC_MVN_ORN_32_LOG_SHIFT:
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT:
		case ENC_NEG_SUB_32_ADDSUB_SHIFT:
		{
			// SYNTAX: <Wd>,<Wm>{,<shift>#<amount>}
			ADD_OPERAND_WD;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_CLS_32_DP_1SRC:
		case ENC_CLZ_32_DP_1SRC:
		case ENC_RBIT_32_DP_1SRC:
		case ENC_REV16_32_DP_1SRC:
		case ENC_REV_32_DP_1SRC:
		case ENC_SXTB_SBFM_32M_BITFIELD:
		case ENC_SXTH_SBFM_32M_BITFIELD:
		case ENC_UXTB_UBFM_32M_BITFIELD:
		case ENC_UXTH_UBFM_32M_BITFIELD:
		{
			// SYNTAX: <Wd>,<Wn>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_ANDS_32S_LOG_IMM:
		{
			uint64_t imm = dec->imm & 0xFFFFFFFF;
			// SYNTAX: <Wd>,<Wn>, #<imm>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_BFM_32M_BITFIELD:
		case ENC_SBFM_32M_BITFIELD:
		case ENC_UBFM_32M_BITFIELD:
		{
			// SYNTAX: <Wd>,<Wn>, #<immr>, #<imms>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_IMMR;
			ADD_OPERAND_IMMS;
			// SYNTAX-END
			break;
		}
		case ENC_BFI_BFM_32M_BITFIELD:
		case ENC_SBFIZ_SBFM_32M_BITFIELD:
		case ENC_UBFIZ_UBFM_32M_BITFIELD:
		case ENC_UBFX_UBFM_32M_BITFIELD:
		{
			unsigned lsb, width;
			switch(dec->encoding) {
				case ENC_BFI_BFM_32M_BITFIELD:
				case ENC_SBFIZ_SBFM_32M_BITFIELD:
				case ENC_UBFIZ_UBFM_32M_BITFIELD:
					lsb = -IMMR % 32;
					width = IMMS+1;
					break;
				default:
					lsb = IMMR;
					width = IMMS-IMMR+1;
			}

			// SYNTAX: <Wd>,<Wn>, #<lsb>, #<width>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_BFXIL_BFM_32M_BITFIELD:
		case ENC_SBFX_SBFM_32M_BITFIELD:
		{
			unsigned lsb = IMMR;
			unsigned width = IMMS-IMMR+1;
			// SYNTAX: <Wd>,<Wn>, #<lsb>, #<width>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_ASR_SBFM_32M_BITFIELD:
		case ENC_LSL_UBFM_32M_BITFIELD:
		case ENC_LSR_UBFM_32M_BITFIELD:
		{
			unsigned const_ = (dec->encoding == ENC_LSL_UBFM_32M_BITFIELD) ?
				31 - dec->imms : dec->immr;
			// SYNTAX: <Wd>,<Wn>, #<const>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ADCS_32_ADDSUB_CARRY:
		case ENC_ADC_32_ADDSUB_CARRY:
		case ENC_ASRV_32_DP_2SRC:
		case ENC_ASR_ASRV_32_DP_2SRC:
		case ENC_CRC32B_32C_DP_2SRC:
		case ENC_CRC32CB_32C_DP_2SRC:
		case ENC_CRC32CH_32C_DP_2SRC:
		case ENC_CRC32CW_32C_DP_2SRC:
		case ENC_CRC32H_32C_DP_2SRC:
		case ENC_CRC32W_32C_DP_2SRC:
		case ENC_LSLV_32_DP_2SRC:
		case ENC_LSL_LSLV_32_DP_2SRC:
		case ENC_LSRV_32_DP_2SRC:
		case ENC_LSR_LSRV_32_DP_2SRC:
		case ENC_MNEG_MSUB_32A_DP_3SRC:
		case ENC_MUL_MADD_32A_DP_3SRC:
		case ENC_RORV_32_DP_2SRC:
		case ENC_ROR_RORV_32_DP_2SRC:
		case ENC_SBCS_32_ADDSUB_CARRY:
		case ENC_SBC_32_ADDSUB_CARRY:
		case ENC_SDIV_32_DP_2SRC:
		case ENC_UDIV_32_DP_2SRC:
		{
			// SYNTAX: <Wd>,<Wn>,<Wm>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			// SYNTAX-END
			break;
		}
		case ENC_EXTR_32_EXTRACT:
		{
			unsigned lsb = dec->lsb;
			// SYNTAX: <Wd>,<Wn>,<Wm>, #<lsb>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			ADD_OPERAND_LSB;
			// SYNTAX-END
			break;
		}
		case ENC_MADD_32A_DP_3SRC:
		case ENC_MSUB_32A_DP_3SRC:
		{
			// SYNTAX: <Wd>,<Wn>,<Wm>,<Wa>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			ADD_OPERAND_WA;
			// SYNTAX-END
			break;
		}
		case ENC_CSEL_32_CONDSEL:
		case ENC_CSINC_32_CONDSEL:
		case ENC_CSINV_32_CONDSEL:
		case ENC_CSNEG_32_CONDSEL:
		{
			// SYNTAX: <Wd>,<Wn>,<Wm>,<cond>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_ADDS_32_ADDSUB_SHIFT:
		case ENC_ADD_32_ADDSUB_SHIFT:
		case ENC_ANDS_32_LOG_SHIFT:
		case ENC_AND_32_LOG_SHIFT:
		case ENC_BICS_32_LOG_SHIFT:
		case ENC_BIC_32_LOG_SHIFT:
		case ENC_EON_32_LOG_SHIFT:
		case ENC_EOR_32_LOG_SHIFT:
		case ENC_ORN_32_LOG_SHIFT:
		case ENC_ORR_32_LOG_SHIFT:
		case ENC_SUBS_32_ADDSUB_SHIFT:
		case ENC_SUB_32_ADDSUB_SHIFT:
		{
			// SYNTAX: <Wd>,<Wn>,<Wm>{,<shift>#<amount>}
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_CRC32CX_64C_DP_2SRC:
		case ENC_CRC32X_64C_DP_2SRC:
		{
			// SYNTAX: <Wd>,<Wn>,<Xm>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_CINC_CSINC_32_CONDSEL:
		case ENC_CINV_CSINV_32_CONDSEL:
		case ENC_CNEG_CSNEG_32_CONDSEL:
		{
			// SYNTAX: <Wd>,<Wn>,<cond_neg>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_COND_NEG;
			// SYNTAX-END
			break;
		}
		case ENC_ADDS_32S_ADDSUB_IMM:
		case ENC_SUBS_32S_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Wd>,<Wn|WSP>, #<imm>{,<shift>}
			ADD_OPERAND_WD;
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_ADDS_32S_ADDSUB_EXT:
		case ENC_SUBS_32S_ADDSUB_EXT:
		{
			// SYNTAX: <Wd>,<Wn|WSP>,<Wm>{,<extend>{#<amount>}}
			ADD_OPERAND_WD;
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_32(dec->n);
			break;
		}
		case ENC_ROR_EXTR_32_EXTRACT:
		{
			unsigned shift = IMMS;
			// SYNTAX: <Wd>,<Wn>, #<shift>
			ADD_OPERAND_WD;
			ADD_OPERAND_WN;
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_CSETM_CSINV_32_CONDSEL:
		case ENC_CSET_CSINC_32_CONDSEL:
		{
			// SYNTAX: <Wd>,<cond_neg>
			ADD_OPERAND_WD;
			ADD_OPERAND_COND_NEG;
			// SYNTAX-END
			break;
		}
		case ENC_UQDECP_R_P_R_UW:
		case ENC_UQINCP_R_P_R_UW:
		{
			unsigned elem_sz = dec->esize / 8;
			// SYNTAX: <Wdn>,<Pm>.<Ts>
			ADD_OPERAND_WDN;
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_UQDECB_R_RS_UW:
		case ENC_UQDECD_R_RS_UW:
		case ENC_UQDECH_R_RS_UW:
		case ENC_UQDECW_R_RS_UW:
		case ENC_UQINCB_R_RS_UW:
		case ENC_UQINCD_R_RS_UW:
		case ENC_UQINCH_R_RS_UW:
		case ENC_UQINCW_R_RS_UW:
		{
			// SYNTAX: <Wdn>{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_WDN;
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ORR_32_LOG_IMM:
		{
			uint32_t imm = dec->imm & 0xFFFFFFFF;
			// SYNTAX: <Wd|WSP>, #<imm>
			ADD_OPERAND_WD_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_AND_32_LOG_IMM:
		case ENC_EOR_32_LOG_IMM:
		case ENC_ORR_32_LOG_IMM:
		{
			uint64_t imm = dec->imm & 0xFFFFFFFF;
			// SYNTAX: <Wd|WSP>,<Wn>, #<imm>
			ADD_OPERAND_WD_SP;
			ADD_OPERAND_WN;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ADD_32_ADDSUB_IMM:
		{
			// SYNTAX: <Wd|WSP>,<Wn|WSP>
			ADD_OPERAND_WD_SP;
			ADD_OPERAND_WN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_ADD_32_ADDSUB_IMM:
		case ENC_SUB_32_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Wd|WSP>,<Wn|WSP>, #<imm>{,<shift>}
			ADD_OPERAND_WD_SP;
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_ADD_32_ADDSUB_EXT:
		case ENC_SUB_32_ADDSUB_EXT:
		{
			// SYNTAX: <Wd|WSP>,<Wn|WSP>,<Wm>{,<extend>{#<amount>}}
			ADD_OPERAND_WD_SP;
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_32(dec->n);
			break;
		}
		case ENC_SETF16_ONLY_SETF:
		case ENC_SETF8_ONLY_SETF:
		{
			// SYNTAX: <Wn>
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_TST_ANDS_32S_LOG_IMM:
		{
			uint64_t imm = dec->imm & 0xFFFFFFFF;
			// SYNTAX: <Wn>, #<imm>
			ADD_OPERAND_WN;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_CCMN_32_CONDCMP_IMM:
		case ENC_CCMP_32_CONDCMP_IMM:
		{
			uint32_t imm = dec->imm;
			// SYNTAX: <Wn>, #<imm>, #<nzcv>,<cond>
			ADD_OPERAND_WN;
			ADD_OPERAND_UIMM32;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_CCMN_32_CONDCMP_REG:
		case ENC_CCMP_32_CONDCMP_REG:
		{
			// SYNTAX: <Wn>,<Wm>, #<nzcv>,<cond>
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT:
		case ENC_TST_ANDS_32_LOG_SHIFT:
		{
			// SYNTAX: <Wn>,<Wm>{,<shift>#<amount>}
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_CMN_ADDS_32S_ADDSUB_IMM:
		case ENC_CMP_SUBS_32S_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Wn|WSP>, #<imm>{,<shift>}
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_CMN_ADDS_32S_ADDSUB_EXT:
		case ENC_CMP_SUBS_32S_ADDSUB_EXT:
		{
			// SYNTAX: <Wn|WSP>,<Wm>{,<extend>{#<amount>}}
			ADD_OPERAND_WN_SP;
			ADD_OPERAND_WM;
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_32(dec->n);
			//dec->operands[i-1].shiftValueUsed = 1;
			break;
		}
		case ENC_STADDB_LDADDB_32_MEMOP:
		case ENC_STADDH_LDADDH_32_MEMOP:
		case ENC_STADDLB_LDADDLB_32_MEMOP:
		case ENC_STADDLH_LDADDLH_32_MEMOP:
		case ENC_STADDL_LDADDL_32_MEMOP:
		case ENC_STADD_LDADD_32_MEMOP:
		case ENC_STCLRB_LDCLRB_32_MEMOP:
		case ENC_STCLRH_LDCLRH_32_MEMOP:
		case ENC_STCLRLB_LDCLRLB_32_MEMOP:
		case ENC_STCLRLH_LDCLRLH_32_MEMOP:
		case ENC_STCLRL_LDCLRL_32_MEMOP:
		case ENC_STCLR_LDCLR_32_MEMOP:
		case ENC_STEORB_LDEORB_32_MEMOP:
		case ENC_STEORH_LDEORH_32_MEMOP:
		case ENC_STEORLB_LDEORLB_32_MEMOP:
		case ENC_STEORLH_LDEORLH_32_MEMOP:
		case ENC_STEORL_LDEORL_32_MEMOP:
		case ENC_STEOR_LDEOR_32_MEMOP:
		case ENC_STSETB_LDSETB_32_MEMOP:
		case ENC_STSETH_LDSETH_32_MEMOP:
		case ENC_STSETLB_LDSETLB_32_MEMOP:
		case ENC_STSETLH_LDSETLH_32_MEMOP:
		case ENC_STSETL_LDSETL_32_MEMOP:
		case ENC_STSET_LDSET_32_MEMOP:
		case ENC_STSMAXB_LDSMAXB_32_MEMOP:
		case ENC_STSMAXH_LDSMAXH_32_MEMOP:
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP:
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP:
		case ENC_STSMAXL_LDSMAXL_32_MEMOP:
		case ENC_STSMAX_LDSMAX_32_MEMOP:
		case ENC_STSMINB_LDSMINB_32_MEMOP:
		case ENC_STSMINH_LDSMINH_32_MEMOP:
		case ENC_STSMINLB_LDSMINLB_32_MEMOP:
		case ENC_STSMINLH_LDSMINLH_32_MEMOP:
		case ENC_STSMINL_LDSMINL_32_MEMOP:
		case ENC_STSMIN_LDSMIN_32_MEMOP:
		case ENC_STUMAXB_LDUMAXB_32_MEMOP:
		case ENC_STUMAXH_LDUMAXH_32_MEMOP:
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP:
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP:
		case ENC_STUMAXL_LDUMAXL_32_MEMOP:
		case ENC_STUMAX_LDUMAX_32_MEMOP:
		case ENC_STUMINB_LDUMINB_32_MEMOP:
		case ENC_STUMINH_LDUMINH_32_MEMOP:
		case ENC_STUMINLB_LDUMINLB_32_MEMOP:
		case ENC_STUMINLH_LDUMINLH_32_MEMOP:
		case ENC_STUMINL_LDUMINL_32_MEMOP:
		case ENC_STUMIN_LDUMIN_32_MEMOP:
		{
			// SYNTAX: <Ws>, [<Xn|SP>]
			ADD_OPERAND_WS;
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CASPAL_CP32_LDSTEXCL:
		case ENC_CASPA_CP32_LDSTEXCL:
		case ENC_CASPL_CP32_LDSTEXCL:
		case ENC_CASP_CP32_LDSTEXCL:
		{
			// SYNTAX: <Ws>,<W(s+1)>,<Wt>,<W(t+1)>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WS;
			ADD_OPERAND_WS_PLUS_1;
			ADD_OPERAND_WT;
			ADD_OPERAND_WT_PLUS_1;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_STLXP_SP32_LDSTEXCL:
		case ENC_STXP_SP32_LDSTEXCL:
		{
			// SYNTAX: <Ws>,<Wt1>,<Wt2>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WS;
			ADD_OPERAND_WT1;
			ADD_OPERAND_WT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LDADDAB_32_MEMOP:
		case ENC_LDADDAH_32_MEMOP:
		case ENC_LDADDALB_32_MEMOP:
		case ENC_LDADDALH_32_MEMOP:
		case ENC_LDADDAL_32_MEMOP:
		case ENC_LDADDA_32_MEMOP:
		case ENC_LDADDB_32_MEMOP:
		case ENC_LDADDH_32_MEMOP:
		case ENC_LDADDLB_32_MEMOP:
		case ENC_LDADDLH_32_MEMOP:
		case ENC_LDADDL_32_MEMOP:
		case ENC_LDADD_32_MEMOP:
		case ENC_LDCLRAB_32_MEMOP:
		case ENC_LDCLRAH_32_MEMOP:
		case ENC_LDCLRALB_32_MEMOP:
		case ENC_LDCLRALH_32_MEMOP:
		case ENC_LDCLRAL_32_MEMOP:
		case ENC_LDCLRA_32_MEMOP:
		case ENC_LDCLRB_32_MEMOP:
		case ENC_LDCLRH_32_MEMOP:
		case ENC_LDCLRLB_32_MEMOP:
		case ENC_LDCLRLH_32_MEMOP:
		case ENC_LDCLRL_32_MEMOP:
		case ENC_LDCLR_32_MEMOP:
		case ENC_LDEORAB_32_MEMOP:
		case ENC_LDEORAH_32_MEMOP:
		case ENC_LDEORALB_32_MEMOP:
		case ENC_LDEORALH_32_MEMOP:
		case ENC_LDEORAL_32_MEMOP:
		case ENC_LDEORA_32_MEMOP:
		case ENC_LDEORB_32_MEMOP:
		case ENC_LDEORH_32_MEMOP:
		case ENC_LDEORLB_32_MEMOP:
		case ENC_LDEORLH_32_MEMOP:
		case ENC_LDEORL_32_MEMOP:
		case ENC_LDEOR_32_MEMOP:
		case ENC_LDSETAB_32_MEMOP:
		case ENC_LDSETAH_32_MEMOP:
		case ENC_LDSETALB_32_MEMOP:
		case ENC_LDSETALH_32_MEMOP:
		case ENC_LDSETAL_32_MEMOP:
		case ENC_LDSETA_32_MEMOP:
		case ENC_LDSETB_32_MEMOP:
		case ENC_LDSETH_32_MEMOP:
		case ENC_LDSETLB_32_MEMOP:
		case ENC_LDSETLH_32_MEMOP:
		case ENC_LDSETL_32_MEMOP:
		case ENC_LDSET_32_MEMOP:
		case ENC_LDSMAXAB_32_MEMOP:
		case ENC_LDSMAXAH_32_MEMOP:
		case ENC_LDSMAXALB_32_MEMOP:
		case ENC_LDSMAXALH_32_MEMOP:
		case ENC_LDSMAXAL_32_MEMOP:
		case ENC_LDSMAXA_32_MEMOP:
		case ENC_LDSMAXB_32_MEMOP:
		case ENC_LDSMAXH_32_MEMOP:
		case ENC_LDSMAXLB_32_MEMOP:
		case ENC_LDSMAXLH_32_MEMOP:
		case ENC_LDSMAXL_32_MEMOP:
		case ENC_LDSMAX_32_MEMOP:
		case ENC_LDSMINAB_32_MEMOP:
		case ENC_LDSMINAH_32_MEMOP:
		case ENC_LDSMINALB_32_MEMOP:
		case ENC_LDSMINALH_32_MEMOP:
		case ENC_LDSMINAL_32_MEMOP:
		case ENC_LDSMINA_32_MEMOP:
		case ENC_LDSMINB_32_MEMOP:
		case ENC_LDSMINH_32_MEMOP:
		case ENC_LDSMINLB_32_MEMOP:
		case ENC_LDSMINLH_32_MEMOP:
		case ENC_LDSMINL_32_MEMOP:
		case ENC_LDSMIN_32_MEMOP:
		case ENC_LDUMAXAB_32_MEMOP:
		case ENC_LDUMAXAH_32_MEMOP:
		case ENC_LDUMAXALB_32_MEMOP:
		case ENC_LDUMAXALH_32_MEMOP:
		case ENC_LDUMAXAL_32_MEMOP:
		case ENC_LDUMAXA_32_MEMOP:
		case ENC_LDUMAXB_32_MEMOP:
		case ENC_LDUMAXH_32_MEMOP:
		case ENC_LDUMAXLB_32_MEMOP:
		case ENC_LDUMAXLH_32_MEMOP:
		case ENC_LDUMAXL_32_MEMOP:
		case ENC_LDUMAX_32_MEMOP:
		case ENC_LDUMINAB_32_MEMOP:
		case ENC_LDUMINAH_32_MEMOP:
		case ENC_LDUMINALB_32_MEMOP:
		case ENC_LDUMINALH_32_MEMOP:
		case ENC_LDUMINAL_32_MEMOP:
		case ENC_LDUMINA_32_MEMOP:
		case ENC_LDUMINB_32_MEMOP:
		case ENC_LDUMINH_32_MEMOP:
		case ENC_LDUMINLB_32_MEMOP:
		case ENC_LDUMINLH_32_MEMOP:
		case ENC_LDUMINL_32_MEMOP:
		case ENC_LDUMIN_32_MEMOP:
		case ENC_SWPAB_32_MEMOP:
		case ENC_SWPAH_32_MEMOP:
		case ENC_SWPALB_32_MEMOP:
		case ENC_SWPALH_32_MEMOP:
		case ENC_SWPAL_32_MEMOP:
		case ENC_SWPA_32_MEMOP:
		case ENC_SWPB_32_MEMOP:
		case ENC_SWPH_32_MEMOP:
		case ENC_SWPLB_32_MEMOP:
		case ENC_SWPLH_32_MEMOP:
		case ENC_SWPL_32_MEMOP:
		case ENC_SWP_32_MEMOP:
		{
			// SYNTAX: <Ws>,<Wt>, [<Xn|SP>]
			ADD_OPERAND_WS;
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CASAB_C32_LDSTEXCL:
		case ENC_CASAH_C32_LDSTEXCL:
		case ENC_CASALB_C32_LDSTEXCL:
		case ENC_CASALH_C32_LDSTEXCL:
		case ENC_CASAL_C32_LDSTEXCL:
		case ENC_CASA_C32_LDSTEXCL:
		case ENC_CASB_C32_LDSTEXCL:
		case ENC_CASH_C32_LDSTEXCL:
		case ENC_CASLB_C32_LDSTEXCL:
		case ENC_CASLH_C32_LDSTEXCL:
		case ENC_CASL_C32_LDSTEXCL:
		case ENC_CAS_C32_LDSTEXCL:
		case ENC_STLXRB_SR32_LDSTEXCL:
		case ENC_STLXRH_SR32_LDSTEXCL:
		case ENC_STLXR_SR32_LDSTEXCL:
		case ENC_STXRB_SR32_LDSTEXCL:
		case ENC_STXRH_SR32_LDSTEXCL:
		case ENC_STXR_SR32_LDSTEXCL:
		{
			// SYNTAX: <Ws>,<Wt>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WS;
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_STLXP_SP64_LDSTEXCL:
		case ENC_STXP_SP64_LDSTEXCL:
		{
			// SYNTAX: <Ws>,<Xt1>,<Xt2>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WS;
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_STLXR_SR64_LDSTEXCL:
		case ENC_STXR_SR64_LDSTEXCL:
		{
			// SYNTAX: <Ws>,<Xt>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WS;
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_32_LDSTPAIR_PRE:
		case ENC_STP_32_LDSTPAIR_PRE:
		{
			// SYNTAX: <Wt1>,<Wt2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_WT1;
			ADD_OPERAND_WT2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_32_LDSTPAIR_POST:
		case ENC_STP_32_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Wt1>,<Wt2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_WT1;
			ADD_OPERAND_WT2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDNP_32_LDSTNAPAIR_OFFS:
		case ENC_LDP_32_LDSTPAIR_OFF:
		case ENC_STNP_32_LDSTNAPAIR_OFFS:
		case ENC_STP_32_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Wt1>,<Wt2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_WT1;
			ADD_OPERAND_WT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDAXP_LP32_LDSTEXCL:
		case ENC_LDXP_LP32_LDSTEXCL:
		{
			// SYNTAX: <Wt1>,<Wt2>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WT1;
			ADD_OPERAND_WT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LDRB_32_LDST_IMMPRE:
		case ENC_LDRH_32_LDST_IMMPRE:
		case ENC_LDRSB_32_LDST_IMMPRE:
		case ENC_LDRSH_32_LDST_IMMPRE:
		case ENC_LDR_32_LDST_IMMPRE:
		case ENC_STRB_32_LDST_IMMPRE:
		case ENC_STRH_32_LDST_IMMPRE:
		case ENC_STR_32_LDST_IMMPRE:
		{
			// SYNTAX: <Wt>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDRB_32B_LDST_REGOFF:
		case ENC_LDRSB_32B_LDST_REGOFF:
		case ENC_STRB_32B_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Wt>, [<Xn|SP>, (<Wm>|<Xm>),<extend>{<amount>}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_0;
			break;
		}
		case ENC_LDRH_32_LDST_REGOFF:
		case ENC_LDRSH_32_LDST_REGOFF:
		case ENC_LDR_32_LDST_REGOFF:
		case ENC_STRH_32_LDST_REGOFF:
		case ENC_STR_32_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Wt>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDRB_32BL_LDST_REGOFF:
		case ENC_LDRSB_32BL_LDST_REGOFF:
		case ENC_STRB_32BL_LDST_REGOFF:
		{
			// SYNTAX: <Wt>, [<Xn|SP>,<Xm>{, LSL #0}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_LSL0;
			break;
		}
		case ENC_LDRB_32_LDST_IMMPOST:
		case ENC_LDRH_32_LDST_IMMPOST:
		case ENC_LDRSB_32_LDST_IMMPOST:
		case ENC_LDRSH_32_LDST_IMMPOST:
		case ENC_LDR_32_LDST_IMMPOST:
		case ENC_STRB_32_LDST_IMMPOST:
		case ENC_STRH_32_LDST_IMMPOST:
		case ENC_STR_32_LDST_IMMPOST:
		{
			// SYNTAX: <Wt>, [<Xn|SP>], #<simm>
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDRB_32_LDST_POS:
		case ENC_LDRH_32_LDST_POS:
		case ENC_LDRSB_32_LDST_POS:
		case ENC_LDRSH_32_LDST_POS:
		case ENC_LDR_32_LDST_POS:
		case ENC_STRB_32_LDST_POS:
		case ENC_STRH_32_LDST_POS:
		case ENC_STR_32_LDST_POS:
		{
			// SYNTAX: <Wt>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED:
		case ENC_LDTRB_32_LDST_UNPRIV:
		case ENC_LDTRH_32_LDST_UNPRIV:
		case ENC_LDTRSB_32_LDST_UNPRIV:
		case ENC_LDTRSH_32_LDST_UNPRIV:
		case ENC_LDTR_32_LDST_UNPRIV:
		case ENC_LDURB_32_LDST_UNSCALED:
		case ENC_LDURH_32_LDST_UNSCALED:
		case ENC_LDURSB_32_LDST_UNSCALED:
		case ENC_LDURSH_32_LDST_UNSCALED:
		case ENC_LDUR_32_LDST_UNSCALED:
		case ENC_STLURB_32_LDAPSTL_UNSCALED:
		case ENC_STLURH_32_LDAPSTL_UNSCALED:
		case ENC_STLUR_32_LDAPSTL_UNSCALED:
		case ENC_STTRB_32_LDST_UNPRIV:
		case ENC_STTRH_32_LDST_UNPRIV:
		case ENC_STTR_32_LDST_UNPRIV:
		case ENC_STURB_32_LDST_UNSCALED:
		case ENC_STURH_32_LDST_UNSCALED:
		case ENC_STUR_32_LDST_UNSCALED:
		{
			// SYNTAX: <Wt>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDAPRB_32L_MEMOP:
		case ENC_LDAPRH_32L_MEMOP:
		case ENC_LDAPR_32L_MEMOP:
		case ENC_LDARB_LR32_LDSTEXCL:
		case ENC_LDARH_LR32_LDSTEXCL:
		case ENC_LDAR_LR32_LDSTEXCL:
		case ENC_LDAXRB_LR32_LDSTEXCL:
		case ENC_LDAXRH_LR32_LDSTEXCL:
		case ENC_LDAXR_LR32_LDSTEXCL:
		case ENC_LDLARB_LR32_LDSTEXCL:
		case ENC_LDLARH_LR32_LDSTEXCL:
		case ENC_LDLAR_LR32_LDSTEXCL:
		case ENC_LDXRB_LR32_LDSTEXCL:
		case ENC_LDXRH_LR32_LDSTEXCL:
		case ENC_LDXR_LR32_LDSTEXCL:
		case ENC_STLLRB_SL32_LDSTEXCL:
		case ENC_STLLRH_SL32_LDSTEXCL:
		case ENC_STLLR_SL32_LDSTEXCL:
		case ENC_STLRB_SL32_LDSTEXCL:
		case ENC_STLRH_SL32_LDSTEXCL:
		case ENC_STLR_SL32_LDSTEXCL:
		{
			// SYNTAX: <Wt>, [<Xn|SP>{,#0}]
			ADD_OPERAND_WT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_CBNZ_32_COMPBRANCH:
		case ENC_CBZ_32_COMPBRANCH:
		case ENC_LDR_32_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: <Wt>,<label>
			ADD_OPERAND_WT;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_AUTDZA_64Z_DP_1SRC:
		case ENC_AUTDZB_64Z_DP_1SRC:
		case ENC_AUTIZA_64Z_DP_1SRC:
		case ENC_AUTIZB_64Z_DP_1SRC:
		case ENC_PACDZA_64Z_DP_1SRC:
		case ENC_PACDZB_64Z_DP_1SRC:
		case ENC_PACIZA_64Z_DP_1SRC:
		case ENC_PACIZB_64Z_DP_1SRC:
		case ENC_XPACD_64Z_DP_1SRC:
		case ENC_XPACI_64Z_DP_1SRC:
		{
			// SYNTAX: <Xd>
			ADD_OPERAND_XD;
			// SYNTAX-END
			break;
		}
		case ENC_RDVL_R_I_:
		case ENC_MOV_MOVZ_64_MOVEWIDE:
		{
			int64_t imm = dec->imm << (dec->hw*16);
			// SYNTAX: <Xd>, #<imm64>
			ADD_OPERAND_XD;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}

		case ENC_MOV_MOVN_64_MOVEWIDE:
		{
			int64_t imm = (dec->imm << (dec->hw*16)) ^ 0xFFFFFFFFFFFFFFFF;
			// SYNTAX: <Xd>, #<imm>
			ADD_OPERAND_XD;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_MOVK_64_MOVEWIDE:
		case ENC_MOVN_64_MOVEWIDE:
		case ENC_MOVZ_64_MOVEWIDE:
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Xd>, #<imm>{, LSL #<shift>}
			ADD_OPERAND_XD;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			if(dec->hw) {
				dec->operands[1].shiftType = ShiftType_LSL;
				dec->operands[1].shiftValue = 16*dec->hw;
				dec->operands[1].shiftValueUsed = 1;
			}
			break;
		}
		case ENC_BFC_BFM_64M_BITFIELD:
		{
			unsigned lsb = IMMR ? 64 - IMMR : 0;
			unsigned width = IMMS+1;
			// SYNTAX: <Xd>, #<lsb>, #<width>
			ADD_OPERAND_XD;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_64D_FLOAT2INT:
		case ENC_FCVTAU_64D_FLOAT2INT:
		case ENC_FCVTMS_64D_FLOAT2INT:
		case ENC_FCVTMU_64D_FLOAT2INT:
		case ENC_FCVTNS_64D_FLOAT2INT:
		case ENC_FCVTNU_64D_FLOAT2INT:
		case ENC_FCVTPS_64D_FLOAT2INT:
		case ENC_FCVTPU_64D_FLOAT2INT:
		case ENC_FCVTZS_64D_FLOAT2INT:
		case ENC_FCVTZU_64D_FLOAT2INT:
		case ENC_FMOV_64D_FLOAT2INT:
		{
			// SYNTAX: <Xd>,<Dn>
			ADD_OPERAND_XD;
			ADD_OPERAND_DN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_64D_FLOAT2FIX:
		case ENC_FCVTZU_64D_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Xd>,<Dn>, #<fbits>
			ADD_OPERAND_XD;
			ADD_OPERAND_DN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_64H_FLOAT2INT:
		case ENC_FCVTAU_64H_FLOAT2INT:
		case ENC_FCVTMS_64H_FLOAT2INT:
		case ENC_FCVTMU_64H_FLOAT2INT:
		case ENC_FCVTNS_64H_FLOAT2INT:
		case ENC_FCVTNU_64H_FLOAT2INT:
		case ENC_FCVTPS_64H_FLOAT2INT:
		case ENC_FCVTPU_64H_FLOAT2INT:
		case ENC_FCVTZS_64H_FLOAT2INT:
		case ENC_FCVTZU_64H_FLOAT2INT:
		case ENC_FMOV_64H_FLOAT2INT:
		{
			// SYNTAX: <Xd>,<Hn>
			ADD_OPERAND_XD;
			ADD_OPERAND_HN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_64H_FLOAT2FIX:
		case ENC_FCVTZU_64H_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Xd>,<Hn>, #<fbits>
			ADD_OPERAND_XD;
			ADD_OPERAND_HN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_CNTP_R_P_P_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Xd>,<Pg>,<Pn>.<Ts>
			ADD_OPERAND_XD;
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_PRED_REG_ESIZE(dec->n, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTAS_64S_FLOAT2INT:
		case ENC_FCVTAU_64S_FLOAT2INT:
		case ENC_FCVTMS_64S_FLOAT2INT:
		case ENC_FCVTMU_64S_FLOAT2INT:
		case ENC_FCVTNS_64S_FLOAT2INT:
		case ENC_FCVTNU_64S_FLOAT2INT:
		case ENC_FCVTPS_64S_FLOAT2INT:
		case ENC_FCVTPU_64S_FLOAT2INT:
		case ENC_FCVTZS_64S_FLOAT2INT:
		case ENC_FCVTZU_64S_FLOAT2INT:
		{
			// SYNTAX: <Xd>,<Sn>
			ADD_OPERAND_XD;
			ADD_OPERAND_SN;
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_64S_FLOAT2FIX:
		case ENC_FCVTZU_64S_FLOAT2FIX:
		{
			uint64_t fbits = dec->fracbits;
			// SYNTAX: <Xd>,<Sn>, #<fbits>
			ADD_OPERAND_XD;
			ADD_OPERAND_SN;
			ADD_OPERAND_FBITS;
			// SYNTAX-END
			break;
		}
		case ENC_SMOV_ASIMDINS_X_X:
		case ENC_UMOV_ASIMDINS_X_X:
		{
			unsigned elem_sz = dec->esize/8;
			// SYNTAX: <Xd>,<Vn>.<Ts>[<index>]
			ADD_OPERAND_XD;
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_64VX_FLOAT2INT:
		{
			// SYNTAX: <Xd>,<Vn>.D[1]
			ADD_OPERAND_XD;
			ADD_OPERAND_VREG_ESIZE_INDEXED(8, dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_UMOV_ASIMDINS_X_X:
		{
			// SYNTAX: <Xd>,<Vn>.D[<index>]
			ADD_OPERAND_XD;
			ADD_OPERAND_VREG_ESIZE_INDEXED(8, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SXTB_SBFM_64M_BITFIELD:
		case ENC_SXTH_SBFM_64M_BITFIELD:
		case ENC_SXTW_SBFM_64M_BITFIELD:
		{
			// SYNTAX: <Xd>,<Wn>
			ADD_OPERAND_XD;
			ADD_OPERAND_WN;
			// SYNTAX-END
			break;
		}
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC:
		case ENC_SMULL_SMADDL_64WA_DP_3SRC:
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC:
		case ENC_UMULL_UMADDL_64WA_DP_3SRC:
		{
			// SYNTAX: <Xd>,<Wn>,<Wm>
			ADD_OPERAND_XD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			// SYNTAX-END
			break;
		}
		case ENC_SMADDL_64WA_DP_3SRC:
		case ENC_SMSUBL_64WA_DP_3SRC:
		case ENC_UMADDL_64WA_DP_3SRC:
		case ENC_UMSUBL_64WA_DP_3SRC:
		{
			// SYNTAX: <Xd>,<Wn>,<Wm>,<Xa>
			ADD_OPERAND_XD;
			ADD_OPERAND_WN;
			ADD_OPERAND_WM;
			ADD_OPERAND_XA;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ORR_64_LOG_SHIFT:
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY:
		case ENC_NGC_SBC_64_ADDSUB_CARRY:
		{
			// SYNTAX: <Xd>,<Xm>
			ADD_OPERAND_XD;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_MVN_ORN_64_LOG_SHIFT:
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT:
		case ENC_NEG_SUB_64_ADDSUB_SHIFT:
		{
			// SYNTAX: <Xd>,<Xm>{,<shift>#<amount>}
			ADD_OPERAND_XD;
			ADD_OPERAND_XM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_CLS_64_DP_1SRC:
		case ENC_CLZ_64_DP_1SRC:
		case ENC_RBIT_64_DP_1SRC:
		case ENC_REV16_64_DP_1SRC:
		case ENC_REV32_64_DP_1SRC:
		case ENC_REV64_REV_64_DP_1SRC:
		case ENC_REV_64_DP_1SRC:
		{
			// SYNTAX: <Xd>,<Xn>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_ANDS_64S_LOG_IMM:
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Xd>,<Xn>, #<imm>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_BFM_64M_BITFIELD:
		case ENC_SBFM_64M_BITFIELD:
		case ENC_UBFM_64M_BITFIELD:
		{
			// SYNTAX: <Xd>,<Xn>, #<immr>, #<imms>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_IMMR;
			ADD_OPERAND_IMMS;
			// SYNTAX-END
			break;
		}
		case ENC_BFI_BFM_64M_BITFIELD:
		case ENC_SBFIZ_SBFM_64M_BITFIELD:
		case ENC_UBFIZ_UBFM_64M_BITFIELD:
		{
			unsigned lsb = IMMR ? 64 - IMMR : 0;
			unsigned width = IMMS+1;
			// SYNTAX: <Xd>,<Xn>, #<lsb>, #<width>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_BFXIL_BFM_64M_BITFIELD:
		case ENC_SBFX_SBFM_64M_BITFIELD:
		case ENC_UBFX_UBFM_64M_BITFIELD:
		{
			unsigned lsb = IMMR;
			unsigned width = IMMS-IMMR+1;
			// SYNTAX: <Xd>,<Xn>, #<lsb>, #<width>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_LSB;
			ADD_OPERAND_WIDTH;
			// SYNTAX-END
			break;
		}
		case ENC_ASR_SBFM_64M_BITFIELD:
		case ENC_LSL_UBFM_64M_BITFIELD:
		case ENC_LSR_UBFM_64M_BITFIELD:
		{
			unsigned const_ = (dec->encoding == ENC_LSL_UBFM_64M_BITFIELD) ?
				64 - dec->immr : dec->immr;
			// SYNTAX: <Xd>,<Xn>, #<const>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ADCS_64_ADDSUB_CARRY:
		case ENC_ADC_64_ADDSUB_CARRY:
		case ENC_ASRV_64_DP_2SRC:
		case ENC_ASR_ASRV_64_DP_2SRC:
		case ENC_LSLV_64_DP_2SRC:
		case ENC_LSL_LSLV_64_DP_2SRC:
		case ENC_LSRV_64_DP_2SRC:
		case ENC_LSR_LSRV_64_DP_2SRC:
		case ENC_MNEG_MSUB_64A_DP_3SRC:
		case ENC_MUL_MADD_64A_DP_3SRC:
		case ENC_RORV_64_DP_2SRC:
		case ENC_ROR_RORV_64_DP_2SRC:
		case ENC_SBCS_64_ADDSUB_CARRY:
		case ENC_SBC_64_ADDSUB_CARRY:
		case ENC_SDIV_64_DP_2SRC:
		case ENC_SMULH_64_DP_3SRC:
		case ENC_UDIV_64_DP_2SRC:
		case ENC_UMULH_64_DP_3SRC:
		{
			// SYNTAX: <Xd>,<Xn>,<Xm>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_EXTR_64_EXTRACT:
		{
			unsigned lsb = dec->lsb;
			// SYNTAX: <Xd>,<Xn>,<Xm>, #<lsb>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			ADD_OPERAND_LSB;
			// SYNTAX-END
			break;
		}
		case ENC_MADD_64A_DP_3SRC:
		case ENC_MSUB_64A_DP_3SRC:
		{
			// SYNTAX: <Xd>,<Xn>,<Xm>,<Xa>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			ADD_OPERAND_XA;
			// SYNTAX-END
			break;
		}
		case ENC_CSEL_64_CONDSEL:
		case ENC_CSINC_64_CONDSEL:
		case ENC_CSINV_64_CONDSEL:
		case ENC_CSNEG_64_CONDSEL:
		{
			// SYNTAX: <Xd>,<Xn>,<Xm>,<cond>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_ADDS_64_ADDSUB_SHIFT:
		case ENC_ADD_64_ADDSUB_SHIFT:
		case ENC_ANDS_64_LOG_SHIFT:
		case ENC_AND_64_LOG_SHIFT:
		case ENC_BICS_64_LOG_SHIFT:
		case ENC_BIC_64_LOG_SHIFT:
		case ENC_EON_64_LOG_SHIFT:
		case ENC_EOR_64_LOG_SHIFT:
		case ENC_ORN_64_LOG_SHIFT:
		case ENC_ORR_64_LOG_SHIFT:
		case ENC_SUBS_64_ADDSUB_SHIFT:
		case ENC_SUB_64_ADDSUB_SHIFT:
		{
			// SYNTAX: <Xd>,<Xn>,<Xm>{,<shift>#<amount>}
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_PACGA_64P_DP_2SRC:
		{
			// SYNTAX: <Xd>,<Xn>,<Xm|SP>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_XM_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CINC_CSINC_64_CONDSEL:
		case ENC_CINV_CSINV_64_CONDSEL:
		case ENC_CNEG_CSNEG_64_CONDSEL:
		{
			// SYNTAX: <Xd>,<Xn>,<cond_neg>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_COND_NEG;
			// SYNTAX-END
			break;
		}
		case ENC_AUTDA_64P_DP_1SRC:
		case ENC_AUTDB_64P_DP_1SRC:
		case ENC_AUTIA_64P_DP_1SRC:
		case ENC_AUTIB_64P_DP_1SRC:
		case ENC_PACDA_64P_DP_1SRC:
		case ENC_PACDB_64P_DP_1SRC:
		case ENC_PACIA_64P_DP_1SRC:
		case ENC_PACIB_64P_DP_1SRC:
		{
			// SYNTAX: <Xd>,<Xn|SP>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_ADDS_64S_ADDSUB_IMM:
		case ENC_SUBS_64S_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Xd>,<Xn|SP>, #<imm>{,<shift>}
			ADD_OPERAND_XD;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_ADDS_64S_ADDSUB_EXT:
		case ENC_SUBS_64S_ADDSUB_EXT:
		{
			unsigned rm_base = (dec->option & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Xd>,<Xn|SP>,<R><m>{,<extend>{#<amount>}}
			ADD_OPERAND_XD;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR1;
			break;
		}
		case ENC_GMI_64G_DP_2SRC:
		{
			// SYNTAX: <Xd>,<Xn|SP>,<Xm>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_SUBPS_64S_DP_2SRC:
		case ENC_SUBP_64S_DP_2SRC:
		{
			// SYNTAX: <Xd>,<Xn|SP>,<Xm|SP>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_XM_SP;
			// SYNTAX-END
			break;
		}
		case ENC_ROR_EXTR_64_EXTRACT:
		{
			unsigned imm = IMMS;
			// SYNTAX: <Xd>,<Xn>, #<imm>
			ADD_OPERAND_XD;
			ADD_OPERAND_XN;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_CSETM_CSINV_64_CONDSEL:
		case ENC_CSET_CSINC_64_CONDSEL:
		{
			// SYNTAX: <Xd>,<cond_neg>
			ADD_OPERAND_XD;
			ADD_OPERAND_COND_NEG;
			// SYNTAX-END
			break;
		}
		case ENC_ADRP_ONLY_PCRELADDR:
		{
			uint64_t eaddr = dec->imm;
			// SYNTAX: <Xd>,<label>
			ADD_OPERAND_XD;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_ADR_ONLY_PCRELADDR:
		{
			uint64_t eaddr = dec->imm;
			// SYNTAX: <Xd>,<label>
			ADD_OPERAND_XD;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_CNTB_R_S_:
		case ENC_CNTD_R_S_:
		case ENC_CNTH_R_S_:
		case ENC_CNTW_R_S_:
		{
			// SYNTAX: <Xd>{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_XD;
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_DECP_R_P_R_:
		case ENC_INCP_R_P_R_:
		case ENC_SQDECP_R_P_R_X:
		case ENC_SQINCP_R_P_R_X:
		case ENC_UQDECP_R_P_R_X:
		case ENC_UQINCP_R_P_R_X:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Xdn>,<Pm>.<Ts>
			ADD_OPERAND_XDN;
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, elem_sz);
			// SYNTAX-END
			break;
		}
		case ENC_SQDECP_R_P_R_SX:
		case ENC_SQINCP_R_P_R_SX:
		{
			unsigned elem_sz = dec->esize/8;
			// SYNTAX: <Xdn>,<Pm>.<Ts>,<Wdn>
			ADD_OPERAND_XDN;
			ADD_OPERAND_PRED_REG_ESIZE(dec->m, elem_sz);
			ADD_OPERAND_WDN;
			// SYNTAX-END
			break;
		}
		case ENC_SQDECB_R_RS_SX:
		case ENC_SQDECD_R_RS_SX:
		case ENC_SQDECH_R_RS_SX:
		case ENC_SQDECW_R_RS_SX:
		case ENC_SQINCB_R_RS_SX:
		case ENC_SQINCD_R_RS_SX:
		case ENC_SQINCH_R_RS_SX:
		case ENC_SQINCW_R_RS_SX:
		{
			// SYNTAX: <Xdn>,<Wdn>{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_XDN;
			ADD_OPERAND_WDN;
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_DECB_R_RS_:
		case ENC_DECD_R_RS_:
		case ENC_DECH_R_RS_:
		case ENC_DECW_R_RS_: // pattern "all" is required
		case ENC_INCB_R_RS_:
		case ENC_INCD_R_RS_:
		case ENC_INCH_R_RS_:
		case ENC_INCW_R_RS_: // pattern "all" is dropped
		case ENC_SQDECB_R_RS_X:
		case ENC_SQDECD_R_RS_X:
		case ENC_SQDECH_R_RS_X:
		case ENC_SQDECW_R_RS_X:
		case ENC_SQINCB_R_RS_X:
		case ENC_SQINCD_R_RS_X:
		case ENC_SQINCH_R_RS_X:
		case ENC_SQINCW_R_RS_X:
		case ENC_UQDECB_R_RS_X:
		case ENC_UQDECD_R_RS_X:
		case ENC_UQDECH_R_RS_X:
		case ENC_UQDECW_R_RS_X:
		case ENC_UQINCB_R_RS_X:
		case ENC_UQINCD_R_RS_X:
		case ENC_UQINCH_R_RS_X:
		case ENC_UQINCW_R_RS_X:
		{
			// NONSYNTAX: <Xdn> {,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_XDN;
			// SYNTAX-END

			bool print_mul = dec->imm != 1;
			bool print_pattern = print_mul || dec->pattern != 0x1f;

			if(print_pattern) {
				ADD_OPERAND_PATTERN;
			}

			if(print_mul) {
				ADD_OPERAND_STR_IMM("mul", dec->imm);
			}
			break;
		}
		case ENC_MOV_ORR_64_LOG_IMM:
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Xd|SP>, #<imm>
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_AND_64_LOG_IMM:
		case ENC_EOR_64_LOG_IMM:
		case ENC_ORR_64_LOG_IMM:
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Xd|SP>,<Xn>, #<imm>
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ADD_64_ADDSUB_IMM:
		{
			// SYNTAX: <Xd|SP>,<Xn|SP>
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_ADDPL_R_RI_:
		case ENC_ADDVL_R_RI_:
		{
			uint32_t imm = dec->imm;
			// SYNTAX: <Xd|SP>,<Xn|SP>, #<imm>
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_ADD_64_ADDSUB_IMM:
		case ENC_SUB_64_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Xd|SP>,<Xn|SP>, #<imm>{,<shift>}
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_ADDG_64_ADDSUB_IMMTAGS:
		case ENC_SUBG_64_ADDSUB_IMMTAGS:
		{
			uint64_t uimm6 = dec->offset;
			uint64_t uimm4 = dec->tag_offset;
			// SYNTAX: <Xd|SP>,<Xn|SP>, #<uimm6>, #<uimm4>
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_IMMEDIATE32(uimm6, 0);
			ADD_OPERAND_IMMEDIATE32(uimm4, 0);
			// SYNTAX-END
			break;
		}
		case ENC_ADD_64_ADDSUB_EXT:
		case ENC_SUB_64_ADDSUB_EXT:
		{
			unsigned rm_base = (dec->option & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Xd|SP>,<Xn|SP>,<R><m>{,<extend>{#<amount>}}
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR1;
			break;
		}
		case ENC_IRG_64I_DP_2SRC:
		{
			// SYNTAX: <Xd|SP>,<Xn|SP>{,<Xm>}
			ADD_OPERAND_XD_SP;
			ADD_OPERAND_XN_SP;
			// SYNTAX-END
			if(dec->Xm != 31) {
				ADD_OPERAND_XM
			}
			break;
		}
		case ENC_BLRAAZ_64_BRANCH_REG:
		case ENC_BLRABZ_64_BRANCH_REG:
		case ENC_BLR_64_BRANCH_REG:
		case ENC_BRAAZ_64_BRANCH_REG:
		case ENC_BRABZ_64_BRANCH_REG:
		case ENC_BR_64_BRANCH_REG:
		{
			// SYNTAX: <Xn>
			ADD_OPERAND_XN;
			// SYNTAX-END
			break;
		}
		case ENC_TST_ANDS_64S_LOG_IMM:
		{
			uint64_t imm = dec->imm;
			// SYNTAX: <Xn>, #<imm>
			ADD_OPERAND_XN;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			break;
		}
		case ENC_CCMN_64_CONDCMP_IMM:
		case ENC_CCMP_64_CONDCMP_IMM:
		{
			uint32_t imm = dec->imm;
			// SYNTAX: <Xn>, #<imm>, #<nzcv>,<cond>
			ADD_OPERAND_XN;
			ADD_OPERAND_UIMM64;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_RMIF_ONLY_RMIF:
		{
			unsigned mask = dec->mask;
			unsigned shift = dec->imm6;
			// SYNTAX: <Xn>, #<shift>, #<mask>
			ADD_OPERAND_XN;
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			ADD_OPERAND_IMMEDIATE32(mask, 0);
			// SYNTAX-END
			break;
		}
		case ENC_CCMN_64_CONDCMP_REG:
		case ENC_CCMP_64_CONDCMP_REG:
		{
			// SYNTAX: <Xn>,<Xm>, #<nzcv>,<cond>
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			ADD_OPERAND_NZCV;
			ADD_OPERAND_COND;
			// SYNTAX-END
			break;
		}
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT:
		case ENC_TST_ANDS_64_LOG_SHIFT:
		{
			// SYNTAX: <Xn>,<Xm>{,<shift>#<amount>}
			ADD_OPERAND_XN;
			ADD_OPERAND_XM;
			// SYNTAX-END
			OPTIONAL_SHIFT_AMOUNT;
			break;
		}
		case ENC_BLRAA_64P_BRANCH_REG:
		case ENC_BLRAB_64P_BRANCH_REG:
		case ENC_BRAA_64P_BRANCH_REG:
		case ENC_BRAB_64P_BRANCH_REG:
		{
			// SYNTAX: <Xn>,<Xm|SP>
			ADD_OPERAND_XN;
			ADD_OPERAND_XM_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CMN_ADDS_64S_ADDSUB_IMM:
		case ENC_CMP_SUBS_64S_ADDSUB_IMM:
		{
			uint64_t imm = dec->imm12;
			// SYNTAX: <Xn|SP>, #<imm>{,<shift>}
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_UIMM64;
			// SYNTAX-END
			if(dec->sh) {
				LAST_OPERAND_LSL_12;
			}
			break;
		}
		case ENC_CMN_ADDS_64S_ADDSUB_EXT:
		case ENC_CMP_SUBS_64S_ADDSUB_EXT:
		{
			unsigned rm_base = (dec->option & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Xn|SP>,<R><m>{,<extend>{#<amount>}}
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_64_BEHAVIOR0;
			break;
		}
		case ENC_CMPP_SUBPS_64S_DP_2SRC:
		{
			// SYNTAX: <Xn|SP>,<Xm|SP>
			ADD_OPERAND_XN_SP;
			ADD_OPERAND_XM_SP;
			// SYNTAX-END
			break;
		}
		case ENC_STADDL_LDADDL_64_MEMOP:
		case ENC_STADD_LDADD_64_MEMOP:
		case ENC_STCLRL_LDCLRL_64_MEMOP:
		case ENC_STCLR_LDCLR_64_MEMOP:
		case ENC_STEORL_LDEORL_64_MEMOP:
		case ENC_STEOR_LDEOR_64_MEMOP:
		case ENC_STSETL_LDSETL_64_MEMOP:
		case ENC_STSET_LDSET_64_MEMOP:
		case ENC_STSMAXL_LDSMAXL_64_MEMOP:
		case ENC_STSMAX_LDSMAX_64_MEMOP:
		case ENC_STSMINL_LDSMINL_64_MEMOP:
		case ENC_STSMIN_LDSMIN_64_MEMOP:
		case ENC_STUMAXL_LDUMAXL_64_MEMOP:
		case ENC_STUMAX_LDUMAX_64_MEMOP:
		case ENC_STUMINL_LDUMINL_64_MEMOP:
		case ENC_STUMIN_LDUMIN_64_MEMOP:
		{
			// SYNTAX: <Xs>, [<Xn|SP>]
			ADD_OPERAND_XS;
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CASPAL_CP64_LDSTEXCL:
		case ENC_CASPA_CP64_LDSTEXCL:
		case ENC_CASPL_CP64_LDSTEXCL:
		case ENC_CASP_CP64_LDSTEXCL:
		{
			// SYNTAX: <Xs>,<X(s+1)>,<Xt>,<X(t+1)>, [<Xn|SP>{,#0}]
			ADD_OPERAND_XS;
			ADD_OPERAND_XS_PLUS_1;
			ADD_OPERAND_XT;
			ADD_OPERAND_XT_PLUS_1;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LDADDAL_64_MEMOP:
		case ENC_LDADDA_64_MEMOP:
		case ENC_LDADDL_64_MEMOP:
		case ENC_LDADD_64_MEMOP:
		case ENC_LDCLRAL_64_MEMOP:
		case ENC_LDCLRA_64_MEMOP:
		case ENC_LDCLRL_64_MEMOP:
		case ENC_LDCLR_64_MEMOP:
		case ENC_LDEORAL_64_MEMOP:
		case ENC_LDEORA_64_MEMOP:
		case ENC_LDEORL_64_MEMOP:
		case ENC_LDEOR_64_MEMOP:
		case ENC_LDSETAL_64_MEMOP:
		case ENC_LDSETA_64_MEMOP:
		case ENC_LDSETL_64_MEMOP:
		case ENC_LDSET_64_MEMOP:
		case ENC_LDSMAXAL_64_MEMOP:
		case ENC_LDSMAXA_64_MEMOP:
		case ENC_LDSMAXL_64_MEMOP:
		case ENC_LDSMAX_64_MEMOP:
		case ENC_LDSMINAL_64_MEMOP:
		case ENC_LDSMINA_64_MEMOP:
		case ENC_LDSMINL_64_MEMOP:
		case ENC_LDSMIN_64_MEMOP:
		case ENC_LDUMAXAL_64_MEMOP:
		case ENC_LDUMAXA_64_MEMOP:
		case ENC_LDUMAXL_64_MEMOP:
		case ENC_LDUMAX_64_MEMOP:
		case ENC_LDUMINAL_64_MEMOP:
		case ENC_LDUMINA_64_MEMOP:
		case ENC_LDUMINL_64_MEMOP:
		case ENC_LDUMIN_64_MEMOP:
		case ENC_SWPAL_64_MEMOP:
		case ENC_SWPA_64_MEMOP:
		case ENC_SWPL_64_MEMOP:
		case ENC_SWP_64_MEMOP:
		{
			// SYNTAX: <Xs>,<Xt>, [<Xn|SP>]
			ADD_OPERAND_XS;
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_CASAL_C64_LDSTEXCL:
		case ENC_CASA_C64_LDSTEXCL:
		case ENC_CASL_C64_LDSTEXCL:
		case ENC_CAS_C64_LDSTEXCL:
		{
			// SYNTAX: <Xs>,<Xt>, [<Xn|SP>{,#0}]
			ADD_OPERAND_XS;
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_STGP_64_LDSTPAIR_PRE:
		{
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDP_64_LDSTPAIR_PRE:
		case ENC_LDPSW_64_LDSTPAIR_PRE:
		case ENC_STP_64_LDSTPAIR_PRE:
		{
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>, #<imm>]!
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDPSW_64_LDSTPAIR_POST:
		case ENC_LDP_64_LDSTPAIR_POST:
		case ENC_STGP_64_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_STP_64_LDSTPAIR_POST:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>], #<imm>
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_STGP_64_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDNP_64_LDSTNAPAIR_OFFS:
		case ENC_LDPSW_64_LDSTPAIR_OFF:
		case ENC_LDP_64_LDSTPAIR_OFF:
		case ENC_STNP_64_LDSTNAPAIR_OFFS:
		case ENC_STP_64_LDSTPAIR_OFF:
		{
			uint64_t imm = dec->offset;
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDAXP_LP64_LDSTEXCL:
		case ENC_LDXP_LP64_LDSTEXCL:
		{
			// SYNTAX: <Xt1>,<Xt2>, [<Xn|SP>{,#0}]
			ADD_OPERAND_XT1;
			ADD_OPERAND_XT2;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_CFP_SYS_CR_SYSTEMINSTRS:
		case ENC_CPP_SYS_CR_SYSTEMINSTRS:
		case ENC_DVP_SYS_CR_SYSTEMINSTRS:
		{
			ADD_OPERAND_NAME("rctx");
			// SYNTAX: RCTX, <Xt>
			ADD_OPERAND_XT;
			// SYNTAX-END
			break;
		}
		case ENC_SYSL_RC_SYSTEMINSTRS:
		{
			// SYNTAX: <Xt>, #<op1>,<Cn>,<Cm>, #<op2>
			ADD_OPERAND_XT;
			ADD_OPERAND_IMMEDIATE32(dec->op1, 0);
			ADD_OPERAND_NAME(reg_lookup_c[dec->sys_crn]);
			ADD_OPERAND_NAME(reg_lookup_c[dec->sys_crm]);
			ADD_OPERAND_IMMEDIATE32(dec->op2, 0);
			// SYNTAX-END
			break;
		}
		case ENC_MRS_RS_SYSTEMMOVE:
		{
			// SYNTAX: <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
			ADD_OPERAND_XT;
			ADD_OPERAND_SYSTEMREG;
			// SYNTAX-END
			break;
		}
		case ENC_LDRSB_64_LDST_IMMPRE:
		case ENC_LDRSH_64_LDST_IMMPRE:
		case ENC_LDRSW_64_LDST_IMMPRE:
		case ENC_LDR_64_LDST_IMMPRE:
		case ENC_STR_64_LDST_IMMPRE:
		{
			// SYNTAX: <Xt>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDRSB_64B_LDST_REGOFF:
		{
			int reg_base = dec->option & 1 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Xt>, [<Xn|SP>, (<Wm>|<Xm>),<extend>{<amount>}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT_0;
			break;
		}
		case ENC_LDRSH_64_LDST_REGOFF:
		case ENC_LDRSW_64_LDST_REGOFF:
		case ENC_LDR_64_LDST_REGOFF:
		case ENC_STR_64_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: <Xt>, [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_LDRSB_64BL_LDST_REGOFF:
		{
			// SYNTAX: <Xt>, [<Xn|SP>,<Xm>{, LSL #0}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_LSL0;
			break;
		}
		case ENC_LDGM_64BULK_LDSTTAGS:
		case ENC_STGM_64BULK_LDSTTAGS:
		case ENC_STZGM_64BULK_LDSTTAGS:
		{
			// SYNTAX: <Xt>, [<Xn|SP>]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LDRSB_64_LDST_IMMPOST:
		case ENC_LDRSH_64_LDST_IMMPOST:
		case ENC_LDRSW_64_LDST_IMMPOST:
		case ENC_LDR_64_LDST_IMMPOST:
		case ENC_STR_64_LDST_IMMPOST:
		{
			// SYNTAX: <Xt>, [<Xn|SP>], #<simm>
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDRSB_64_LDST_POS:
		case ENC_LDRSH_64_LDST_POS:
		case ENC_LDRSW_64_LDST_POS:
		case ENC_LDR_64_LDST_POS:
		case ENC_STR_64_LDST_POS:
		{
			// SYNTAX: <Xt>, [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED:
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED:
		case ENC_LDG_64LOFFSET_LDSTTAGS:
		case ENC_LDRAA_64_LDST_PAC:
		case ENC_LDRAB_64_LDST_PAC:
		case ENC_LDTRSB_64_LDST_UNPRIV:
		case ENC_LDTRSH_64_LDST_UNPRIV:
		case ENC_LDTRSW_64_LDST_UNPRIV:
		case ENC_LDTR_64_LDST_UNPRIV:
		case ENC_LDURSB_64_LDST_UNSCALED:
		case ENC_LDURSH_64_LDST_UNSCALED:
		case ENC_LDURSW_64_LDST_UNSCALED:
		case ENC_LDUR_64_LDST_UNSCALED:
		case ENC_STLUR_64_LDAPSTL_UNSCALED:
		case ENC_STTR_64_LDST_UNPRIV:
		case ENC_STUR_64_LDST_UNSCALED:
		{
			// SYNTAX: <Xt>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}

		case ENC_LDRAA_64W_LDST_PAC:
		case ENC_LDRAB_64W_LDST_PAC:
		{
			// SYNTAX: <Xt>, [<Xn|SP>{, #<simm>}]!
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}

		case ENC_LDAPR_64L_MEMOP:
		case ENC_LDAR_LR64_LDSTEXCL:
		case ENC_LDAXR_LR64_LDSTEXCL:
		case ENC_LDLAR_LR64_LDSTEXCL:
		case ENC_LDXR_LR64_LDSTEXCL:
		case ENC_STLLR_SL64_LDSTEXCL:
		case ENC_STLR_SL64_LDSTEXCL:
		{
			// SYNTAX: <Xt>, [<Xn|SP>{,#0}]
			ADD_OPERAND_XT;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, 0);
			// SYNTAX-END
			break;
		}
		case ENC_CBNZ_64_COMPBRANCH:
		case ENC_CBZ_64_COMPBRANCH:
		case ENC_LDRSW_64_LOADLIT:
		case ENC_LDR_64_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: <Xt>,<label>
			ADD_OPERAND_XT;
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_ST2G_64SPRE_LDSTTAGS:
		case ENC_STG_64SPRE_LDSTTAGS:
		case ENC_STZ2G_64SPRE_LDSTTAGS:
		case ENC_STZG_64SPRE_LDSTTAGS:
		{
			// SYNTAX: <Xt|SP>, [<Xn|SP>, #<simm>]!
			ADD_OPERAND_XT_SP;
			ADD_OPERAND_MEM_PRE_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_ST2G_64SPOST_LDSTTAGS:
		case ENC_STG_64SPOST_LDSTTAGS:
		case ENC_STZ2G_64SPOST_LDSTTAGS:
		case ENC_STZG_64SPOST_LDSTTAGS:
		{
			// SYNTAX: <Xt|SP>, [<Xn|SP>], #<simm>
			ADD_OPERAND_XT_SP;
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_ST2G_64SOFFSET_LDSTTAGS:
		case ENC_STG_64SOFFSET_LDSTTAGS:
		case ENC_STZ2G_64SOFFSET_LDSTTAGS:
		case ENC_STZG_64SOFFSET_LDSTTAGS:
		{
			// SYNTAX: <Xt|SP>, [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_XT_SP;
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_MOVPRFX_Z_Z_:
		{
			// SYNTAX: <Zd>,<Zn>
			ADD_OPERAND_ZD;
			ADD_OPERAND_ZN;
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_DUP_Z_I_:
		{
			arrangement_spec arr_spec = arr_spec_method0(dec->immh, dec->Q);
			// SYNTAX: <Zd>.<T>, #0.0
			ADD_OPERAND_ZREG_T(arr_spec, dec->d);
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_FDUP_Z_I_:
		case ENC_FDUP_Z_I_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			float fimm = table_imm8_to_float[dec->imm8];
			// SYNTAX: <Zd>.<Ts>, #<fimm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}

		case ENC_MOV_DUPM_Z_I_:
		case ENC_DUPM_Z_I_:
		{
			unsigned elem_sz = size_spec_method1(dec->imm13);
			uint64_t const_ = dec->imm;
			if(elem_sz==1) const_ &= 0xFF;
			if(elem_sz==2) const_ &= 0xFFFF;
			if(elem_sz==4) const_ &= 0xFFFFFFFF;
			// SYNTAX: <Zd>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_INDEX_Z_II_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			uint64_t imm1 = dec->imm1;
			uint64_t imm2 = dec->imm2;
			// SYNTAX: <Zd>.<Ts>, #<imm1>, #<imm2>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_IMM1;
			ADD_OPERAND_IMM2;
			// SYNTAX-END
			break;
		}
		case ENC_INDEX_Z_IR_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rm_base = wwwx_0123_reg(dec->size);
			// SYNTAX: <Zd>.<Ts>, #<imm>,<R><m>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_UIMM32;
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_DUP_Z_I_:
		case ENC_DUP_Z_I_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>, #<imm>{,<shift>}
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			// imm is the imm8 with shift applied, no need to print
			break;
		}
		case ENC_ADR_Z_AZ_SD_SAME_SCALED:
		{
			unsigned elem_sz = dec->sz ? 8 : 4;
			// SYNTAX: <Zd>.<Ts>, [<Zn>.<Ts>,<Zm>.<Ts>{,<mod><amount>}]
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_Z_BASE, dec->n, REG_Z_BASE, dec->m, elem_sz);
			// SYNTAX-END
			if(dec->msz) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, dec->msz)
			}
			break;
		}
		case ENC_COMPACT_Z_P_Z_:
		{
			arrangement_spec arr_spec = table_1s_1d[dec->size & 1];
			unsigned elem_sz = arr_spec.elem_sz;
			// SYNTAX: <Zd>.<Ts>,<Pg>,<Zn>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SEL_Z_P_ZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Pg>,<Zn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_MOVPRFX_Z_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			char pred_qual = dec->M ? 'm' : 'z';
			// SYNTAX: <Zd>.<Ts>,<Pg>/<ZM>,<Zn>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, pred_qual);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_CPY_Z_P_I_:
		{
			unsigned elem_sz = table_b_d_h_s[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Pg>/M, #0.0
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_FLOAT32(0);
			// SYNTAX-END
			break;
		}
		case ENC_FMOV_FCPY_Z_P_I_:
		case ENC_FCPY_Z_P_I_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			float fimm = table_imm8_to_float[dec->imm8];
			// SYNTAX: <Zd>.<Ts>,<Pg>/M, #<fimm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_MOV_CPY_Z_P_I_:
		case ENC_CPY_Z_P_I_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Pg>/M, #<imm>{,<shift>}
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			// imm is the imm8 with shift applied, no need to print
			break;
		}
		case ENC_MOV_CPY_Z_P_R_:
		case ENC_CPY_Z_P_R_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = dec->size==3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Zd>.<Ts>,<Pg>/M,<R><n|SP>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_REG(REGSET_SP, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_CPY_Z_P_V_:
		case ENC_CPY_Z_P_V_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <Zd>.<Ts>,<Pg>/M,<V><n>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_SEL_Z_P_ZZ_:
		case ENC_ABS_Z_P_Z_:
		case ENC_CLS_Z_P_Z_:
		case ENC_CLZ_Z_P_Z_:
		case ENC_CNOT_Z_P_Z_:
		case ENC_CNT_Z_P_Z_:
		case ENC_FABS_Z_P_Z_:
		case ENC_FNEG_Z_P_Z_:
		case ENC_FRECPX_Z_P_Z_:
		case ENC_FRINTA_Z_P_Z_:
		case ENC_FRINTI_Z_P_Z_:
		case ENC_FRINTM_Z_P_Z_:
		case ENC_FRINTN_Z_P_Z_:
		case ENC_FRINTP_Z_P_Z_:
		case ENC_FRINTX_Z_P_Z_:
		case ENC_FRINTZ_Z_P_Z_:
		case ENC_FSQRT_Z_P_Z_:
		case ENC_NEG_Z_P_Z_:
		case ENC_NOT_Z_P_Z_:
		case ENC_RBIT_Z_P_Z_:
		case ENC_REVB_Z_Z_:
		case ENC_REVH_Z_Z_:
		case ENC_SXTB_Z_P_Z_:
		case ENC_SXTH_Z_P_Z_:
		case ENC_UXTB_Z_P_Z_:
		case ENC_UXTH_Z_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Pg>/M,<Zn>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_CPY_Z_O_I_:
		case ENC_CPY_Z_O_I_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Pg>/Z, #<imm>{,<shift>}
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			// imm is the imm8 with shift applied, no need to print
			break;
		}
		case ENC_INDEX_Z_RI_: // checked bhsd, on 04b346fd
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = wwwx_0123_reg(dec->size);
			// SYNTAX: <Zd>.<Ts>,<R><n>, #<imm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_INDEX_Z_RR_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = (dec->size & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			unsigned rm_base = (dec->size & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Zd>.<Ts>,<R><n>,<R><m>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_DUP_Z_R_:
		case ENC_DUP_Z_R_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rn_base = (dec->size & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Zd>.<Ts>,<R><n|SP>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_REG(REGSET_SP, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_DUP_Z_ZI_:
		{
			arr_spec = arr_spec_method1(dec->tsz);
			unsigned elem_sz = arr_spec.elem_sz;
			unsigned rn_base = rbhsdq_5bit_reg(dec->tsz);
			// SYNTAX: <Zd>.<Ts>,<V><n>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FEXPA_Z_Z_:
		case ENC_FRECPE_Z_Z_:
		case ENC_FRSQRTE_Z_Z_:
		case ENC_REV_Z_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_ASR_Z_ZI_:
		case ENC_LSL_Z_ZI_:
		case ENC_LSR_Z_ZI_:
		{
			arrangement_spec arr_spec = table16_r_b_h_s_d[(dec->tszh<<2)|dec->tszl];
			unsigned elem_sz = arr_spec.elem_sz;
			uint64_t const_ = dec->shift;
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ADD_Z_ZZ_:
		case ENC_FADD_Z_ZZ_:
		case ENC_FMUL_Z_ZZ_:
		case ENC_FRECPS_Z_ZZ_:
		case ENC_FRSQRTS_Z_ZZ_:
		case ENC_FSUB_Z_ZZ_:
		case ENC_FTSMUL_Z_ZZ_:
		case ENC_FTSSEL_Z_ZZ_:
		case ENC_SQADD_Z_ZZ_:
		case ENC_SQSUB_Z_ZZ_:
		case ENC_SUB_Z_ZZ_:
		case ENC_TRN1_Z_ZZ_:
		case ENC_TRN2_Z_ZZ_:
		case ENC_UQADD_Z_ZZ_:
		case ENC_UQSUB_Z_ZZ_:
		case ENC_UZP1_Z_ZZ_:
		case ENC_UZP2_Z_ZZ_:
		case ENC_ZIP1_Z_ZZ_:
		case ENC_ZIP2_Z_ZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ASR_Z_ZW_:
		case ENC_LSL_Z_ZW_:
		case ENC_LSR_Z_ZW_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Ts>,<Zm>.D
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(8, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_DUP_Z_ZI_:
		{
			arrangement_spec arr_spec = arr_spec_method1(dec->tsz);
			unsigned elem_sz = arr_spec.elem_sz;
			unsigned rn_base = rbhsdq_5bit_reg(dec->tsz);
			// SYNTAX: <Zd>.<Ts>,<V><n>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_REG(REGSET_ZR, rn_base, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_DUP_Z_ZI_2:
		{
			arrangement_spec arr_spec = arr_spec_method1(dec->tsz);
			unsigned elem_sz = arr_spec.elem_sz;
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Ts>[<imm>]
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(elem_sz, dec->n, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SUNPKHI_Z_Z_:
		case ENC_SUNPKLO_Z_Z_:
		case ENC_UUNPKHI_Z_Z_:
		case ENC_UUNPKLO_Z_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned elem_sz_b = table_d_b_h_s[dec->size];
			// SYNTAX: <Zd>.<Ts>,<Zn>.<Tb>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_ZREG_ESIZE(elem_sz_b, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_TBL_Z_ZZ_1:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zd>.<Ts>,{<Zn>.<Ts>},<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->d);
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ADR_Z_AZ_D_S32_SCALED:
		{
			// SYNTAX: <Zd>.D, [<Zn>.D,<Zm>.D, SXTW{<amount>}]
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_Z_BASE, dec->n, REG_Z_BASE, dec->m, 8);
			// SYNTAX-END
			if(dec->msz) {
				LAST_OPERAND_SHIFT(ShiftType_SXTW, dec->msz)
			}
			break;
		}
		case ENC_ADR_Z_AZ_D_U32_SCALED:
		{
			// SYNTAX: <Zd>.D, [<Zn>.D,<Zm>.D, UXTW{<amount>}]
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_Z_BASE, dec->n, REG_Z_BASE, dec->m, 8);
			// SYNTAX-END
			if(dec->msz) {
				LAST_OPERAND_SHIFT(ShiftType_UXTW, dec->msz)
			}
			break;
		}
		case ENC_FCVTZS_Z_P_Z_D2X:
		case ENC_FCVTZU_Z_P_Z_D2X:
		case ENC_REVW_Z_Z_:
		case ENC_SCVTF_Z_P_Z_X2D:
		case ENC_SXTW_Z_P_Z_:
		case ENC_UCVTF_Z_P_Z_X2D:
		case ENC_UXTW_Z_P_Z_:
		{
			// SYNTAX: <Zd>.D,<Pg>/M,<Zn>.D
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_Z_P_Z_H2D:
		case ENC_FCVTZS_Z_P_Z_FP162X:
		case ENC_FCVTZU_Z_P_Z_FP162X:
		{
			// SYNTAX: <Zd>.D,<Pg>/M,<Zn>.H
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_Z_P_Z_S2D:
		case ENC_FCVTZS_Z_P_Z_S2X:
		case ENC_FCVTZU_Z_P_Z_S2X:
		case ENC_SCVTF_Z_P_Z_W2D:
		case ENC_UCVTF_Z_P_Z_W2D:
		{
			// SYNTAX: <Zd>.D,<Pg>/M,<Zn>.S
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_MOV_ORR_Z_ZZ_:
		{
			// SYNTAX: <Zd>.D,<Zn>.D
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_AND_Z_ZZ_:
		case ENC_BIC_Z_ZZ_:
		case ENC_EOR_Z_ZZ_:
		case ENC_ORR_Z_ZZ_:
		{
			// SYNTAX: <Zd>.D,<Zn>.D,<Zm>.D
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			ADD_OPERAND_ZREG_ESIZE(8, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMUL_Z_ZZI_D:
		{
			// SYNTAX: <Zd>.D,<Zn>.D,<Zm>.D[<index>]
			ADD_OPERAND_ZREG_ESIZE(8, dec->d);
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(8, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_Z_P_Z_D2H:
		case ENC_SCVTF_Z_P_Z_X2FP16:
		case ENC_UCVTF_Z_P_Z_X2FP16:
		{
			// SYNTAX: <Zd>.H,<Pg>/M,<Zn>.D
			ADD_OPERAND_ZREG_ESIZE(2, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_Z_P_Z_FP162H:
		case ENC_FCVTZU_Z_P_Z_FP162H:
		case ENC_SCVTF_Z_P_Z_H2FP16:
		case ENC_UCVTF_Z_P_Z_H2FP16:
		{
			// SYNTAX: <Zd>.H,<Pg>/M,<Zn>.H
			ADD_OPERAND_ZREG_ESIZE(2, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_BFCVT_Z_P_Z_S2BF:
		case ENC_BFCVTNT_Z_P_Z_S2BF:
		case ENC_FCVT_Z_P_Z_S2H:
		case ENC_SCVTF_Z_P_Z_W2FP16:
		case ENC_UCVTF_Z_P_Z_W2FP16:
		{
			// SYNTAX: <Zd>.H,<Pg>/M,<Zn>.S
			ADD_OPERAND_ZREG_ESIZE(2, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMUL_Z_ZZI_H:
		{
			// SYNTAX: <Zd>.H,<Zn>.H,<Zm>.H[<index>]
			ADD_OPERAND_ZREG_ESIZE(2, dec->d);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_TRN1_Z_ZZ_Q:
		case ENC_TRN2_Z_ZZ_Q:
		case ENC_UZP1_Z_ZZ_Q:
		case ENC_UZP2_Z_ZZ_Q:
		case ENC_ZIP1_Z_ZZ_Q:
		case ENC_ZIP2_Z_ZZ_Q:
		{
			// SYNTAX: <Zd>.Q,<Zn>.Q,<Zm>.Q
			ADD_OPERAND_ZREG_ESIZE(16, dec->d);
			ADD_OPERAND_ZREG_ESIZE(16, dec->n);
			ADD_OPERAND_ZREG_ESIZE(16, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_Z_P_Z_D2S:
		case ENC_FCVTZS_Z_P_Z_D2W:
		case ENC_FCVTZU_Z_P_Z_D2W:
		case ENC_SCVTF_Z_P_Z_X2S:
		case ENC_UCVTF_Z_P_Z_X2S:
		{
			// SYNTAX: <Zd>.S,<Pg>/M,<Zn>.D
			ADD_OPERAND_ZREG_ESIZE(4, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVT_Z_P_Z_H2S:
		case ENC_FCVTZS_Z_P_Z_FP162W:
		case ENC_FCVTZU_Z_P_Z_FP162W:
		{
			// SYNTAX: <Zd>.S,<Pg>/M,<Zn>.H
			ADD_OPERAND_ZREG_ESIZE(4, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTZS_Z_P_Z_S2W:
		case ENC_FCVTZU_Z_P_Z_S2W:
		case ENC_SCVTF_Z_P_Z_W2S:
		case ENC_UCVTF_Z_P_Z_W2S:
		{
			// SYNTAX: <Zd>.S,<Pg>/M,<Zn>.S
			ADD_OPERAND_ZREG_ESIZE(4, dec->d);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_FMUL_Z_ZZI_S:
		{
			// SYNTAX: <Zd>.S,<Zn>.S,<Zm>.S[<index>]
			ADD_OPERAND_ZREG_ESIZE(4, dec->d);
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(4, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_Z_P_ZZZ_:
		case ENC_FMLS_Z_P_ZZZ_:
		case ENC_FNMLA_Z_P_ZZZ_:
		case ENC_FNMLS_Z_P_ZZZ_:
		case ENC_MLA_Z_P_ZZZ_:
		case ENC_MLS_Z_P_ZZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zda>.<Ts>,<Pg>/M,<Zn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zda);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FCMLA_Z_P_ZZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			uint64_t const_ = 90*dec->rot;
			// SYNTAX: <Zda>.<Ts>,<Pg>/M,<Zn>.<Ts>,<Zm>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zda);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_SDOT_Z_ZZZ_:
		case ENC_UDOT_Z_ZZZ_:
		{
			unsigned elem_sz = (dec->size & 1) ? 8 : 4;
			unsigned elem_sz_b = (dec->size & 1) ? 2 : 1;
			// SYNTAX: <Zda>.<Ts>,<Zn>.<Tb>,<Zm>.<Tb>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(elem_sz_b, dec->n);
			ADD_OPERAND_ZREG_ESIZE(elem_sz_b, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMMLA_Z_ZZZ_D:
		{
			// SYNTAX: <Zda>.D,<Zn>.D,<Zm>.D
			ADD_OPERAND_ZREG_ESIZE(8, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			ADD_OPERAND_ZREG_ESIZE(8, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_Z_ZZZI_D:
		case ENC_FMLS_Z_ZZZI_D:
		{
			// SYNTAX: <Zda>.D,<Zn>.D,<Zm>.D[<index>]
			ADD_OPERAND_ZREG_ESIZE(8, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(8, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(8, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_SDOT_Z_ZZZI_D:
		case ENC_UDOT_Z_ZZZI_D:
		{
			// SYNTAX: <Zda>.D,<Zn>.H,<Zm>.H[<index>]
			ADD_OPERAND_ZREG_ESIZE(8, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_Z_ZZZI_H:
		case ENC_FMLS_Z_ZZZI_H:
		{
			// SYNTAX: <Zda>.H,<Zn>.H,<Zm>.H[<index>]
			ADD_OPERAND_ZREG_ESIZE(2, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FCMLA_Z_ZZZI_H:
		{
			uint64_t const_ = 90*dec->rot;
			// SYNTAX: <Zda>.H,<Zn>.H,<Zm>.H[<index>], #<const>
			ADD_OPERAND_ZREG_ESIZE(2, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(2, dec->m, dec->index);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_SMMLA_Z_ZZZ_:
		case ENC_UMMLA_Z_ZZZ_:
		case ENC_USDOT_Z_ZZZ_S:
		case ENC_USMMLA_Z_ZZZ_:
		{
			// SYNTAX: <Zda>.S,<Zn>.B,<Zm>.B
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(1, dec->n);
			ADD_OPERAND_ZREG_ESIZE(1, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SDOT_Z_ZZZI_S:
		case ENC_SUDOT_Z_ZZZI_S:
		case ENC_UDOT_Z_ZZZI_S:
		case ENC_USDOT_Z_ZZZI_S:
		{
			// SYNTAX: <Zda>.S,<Zn>.B,<Zm>.B[<index>]
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(1, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(1, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_BFDOT_Z_ZZZ_:
		case ENC_BFMLALB_Z_ZZZ_:
		case ENC_BFMLALT_Z_ZZZ_:
		case ENC_BFMMLA_Z_ZZZ_:
		{
			// SYNTAX: <Zda>.S,<Zn>.H,<Zm>.H
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE(2, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_BFDOT_Z_ZZZI_:
		case ENC_BFMLALB_Z_ZZZI_:
		case ENC_BFMLALT_Z_ZZZI_:
		{
			// SYNTAX: <Zda>.S,<Zn>.H,<Zm>.H[<index>]
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(2, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(2, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FMMLA_Z_ZZZ_S:
		{
			// SYNTAX: <Zda>.S,<Zn>.S,<Zm>.S
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			ADD_OPERAND_ZREG_ESIZE(4, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FMLA_Z_ZZZI_S:
		case ENC_FMLS_Z_ZZZI_S:
		{
			// SYNTAX: <Zda>.S,<Zn>.S,<Zm>.S[<index>]
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(4, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FCMLA_Z_ZZZI_S:
		{
			uint64_t const_ = 90*dec->rot;
			// SYNTAX: <Zda>.S,<Zn>.S,<Zm>.S[<index>], #<const>
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zda);
			ADD_OPERAND_ZREG_ESIZE(4, dec->n);
			ADD_OPERAND_ZREG_ESIZE_INDEXED(4, dec->m, dec->index);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_CLASTA_Z_P_ZZ_:
		case ENC_CLASTB_Z_P_ZZ_:
		case ENC_SPLICE_Z_P_ZZ_DES:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Pg>,<Zdn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LSL_Z_P_ZI_:
		case ENC_LSR_Z_P_ZI_:
		{
			unsigned elem_sz = dec->esize / 8;
			uint64_t const_ = dec->shift;
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ASR_Z_P_ZI_:
		case ENC_ASRD_Z_P_ZI_:
		{
			arrangement_spec arr_spec = table16_r_b_h_s_d[(dec->tszh<<2)|dec->tszl];
			unsigned elem_sz = arr_spec.elem_sz;
			uint64_t const_ = dec->shift;
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ADD_Z_P_ZZ_:
		case ENC_AND_Z_P_ZZ_:
		case ENC_ASR_Z_P_ZZ_:
		case ENC_ASRR_Z_P_ZZ_:
		case ENC_BIC_Z_P_ZZ_:
		case ENC_EOR_Z_P_ZZ_:
		case ENC_FABD_Z_P_ZZ_:
		case ENC_FADD_Z_P_ZZ_:
		case ENC_FDIV_Z_P_ZZ_:
		case ENC_FDIVR_Z_P_ZZ_:
		case ENC_FMAX_Z_P_ZZ_:
		case ENC_FMAXNM_Z_P_ZZ_:
		case ENC_FMIN_Z_P_ZZ_:
		case ENC_FMINNM_Z_P_ZZ_:
		case ENC_FMUL_Z_P_ZZ_:
		case ENC_FMULX_Z_P_ZZ_:
		case ENC_FSCALE_Z_P_ZZ_:
		case ENC_FSUB_Z_P_ZZ_:
		case ENC_FSUBR_Z_P_ZZ_:
		case ENC_LSL_Z_P_ZZ_:
		case ENC_LSLR_Z_P_ZZ_:
		case ENC_LSR_Z_P_ZZ_:
		case ENC_LSRR_Z_P_ZZ_:
		case ENC_MUL_Z_P_ZZ_:
		case ENC_ORR_Z_P_ZZ_:
		case ENC_SABD_Z_P_ZZ_:
		case ENC_SDIV_Z_P_ZZ_:
		case ENC_SDIVR_Z_P_ZZ_:
		case ENC_SMAX_Z_P_ZZ_:
		case ENC_SMIN_Z_P_ZZ_:
		case ENC_SMULH_Z_P_ZZ_:
		case ENC_SUB_Z_P_ZZ_:
		case ENC_SUBR_Z_P_ZZ_:
		case ENC_UABD_Z_P_ZZ_:
		case ENC_UDIV_Z_P_ZZ_:
		case ENC_UDIVR_Z_P_ZZ_:
		case ENC_UMAX_Z_P_ZZ_:
		case ENC_UMIN_Z_P_ZZ_:
		case ENC_UMULH_Z_P_ZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>,<Zm>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FCADD_Z_P_ZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			uint64_t const_ = dec->rot ? 270 : 90;
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>,<Zm>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_ASR_Z_P_ZW_:
		case ENC_LSL_Z_P_ZW_:
		case ENC_LSR_Z_P_ZW_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>,<Zm>.D
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(8, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FADD_Z_P_ZS_:
		case ENC_FMAX_Z_P_ZS_:
		case ENC_FMAXNM_Z_P_ZS_:
		case ENC_FMIN_Z_P_ZS_:
		case ENC_FMINNM_Z_P_ZS_:
		case ENC_FMUL_Z_P_ZS_:
		case ENC_FSUB_Z_P_ZS_:
		case ENC_FSUBR_Z_P_ZS_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			float fimm;
			if(dec->encoding == ENC_FADD_Z_P_ZS_ || dec->encoding == ENC_FSUB_Z_P_ZS_ || dec->encoding == ENC_FSUBR_Z_P_ZS_)
				fimm = dec->i1 ? 1.0 : 0.5;
			else if(dec->encoding == ENC_FMUL_Z_P_ZS_)
				fimm = dec->i1 ? 2.0 : 0.5;
			else
				fimm = dec->i1 ? 1.0 : 0;
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zdn>.<Ts>, #<fimm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_FIMM;
			// SYNTAX-END
			break;
		}
		case ENC_FMAD_Z_P_ZZZ_:
		case ENC_FMSB_Z_P_ZZZ_:
		case ENC_FNMAD_Z_P_ZZZ_:
		case ENC_FNMSB_Z_P_ZZZ_:
		case ENC_MAD_Z_P_ZZZ_:
		case ENC_MSB_Z_P_ZZZ_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Pg>/M,<Zm>.<Ts>,<Za>.<Ts>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'm');
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->a);
			// SYNTAX-END
			break;
		}
		case ENC_DECP_Z_P_Z_:
		case ENC_INCP_Z_P_Z_:
		case ENC_SQDECP_Z_P_Z_:
		case ENC_SQINCP_Z_P_Z_:
		case ENC_UQDECP_Z_P_Z_:
		case ENC_UQINCP_Z_P_Z_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Pm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_PRED_REG(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_INSR_Z_R_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rm_base = (dec->size & 0x3) == 3 ? REG_X_BASE : REG_W_BASE;
			// SYNTAX: <Zdn>.<Ts>,<R><m>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_INSR_Z_V_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			unsigned rm_base = bhsd_0123_reg(dec->size);
			// SYNTAX: <Zdn>.<Ts>,<V><m>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_REG(REGSET_ZR, rm_base, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_BIC_AND_Z_ZI_:
		case ENC_EON_EOR_Z_ZI_:
		case ENC_ORN_ORR_Z_ZI_:
		case ENC_AND_Z_ZI_:
		case ENC_EOR_Z_ZI_:
		case ENC_ORR_Z_ZI_:
		{
			unsigned elem_sz = size_spec_method0((dec->imm13>>12)&1, dec->imm13&0x3F);
			uint64_t const_ = dec->imm;
			switch(elem_sz) {
				case 1: const_ &= 0xFF; break;
				case 2: const_ &= 0xFFFF; break;
				case 4: const_ &= 0xFFFFFFFF; break;
				default: break;
			}
			// SYNTAX: <Zdn>.<Ts>,<Zdn>.<Ts>, #<const>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_CONST;
			// SYNTAX-END
			break;
		}
		case ENC_MUL_Z_ZI_:
		case ENC_SMAX_Z_ZI_:
		case ENC_SMIN_Z_ZI_:
		case ENC_UMAX_Z_ZI_:
		case ENC_UMIN_Z_ZI_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Zdn>.<Ts>, #<imm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_ADD_Z_ZI_:
		case ENC_SQADD_Z_ZI_:
		case ENC_SQSUB_Z_ZI_:
		case ENC_SUB_Z_ZI_:
		case ENC_SUBR_Z_ZI_:
		case ENC_UQSUB_Z_ZI_:
		case ENC_UQADD_Z_ZI_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Zdn>.<Ts>, #<imm>{,<shift>}
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			if(dec->encoding == ENC_UQADD_Z_ZI_ && dec->sh && !imm) {
				LAST_OPERAND_SHIFT(ShiftType_LSL, 8);
			}
			// else imm is the imm8 with shift applied, no need to print
			break;
		}
		case ENC_FTMAD_Z_ZZI_:
		{
			uint64_t imm = dec->imm;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: <Zdn>.<Ts>,<Zdn>.<Ts>,<Zm>.<Ts>, #<imm>
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(elem_sz, dec->m);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_EXT_Z_ZI_DES:
		{
			uint64_t imm = dec->position;
			// SYNTAX: <Zdn>.B,<Zdn>.B,<Zm>.B, #<imm>
			ADD_OPERAND_ZREG_ESIZE(1, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(1, dec->Zdn);
			ADD_OPERAND_ZREG_ESIZE(1, dec->m);
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_DECD_Z_ZS_:
		case ENC_INCD_Z_ZS_:
		case ENC_SQDECD_Z_ZS_:
		case ENC_SQINCD_Z_ZS_:
		case ENC_UQDECD_Z_ZS_:
		case ENC_UQINCD_Z_ZS_:
		{
			// SYNTAX: <Zdn>.D{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_ZREG_ESIZE(8, dec->Zdn);
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_DECH_Z_ZS_:
		case ENC_INCH_Z_ZS_:
		case ENC_SQDECH_Z_ZS_:
		case ENC_SQINCH_Z_ZS_:
		case ENC_UQDECH_Z_ZS_:
		case ENC_UQINCH_Z_ZS_:
		{
			// SYNTAX: <Zdn>.H{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_ZREG_ESIZE(2, dec->Zdn);
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_DECW_Z_ZS_:
		case ENC_INCW_Z_ZS_:
		case ENC_SQDECW_Z_ZS_:
		case ENC_SQINCW_Z_ZS_:
		case ENC_UQDECW_Z_ZS_:
		case ENC_UQINCW_Z_ZS_:
		{
			// SYNTAX: <Zdn>.S{,<pattern>{, MUL #<imm>}}
			ADD_OPERAND_ZREG_ESIZE(4, dec->Zdn);
			ADD_OPERAND_OPTIONAL_PATTERN_MUL;
			// SYNTAX-END
			break;
		}
		case ENC_LDR_Z_BI_:
		case ENC_STR_Z_BI_:
		{
			signed imm = dec->imm;
			// SYNTAX: <Zt>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_ZT;
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_AT_SYS_CR_SYSTEMINSTRS:
		{
			char *at_op = "";
			switch((dec->sys_op1 << 4) | ((dec->sys_crm & 1)<<3) | (dec->sys_op2 & 7)) {
				case 0b0000000: at_op = "S1E1R"; break;
				case 0b0000001: at_op = "S1E1W"; break;
				case 0b0000010: at_op = "S1E0R"; break;
				case 0b0000011: at_op = "S1E0W"; break;
				case 0b0001000: at_op = "S1E1RP"; break;
				case 0b0001001: at_op = "S1E1WP"; break;
				case 0b1000000: at_op = "S1E2R"; break;
				case 0b1000001: at_op = "S1E2W"; break;
				case 0b1000100: at_op = "S12E1R"; break;
				case 0b1000101: at_op = "S12E1W"; break;
				case 0b1000110: at_op = "S12E1R"; break;
				case 0b1000111: at_op = "S12E0W"; break;
				case 0b1100000: at_op = "S1E3R"; break;
				case 0b1100001: at_op = "S1E3W"; break;
			}
			// <at_op>
			ADD_OPERAND_NAME(at_op)
			// <Xt>
			ADD_OPERAND_XT
			break;
		}
		case ENC_BFMLAL_ASIMDSAME2_F_:
		{
			// SYNTAX: <Vd>.4S,<Vn>.8H,<Vm>.8H
			ADD_OPERAND_VD;
			ADD_OPERAND_VN;
			ADD_OPERAND_VM;
			// SYNTAX-END
			break;
		}
		case ENC_BFMLAL_ASIMDELEM_F:
		{
			// SYNTAX: <Vd>.4S,<Vn>.8H,<Vm>.H[<index>]
			ADD_OPERAND_VD;
			ADD_OPERAND_VN;
			ADD_OPERAND_VM;
			ADD_OPERAND_INDEX;
			// SYNTAX-END
			break;
		}
		case ENC_B_ONLY_CONDBRANCH:
		{
			Operation lookup[16] = {
				ARM64_B_EQ, ARM64_B_NE, ARM64_B_CS, ARM64_B_CC,
				ARM64_B_MI, ARM64_B_PL, ARM64_B_VS, ARM64_B_VC,
				ARM64_B_HI, ARM64_B_LS, ARM64_B_GE, ARM64_B_LT,
				ARM64_B_GT, ARM64_B_LE, ARM64_B_AL, ARM64_B_NV
			};

			dec->operation = lookup[dec->condition];

			uint64_t eaddr = dec->offset;
			// SYNTAX: <label>
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_DC_SYS_CR_SYSTEMINSTRS:
		{
			const char *dc_op = "RESERVED";
			uint64_t op1 = dec->op1;
			uint64_t op2 = dec->op2;
			uint64_t CRm = dec->CRm;
			     if(op1==0b000 && CRm==0b0110 && op2==0b001) dc_op = "ivac";
			else if(op1==0b000 && CRm==0b0110 && op2==0b010) dc_op = "isw";
			else if(op1==0b000 && CRm==0b0110 && op2==0b011 && HasMemTag()) dc_op = "igvac";
			else if(op1==0b000 && CRm==0b0110 && op2==0b100 && HasMemTag()) dc_op = "igsw";
			else if(op1==0b000 && CRm==0b0110 && op2==0b101 && HasMemTag()) dc_op = "igdvac";
			else if(op1==0b000 && CRm==0b0110 && op2==0b110 && HasMemTag()) dc_op = "igdsw";
			else if(op1==0b000 && CRm==0b1010 && op2==0b010) dc_op = "csw";
			else if(op1==0b000 && CRm==0b1010 && op2==0b100 && HasMemTag()) dc_op = "cgsw";
			else if(op1==0b000 && CRm==0b1010 && op2==0b010 && HasMemTag()) dc_op = "cisw";
			else if(op1==0b000 && CRm==0b1110 && op2==0b010) dc_op = "igdsw";
			else if(op1==0b000 && CRm==0b1110 && op2==0b100 && HasMemTag()) dc_op = "csw";
			else if(op1==0b000 && CRm==0b1110 && op2==0b110 && HasMemTag()) dc_op = "cgsw";
			else if(op1==0b011 && CRm==0b0100 && op2==0b001) dc_op = "zva";
			else if(op1==0b011 && CRm==0b0100 && op2==0b011 && HasMemTag()) dc_op = "gva";
			else if(op1==0b011 && CRm==0b0100 && op2==0b100 && HasMemTag()) dc_op = "gzva";
			else if(op1==0b011 && CRm==0b1010 && op2==0b001) dc_op = "cvac";
			else if(op1==0b011 && CRm==0b1010 && op2==0b011 && HasMemTag()) dc_op = "cgvac";
			else if(op1==0b011 && CRm==0b1010 && op2==0b101 && HasMemTag()) dc_op = "cgdvac";
			else if(op1==0b011 && CRm==0b1011 && op2==0b001) dc_op = "cvau";
			else if(op1==0b011 && CRm==0b1100 && op2==0b001 && HaveDCPoP()) dc_op = "cvap";
			else if(op1==0b011 && CRm==0b1100 && op2==0b011 && HasMemTag()) dc_op = "cgvap";
			else if(op1==0b011 && CRm==0b1100 && op2==0b101 && HasMemTag()) dc_op = "cgdvap";
			else if(op1==0b011 && CRm==0b1101 && op2==0b001 && HaveDCCVADP()) dc_op = "cvadp";
			else if(op1==0b011 && CRm==0b1101 && op2==0b011 && HasMemTag()) dc_op = "cvadp";
			else if(op1==0b011 && CRm==0b1101 && op2==0b101 && HasMemTag()) dc_op = "cgvadp";
			else if(op1==0b011 && CRm==0b1110 && op2==0b001) dc_op = "civac";
			else if(op1==0b011 && CRm==0b1110 && op2==0b011 && HasMemTag()) dc_op = "cigvac";
			else if(op1==0b011 && CRm==0b1110 && op2==0b101 && HasMemTag()) dc_op = "cgdvac";

			// SYNTAX: <dc_op>,<Xt>
			ADD_OPERAND_NAME(dc_op);
			ADD_OPERAND_XT;
			// SYNTAX-END

			break;
		}
		case ENC_IC_SYS_CR_SYSTEMINSTRS:
		{
			// NON-SYNTAX: <ic_op>{,<Xt>}
			break;
		}
		case ENC_BRK_EX_EXCEPTION:
		case ENC_HINT_HM_HINTS:
		case ENC_HLT_EX_EXCEPTION:
		case ENC_HVC_EX_EXCEPTION:
		case ENC_SMC_EX_EXCEPTION:
		case ENC_SVC_EX_EXCEPTION:
		case ENC_UDF_ONLY_PERM_UNDEF:
		{
			uint64_t imm = dec->imm16;
			// SYNTAX: #<imm>
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_BL_ONLY_BRANCH_IMM:
		case ENC_B_ONLY_BRANCH_IMM:
		{
			uint64_t eaddr = ctx->address + dec->offset;
			// SYNTAX: <label>
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_SYS_CR_SYSTEMINSTRS:
		{
			// sys #<op1>,<Cn>,<Cm>, #<op2>{,<Xt>}
			// #<op1>
			dec->operands[i].operandClass = IMM32;
			dec->operands[i].signedImm = 0;
			dec->operands[i++].immediate = dec->sys_op1;
			// C7
			dec->operands[i].operandClass = NAME;
			sprintf(dec->operands[i++].name, "c%llu", dec->sys_crn);
			// <Cm>
			dec->operands[i].operandClass = NAME;
			sprintf(dec->operands[i++].name, "c%llu", dec->sys_crm);
			// #<op2>
			dec->operands[i].operandClass = IMM32;
			dec->operands[i].signedImm = 0;
			dec->operands[i++].immediate = dec->sys_op2;
			// {,<Xt>}
			if(dec->Rt != 31) {
				ADD_OPERAND_XT
			}
			break;
		}
		case ENC_DMB_BO_BARRIERS:
		case ENC_DSB_BO_BARRIERS:
		{
			const char *table_barrier_limitations[16] = {
				"#0", "oshld", "oshst", "osh",
				"#4", "nshld", "nshst", "nsh",
				"#8", "ishld", "ishst", "ish",
				"#12", "ld", "st", "sy"
			};
			ADD_OPERAND_NAME(table_barrier_limitations[dec->CRm]);
			break;
		}
		case ENC_PRFH_I_P_BR_S:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFW_I_P_BR_S:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFD_I_P_BR_S:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_BR_S:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_PRFH_I_P_BZ_D_64_SCALED:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D, LSL #1]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFW_I_P_BZ_D_64_SCALED:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D, LSL #2]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFD_I_P_BZ_D_64_SCALED:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D, LSL #3]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFH_I_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D,<mod>#1]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFW_I_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D,<mod>#2]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFD_I_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D,<mod>#3]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D,<mod>]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_BZ_D_64_SCALED:
		{
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.D]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_X_BASE, dec->n, REG_Z_BASE, dec->m, 8);
			// SYNTAX-END
			break;
		}
		case ENC_PRFH_I_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.S,<mod>#1]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFW_I_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.S,<mod>#2]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFD_I_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.S,<mod>#3]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>,<Zm>.S,<mod>]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_BI_S:
		case ENC_PRFD_I_P_BI_S:
		case ENC_PRFH_I_P_BI_S:
		case ENC_PRFW_I_P_BI_S:
		{
			signed imm = dec->offset;
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			unsigned factor;
			switch(dec->encoding) {
				//case ENC_PRFH_I_P_BI_S: factor = 2; break;
				//case ENC_PRFW_I_P_BI_S: factor = 4; break;
				//case ENC_PRFD_I_P_BI_S: factor = 8; break;
				default: factor = 1;
			}
			break;
		}
		case ENC_PRFB_I_P_AI_D:
		case ENC_PRFD_I_P_AI_D:
		case ENC_PRFH_I_P_AI_D:
		case ENC_PRFW_I_P_AI_D:
		{
			signed imm = dec->offset;
			switch(dec->encoding) {
				case ENC_PRFH_I_P_AI_D: imm *= 2; break;
				case ENC_PRFW_I_P_AI_D: imm *= 4; break;
				case ENC_PRFD_I_P_AI_D: imm *= 8; break;
				default: break;
			}
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Zn>.D{, #<imm>}]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 8);
			// SYNTAX-END
			break;
		}
		case ENC_PRFB_I_P_AI_S:
		case ENC_PRFD_I_P_AI_S:
		case ENC_PRFH_I_P_AI_S:
		case ENC_PRFW_I_P_AI_S:
		{
			uint64_t imm = dec->offset;
			switch(dec->encoding) {
				case ENC_PRFH_I_P_AI_S: imm *= 2; break;
				case ENC_PRFW_I_P_AI_S: imm *= 4; break;
				case ENC_PRFD_I_P_AI_S: imm *= 8; break;
				default: break;
			}
			const char *prfop = prfop_lookup_4(dec->prfop);
			// SYNTAX: <prfop>,<Pg>, [<Zn>.S{, #<imm>}]
			ADD_OPERAND_NAME(prfop);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 4);
			// SYNTAX-END
			break;
		}
		case ENC_PRFM_P_LDST_REGOFF:
		{
			int reg_base = table_wbase_xbase[dec->option & 1];
			// SYNTAX: (<prfop>|#<imm5>), [<Xn|SP>, (<Wm>|<Xm>){,<extend>{<amount>}}]
			ADD_OPERAND_NAME(prfop_lookup(dec->Rt));
			ADD_OPERAND_MEM_EXTENDED(reg_base, dec->n, dec->m);
			// SYNTAX-END
			OPTIONAL_EXTEND_AMOUNT(3);
			break;
		}
		case ENC_PRFM_P_LDST_POS:
		{
			// SYNTAX: (<prfop>|#<imm5>), [<Xn|SP>{, #<pimm>}]
			ADD_OPERAND_NAME(prfop_lookup(dec->Rt));
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END

			break;
		}
		case ENC_PRFUM_P_LDST_UNSCALED:
		{
			// SYNTAX: (<prfop>|#<imm5>), [<Xn|SP>{, #<simm>}]
			ADD_OPERAND_NAME(prfop_lookup(dec->Rt));
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, dec->offset);
			// SYNTAX-END
			break;
		}
		case ENC_PRFM_P_LOADLIT:
		{
			uint64_t eaddr = dec->offset;
			// SYNTAX: (<prfop>|#<imm5>),<label>
			ADD_OPERAND_NAME(prfop_lookup(dec->Rt));
			ADD_OPERAND_LABEL;
			// SYNTAX-END
			break;
		}
		case ENC_MSR_SI_PSTATE:
		{
			const char *PSTATEFIELD = "RESERVED";
			uint64_t op1 = dec->op1;
			uint64_t op2 = dec->op2;
			if(op1==0 && op2==3 && HaveUAOExt()) PSTATEFIELD = "UAO";
			else if(op1==0 && op2==4 && HavePANExt()) PSTATEFIELD = "PAN";
			else if(op1==0 && op2==5) PSTATEFIELD = "SPSel";
			else if(op1==3 && op2==1 && HaveSSBSExt()) PSTATEFIELD = "SSBS";
			else if(op1==3 && op2==2 && HaveDITExt()) PSTATEFIELD = "DIT";
			else if(op1==3 && op2==4 && HasMemTag()) PSTATEFIELD = "TCO";
			else if(op1==3 && op2==6 && HasMemTag()) PSTATEFIELD = "DAIFSet";
			else if(op1==3 && op2==7 && HasMemTag()) PSTATEFIELD = "DAIFClr";
			ADD_OPERAND_NAME(PSTATEFIELD)

			unsigned imm = dec->CRm;
			// SYNTAX: <pstatefield>, #<imm>
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_MSR_SR_SYSTEMMOVE:
		{
			// SYNTAX: (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>),<Xt>
			ADD_OPERAND_SYSTEMREG;
			ADD_OPERAND_XT;
			// SYNTAX-END
			break;
		}
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS:
		{
			uint64_t OP1 = dec->op1;
			uint64_t OP2 = dec->op2;
			uint64_t CRM = dec->CRm;
			const char *TLBI_OP="";
			if(OP1==0b000 && CRM==0b0001 && OP2==0b000 && HaveTLBI()) TLBI_OP="VMALLE1OS";
			else if(OP1==0b000 && CRM==0b0001 && OP2==0b001 && HaveTLBI()) TLBI_OP="VAE1OS";
			else if(OP1==0b000 && CRM==0b0001 && OP2==0b010 && HaveTLBI()) TLBI_OP="ASIDE1OS";
			else if(OP1==0b000 && CRM==0b0001 && OP2==0b011 && HaveTLBI()) TLBI_OP="VAAE1OS";
			else if(OP1==0b000 && CRM==0b0001 && OP2==0b101 && HaveTLBI()) TLBI_OP="VALE1OS";
			else if(OP1==0b000 && CRM==0b0001 && OP2==0b111 && HaveTLBI()) TLBI_OP="VAALE1OS";
			else if(OP1==0b000 && CRM==0b0010 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE1IS";
			else if(OP1==0b000 && CRM==0b0010 && OP2==0b011 && HaveTLBI()) TLBI_OP="RVAAE1IS";
			else if(OP1==0b000 && CRM==0b0010 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE1IS";
			else if(OP1==0b000 && CRM==0b0010 && OP2==0b111 && HaveTLBI()) TLBI_OP="RVAALE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b000) TLBI_OP="VMALLE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b001) TLBI_OP="VAE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b010) TLBI_OP="ASIDE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b011) TLBI_OP="VAAE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b101) TLBI_OP="VALE1IS";
			else if(OP1==0b000 && CRM==0b0011 && OP2==0b111) TLBI_OP="VAALE1IS";
			else if(OP1==0b000 && CRM==0b0101 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE1OS";
			else if(OP1==0b000 && CRM==0b0101 && OP2==0b011 && HaveTLBI()) TLBI_OP="RVAAE1OS";
			else if(OP1==0b000 && CRM==0b0101 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE1OS";
			else if(OP1==0b000 && CRM==0b0101 && OP2==0b111 && HaveTLBI()) TLBI_OP="RVAALE1OS";
			else if(OP1==0b000 && CRM==0b0110 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE1";
			else if(OP1==0b000 && CRM==0b0110 && OP2==0b011 && HaveTLBI()) TLBI_OP="RVAAE1";
			else if(OP1==0b000 && CRM==0b0110 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE1";
			else if(OP1==0b000 && CRM==0b0110 && OP2==0b111 && HaveTLBI()) TLBI_OP="RVAALE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b000) TLBI_OP="VMALLE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b001) TLBI_OP="VAE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b010) TLBI_OP="ASIDE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b011) TLBI_OP="VAAE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b101) TLBI_OP="VALE1";
			else if(OP1==0b000 && CRM==0b0111 && OP2==0b111) TLBI_OP="VAALE1";
			else if(OP1==0b100 && CRM==0b0000 && OP2==0b001) TLBI_OP="IPAS2E1IS";
			else if(OP1==0b100 && CRM==0b0000 && OP2==0b010 && HaveTLBI()) TLBI_OP="RIPAS2E1IS";
			else if(OP1==0b100 && CRM==0b0000 && OP2==0b101) TLBI_OP="IPAS2LE1IS";
			else if(OP1==0b100 && CRM==0b0000 && OP2==0b110 && HaveTLBI()) TLBI_OP="RIPAS2LE1IS";
			else if(OP1==0b100 && CRM==0b0001 && OP2==0b000 && HaveTLBI()) TLBI_OP="ALLE2OS";
			else if(OP1==0b100 && CRM==0b0001 && OP2==0b001 && HaveTLBI()) TLBI_OP="VAE2OS";
			else if(OP1==0b100 && CRM==0b0001 && OP2==0b100 && HaveTLBI()) TLBI_OP="ALLE1OS";
			else if(OP1==0b100 && CRM==0b0001 && OP2==0b101 && HaveTLBI()) TLBI_OP="VALE2OS";
			else if(OP1==0b100 && CRM==0b0001 && OP2==0b110 && HaveTLBI()) TLBI_OP="VMALLS12E1OS";
			else if(OP1==0b100 && CRM==0b0010 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE2IS";
			else if(OP1==0b100 && CRM==0b0010 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE2IS";
			else if(OP1==0b100 && CRM==0b0011 && OP2==0b000) TLBI_OP="ALLE2IS";
			else if(OP1==0b100 && CRM==0b0011 && OP2==0b001) TLBI_OP="VAE2IS";
			else if(OP1==0b100 && CRM==0b0011 && OP2==0b100) TLBI_OP="ALLE1IS";
			else if(OP1==0b100 && CRM==0b0011 && OP2==0b101) TLBI_OP="VALE2IS";
			else if(OP1==0b100 && CRM==0b0011 && OP2==0b110) TLBI_OP="VMALLS12E1IS";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b000 && HaveTLBI()) TLBI_OP="IPAS2E1OS";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b001) TLBI_OP="IPAS2E1";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b010 && HaveTLBI()) TLBI_OP="RIPAS2E1";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b011 && HaveTLBI()) TLBI_OP="RIPAS2E1OS";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b100 && HaveTLBI()) TLBI_OP="IPAS2LE1OS";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b101) TLBI_OP="IPAS2LE1";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b110 && HaveTLBI()) TLBI_OP="RIPAS2LE1";
			else if(OP1==0b100 && CRM==0b0100 && OP2==0b111 && HaveTLBI()) TLBI_OP="RIPAS2LE1OS";
			else if(OP1==0b100 && CRM==0b0101 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE2OS";
			else if(OP1==0b100 && CRM==0b0101 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE2OS";
			else if(OP1==0b100 && CRM==0b0110 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE2";
			else if(OP1==0b100 && CRM==0b0110 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE2";
			else if(OP1==0b100 && CRM==0b0111 && OP2==0b000) TLBI_OP="ALLE2";
			else if(OP1==0b100 && CRM==0b0111 && OP2==0b001) TLBI_OP="VAE2";
			else if(OP1==0b100 && CRM==0b0111 && OP2==0b100) TLBI_OP="ALLE1";
			else if(OP1==0b100 && CRM==0b0111 && OP2==0b101) TLBI_OP="VALE2";
			else if(OP1==0b100 && CRM==0b0111 && OP2==0b110) TLBI_OP="VMALLS12E1";
			else if(OP1==0b110 && CRM==0b0001 && OP2==0b000 && HaveTLBI()) TLBI_OP="ALLE3OS";
			else if(OP1==0b110 && CRM==0b0001 && OP2==0b001 && HaveTLBI()) TLBI_OP="VAE3OS";
			else if(OP1==0b110 && CRM==0b0001 && OP2==0b101 && HaveTLBI()) TLBI_OP="VALE3OS";
			else if(OP1==0b110 && CRM==0b0010 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE3IS";
			else if(OP1==0b110 && CRM==0b0010 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE3IS";
			else if(OP1==0b110 && CRM==0b0011 && OP2==0b000) TLBI_OP="ALLE3IS";
			else if(OP1==0b110 && CRM==0b0011 && OP2==0b001) TLBI_OP="VAE3IS";
			else if(OP1==0b110 && CRM==0b0011 && OP2==0b101) TLBI_OP="VALE3IS";
			else if(OP1==0b110 && CRM==0b0101 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE3OS";
			else if(OP1==0b110 && CRM==0b0101 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE3OS";
			else if(OP1==0b110 && CRM==0b0110 && OP2==0b001 && HaveTLBI()) TLBI_OP="RVAE3";
			else if(OP1==0b110 && CRM==0b0110 && OP2==0b101 && HaveTLBI()) TLBI_OP="RVALE3";
			else if(OP1==0b110 && CRM==0b0111 && OP2==0b000) TLBI_OP="ALLE3";
			else if(OP1==0b110 && CRM==0b0111 && OP2==0b001) TLBI_OP="VAE3";
			else if(OP1==0b110 && CRM==0b0111 && OP2==0b101) TLBI_OP="VALE3";
			// NON-SYNTAX: <tlbi_op>{,<Xt>}
			break;
		}
		case ENC_DCPS1_DC_EXCEPTION:
		case ENC_DCPS2_DC_EXCEPTION:
		case ENC_DCPS3_DC_EXCEPTION:
		{
			uint64_t imm = dec->imm16;
			// NON-SYNTAX: #<imm>
			if(imm) {
				ADD_OPERAND_UIMM32;
			}
			break;
		}

		case ENC_CLREX_BN_BARRIERS:
		{
			unsigned imm = dec->CRm;
			// NON-SYNTAX: #<imm>
			if(imm != 15) {
				ADD_OPERAND_UIMM32;
			}
			break;
		}
		case ENC_BFCVTN_ASIMDMISC_4S:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_4s = _4S;
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.4S
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_T(arr_spec_4s, dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SADDW_ASIMDDIFF_W:
		case ENC_SSUBW_ASIMDDIFF_W:
		case ENC_UADDW_ASIMDDIFF_W:
		case ENC_USUBW_ASIMDDIFF_W:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Ta>,<Vm>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TA(dec->n);
			ADD_OPERAND_VREG_TB(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTL_ASIMDMISC_L:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_4s_2d[dec->sz];
			arrangement_spec arr_spec_b = table_4h_8h_2s_4s_1d_2d_r_r[(dec->sz<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SXTL_SSHLL_ASIMDSHF_L:
		case ENC_UXTL_USHLL_ASIMDSHF_L:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = arr_spec_method2(dec->immh);
			arrangement_spec arr_spec_b = arr_spec_method3(dec->immh, dec->Q);
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SHLL_ASIMDMISC_S:
		{
			unsigned shift = dec->shift;
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>, #<shift>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_SSHLL_ASIMDSHF_L:
		case ENC_USHLL_ASIMDSHF_L:
		{
			unsigned shift = dec->shift;
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = arr_spec_method2(dec->immh);
			arrangement_spec arr_spec_b = arr_spec_method3(dec->immh, dec->Q);
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>, #<shift>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_PMULL_ASIMDDIFF_L:
		case ENC_SABAL_ASIMDDIFF_L:
		case ENC_SABDL_ASIMDDIFF_L:
		case ENC_SADDL_ASIMDDIFF_L:
		case ENC_SMLAL_ASIMDDIFF_L:
		case ENC_SMLSL_ASIMDDIFF_L:
		case ENC_SMULL_ASIMDDIFF_L:
		case ENC_SQDMLAL_ASIMDDIFF_L:
		case ENC_SQDMLSL_ASIMDDIFF_L:
		case ENC_SQDMULL_ASIMDDIFF_L:
		case ENC_SSUBL_ASIMDDIFF_L:
		case ENC_UABAL_ASIMDDIFF_L:
		case ENC_UABDL_ASIMDDIFF_L:
		case ENC_UADDL_ASIMDDIFF_L:
		case ENC_UMLAL_ASIMDDIFF_L:
		case ENC_UMLSL_ASIMDDIFF_L:
		case ENC_UMULL_ASIMDDIFF_L:
		case ENC_USUBL_ASIMDDIFF_L:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>,<Vm>.<Tb>
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_TB(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_SMLAL_ASIMDELEM_L:
		case ENC_SMLSL_ASIMDELEM_L:
		case ENC_SMULL_ASIMDELEM_L:
		case ENC_SQDMLAL_ASIMDELEM_L:
		case ENC_SQDMLSL_ASIMDELEM_L:
		case ENC_SQDMULL_ASIMDELEM_L:
		case ENC_UMLAL_ASIMDELEM_L:
		case ENC_UMLSL_ASIMDELEM_L:
		case ENC_UMULL_ASIMDELEM_L:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			unsigned elem_sz = table_r_h_s_d[dec->size];
			// SYNTAX: {2}<Vd>.<Ta>,<Vn>.<Tb>,<Vm>.<Ts>[<index>]
			ADD_OPERAND_VREG_TA(dec->d);
			ADD_OPERAND_VREG_TB(dec->n);
			ADD_OPERAND_VREG_ESIZE_INDEXED(elem_sz, dec->m, dec->index);
			// SYNTAX-END
			break;
		}
		case ENC_FCVTN_ASIMDMISC_N:
		case ENC_FCVTXN_ASIMDMISC_N:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_4s_2d[dec->sz];
			arrangement_spec arr_spec_b = table_4h_8h_2s_4s_1d_2d_r_r[(dec->sz<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Tb>,<Vn>.<Ta>
			ADD_OPERAND_VREG_TB(dec->d);
			ADD_OPERAND_VREG_TA(dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_SQXTN_ASIMDMISC_N:
		case ENC_SQXTUN_ASIMDMISC_N:
		case ENC_UQXTN_ASIMDMISC_N:
		case ENC_XTN_ASIMDMISC_N:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Tb>,<Vn>.<Ta>
			ADD_OPERAND_VREG_TB(dec->d);
			ADD_OPERAND_VREG_TA(dec->n);
			// SYNTAX-END
			break;
		}
		case ENC_RSHRN_ASIMDSHF_N:
		case ENC_SHRN_ASIMDSHF_N:
		case ENC_SQRSHRN_ASIMDSHF_N:
		case ENC_SQRSHRUN_ASIMDSHF_N:
		case ENC_SQSHRN_ASIMDSHF_N:
		case ENC_SQSHRUN_ASIMDSHF_N:
		case ENC_UQRSHRN_ASIMDSHF_N:
		case ENC_UQSHRN_ASIMDSHF_N:
		{
			unsigned shift = dec->shift;
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = arr_spec_method2(dec->immh);
			arrangement_spec arr_spec_b = arr_spec_method3(dec->immh, dec->Q);
			// SYNTAX: {2}<Vd>.<Tb>,<Vn>.<Ta>, #<shift>
			ADD_OPERAND_VREG_TB(dec->d);
			ADD_OPERAND_VREG_TA(dec->n);
			ADD_OPERAND_IMMEDIATE32(shift, 0);
			// SYNTAX-END
			break;
		}
		case ENC_ADDHN_ASIMDDIFF_N:
		case ENC_RADDHN_ASIMDDIFF_N:
		case ENC_RSUBHN_ASIMDDIFF_N:
		case ENC_SUBHN_ASIMDDIFF_N:
		{
			if(dec->Q) dec->operation = enc_to_oper2(dec->encoding);
			arrangement_spec arr_spec_a = table_8h_4s_2d_1q[dec->size];
			arrangement_spec arr_spec_b = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {2}<Vd>.<Tb>,<Vn>.<Ta>,<Vm>.<Ta>
			ADD_OPERAND_VREG_TB(dec->d);
			ADD_OPERAND_VREG_TA(dec->n);
			ADD_OPERAND_VREG_TA(dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSE_R4_4V:
		case ENC_LD4R_ASISDLSO_R4:
		case ENC_LD4_ASISDLSE_R4:
		case ENC_ST1_ASISDLSE_R4_4V:
		case ENC_ST4_ASISDLSE_R4:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>,<Vt4>.<T>}, [<Xn|SP>]
			ADD_OPERAND_MULTIREG_4(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_R4_R4:
		case ENC_LD4R_ASISDLSOP_RX4_R:
		case ENC_LD4_ASISDLSEP_R4_R:
		case ENC_ST1_ASISDLSEP_R4_R4:
		case ENC_ST4_ASISDLSEP_R4_R:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>,<Vt4>.<T>}, [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_4(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_I4_I4:
		case ENC_LD4R_ASISDLSOP_R4_I:
		case ENC_LD4_ASISDLSEP_I4_I:
		case ENC_ST1_ASISDLSEP_I4_I4: // four registers, immediate offset (Rm == 11111 && opcode == 0010)
		case ENC_ST4_ASISDLSEP_I4_I:
		{
			unsigned imm;
			if(dec->encoding == ENC_LD4R_ASISDLSOP_R4_I)
				imm = 4 << (dec->size);
			else
				imm = dec->Q ? 64 : 32;
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>,<Vt4>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_4(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSE_R3_3V:
		case ENC_LD3R_ASISDLSO_R3:
		case ENC_LD3_ASISDLSE_R3:
		case ENC_ST1_ASISDLSE_R3_3V:
		case ENC_ST3_ASISDLSE_R3:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>}, [<Xn|SP>]
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_R3_R3:
		case ENC_LD3R_ASISDLSOP_RX3_R:
		case ENC_LD3_ASISDLSEP_R3_R:
		case ENC_ST1_ASISDLSEP_R3_R3:
		case ENC_ST3_ASISDLSEP_R3_R:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>}, [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_I3_I3:
		case ENC_ST1_ASISDLSEP_I3_I3:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			unsigned imm = dec->Q ? 48 : 24;
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSEP_I3_I:
		case ENC_ST3_ASISDLSEP_I3_I:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			unsigned imm = dec->Q ? 48 : 24;
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}

		case ENC_LD3R_ASISDLSOP_R3_I:
		{
			uint32_t imm = 3 << dec->size;
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>,<Vt3>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_3(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}

		case ENC_LD1_ASISDLSE_R2_2V:
		case ENC_LD2R_ASISDLSO_R2:
		case ENC_LD2_ASISDLSE_R2:
		case ENC_ST1_ASISDLSE_R2_2V:
		case ENC_ST2_ASISDLSE_R2:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>}, [<Xn|SP>]
			ADD_OPERAND_MULTIREG_2(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_R2_R2:
		case ENC_LD2R_ASISDLSOP_RX2_R:
		case ENC_LD2_ASISDLSEP_R2_R:
		case ENC_ST1_ASISDLSEP_R2_R2:
		case ENC_ST2_ASISDLSEP_R2_R:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>}, [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_2(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD2R_ASISDLSOP_R2_I:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			unsigned imm = 2<<dec->size;
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_2(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_I2_I2:
		case ENC_LD2_ASISDLSEP_I2_I:
		case ENC_ST1_ASISDLSEP_I2_I2:
		case ENC_ST2_ASISDLSEP_I2_I:
		{
			unsigned imm = dec->Q ? 32 : 16;
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>,<Vt2>.<T>}, [<Xn|SP>], #<imm>
			ADD_OPERAND_MULTIREG_2(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1R_ASISDLSO_R1:
		case ENC_LD1_ASISDLSE_R1_1V:
		case ENC_ST1_ASISDLSE_R1_1V:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>}, [<Xn|SP>]
			ADD_OPERAND_MULTIREG_1(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1R_ASISDLSOP_RX1_R:
		case ENC_LD1_ASISDLSEP_R1_R1:
		case ENC_ST1_ASISDLSEP_R1_R1:
		{
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>}, [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_1(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1R_ASISDLSOP_R1_I:
		{
			unsigned imm = 1<<dec->size;
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>}, [<Xn|SP>],#<imm>
			ADD_OPERAND_MULTIREG_1(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSEP_I1_I1: // one register, immediate offset
		case ENC_ST1_ASISDLSEP_I1_I1:
		{
			unsigned imm = dec->Q ? 16 : 8;
			arrangement_spec arr_spec = table_8b_16b_4h_8h_2s_4s_1d_2d[(dec->size<<1) | dec->Q];
			// SYNTAX: {<Vt>.<T>}, [<Xn|SP>],<imm>
			ADD_OPERAND_MULTIREG_1(REG_V_BASE, arr_spec.data_sz, arr_spec.elem_sz, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_UIMM32;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSO_B4_4B:
		case ENC_ST4_ASISDLSO_B4_4B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B,<Vt4>.B}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_B4_I4B:
		case ENC_ST4_ASISDLSOP_B4_I4B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B,<Vt4>.B}[<index>], [<Xn|SP>], #4
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 4);
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_BX4_R4B:
		case ENC_ST4_ASISDLSOP_BX4_R4B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B,<Vt4>.B}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSO_B3_3B:
		case ENC_ST3_ASISDLSO_B3_3B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_B3_I3B:
		case ENC_ST3_ASISDLSOP_B3_I3B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B}[<index>], [<Xn|SP>], #3
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 3);
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_BX3_R3B:
		case ENC_ST3_ASISDLSOP_BX3_R3B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B,<Vt3>.B}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSO_B2_2B:
		case ENC_ST2_ASISDLSO_B2_2B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_B2_I2B:
		case ENC_ST2_ASISDLSOP_B2_I2B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B}[<index>], [<Xn|SP>], #2
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 2);
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_BX2_R2B:
		case ENC_ST2_ASISDLSOP_BX2_R2B:
		{
			// SYNTAX: {<Vt>.B,<Vt2>.B}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSO_B1_1B:
		case ENC_ST1_ASISDLSO_B1_1B:
		{
			// SYNTAX: {<Vt>.B}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_B1_I1B:
		case ENC_ST1_ASISDLSOP_B1_I1B:
		{
			// SYNTAX: {<Vt>.B}[<index>], [<Xn|SP>], #1
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_BX1_R1B:
		case ENC_ST1_ASISDLSOP_BX1_R1B:
		{
			// SYNTAX: {<Vt>.B}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 1, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSO_D4_4D:
		case ENC_ST4_ASISDLSO_D4_4D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D,<Vt4>.D}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_D4_I4D:
		case ENC_ST4_ASISDLSOP_D4_I4D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D,<Vt4>.D}[<index>], [<Xn|SP>], #32
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 32);
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_DX4_R4D:
		case ENC_ST4_ASISDLSOP_DX4_R4D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D,<Vt4>.D}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSO_D3_3D:
		case ENC_ST3_ASISDLSO_D3_3D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_D3_I3D:
		case ENC_ST3_ASISDLSOP_D3_I3D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D}[<index>], [<Xn|SP>], #24
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 24);
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_DX3_R3D:
		case ENC_ST3_ASISDLSOP_DX3_R3D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D,<Vt3>.D}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSO_D2_2D:
		case ENC_ST2_ASISDLSO_D2_2D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_D2_I2D:
		case ENC_ST2_ASISDLSOP_D2_I2D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D}[<index>], [<Xn|SP>], #16
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 16);
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_DX2_R2D:
		case ENC_ST2_ASISDLSOP_DX2_R2D:
		{
			// SYNTAX: {<Vt>.D,<Vt2>.D}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSO_D1_1D:
		case ENC_ST1_ASISDLSO_D1_1D:
		{
			// SYNTAX: {<Vt>.D}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_D1_I1D:
		case ENC_ST1_ASISDLSOP_D1_I1D:
		{
			// SYNTAX: {<Vt>.D}[<index>], [<Xn|SP>], #8
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 8);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_DX1_R1D:
		case ENC_ST1_ASISDLSOP_DX1_R1D:
		{
			// SYNTAX: {<Vt>.D}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 8, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSO_H4_4H:
		case ENC_ST4_ASISDLSO_H4_4H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H,<Vt4>.H}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_H4_I4H:
		case ENC_ST4_ASISDLSOP_H4_I4H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H,<Vt4>.H}[<index>], [<Xn|SP>], #8
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 8);
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_HX4_R4H:
		case ENC_ST4_ASISDLSOP_HX4_R4H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H,<Vt4>.H}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSO_H3_3H:
		case ENC_ST3_ASISDLSO_H3_3H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_H3_I3H:
		case ENC_ST3_ASISDLSOP_H3_I3H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H}[<index>], [<Xn|SP>], #6
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_IMMEDIATE32(6, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_HX3_R3H:
		case ENC_ST3_ASISDLSOP_HX3_R3H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H,<Vt3>.H}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSO_H2_2H:
		case ENC_ST2_ASISDLSO_H2_2H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_H2_I2H:
		case ENC_ST2_ASISDLSOP_H2_I2H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H}[<index>], [<Xn|SP>], #4
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 4);
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_HX2_R2H:
		case ENC_ST2_ASISDLSOP_HX2_R2H:
		{
			// SYNTAX: {<Vt>.H,<Vt2>.H}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSO_H1_1H:
		case ENC_ST1_ASISDLSO_H1_1H:
		{
			// SYNTAX: {<Vt>.H}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_H1_I1H:
		case ENC_ST1_ASISDLSOP_H1_I1H:
		{
			// SYNTAX: {<Vt>.H}[<index>], [<Xn|SP>], #2
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 2);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_HX1_R1H:
		case ENC_ST1_ASISDLSOP_HX1_R1H:
		{
			// SYNTAX: {<Vt>.H}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 2, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSO_S4_4S:
		case ENC_ST4_ASISDLSO_S4_4S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S,<Vt4>.S}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_S4_I4S:
		case ENC_ST4_ASISDLSOP_S4_I4S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S,<Vt4>.S}[<index>], [<Xn|SP>], #16
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 16);
			// SYNTAX-END
			break;
		}
		case ENC_LD4_ASISDLSOP_SX4_R4S:
		case ENC_ST4_ASISDLSOP_SX4_R4S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S,<Vt4>.S}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_4_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSO_S3_3S:
		case ENC_ST3_ASISDLSO_S3_3S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_S3_I3S:
		case ENC_ST3_ASISDLSOP_S3_I3S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S}[<index>], [<Xn|SP>], #12
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 12);
			// SYNTAX-END
			break;
		}
		case ENC_LD3_ASISDLSOP_SX3_R3S:
		case ENC_ST3_ASISDLSOP_SX3_R3S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S,<Vt3>.S}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_3_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSO_S2_2S:
		case ENC_ST2_ASISDLSO_S2_2S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_S2_I2S:
		case ENC_ST2_ASISDLSOP_S2_I2S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S}[<index>], [<Xn|SP>], #8
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 8);
			// SYNTAX-END
			break;
		}
		case ENC_LD2_ASISDLSOP_SX2_R2S:
		case ENC_ST2_ASISDLSOP_SX2_R2S:
		{
			// SYNTAX: {<Vt>.S,<Vt2>.S}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_2_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSO_S1_1S:
		case ENC_ST1_ASISDLSO_S1_1S:
		{
			// SYNTAX: {<Vt>.S}[<index>], [<Xn|SP>]
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_S1_I1S:
		case ENC_ST1_ASISDLSOP_S1_I1S:
		{
			// SYNTAX: {<Vt>.S}[<index>], [<Xn|SP>], #4
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_POST_INDEX(REGSET_SP, REG_X_BASE, dec->n, 4);
			// SYNTAX-END
			break;
		}
		case ENC_LD1_ASISDLSOP_SX1_R1S:
		case ENC_ST1_ASISDLSOP_SX1_R1S:
		{
			// SYNTAX: {<Vt>.S}[<index>], [<Xn|SP>],<Xm>
			ADD_OPERAND_MULTIREG_1_INDEXED(REG_V_BASE, 0, 4, dec->t);
			ADD_OPERAND_MEM_XN_SP;
			ADD_OPERAND_XM;
			// SYNTAX-END
			break;
		}
		case ENC_RET_64R_BRANCH_REG:
		{
			// NON-SYNTAX: {<Xn>}
			if(dec->Rn != 30) {
				ADD_OPERAND_XN
			}
			break;
		}
		case ENC_ST4B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B,<Zt4>.B},<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ST4B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B,<Zt4>.B},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD4B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B,<Zt4>.B},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD4B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B,<Zt4>.B},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST3B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B},<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ST3B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD3B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD3B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B,<Zt3>.B},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST2B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B},<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ST2B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD2B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.B,<Zt2>.B},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD2B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.B,<Zt2>.B},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST4D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D,<Zt4>.D},<Pg>, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST4D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D,<Zt4>.D},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD4D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D,<Zt4>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD4D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D,<Zt4>.D},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST3D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D},<Pg>, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST3D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD3D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD3D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D,<Zt3>.D},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST2D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D},<Pg>, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST2D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD2D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.D,<Zt2>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD2D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.D,<Zt2>.D},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST4H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H,<Zt4>.H},<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST4H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H,<Zt4>.H},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD4H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H,<Zt4>.H},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD4H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H,<Zt4>.H},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST3H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H},<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST3H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD3H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD3H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H,<Zt3>.H},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST2H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H},<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST2H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD2H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.H,<Zt2>.H},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD2H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.H,<Zt2>.H},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST4W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S,<Zt4>.S},<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST4W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S,<Zt4>.S},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD4W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S,<Zt4>.S},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD4W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 4*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S,<Zt4>.S},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_4(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST3W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S},<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST3W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD3W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD3W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 3*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S,<Zt3>.S},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_3(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST2W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S},<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST2W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD2W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt1>.S,<Zt2>.S},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD2W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = 2*dec->offset;
			// SYNTAX: {<Zt1>.S,<Zt2>.S},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_2(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST1H_Z_P_BR_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: {<Zt>.<Ts>},<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, elem_sz, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1W_Z_P_BR_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: {<Zt>.<Ts>},<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, elem_sz, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_BR_:
		{
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: {<Zt>.<Ts>},<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, elem_sz, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_BI_:
		case ENC_ST1H_Z_P_BI_:
		case ENC_ST1W_Z_P_BI_:
		{
			signed imm = dec->offset;
			unsigned elem_sz = table_b_h_s_d[dec->size];
			// SYNTAX: {<Zt>.<Ts>},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, elem_sz, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.B},<Pg>, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.B},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BR_U8:
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.B},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BI_U8:
		case ENC_LDNF1B_Z_P_BI_U8:
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.B},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1RB_Z_P_BI_U8:
		case ENC_LD1ROB_Z_P_BI_U8:
		case ENC_LD1RQB_Z_P_BI_U8:
		{
			signed imm = (dec->encoding == ENC_LD1RQB_Z_P_BI_U8) ? 16*(dec->offset) : dec->offset;
			// SYNTAX: {<Zt>.B},<Pg>/Z, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1B_Z_P_BR_U8:
		{
			// SYNTAX: {<Zt>.B},<Pg>/Z, [<Xn|SP>{,<Xm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 1, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_ST1D_Z_P_BR_:
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1H_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1W_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1D_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D, LSL #3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D,<mod>#1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 1, 1);
			// SYNTAX-END
break;
		}
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D,<mod>#2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D,<mod>#3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D,<mod>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>,<Zm>.D]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_X_BASE, dec->n, REG_Z_BASE, dec->m, 8);
			// SYNTAX-END
			break;
		}
		case ENC_ST1D_Z_P_BI_:
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.D},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST1H_Z_P_AI_D:
		case ENC_ST1B_Z_P_AI_D:
		case ENC_ST1D_Z_P_AI_D:
		case ENC_ST1W_Z_P_AI_D:
		{
			signed imm = dec->offset;
			switch(dec->encoding) {
				case ENC_ST1H_Z_P_AI_D: imm *= 2; break;
				case ENC_ST1W_Z_P_AI_D: imm *= 4; break;
				case ENC_ST1D_Z_P_AI_D: imm *= 8; break;
				default: break;
			}
			// SYNTAX: {<Zt>.D},<Pg>, [<Zn>.D{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 8);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BR_U64:
		case ENC_LD1SH_Z_P_BR_S64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1SW_Z_P_BR_S64:
		case ENC_LD1W_Z_P_BR_U64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1D_Z_P_BR_U64:
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BR_U64:
		case ENC_LD1SB_Z_P_BR_S64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LD1W_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1D_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D, LSL #3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D,<mod>#1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D,<mod>#2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D,<mod>#3]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D,<mod>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 8, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>,<Zm>.D]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ(REG_X_BASE, dec->n, REG_Z_BASE, dec->m, 8);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BI_U64:
		case ENC_LD1D_Z_P_BI_U64:
		case ENC_LD1H_Z_P_BI_U64:
		case ENC_LD1SB_Z_P_BI_S64:
		case ENC_LD1SH_Z_P_BI_S64:
		case ENC_LD1SW_Z_P_BI_S64:
		case ENC_LD1W_Z_P_BI_U64:
		case ENC_LDNF1B_Z_P_BI_U64:
		case ENC_LDNF1D_Z_P_BI_U64:
		case ENC_LDNF1H_Z_P_BI_U64:
		case ENC_LDNF1SB_Z_P_BI_S64:
		case ENC_LDNF1SH_Z_P_BI_S64:
		case ENC_LDNF1SW_Z_P_BI_S64:
		case ENC_LDNF1W_Z_P_BI_U64:
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1RB_Z_P_BI_U64:
		case ENC_LD1RD_Z_P_BI_U64:
		case ENC_LD1RH_Z_P_BI_U64:
		case ENC_LD1ROD_Z_P_BI_U64:
		case ENC_LD1RQD_Z_P_BI_U64:
		case ENC_LD1RSB_Z_P_BI_S64:
		case ENC_LD1RSH_Z_P_BI_S64:
		case ENC_LD1RW_Z_P_BI_U64:
		case ENC_LD1RSW_Z_P_BI_S64:
		{
			signed imm;
			switch(dec->encoding) {
				case ENC_LD1RB_Z_P_BI_U64:
				case ENC_LD1RSB_Z_P_BI_S64:
					imm = dec->offset; break;
				case ENC_LD1RH_Z_P_BI_U64:
				case ENC_LD1RSH_Z_P_BI_S64:
					imm = 2*dec->offset; break;
				case ENC_LD1RSW_Z_P_BI_S64:
				case ENC_LD1RW_Z_P_BI_U64:
					imm = 4*dec->offset; break;
				case ENC_LD1RD_Z_P_BI_U64:
					imm = 8*dec->offset; break;
				default:
					imm = 16*dec->offset; break;
			}
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1H_Z_P_BR_U64:
		case ENC_LDFF1SH_Z_P_BR_S64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #1}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1SW_Z_P_BR_S64:
		case ENC_LDFF1W_Z_P_BR_U64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #2}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1D_Z_P_BR_U64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #3}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 3, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1B_Z_P_BR_U64:
		case ENC_LDFF1SB_Z_P_BR_S64:
		{
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Xn|SP>{,<Xm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_AI_D:
		case ENC_LD1SB_Z_P_AI_D:
		case ENC_LDFF1B_Z_P_AI_D:
		case ENC_LDFF1SB_Z_P_AI_D:
		case ENC_LD1H_Z_P_AI_D:
		case ENC_LD1SH_Z_P_AI_D:
		case ENC_LDFF1H_Z_P_AI_D:
		case ENC_LDFF1SH_Z_P_AI_D:
		case ENC_LD1W_Z_P_AI_D:
		case ENC_LD1SW_Z_P_AI_D:
		case ENC_LDFF1W_Z_P_AI_D:
		case ENC_LDFF1SW_Z_P_AI_D:
		case ENC_LD1D_Z_P_AI_D:
		case ENC_LDFF1D_Z_P_AI_D:
		{
			unsigned imm;
			switch(dec->encoding) {
				case ENC_LD1H_Z_P_AI_D:
				case ENC_LD1SH_Z_P_AI_D:
				case ENC_LDFF1H_Z_P_AI_D:
				case ENC_LDFF1SH_Z_P_AI_D:
					imm = 2 * dec->offset; break;
				case ENC_LD1W_Z_P_AI_D:
				case ENC_LD1SW_Z_P_AI_D:
				case ENC_LDFF1W_Z_P_AI_D:
				case ENC_LDFF1SW_Z_P_AI_D:
					imm = 4 * dec->offset; break;
				case ENC_LD1D_Z_P_AI_D:
				case ENC_LDFF1D_Z_P_AI_D:
					imm = 8 * dec->offset; break;
				default:
					imm = 1 * dec->offset;
			}
			// SYNTAX: {<Zt>.D},<Pg>/Z, [<Zn>.D{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 8, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 8);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.H},<Pg>, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.H},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BR_U16:
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BR_U16:
		case ENC_LD1SB_Z_P_BR_S16:
		{
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BI_U16:
		case ENC_LD1H_Z_P_BI_U16:
		case ENC_LD1SB_Z_P_BI_S16:
		case ENC_LDNF1B_Z_P_BI_U16:
		case ENC_LDNF1H_Z_P_BI_U16:
		case ENC_LDNF1SB_Z_P_BI_S16:
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1RB_Z_P_BI_U16:
		case ENC_LD1RH_Z_P_BI_U16:
		case ENC_LD1ROH_Z_P_BI_U16:
		case ENC_LD1RQH_Z_P_BI_U16:
		case ENC_LD1RSB_Z_P_BI_S16:
		{
			signed imm;
			switch(dec->encoding) {
				case ENC_LD1RH_Z_P_BI_U16:
				case ENC_LD1ROH_Z_P_BI_U16:
					imm = 2 * dec->offset; break;
				case ENC_LD1RQH_Z_P_BI_U16:
					imm = 16 * dec->offset; break;
				default:
					imm = dec->offset; break;
			}
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1H_Z_P_BR_U16:
		{
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #1}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1B_Z_P_BR_U16:
		case ENC_LDFF1SB_Z_P_BR_S16:
		{
			// SYNTAX: {<Zt>.H},<Pg>/Z, [<Xn|SP>{,<Xm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 2, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.S},<Pg>, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>, [<Xn|SP>,<Zm>.S,<mod>#1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>, [<Xn|SP>,<Zm>.S,<mod>#2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>, [<Xn|SP>,<Zm>.S,<mod>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.S},<Pg>, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_ST1B_Z_P_AI_S:
		case ENC_ST1H_Z_P_AI_S:
		case ENC_ST1W_Z_P_AI_S:
		{
			uint64_t imm = dec->offset;
			switch(dec->encoding) {
				case ENC_ST1H_Z_P_AI_S: imm *= 2; break;
				case ENC_ST1W_Z_P_AI_S: imm *= 4; break;
				default: imm *= 1; break;
			}
			// SYNTAX: {<Zt>.S},<Pg>, [<Zn>.S{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG(dec->g);
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 4);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BR_U32:
		case ENC_LD1SH_Z_P_BR_S32:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS:
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS:
		case ENC_LD1W_Z_P_BR_U32:
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Xm>, LSL #2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BR_U32:
		case ENC_LD1SB_Z_P_BR_S32:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Xm>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Zm>.S,<mod>#1]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Zm>.S,<mod>#2]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED:
		{
			ShiftType mod = dec->xs==0 ? ShiftType_UXTW : ShiftType_SXTW;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>,<Zm>.S,<mod>]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_Z_BASE, dec->m, 4, mod, 0, 0);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_BI_U32:
		case ENC_LD1H_Z_P_BI_U32:
		case ENC_LD1SB_Z_P_BI_S32:
		case ENC_LD1SH_Z_P_BI_S32:
		case ENC_LD1W_Z_P_BI_U32:
		case ENC_LDNF1B_Z_P_BI_U32:
		case ENC_LDNF1H_Z_P_BI_U32:
		case ENC_LDNF1SB_Z_P_BI_S32:
		case ENC_LDNF1SH_Z_P_BI_S32:
		case ENC_LDNF1W_Z_P_BI_U32:
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS:
		{
			signed imm = dec->offset;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_VL(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LD1RB_Z_P_BI_U32:
		case ENC_LD1RH_Z_P_BI_U32:
		case ENC_LD1ROW_Z_P_BI_U32:
		case ENC_LD1RQW_Z_P_BI_U32:
		case ENC_LD1RSB_Z_P_BI_S32:
		case ENC_LD1RSH_Z_P_BI_S32:
		case ENC_LD1RW_Z_P_BI_U32:
		{
			unsigned factor;
			switch(dec->encoding) {
				case ENC_LD1RH_Z_P_BI_U32:
				case ENC_LD1RSH_Z_P_BI_S32:
					factor = 2; break;
				case ENC_LD1RW_Z_P_BI_U32:
				case ENC_LD1ROW_Z_P_BI_U32:
					factor = 4; break;
				case ENC_LD1RQW_Z_P_BI_U32:
					factor = 16; break;
				default:
					factor = 1;
			}
			signed imm = factor * dec->offset;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET(REGSET_SP, REG_X_BASE, dec->n, imm);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1H_Z_P_BR_U32:
		case ENC_LDFF1SH_Z_P_BR_S32:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #1}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 1, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1W_Z_P_BR_U32:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>{,<Xm>, LSL #2}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED_SZ_SHIFT(REG_X_BASE, dec->n, 0, REG_X_BASE, dec->m, 0, ShiftType_LSL, 2, 1);
			// SYNTAX-END
			break;
		}
		case ENC_LDFF1B_Z_P_BR_U32:
		case ENC_LDFF1SB_Z_P_BR_S32:
		{
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Xn|SP>{,<Xm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_EXTENDED(REG_X_BASE, dec->n, dec->m);
			// SYNTAX-END
			break;
		}
		case ENC_LD1B_Z_P_AI_S:
		case ENC_LD1H_Z_P_AI_S:
		case ENC_LD1SB_Z_P_AI_S:
		case ENC_LD1SH_Z_P_AI_S:
		case ENC_LD1W_Z_P_AI_S:
		case ENC_LDFF1B_Z_P_AI_S:
		case ENC_LDFF1H_Z_P_AI_S:
		case ENC_LDFF1SB_Z_P_AI_S:
		case ENC_LDFF1SH_Z_P_AI_S:
		case ENC_LDFF1W_Z_P_AI_S:
		{
			unsigned imm = dec->msize/8 * dec->offset;
			// SYNTAX: {<Zt>.S},<Pg>/Z, [<Zn>.S{, #<imm>}]
			ADD_OPERAND_MULTIREG_1(REG_Z_BASE, 0, 4, dec->t);
			ADD_OPERAND_PRED_REG_QUAL(dec->g, 'z');
			ADD_OPERAND_MEM_REG_OFFSET_SZ(REGSET_ZR, REG_Z_BASE, dec->n, imm, 0, 4);
			// SYNTAX-END
			break;
		}
		case ENC_ISB_BI_BARRIERS:
		{
			uint64_t imm = dec->CRm;
			// NON-SYNTAX: OPTION_OR_IMMEDIATE
			if(dec->CRm != 15) {
				ADD_OPERAND_UIMM32;
			}
			break;
		}
		case ENC_BTI_HB_HINTS:
		{
			// NON-SYNTAX: {<targets>}
			const char *table_indirection[4] = {"", "c", "j", "jc"};
			const char *TARGETS = table_indirection[(dec->op2 & 6)>>1];
			if(TARGETS) {
				ADD_OPERAND_NAME(TARGETS)
			}
			break;
		}
		default:
			break;
	}

	return 0;
}
