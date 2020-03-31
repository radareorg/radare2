/* radare - LGPL - Copyright 2013-2018 - condret, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <stdio.h>
#include <string.h>
#include "gb_op_table.h"

static int gbOpLength(int gboptype){
	switch (gboptype) {
	case GB_8BIT:
		return 1;
	case GB_8BIT + ARG_8 + GB_IO:
	case GB_8BIT + ARG_8:
	case GB_16BIT:
		return 2;
	case GB_8BIT + ARG_16:
		return 3;
	default:
		return 0;
	}
}

static void gb_hardware_register_name (char *reg, ut8 offset) {
	switch (offset) {
	case 0x00: // Joy pad info
		r_str_cpy (reg, "rP1")
		break;
	case 0x01: // Serial Transfer Data
		r_str_cpy (reg, "rSB")
		break;
	case 0x02: // Serial I/O Control
		r_str_cpy (reg, "rSC")
		break;
	case 0x04: // Divider register
		r_str_cpy (reg, "rDIV")
		break;
	case 0x05: // Timer Counter
		r_str_cpy (reg, "rTIMA")
		break;
	case 0x06: // Timer modulo
		r_str_cpy (reg, "rTMA")
		break;
	case 0x07: // Timer control
		r_str_cpy (reg, "rTAC")
		break;
	case 0x0f: // Interrupt Flag
		r_str_cpy (reg, "rIF")
		break;
		// Audio Channel #1
	case 0x10: // Sweep Register
		r_str_cpy (reg, "rAUD1SWEEP")
		break;
	case 0x11: // Sound length/Wave pattern duty
		r_str_cpy (reg, "rAUD1LEN")
		break;
	case 0x12: // Envelope
		r_str_cpy (reg, "rAUD1ENV")
		break;
	case 0x13: // Frequency low
		r_str_cpy (reg, "rAUD1LOW")
		break;
	case 0x14: // Frequency high
		r_str_cpy (reg, "rAUD1HIGH")
		break;
		// Audio Channel #2
	case 0x16: // Sound length/Wave pattern duty
		r_str_cpy (reg, "rAUD2LEN")
		break;
	case 0x17: // Envelope
		r_str_cpy (reg, "rAUD2ENV")
		break;
	case 0x18: // Frequency low
		r_str_cpy (reg, "rAUD2LOW")
		break;
	case 0x19: // Frequency high
		r_str_cpy (reg, "rAUD2HIGH")
		break;
		// Sound Channel #3
	case 0x1a: // Sound on/off
		r_str_cpy (reg, "rAUD3ENA")
		break;
	case 0x1b: // Sound length
		r_str_cpy (reg, "rAUD3LEN")
		break;
	case 0x1c: // Select output level
		r_str_cpy (reg, "rAUD3LEVEL")
		break;
	case 0x1d: // Frequency low
		r_str_cpy (reg, "rAUD3LOW")
		break;
	case 0x1e: // Frequency high
		r_str_cpy (reg, "rAUD3HIGH")
		break;
		// Sound Channel #4
	case 0x20: // Sound length
		r_str_cpy (reg, "rAUD4LEN")
		break;
	case 0x21: // Envelope
		r_str_cpy (reg, "rAUD4ENV")
		break;
	case 0x22: // Polynomial counter
		r_str_cpy (reg, "rAUD4POLY")
		break;
		// Sound (general)
	case 0x23:
		r_str_cpy (reg, "rAUD4GO")
		break;
	case 0x24: // Channel control / ON-OFF / Volume
		r_str_cpy (reg, "rAUDVOL")
		break;
	case 0x25: // Selection of Sound output terminal
		r_str_cpy (reg, "rAUDTERM")
		break;
	case 0x26: // Sound on/off
		r_str_cpy (reg, "rAUDENA")
		break;
	case 0x76: // Sound Channel 1&2 PCM amplitude
		r_str_cpy (reg, "rPCM12")
		break;
	case 0x77: // Sound Channel 3&4 PCM amplitude
		r_str_cpy (reg, "rPCM34")
		break;
	case 0x40: // LCD Control
		r_str_cpy (reg, "rLCDC")
		break;
	case 0x41: // LCD Status
		r_str_cpy (reg, "rSTAT")
		break;
	case 0x42: // Scroll Y
		r_str_cpy (reg, "rSCY")
		break;
	case 0x43: // Scroll X
		r_str_cpy (reg, "rSCX")
		break;
	case 0x44: // Y-Coordinate
		r_str_cpy (reg, "rLY")
		break;
	case 0x45: // Y-Coordinate Compare
		r_str_cpy (reg, "rLYC")
		break;
	case 0x46: // Transfer and Start Address
		r_str_cpy (reg, "rDMA")
		break;
	case 0x47: // BG Palette Data
		r_str_cpy (reg, "rBGP")
		break;
	case 0x48: // Object Palette 0 Data
		r_str_cpy (reg, "rOBP0")
		break;
	case 0x49: // Object Palette 1 Data
		r_str_cpy (reg, "rOBP1")
		break;
	case 0x4a: // Window Y Position
		r_str_cpy (reg, "rWY")
		break;
	case 0x4b: // Window X Position
		r_str_cpy (reg, "rWX")
		break;
	case 0x4d: // Select CPU Speed
		r_str_cpy (reg, "rKEY1")
		break;
	case 0x4f: // Select Video RAM Bank
		r_str_cpy (reg, "rVBK")
		break;
	case 0x51: // Horizontal Blanking, General Purpose DMA
	case 0x52: // Horizontal Blanking, General Purpose DMA
	case 0x53: // Horizontal Blanking, General Purpose DMA
	case 0x54: // Horizontal Blanking, General Purpose DMA
	case 0x55: // Horizontal Blanking, General Purpose DMA
		sprintf (reg, "rHDMA%d", offset - 0x50);
		break;
	case 0x56: // Infrared Communications Port
		r_str_cpy (reg, "rRP")
		break;
	case 0x68: // Background Color Palette Specification
		r_str_cpy (reg, "rBCPS")
		break;
	case 0x69: // Background Color Palette Data
		r_str_cpy (reg, "rBCPD")
		break;
	case 0x6a: // Object Color Palette Specification
		r_str_cpy (reg, "rOCPS")
		break;
	case 0x6b: // Object Color Palette Data
		r_str_cpy (reg, "rOCPD")
		break;
	case 0x70: // Select Main RAM Bank
		r_str_cpy (reg, "rSVBK")
		break;
	case 0xff: // Interrupt Enable Flag
		r_str_cpy (reg, "rIE")
		break;
	default:
		// If unknown, return the original address
		sprintf (reg, "0xff%02x", offset);
		break;
	}
}

#ifndef GB_DIS_LEN_ONLY
static int gbDisass(RAsmOp *op, const ut8 *buf, int len){
	int foo = gbOpLength (gb_op[buf[0]].type);
	if (len < foo) {
		return 0;
	}
	const char *buf_asm = "invalid";
	char reg[32];
	memset (reg, '\0', sizeof (reg));
	switch (gb_op[buf[0]].type) {
	case GB_8BIT:
		buf_asm = sdb_fmt ("%s", gb_op[buf[0]].name);
		break;
	case GB_16BIT:
		buf_asm = sdb_fmt ("%s %s", cb_ops[buf[1] >> 3u], cb_regs[buf[1] & 7u]);
		break;
	case GB_8BIT + ARG_8:
		buf_asm = sdb_fmt (gb_op[buf[0]].name, buf[1]);
		break;
	case GB_8BIT + ARG_16:
		buf_asm = sdb_fmt (gb_op[buf[0]].name, buf[1] + 0x100 * buf[2]);
		break;
	case GB_8BIT + ARG_8 + GB_IO:
		gb_hardware_register_name(reg, buf[1]);
		buf_asm = sdb_fmt (gb_op[buf[0]].name, reg);
		break;
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
	return foo;
}
#endif
