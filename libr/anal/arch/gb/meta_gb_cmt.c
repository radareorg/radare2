/* radare - LGPL - Copyright 2013 - condret */

#include <r_io.h>
#include <r_anal.h>

void meta_gb_bankswitch_cmt(RAnal *a, ut64 addr, ut16 ldarg) {
	if(0x1fff <ldarg && ldarg < 0x4000 && addr < 0x4000)
		r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "Bankswitch");
	if(0x6000 > ldarg && ldarg > 0x3fff)
		r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Ramswitch");
}

void meta_gb_hardware_cmt(RAnal *a, const ut8 hw, ut64 addr) {
	switch(hw)
	{
		case 0x00:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "P1 - Joypad info)"); //Moar context for this (which Key is affected)
			break;
		case 0x01:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "SB - Serial Transfer Data");
			break;
		case 0x02:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "SC - Serial I/O Control");
			break;
		case 0x04:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "DIV - Divider register");
			break;
		case 0x05:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "TIMA - Timer Counter");
			break;
		case 0x06:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "TMA - Timer modulo");
			break;
		case 0x07:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "TAC - Timer control");
			break;
		case 0x0f:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "IF - Interrupt Flag");
			break;
		case 0x10:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD1SWEEP - Sweep Register");
			break;
		case 0x11:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD1LEN - Sound length/Wave pattern duty");
			break;
		case 0x12:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD1ENV - Envelope");
			break;
		case 0x13:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD1LOW - Frequency low");
			break;
		case 0x14:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD1HIGH - Frequency high");
			break;
		case 0x16:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD2LEN - Sound length/Wave pattern duty");
			break;
		case 0x17:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD2ENV - Envelope");
			break;
		case 0x18:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD2LOW - Frequency low");
			break;
		case 0x19:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD2HIGH - Frequency high");
			break;
		case 0x1a:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD3ENA - Sound on/off");
			break;
		case 0x1b:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD3LEN - Sound length");
			break;
		case 0x1c:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD3LEVEL - Select output level");
			break;
		case 0x1d:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD3LOW - Frequency low");
			break;
		case 0x1e:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD3HIGH - Frequency high");
			break;
		case 0x20:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD4LEN - Sound length");
			break;
		case 0x21:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD4ENV - Envelope");
			break;
		case 0x22:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD4POLY - Polynomial counter");
			break;
		case 0x23:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUD4GO");
			break;
		case 0x24:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUDVOL - Channel control / ON-OFF / Volume");
			break;
		case 0x25:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUDTERM - Selection of Sound output terminal");
			break;
		case 0x26:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "AUDENA - Sound on/off");
			break;
		case 0x76:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "PCM12 - Sound Channel 1&2 PCM amplitude");
			break;
		case 0x77:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "PCM34 - Sound Channel 3&4 PCM amplitude");
			break;
		/*
		// Wrong name and value in Dr.Pan's doc. Not a register. Delete?
		case 0x30:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "Wave Pattern RAM/SOUND");
			break;
		*/
		case 0x40:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "LCDC - LCD Control");
			break;
		case 0x41:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "STAT - LCD Status");
			break;
		case 0x42:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "SCY - Scroll Y");
			break;
		case 0x43:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "SCX - Scroll X");
			break;
		case 0x44:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "LY - Y-Coordinate");
			break;
		case 0x45:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "LYC - Y-Coordinate Compare");
			break;
		case 0x46:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "DMA - Transfer and Start Address");
			break;
		case 0x47:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "BGP - BG Palette Data");
			break;
		case 0x48:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "OBP0 - Object Palette 0 Data");
			break;
		case 0x49:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "OBP1 - Object Palette 1 Data");
			break;
		case 0x4a:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "WY - Window Y Position");
			break;
		case 0x4b:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "WX - Window X Position");
			break;
		case 0x4d:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "KEY1 - Select CPU Speed");
			break;
		case 0x4f:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "VBK - Select Video RAM Bank");
			break;
		// DMA registers (0xff51 to 0xff55)
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "HDMA - Horizontal Blanking, General Purpose DMA");
			break;
		case 0x56:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "RP - Infrared Communications Port");
			break;
		case 0x68:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "BCPS - Background Color Palette Specification");
			break;
		case 0x69:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "BCPD - Background Color Palette Data");
			break;
		case 0x6a:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "OCPS - Object Color Palette Specification");
			break;
		case 0x6b:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "OCPD - Object Color Palette Data");
			break;
		case 0x70:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "SVBK - Select Main RAM Bank");
			break;
		case 0xff:
			r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "IE - Interrupt Enable Flag");
			break;
		}
}
