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
		case 0:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "JOYPAD");				//Moar context for this (which Key is affected)
			break;
		case 1:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Serial tranfer data");
			break;
		case 2:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Serial tranfer data - Ctl");
			break;
		case 4:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "DIV");
			break;
		case 5:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "TIMA");
			break;
		case 6:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "TMA");
			break;
		case 7:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "TAC");
			break;
		case 0x0f:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Interrupt Flag");
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1d:
		case 0x1e:
		case 0x20:
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "SOUND");
			break;
		case 0x30:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Wave Pattern RAM/SOUND");
			break;
		case 0x40:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC");
			break;
		case 0x41:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC - STAT");
			break;
		case 0x42:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC - Scroll y");
			break;
		case 0x43:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC - Scroll x");
			break;
		case 0x44:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC - y cord");
			break;
		case 0x45:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "LCDC - y cord cmp");
			break;
		case 0x46:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "DMA");
			break;
		case 0xff:
			r_meta_set_string(a, R_META_TYPE_COMMENT, addr, "Interrupt Enable Flag");

	}
}
