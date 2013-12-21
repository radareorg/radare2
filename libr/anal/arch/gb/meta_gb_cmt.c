/* radare - LGPL - Copyright 2013 - condret */

#include <r_io.h>
#include <r_anal.h>
#include "mbc.h"

void meta_gb_bankswitch_cmt(RMeta *m, ut64 addr, ut16 ldarg, ut8 rmbc) {
	if(rmbc>4)												//todo
		return;
	if(mbc[rmbc-1].from<ldarg && ldarg<mbc[rmbc-1].to)
		r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Bankswitch");
}

void gb_bankswitch_detect(RMeta *m, RIOBind iob, ut64 addr, ut16 ldarg) {
	ut8 rt;
	if(addr > 0x3fff)
		return;
	iob.read_at(iob.io, 0x147, &rt, 1);									//xxx: it won't change
	switch(gb_mbc_resolve(rt)) {
		case -1:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "unknown MBC!!!");
		case 0:
			return;
		default:
			meta_gb_bankswitch_cmt(m, addr, ldarg, (ut8)gb_mbc_resolve(rt));
	}
}

void meta_gb_hardware_cmt(RMeta *m, const ut8 hw, ut64 addr) {
	switch(hw)
	{
		case 0:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "JOYPAD");				//Moar context for this (which Key is affected)
			break;
		case 1:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Serial tranfer data");
			break;
		case 2:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Serial tranfer data - Ctl");
			break;
		case 4:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "DIV");
			break;
		case 5:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TIMA");
			break;
		case 6:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TMA");
			break;
		case 7:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TAC");
			break;
		case 0x0f:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Interrupt Flag");			//TODO: save in sdb for halt
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
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "SOUND");
			break;
		case 0x30:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Wave Pattern RAM/SOUND");
			break;
		case 0x40:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC");
			break;
		case 0x41:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC - STAT");
			break;
		case 0x42:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC - Scroll y");
			break;
		case 0x43:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC - Scroll x");
			break;
		case 0x44:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC - y cord");
			break;
		case 0x45:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC - y cord cmp");
			break;
		case 0x46:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "DMA");
			break;

	}
}
