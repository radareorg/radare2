/* radare - LGPL - Copyright 2013 - condret */

#include <r_types.h>

static st8 gb_mbc_resolve(ut8 rt) {	//rename
	switch(rt) {
		case 0:
		case 8:
		case 9:
		case 0xb:		//?
		case 0xc:		//?
		case 0xd:		//?
		case 0x1f:
			return 0;
		case 1:
		case 2:
		case 3:
		case 0xff:		//huc1
			return 1;
		case 5:
		case 6:
			return 2;
		case 0xf:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			return 3;
		case 0x19:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1d:
		case 0x1e:
			return 4;
		case 0xfd:		//?
			return 5;
		case 0xfe:		//?
			return 6;
	}
	return -1;
}
