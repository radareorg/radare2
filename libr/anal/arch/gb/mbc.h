/* radare - LGPL - Copyright 2013 - condret */

#include <r_types.h>

typedef struct {
	const ut16 from;
	const ut16 to;
} mbc_t;

static const mbc_t mbc[]={
	{ 0x1fff, 0x4000 },
	{ 0x1fff, 0x4000 },
	{ 0x1fff, 0x4000 },
	{ 0x1fff, 0x4000 }		//this is not what it looks like mbc5 uses a 9-bit-value: 8 bit too 0x2000-0x2fff , 1 bit to 0x3000-0x3fff
};
