
/*
https://www.3dbrew.org/wiki/FIRM
More formats to support: https://www.3dbrew.org/wiki/Category:File_formats
*/

#ifndef NIN_N3DS_H
#define NIN_N3DS_H

#include <r_types_base.h>

struct n3ds_firm_sect_hdr
{
	ut32 offset;
	ut32 address;
	ut32 size;
	ut32 type; /* ('0'=ARM9/'1'=ARM11) */
	ut8 sha256[0x20];
} __attribute__((packed));

struct n3ds_firm_hdr
{
	ut8 magic[4];
	ut8 reserved1[4];
	ut32 arm11_ep;
	ut32 arm9_ep;
	ut8 reserved2[0x30];
	struct n3ds_firm_sect_hdr sections[4];
	ut8 rsa2048[0x100];
} __attribute__((packed));

#endif /* NIN_N3DS_H */

