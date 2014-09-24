
/*
http://dsibrew.org/wiki/NDS_Format
http://sourceforge.net/p/devkitpro/ndstool/ci/master/tree/source/header.h
*/

#ifndef NIN_NDS_H
#define NIN_NDS_H

#include <r_types_base.h>

struct nds_hdr
{
    st8 title[0xC];
    st8 gamecode[0x4];
    st8 makercode[2];
    ut8 unitcode;
    ut8 devicetype;
    ut8 devicecap;
    ut8 reserved1[0x9];
    ut8 romversion;
    ut8 reserved2;
    ut32 arm9_rom_offset;
    ut32 arm9_entry_address;
    ut32 arm9_ram_address;
    ut32 arm9_size;
    ut32 arm7_rom_offset;
    ut32 arm7_entry_address;
    ut32 arm7_ram_address;
    ut32 arm7_size;
    ut32 fnt_offset;
    ut32 fnt_size;
    ut32 fat_offset;
    ut32 fat_size;
    ut32 arm9_overlay_offset;
    ut32 arm9_overlay_size;
    ut32 arm7_overlay_offset;
    ut32 arm7_overlay_size;
    ut32 rom_control_info1;
    ut32 rom_control_info2;
    ut32 banner_offset;
    ut16 secure_area_crc;
    ut16 rom_control_info3;
    ut32 offset_0x70;
    ut32 offset_0x74;
    ut32 offset_0x78;
    ut32 offset_0x7C;
    ut32 application_end_offset;
    ut32 rom_header_size;
    ut32 offset_0x88;
    ut32 offset_0x8C;

    /* reserved */
    ut32 offset_0x90;
    ut32 offset_0x94;
    ut32 offset_0x98;
    ut32 offset_0x9C;
    ut32 offset_0xA0;
    ut32 offset_0xA4;
    ut32 offset_0xA8;
    ut32 offset_0xAC;
    ut32 offset_0xB0;
    ut32 offset_0xB4;
    ut32 offset_0xB8;
    ut32 offset_0xBC;

    ut8 logo[156];
    ut16 logo_crc;
    ut16 header_crc;

} __attribute__((packed));

#endif /* NIN_NDS_H */

