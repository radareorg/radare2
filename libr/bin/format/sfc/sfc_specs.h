/* radare - LGPL - 2015 - maijin */

//CPU_memory_map: http://wiki.nesdev.com/w/index.php/CPU_memory_map

#ifndef _SFC_SPECS_H
#define _SFC_SPECS_H

#define LOROM_PAGE_SIZE                     0x8000
#define HIROM_PAGE_SIZE                     0x10000
#define BANK_SIZE			    0x10000

#define SFC_HDR_SIZE                        sizeof (sfc_int_hdr)
#define LOROM_HDR_LOC			    0x7FC0
#define HIROM_HDR_LOC			    0xFFC0

#define ADDMEM_START_ADDRESS                0x6000
#define ADDMEM_SIZE                         0x2000

//identical for both LoROM and HiROM

#define PPU1_REG_ADDRESS                    0x2100
#define PPU1_REG_SIZE                       0x0100

#define DSP_REG_ADDRESS        		    0x3000
#define DSP_REG_SIZE                 	    0x1000

#define OLDJOY_REG_ADDRESS        	    0x4000
#define OLDJOY_REG_SIZE                     0x0100

#define PPU2_REG_ADDRESS                    0x4200
#define PPU2_REG_SIZE                       0x0300

#define LOWRAM_START_ADDRESS		    0x7E0000
#define LOWRAM_SIZE			    0x2000

#define LOWRAM_MIRROR_START_ADDRESS         0x0000
#define LOWRAM_MIRROR_SIZE                  0x2000

#define HIRAM_START_ADDRESS		    0x7E2000
#define HIRAM_SIZE			    0x6000

#define EXTRAM_START_ADDRESS		    0x7E8000
#define EXTRAM_SIZE			    0x18000

R_PACKED (
typedef struct {
	char name[0x15];	//game title.
	ut8 rom_setup;		//ROM setup (LoROM/HiROM, etc.)
	ut8 rom_type;	
	ut8 rom_size;		//in 1kb chunks
	ut8 sram_size;		//in 1kb chunks
	ut8 dest_code;
	ut8 fixed_0x33;		//should be equal to 0x33
	ut8 rom_version;
	ut16 comp_check;	//should be equal to ~checksum
	ut16 checksum;
}) sfc_int_hdr;

#endif // _SFC_SPECS_H
