/* radare - LGPL - 2015 - maijin */

//CPU_memory_map: http://wiki.nesdev.com/w/index.php/CPU_memory_map

#ifndef _NES_H
#define _NES_H

#define INES_MAGIC                          "\x4E\x45\x53\x1A"

#define PRG_PAGE_SIZE                       0x4000
#define CHR_PAGE_SIZE                       0x2000
#define INES_HDR_SIZE                       sizeof (ines_hdr)

#define RAM_START_ADDRESS                   0x0000
#define RAM_SIZE                            0x0800

#define RAM_MIRROR_1_ADDRESS                0x0800
#define RAM_MIRROR_1_SIZE                   0x0800

#define RAM_MIRROR_2_ADDRESS                0x1000
#define RAM_MIRROR_2_SIZE                   0x0800

#define RAM_MIRROR_3_ADDRESS                0x1800
#define RAM_MIRROR_3_SIZE                   0x0800

#define PPU_REG_ADDRESS                     0x2000
#define PPU_REG_SIZE                        0x0008

#define APU_AND_IOREGS_START_ADDRESS        0x4000
#define APU_AND_IOREGS_SIZE                 0x0020

#define SRAM_START_ADDRESS                  0x6000
#define SRAM_SIZE                           0x2000

#define ROM_START_ADDRESS                   0x8000
#define ROM_SIZE                            0x8000

#define ROM_MIRROR_ADDRESS                  0xC000
#define ROM_MIRROR_SIZE 0x8000

#define NMI_VECTOR_START_ADDRESS 0xFFFA
#define RESET_VECTOR_START_ADDRESS          0xFFFC
#define IRQ_VECTOR_START_ADDRESS            0xFFFE

#define PPU_CTRL_REG1                       0x2000
#define PPU_CTRL_REG2                       0x2001
#define PPU_STATUS                          0x2002
#define PPU_SPR_ADDR                        0x2003
#define PPU_SPR_DATA                        0x2004
#define PPU_SCROLL_REG                      0x2005
#define PPU_ADDRESS                         0x2006
#define PPU_DATA                            0x2007

#define SND_REGISTER                        0x4000
#define SND_SQUARE1_REG                     0x4000
#define SND_SQUARE2_REG                     0x4004
#define SND_TRIANGLE_REG                    0x4008
#define SND_NOISE_REG                       0x400c
#define SND_DELTA_REG                       0x4010
#define SND_MASTERCTRL_REG                  0x4015

#define SPR_DMA                             0x4014
#define JOYPAD_PORT                         0x4016
#define JOYPAD_PORT1                        0x4016
#define JOYPAD_PORT2                        0x4017

R_PACKED (
typedef struct  {
	char id[0x4];					// NES\x1A
	ut8 prg_page_count_16k;				 // number of PRG-ROM pages
	ut8 chr_page_count_8k;				// number of CHR-ROM pages
	ut8 rom_control_byte_0;				 // flags describing ROM image
	ut8 rom_control_byte_1;				 // flags describing ROM image
	ut8 ram_bank_count_8k;				// size of PRG RAM
	ut8 reserved[7];				// zero filled
}) ines_hdr;

#endif // _NES_H
