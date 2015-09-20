/* radare - LGPL - 2015 - maijin */

#ifndef _NES_H
#define _NES_H

#define INES_MAGIC                          "\x4E\x45\x53\x1A"

#define PRG_PAGE_SIZE                       0x4000
#define CHR_PAGE_SIZE                       0x2000
#define INES_HDR_SIZE                       sizeof (ines_hdr)

#define RAM_START_ADDRESS                   0x0
#define RAM_SIZE                            0x2000

#define IOREGS_START_ADDRESS                0x2000
#define IOREGS_SIZE                         0x2020

#define EXPROM_START_ADDRESS                0x4020
#define EXPROM_SIZE                         0x1FE0

#define SRAM_START_ADDRESS                  0x6000
#define SRAM_SIZE                           0x2000

#define TRAINER_START_ADDRESS               0x7000
#define TRAINER_SIZE                        0x0200

#define ROM_START_ADDRESS                   0x8000
#define ROM_SIZE                            0x8000

#define NMI_VECTOR_START_ADDRESS            0xFFFA
#define RESET_VECTOR_START_ADDRESS          0xFFFC
#define IRQ_VECTOR_START_ADDRESS            0xFFFE

typedef struct __attribute__((__packed__)) {
	char id[0x4];					// NES\x1A
	ut8 prg_page_count_16k;				 // number of PRG-ROM pages
	ut8 chr_page_count_8k;				// number of CHR-ROM pages
	ut8 rom_control_byte_0;				 // flags describing ROM image
	ut8 rom_control_byte_1;				 // flags describing ROM image
	ut8 ram_bank_count_8k;				// size of PRG RAM
	ut8 reserved[7];				// zero filled
} ines_hdr;

#endif // _NES_H
