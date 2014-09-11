#ifndef GB_H
#define GB_H
#include <r_types.h>

typedef struct gb_user_t {
	ut8 mbc_id;
	ut8 romsz_id;
	ut8 ramsz_id;
	ut8 rombanks;
	ut8 rambanks;
	ut32 cycles;
} GBUser;

enum {
	MBC_ROM = 0,
	MBC1,
	MBC1_RAM,
	MBC1_RAM_BAT,
	MBC2 = 0x5,
	MBC2_BAT,
	MBC_ROM_RAM = 0x8,
	MBC_ROM_RAM_BAT,
	MBC_MMM = 0x0b,
	MBC_MMM_RAM,
	MBC_MMM_RAM_BAT,
	MBC3_BAT_TIM = 0x0f,
	MBC3_RAM_BAT_TIM,
	MBC3,
	MBC3_RAM,
	MBC3_RAM_BAT,
	MBC4 = 0x15,
	MBC4_RAM,
	MBC4_RAM_BAT,
	MBC5 = 0x19,
	MBC5_RAM,
	MBC5_RAM_BAT,
	MBC5_RUM,
	MBC5_RAM_RUM,
	MBC5_RAM_BAT_RUM,
	CAM = 0xfc,
	TAMA5,
	HUC3,
	HUC1_RAM_BAT
};

enum {
	NOBANK = 0,
	BANK4,
	BANK8,
	BANK16,
	BANK32,
	BANK64,
	BANK128,
	BANK256,
	BANK72 = 0x52,
	BANK80,
	BANK96
};

enum {
	NORAM = 0,
	RAM2K,
	RAM8K,
	RAM32K
};
#endif
