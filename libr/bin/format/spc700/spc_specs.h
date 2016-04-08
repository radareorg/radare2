/* radare - LGPL - 2015 - maijin */

#ifndef _SPC_H
#define _SPC_H

#define SPC_MAGIC			"SNES-SPC700 Sound File Data"
#define SPC_HDR_SIZE			sizeof (spc_hdr)

#define RAM_START_ADDRESS		0x100
#define RAM_SIZE 			0x10000

#define DSP_REG_START_ADDRESS		0x10100
#define DSP_REG_SIZE			0x80

#define EXTRA_RAM_START_ADDRESS		0x101C0
#define EXTRA_RAM_SIZE			0x40

#define EXTENDED_ID666_START_ADDRESS	0x10200

typedef enum {
	UNKNOWN,
	ZSNES,
	SNES9X,
} emulator_used;

typedef struct __attribute__((__packed__)) { //SNES9x
	char	song_title [32];
	char	game_title [32];
	char	name_of_dumper [16];
	char	comments [32];
	ut8	date[11];
	ut8	num_sec_bef_fade_out[3];
	ut8	len_fade_out[5];
	char artist_song [32];
	bool default_channel_disabled;
	emulator_used emulator_used[1];
	ut8 reserved[1];
} id666_tag_text;

typedef struct __attribute__((__packed__)) { //ZSNES
	char	song_title [32];
	char	game_title [32];
	char	name_of_dumper [16];
	char	comments [32];
	ut8	date[4];
	ut8 unused[8];
	ut8	num_sec_bef_fade_out[3];
	ut8	len_fade_out[4];
	char	artist_song [32];
	bool default_channel_disabled;
	ut8 reserved[1];
} id666_tag_binary;

typedef struct __attribute__((__packed__))	{
	char	signature [33];
	ut8	 signature2 [2];
	ut8 has_id666;
	ut8 version;
} spc_hdr;

typedef struct __attribute__((__packed__))	{
	ut8 pcl, pch;
	ut8 a;
	ut8 x;
	ut8 y;
	ut8 psw;
	ut8 sp;
	ut8 reserved_1, reserved_2;
} spc_reg;

typedef struct __attribute__((__packed__))	{
	ut8 ram [0x10000];
	ut8 dsp [128];
	ut8 unused [0x40];
	ut8 ipl_rom [0x40];
} spc_data;

#endif // _SPC_H
