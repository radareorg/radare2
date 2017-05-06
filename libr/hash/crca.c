//author: Victor Mu~noz (vmunoz@ingenieria-inversa.cl
//license: the very same than radare, blah, blah
//some definitions and test cases borrowed from http://www.nightmare.com/~ryb/code/CrcMoose.py (Ray Burr)

#include <r_hash.h>

void crc_init (R_CRC_CTX *ctx, ut32 crc, ut32 size, int reflect, ut32 poly, ut32 xout) {
	ctx->crc = crc;
	ctx->size = size;
	ctx->reflect = reflect;
	ctx->poly = poly;
	ctx->xout = xout;
}

void crc_update (R_CRC_CTX *ctx, const ut8 *data, ut32 sz) {
	ut32 crc, d;
	int i, j;

	crc = ctx->crc;
	for (i = 0; i < sz; i++) {
		d = data[i];
		if (ctx->reflect) {
			for (j = 0; j < 4; j++) {
				if (((d >> j) ^ (d >> (7 - j))) & 1) {
					d ^= (1 << j) ^ (1 << (7 - j));
				}
			}
		}
		crc ^= d << (ctx->size - 8);
		for (j = 0; j < 8; j++) {
			crc = ((crc >> (ctx->size - 1)) & 1? ctx->poly: 0) ^ (crc << 1);
		}
	}
	ctx->crc = crc;
}

static void crc_final (R_CRC_CTX *ctx, ut32 *r) {
	ut32 crc;
	int i;

	crc = ctx->crc;
	crc &= ((((ut32) 1 << (ctx->size - 1)) - 1) << 1) | 1;
	if (ctx->reflect) {
		for (i = 0; i < (ctx->size >> 1); i++) {
			if (((crc >> i) ^ (crc >> (ctx->size - 1 - i))) & 1) {
				crc ^= ((ut32) 1 << i) ^ ((ut32) 1 << (ctx->size - 1 - i));
			}
		}
	}

	*r = crc ^ ctx->xout;
}

R_CRC_CTX crc_presets[] = {
	{ 0xFFFFFFFF, 32, 1, 0x04C11DB7, 0xFFFFFFFF }, //CRC-32, test vector for "1234567892: cbf43926
	{ 0x0000    , 16, 1, 0x8005    , 0x0000 },     //CRC-16-IBM, test vector for "1234567892: bb3d
	{ 0x00000000, 32, 0, 0x80000011, 0x00000000 }, //CRC-32-ECMA-267 (EDC for DVD sectors), test vector for "1234567892: b27ce117
	{ 0xFFFFFFFF, 32, 1, 0x1EDC6F41, 0xFFFFFFFF }, //CRC-32C, test vector for "1234567892: e3069283
	{ 0xB704CE  , 24, 0, 0x864CFB  , 0x000000 },   //CRC-24, test vector for "1234567892: 21cf02
	{ 0xFFFF    , 16, 0, 0x1021    , 0x0000 },     //CRC-16-CITT, test vector for "1234567892: 29b1
	{ 0xFFFF    , 16, 1, 0x8005    , 0xFFFF },     //CRC-16-USB, test vector for "1234567892:  b4c8
	{ 0xFFFF    , 16, 1, 0x1021    , 0xFFFF },     //CRC-HDLC, test vector for "1234567892: 906e
	{ 0x0000    , 15, 0, 0x4599    , 0x0000 },     //CRC-15-CAN, test vector for "1234567892: 059e
	{ 0x00      ,  8, 0, 0x07      , 0x00 },       //CRC-8-SMBUS, test vector for "1234567892: f4
};

void crc_init_preset (R_CRC_CTX *ctx, enum CRC_PRESETS preset) {
	ctx->crc = crc_presets[preset].crc;
	ctx->size = crc_presets[preset].size;
	ctx->reflect = crc_presets[preset].reflect;
	ctx->poly = crc_presets[preset].poly;
	ctx->xout = crc_presets[preset].xout;
}

ut32 r_hash_crc_preset (const ut8 *data, ut32 size, enum CRC_PRESETS preset) {
	if (!data || !size || preset >= CRC_PRESET_SIZE) {
		return 0;
	}
	ut32 r;
	R_CRC_CTX crc32;
	crc_init_preset (&crc32, preset);
	crc_update (&crc32, data, size);
	crc_final (&crc32, &r);
	return r;
}



