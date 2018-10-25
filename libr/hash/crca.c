//author: Victor Mu~noz (vmunoz@ingenieria-inversa.cl
//license: the very same than radare, blah, blah
//some definitions and test cases borrowed from http://www.nightmare.com/~ryb/code/CrcMoose.py (Ray Burr)

#include <r_hash.h>

void crc_init (R_CRC_CTX *ctx, utcrc crc, ut32 size, int reflect, utcrc poly, utcrc xout) {
	ctx->crc = crc;
	ctx->size = size;
	ctx->reflect = reflect;
	ctx->poly = poly;
	ctx->xout = xout;
}

void crc_update (R_CRC_CTX *ctx, const ut8 *data, ut32 sz) {
	utcrc crc, d;
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

static void crc_final (R_CRC_CTX *ctx, utcrc *r) {
	utcrc crc;
	int i;

	crc = ctx->crc;
	crc &= (((UTCRC_C(1) << (ctx->size - 1)) - 1) << 1) | 1;
	if (ctx->reflect) {
		for (i = 0; i < (ctx->size >> 1); i++) {
			if (((crc >> i) ^ (crc >> (ctx->size - 1 - i))) & 1) {
				crc ^= (UTCRC_C(1) << i) ^ (UTCRC_C(1) << (ctx->size - 1 - i));
			}
		}
	}

	*r = crc ^ ctx->xout;
}

/* preset initializer to provide compatibility */
#define CRC_PRESET(crc, size, reflect, poly, xout) \
	{ UTCRC_C(crc), (size), (reflect), UTCRC_C(poly), UTCRC_C(xout) }

/* NOTE: Run `rahash2 -a <algo> -s 123456789` to test CRC. */
R_CRC_CTX crc_presets[] = {
	CRC_PRESET (0x00      ,  8, 0, 0x07      , 0x00 ),       //CRC-8-SMBUS, test vector for "1234567892: f4
#if R_HAVE_CRC8_EXTRA
	CRC_PRESET (0xFF      ,  8, 0, 0x9B      , 0x00 ),       //CRC-8/CDMA2000,     test vector for "123456789": 0xda
	CRC_PRESET (0x00      ,  8, 1, 0x39      , 0x00 ),       //CRC-8/DARC,         test vector for "123456789": 0x15
	CRC_PRESET (0x00      ,  8, 0, 0xD5      , 0x00 ),       //CRC-8/DVB-S2,       test vector for "123456789": 0xbc
	CRC_PRESET (0xFF      ,  8, 1, 0x1D      , 0x00 ),       //CRC-8/EBU,          test vector for "123456789": 0x97
	CRC_PRESET (0xFD      ,  8, 0, 0x1D      , 0x00 ),       //CRC-8/I-CODE,       test vector for "123456789": 0x7e
	CRC_PRESET (0x00      ,  8, 0, 0x07      , 0x55 ),       //CRC-8/ITU,          test vector for "123456789": 0xa1
	CRC_PRESET (0x00      ,  8, 1, 0x31      , 0x00 ),       //CRC-8/MAXIM,        test vector for "123456789": 0xa1
	CRC_PRESET (0xFF      ,  8, 1, 0x07      , 0x00 ),       //CRC-8/ROHC,         test vector for "123456789": 0xd0
	CRC_PRESET (0x00      ,  8, 1, 0x9B      , 0x00 ),       //CRC-8/WCDMA,        test vector for "123456789": 0x25
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	CRC_PRESET (0x0000    , 15, 0, 0x4599    , 0x0000 ),     //CRC-15-CAN, test vector for "1234567892: 059e
#endif /* #if R_HAVE_CRC15_EXTRA */

	CRC_PRESET (0x0000    , 16, 1, 0x8005    , 0x0000 ),     //CRC-16-IBM (CRC-16/ARC), test vector for "1234567892: bb3d
	CRC_PRESET (0xFFFF    , 16, 0, 0x1021    , 0x0000 ),     //CRC-16-CITT (CRC-16/CCITT-FALSE), test vector for "1234567892: 29b1
	CRC_PRESET (0xFFFF    , 16, 1, 0x8005    , 0xFFFF ),     //CRC-16-USB, test vector for "1234567892:  b4c8
	CRC_PRESET (0xFFFF    , 16, 1, 0x1021    , 0xFFFF ),     //CRC-HDLC, test vector for "1234567892: 906e
#if R_HAVE_CRC16_EXTRA
	CRC_PRESET (0x1D0F    , 16, 0, 0x1021    , 0x0000 ),     //CRC-16/AUG-CCITT,   test vector for "123456789": 0xe5cc
	CRC_PRESET (0x0000    , 16, 0, 0x8005    , 0x0000 ),     //CRC-16/BUYPASS,     test vector for "123456789": 0xfee8
	CRC_PRESET (0xFFFF    , 16, 0, 0xC867    , 0x0000 ),     //CRC-16/CDMA2000,    test vector for "123456789": 0x4c06
	CRC_PRESET (0x800D    , 16, 0, 0x8005    , 0x0000 ),     //CRC-16/DDS110,      test vector for "123456789": 0x9ecf
	CRC_PRESET (0x0000    , 16, 0, 0x0589    , 0x0001 ),     //CRC-16/DECT-R,      test vector for "123456789": 0x007e
	CRC_PRESET (0x0000    , 16, 0, 0x0589    , 0x0000 ),     //CRC-16/DECT-X,      test vector for "123456789": 0x007f
	CRC_PRESET (0x0000    , 16, 1, 0x3D65    , 0xFFFF ),     //CRC-16/DNP,         test vector for "123456789": 0xea82
	CRC_PRESET (0x0000    , 16, 0, 0x3D65    , 0xFFFF ),     //CRC-16/EN-13757,    test vector for "123456789": 0xc2b7
	CRC_PRESET (0xFFFF    , 16, 0, 0x1021    , 0xFFFF ),     //CRC-16/GENIBUS,     test vector for "123456789": 0xd64e
	CRC_PRESET (0x0000    , 16, 1, 0x8005    , 0xFFFF ),     //CRC-16/MAXIM,       test vector for "123456789": 0x44c2
	CRC_PRESET (0xFFFF    , 16, 1, 0x1021    , 0x0000 ),     //CRC-16/MCRF4XX,     test vector for "123456789": 0x6f91
	CRC_PRESET (0xB2AA    , 16, 1, 0x1021    , 0x0000 ),     //CRC-16/RIELLO,      test vector for "123456789": 0x63d0
	CRC_PRESET (0x0000    , 16, 0, 0x8BB7    , 0x0000 ),     //CRC-16/T10-DIF,     test vector for "123456789": 0xd0db
	CRC_PRESET (0x0000    , 16, 0, 0xA097    , 0x0000 ),     //CRC-16/TELEDISK,    test vector for "123456789": 0x0fb3
	CRC_PRESET (0x89EC    , 16, 1, 0x1021    , 0x0000 ),     //CRC-16/TMS37157,    test vector for "123456789": 0x26b1
	CRC_PRESET (0xC6C6    , 16, 1, 0x1021    , 0x0000 ),     //CRC-A,              test vector for "123456789": 0xbf05
	CRC_PRESET (0x0000    , 16, 1, 0x1021    , 0x0000 ),     //CRC-16/KERMIT,      test vector for "123456789": 0x2189
	CRC_PRESET (0xFFFF    , 16, 1, 0x8005    , 0x0000 ),     //CRC-16/MODBUS,      test vector for "123456789": 0x4b37
	CRC_PRESET (0xFFFF    , 16, 1, 0x1021    , 0xFFFF ),     //CRC-16/X-25,        test vector for "123456789": 0x906e
	CRC_PRESET (0x0000    , 16, 0, 0x1021    , 0x0000 ),     //CRC-16/XMODEM,      test vector for "123456789": 0x31c3
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	CRC_PRESET (0xB704CE  , 24, 0, 0x864CFB  , 0x000000 ),   //CRC-24, test vector for "1234567892: 21cf02
#endif /* #if R_HAVE_CRC24 */

	CRC_PRESET (0xFFFFFFFF, 32, 1, 0x04C11DB7, 0xFFFFFFFF ), //CRC-32, test vector for "1234567892: cbf43926
	CRC_PRESET (0x00000000, 32, 0, 0x80000011, 0x00000000 ), //CRC-32-ECMA-267 (EDC for DVD sectors), test vector for "1234567892: b27ce117
	CRC_PRESET (0xFFFFFFFF, 32, 1, 0x1EDC6F41, 0xFFFFFFFF ), //CRC-32C, test vector for "1234567892: e3069283
#if R_HAVE_CRC32_EXTRA
	CRC_PRESET (0xFFFFFFFF, 32, 0, 0x04C11DB7, 0xFFFFFFFF ), //CRC-32/BZIP2,       test vector for "123456789": 0xfc891918
	CRC_PRESET (0xFFFFFFFF, 32, 1, 0xA833982B, 0xFFFFFFFF ), //CRC-32D,            test vector for "123456789": 0x87315576
	CRC_PRESET (0xFFFFFFFF, 32, 0, 0x04C11DB7, 0x00000000 ), //CRC-32/MPEG2,       test vector for "123456789": 0x0376e6e7
	CRC_PRESET (0x00000000, 32, 0, 0x04C11DB7, 0xFFFFFFFF ), //CRC-32/POSIX,       test vector for "123456789": 0x765e7680
	CRC_PRESET (0x00000000, 32, 0, 0x814141AB, 0x00000000 ), //CRC-32Q,            test vector for "123456789": 0x3010bf7f
	CRC_PRESET (0xFFFFFFFF, 32, 1, 0x04C11DB7, 0x00000000 ), //CRC-32/JAMCRC,      test vector for "123456789": 0x340bc6d9
	CRC_PRESET (0x00000000, 32, 0, 0x000000AF, 0x00000000 ), //CRC-32/XFER,        test vector for "123456789": 0xbd0be338
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	CRC_PRESET (0x0000000000000000, 64, 0, 0x42F0E1EBA9EA3693, 0x0000000000000000 ), //CRC-64, check: 0x6c40df5f0b497347
#endif /* #if R_HAVE_CRC64 */
#if R_HAVE_CRC64_EXTRA
	CRC_PRESET (0x0000000000000000, 64, 0, 0x42F0E1EBA9EA3693, 0x0000000000000000 ), //CRC-64/ECMA-182, check: 0x6c40df5f0b497347
	CRC_PRESET (0xFFFFFFFFFFFFFFFF, 64, 0, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF ), //CRC-64/WE, check: 0x62ec59e3f1a4f00a
	CRC_PRESET (0xFFFFFFFFFFFFFFFF, 64, 1, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF ), //CRC-64/XZ, check: 0x995dc9bbdf1939fa
	CRC_PRESET (0xFFFFFFFFFFFFFFFF, 64, 1, 0x000000000000001b, 0xFFFFFFFFFFFFFFFF ), //CRC-64/ISO, check: 0xb90956c775a41001
#endif /* #if R_HAVE_CRC64_EXTRA */
};

void crc_init_preset (R_CRC_CTX *ctx, enum CRC_PRESETS preset) {
	ctx->crc = crc_presets[preset].crc;
	ctx->size = crc_presets[preset].size;
	ctx->reflect = crc_presets[preset].reflect;
	ctx->poly = crc_presets[preset].poly;
	ctx->xout = crc_presets[preset].xout;
}

utcrc r_hash_crc_preset (const ut8 *data, ut32 size, enum CRC_PRESETS preset) {
	if (!data || !size || preset >= CRC_PRESET_SIZE) {
		return 0;
	}
	utcrc r;
	R_CRC_CTX crcctx;
	crc_init_preset (&crcctx, preset);
	crc_update (&crcctx, data, size);
	crc_final (&crcctx, &r);
	return r;
}



