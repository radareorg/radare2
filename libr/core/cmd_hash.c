/* radare - LGPL - Copyright 2009-2020 - pancake, nibble */

#include <r_core.h>

typedef void (*HashHandler)(const ut8 *block, int len);

typedef struct {
	const char *name;
	HashHandler handler;
} RHashHashHandlers;

static inline void hexprint(const ut8 *data, int len) {
	int i = 0;
	for (i = 0; i < len; i++) {
		r_cons_printf ("%02x", data[i]);
	}
	r_cons_newline ();
}

static void handle_md4 (const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_MD4);
	const ut8 *c = r_hash_do_md4 (ctx, block, len);
	hexprint (c, R_HASH_SIZE_MD4);
	r_hash_free (ctx);
}

static void handle_md5 (const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_MD5);
	const ut8 *c = r_hash_do_md5 (ctx, block, len);
	hexprint (c, R_HASH_SIZE_MD5);
	r_hash_free (ctx);
}

static void handle_sha1 (const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA1);
	const ut8 *c = r_hash_do_sha1 (ctx, block, len);
	hexprint (c, R_HASH_SIZE_SHA1);
	r_hash_free (ctx);
}

static void handle_sha256 (const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	hexprint (c, R_HASH_SIZE_SHA256);
	r_hash_free (ctx);
}

static void handle_sha512 (const ut8 *block, int len) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA512);
	const ut8 *c = r_hash_do_sha512 (ctx, block, len);
	hexprint (c, R_HASH_SIZE_SHA512);
	r_hash_free (ctx);
}

static void handle_adler32 (const ut8 *block, int len) {
	ut32 hn = r_hash_adler32 (block, len);
	hexprint ((ut8 *)&hn, sizeof (ut32));
}

static void handle_xor (const ut8 *block, int len) {
	r_cons_printf ("%02x\n", r_hash_xor (block, len));
}

static void handle_entropy (const ut8 *block, int len) {
	r_cons_printf ("%f\n", r_hash_entropy (block, len));
}

static void handle_parity (const ut8 *block, int len) {
	r_cons_printf ("%d\n", r_hash_parity (block, len)?1:0);
}

static void handle_hamdist (const ut8 *block, int len) {
	r_cons_printf ("%02x\n", r_hash_hamdist (block, len));
}

static void handle_pcprint (const ut8 *block, int len) {
	r_cons_printf ("%d\n", r_hash_pcprint (block, len));
	//r_cons_printf ("%02x\n", r_hash_pcprint (block, len));
}

static void handle_mod255 (const ut8 *block, int len) {
	r_cons_printf ("%d\n", r_hash_mod255 (block, len));
	//r_cons_printf ("%02x\n", r_hash_pcprint (block, len));
}

static void handle_luhn (const ut8 *block, int len) {
	r_cons_printf ("%" PFMT64u "\n", r_hash_luhn (block, len));
}

static void handle_crc8_smbus (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_8_SMBUS));
}

#if R_HAVE_CRC8_EXTRA
static void handle_crc8_cdma2000 (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_CDMA2000));
}

static void handle_crc8_darc (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_DARC));
}

static void handle_crc8_dvb_s2 (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_DVB_S2));
}

static void handle_crc8_ebu (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_EBU));
}

static void handle_crc8_icode (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_ICODE));
}

static void handle_crc8_itu (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_ITU));
}

static void handle_crc8_maxim (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_MAXIM));
}

static void handle_crc8_rohc (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_ROHC));
}

static void handle_crc8_wcdma (const ut8 *block, int len) {
	r_cons_printf ("%02" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC8_WCDMA));
}
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
static void handle_crc15_can (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_15_CAN));
}
#endif /* #if R_HAVE_CRC15_EXTRA */

static void handle_crc16 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_16));
}

static void handle_crc16_hdlc (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_16_HDLC));
}

static void handle_crc16_usb (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_16_USB));
}

static void handle_crc16_citt (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_16_CITT));
}

#if R_HAVE_CRC16_EXTRA
static void handle_crc16_aug_ccitt (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_AUG_CCITT));
}

static void handle_crc16_buypass (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_BUYPASS));
}

static void handle_crc16_cdma2000 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_CDMA2000));
}

static void handle_crc16_dds110 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_DDS110));
}

static void handle_crc16_dect_r (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_DECT_R));
}

static void handle_crc16_dect_x (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_DECT_X));
}

static void handle_crc16_dnp (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_DNP));
}

static void handle_crc16_en13757 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_EN13757));
}

static void handle_crc16_genibus (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_GENIBUS));
}

static void handle_crc16_maxim (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_MAXIM));
}

static void handle_crc16_mcrf4xx (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_MCRF4XX));
}

static void handle_crc16_riello (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_RIELLO));
}

static void handle_crc16_t10dif (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_T10_DIF));
}

static void handle_crc16_teledisk (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_TELEDISK));
}

static void handle_crc16_tms37157 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_TMS37157));
}

static void handle_crca (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRCA));
}

static void handle_crc16_kermit (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_KERMIT));
}

static void handle_crc16_modbus (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_MODBUS));
}

static void handle_crc16_x25 (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_X25));
}

static void handle_crc16_xmodem (const ut8 *block, int len) {
	r_cons_printf ("%04" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC16_XMODEM));
}
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
static void handle_crc24 (const ut8 *block, int len) {
	r_cons_printf ("%06" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_24));
}
#endif /* #if R_HAVE_CRC24 */

static void handle_crc32 (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_32));
}

static void handle_crc32c (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_32C));
}

static void handle_crc32_ecma_267 (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_32_ECMA_267));
}

#if R_HAVE_CRC32_EXTRA
static void handle_crc32_bzip2 (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32_BZIP2));
}

static void handle_crc32d (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32D));
}

static void handle_crc32_mpeg2 (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32_MPEG2));
}

static void handle_crc32_posix (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32_POSIX));
}

static void handle_crc32q (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32Q));
}

static void handle_crc32_jamcrc (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32_JAMCRC));
}

static void handle_crc32_xfer (const ut8 *block, int len) {
	r_cons_printf ("%08" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC32_XFER));
}
#endif /* #ifR_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
static void handle_crc64 (const ut8 * block, int len) {
	r_cons_printf ("%016" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC64));
}
#endif /* #if R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
static void handle_crc64_ecma182 (const ut8 * block, int len) {
	r_cons_printf ("%016" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC64_ECMA182));
}

static void handle_crc64_we (const ut8 * block, int len) {
	r_cons_printf ("%016" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC64_WE));
}

static void handle_crc64_xz (const ut8 * block, int len) {
	r_cons_printf ("%016" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC64_XZ));
}

static void handle_crc64_iso (const ut8 * block, int len) {
	r_cons_printf ("%016" PFMTCRCx "\n", r_hash_crc_preset (block, len, CRC_PRESET_CRC64_ISO));
}
#endif /* #if R_HAVE_CRC64_EXTRA */

static int cmd_hash_bang (RCore *core, const char *input) {
	if (r_sandbox_enable (0)) {
		eprintf ("hashbang disabled in sandbox mode\n");
		return false;
	}
	int ac;
	char **av = r_str_argv (input + 1, &ac);
	if (ac > 0) {
		RLangPlugin *p = r_lang_get_by_name (core->lang, av[0]);
		if (p) {
			// I see no point in using r_lang_use here, as we already haz a ptr to the pluging in our handz
			// Maybe add r_lang_use_plugin in r_lang api?
			core->lang->cur = p;
			if (ac > 1) {
				if (!strcmp (av[1], "-e")) {
					char *run_str = strstr (input + 2, "-e") + 2;
					r_lang_run_string (core->lang, run_str);
				} else {
					if (r_lang_set_argv (core->lang, ac - 1, &av[1])) {
						r_lang_run_file (core->lang, av[1]);
					} else {
						char *run_str = strstr (input + 2, av[1]);
						r_lang_run_file (core->lang, run_str);
					}
				}
			} else {
				if (r_cons_is_interactive ()) {
					r_lang_prompt (core->lang);
				} else {
					eprintf ("Error: scr.interactive required to run the rlang prompt\n");
				}
			}
		} else if (av[0][0] == '?' || av[0][0] == '*') {
			r_lang_list (core->lang);
		}
	} else {
		r_lang_list (core->lang);
	}
	r_str_argv_free (av);
	return true;
}

static int cmd_hash(void *data, const char *input) {
	RCore *core = (RCore *)data;

	if (*input == '!') {
		return cmd_hash_bang (core, input);
	}
	if (*input == '?') {
		const char *helpmsg3[] = {
		"Usage #!interpreter [<args>] [<file] [<<eof]","","",
		" #", "", "comment - do nothing",
		" #!","","list all available interpreters",
		" #!python","","run python commandline",
		" #!python"," foo.py","run foo.py python script (same as '. foo.py')",
		//" #!python <<EOF        get python code until 'EOF' mark\n"
		" #!python"," arg0 a1 <<q","set arg0 and arg1 and read until 'q'",
		NULL};
		r_core_cmd_help (core, helpmsg3);
		return false;
	}
	/* this is a comment - captain obvious
	   should not be reached, see r_core_cmd_subst() */
	return 0;
}

static RHashHashHandlers hash_handlers[] = {
	{"md4", handle_md4},
	{"md5", handle_md5},
	{"sha1", handle_sha1},
	{"sha256", handle_sha256},
	{"sha512", handle_sha512},
	{"adler32", handle_adler32},
	{"xor", handle_xor},
	{"entropy", handle_entropy},
	{"parity", handle_parity},
	{"hamdist", handle_hamdist},
	{"pcprint", handle_pcprint},
	{"mod255", handle_mod255},
	{"luhn", handle_luhn},

	{"crc8smbus", handle_crc8_smbus},
#if R_HAVE_CRC8_EXTRA
	{ /* CRC-8/CDMA2000     */ "crc8cdma2000", handle_crc8_cdma2000},
	{ /* CRC-8/DARC         */ "crc8darc", handle_crc8_darc},
	{ /* CRC-8/DVB-S2       */ "crc8dvbs2", handle_crc8_dvb_s2},
	{ /* CRC-8/EBU          */ "crc8ebu", handle_crc8_ebu},
	{ /* CRC-8/I-CODE       */ "crc8icode", handle_crc8_icode},
	{ /* CRC-8/ITU          */ "crc8itu", handle_crc8_itu},
	{ /* CRC-8/MAXIM        */ "crc8maxim", handle_crc8_maxim},
	{ /* CRC-8/ROHC         */ "crc8rohc", handle_crc8_rohc},
	{ /* CRC-8/WCDMA        */ "crc8wcdma", handle_crc8_wcdma},
#endif /* #if R_HAVE_CRC8_EXTRA */

#if R_HAVE_CRC15_EXTRA
	{"crc15can", handle_crc15_can},
#endif /* #if R_HAVE_CRC15_EXTRA */

	{"crc16", handle_crc16},
	{"crc16hdlc", handle_crc16_hdlc},
	{ /* CRC-16/USB         */ "crc16usb", handle_crc16_usb},
	{ /* CRC-16/CCITT-FALSE */ "crc16citt", handle_crc16_citt},
#if R_HAVE_CRC16_EXTRA
	{ /* CRC-16/AUG-CCITT   */ "crc16augccitt", handle_crc16_aug_ccitt },
	{ /* CRC-16/BUYPASS     */ "crc16buypass", handle_crc16_buypass },
	{ /* CRC-16/CDMA2000    */ "crc16cdma2000", handle_crc16_cdma2000 },
	{ /* CRC-16/DDS-110     */ "crc16dds110", handle_crc16_dds110 },
	{ /* CRC-16/RECT-R      */ "crc16dectr", handle_crc16_dect_r },
	{ /* CRC-16/RECT-X      */ "crc16dectx", handle_crc16_dect_x },
	{ /* CRC-16/DNP         */ "crc16dnp", handle_crc16_dnp },
	{ /* CRC-16/EN-13757    */ "crc16en13757", handle_crc16_en13757 },
	{ /* CRC-16/GENIBUS     */ "crc16genibus", handle_crc16_genibus },
	{ /* CRC-16/MAXIM       */ "crc16maxim", handle_crc16_maxim },
	{ /* CRC-16/MCRF4XX     */ "crc16mcrf4xx", handle_crc16_mcrf4xx },
	{ /* CRC-16/RIELLO      */ "crc16riello", handle_crc16_riello },
	{ /* CRC-16/T10-DIF     */ "crc16t10dif", handle_crc16_t10dif },
	{ /* CRC-16/TELEDISK    */ "crc16teledisk", handle_crc16_teledisk },
	{ /* CRC-16/TMS37157    */ "crc16tms37157", handle_crc16_tms37157 },
	{ /* CRC-A              */ "crca", handle_crca },
	{ /* CRC-16/KERMIT      */ "crc16kermit", handle_crc16_kermit },
	{ /* CRC-16/MODBUS      */ "crc16modbus", handle_crc16_modbus },
	{ /* CRC-16/X-25        */ "crc16x25", handle_crc16_x25 },
	{ /* CRC-16/XMODEM      */ "crc16xmodem", handle_crc16_xmodem },
#endif /* #if R_HAVE_CRC16_EXTRA */

#if R_HAVE_CRC24
	{"crc24", handle_crc24},
#endif /* #if R_HAVE_CRC24 */

	{"crc32", handle_crc32},
	{"crc32c", handle_crc32c},
	{"crc32ecma267", handle_crc32_ecma_267},
#if R_HAVE_CRC32_EXTRA
	{ /* CRC-32/BZIP2       */ "crc32bzip2", handle_crc32_bzip2 },
	{ /* CRC-32D            */ "crc32d", handle_crc32d },
	{ /* CRC-32/MPEG-2      */ "crc32mpeg2", handle_crc32_mpeg2 },
	{ /* CRC-32/POSIX       */ "crc32posix", handle_crc32_posix },
	{ /* CRC-32Q            */ "crc32q", handle_crc32q },
	{ /* CRC-32/JAMCRC      */ "crc32jamcrc", handle_crc32_jamcrc },
	{ /* CRC-32/XFER        */ "crc32xfer", handle_crc32_xfer },
#endif /* #if R_HAVE_CRC32_EXTRA */

#if R_HAVE_CRC64
	{ /* CRC-64             */ "crc64", handle_crc64 },
#endif /* #if R_HAVE_CRC64 */

#if R_HAVE_CRC64_EXTRA
	{ /* CRC-64/ECMA-182    */ "crc64ecma182", handle_crc64_ecma182 },
	{ /* CRC-64/WE          */ "crc64we", handle_crc64_we },
	{ /* CRC-64/XZ          */ "crc64xz", handle_crc64_xz },
	{ /* CRC-64/ISO         */ "crc64iso", handle_crc64_iso },
#endif /* #if R_HAVE_CRC64_EXTRA */

	{NULL, NULL},
};
