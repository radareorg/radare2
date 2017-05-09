/* radare - LGPL - Copyright 2009-2015 - pancake, nibble */
#include <stddef.h>

#include "r_cons.h"
#include "r_core.h"
#include "r_hash.h"
#include "r_types_base.h"

typedef void (*HashHandler)(const ut8 *block, int len);

static void handle_md4 (const ut8 *block, int len);
static void handle_md5 (const ut8 *block, int len);
static void handle_sha1 (const ut8 *block, int len);
static void handle_sha256 (const ut8 *block, int len);
static void handle_sha512 (const ut8 *block, int len);
static void handle_adler32 (const ut8 *block, int len);
static void handle_xor (const ut8 *block, int len);
static void handle_entropy (const ut8 *block, int len);
static void handle_hamdist (const ut8 *block, int len);
static void handle_parity (const ut8 *block, int len);
static void handle_pcprint (const ut8 *input, int len);
static void handle_mod255 (const ut8 *input, int len);
static void handle_luhn (const ut8 *input, int len);
static void handle_crc8_smbus (const ut8 *block, int len);
static void handle_crc15_can (const ut8 *block, int len);
static void handle_crc16 (const ut8 *block, int len);
static void handle_crc16_hdlc (const ut8 *block, int len);
static void handle_crc16_usb (const ut8 *block, int len);
static void handle_crc16_citt (const ut8 *block, int len);
static void handle_crc24 (const ut8 *block, int len);
static void handle_crc32 (const ut8 *block, int len);
static void handle_crc32c (const ut8 *block, int len);
static void handle_crc32_ecma_267 (const ut8 *block, int len);

typedef struct {
	const char *name;
	HashHandler handler;
} RHashHashHandlers;

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
	{"crc15can", handle_crc15_can},
	{"crc16", handle_crc16},
	{"crc16hdlc", handle_crc16_hdlc},
	{"crc16usb", handle_crc16_usb},
	{"crc16citt", handle_crc16_citt},
	{"crc24", handle_crc24},
	{"crc32", handle_crc32},
	{"crc32c", handle_crc32c},
	{"crc32ecma267", handle_crc32_ecma_267},
	{NULL, NULL},
};

static void handle_md4 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_MD4);
	const ut8 *c = r_hash_do_md4 (ctx, block, len);
	for (i=0; i<R_HASH_SIZE_MD4; i++) r_cons_printf ("%02x", c[i]);
	r_cons_newline ();
	r_hash_free (ctx);
}

static void handle_md5 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_MD5);
	const ut8 *c = r_hash_do_md5 (ctx, block, len);
	for (i=0; i<R_HASH_SIZE_MD5; i++) r_cons_printf ("%02x", c[i]);
	r_cons_newline ();
	r_hash_free (ctx);
}

static void handle_sha1 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_SHA1);
	const ut8 *c = r_hash_do_sha1 (ctx, block, len);
	for (i=0; i<R_HASH_SIZE_SHA1; i++) r_cons_printf ("%02x", c[i]);
	r_cons_newline ();
	r_hash_free (ctx);
}

static void handle_sha256 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	const ut8 *c = r_hash_do_sha256 (ctx, block, len);
	for (i=0; i<R_HASH_SIZE_SHA256; i++) r_cons_printf ("%02x", c[i]);
	r_cons_newline ();
	r_hash_free (ctx);
}

static void handle_sha512 (const ut8 *block, int len) {
	int i = 0;
	RHash *ctx = r_hash_new (true, R_HASH_SHA512);
	const ut8 *c = r_hash_do_sha512 (ctx, block, len);
	for (i = 0; i < R_HASH_SIZE_SHA512; i++) r_cons_printf ("%02x", c[i]);
	r_cons_newline ();
	r_hash_free (ctx);
}

static void handle_adler32 (const ut8 *block, int len) {
	ut32 hn = r_hash_adler32 (block, len);
	ut8 *b = (ut8*)&hn;
	r_cons_printf ("%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3]);
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
	r_cons_printf ("%d\n", r_hash_luhn (block, len));
}

static void handle_crc8_smbus (const ut8 *block, int len) {
	r_cons_printf ("%02x\n", r_hash_crc_preset (block, len, CRC_PRESET_8_SMBUS));
}

static void handle_crc15_can (const ut8 *block, int len) {
	r_cons_printf ("%04x\n", r_hash_crc_preset (block, len, CRC_PRESET_15_CAN));
}

static void handle_crc16 (const ut8 *block, int len) {
	r_cons_printf ("%04x\n", r_hash_crc_preset (block, len, CRC_PRESET_16));
}

static void handle_crc16_hdlc (const ut8 *block, int len) {
	r_cons_printf ("%04x\n", r_hash_crc_preset (block, len, CRC_PRESET_16_HDLC));
}

static void handle_crc16_usb (const ut8 *block, int len) {
	r_cons_printf ("%04x\n", r_hash_crc_preset (block, len, CRC_PRESET_16_USB));
}

static void handle_crc16_citt (const ut8 *block, int len) {
	r_cons_printf ("%04x\n", r_hash_crc_preset (block, len, CRC_PRESET_16_CITT));
}

static void handle_crc24 (const ut8 *block, int len) {
	r_cons_printf ("%06x\n", r_hash_crc_preset (block, len, CRC_PRESET_24));
}

static void handle_crc32 (const ut8 *block, int len) {
	r_cons_printf ("%08x\n", r_hash_crc_preset (block, len, CRC_PRESET_32));
}

static void handle_crc32c (const ut8 *block, int len) {
	r_cons_printf ("%08x\n", r_hash_crc_preset (block, len, CRC_PRESET_32C));
}

static void handle_crc32_ecma_267 (const ut8 *block, int len) {
	r_cons_printf ("%08x\n", r_hash_crc_preset (block, len, CRC_PRESET_32_ECMA_267));
}

static int cmd_hash_bang (RCore *core, const char *input) {
	char *p;
	const char *lang = input+1;
	if (r_sandbox_enable (0)) {
		eprintf ("hashbang disabled in sandbox mode\n");
		return false;
	}
	if (*lang=='/') {
		const char *ptr = lang+1;
		while (*lang) {
			if (*lang=='/')
				ptr = lang+1;
			lang++;
		}
		RLangPlugin *p = r_lang_get_by_extension (core->lang, ptr);
		if (p && p->name) lang = p->name;
	}
	if (*lang==' ') {
		RLangPlugin *p = r_lang_get_by_extension (core->lang, input+2);
		if (p && p->name) lang = p->name;
	} else if (input[1]=='?' || input[1]=='*' || input[1]=='\0') {
		r_lang_list (core->lang);
		return true;
	}
	p = strchr (input, ' ');
	bool doEval = false;
	if (p) {
		*p++ = 0;
		char *_e = strstr (p, "-e");
		if (_e) {
			doEval = true;
			p = _e + 2;
			p = r_str_chop (p);
		}
	}
	// TODO: set argv here
	if (r_lang_use (core->lang, lang)) {
		r_lang_setup (core->lang);
		if (p) {
			if (doEval) {
				r_lang_run_string (core->lang, p);
			} else {
				r_lang_run_file (core->lang, p);
			}
		} else {
			if (r_config_get_i (core->config, "scr.interactive")) {
				r_lang_prompt (core->lang);
			} else eprintf ("Error: scr.interactive required to run the rlang prompt\n");
		}
	} else {
		if (!p || *p==' ')
			eprintf ("Invalid hashbang. See '#!' for help.\n");
	}
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
