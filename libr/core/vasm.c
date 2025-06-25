/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>

#define R_VISUAL_ASM_BUFSIZE 1024

typedef struct {
	RCore *core;
	char blockbuf[R_VISUAL_ASM_BUFSIZE];
	char codebuf[R_VISUAL_ASM_BUFSIZE];
	int oplen;
	ut8 buf[128];
	RAsmCode *acode;
	int blocklen;
	ut64 off;
	bool amode;
	char *otherstr;
} RCoreVisualAsm;

static int readline_callback(RCons *cons, void *_a, const char *str) {
	RCoreVisualAsm *a = _a;
	RCore *core = a->core;
	r_kons_clear00 (cons);
	r_kons_printf (cons, "Write %s-%" PFMT64d " %s... (! for %s, ^C to quit)\n\n",
		r_config_get (a->core->config, "asm.arch"),
		r_config_get_i (a->core->config, "asm.bits"),
		a->amode? "assembly": "hexpairs",
		a->amode? "hexpairs": "assembly"
		);
	r_asm_set_pc (a->core->rasm, a->off);
	RLine *line = cons->line;
	if (*str == '!') {
		a->amode = !a->amode;
		line->buffer.data[0] = 0;
		line->buffer.length = 0;
	} else if (r_str_endswith (str, "!")) {
		a->amode = !a->amode;
		strcpy (line->buffer.data, a->otherstr);
		line->buffer.length = strlen (a->otherstr);
		line->buffer.index = line->buffer.length;
	} else if (*str == '?') {
		r_cons_printf ("[VA]> ?\n\n"
			"Visual assembler help:\n\n"
			"  assemble input while typing using asm.arch, asm.bits and cfg.bigendian\n"
			"  press enter to quit (prompt if there are bytes to be written)\n"
			"  this assembler supports various directives like .hex ...\n"
			"!       toggle between hexpairs or assembly as input\n"
			"RETURN  write the bytes/assembly in place\n"
			"^C      leave this mode\n"
			);
	} else if (a->amode) {
		r_asm_code_free (a->acode);
		a->acode = r_asm_massemble (a->core->rasm, str);
	} else {
#if 0
		r_asm_code_free (a->acode);
		char *fmthex = r_str_newf (".hex %s", str);
		a->acode = r_asm_massemble (a->core->rasm, fmthex);
		free (fmthex);
#else
		ut8 out[1024];
		int len = r_hex_str2bin (str, out);
		if (len > 0) {
			free (a->acode->bytes);
			a->acode->bytes = r_mem_dup (out, len);
			a->acode->len = len;
		}
		a->codebuf[0] = 0;
#endif
	}
	const char *hex = (a->acode)? r_asm_code_get_hex (a->acode): "";
	r_cons_printf ("[%s:%d]> %s\n",
			a->amode? "ASM": "HEX",
			a->acode? a->acode->len: 0, str);
	if (a->acode) {
		int xlen = R_MIN ((2 * a->acode->len), R_VISUAL_ASM_BUFSIZE - 2);
		strcpy (a->codebuf, a->blockbuf);
		memcpy (a->codebuf, hex, xlen);
		if (xlen >= strlen (a->blockbuf)) {
			a->codebuf[xlen] = '\0';
		}
	}
	if (a->amode) {
		free (a->otherstr);
		a->otherstr = strdup (hex);
	} else {
		free (a->otherstr);
		a->otherstr = r_core_cmd_strf (a->core, "pad %s", hex);
		r_str_replace_char (a->otherstr, '\n', ';');
	}
	{
		int rows = 0;
		int cols = r_cons_get_size (core->cons, &rows);
		core->print->cur_enabled = true;
		core->print->ocur = 0;
		core->print->cur = (a->acode && a->acode->len) ? a->acode->len - 1: 0;
		char *res = r_core_cmd_strf (a->core, "pd %d @x:%s @0x%08"PFMT64x, rows - 11, a->codebuf, a->off);
		char *msg = r_str_ansi_crop (res, 0, 0, cols - 2, rows - 5);
		r_cons_printf ("%s\n", msg);
		free (msg);
		free (res);
	}
	r_cons_flush (core->cons);
	return 1;
}

R_API void r_core_visual_asm(RCore *core, ut64 off) {
	RCoreVisualAsm cva = {
		.core = core,
		.off = off,
		.amode = true
	};
	r_io_read_at (core->io, off, cva.buf, sizeof (cva.buf));
	cva.blocklen = r_hex_bin2str (cva.buf, sizeof (cva.buf), cva.blockbuf);

	r_line_readline_cb (core->cons, readline_callback, &cva);

	if (cva.acode && cva.acode->len > 0) {
		if (r_kons_yesno (core->cons, 'y', "Save changes? (Y/n)")) {
			if (!r_io_write_at (core->io, off, cva.acode->bytes, cva.acode->len)) {
				R_LOG_ERROR ("Cannot write in here, check map permissions or reopen the file with oo+");
				r_cons_any_key (core->cons, NULL);
			}
		}
	}
	r_asm_code_free (cva.acode);
}
