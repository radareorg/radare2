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
	RLine *line = cons->line;
	r_cons_clear00 (cons);
	r_cons_printf (cons, "Write %s-%" PFMT64d " %s... (! for %s, ^C to quit)\n\n",
		r_config_get (core->config, "asm.arch"),
		r_config_get_i (core->config, "asm.bits"),
		a->amode? "assembly": "hexpairs",
		a->amode? "hexpairs": "assembly");
	r_asm_set_pc (core->rasm, a->off);
	if (*str == '!') {
		a->amode = !a->amode;
		line->buffer.data[0] = 0;
		line->buffer.length = 0;
	} else if (r_str_endswith (str, "!")) {
		a->amode = !a->amode;
		const char *src = a->otherstr? a->otherstr: "";
		line->buffer.length = r_str_ncpy (line->buffer.data, src, sizeof (line->buffer.data));
		line->buffer.index = line->buffer.length;
	} else if (*str == '?') {
		r_cons_printf (core->cons, "[VA]> ?\n\n"
			"Visual assembler help:\n\n"
			"  assemble input while typing using asm.arch, asm.bits and cfg.bigendian\n"
			"  press enter to quit (prompt if there are bytes to be written)\n"
			"  this assembler supports various directives like .hex ...\n"
			"!       toggle between hexpairs or assembly as input\n"
			"RETURN  write the bytes/assembly in place\n"
			"^C      leave this mode\n");
	} else if (a->amode) {
		r_asm_code_free (a->acode);
		a->acode = r_asm_assemble (core->rasm, str);
	} else {
		ut8 out[1024];
		int len = r_hex_str2bin (str, out);
		if (len > 0 && a->acode) {
			free (a->acode->bytes);
			a->acode->bytes = r_mem_dup (out, len);
			a->acode->len = len;
		}
		a->codebuf[0] = 0;
	}
	const char *hex = a->acode? r_asm_code_get_hex (a->acode): "";
	r_cons_printf (core->cons, "[%s:%d]> %s\n",
		a->amode? "ASM": "HEX",
		a->acode? a->acode->len: 0, str);
	if (a->acode) {
		int xlen = R_MIN ((2 * a->acode->len), R_VISUAL_ASM_BUFSIZE - 2);
		r_str_ncpy (a->codebuf, a->blockbuf, R_VISUAL_ASM_BUFSIZE);
		memcpy (a->codebuf, hex, xlen);
		if (xlen >= strlen (a->blockbuf)) {
			a->codebuf[xlen] = '\0';
		}
	}
	free (a->otherstr);
	if (a->amode) {
		a->otherstr = strdup (hex);
	} else {
		a->otherstr = r_core_cmd_strf (core, "pad %s", hex);
		r_str_replace_char (a->otherstr, '\n', ';');
	}
	int rows = 0;
	int cols = r_cons_get_size (core->cons, &rows);
	core->print->cur_enabled = true;
	core->print->ocur = 0;
	core->print->cur = (a->acode && a->acode->len)? a->acode->len - 1: 0;
	char *res = r_core_cmd_strf (core, "pd %d @x:%s @0x%08"PFMT64x, rows - 11, a->codebuf, a->off);
	char *msg = r_str_ansi_crop (res, 0, 0, cols - 2, rows - 5);
	r_cons_println (core->cons, msg);
	free (msg);
	free (res);
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
		if (r_cons_yesno (core->cons, 'y', "Save changes? (Y/n)")) {
			if (!r_io_write_at (core->io, off, cva.acode->bytes, cva.acode->len)) {
				R_LOG_ERROR ("Cannot write in here, check map permissions or reopen the file with oo+");
				r_cons_any_key (core->cons, NULL);
			}
		}
	}
	r_asm_code_free (cva.acode);
}
