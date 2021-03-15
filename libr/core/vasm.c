/* radare - LGPL - Copyright 2009-2018 - pancake */

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
} RCoreVisualAsm;

static int readline_callback(void *_a, const char *str) {
	RCoreVisualAsm *a = _a;
	RCore *core = a->core;
	r_cons_clear00 ();
	r_cons_printf ("Write some %s-%" PFMT64d " assembly...\n\n",
		r_config_get (a->core->config, "asm.arch"),
		r_config_get_i (a->core->config, "asm.bits"));
	if (*str == '?') {
		r_cons_printf ("0> ?\n\n"
			"Visual assembler help:\n\n"
			"  assemble input while typing using asm.arch, asm.bits and cfg.bigendian\n"
			"  press enter to quit (prompt if there are bytes to be written)\n"
			"  this assembler supports various directives like .hex ...\n");
	} else {
		r_asm_code_free (a->acode);
		r_asm_set_pc (a->core->rasm, a->off);
		a->acode = r_asm_massemble (a->core->rasm, str);
		if (a->acode) {
			char* hex = r_asm_code_get_hex (a->acode);
			r_cons_printf ("[VA:%d]> %s\n", a->acode? a->acode->len: 0, str);
			if (a->acode && a->acode->len) {
				r_cons_printf ("* %s\n\n", hex);
			} else {
				r_cons_print ("\n\n");
			}
			int xlen = R_MIN (strlen (hex), R_VISUAL_ASM_BUFSIZE - 2);
			strcpy (a->codebuf, a->blockbuf);
			memcpy (a->codebuf, hex, xlen);
			if (xlen >= strlen (a->blockbuf)) {
				a->codebuf[xlen] = '\0';
			}
			free (hex);
		} else {
			r_cons_printf ("[VA:0]> %s\n* ?\n\n", str);
		}
		{
			int rows = 0;
			int cols = r_cons_get_size (&rows);
			core->print->cur_enabled = 1;
			core->print->ocur = 0;
			core->print->cur = (a->acode && a->acode->len) ? a->acode->len - 1: 0;
			char *cmd = r_str_newf ("pd %d @x:%s @0x%"PFMT64x, rows - 11, a->codebuf, a->off);
			char *res = r_core_cmd_str (a->core, cmd);
			char *msg = r_str_ansi_crop (res, 0,0, cols - 2, rows - 5);
			r_cons_printf ("%s\n", msg);
			free (msg);
			free (res);
			free (cmd);
		}
	}
	r_cons_flush ();
	return 1;
}

R_API void r_core_visual_asm(RCore *core, ut64 off) {
	RCoreVisualAsm cva = {
		.core = core,
		.off = off
	};
	r_io_read_at (core->io, off, cva.buf, sizeof (cva.buf));
	cva.blocklen = r_hex_bin2str (cva.buf, sizeof (cva.buf), cva.blockbuf);

	r_line_readline_cb (readline_callback, &cva);

	if (cva.acode && cva.acode->len > 0) {
		if (r_cons_yesno ('y', "Save changes? (Y/n)")) {
			if (!r_io_write_at (core->io, off, cva.acode->bytes, cva.acode->len)) {
				eprintf ("ERROR: Cannot write in here, check map permissions or reopen the file with oo+\n");
				r_cons_any_key (NULL);
			}
			// r_core_cmdf (core, "wx %s @ 0x%"PFMT64x, cva.acode->buf_hex, off);
		}
#if 0
	} else if (!cva.acode || cva.acode->len == 0) {
		eprintf ("ERROR: Cannot assemble those instructions\n");
//		r_cons_any_key (NULL);
#endif
	}
	r_asm_code_free (cva.acode);
}
