/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_core.h>

typedef struct {
	RCore *core;
	char blockbuf[1024];
	char codebuf[1024];
	int oplen;
	ut8 buf[128];
	RAsmCode *acode;
	int blocklen;
	ut64 off;
} RCoreVisualAsm;

static int readline_callback(void *_a, const char *str) {
	RCoreVisualAsm *a = _a;
	int xlen;
	r_cons_clear00 ();
	r_cons_printf ("Write your favourite %s-%d opcode...\n\n",
		r_config_get (a->core->config, "asm.arch"),
		r_config_get_i (a->core->config, "asm.bits"));
	if (*str == '?') {
		r_cons_printf ("0> ?\n\n"
			"Visual assembler help:\n\n"
			"  assemble input while typing using asm.arch, asm.bits and cfg.bigendian\n"
			"  press enter to quit (prompt if there are bytes to be written)\n"
			"  this assembler supports various directives like .hex ...\n"
			);
	} else {
		r_asm_code_free (a->acode);
		a->acode = r_asm_massemble (a->core->assembler, str);
		r_cons_printf ("%d> %s\n", a->acode? a->acode->len: 0, str);
		if (a->acode && a->acode->len)
			r_cons_printf ("* %s\n\n", a->acode->buf_hex);
		else r_cons_printf ("\n\n");
		if (a->acode) {
			xlen = strlen (a->acode->buf_hex);
			strcpy (a->codebuf, a->blockbuf);
			memcpy (a->codebuf, a->acode->buf_hex, xlen);
		}
		r_core_cmdf (a->core, "pd 7@b:%s @0x%"PFMT64x, a->codebuf, a->off);
	}
	r_cons_flush ();
	return 1;
}

R_API void r_core_visual_asm(RCore *core, ut64 off) {
	RCoreVisualAsm cva = {0};
	cva.core = core;
	cva.off = off;

	r_io_read_at (core->io, off, cva.buf, sizeof (cva.buf));
	cva.blocklen = r_hex_bin2str (cva.buf, sizeof (cva.buf), cva.blockbuf);

	r_line_readline_cb (readline_callback, &cva);

	if (cva.acode && cva.acode->len>0)
		if (r_cons_yesno ('y', "Save changes? (Y/n)"))
			r_core_cmdf (core, "wx %s @ 0x%"PFMT64x,
				cva.acode->buf_hex, off);
	r_asm_code_free (cva.acode);
}
