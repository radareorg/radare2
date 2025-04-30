/* radare - LGPL - Copyright 2013-2025 - pancake, sghctoma, xarkes */

#include <r_cons.h>
#include <r_th.h>

#define RCOLOR_AT(i) (RColor *) (((ut8 *) &(cons->context->cpal)) + keys[i].coff)
#define COLOR_AT(i) (char **) (((ut8 *) &(cons->context->pal)) + keys[i].off)
#define COLOR_KEY(name, field) { name, r_offsetof (RConsPrintablePalette, field), r_offsetof (RConsPalette, field) }

static R_TH_LOCAL RThreadLock *lock = NULL;

static struct {
	const char *name;
	int off; // RConsPrintablePalette offset
	int coff; // RConsPalette offset
} keys[] = {
	COLOR_KEY ("comment", comment),
	COLOR_KEY ("usrcmt", usercomment),
	COLOR_KEY ("args", args),
	COLOR_KEY ("fname", fname),
	COLOR_KEY ("floc", floc),
	COLOR_KEY ("fline", fline),
	COLOR_KEY ("flag", flag),
	COLOR_KEY ("label", label),
	COLOR_KEY ("help", help),
	COLOR_KEY ("flow", flow),
	COLOR_KEY ("flow2", flow2),
	COLOR_KEY ("prompt", prompt),
	COLOR_KEY ("bgprompt", bgprompt),
	COLOR_KEY ("addr", addr),
	COLOR_KEY ("input", input),
	COLOR_KEY ("invalid", invalid),
	COLOR_KEY ("other", other),
	COLOR_KEY ("b0x00", b0x00),
	COLOR_KEY ("b0x7f", b0x7f),
	COLOR_KEY ("b0xff", b0xff),
	COLOR_KEY ("math", math),
	COLOR_KEY ("bin", bin),
	COLOR_KEY ("btext", btext),
	COLOR_KEY ("push", push),
	COLOR_KEY ("pop", pop),
	COLOR_KEY ("crypto", crypto),
	COLOR_KEY ("jmp", jmp),
	COLOR_KEY ("cjmp", cjmp),
	COLOR_KEY ("call", call),
	COLOR_KEY ("nop", nop),
	COLOR_KEY ("ret", ret),
	COLOR_KEY ("trap", trap),
	COLOR_KEY ("ucall", ucall),
	COLOR_KEY ("ujmp", ujmp),
	COLOR_KEY ("swi", swi),
	COLOR_KEY ("cmp", cmp),
	COLOR_KEY ("reg", reg),
	COLOR_KEY ("creg", creg),
	COLOR_KEY ("num", num),
	COLOR_KEY ("mov", mov),
	COLOR_KEY ("var", var),
	COLOR_KEY ("var.name", var_name),
	COLOR_KEY ("var.type", var_type),
	COLOR_KEY ("var.addr", var_addr),
	COLOR_KEY ("widget.bg", widget_bg),
	COLOR_KEY ("widget.sel", widget_sel),
	COLOR_KEY ("ai.read", ai_read),
	COLOR_KEY ("ai.write", ai_write),
	COLOR_KEY ("ai.exec", ai_exec),
	COLOR_KEY ("ai.seq", ai_seq),
	COLOR_KEY ("ai.ascii", ai_ascii),
	COLOR_KEY ("graph.box", graph_box),
	COLOR_KEY ("graph.box2", graph_box2),
	COLOR_KEY ("graph.box3", graph_box3),
	COLOR_KEY ("graph.box4", graph_box4),
	COLOR_KEY ("graph.true", graph_true),
	COLOR_KEY ("graph.false", graph_false),
	COLOR_KEY ("graph.current", graph_current),
	COLOR_KEY ("graph.traced", graph_traced),

	// rename to diff, no need for graph prefix here
	{ "diff.unknown", r_offsetof (RConsPrintablePalette, diff_unknown), r_offsetof (RConsPalette, diff_unknown) },
	{ "diff.new", r_offsetof (RConsPrintablePalette, diff_new), r_offsetof (RConsPalette, diff_new) },
	{ "diff.match", r_offsetof (RConsPrintablePalette, diff_match), r_offsetof (RConsPalette, diff_match) },
	{ "diff.unmatch", r_offsetof (RConsPrintablePalette, diff_unmatch), r_offsetof (RConsPalette, diff_unmatch) },

	{ "gui.cflow", r_offsetof (RConsPrintablePalette, gui_cflow), r_offsetof (RConsPalette, gui_cflow) },
	{ "gui.dataoffset", r_offsetof (RConsPrintablePalette, gui_dataoffset), r_offsetof (RConsPalette, gui_dataoffset) },
	{ "gui.background", r_offsetof (RConsPrintablePalette, gui_background), r_offsetof (RConsPalette, gui_background) },
	{ "gui.background2", r_offsetof (RConsPrintablePalette, gui_background2), r_offsetof (RConsPalette, gui_background2) },
	{ "gui.border", r_offsetof (RConsPrintablePalette, gui_border), r_offsetof (RConsPalette, gui_border) },
	{ "wordhl", r_offsetof (RConsPrintablePalette, wordhl), r_offsetof (RConsPalette, wordhl) },
	{ "linehl", r_offsetof (RConsPrintablePalette, linehl), r_offsetof (RConsPalette, linehl) },


	{ NULL, 0, 0 }
};
static const int keys_len = sizeof (keys) / sizeof (keys[0]) - 1;

struct {
	const char *name;
	RColor rcolor;
	const char *code;
	const char *bgcode;
} colors[] = {
	{ "black",    RColor_BLACK,    Color_BLACK,    Color_BGBLACK },
	{ "red",      RColor_RED,      Color_RED,      Color_BGRED },
	{ "white",    RColor_WHITE,    Color_WHITE,    Color_BGWHITE },
	{ "green",    RColor_GREEN,    Color_GREEN,    Color_BGGREEN },
	{ "magenta",  RColor_MAGENTA,  Color_MAGENTA,  Color_BGMAGENTA },
	{ "yellow",   RColor_YELLOW,   Color_YELLOW,   Color_BGYELLOW },
	{ "orange",   RColor_ORANGE,   Color_ORANGE,   Color_BGORANGE },
	{ "cyan",     RColor_CYAN,     Color_CYAN,     Color_BGCYAN },
	{ "blue",     RColor_BLUE,     Color_BLUE,     Color_BGBLUE },
	{ "gray",     RColor_GRAY,     Color_GRAY,     Color_BGGRAY },
	{ "bblack",   RColor_BBLACK,   Color_BBLACK,   Color_BBGBLACK },
	{ "bred",     RColor_BRED,     Color_BRED,     Color_BBGRED },
	{ "bwhite",   RColor_BWHITE,   Color_BWHITE,   Color_BBGWHITE },
	{ "bgreen",   RColor_BGREEN,   Color_BGREEN,   Color_BBGGREEN },
	{ "bmagenta", RColor_BMAGENTA, Color_BMAGENTA, Color_BBGMAGENTA },
	{ "byellow",  RColor_BYELLOW,  Color_BYELLOW,  Color_BBGYELLOW },
	{ "bcyan",    RColor_BCYAN,    Color_BCYAN,    Color_BBGCYAN },
	{ "bblue",    RColor_BBLUE,    Color_BBLUE,    Color_BBGBLUE },
	{ "none",     RColor_NULL,     Color_RESET,    Color_RESET },
	{ NULL, RColor_NULL, NULL, NULL }
};

static inline ut8 rgbnum(const char ch1, const char ch2) {
	ut8 r = 0, r2 = 0;
	r_hex_to_byte (&r, ch1);
	r_hex_to_byte (&r2, ch2);
	return r << 4 | r2;
}

R_API void r_kons_pal_clone(RConsContext *ctx) {
	int i;
	/* Compute cons->pal values */
	for (i = 0; keys[i].name; i++) {
		char **color = (char **) (((ut8 *) &(ctx->pal)) + keys[i].off);
		if (*color) {
			*color = strdup (*color);
		}
	}
	if (ctx->pal.rainbow) {
		int sz = ctx->pal.rainbow_sz;
		for (i = 0; i < sz; i++) {
			if (ctx->pal.rainbow[i]) {
				ctx->pal.rainbow[i] = strdup (ctx->pal.rainbow[i]);
			}
		}
	}
}

static bool is_valid_color(RColor c) {
	if (c.r == 0 && c.g == 0 && c.b == 0) {
		// no black
		return false;
	}
	if (c.r == 255 && c.g == 255 && c.b == 255) {
		// no white
		return false;
	}
	return true;
}

static void pal_refresh(RCons *cons, bool rain) {
	// TODO: unnecessarily slow
	RConsContext *ctx = cons->context;
	Sdb *db = sdb_new0 ();
	int i;
	/* Compute cons->pal values */
	for (i = 0; keys[i].name; i++) {
		RColor *rcolor = (RColor *) (((ut8 *) &(ctx->cpal)) + keys[i].coff);
		char **color = (char **) (((ut8 *) &(ctx->pal)) + keys[i].off);
		// Color is dynamically allocated, needs to be freed
		R_FREE (*color);
		*color = r_cons_rgb_str_mode (ctx->color_mode, NULL, 0, rcolor);
		if (is_valid_color (*rcolor)) {
			r_strf_var (rgbstr, 16, "rgb:%02x%02x%02x", rcolor->r, rcolor->g, rcolor->b);
			// eprintf ("-> %s\n", rgbstr);
			sdb_set (db, rgbstr, "1", 0);
		}
	}
	if (rain) {
		SdbList *list = sdb_foreach_list (db, false);
		SdbListIter *iter;
		SdbKv *kv;
		r_cons_rainbow_free (cons);
		cons->context->pal.rainbow = calloc (sizeof (char *), list->length);
		r_cons_rainbow_new (cons, list->length); // alocated here
		int n = 0;
		if (ctx->pal.rainbow) {
			ls_foreach (list, iter, kv) {
				ctx->pal.rainbow[n++] = strdup (sdbkv_key (kv));
			}
		}
		ctx->pal.rainbow_sz = n;
		ls_free (list);
	}
	sdb_free (db);
}

R_API void r_cons_pal_init(RCons *cons) {
	RConsContext *ctx = cons->context;
	size_t i;
	if (!lock) {
		lock = r_th_lock_new (false);
	}
	r_th_lock_enter (lock);
	memset (&ctx->cpal, 0, sizeof (ctx->cpal));
	for (i = 0; keys[i].name; i++) {
		char **color = (char **) (((ut8 *) &(ctx->pal)) + keys[i].off);
		if (R_STR_ISNOTEMPTY (color)) {
			R_FREE (*color);
		}
	}

	ctx->cpal.b0x00         = (RColor) RColor_GREEN;
	ctx->cpal.b0x7f         = (RColor) RColor_CYAN;
	ctx->cpal.b0xff         = (RColor) RColor_RED;
	ctx->cpal.args          = (RColor) RColor_YELLOW;
	ctx->cpal.bin           = (RColor) RColor_YELLOW;
	ctx->cpal.btext         = (RColor) RColor_YELLOW;
	ctx->cpal.call          = (RColor) RColor_GREEN;
	ctx->cpal.call.attr     = R_CONS_ATTR_BOLD;
	ctx->cpal.ucall         = (RColor) RColor_GREEN;
	ctx->cpal.ujmp          = (RColor) RColor_GREEN;
	ctx->cpal.cjmp          = (RColor) RColor_GREEN;
	ctx->cpal.cmp           = (RColor) RColor_YELLOW;
	ctx->cpal.comment       = (RColor) RColor_RED;
	ctx->cpal.usercomment   = (RColor) RColor_WHITE;
	ctx->cpal.creg          = (RColor) RColor_CYAN;
	ctx->cpal.flag          = (RColor) RColor_CYAN;
	ctx->cpal.fline         = (RColor) RColor_CYAN;
	ctx->cpal.floc          = (RColor) RColor_CYAN;
	ctx->cpal.flow          = (RColor) RColor_CYAN;
	ctx->cpal.flow2         = (RColor) RColor_BLUE;
	ctx->cpal.fname         = (RColor) RColor_RED;
	ctx->cpal.help          = (RColor) RColor_GREEN;
	ctx->cpal.input         = (RColor) RColor_WHITE;
	ctx->cpal.invalid       = (RColor) RColor_RED;
	ctx->cpal.invalid.attr  = R_CONS_ATTR_BOLD;
	ctx->cpal.jmp           = (RColor) RColor_GREEN;
	ctx->cpal.label         = (RColor) RColor_CYAN;
	ctx->cpal.math          = (RColor) RColor_YELLOW;
	// ctx->cpal.mov           = (RColor) RColor_WHITE;
	ctx->cpal.mov           = (RColor) RColor_CYAN; // works on white and black terminals
	ctx->cpal.nop           = (RColor) RColor_BLUE;
	ctx->cpal.num           = (RColor) RColor_YELLOW;
	ctx->cpal.addr          = (RColor) RColor_GREEN;
	ctx->cpal.other         = (RColor) RColor_CYAN;
	ctx->cpal.pop           = (RColor) RColor_MAGENTA;
	// ctx->cpal.pop.attr      = R_CONS_ATTR_BOLD;
	ctx->cpal.prompt        = (RColor) RColor_YELLOW;
	ctx->cpal.bgprompt      = (RColor) RColor_NULL;
	ctx->cpal.push          = (RColor) RColor_MAGENTA;
	ctx->cpal.crypto        = (RColor) RColor_BGBLUE;
	ctx->cpal.reg           = (RColor) RColor_CYAN;
	ctx->cpal.ret           = (RColor) RColor_RED;
	ctx->cpal.swi           = (RColor) RColor_MAGENTA;
	ctx->cpal.trap          = (RColor) RColor_RED;
	ctx->cpal.trap.attr     = R_CONS_ATTR_BOLD;

	ctx->cpal.ai_read       = (RColor) RColor_GREEN;
	ctx->cpal.ai_write      = (RColor) RColor_BLUE;
	ctx->cpal.ai_exec       = (RColor) RColor_RED;
	ctx->cpal.ai_seq        = (RColor) RColor_MAGENTA;
	ctx->cpal.ai_ascii      = (RColor) RColor_YELLOW;

	ctx->cpal.gui_cflow          = (RColor) RColor_YELLOW;
	ctx->cpal.gui_dataoffset     = (RColor) RColor_YELLOW;
	ctx->cpal.gui_background     = (RColor) RColor_BLACK;
	ctx->cpal.gui_background2    = (RColor) RColor_WHITE;
	ctx->cpal.gui_border    = (RColor) RColor_BLACK;
	ctx->cpal.wordhl        = (RColor) RColor_BGRED;
	// No good choice for fallback ansi16 color
#if R2__WINDOWS__
	ctx->cpal.linehl        = (RColor) RCOLOR (ALPHA_BG, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 4);
#else
	ctx->cpal.linehl        = (RColor) RCOLOR (ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4);
#endif

	ctx->cpal.var           = (RColor) RColor_WHITE;
	ctx->cpal.var_type      = (RColor) RColor_CYAN;
	ctx->cpal.var_name      = (RColor) RColor_YELLOW;
	ctx->cpal.var_addr      = (RColor) RColor_GREEN;

	ctx->cpal.widget_bg     = (RColor) RCOLOR (ALPHA_BG, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0);
	ctx->cpal.widget_sel    = (RColor) RColor_BGRED;

	ctx->cpal.graph_box     = (RColor) RColor_NULL;
	ctx->cpal.graph_box2    = (RColor) RColor_YELLOW;
	ctx->cpal.graph_box3    = (RColor) RColor_MAGENTA;
	ctx->cpal.graph_box4    = (RColor) RColor_GRAY;
	ctx->cpal.graph_true    = (RColor) RColor_GREEN;
	ctx->cpal.graph_false   = (RColor) RColor_RED;
	ctx->cpal.graph_trufae  = (RColor) RColor_CYAN; // single jump
	ctx->cpal.graph_traced  = (RColor) RColor_YELLOW;
	ctx->cpal.graph_current = (RColor) RColor_BLUE;
	ctx->cpal.diff_unknown  = (RColor) RColor_MAGENTA;
	ctx->cpal.diff_new      = (RColor) RColor_RED;
	ctx->cpal.diff_match    = (RColor) RColor_GRAY;
	ctx->cpal.diff_unmatch  = (RColor) RColor_YELLOW;
	ctx->pal.reset          = Color_RESET; // reset is not user accessible, const char* is ok
	pal_refresh (cons, false);
	r_th_lock_leave (lock);
}

R_API void r_cons_pal_free(RCons *cons) {
	size_t i;
	for (i = 0; keys[i].name; i++) {
		char **color = (char **) (((ut8 *) &(cons->context->pal)) + keys[i].off);
		if (R_STR_ISNOTEMPTY (color)) {
			R_FREE (*color);
		}
	}
	r_cons_rainbow_free (cons);
}

// rename to copy_from for clarity?
R_API void r_cons_pal_copy(RCons *cons, RConsContext *src) {
	RConsContext *dst = cons->context;
	memcpy (&dst->cpal, &src->cpal, sizeof (src->cpal));
	memset (&dst->pal, 0, sizeof (dst->pal));

	dst->pal.rainbow = NULL;
	dst->pal.rainbow_sz = 0;

	dst->pal.reset = Color_RESET; // reset is not user accessible, const char* is ok

	// pal_refresh (cons);
}

R_API void r_cons_pal_random(RCons *cons) {
	R_RETURN_IF_FAIL (cons);
	int i;
	for (i = 0; keys[i].name; i++) {
		RColor *rcolor = RCOLOR_AT (i);
		*rcolor = r_cons_color_random (ALPHA_FG);
	}
	r_cons_pal_reload (cons);
}

R_API char *r_cons_pal_parse(const char *str, R_NULLABLE RColor *outcol) {
	R_RETURN_VAL_IF_FAIL (str, NULL);
	RColor rcolor = (RColor) RColor_BLACK;
	rcolor.id16 = -1;
	char *attr = NULL;
	char out[128];
	char *fgcolor = strdup (str);
	if (!fgcolor) {
		return NULL;
	}
	bool ok = false;
	char *bgcolor = strchr (fgcolor + 1, ' ');
	out[0] = 0;
	if (bgcolor) {
		*bgcolor++ = '\0';
		attr = strchr (bgcolor, ' ');
		if (attr) {
			*attr++ = '\0';
		}
	}
	// Handle first color (fgcolor)
	if (!strcmp (fgcolor, "random")) {
		rcolor = r_cons_color_random (ALPHA_FG);
		r_cons_rgb_str (out, sizeof (out), &rcolor);
		ok = true;
	} else if (fgcolor[0] == '#') { // "#00ff00" HTML format
		if (strlen (fgcolor + 1) == 6) {
			const char *kule = fgcolor + 1;
			rcolor.r = rgbnum (kule[0], kule[1]);
			rcolor.g = rgbnum (kule[2], kule[3]);
			rcolor.b = rgbnum (kule[4], kule[5]);
			r_cons_rgb_str (out, sizeof (out), &rcolor);
			ok = true;
		} else {
			R_LOG_WARN ("Invalid html color code");
		}
	} else if (r_str_startswith (fgcolor, "rgb:")) { // "rgb:123" rgb format
		if (strlen (fgcolor + 4) == 3) { // "rgb:RGB"
			rcolor.r = rgbnum (fgcolor[4], '0');
			rcolor.g = rgbnum (fgcolor[5], '0');
			rcolor.b = rgbnum (fgcolor[6], '0');
			r_cons_rgb_str (out, sizeof (out), &rcolor);
			ok = true;
		} else if (strlen (fgcolor + 4) == 6) { // rgb:RRGGBB
			rcolor.r = rgbnum (fgcolor[4], fgcolor[5]);
			rcolor.g = rgbnum (fgcolor[6], fgcolor[7]);
			rcolor.b = rgbnum (fgcolor[8], fgcolor[9]);
			r_cons_rgb_str (out, sizeof (out), &rcolor);
			ok = true;
		}
	}
	// Handle second color (bgcolor)
	if (bgcolor && r_str_startswith (bgcolor, "rgb:")) { // "rgb:123" rgb format
		rcolor.a |= ALPHA_BG;
		if (strlen (bgcolor + 4) == 3) {
			rcolor.r2 = rgbnum (bgcolor[4], '0');
			rcolor.g2 = rgbnum (bgcolor[5], '0');
			rcolor.b2 = rgbnum (bgcolor[6], '0');
		} else if (strlen (bgcolor + 4) == 6) {
			rcolor.r2 = rgbnum (bgcolor[4], bgcolor[5]);
			rcolor.g2 = rgbnum (bgcolor[6], bgcolor[7]);
			rcolor.b2 = rgbnum (bgcolor[8], bgcolor[9]);
		}
		// if (!outcol) {
			size_t len = strlen (out);
			r_cons_rgb_str (out + len, sizeof (out) - len, &rcolor);
			ok = true;
		//}
	}
	// No suitable format, checking if colors are named
	int i;
	for (i = 0; colors[i].name; i++) {
		if (!strcmp (fgcolor, colors[i].name)) {
			ok = true;
			rcolor.r = colors[i].rcolor.r;
			rcolor.g = colors[i].rcolor.g;
			rcolor.b = colors[i].rcolor.b;
			rcolor.id16 = colors[i].rcolor.id16;
	//		if (!outcol) {
				size_t n = strlen (out);
				snprintf (out + n, sizeof (out) - n, "%s", colors[i].code);
	//		}
		}
		if (bgcolor && !strcmp (bgcolor, colors[i].name)) {
			ok = true;
			rcolor.a |= ALPHA_BG;
			rcolor.r2 = colors[i].rcolor.r; // Initial color doesn't
			rcolor.g2 = colors[i].rcolor.g; // have r2, g2, b2
			rcolor.b2 = colors[i].rcolor.b;
			rcolor.id16 = colors[i].rcolor.id16;
	//		if (!outcol) {
				size_t n = strlen (out);
				snprintf (out + n, sizeof (out) - n, "%s", colors[i].bgcode);
	//		}
		}
	}
	if (attr) {
		// Parse extra attributes.
		const char *p = attr;
		while (p) {
			if (r_str_startswith (p, "bold")) {
				rcolor.attr |= R_CONS_ATTR_BOLD;
			} else if (r_str_startswith (p, "dim")) {
				rcolor.attr |= R_CONS_ATTR_DIM;
			} else if (r_str_startswith (p, "italic")) {
				rcolor.attr |= R_CONS_ATTR_ITALIC;
			} else if (r_str_startswith (p, "underline")) {
				rcolor.attr |= R_CONS_ATTR_UNDERLINE;
			} else if (r_str_startswith (p, "blink")) {
				rcolor.attr |= R_CONS_ATTR_BLINK;
			} else {
				R_LOG_ERROR ("Failed to parse terminal attributes: %s", p);
				break;
			}
			ok = true;
			p = strchr (p, ' ');
			if (p) {
				p++;
			}
		}
	}
	if (outcol) {
		if (outcol->a == ALPHA_BG && !bgcolor) {
			rcolor.a = ALPHA_BG;
		}
		*outcol = rcolor;
	}
	free (fgcolor);
	if (!ok) {
		R_LOG_ERROR ("Invalid color code");
		return NULL;
	}
	return *out ? strdup (out) : strdup ("");
}

static void r_cons_pal_show_gs(RCons *cons) {
	int i, n;
	r_kons_print (cons, "\nGreyscale:\n");
	RColor rcolor = RColor_BLACK;
	for (i = 0x08, n = 0;  i <= 0xee; i += 0xa) {
		char fg[32], bg[32];
		rcolor.r = i;
		rcolor.g = i;
		rcolor.b = i;

		if (i < 0x76) {
			strcpy (fg, Color_WHITE);
		} else {
			strcpy (fg, Color_BLACK);
		}
		r_cons_rgb_str (bg, sizeof (bg), &rcolor);
		r_kons_printf (cons, "%s%s rgb:%02x%02x%02x "Color_RESET,
			fg, bg, i, i, i);
		if (n++ == 5) {
			n = 0;
			r_kons_newline (cons);
		}
	}
}

static void r_cons_pal_show_256(RCons *cons) {
	RColor rc = RColor_BLACK;
	r_kons_print (cons, "\n\nXTerm colors:\n");
	int r = 0;
	int g = 0;
	int b = 0;
	for (r = 0x00; r <= 0xff; r += 0x28) {
		rc.r = r;
		if (rc.r == 0x28) {
			rc.r = 0x5f;
		}
		for (b = 0x00; b <= 0xff; b += 0x28) {
			rc.b = b;
			if (rc.b == 0x28) {
				rc.b = 0x5f;
			}
			for (g = 0x00; g <= 0xff; g += 0x28) {
				rc.g = g;
				char bg[32];
				if (rc.g == 0x28) {
					rc.g = 0x5f;
				}
				const char *fg = ((rc.r <= 0x5f) && (rc.g <= 0x5f)) ? Color_WHITE: Color_BLACK;
				r_cons_rgb_str (bg, sizeof (bg), &rc);
				r_kons_printf (cons, "%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, rc.r, rc.g, rc.b);
			}
			r_kons_newline (cons);
		}
	}
}

static void r_cons_pal_show_rgb(RCons *cons) {
	const int inc = 3;
	int i, j, k, n = 0;
	RColor rc = RColor_BLACK;
	r_cons_print ("\n\nRGB:\n");
	for (i = n = 0; i <= 0xf; i += inc) {
		for (k = 0; k <= 0xf; k += inc) {
			for (j = 0; j <= 0xf; j += inc) {
				char fg[32], bg[32];
				rc.r = i * 16;
				rc.g = j * 16;
				rc.b = k * 16;
				strcpy (fg, ((i < 6) && (j < 5))
					? Color_WHITE: Color_BLACK);
				r_cons_rgb_str (bg, sizeof (bg), &rc);
				r_cons_printf ("%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, rc.r, rc.g, rc.b);
				if (n ++== 5) {
					n = 0;
					r_cons_newline ();
				}
			}
		}
	}
}

R_API void r_cons_pal_show(RCons *cons) {
	size_t i;
	for (i = 0; colors[i].name; i++) {
		r_cons_printf ("%s%s__"Color_RESET" %s\n",
			colors[i].code,
			colors[i].bgcode,
			colors[i].name);
	}
	switch (cons->context->color_mode) {
	case COLOR_MODE_256: // 256 color palette
		r_cons_pal_show_gs (cons);
		r_cons_pal_show_256 (cons);
		break;
	case COLOR_MODE_16M: // 16M (truecolor)
		r_cons_pal_show_gs (cons);
		r_cons_pal_show_rgb (cons);
		break;
	default:
		break;
	}
}

typedef struct {
	int val;
	const char *str;
} RAttrStr;

R_API void r_cons_pal_list(RCons *cons, int rad, const char *arg) {
	char *name, **color;
	const char *hasnext;
	int i;
	PJ *pj = NULL;
	if (rad == 'j') {
		pj = pj_new ();
		pj_o (pj);
	}
	for (i = 0; keys[i].name; i++) {
		RColor *rcolor = RCOLOR_AT (i);
		color = COLOR_AT (i);
		switch (rad) {
		case 'j':
			pj_k (pj, keys[i].name);
			pj_a (pj);
			pj_n (pj, rcolor->r);
			pj_n (pj, rcolor->g);
			pj_n (pj, rcolor->b);
			pj_end (pj);
			break;
		case 'c': {
			const char *prefix = r_str_trim_head_ro (arg);
			if (!prefix) {
				prefix = "";
			}
			hasnext = (keys[i + 1].name) ? "\n" : "";
			// TODO Need to replace the '.' char because this is not valid CSS
			char *sname = strdup (keys[i].name);
			int j, len = strlen (sname);
			for (j = 0; j < len; j++) {
				if (sname[j] == '.') {
					sname[j] = '_';
				}
			}
			r_kons_printf (cons, ".%s%s { color: rgb(%d, %d, %d); }%s",
				prefix, sname, rcolor->r, rcolor->g, rcolor->b, hasnext);
			free (sname);
			}
			break;
		case 'h':
			name = strdup (keys[i].name);
			r_str_replace_char (name, '.', '_');
			r_kons_printf (cons, ".%s { color:#%02x%02x%02x }\n",
				name, rcolor->r, rcolor->g, rcolor->b);
			free (name);
			break;
		case '*':
		case 'r':
		case 1:
			r_kons_printf (cons, "ec %s rgb:%02x%02x%02x",
				keys[i].name, rcolor->r, rcolor->g, rcolor->b);
			if (rcolor->a == ALPHA_FGBG) {
				r_kons_printf (cons, " rgb:%02x%02x%02x",
					rcolor->r2, rcolor->g2, rcolor->b2);
			}
			if (rcolor->attr) {
				const RAttrStr attrs[] = {
				    { R_CONS_ATTR_BOLD, "bold" },
				    { R_CONS_ATTR_DIM, "dim" },
				    { R_CONS_ATTR_ITALIC, "italic" },
				    { R_CONS_ATTR_UNDERLINE, "underline" },
				    { R_CONS_ATTR_BLINK, "blink" }
				};
				int j;
				if (rcolor->a != ALPHA_FGBG) {
					r_kons_print (cons, " .");
				}
				for (j = 0; j < R_ARRAY_SIZE (attrs); j++) {
					if (rcolor->attr & attrs[j].val) {
						r_kons_printf (cons, " %s", attrs[j].str);
					}
				}
			}
			r_kons_newline (cons);
			break;
		default:
			r_kons_printf (cons, " %s##"Color_RESET"  %s\n", *color, keys[i].name);
			break;
		}
	}
	if (rad == 'j' || pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_kons_println (cons, s);
		free (s);
	}
}

/* Modify the palette to set a color value.
 * r_cons_pal_reload () must be called after this function
 * so the changes take effect. */
R_API bool r_cons_pal_set(RCons *cons, const char *key, const char *val) {
	size_t i;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			RColor *rcolor = RCOLOR_AT (i);
			RColor rrcolor = *rcolor;
			char *res = r_cons_pal_parse (val, &rrcolor);
			if (res) {
				*rcolor = rrcolor;
				free (res);
				return true;
			}
			R_LOG_ERROR ("Parsing color fail %s", val);
			return false;
		}
	}
	R_LOG_ERROR ("Unknown color for %s", key);
	return false;
}

/* Get the named RColor */
R_API RColor r_cons_pal_get(RCons *cons, const char *key) {
	size_t i;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			RColor *rcolor = RCOLOR_AT (i);
			return rcolor? *rcolor: (RColor) RColor_NULL;
		}
	}
	return (RColor) RColor_NULL;
}

/* Get the RColor at specified index */
R_API RColor r_cons_pal_get_i(RCons *cons, int index) {
	if (index >= 0 && index < keys_len) {
		return *(RCOLOR_AT (index));
	}
	return *(RCOLOR_AT (0));
}

/* Get color name at index */
R_API const char *r_cons_pal_get_name(RCons *cons, int index) {
	return (index >= 0 && index < keys_len) ? keys[index].name : NULL;
}

R_API int r_cons_pal_len(void) {
	return keys_len;
}

R_API void r_cons_pal_reload(RCons *cons) {
	// This is slowly executed on every change of scr.color
	pal_refresh (cons, false);
}

R_API void r_cons_rainbow_new(RCons *cons, size_t sz) {
	if (sz < 1) {
		R_LOG_ERROR ("Negative rainbow");
	}
	cons->context->pal.rainbow_sz = sz;
	if (!cons->context->pal.rainbow) {
		cons->context->pal.rainbow = (char **)calloc (sizeof (char *), sz);
	}
	int i;
	for (i = 0; i < sz; i++) {
		cons->context->pal.rainbow[i] = NULL;
	}
}

R_API void r_cons_rainbow_free(RCons *cons) {
	int i, sz = cons->context->pal.rainbow_sz;
	if (sz > 0 && cons->context->pal.rainbow) {
		for (i = 0; i < sz; i++) {
			R_FREE (cons->context->pal.rainbow[i]);
		}
		R_FREE (cons->context->pal.rainbow);
	}
	cons->context->pal.rainbow_sz = 0;
}

R_API char *r_cons_rainbow_get(RCons *cons, int idx, int last, bool bg) {
	if (!cons->context->pal.rainbow) {
		pal_refresh (cons, true);
	}
	if (last < 0) {
		last = cons->context->pal.rainbow_sz;
	}
	if (idx < 0 || idx >= last || !cons->context->pal.rainbow) {
		return NULL;
	}
	int x = (last == cons->context->pal.rainbow_sz)
		? idx : (cons->context->pal.rainbow_sz * idx) / (last + 1);
	const char *a = cons->context->pal.rainbow[x];
	if (bg) {
		char *dup = r_str_newf ("%s %s", a, a);
		char *res = r_cons_pal_parse (dup, NULL);
		free (dup);
		return res;
	}
// eprintf ("banana\n");dd
	return r_cons_pal_parse (a, NULL);
}
