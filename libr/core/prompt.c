/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_core.h>

typedef struct {
	const char *key;
	const char *color;
} ColorSubst;

static const ColorSubst color_substs[] = {
	{ "RED", Color_RED },
	{ "GREEN", Color_GREEN },
	{ "BLUE", Color_BLUE },
	{ "YELLOW", Color_YELLOW },
	{ "CYAN", Color_CYAN },
	{ "MAGENTA", Color_MAGENTA },
	{ "RESET", Color_RESET },
	{ "BGRED", Color_BGRED },
	{ "BGGREEN", Color_BGGREEN },
	{ "BGBLUE", Color_BGBLUE },
	{ "BGYELLOW", Color_BGYELLOW },
	{ "BGCYAN", Color_BGCYAN },
	{ "BGMAGENTA", Color_BGMAGENTA },
	{ "BGRESET", Color_RESET_BG },
	{ NULL, NULL }
};

static int prompt_reloff_mask(RCore *core) {
	const char *relto = r_config_get (core->config, "asm.addr.relto");
	int mask = 0;
	if (!relto) {
		return 0;
	}
	mask |= strstr (relto, "fu")? RELOFF_TO_FUNC: 0;
	mask |= strstr (relto, "fl")? RELOFF_TO_FLAG: 0;
	mask |= strstr (relto, "ma")? RELOFF_TO_MAPS: 0;
	mask |= strstr (relto, "dm")? RELOFF_TO_DMAP: 0;
	mask |= strstr (relto, "se")? RELOFF_TO_SECT: 0;
	mask |= strstr (relto, "sy")? RELOFF_TO_SYMB: 0;
	mask |= strstr (relto, "fi")? RELOFF_TO_FILE: 0;
	mask |= strstr (relto, "fm")? RELOFF_TO_FMAP: 0;
	mask |= strstr (relto, "li")? RELOFF_TO_LIBS: 0;
	return mask;
}

static char *r_core_prompt_substitute(RCore *core, char *key) {
	size_t i;
	if (!strcmp (key, "RGB") || r_str_startswith (key, "RGB:")) {
		if (r_str_startswith (key, "RGB:")) {
			char *rgb_str = key + 4;
			int r, g, b;
			if (sscanf (rgb_str, "%d,%d,%d", &r, &g, &b) == 3) {
				if (r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
					return r_str_newf ("\x1b[38;2;%d;%d;%dm", r, g, b);
				}
			}
		}
		return NULL;
	} else if (!strcmp (key, "BGRGB") || r_str_startswith (key, "BGRGB:")) {
		if (r_str_startswith (key, "BGRGB:")) {
			char *rgb_str = key + 6;
			int r, g, b;
			if (sscanf (rgb_str, "%d,%d,%d", &r, &g, &b) == 3) {
				if (r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
					return r_str_newf ("\x1b[48;2;%d;%d;%dm", r, g, b);
				}
			}
		}
		return NULL;
	}
	for (i = 0; color_substs[i].key; i++) {
		if (!strcmp (key, color_substs[i].key)) {
			return strdup (color_substs[i].color);
		}
	}
	if (r_str_startswith (key, "pal:")) {
		const char *pal_name = key + 4;
		RColor rcolor = r_cons_pal_get (core->cons, pal_name);
		if (rcolor.id16 != -1) {
			return r_cons_rgb_str (core->cons, NULL, 0, &rcolor);
		}
		return NULL;
	}
	if (!strcmp (key, "filename") || !strcmp (key, "file")) {
		if (r_config_get_b (core->config, "scr.prompt.file")) {
			const char *fn = core->io->desc? r_file_basename (core->io->desc->name): "";
			return strdup (fn);
		} else {
			return strdup ("");
		}
	} else if (!strcmp (key, "prj")) {
		if (r_config_get_b (core->config, "scr.prompt.prj")) {
			const char *pn = r_config_get (core->config, "prj.name");
			return strdup (pn);
		} else {
			return strdup ("");
		}
	} else if (!strcmp (key, "rc")) {
		return r_str_newf ("%d", (int)(core->rc & UT32_MAX));
	} else if (!strcmp (key, "value")) {
		return r_str_newf ("%"PFMT64d, (st64)core->num->value);
	} else if (!strcmp (key, "remote")) {
		return core->cmdremote? strdup ("=!"): strdup ("");
	} else if (!strcmp (key, "section") || !strcmp (key, "sect")) {
		RBinObject *bo = r_bin_cur_object (core->bin);
		if (bo) {
			const RBinSection *sec = r_bin_get_section_at (bo, core->addr, true);
			if (sec) {
				return strdup (sec->name);
			}
		}
		return strdup ("");
	} else if (!strcmp (key, "flag")) {
		const RFlagItem *f = r_flag_get_at (core->flags, core->addr, true);
		if (f) {
			if (core->addr > f->addr) {
				return r_str_newf ("%s+0x%" PFMT64x, f->name, core->addr - f->addr);
			} else {
				return strdup (f->name);
			}
		} else {
			return strdup ("");
		}
	} else if (!strcmp (key, "fcn")) {
		const char *fcnName = "";
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
		if (fcn) {
			fcnName = fcn->name;
		}
		return strdup (fcnName);
	} else if (!strcmp (key, "vaddr")) {
		ut64 vaddr = core->addr;
		if (!r_config_get_b (core->config, "io.va") && core->io) {
			ut64 tmp = core->addr;
			if (r_io_p2v (core->io, core->addr, &tmp)) {
				vaddr = tmp;
			}
		}
		const char *fmt_addr = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
			? "0x%016" PFMT64x
			: "0x%08" PFMT64x;
		return r_str_newf (fmt_addr, vaddr);
	} else if (!strcmp (key, "addr") || !strcmp (key, "address")) {
		const char *fmt_addr = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
			? "0x%016" PFMT64x
			: "0x%08" PFMT64x;
		return r_str_newf (fmt_addr, core->addr);
	} else if (!strcmp (key, "paddr")) {

		ut64 paddr = r_io_v2p (core->io, core->addr);
		const char *fmt_addr = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
			? "0x%016" PFMT64x
			: "0x%08" PFMT64x;
		return r_str_newf (fmt_addr, paddr);
	} else if (r_str_startswith (key, "r:")) {
		const char *regname = key + 2;
		RRegItem *reg = r_reg_get (core->dbg->reg, regname, -1);
		if (reg) {
			ut64 val = r_reg_get_value (core->dbg->reg, reg);
			const char *fmt_addr = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
				? "0x%016" PFMT64x
				: "0x%08" PFMT64x;
			return r_str_newf (fmt_addr, val);
		}
		return strdup ("");
	} else if (!strcmp (key, "relto")) {
		int mask = prompt_reloff_mask (core);
		if (mask) {
			st64 delta = 0;
			char *label = r_core_get_reloff (core, mask, core->addr, &delta);
			if (label) {
				char *res = r_str_newf ("%s+0x%" PFMT64x, label, (ut64)delta);
				free (label);
				return res;
			}
		}
		return strdup ("");
	} else if (!strcmp (key, "cwdn")) {
		char *cwd = r_sys_getdir ();
		if (cwd) {
			char *cwdn = strdup (r_file_basename (cwd));
			free (cwd);
			return cwdn;
		}
		return NULL;
	} else if (!strcmp (key, "user") || !strcmp (key, "username")) {
		return r_sys_whoami ();
	} else if (!strcmp (key, "host") || !strcmp (key, "hostname")) {
		RSysInfo *si = r_sys_info ();
		if (si) {
			char *hostname = strdup (si->nodename);
			r_sys_info_free (si);
			return hostname;
		}
		return NULL;
	} else if (!strcmp (key, "time")) {
		char time_str[16] = { 0 };
		time_t now = time (NULL);
		struct tm *tm = localtime (&now);
		if (tm) {
			strftime (time_str, sizeof (time_str), "%H:%M", tm);
		}
		return strdup (time_str);
	} else if (!strcmp (key, "date")) {
		char date_str[16] = { 0 };
		time_t now = time (NULL);
		struct tm *tm = localtime (&now);
		if (tm) {
			strftime (date_str, sizeof (date_str), "%Y-%m-%d", tm);
		}
		return strdup (date_str);
	}
	return NULL;
}

static char *handle_dollar_case(RCore *core, RStrBuf *sb, const char **p_ptr) {
	const char *p = *p_ptr;
	if (p[1] == '(') {
		const char *end = strchr (p + 2, ')');
		if (!end) {
			return "Missing closing )";
		}
		char *cmd = r_str_ndup (p + 2, end - p - 2);
		if (cmd) {
			char *res = r_core_cmd_str (core, cmd);
			if (res) {
				r_strbuf_append (sb, res);
				free (res);
			}
			free (cmd);
		}
		*p_ptr = end + 1;
	} else if (p[1] == '{') {
		const char *end = strchr (p + 2, '}');
		if (!end) {
			return "Missing closing }";
		}
		char *key = r_str_ndup (p + 2, end - p - 2);
		if (key) {
			char *subst = r_core_prompt_substitute (core, key);
			if (subst) {
				r_strbuf_append (sb, subst);
				free (subst);
			} else {
				r_strbuf_appendf (sb, "${%s}", key);
			}
			free (key);
		}
		*p_ptr = end + 1;
	}
	return NULL;
}

R_API void r_core_prompt_format_help(RCore *core) {
	static RCoreHelpMessage help_msg = {
		"Usage: -e", "scr.prompt.format", "",
		"$", "(...)", "inline r2 command output",
		"$", "{COLOR}", "ANSI colors (e.g. ${RED})",
		"$", "{BGCOLOR}", "background ANSI colors (e.g. ${BGRED})",
		"$", "{pal:NAME}", "color from palette theme (see 'ec' command)",
		"", "\\s", "literal space (use to keep trailing spaces)",
		"$", "{RGB:r,g,b}", "RGB foreground color (0-255)",
		"$", "{BGRGB:r,g,b}", "RGB background color (0-255)",
		"$", "{addr}", "current virtual address (alias ${address}/${vaddr})",
		"$", "{cwd}", "current working directory",
		"$", "{cwdn}", "basename of the working directory",
		"$", "{date}", "current date",
		"$", "{e:var}", "value of an eval/config variable",
		"$", "{fcn}", "current function name (alias ${function})",
		"$", "{file}", "current file name (alias ${filename})",
		"$", "{flag}", "current flag name",
		"$", "{host}", "hostname (alias ${hostname})",
		"$", "{paddr}", "current physical address",
		"$", "{prj}", "project name",
		"$", "{r:REGNAME}", "value of the given register",
		"$", "{rc}", "return code from last command",
		"$", "{relto}", "relative address using asm.addr.relto",
		"$", "{remote}", "remote indicator",
		"$", "{sect}", "current section name (alias ${section})",
		"$", "{time}", "current time",
		"$", "{user}", "username (alias $(whoami))",
		"$", "{vaddr}", "current virtual address (converted when io.va is disabled)",
		"$", "{value}", "number from last math operation",
// 		"Example:", "scr.prompt.format = \"${GREEN}${filename}${RESET} [${addr}]> \"",
		NULL
	};
	r_core_cmd_help (core, help_msg);
}

R_API char *r_core_prompt_format(RCore *core, const char *fmt) {
	RStrBuf *sb = r_strbuf_new ("");
	const char *p = fmt;
	while (*p) {
		if (*p == '$') {
			if (p[1] == '(' || p[1] == '{') {
				char *err = handle_dollar_case (core, sb, &p);
				if (err) {
					R_LOG_WARN (err);
				}
			} else {
				r_strbuf_append_n (sb, p, 1);
				p++;
			}
		} else if (*p == '\\') {
			if (p[1] == 's') {
				r_strbuf_append_n (sb, " ", 1);
				p += 2;
				continue;
			}
			r_strbuf_append_n (sb, p, 1);
			p++;
		} else {
			r_strbuf_append_n (sb, p, 1);
			p++;
		}
	}
	char *res = r_strbuf_drain (sb);
	r_str_trim (res);
	return res;
}
