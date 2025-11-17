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
	} else if (!strcmp (key, "function") || !strcmp (key, "fcn")) {
		const char *fcnName = "";
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
		if (fcn) {
			fcnName = fcn->name;
		}
		return strdup (fcnName);
	} else if (!strcmp (key, "addr") || !strcmp (key, "address")) {
		const char *fmt_addr = (core->print->wide_offsets && R_SYS_BITS_CHECK (core->dbg->bits, 64))
			? "0x%016" PFMT64x
			: "0x%08" PFMT64x;
		return r_str_newf (fmt_addr, core->addr);
	} else if (!strcmp (key, "cwd")) {
		return r_sys_getdir ();
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

static char *r_core_prompt_format_apply(RCore *core, const char *fmt) {
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
		} else {
			r_strbuf_append_n (sb, p, 1);
			p++;
		}
	}
	char *res = r_strbuf_drain (sb);
	r_str_trim (res);
	return res;
}
