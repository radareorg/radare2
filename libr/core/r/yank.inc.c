/* radare - LGPL - Copyright 2009-2026 - pancake */

#if R_INCLUDE_BEGIN

// clang-format off

static RCoreHelpMessage help_msg_y = {
	"Usage:", "y[fptxy] [len] [[@]addr]", " # See wd? for memcpy, same as 'yf'.",
	"y!", "", "open cfg.editor to edit the clipboard",
	"y", " 16 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16 @ 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16", "copy 16 bytes into clipboard",
	"y", "", "show yank buffer information (origin len bytes)",
	"y*", "", "print in r2 commands what's been yanked",
	"y-", "", "empty / reset clipboard",
	"y8", "", "print contents of clipboard in hexpairs",
	"yf", " [L] [O] [file]", "copy [L] bytes from offset [O] of [file] into clipboard",
	"yfa", " [filepath]", "copy all bytes from file into clipboard",
	"yfx", " 10203040", "yank from hexpairs (same as ywx)",
	"yj", "", "print in JSON commands what's been yanked",
	"yl", "", "set $? to the clipboard length",
	"yp", " [pos]", "print contents of clipboard",
	"ys", " [pos]", "print contents of clipboard as string",
	"yt", " 64 0x200", "copy 64 bytes from current seek to 0x200",
	"ytf", " file", "dump the clipboard to given file",
	"yw", " hello world", "yank from string",
	"ywx", " 10203040", "yank from hexpairs (same as yfx)",
	"yx", " [pos]", "print contents of clipboard in hexadecimal",
	"yy", " 0x3344", "paste contents of clipboard to 0x3344",
	"yy", " @ 0x3344", "paste contents of clipboard to 0x3344",
	"yy", "", "paste contents of clipboard at current seek",
	"yz", " [len]", "copy nul-terminated string (up to blocksize) into clipboard",
	NULL
};

// clang-format on

static RCmdResult yank_status(bool ok) {
	return (RCmdResult) { .status = ok? 0: 1 };
}

static RCmdResult yank_usage(RCmdContext *ctx, const char *command) {
	r_cons_cmd_help_match (ctx->cons, help_msg_y, command, 0, true);
	return yank_status (false);
}

// Copy the clipboard from pos; NULL when empty or out of range
static ut8 *yank_bytes(RCore *core, ut64 pos, size_t *len) {
	const ut64 size = r_buf_size (core->yank_buf);
	if (!size) {
		R_LOG_ERROR ("No buffer yanked yet");
		return NULL;
	}
	if (pos >= size) {
		R_LOG_ERROR ("Position exceeds buffer length");
		return NULL;
	}
	*len = size - pos;
	ut8 *buf = malloc (*len + 1);
	if (buf) {
		r_buf_read_at (core->yank_buf, pos, buf, *len);
		buf[*len] = 0;
	}
	return buf;
}

// Arguments joined by spaces, keeping embedded NULs
static RStrBuf *yank_text(RCmdContext *ctx) {
	RStrBuf *sb = r_strbuf_new (NULL);
	if (ctx->raw) {
		r_strbuf_set (sb, r_str_trim_head_ro (ctx->subcmd.b));
		return sb;
	}
	const size_t argc = r_cmdctx_argc (ctx);
	size_t i;
	for (i = 0; i < argc; i++) {
		RStrs arg = r_cmdctx_arg (ctx, i);
		if (i) {
			r_strbuf_append_n (sb, " ", 1);
		}
		r_strbuf_append_n (sb, arg.a, r_strs_len (arg));
	}
	return sb;
}

static bool yank_hexpairs(RCore *core, const char *hex) {
	ut8 *bytes = malloc (strlen (hex) + 1);
	const int len = bytes? r_hex_str2bin (hex, bytes): -1;
	const bool ok = len > 0 && r_core_yank_set (core, core->addr, bytes, len);
	if (len <= 0) {
		R_LOG_ERROR ("Invalid hexpairs");
	}
	free (bytes);
	return ok;
}

static RCmdResult yank_dump(RCmdContext *ctx, char mode) {
	RCore *core = ctx->user;
	if (mode == 'j' && !r_buf_size (core->yank_buf)) {
		r_cons_println (ctx->cons, "{}");
		return yank_status (false);
	}
	size_t len = 0;
	ut8 *buf = yank_bytes (core, 0, &len);
	char *hex = buf? r_hex_bin2strdup (buf, len): NULL;
	free (buf);
	if (!hex) {
		return yank_status (false);
	}
	switch (mode) {
	case 'j': {
		PJ *pj = r_core_pj_new (core);
		pj_o (pj);
		pj_kn (pj, "addr", core->yank_addr);
		pj_ks (pj, "bytes", hex);
		pj_end (pj);
		r_cons_println (ctx->cons, pj_string (pj));
		pj_free (pj);
		break;
	}
	case '*':
		r_cons_printf (ctx->cons, "'wx %s\n", hex);
		break;
	case '8':
		r_cons_println (ctx->cons, hex);
		break;
	default:
		r_cons_printf (ctx->cons, "0x%08" PFMT64x " %" PFMT64u " %s\n", core->yank_addr, (ut64)len, hex);
		break;
	}
	free (hex);
	return yank_status (true);
}

static RCmdResult yank_print(RCmdContext *ctx, char mode) {
	RCore *core = ctx->user;
	ut64 pos = 0;
	if (!r_cmdctx_num (ctx, 0, core->num, &pos)) {
		return yank_status (false);
	}
	if (mode != 'x' && !r_buf_size (core->yank_buf)) {
		r_cons_newline (ctx->cons);
		return yank_status (false);
	}
	size_t len = 0;
	ut8 *buf = yank_bytes (core, pos, &len);
	if (!buf) {
		return yank_status (false);
	}
	if (mode == 'x') {
		RStrBuf *sb = r_strbuf_new (NULL);
		r_print_hexdump_strbuf (core->print, sb, pos, buf, len, 16, 1, 1);
		r_cons_print (ctx->cons, r_strbuf_get (sb));
		r_strbuf_free (sb);
	} else {
		r_cons_write (ctx->cons, (const char *)buf, mode == 's'? r_str_nlen ((const char *)buf, len): len);
		r_cons_newline (ctx->cons);
	}
	free (buf);
	return yank_status (true);
}

static RCmdResult yank_edit(RCmdContext *ctx) {
	RCore *core = ctx->user;
	size_t len = 0;
	ut8 *buf = r_buf_size (core->yank_buf)? yank_bytes (core, 0, &len): NULL;
	char *hex = buf? r_hex_bin2strdup (buf, len): strdup ("10203040");
	free (buf);
	char *data = r_core_editor (core, NULL, hex, NULL);
	free (hex);
	if (data) {
		r_str_trim (data);
	}
	const bool ok = data && yank_hexpairs (core, data);
	free (data);
	return yank_status (ok);
}

static RCmdResult yank_to_file(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (r_cmdctx_argc (ctx) != 1) {
		return yank_usage (ctx, "ytf");
	}
	const char *file = r_cmdctx_arg (ctx, 0).a;
	size_t len = 0;
	ut8 *buf = yank_bytes (core, 0, &len);
	if (!buf) {
		return yank_status (false);
	}
	bool ok = true;
	if (*file == '$') {
		r_cmd_alias_set_raw (core->rcmd, file + 1, buf, len, false);
	} else if (!r_file_dump (file, buf, len, false)) {
		R_LOG_ERROR ("Cannot dump to '%s'", file);
		ok = false;
	}
	free (buf);
	return yank_status (ok);
}

static RCmdResult yank_range(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 len = 0;
	ut64 addr = core->addr;
	if (r_cmdctx_argc (ctx) > 2) {
		return yank_usage (ctx, "y");
	}
	if (!r_cmdctx_num (ctx, 0, core->num, &len) || !r_cmdctx_num (ctx, 1, core->num, &addr)) {
		return yank_status (false);
	}
	return yank_status (r_core_yank (core, addr, (int)len));
}

static RCmdResult yank_to(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 len = 0;
	ut64 addr = 0;
	if (r_cmdctx_argc (ctx) != 2) {
		return yank_usage (ctx, "yt");
	}
	if (!r_cmdctx_num (ctx, 0, core->num, &len) || !r_cmdctx_num (ctx, 1, core->num, &addr)) {
		return yank_status (false);
	}
	if (!len || len > ST32_MAX) {
		R_LOG_ERROR ("Invalid yank length");
		return yank_status (false);
	}
	return yank_status (r_core_yank (core, core->addr, len) && r_core_yank_paste (core, addr, len));
}

static RCmdResult yank_file(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const size_t argc = r_cmdctx_argc (ctx);
	ut64 len = 0;
	ut64 offset = 0;
	if (!r_cmdctx_num (ctx, 0, core->num, &len) || !r_cmdctx_num (ctx, 1, core->num, &offset)) {
		return yank_status (false);
	}
	if (!len) {
		R_LOG_ERROR ("Number of bytes read must be > 0");
	} else if (argc < 2) {
		R_LOG_ERROR ("Address must be specified");
	} else if (argc < 3) {
		R_LOG_ERROR ("File must be specified");
	} else if (argc > 3) {
		return yank_usage (ctx, "yf");
	} else {
		return yank_status (r_core_yank_file (core, offset, len, r_cmdctx_arg (ctx, 2).a));
	}
	return yank_status (false);
}

static RCmdResult yank_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const RStrs sub = ctx->subcmd;
	const size_t argc = r_cmdctx_argc (ctx);
	ut64 n = 0;
	if (r_cmdctx_help (ctx)) {
		if (r_strs_len (sub) == 1) {
			r_cons_cmd_help (ctx->cons, help_msg_y);
		} else {
			char *command = r_str_newf ("y%.*s", (int)r_strs_len (sub) - 1, sub.a);
			r_cons_cmd_help_match (ctx->cons, help_msg_y, command, 0, false);
			free (command);
		}
		return yank_status (true);
	}
	if (r_strs_len (sub) > 1) {
		const bool hex = r_strs_equals_str (sub, "wx") || r_strs_equals_str (sub, "fx");
		if (hex || r_strs_equals_str (sub, "fa")) {
			if (argc < 1) {
				return yank_usage (ctx, hex? "ywx": "yfa");
			}
			RStrBuf *sb = yank_text (ctx);
			const char *text = r_strbuf_get (sb);
			const bool ok = hex? yank_hexpairs (core, text): r_core_yank_file (core, 0, UT64_MAX, text);
			r_strbuf_free (sb);
			return yank_status (ok);
		}
		if (r_strs_equals_str (sub, "tf")) {
			return yank_to_file (ctx);
		}
		r_core_return_invalid_command (core, "y", r_strs_at (sub, 0));
		return yank_status (false);
	}
	switch (r_strs_at (sub, 0)) {
	case '\0': // "y"
		return argc? yank_range (ctx): yank_dump (ctx, 0);
	case '*': // "y*"
	case 'j': // "yj"
	case '8': // "y8"
		return yank_dump (ctx, r_strs_at (sub, 0));
	case '-': // "y-"
		r_core_yank_unset (core);
		break;
	case 'l': // "yl"
		r_core_return_value (core, r_buf_size (core->yank_buf));
		break;
	case 'r': // "yr"
		R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2yara");
		return yank_status (false);
	case 'y': // "yy"
		n = core->addr;
		if (!r_cmdctx_num (ctx, 0, core->num, &n)) {
			return yank_status (false);
		}
		return yank_status (r_core_yank_paste (core, n, 0));
	case 'x': // "yx"
	case 'p': // "yp"
	case 's': // "ys"
		return yank_print (ctx, r_strs_at (sub, 0));
	case 'z': // "yz"
		if (!r_cmdctx_num (ctx, 0, core->num, &n)) {
			return yank_status (false);
		}
		return yank_status (r_core_yank_string (core, core->addr, (int)n));
	case 'w': { // "yw"
		if (!argc) {
			return yank_usage (ctx, "yw");
		}
		RStrBuf *sb = yank_text (ctx);
		const bool ok = r_core_yank_set (core, 0, (const ut8 *)r_strbuf_get (sb), r_strbuf_length (sb));
		r_strbuf_free (sb);
		return yank_status (ok);
	}
	case 't': // "yt"
		return yank_to (ctx);
	case 'f': // "yf"
		return yank_file (ctx);
	case '!': // "y!"
		return yank_edit (ctx);
	default:
		r_core_return_invalid_command (core, "y", r_strs_at (sub, 0));
		return yank_status (false);
	}
	return yank_status (true);
}

static bool r_core_cmd_yank_init(RCmd *cmd) {
	return r_cmd_register (cmd, "y", yank_callback, NULL);
}

#endif
