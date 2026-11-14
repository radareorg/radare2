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

// Output mode is the registered name suffix: "y*" -> '*', "y" -> 0
static char yank_mode(RCmdContext *ctx) {
	const RCmdRow *command = ctx->handler_user;
	return command->name[1];
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

static bool yank_dump(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char mode = yank_mode (ctx);
	if (mode == 'j' && !r_buf_size (core->yank_buf)) {
		r_cons_println (ctx->cons, "{}");
		return false;
	}
	size_t len = 0;
	ut8 *buf = yank_bytes (core, 0, &len);
	char *hex = buf? r_hex_bin2strdup (buf, len): NULL;
	free (buf);
	if (!hex) {
		return false;
	}
	if (mode == 'j') {
		PJ *pj = r_core_pj_new (core);
		pj_o (pj);
		pj_kn (pj, "addr", core->yank_addr);
		pj_ks (pj, "bytes", hex);
		pj_end (pj);
		r_cons_println (ctx->cons, pj_string (pj));
		pj_free (pj);
	} else if (mode) {
		r_cons_printf (ctx->cons, "%s%s\n", mode == '*'? "'wx ": "", hex);
	} else {
		r_cons_printf (ctx->cons, "0x%08" PFMT64x " %" PFMT64u " %s\n", core->yank_addr, (ut64)len, hex);
	}
	free (hex);
	return true;
}

static bool yank_print(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char mode = yank_mode (ctx);
	ut64 pos = 0;
	size_t len = 0;
	ut8 *buf = r_cmdctx_num (ctx, 0, core->num, &pos)? yank_bytes (core, pos, &len): NULL;
	if (!buf) {
		return false;
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
	return true;
}

static bool yank_edit(RCmdContext *ctx) {
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
	return ok;
}

static bool yank_to_file(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *file = r_cmdctx_arg (ctx, 0).a;
	size_t len = 0;
	ut8 *buf = yank_bytes (core, 0, &len);
	bool ok = buf != NULL;
	if (!ok) {
		return false;
	}
	if (*file == '$') {
		r_cmd_alias_set_raw (core->rcmd, file + 1, buf, len, false);
	} else if (!r_file_dump (file, buf, len, false)) {
		R_LOG_ERROR ("Cannot dump to '%s'", file);
		ok = false;
	}
	free (buf);
	return ok;
}

// Parses the length argument at index; 0 selects the block size
static bool yank_len(RCore *core, RCmdContext *ctx, size_t index, ut64 *len) {
	*len = 0;
	if (!r_cmdctx_num (ctx, index, core->num, len)) {
		return false;
	}
	if (!*len) {
		*len = ctx->blocksize;
	}
	if (*len > ST32_MAX) {
		R_LOG_ERROR ("Invalid yank length");
		return false;
	}
	return true;
}

static bool yank_range(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (!r_cmdctx_argc (ctx)) {
		return yank_dump (ctx);
	}
	ut64 len;
	ut64 addr = core->addr;
	return yank_len (core, ctx, 0, &len) && r_cmdctx_num (ctx, 1, core->num, &addr)
		&& r_core_yank (core, addr, len);
}

static bool yank_to(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 len;
	ut64 addr = 0;
	return yank_len (core, ctx, 0, &len) && r_cmdctx_num (ctx, 1, core->num, &addr)
		&& r_core_yank (core, core->addr, len) && r_core_yank_paste (core, addr, len);
}

// Yanks len bytes at offset of filename, or the whole file when len is UT64_MAX
static bool yank_file_range(RCore *core, ut64 offset, ut64 len, const char *filename) {
	const ut64 io_off = core->io->off;
	RIODesc *desc = r_io_desc_open (core->io, filename, R_PERM_R, 0644);
	bool ok = false;
	if (desc) {
		const ut64 size = r_io_desc_size (desc);
		if (len == UT64_MAX) {
			len = size;
		}
		if (!len || len > ST32_MAX || offset > size || len > size - offset) {
			R_LOG_ERROR ("Invalid file yank range");
		} else {
			ut8 *buf = malloc (len);
			if (buf && r_io_desc_read_at (desc, offset, buf, len) == len) {
				ok = r_core_yank_set (core, R_CORE_FOREIGN_ADDR, buf, len);
			} else if (buf) {
				R_LOG_ERROR ("Cannot read file for yank: %s", filename);
			}
			free (buf);
		}
		r_io_desc_close (desc);
	}
	core->io->off = io_off;
	return ok;
}

static bool yank_file(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 len = 0;
	ut64 offset = 0;
	return r_cmdctx_num (ctx, 0, core->num, &len) && r_cmdctx_num (ctx, 1, core->num, &offset)
		&& yank_file_range (core, offset, len, r_cmdctx_arg (ctx, 2).a);
}

static bool yank_joined(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const RCmdRow *command = ctx->handler_user;
	RStrBuf *sb = yank_text (ctx);
	const char *text = r_strbuf_get (sb);
	bool ok;
	if (!command->name[2]) {
		ok = r_core_yank_set (core, 0, (const ut8 *)text, r_strbuf_length (sb));
	} else if (command->name[2] == 'a') {
		ok = yank_file_range (core, 0, UT64_MAX, text);
	} else {
		ok = yank_hexpairs (core, text);
	}
	r_strbuf_free (sb);
	return ok;
}

static bool yank_paste(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 addr = core->addr;
	return r_cmdctx_num (ctx, 0, core->num, &addr) && r_core_yank_paste (core, addr, 0);
}

// Yanks the NUL-terminated string at the current seek, clamped to [len] or the block size
static bool yank_string(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 max = 0;
	const ut32 bsize = ctx->blocksize;
	ut8 *buf = r_cmdctx_num (ctx, 0, core->num, &max)? calloc (1, bsize + 1): NULL;
	if (!buf) {
		return false;
	}
	r_io_read_at (core->io, core->addr, buf, bsize);
	const ut32 len = max? R_MIN (max, bsize): r_str_nlen ((const char *)buf, bsize);
	const bool ok = r_core_yank_set (core, core->addr, buf, len);
	free (buf);
	return ok;
}

static bool yank_unset(RCmdContext *ctx) {
	RCore *core = ctx->user;
	core->yank_addr = UT64_MAX;
	return r_buf_resize (core->yank_buf, 0);
}

static bool yank_length(RCmdContext *ctx) {
	RCore *core = ctx->user;
	r_core_return_value (core, r_buf_size (core->yank_buf));
	return true;
}

static bool yank_yara(RCmdContext *ctx) {
	R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2yara");
	return false;
}

static bool r_core_cmd_yank_init(RCmd *cmd) {
	static const RCmdRow rows[] = {
		{ "y", yank_range, " [len] [addr]", help_msg_y, 0, 2 },
		{ "y!", yank_edit, "", NULL, 0, 0 },
		{ "y*", yank_dump, "", NULL, 0, 0 },
		{ "y-", yank_unset, "", NULL, 0, 0 },
		{ "y8", yank_dump, "", NULL, 0, 0 },
		{ "yf", yank_file, " [len] [offset] [file]", NULL, 3, 3 },
		{ "yfa", yank_joined, " [file]", NULL, 1, UT8_MAX },
		{ "yfx", yank_joined, " [hexpairs]", NULL, 1, UT8_MAX },
		{ "yj", yank_dump, "", NULL, 0, 0 },
		{ "yl", yank_length, "", NULL, 0, 0, R_CMD_ROW_SETS_VALUE },
		{ "yp", yank_print, " [pos]", NULL, 0, 1 },
		{ "yr", yank_yara, "", NULL, 0, UT8_MAX },
		{ "ys", yank_print, " [pos]", NULL, 0, 1 },
		{ "yt", yank_to, " [len] [addr]", NULL, 2, 2 },
		{ "ytf", yank_to_file, " [file|$alias]", NULL, 1, 1 },
		{ "yw", yank_joined, " [text]", NULL, 1, UT8_MAX },
		{ "ywx", yank_joined, " [hexpairs]", NULL, 1, UT8_MAX },
		{ "yx", yank_print, " [pos]", NULL, 0, 1 },
		{ "yy", yank_paste, " [addr]", NULL, 0, 1 },
		{ "yz", yank_string, " [len]", NULL, 0, 1 },
	};
	static const RCmdTable table = { help_msg_y, rows, R_ARRAY_SIZE (rows) };
	return r_cmd_register_table (cmd, "y", &table);
}

#endif
