/* radare - LGPL - Copyright 2026 - pancake */

#if R_INCLUDE_BEGIN

// clang-format off

static RCoreHelpMessage help_msg_b = {
	"Usage:",  "b[f] [arg]", "change working block size",
	"b", " 32", "set block size to 32",
	"b", "=32", "same as 'b 32'",
	"b", " eip+4", "numeric argument can be an expression",
	"b", "", "display current block size",
	"b", "+3", "increase blocksize by 3",
	"b", "-16", "decrease blocksize by 16",
	"b*", "", "display current block size in r2 command",
	"b64:", "AA=", "execute a base64-encoded r2 script",
	"b64:'", "AA=", "execute a base64-encoded command without evaluating special chars",
	"bf", " foo", "set block size to flag size",
	"bg", " cmd", "run command in background",
	"bj", "", "display block size information in JSON",
	"bm", " 1M", "set max block size",
	NULL
};

// clang-format on

static const char *block_operand(RCmdContext *ctx) {
	return r_str_trim_head_ro (ctx->subcmd.b);
}

static ut32 block_size_max(RCore *core) {
	r_th_lock_enter (core->lock);
	const ut32 blocksize_max = core->blocksize_max;
	r_th_lock_leave (core->lock);
	return blocksize_max;
}

static bool block_parse_size(RCore *core, const char *expression, ut64 *blocksize) {
	const char *error = NULL;
	*blocksize = r_num_math_err (core->num, expression, &error);
	if (error) {
		R_LOG_ERROR ("Invalid block size expression '%s'", expression);
		return false;
	}
	return true;
}

static bool block_set_size(RCmdContext *ctx, ut64 blocksize) {
	if (blocksize > ST32_MAX) {
		R_LOG_ERROR ("Block size 0x%"PFMT64x" is out of range", blocksize);
		return false;
	}
	const int size = (int)blocksize;
	if (!r_core_block_size (ctx->user, size)) {
		return false;
	}
	ctx->blocksize = size > 0? size: 1;
	return true;
}

static bool block_size(RCmdContext *ctx) {
	const char *operand = block_operand (ctx);
	ut64 size = 0;
	if (!*operand) {
		r_cons_printf (ctx->cons, "0x%x\n", ctx->blocksize);
		return true;
	}
	return block_parse_size (ctx->user, operand, &size) && block_set_size (ctx, size);
}

static bool block_script(RCmdContext *ctx) {
	r_cons_printf (ctx->cons, "b 0x%x\n", ctx->blocksize);
	return true;
}

static bool block_json(RCmdContext *ctx) {
	RCore *core = ctx->user;
	PJ *pj = r_core_pj_new (core);
	pj_o (pj);
	pj_kn (pj, "blocksize", ctx->blocksize);
	pj_kn (pj, "blocksize_limit", block_size_max (core));
	pj_end (pj);
	r_cons_println (ctx->cons, pj_string (pj));
	pj_free (pj);
	return true;
}

static bool block_adjust_size(RCmdContext *ctx) {
	const RCmdRow *row = ctx->handler_user;
	const char op = row->name[1];
	ut64 amount = 0;
	if (!block_parse_size (ctx->user, block_operand (ctx), &amount)) {
		return false;
	}
	const ut64 current = ctx->blocksize;
	if (current > ST32_MAX || (op == '+'? amount > ST32_MAX - current: amount > current)) {
		R_LOG_ERROR ("Block size adjustment 0x%"PFMT64x" %c 0x%"PFMT64x" is out of range", current, op, amount);
		return false;
	}
	return block_set_size (ctx, op == '+'? current + amount: current - amount);
}

static bool block_base64(RCmdContext *ctx) {
	const char *input = ctx->subcmd.b;
	if (!strcmp (input, "'?")) {
		r_cons_cmd_help_prefix (ctx->cons, help_msg_b, "b64:");
		return true;
	}
	const bool raw = *input == '\'';
	int len = 0;
	char *cmd = (char *)sdb_decode (input + raw, &len);
	if (!cmd) {
		R_LOG_ERROR ("Missing base64 string after b64:");
		return false;
	}
	cmd[len] = 0;
	if (raw) {
		r_core_call (ctx->user, cmd);
	} else {
		r_core_cmd_lines (ctx->user, cmd);
	}
	free (cmd);
	return true;
}

static bool block_flag_size(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *name = r_cmdctx_arg (ctx, 0).a;
	const RFlagItem *flag = r_flag_get (core->flags, name);
	if (!flag) {
		R_LOG_ERROR ("bf: cannot find flag named '%s'", name);
		return false;
	}
	return block_set_size (ctx, flag->size);
}

static bool block_background(RCmdContext *ctx) {
	const char *command = block_operand (ctx);
	if (!*command) {
		R_LOG_ERROR ("Usage: 'bg r2cmd' # Expected command to run in background, See '&?' for help");
		return false;
	}
	r_core_cmdf (ctx->user, "& %s", command);
	return true;
}

static bool block_max_size(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 size = 0;
	if (!block_parse_size (core, block_operand (ctx), &size)) {
		return false;
	}
	if (size <= 1) {
		r_cons_printf (ctx->cons, "0x%x\n", block_size_max (core));
		return true;
	}
	if (size > UT32_MAX) {
		R_LOG_ERROR ("Block size 0x%"PFMT64x" is out of range", size);
		return false;
	}
	r_th_lock_enter (core->lock);
	core->blocksize_max = (ut32)size;
	r_th_lock_leave (core->lock);
	return true;
}

static bool r_core_cmd_block_init(RCmd *cmd) {
	static const RCmdRow rows[] = {
		{ "b", block_size, " [size]", help_msg_b, 0, 0, R_CMD_ARGS_VERBATIM },
		{ "b*", block_script, "", NULL, 0, 0 },
		{ "b+", block_adjust_size, "[size]", NULL, 0, 0, R_CMD_ARGS_ATTACHED | R_CMD_ARGS_VERBATIM },
		{ "b-", block_adjust_size, "[size]", NULL, 0, 0, R_CMD_ARGS_ATTACHED | R_CMD_ARGS_VERBATIM },
		{ "b64:", block_base64, "[base64]", NULL, 0, 0, R_CMD_ARGS_ATTACHED | R_CMD_ARGS_VERBATIM },
		{ "b=", block_size, "[size]", NULL, 0, 0, R_CMD_ARGS_ATTACHED | R_CMD_ARGS_VERBATIM },
		{ "bf", block_flag_size, " [flag]", NULL, 1, 1 },
		{ "bg", block_background, " [cmd]", NULL, 0, 0, R_CMD_ARGS_VERBATIM },
		{ "bj", block_json, "", NULL, 0, 0 },
		{ "bm", block_max_size, " [size]", NULL, 0, 0, R_CMD_ARGS_VERBATIM },
	};
	static const RCmdTable table = { help_msg_b, rows, R_ARRAY_SIZE (rows) };
	return r_cmd_register_table (cmd, "b", &table);
}

#endif
