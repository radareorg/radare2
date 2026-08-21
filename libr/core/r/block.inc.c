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

static RCmdResult block_help(RCmdContext *ctx) {
	const size_t len = r_strs_len (ctx->subcmd);
	const char mode = r_cmd_ctx_mode (ctx, "j*");
	const char *match = NULL;
	bool exact = true;
	if (r_strs_equals_str (ctx->subcmd, "64?") || r_strs_startswith (ctx->subcmd, "64:")) {
		match = "b64:";
		exact = false;
	} else if (len == 2) {
		switch (r_strs_at (ctx->subcmd, 0)) {
		case 'f':
			match = "bf";
			break;
		case 'g':
			match = "bg";
			break;
		case 'm':
			match = "bm";
			break;
		default:
			match = mode == 'j'? "bj": mode == '*'? "b*": NULL;
			break;
		}
	}
	if (!match || !r_cons_cmd_help_match (ctx->cons, help_msg_b, match, 0, exact)) {
		r_cons_cmd_help (ctx->cons, help_msg_b);
	}
	return (RCmdResult) { 0 };
}

static RCmdResult block_base64(RCmdContext *ctx) {
	RStrs input = ctx->subcmd;
	if (!r_strs_startswith (input, "64:")) {
		r_cons_cmd_help_match (ctx->cons, help_msg_b, "b64:", 0, false);
		return (RCmdResult) { 0 };
	}
	const bool raw = r_strs_at (input, 3) == '\'';
	RStrs encoded = r_strs_sub (input, raw? 4: 3, r_strs_len (input));
	char *encoded_str = r_strs_tostring (encoded);
	if (!encoded_str) {
		return (RCmdResult) { .status = 1 };
	}
	int len = 0;
	char *cmd = (char *)sdb_decode (encoded_str, &len);
	free (encoded_str);
	if (!cmd) {
		R_LOG_ERROR ("Missing base64 string after b64:");
		return (RCmdResult) { .status = 1 };
	}
	cmd[len] = 0;
	if (raw) {
		r_core_call (ctx->user, cmd);
	} else {
		r_core_cmd_lines (ctx->user, cmd);
	}
	free (cmd);
	return (RCmdResult) { 0 };
}

static ut32 block_size_max(RCore *core) {
	r_th_lock_enter (core->lock);
	const ut32 blocksize_max = core->blocksize_max;
	r_th_lock_leave (core->lock);
	return blocksize_max;
}

static RCmdResult block_json(RCmdContext *ctx) {
	RCore *core = ctx->user;
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		return (RCmdResult) { .status = 1 };
	}
	pj_o (pj);
	pj_ki (pj, "blocksize", ctx->blocksize);
	pj_ki (pj, "blocksize_limit", block_size_max (core));
	pj_end (pj);
	r_cons_println (ctx->cons, pj_string (pj));
	pj_free (pj);
	return (RCmdResult) { 0 };
}

static RCmdResult block_invalid_size(ut64 blocksize) {
	R_LOG_ERROR ("Block size 0x%"PFMT64x" is out of range", blocksize);
	return (RCmdResult) { .status = 1 };
}

static RCmdResult block_invalid_adjustment(ut64 current, bool add, ut64 amount) {
	R_LOG_ERROR ("Block size adjustment 0x%"PFMT64x" %c 0x%"PFMT64x" is out of range",
		current, add? '+': '-', amount);
	return (RCmdResult) { .status = 1 };
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

static const char *block_operand(RCmdContext *ctx, size_t prefix_len) {
	const char *operand = r_strs_len (ctx->subcmd) > prefix_len
		? ctx->subcmd.a + prefix_len
		: ctx->subcmd.b;
	return r_str_trim_head_ro (operand);
}

static RCmdResult block_set_size(RCmdContext *ctx, ut64 blocksize) {
	if (blocksize > ST32_MAX) {
		return block_invalid_size (blocksize);
	}
	const int size = (int)blocksize;
	if (!r_core_block_size (ctx->user, size)) {
		return (RCmdResult) { .status = 1 };
	}
	ctx->blocksize = size > 0? size: 1;
	return (RCmdResult) { 0 };
}

static RCmdResult block_adjust_size(RCmdContext *ctx, bool add) {
	RCore *core = ctx->user;
	ut64 amount = 0;
	if (!block_parse_size (core, block_operand (ctx, 1), &amount)) {
		return (RCmdResult) { .status = 1 };
	}
	const ut64 current = ctx->blocksize;
	if (current > ST32_MAX || (add? amount > ST32_MAX - current: amount > current)) {
		return block_invalid_adjustment (current, add, amount);
	}
	return block_set_size (ctx, add? current + amount: current - amount);
}

static RCmdResult block_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const size_t argc = RVecRStrs_length (&ctx->args);
	if (r_cmd_ctx_help (ctx)) {
		return block_help (ctx);
	}
	const char mode = r_cmd_ctx_mode (ctx, "j*");
	if (!argc && r_strs_len (ctx->subcmd) == 1 && mode) {
		if (mode == 'j') {
			return block_json (ctx);
		}
		r_cons_printf (ctx->cons, "b 0x%x\n", ctx->blocksize);
		return (RCmdResult) { 0 };
	}
	switch (r_strs_at (ctx->subcmd, 0)) {
	case '6': // "b6"
		return block_base64 (ctx);
	case 'm': { // "bm"
		ut64 n = 0;
		if (!block_parse_size (core, block_operand (ctx, 1), &n)) {
			return (RCmdResult) { .status = 1 };
		}
		if (n > 1) {
			if (n > UT32_MAX) {
				return block_invalid_size (n);
			}
			r_th_lock_enter (core->lock);
			core->blocksize_max = (ut32)n;
			r_th_lock_leave (core->lock);
		} else {
			r_cons_printf (ctx->cons, "0x%x\n", block_size_max (core));
		}
		break;
	}
	case '+': // "b+"
		return block_adjust_size (ctx, true);
	case '-': // "b-"
		return block_adjust_size (ctx, false);
	case 'f': // "bf"
		if (r_strs_equals_str (ctx->subcmd, "f") && argc == 1) {
			RStrs *arg = RVecRStrs_at (&ctx->args, 0);
			char *name = r_strs_tostring (*arg);
			RFlagItem *flag = name? r_flag_get (core->flags, name): NULL;
			if (flag) {
				const ut64 size = flag->size;
				free (name);
				return block_set_size (ctx, size);
			}
			R_LOG_ERROR ("bf: cannot find flag named '%s'", name? name: "");
			free (name);
			return (RCmdResult) { .status = 1 };
		}
		r_cons_cmd_help_match (ctx->cons, help_msg_b, "bf", 0, true);
		break;
	case '\0': // "b"
		if (!argc) {
			r_cons_printf (ctx->cons, "0x%x\n", ctx->blocksize);
			break;
		}
		// Fall through to parse the raw expression after "b".
	case '=': {
		ut64 blocksize = 0;
		const size_t prefix_len = r_strs_empty (ctx->subcmd)? 0: 1;
		if (!block_parse_size (core, block_operand (ctx, prefix_len), &blocksize)) {
			return (RCmdResult) { .status = 1 };
		}
		return block_set_size (ctx, blocksize);
	}
	case 'g': // "bg"
		if (r_strs_equals_str (ctx->subcmd, "g") && argc) {
			r_core_cmdf (core, "& %s", r_str_trim_head_ro (ctx->subcmd.b));
			break;
		}
		R_LOG_ERROR ("Usage: 'bg r2cmd' # Expected command to run in background, See '&?' for help");
		return (RCmdResult) { .status = 2 };
	default:
		r_core_return_invalid_command (core, "b", r_strs_at (ctx->subcmd, 0));
		return (RCmdResult) { .status = 1 };
	}
	return (RCmdResult) { 0 };
}

static bool r_core_cmd_block_init(RCmd *cmd) {
	return r_cmd_register (cmd, "b", block_callback, NULL);
}

#endif
