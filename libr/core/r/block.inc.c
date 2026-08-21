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
	"bj", "", "display block size information in JSON",
	"bm", " 1M", "set max block size",
	NULL
};

// clang-format on

static RCmdResult block_base64(RCmdContext *ctx, const char *input) {
	if (!r_str_startswith (input, "64:")) {
		r_cons_cmd_help_match (ctx->cons, help_msg_b, "b64:", 0, false);
		return (RCmdResult) { 0 };
	}
	const bool raw = input[3] == '\'';
	const char *encoded = input + (raw? 4: 3);
	int len = 0;
	char *cmd = (char *)sdb_decode (encoded, &len);
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

static RCmdResult block_set_size(RCmdContext *ctx, int blocksize) {
	if (!r_core_block_size (ctx->user, blocksize)) {
		return (RCmdResult) { .status = 1 };
	}
	ctx->blocksize = blocksize > 0? blocksize: 1;
	return (RCmdResult) { 0 };
}

static RCmdResult block_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *input = ctx->subcmd.a;
	switch (*input) {
	case '6': // "b6"
		return block_base64 (ctx, input);
	case 'm': { // "bm"
		const ut64 n = r_num_math (core->num, input + 1);
		if (n > 1) {
			r_th_lock_enter (core->lock);
			core->blocksize_max = n;
			r_th_lock_leave (core->lock);
		} else {
			r_cons_printf (ctx->cons, "0x%x\n", block_size_max (core));
		}
		break;
	}
	case '+': { // "b+"
		const ut64 n = r_num_math (core->num, input + 1);
		return block_set_size (ctx, ctx->blocksize + n);
	}
	case '-': { // "b-"
		const ut64 n = r_num_math (core->num, input + 1);
		return block_set_size (ctx, ctx->blocksize - n);
	}
	case 'f': // "bf"
		if (input[1] == ' ') {
			RFlagItem *flag = r_flag_get (core->flags, input + 2);
			if (flag) {
				return block_set_size (ctx, flag->size);
			}
			R_LOG_ERROR ("bf: cannot find flag named '%s'", input + 2);
			return (RCmdResult) { .status = 1 };
		}
		r_cons_cmd_help_match (ctx->cons, help_msg_b, "bf", 0, true);
		break;
	case 'j': // "bj"
		return block_json (ctx);
	case '*': // "b*"
		r_cons_printf (ctx->cons, "b 0x%x\n", ctx->blocksize);
		break;
	case '\0': // "b"
		r_cons_printf (ctx->cons, "0x%x\n", ctx->blocksize);
		break;
	case '=':
	case ' ':
		return block_set_size (ctx, r_num_math (core->num, input + 1));
	case '?': // "b?"
		r_cons_cmd_help (ctx->cons, help_msg_b);
		break;
	case 'g': // "bg"
		if (input[1] == ' ') {
			r_core_cmdf (core, "& %s", r_str_trim_head_ro (input + 1));
			break;
		}
		R_LOG_ERROR ("Usage: 'bg r2cmd' # Expected command to run in background, See '&?' for help");
		return (RCmdResult) { .status = 2 };
	default:
		r_core_return_invalid_command (core, "b", *input);
		return (RCmdResult) { .status = 1 };
	}
	return (RCmdResult) { 0 };
}

static bool r_core_cmd_block_init(RCmd *cmd) {
	return r_cmd_register (cmd, "b", block_callback, NULL);
}

#endif
