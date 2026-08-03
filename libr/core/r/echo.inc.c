/* radare - LGPL - Copyright 2026 - pancake */

#if R_INCLUDE_BEGIN

// clang-format off

static RCoreHelpMessage help_msg_echo = {
	"Usage:", "echo [-n] [arg ...]", "",
	"echo", " [arg ...]", "print arguments followed by a newline",
	"echo -n", " [arg ...]", "print arguments without a newline",
	"echo -h", "", "show this help (same as echo?)",
	"echo64", " base64", "decode base64 text up to the first NUL",
	"echo?", "", "show this help",
	NULL
};

// clang-format on

static void echo_print(RCmdContext *ctx, const char *input, bool newline) {
	if (newline) {
		r_cons_println (ctx->cons, input);
	} else {
		r_cons_print (ctx->cons, input);
	}
}

static void echo_append_args(RCmdContext *ctx, size_t first, bool newline) {
	RStrBuf output;
	r_strbuf_init (&output);
	const size_t argc = RVecRStrs_length (&ctx->args);
	size_t i;
	for (i = first; i < argc; i++) {
		RStrs *arg = RVecRStrs_at (&ctx->args, i);
		const char *nul = memchr (arg->a, 0, r_strs_len (*arg));
		const size_t length = nul? nul - arg->a: r_strs_len (*arg);
		if (i > first) {
			r_strbuf_append_n (&output, " ", 1);
		}
		r_strbuf_append_n (&output, arg->a, length);
		if (nul) {
			break;
		}
	}
	echo_print (ctx, r_strbuf_get (&output), newline);
	r_strbuf_fini (&output);
}

static RCmdResult echo_base64(RCmdContext *ctx) {
	RStrs *arg = RVecRStrs_at (&ctx->args, 0);
	if (!arg || RVecRStrs_length (&ctx->args) != 1) {
		return (RCmdResult) { .status = 2 };
	}
	char *input = r_strs_tostring (*arg);
	int size = 0;
	ut8 *decoded = input? r_base64_decode_dyn (input, -1, &size): NULL;
	free (input);
	if (!decoded || size < 1) {
		free (decoded);
		return (RCmdResult) { .status = 1 };
	}
	r_cons_println (ctx->cons, (const char *)decoded);
	free (decoded);
	return (RCmdResult) { 0 };
}

static RCmdResult echo_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const bool exact = r_strs_empty (ctx->subcmd);
	const size_t argc = RVecRStrs_length (&ctx->args);
	RStrs *arg = argc? RVecRStrs_at (&ctx->args, 0): NULL;
	if (r_cmd_ctx_help (ctx)
			|| (exact && argc == 1 && r_strs_equals_str (*arg, "-h"))) {
		r_cons_cmd_help (ctx->cons, help_msg_echo);
		return (RCmdResult) { 0 };
	}
	if (r_strs_equals_str (ctx->subcmd, "64")) {
		return echo_base64 (ctx);
	}
	if (!exact) {
		r_core_return_invalid_command (core, "echo", *ctx->subcmd.a);
		return (RCmdResult) { .status = 1 };
	}
	if (!argc) {
		return (RCmdResult) { 0 };
	}
	size_t i = 0;
	bool newline = true;
	if (r_strs_equals_str (*arg, "-n")) {
		newline = false;
		i++;
	}
	if (ctx->raw) {
		const char *input = r_str_trim_head_ro (ctx->subcmd.b);
		if (!newline) {
			input = r_str_trim_head_ro (input + 2);
		}
		echo_print (ctx, input, newline);
		return (RCmdResult) { 0 };
	}
	echo_append_args (ctx, i, newline);
	return (RCmdResult) { 0 };
}

static RCmdResult question_echo_callback(RCmdContext *ctx) {
	const bool newline = r_strs_empty (ctx->subcmd);
	if (!newline && !r_strs_equals_str (ctx->subcmd, "n")) {
		return (RCmdResult) {
			.action = R_CMD_ACTION_UNHANDLED,
			.status = 127
		};
	}
	if (ctx->raw) {
		echo_print (ctx, r_str_trim_head_ro (ctx->subcmd.b), newline);
	} else {
		echo_append_args (ctx, 0, newline);
	}
	if (newline) {
		RCore *core = ctx->user;
		r_core_return_value (core, 0);
	}
	return (RCmdResult) { 0 };
}

static bool r_core_cmd_echo_init(RCmd *cmd) {
	if (!r_cmd_register (cmd, "echo", echo_callback, NULL)) {
		return false;
	}
	if (!r_cmd_register (cmd, "?e", question_echo_callback, NULL)) {
		r_cmd_unregister (cmd, "echo");
		return false;
	}
	return true;
}

#endif
