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
	const size_t argc = r_cmdctx_argc (ctx);
	size_t i;
	for (i = first; i < argc; i++) {
		RStrs arg = r_cmdctx_arg (ctx, i);
		const char *nul = memchr (arg.a, 0, r_strs_len (arg));
		const size_t length = nul? nul - arg.a: r_strs_len (arg);
		if (i > first) {
			r_strbuf_append_n (&output, " ", 1);
		}
		r_strbuf_append_n (&output, arg.a, length);
		if (nul) {
			break;
		}
	}
	echo_print (ctx, r_strbuf_get (&output), newline);
	r_strbuf_fini (&output);
}

static bool echo_base64(RCmdContext *ctx) {
	char *input = r_strs_tostring (r_cmdctx_arg (ctx, 0));
	int size = 0;
	ut8 *decoded = input? r_base64_decode_dyn (input, -1, &size, true): NULL;
	free (input);
	const bool ok = decoded && size > 0;
	if (ok) {
		r_cons_println (ctx->cons, (const char *)decoded);
	} else {
		R_LOG_ERROR ("Invalid base64 string");
	}
	free (decoded);
	return ok;
}

static bool echo_run(RCmdContext *ctx) {
	const size_t argc = r_cmdctx_argc (ctx);
	RStrs arg = r_cmdctx_arg (ctx, 0);
	if (argc == 1 && r_strs_equals_str (arg, "-h")) {
		r_cons_cmd_help (ctx->cons, help_msg_echo);
		return true;
	}
	if (!argc) {
		return true;
	}
	const bool newline = !r_strs_equals_str (arg, "-n");
	if (ctx->raw) {
		const char *input = r_str_trim_head_ro (ctx->subcmd.b);
		echo_print (ctx, newline? input: r_str_trim_head_ro (input + 2), newline);
	} else {
		echo_append_args (ctx, newline? 0: 1, newline);
	}
	return true;
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
	static const RCmdRow rows[] = {
		{ "echo", echo_run, " [-n] [arg ...]", help_msg_echo, 0, UT8_MAX, R_CMD_ROW_SETS_VALUE },
		{ "echo64", echo_base64, " base64", help_msg_echo, 1, 1, R_CMD_ROW_SETS_VALUE },
	};
	static const RCmdTable table = { help_msg_echo, rows, R_ARRAY_SIZE (rows) };
	if (!r_cmd_register_table (cmd, "echo", &table)) {
		return false;
	}
	if (!r_cmd_register (cmd, "?e", question_echo_callback, NULL)) {
		r_cmd_unregister (cmd, "echo");
		return false;
	}
	return true;
}

#endif
