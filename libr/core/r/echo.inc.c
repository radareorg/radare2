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

static bool echo_append_args(RStrBuf *output, RVecRStrs *args, size_t first) {
	const size_t argc = RVecRStrs_length (args);
	size_t i;
	for (i = first; i < argc; i++) {
		RStrs *arg = RVecRStrs_at (args, i);
		const char *nul = memchr (arg->a, 0, r_strs_len (*arg));
		const size_t length = nul? nul - arg->a: r_strs_len (*arg);
		if ((i > first && !r_strbuf_append_n (output, " ", 1))
				|| !r_strbuf_append_n (output, arg->a, length)) {
			return false;
		}
		if (nul) {
			break;
		}
	}
	return true;
}

static ut8 *echo_base64_decode(const char *input, int *size) {
	ut8 *decoded = (ut8 *)strdup (input);
	if (decoded) {
		*size = r_base64_decode (decoded, input, -1, true);
		if (*size < 1) {
			R_FREE (decoded);
		}
	}
	return decoded;
}

static RCmdResult echo_base64(RCmdContext *ctx) {
	RStrs *arg = RVecRStrs_at (&ctx->args, 0);
	if (!arg || RVecRStrs_length (&ctx->args) != 1) {
		return (RCmdResult) { .status = 2 };
	}
	char *input = r_strs_tostring (*arg);
	int size = 0;
	ut8 *decoded = input? echo_base64_decode (input, &size): NULL;
	free (input);
	if (!decoded) {
		return (RCmdResult) { .status = 1 };
	}
	const ut8 *nul = memchr (decoded, 0, size);
	const size_t length = nul? nul - decoded: size;
	RStrBuf output;
	r_strbuf_init (&output);
	const bool success = r_strbuf_append_n (&output, (const char *)decoded, length)
		&& r_strbuf_append_n (&output, "\n", 1)
		&& r_cons_write (ctx->cons, r_strbuf_get (&output), output.len);
	r_strbuf_fini (&output);
	free (decoded);
	return (RCmdResult) { .status = success? 0: 1 };
}

static RCmdResult echo_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const bool exact = r_strs_empty (ctx->subcmd);
	const size_t argc = RVecRStrs_length (&ctx->args);
	RStrs *arg = argc? RVecRStrs_at (&ctx->args, 0): NULL;
	if (r_strs_equals_str (ctx->subcmd, "?")
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
	RStrBuf output;
	r_strbuf_init (&output);
	bool success = echo_append_args (&output, &ctx->args, i);
	if (success && newline) {
		success = r_strbuf_append_n (&output, "\n", 1);
	}
	if (success && output.len) {
		success = r_cons_write (ctx->cons, r_strbuf_get (&output), output.len);
	}
	r_strbuf_fini (&output);
	return (RCmdResult) { .status = success? 0: 1 };
}

// Expand numeric variables for ?e.
static char *expand_num_vars(RCore *core, const char *msg) {
	RStrBuf *sb = r_strbuf_new ("");
	while (*msg) {
		if (*msg != '$' || msg[1] == '(') {
			r_strbuf_append_n (sb, msg++, 1);
			continue;
		}
		const char *end;
		char *word;
		if (msg[1] == '{') {
			end = strchr (msg + 2, '}');
			if (!end) {
				r_strbuf_append_n (sb, msg++, 1);
				continue;
			}
			word = r_str_ndup (msg + 2, end - (msg + 2));
			end++;
		} else {
			end = msg + 1;
			while (*end && r_name_validate_char (*end)) {
				end++;
			}
			word = r_str_ndup (msg + 1, end - (msg + 1));
		}
		if (!word) {
			break;
		}
		r_strbuf_appendf (sb, "0x%"PFMT64x, r_num_math (core->num, word));
		free (word);
		msg = end;
	}
	return r_strbuf_drain (sb);
}

static bool question_echo_print_legacy(RCore *core, RCons *cons, const char *input, bool newline) {
	char *copy = strdup (input);
	if (!copy) {
		return false;
	}
	char *body = (char *)r_str_trim_head_ro (copy);
	char *message = expand_num_vars (core, body);
	free (copy);
	if (!message) {
		return false;
	}
	r_str_unescape (message);
	r_cons_print (cons, message);
	if (newline) {
		r_cons_newline (cons);
		r_core_return_value (core, 0);
	}
	free (message);
	return true;
}

static bool question_echo_print(RCmdContext *ctx, bool newline) {
	RStrBuf input;
	r_strbuf_init (&input);
	bool success = echo_append_args (&input, &ctx->args, 0);
	RCore *core = ctx->user;
	char *message = success? expand_num_vars (core, r_strbuf_get (&input)): NULL;
	r_strbuf_fini (&input);
	if (!message) {
		return false;
	}
	RStrBuf output;
	r_strbuf_init (&output);
	success = r_strbuf_append (&output, message)
		&& (!newline || r_strbuf_append_n (&output, "\n", 1));
	if (success && output.len) {
		success = r_cons_write (ctx->cons, r_strbuf_get (&output), output.len);
	}
	r_strbuf_fini (&output);
	free (message);
	if (success && newline) {
		r_core_return_value (core, 0);
	}
	return success;
}

static void question_echo_legacy(RCore *core, const char *input) {
	const bool newline = input[1] != 'n';
	const char *message = input + (newline? 1: 2);
	question_echo_print_legacy (core, core->cons, message, newline);
}

static RCmdResult question_echo_callback(RCmdContext *ctx) {
	const bool newline = r_strs_empty (ctx->subcmd);
	if (!newline && !r_strs_equals_str (ctx->subcmd, "n")) {
		return (RCmdResult) {
			.action = R_CMD_ACTION_UNHANDLED,
			.status = 127
		};
	}
	RCore *core = ctx->user;
	if (ctx->verbatim) {
		return (RCmdResult) {
			.status = question_echo_print_legacy (core, ctx->cons, ctx->subcmd.b, newline)? 0: 1
		};
	}
	if (!question_echo_print (ctx, newline)) {
		return (RCmdResult) { .status = 1 };
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
