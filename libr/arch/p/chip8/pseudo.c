/* radare - LGPL - Copyright 2019 - Vasilij Schneidermann <mail@vasilij.de> */

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_asm.h>

#define MAXARGS 4

static char *replace(int argc, char *argv[]) {
	int i;
	struct {
		const char *op;
		const char **res;
	} ops[] = {
		{ "add",  (const char*[]){ argv[1], " += ", argv[2], NULL } },
		{ "and",  (const char*[]){ argv[1], " &= ", argv[2], NULL } },
		{ "cls",  (const char*[]){ "clear_screen()", NULL } },
		{ "drw",  (const char*[]){ "draw(", argv[1], ", ", argv[2], ", ", argv[3], ")", NULL } },
		{ "exit", (const char*[]){ "exit()", NULL } },
		{ "high", (const char*[]){ "high_res()", NULL } },
		{ "jp",   (const char*[]){ "goto ", argv[1], NULL } },
		{ "ld",   (const char*[]){ argv[1], " = ", argv[2], NULL } },
		{ "low",  (const char*[]){ "low_res()", NULL } },
		{ "or",   (const char*[]){ argv[1], " |= ", argv[2], NULL } },
		{ "rnd",  (const char*[]){ argv[1], " = random(256) & ", argv[2], NULL } },
		{ "scd",  (const char*[]){ "scroll_down(", argv[1], ")", NULL } },
		{ "scl",  (const char*[]){ "scroll_left()", NULL } },
		{ "scr",  (const char*[]){ "scroll_right()", NULL } },
		{ "se",   (const char*[]){ "skip_next_instr if ", argv[1], " == ", argv[2], NULL } },
		{ "shl",  (const char*[]){ argv[1], " <<= 1", NULL } },
		{ "shr",  (const char*[]){ argv[1], " >>= 1", NULL } },
		{ "sknp", (const char*[]){ "skip_next_instr if !key_pressed(", argv[1], ")", NULL } },
		{ "skp",  (const char*[]){ "skip_next_instr if key_pressed(", argv[1], ")", NULL } },
		{ "sne",  (const char*[]){ "skip_next_instr if ", argv[1], " != ", argv[2], NULL } },
		{ "sub",  (const char*[]){ argv[1], " -= ", argv[2], NULL } },
		{ "subn", (const char*[]){ argv[1], " = ", argv[2], " - ", argv[1], NULL } },
		{ "xor",  (const char*[]){ argv[1], " ^= ", argv[2], NULL } },
		{ NULL }
	};

	if (argc > 0 && argv[0]) {
		for (i = 0; ops[i].op; i++) {
			if (!strcmp (ops[i].op, argv[0])) {
				RStrBuf *sb = r_strbuf_new ("");
				const char **arg;
				for (arg = ops[i].res; *arg; arg++) {
					r_strbuf_append (sb, *arg);
				}
				return r_strbuf_drain (sb);
			}
		}
	}
	return NULL;
}

static int tokenize(const char *in, char *out[]) {
	const char *tokcharset = ", \t\n";
	int count = 0;
	in += strspn (in, tokcharset);
	while (*in && count < MAXARGS) {
		const size_t tokenlen = strcspn (in, tokcharset);
		out[count++] = r_str_ndup (in, tokenlen);
		in += tokenlen;
		in += strspn (in, tokcharset);
	}
	return count;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	int i;
	char *argv[MAXARGS] = { NULL, NULL, NULL, NULL };
	int argc = tokenize (data, argv);
	char *str = replace (argc, argv);
	for (i = 0; i < argc; i++) {
		free (argv[i]);
	}
	if (str && !strcmp (str, data)) {
		R_FREE (str);
	}
	return str;
}

RAsmPlugin r_asm_plugin_chip8 = {
	.meta = {
		.name = "chip8",
		.desc = "chip8 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_chip8,
	.version = R2_VERSION
};
#endif
