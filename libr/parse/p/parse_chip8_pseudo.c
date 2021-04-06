/* radare - LGPL - Copyright 2019 - Vasilij Schneidermann <mail@vasilij.de> */

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

#define MAXARGS 4
#define BUFSIZE 64

static void concat(char *buf, size_t len, const char** args) {
	const char *arg;
	char *dest = buf;
	int arg_len;

	while ((arg = *args++)) {
		if (snprintf (dest, len, "%s", arg) >= len) {
			break;
		}
		arg_len = strlen (arg);
		dest += arg_len;
		len -= arg_len;
	}
}

static int replace(int argc, char *argv[], char *newstr, size_t len) {
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

	for (i = 0; ops[i].op; i++) {
		if (!strcmp (ops[i].op, argv[0]) && newstr) {
			concat (newstr, len, ops[i].res);
			return true;
		}
	}

	return false;
}

static int tokenize(const char* in, char* out[]) {
	int len = strlen (in), count = 0, i = 0, tokenlen = 0, seplen = 0;
	char *token, *buf = (char*) in;
	const char* tokcharset = ", \t\n";

	while (i < len) {
		tokenlen = strcspn (buf, tokcharset);
		token = calloc (tokenlen + 1, sizeof(char));
		memcpy (token, buf, tokenlen);
		out[count] = token;
		i += tokenlen;
		buf += tokenlen;
		count++;

		seplen = strspn (buf, tokcharset);
		i += seplen;
		buf += seplen;
	}

	return count;
}

static int parse(RParse *p, const char *data, char *str) {
	int i;
	char *argv[MAXARGS] = { NULL, NULL, NULL, NULL };
	int argc = tokenize (data, argv);

	if (!replace (argc, argv, str, BUFSIZE)) {
		strcpy (str, data);
	}

	for (i = 0; i < MAXARGS; i++) {
		free (argv[i]);
	}

	return true;
}

RParsePlugin r_parse_plugin_chip8_pseudo = {
	.name = "chip8.pseudo",
	.desc = "chip8 pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_chip8_pseudo,
	.version = R2_VERSION
};
#endif
