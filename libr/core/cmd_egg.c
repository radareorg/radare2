/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "r_cons.h"
#include "r_core.h"
#include "r_egg.h"

static void cmd_egg_option(REgg *egg, const char *key, const char *input) {
	if (!*input) {
		return;
	}
	if (input[1] != ' ') {
		char *a = r_egg_option_get (egg, key);
		if (a) {
			r_cons_println (a);
			free (a);
		}
	} else {
		r_egg_option_set (egg, key, input + 2);
	}
}

static void showBuffer(RBuffer *b) {
	int i;
	if (b && b->length > 0) {
		for (i = 0; i < b->length; i++) {
			r_cons_printf ("%02x", b->buf[i]);
		}
		r_cons_printf ("\n");
	}
}

static int compileShellcode(REgg *egg, const char *input){
	int i = 0;
	RBuffer *b;
	if (!r_egg_shellcode (egg, input)) {
		eprintf ("Unknown shellcode '%s'\n", input);
	}
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble : invalid assembly\n");
		return 1;
	}
	if (!egg->bin) {
		egg->bin = r_buf_new ();
	}
	if (!(b = r_egg_get_bin (egg))) {
		eprintf ("r_egg_get_bin: invalid egg :(\n");
		return 1;
	}
	r_egg_finalize (egg);
	for (i = 0; i < b->length; i++) {
		r_cons_printf ("%02x", b->buf[i]);
	}
	r_cons_newline ();
	return 0;
}

static int cmd_egg_compile(REgg *egg) {
	RBuffer *b;
	int ret = false;
	char *p = r_egg_option_get (egg, "egg.shellcode");
	if (p && *p) {
		if (!r_egg_shellcode (egg, p)) {
			free (p);
			return false;
		}
		free (p);
	}
	r_egg_compile (egg);
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
		return false;
	}
	p = r_egg_option_get (egg, "egg.padding");
	if (p && *p) {
		r_egg_padding (egg, p);
		free (p);
	}
	p = r_egg_option_get (egg, "egg.encoder");
	if (p && *p) {
		r_egg_encode (egg, p);
		free (p);
	}
	if ((b = r_egg_get_bin (egg))) {
		showBuffer (b);
		ret = true;
	}
	// we do not own this buffer!!
	// r_buf_free (b);
	r_egg_reset (egg);
	return ret;
}

static int cmd_egg(void *data, const char *input) {
	RCore *core = (RCore *) data;
	REgg *egg = core->egg;
	char *oa, *p;
	r_egg_setup (egg,
		r_config_get (core->config, "asm.arch"),
		core->assembler->bits, 0,
		r_config_get (core->config, "asm.os")); // XXX
	switch (*input) {
	case 's': // "gs"
		// TODO: pass args to r_core_syscall without vararg
		if (input[1] == ' ') {
			RBuffer *buf = NULL;
			const char *ooaa = input + 2;
			while (IS_WHITESPACE (*ooaa) && *ooaa) ooaa++;
			oa = strdup (ooaa);
			p = strchr (oa + 1, ' ');
			if (p) {
				*p = 0;
				buf = r_core_syscall (core, oa, p + 1);
			} else {
				buf = r_core_syscall (core, oa, "");
			}
			free (oa);
			showBuffer (buf);
		} else {
			eprintf ("Usage: gs [syscallname] [parameters]\n");
		}
		break;
	case ' ': // "g "
		if (input[1] && input[2]) {
			r_egg_load (egg, input + 2, 0);
			if (!cmd_egg_compile (egg)) {
				eprintf ("Cannot compile '%s'\n", input + 2);
			}
		} else {
			eprintf ("wat\n");
		}
		break;
	case '\0': // "g"
		if (!cmd_egg_compile (egg)) {
			eprintf ("Cannot compile\n");
		}
		break;
	case 'p': // "gp"
		if (input[0] && input[2]) {
			r_egg_padding (egg, input + 2);
		}
		// cmd_egg_option (egg, "egg.padding", input);
		break;
	case 'e': // "ge"
		if (input[0] && input[2]) {
			if (!r_egg_encode (egg, input + 2)) {
				eprintf ("Invalid encoder '%s'\n", input + 2);
			}
		}
		// cmd_egg_option (egg, "egg.encoder", input);
		break;
	case 'i': // "gi"
		if (input[0] && input[2]) {
			compileShellcode (egg, input + 2);
		} else {
			eprintf ("Usage: gi [shellcode-type]");
		}
		break;
	case 'l': // "gl"
	{
		RListIter *iter;
		REggPlugin *p;
		r_list_foreach (egg->plugins, iter, p) {
			r_cons_printf ("%s  %6s : %s\n",
				(p->type == R_EGG_PLUGIN_SHELLCODE)?
				"shc": "enc", p->name, p->desc);
		}
	}
	break;
	case 'r': // "gr"
		cmd_egg_option (egg, "egg.padding", "");
		cmd_egg_option (egg, "egg.shellcode", "");
		cmd_egg_option (egg, "egg.encoder", "");
		break;
	case 'c': // "gc"
		// list, get, set egg options
		switch (input[1]) {
		case ' ':
			oa = strdup (input + 2);
			p = strchr (oa, '=');
			if (p) {
				*p = 0;
				r_egg_option_set (egg, oa, p + 1);
			} else {
				char *o = r_egg_option_get (egg, oa);
				if (o) {
					r_cons_printf (o);
					free (o);
				}
			}
			free (oa);
			break;
		case '\0':
			// r_pair_list (egg->pair,NULL);
			eprintf ("TODO: list options\n");
			break;
		default:
			eprintf ("Usage: gc [k=v]\n");
			break;
		}
		break;
	case '?': {
		const char *help_msg[] = {
			"Usage:", "g[wcilper] [arg]", "Go compile shellcodes",
			"g", " foo.r", "Compile r_egg source file",
			"gw", "", "Compile and write",
			"gc", " cmd=/bin/ls", "Set config option for shellcodes and encoders",
			"gc", "", "List all config options",
			"gl", "[?]", "List plugins (shellcodes, encoders)",
			"gs", " name args", "Compile syscall name(args)",
			"gi", " [type]", "Compile shellcode. like ragg2 -i (see gl or ragg2 -L)",
			"gp", " padding", "Define padding for command",
			"ge", " xor", "Specify an encoder",
			"gr", "", "Reset r_egg",
			"EVAL VARS:", "", "asm.arch, asm.bits, asm.os",
			NULL
		};
		r_core_cmd_help (core, help_msg);
	}
		break;
	}
	return true;
}

