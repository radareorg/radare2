/* radare - LGPL - Copyright 2009-2021 - pancake */

#include "r_cons.h"
#include "r_core.h"
#include "r_egg.h"

static const char *help_msg_g[] = {
	"Usage:", "g[wcilper] [arg]", "Go compile shellcodes",
	"g", " ", "compile the shellcode",
	"g", " foo.r", "compile r_egg source file",
	"gw", "", "compile and write",
	"gc", " cmd=/bin/ls", "set config option for shellcodes and encoders",
	"gc", "", "list all config options",
	"gL", "[?]", "list plugins (shellcodes, encoders)",
	"gs", " name args", "compile syscall name(args)",
	"gi", " [type]", "define the shellcode type",
	"git", " [...]", "your favourite version control",
	"gp", " padding", "define padding for command",
	"ge", " [encoder] [key]", "specify an encoder and a key",
	"gr", "", "reset r_egg",
	"gS", "", "show the current configuration",
	"EVAL VARS:", "", "asm.arch, asm.bits, asm.os",
	NULL
};

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
	if (b && r_buf_size (b) > 0) {
		r_buf_seek (b, 0, R_BUF_SET);
		for (i = 0; i < r_buf_size (b); i++) {
			r_cons_printf ("%02x", r_buf_read8 (b));
		}
		r_cons_newline ();
	}
}

#if 0
static int compileShellcode(REgg *egg, const char *input){
	int i = 0;
	RBuffer *b;
	if (!r_egg_shellcode (egg, input)) {
		eprintf ("Unknown shellcode '%s'\n", input);
		return 1;
	}
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble : invalid assembly\n");
		r_egg_reset (egg);
		return 1;
	}
	if (!egg->bin) {
		egg->bin = r_buf_new ();
	}
	if (!(b = r_egg_get_bin (egg))) {
		eprintf ("r_egg_get_bin: invalid egg :(\n");
		r_egg_reset (egg);
		return 1;
	}
	r_egg_finalize (egg);
	for (i = 0; i < b->length; i++) {
		r_cons_printf ("%02x", b->buf[i]);
	}
	r_cons_newline ();
	r_egg_reset (egg);
	return 0;
}
#endif

static int cmd_egg_compile(REgg *egg) {
	RBuffer *b;
	int ret = false;
	char *p = r_egg_option_get (egg, "egg.shellcode");
	if (p && *p) {
		if (!r_egg_shellcode (egg, p)) {
			eprintf ("Unknown shellcode '%s'\n", p);
			free (p);
			return false;
		}
		free (p);
	} else {
		eprintf ("Setup a shellcode before (gi command)\n");
		free (p);
		return false;
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
	r_egg_option_set (egg, "egg.shellcode", "");
	r_egg_option_set (egg, "egg.padding", "");
	r_egg_option_set (egg, "egg.encoder", "");
	r_egg_option_set (egg, "key", "");

	r_egg_reset (egg);
	return ret;
}

static int cmd_egg(void *data, const char *input) {
	RCore *core = (RCore *) data;
	REgg *egg = core->egg;
	char *oa, *p;
	r_egg_setup (egg,
		r_config_get (core->config, "asm.arch"),
		core->rasm->config->bits, 0,
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
			if (buf) {
				showBuffer (buf);
			}
			egg->lang.nsyscalls = 0;
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
		if (input[1] == ' ') {
			if (input[0] && input[2]) {
				r_egg_option_set (egg, "egg.padding", input + 2);
			}
		} else {
			eprintf ("Usage: gp [padding]\n");
		}
		break;
	case 'e': // "ge"
		if (input[1] == ' ') {
			const char *encoder = input + 2;
			while (IS_WHITESPACE (*encoder) && *encoder) {
				encoder++;
			}

			oa = strdup (encoder);
			p = strchr (oa + 1, ' ');

			if (p) {
				*p = 0;
				r_egg_option_set (egg, "key", p + 1);
				r_egg_option_set (egg, "egg.encoder", oa);
			} else {
				eprintf ("Usage: ge [encoder] [key]\n");
			}
			free (oa);
		} else {
			eprintf ("Usage: ge [encoder] [key]\n");
		}
		break;
	case 'i': // "gi"
		if (input[1] == 't') {
			if (input[2] == '?') {
				r_sys_cmd ("git --help");
			} else {
				r_sys_cmdf ("git%s", input + 2);
			}
		} else if (input[1] == ' ') {
			if (input[0] && input[2]) {
				r_egg_option_set (egg, "egg.shellcode", input + 2);
			} else {
				eprintf ("Usage: gi [shellcode-type]\n");
			}
		} else {
			eprintf ("Usage: gi [shellcode-type]\n");
		}
		break;
	case 'L': // "gL"
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
	case 'S': // "gS"
	{
		static const char *configList[] = {
			"egg.shellcode",
			"egg.encoder",
			"egg.padding",
			"key",
			"cmd",
			"suid",
			NULL
		};
		r_cons_printf ("Configuration options\n");
		int i;
		for (i = 0; configList[i]; i++) {
			const char *p = configList[i];
			if (r_egg_option_get (egg, p)) {
				r_cons_printf ("%s : %s\n", p, r_egg_option_get (egg, p));
			} else {
				r_cons_printf ("%s : %s\n", p, "");
			}
		}
		r_cons_printf ("\nTarget options\n");
		r_cons_printf ("arch : %s\n", core->anal->cpu);
		r_cons_printf ("os   : %s\n", core->anal->os);
		r_cons_printf ("bits : %d\n", core->anal->bits);
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
					r_cons_print (o);
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
	case '?':
		r_core_cmd_help (core, help_msg_g);
		break;
	}
	return true;
}
