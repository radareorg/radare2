/* radare - LGPL - Copyright 2009-2024 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_g = {
	"Usage:", "g[wcilper] [arg]", "Go compile shellcodes using asm.arch/bits/os",
	"g", " ", "compile the shellcode",
	"g", " foo.r", "compile r_egg source file",
	"gc", " cmd=/bin/ls", "set config option for shellcodes and encoders",
	"gc", "", "list all config options",
	"ge", " [encoder] [key]", "specify an encoder and a key",
	"git", " [...]", "your favourite version control",
	"gi", " [type]", "define the shellcode type",
	"gL", "[?]", "list plugins (shellcodes, encoders)",
	"gp", " padding", "define padding for command",
	"gr", "", "reset r_egg",
	"gs", " name args", "compile syscall name(args)",
	"gS", "", "show the current configuration",
	"gw", "", "compile and write",
	NULL
};

static void cmd_egg_option(RCore *core, REgg *egg, const char *key, const char *input) {
	if (!*input) {
		return;
	}
	if (input[1] != ' ') {
		char *a = r_egg_option_get (egg, key);
		if (a) {
			r_cons_println (core->cons, a);
			free (a);
		}
	} else {
		r_egg_option_set (egg, key, input + 2);
	}
}

static void showBuffer(RCore *core, RBuffer *b) {
	int i;
	if (b && r_buf_size (b) > 0) {
		r_buf_seek (b, 0, R_BUF_SET);
		for (i = 0; i < r_buf_size (b); i++) {
			r_cons_printf (core->cons, "%02x", r_buf_read8 (b));
		}
		r_cons_newline (core->cons);
	}
}

static int cmd_egg_compile(RCore *core, REgg *egg) {
	RBuffer *b;
	int ret = false;
	char *p = r_egg_option_get (egg, "egg.shellcode");
	if (p && *p) {
		if (!r_egg_shellcode (egg, p)) {
			R_LOG_ERROR ("Unknown shellcode '%s'", p);
			free (p);
			return false;
		}
		free (p);
	} else {
		R_LOG_ERROR ("Setup a shellcode before (gi command)");
		free (p);
		return false;
	}

	r_egg_compile (egg);
	if (!r_egg_assemble (egg)) {
		R_LOG_ERROR ("r_egg_assemble: invalid assembly");
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
		showBuffer (core, b);
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
				showBuffer (core, buf);
			}
			egg->lang.nsyscalls = 0;
		} else {
			r_core_cmd_help_contains (core, help_msg_g, "gs");
		}
		break;
	case ' ': // "g "
		if (input[1] && input[2]) {
			r_egg_load (egg, input + 2, 0);
			if (!cmd_egg_compile (core, egg)) {
				R_LOG_ERROR ("Cannot compile '%s'", input + 2);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_g, "g ");
		}
		break;
	case '\0': // "g"
		if (!cmd_egg_compile (core, egg)) {
			R_LOG_ERROR ("Cannot compile");
		}
		break;
	case 'p': // "gp"
		if (input[1] == ' ') {
			if (input[0] && input[2]) {
				r_egg_option_set (egg, "egg.padding", input + 2);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_g, "gp");
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
				r_core_cmd_help_match (core, help_msg_g, "ge");
			}
			free (oa);
		} else {
			r_core_cmd_help_match (core, help_msg_g, "ge");
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
				r_core_cmd_help_contains (core, help_msg_g, "gi");
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_g, "gi");
		}
		break;
	case 'L': // "gL"
	case 'l': // "gl"
		if (input[1] == 'j') {
			PJ *pj = r_core_pj_new (core);
			pj_a (pj);
			RListIter *iter;
			REggPlugin *p;
			r_list_foreach (egg->plugins, iter, p) {
				pj_o (pj);
				pj_ks (pj, "name", p->meta.name);
				pj_ks (pj, "type", (p->type == R_EGG_PLUGIN_SHELLCODE)?  "shc": "enc");
				pj_ks (pj, "description", p->meta.desc);
				pj_ks (pj, "license", p->meta.license);

				pj_end (pj);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf (core->cons, "%s\n", s);
			free (s);
		} else {
			RListIter *iter;
			REggPlugin *p;
			r_list_foreach (egg->plugins, iter, p) {
				r_cons_printf (core->cons, "%s  %6s : %s\n",
					(p->type == R_EGG_PLUGIN_SHELLCODE)?
					"shc": "enc", p->meta.name, p->meta.desc);
			}
		}
		break;
	case 'S': // "gS"
	{
		const char *configList[] = {
			"egg.shellcode",
			"egg.encoder",
			"egg.padding",
			"key",
			"cmd",
			"suid",
			NULL
		};
		r_cons_printf (core->cons, "# Configuration options\n");
		int i;
		for (i = 0; configList[i]; i++) {
			const char *p = configList[i];
			if (r_egg_option_get (egg, p)) {
				r_cons_printf (core->cons, "%s : %s\n", p, r_egg_option_get (egg, p));
			} else {
				r_cons_printf (core->cons, "%s : %s\n", p, "");
			}
		}
		r_cons_printf (core->cons, "\n# Target options\n");
		RArchConfig *ac = core->anal->config;
		const char *os = ac->os? ac->os: R_SYS_OS;
		r_cons_printf (core->cons, "arch : %s\n", ac->cpu);
		r_cons_printf (core->cons, "os   : %s\n", os);
		r_cons_printf (core->cons, "bits : %d\n", ac->bits);
	}
	break;
	case 'r': // "gr"
		cmd_egg_option (core, egg, "egg.padding", "");
		cmd_egg_option (core, egg, "egg.shellcode", "");
		cmd_egg_option (core, egg, "egg.encoder", "");
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
					r_cons_print (core->cons, o);
					free (o);
				}
			}
			free (oa);
			break;
		case '\0':
			// r_pair_list (egg->pair,NULL);
			R_LOG_TODO ("list options");
			break;
		default:
			r_core_cmd_help_contains (core, help_msg_g, "gc");
			break;
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_g);
		break;
	default:
		r_core_return_invalid_command (core, "g", *input);
		break;
	}
	return true;
}
#endif
