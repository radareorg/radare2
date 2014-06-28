/* radare - LGPL - Copyright 2009-2014 - pancake */

static void cmd_egg_option (REgg *egg, const char *key, const char *input) {
	if (input[1]!=' ') {
		char *a = r_egg_option_get (egg, key);
		if (a) {
			r_cons_printf ("%s\n", a);
			free (a);
		}
	} else r_egg_option_set (egg, key, input+2);
}

static int cmd_egg_compile(REgg *egg) {
	int i;
	RBuffer *b;
	int ret = R_FALSE;
	char *p = r_egg_option_get (egg, "egg.shellcode");
	if (p && *p) {
		if (!r_egg_shellcode (egg, p)) {
			free (p);
			return R_FALSE;
		}
		free (p);
	}
	r_egg_compile (egg);
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
		return R_FALSE;
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
		if (b->length>0) {
			for (i=0; i<b->length; i++)
				r_cons_printf ("%02x", b->buf[i]);
			r_cons_printf ("\n");
		}
		ret = R_TRUE;
	}
	// we do not own this buffer!!
	// r_buf_free (b);
	r_egg_reset (egg);
	return ret;
}

static int cmd_egg(void *data, const char *input) {
	RCore *core = (RCore *)data;
	REgg *egg = core->egg;
	char *oa, *p;
	r_egg_setup (egg,
		r_config_get (core->config, "asm.arch"),
		core->assembler->bits, 0,
		r_config_get (core->config, "asm.os")); // XXX
	switch (*input) {
	case 's':
		// TODO: pass args to r_core_syscall without vararg
		if (input[1]=='?' || !input[1]) {
			eprintf ("Usage: gs [syscallname] [parameters]\n");
		} else {
			oa = strdup (input+2);
			p = strchr (oa+1, ' ');
			if (p) {
				*p = 0;
				r_core_syscall (core, oa, p+1);
			} else {
				r_core_syscall (core, oa, "");
			}
			free (oa);
		}
		break;
	case ' ':
		r_egg_load (egg, input+2, 0);
		if (!cmd_egg_compile (egg))
			eprintf ("Cannot compile '%s'\n", input+2);
		break;
	case '\0':
		if (!cmd_egg_compile (egg))
			eprintf ("Cannot compile\n");
		break;
	case 'p':
		cmd_egg_option (egg, "egg.padding", input);
		break;
	case 'e':
		cmd_egg_option (egg, "egg.encoder", input);
		break;
	case 'i':
		cmd_egg_option (egg, "egg.shellcode", input);
		break;
	case 'l':
		{
			RListIter *iter;
			REggPlugin *p;
			r_list_foreach (egg->plugins, iter, p) {
				printf ("%s  %6s : %s\n",
				(p->type==R_EGG_PLUGIN_SHELLCODE)?
					"shc":"enc", p->name, p->desc);
			}
		}
		break;
	case 'r':
		cmd_egg_option (egg, "egg.padding", "");
		cmd_egg_option (egg, "egg.shellcode", "");
		cmd_egg_option (egg, "egg.encoder", "");
		break;
	case 'c':
		// list, get, set egg options
		switch (input[1]) {
		case ' ':
			oa = strdup (input+2);
			p = strchr (oa, '=');
			if (p) {
				*p = 0;
				r_egg_option_set (egg, oa, p+1);
			} else {
				char *o = r_egg_option_get (egg, oa);
				if (o) {
					r_cons_printf ("%s\n", o);
					free (o);
				}
			}
			free (oa);
			break;
		case '\0':
			// list
			// r_pair_list (egg->pair,NULL);
eprintf ("TODO: list options\n");
			eprintf ("list options\n");
			break;
		default:
			eprintf ("Usage: gc [k=v]\n");
			break;
		}
		break;
	case '?': {
		const char* help_msg[] = {
			"Usage:", "g[wcilper] [arg]", "Go compile shellcodes",
			"g", " foo.r", "Compile r_egg source file",
			"gw", "", "Compile and write",
			"gc", " cmd=/bin/ls", "Set config option for shellcodes and encoders",
			"gc", "", "List all config options",
			"gl", "", "List plugins (shellcodes, encoders)",
			"gs", " name args", "Compile syscall name(args)",
			"gi", " exec", "Compile shellcode. like ragg2 -i",
			"gp", " padding", "Define padding for command",
			"ge", " xor", "Specify an encoder",
			"gr", "", "Reset r_egg",
			"EVAL VARS:", "", "asm.arch, asm.bits, asm.os",
			NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	}
	return R_TRUE;
}

