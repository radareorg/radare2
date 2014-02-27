/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_core.h>
#include <r_anal.h>

#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>

static void cmd_debug_reg(RCore *core, const char *str);
#include "cmd_hash.c"
#include "cmd_debug.c"
#include "cmd_zign.c"
#include "cmd_section.c"
#include "cmd_flag.c"
#include "cmd_project.c"
#include "cmd_write.c"
#include "cmd_cmp.c"
#include "cmd_anal.c"
#include "cmd_open.c"
#include "cmd_meta.c"
#include "cmd_type.c"
#include "cmd_egg.c"
#include "cmd_info.c"
#include "cmd_macro.c"
#include "cmd_magic.c"
#include "cmd_mount.c"
#include "cmd_seek.c"
#include "cmd_print.c"
#include "cmd_help.c"
#include "cmd_search.c"

static int r_core_cmd_nullcallback(void *data) {
	RCore *core = (RCore*) data;
	if (!core->cmdrepeat) return 0;
	r_core_cmd_repeat (core, 1);
	return 1;
}

// TODO: move somewhere else
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr) {
	int delta;
	ut8 buf[128];
	static RBuffer *b = NULL; // XXX: never freed and non-thread safe. move to RCore
	RAsmOp *op;
	if (b == NULL) {
		b = r_buf_new ();
		if (!r_core_read_at (core, addr, buf, sizeof (buf)))
			return NULL;
		b->base = addr;
		r_buf_set_bytes (b, buf, sizeof (buf));
	} else {
		if ((addr < b->base) || addr > (b->base+b->length-32)) {
			if (!r_core_read_at (core, addr, buf, sizeof (buf)))
				return NULL;
			b->base = addr;
			r_buf_set_bytes (b, buf, sizeof (buf));
		}
	}
	delta = addr - b->base;
	op = R_NEW0 (RAsmOp);
	r_asm_set_pc (core->assembler, addr);
	if (r_asm_disassemble (core->assembler, op, b->buf+delta, b->length)<1) {
		free (op);
		return NULL;
	}
	return op;
}

static int cmd_log(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *input2 = input + (*input? (*input==' '? 2: 1): 0);
	char *arg = strchr (input2, ' ');
	int n = atoi (input2);
	int n2 = arg? atoi (arg+1): 0;
	switch (*input) {
	case 'e': // shell: less
		{
		char *p = strchr (input, ' ');
		if (p) {
			char *b = r_file_slurp (p+1, NULL);
			if (b) {
				r_cons_less_str (b);
				free (b);
			} else eprintf ("File not found\n");
		} else eprintf ("Usage: less [filename]\n");
		}
		break;
	case 'l':
		r_cons_printf ("%d\n", core->log->last-1);
		break;
	case '-':
		r_core_log_del (core, n);
		break;
	case '?':
		r_cons_printf ("|Usage: l[-][ num|msg]\n"
			"|  l new comment 0x80480\n"
			"|  l       list all log messages\n"
			"|  l*      list in radare commands\n"
			"|  ll      get last log message id\n"
			"|  ls      list files in current directory (see pwd, cd)\n"
			"|  lj      list in json format\n"
			"|  l-      delete all logs\n"
			"|  l-123   delete logs before 123\n"
			"|  l 123   list log from 123 \n"
			"|  l 10 3  list 3 log messages starting from 10\n"
		);
		break;
	case ' ':
		if (!n) {
			r_core_log_add (core, input+1);
			break;
		}
	case 's':
		r_core_syscmd_ls (input);
		break;
	case 'j':
	case '*':
	case '\0':
		r_core_log_list (core, n, n2, *input);
		break;
	}
	return 0;
}

static int cmd_alias(void *data, const char *input) {
	int i;
	char *p, *q, *buf;
	RCore *core = (RCore *)data;
	if (*input=='?') {
		r_cons_printf ("|Usage: -alias[=cmd] [args...]\n"
			"| $dis=af,pdf # create command -analyze to show function\n"
			"| $dis=       # undefine alias\n"
			"| $dis# execute the previously defined alias\n"
			"| $dis?       # show commands aliased by 'analyze'\n"
			"| $           # list all defined aliases\n"
			"| $*          # sas above, but using r2 commands\n");
		return 0;
	}
	i = strlen (input);
	buf = malloc (i+2);
	if (!buf) return 0;
	*buf = '$'; // prefix aliases with a dash
	memcpy (buf+1, input, i+1);
	p = strchr (buf, '=');
	q = strchr (buf, ' ');
	if (p) {
		*p++ = 0;
		if (!q || (q && q>p)) {
			if (*p) r_cmd_alias_set (core->rcmd, buf, p);
			else r_cmd_alias_del (core->rcmd, buf);
		}
	} else 
	if (buf[1]=='*') {
		int i, count = 0;
		char **keys = r_cmd_alias_keys (core->rcmd, &count);
		for (i=0; i<count; i++) {
			const char *v = r_cmd_alias_get (core->rcmd, keys[i]);
			r_cons_printf ("%s=%s\n", keys[i], v);
		}
	} else
	if (!buf[1]) {
		int i, count = 0;
		char **keys = r_cmd_alias_keys (core->rcmd, &count);
		for (i=0; i<count; i++)
			r_cons_printf ("%s\n", keys[i]);
	} else {
		char *describe = strchr (buf, '?');
		char *v;
		if (q) *q = 0;
		if (describe) *describe = 0;
		v = r_cmd_alias_get (core->rcmd, buf);
		if (v) {
			if (describe) {
				r_cons_printf ("%s\n", v);
				return 1;
			}
			if (q) {
				char *out, *args = q+1;
				out = malloc (strlen (v) + strlen (args) + 2);
				if (out) { //XXX slow
					strcpy (out, v);
					strcat (out, " ");
					strcat (out, args);
					r_str_replace_char (out, ',', ';');
					r_core_cmd0 (core, out);
					r_str_replace_char (out, ';', ',');
					free (out);
				} else eprintf ("cannot malloc\n");
			} else {
				r_str_replace_char (v, ',', ';');
				r_core_cmd0 (core, v);
				r_str_replace_char (v, ';', ',');
			}
		} else eprintf ("unknown key '%s'\n", buf);
	}
	return 0;
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0': r_core_rtr_list (core); break;
	case 'h': r_core_rtr_http (core, 0, input+1); break;
	case 'H': 
		  while (input[1]==' ') input++;
		  r_core_rtr_http (core, 1, input+1); break;
	case '?': r_core_rtr_help (core); break;
	case '+': r_core_rtr_add (core, input+1); break;
	case '-': r_core_rtr_remove (core, input+1); break;
	case '=': r_core_rtr_session (core, input+1); break;
	//case ':': r_core_rtr_cmds (core, input+1); break;
	case '<': r_core_rtr_pushout (core, input+1); break;
	case '!': r_io_system (core->io, input+1); break;
	default: r_core_rtr_cmd (core, input);
	}
	return R_TRUE;
}

static int cmd_yank(void *data, const char *input) {
	int i;
	ut64 n;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ':
		r_core_yank (core, core->offset, r_num_math (core->num, input+1));
		break;
	case 'y':
		while (input[1]==' ') input++;
		n = input[1]? r_num_math (core->num, input+1): core->offset;
		r_core_yank_paste (core, n, 0);
		break;
	case 'x':
		r_print_hexdump (core->print, 0LL, core->yank_buf, core->yank_len, 16, 4);
		break;
	case 'p':
		r_cons_memcat ((const char*)core->yank_buf, core->yank_len);
		r_cons_newline ();
		break;
	case 't':
		{ /* hacky implementation */
			char *arg = strdup (input+1);
			r_core_yank_to (core, arg);
			free (arg);
		}
		break;
	case '\0':
		if (core->yank_buf) {
			r_cons_printf ("0x%08"PFMT64x" %d ",
				core->yank_off, core->yank_len);
			for (i=0; i<core->yank_len; i++)
				r_cons_printf ("%02x", core->yank_buf[i]);
			r_cons_newline ();
		} else eprintf ("No buffer yanked already\n");
		break;
	default:
		r_cons_printf (
		"|Usage: y[ptxy] [len] [[@]addr]\n"
		"| y             show yank buffer information (srcoff len bytes)\n"
		"| y 16          copy 16 bytes into clipboard\n"
		"| y 16 0x200    copy 16 bytes into clipboard from 0x200\n"
		"| y 16 @ 0x200  copy 16 bytes into clipboard from 0x200\n"
		"| yp            print contents of clipboard\n"
		"| yx            print contents of clipboard in hexadecimal\n"
		"| yt 64 0x200   copy 64 bytes from current seek to 0x200\n"
		"| yy 0x3344     paste clipboard\n");
		break;
	}
	return R_TRUE;
}

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input)
	switch (*input) {
	case '?':
		r_cons_printf (
		"|Usage: q[!] [retvalue]\n"
		"| q      quit program\n"
		"| q!     force quit (no questions)\n"
		"| q 1    quit with return value 1\n"
		"| q a-b  quit with return value a-b\n");
		break;
	case ' ':
	case '!':
		input++;
	case '\0':
		// TODO
	default:
		r_line_hist_save (R2_HOMEDIR"/history");
		if (*input)
			r_num_math (core->num, input);
		else core->num->value = 0LL;
		//exit (*input?r_num_math (core->num, input+1):0);
		//if (core->http_up) return R_FALSE; // cancel quit when http is running
		return -2;
	}
	return R_FALSE;
}

R_API int r_core_run_script (RCore *core, const char *file) {
	int ret = R_FALSE;
	RListIter *iter;
	RLangPlugin *p;
	char *name;

	r_list_foreach (core->scriptstack, iter, name) {
		if (!strcmp (file, name)) {
			eprintf ("WARNING: ignored nested source: %s\n", file);
			return R_FALSE;
		}
	}
	r_list_push (core->scriptstack, strdup (file));

	if (!strcmp (file, "-")) {
		char *out = r_core_editor (core, NULL);
		if (out) {
			ret = r_core_cmd_lines (core, out);
			free (out);
		}
	} else if (r_parse_is_c_file (file)) {
		char *out = r_parse_c_file (file);
		if (out) {
			r_cons_strcat (out);
			sdb_query_lines (core->anal->sdb_types, out);
			free (out);
		}
		ret = out? R_TRUE: R_FALSE;
	} else {
		p = r_lang_get_by_extension (core->lang, file);
		if (p) {
			r_lang_use (core->lang, p->name);
			ret = r_lang_run_file (core->lang, file);
		} else {
			ret = r_core_cmd_file (core, file);
		}
	}
	free (r_list_pop (core->scriptstack));
	return ret;
}

static int cmd_stdin(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0]=='?') {
		r_cons_printf ("Usage: '-' '.-' '. -' do the same\n");
		return R_FALSE;
	}
	return r_core_run_script (core, "-");
}

static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol, *rbuf, *filter, *inp;
	const char *host, *port, *cmd;
	RCore *core = (RCore *)data;

	switch (*input) {
	case '\0':
		r_core_cmd_repeat (core, 0);
		break;
	case ':':
		if ((ptr = strchr (input+1, ' '))) {
			/* .:port cmd */
			/* .:host:port cmd */
			cmd = ptr+1;
			*ptr = 0;
			eol = strchr (input+1, ':');
			if (eol) {
				*eol = 0;
				host = input+1;
				port = eol+1;
			} else {
				host = "localhost";
				port = input+((input[1]==':')?2:1);
			}
			rbuf = r_core_rtr_cmds_query (core, host, port, cmd);
			if (rbuf) {
				r_cons_printf ("%s", rbuf);
				free (rbuf);
			}
		} else r_core_rtr_cmds (core, input+1);
		break;
	case '.': // same as \n
		r_core_cmd_repeat (core, 1);
		break;
	case '-':
		if (input[1]=='?') {
			r_cons_printf ("Usage: '-' '.-' '. -' do the same\n");
		} else r_core_run_script (core, "-");
		break;
	case ' ':
		r_core_run_script (core, input+1);
		break;
	case '!':
		/* from command */
		r_core_cmd_command (core, input+1);
		break;
	case '(':
		r_cmd_macro_call (&core->rcmd->macro, input+1);
		break;
	case '?':
		r_cons_printf (
		"|Usage: . [file] | [!command] | [(macro)]\n"
		"| .                  repeat last command backward\n"
		"| ..                 repeat last command forward (same as \\n)\n"
		"| .:8080             listen for commands on given tcp port\n"
		"| . foo.r2           interpret r2 script\n"
		"| .-                 open cfg.editor and interpret tmp file\n"
		"| .!rabin -ri $FILE  interpret output of command\n"
		"| .(foo 1 2 3)       run macro 'foo' with args 1, 2, 3\n"
		"| ./ ELF             interpret output of command /m ELF as r. commands\n");
		break;
	default:
		inp = strdup (input);
		filter = strchr (inp, '~');
		if (filter) *filter = 0;
		ptr = str = r_core_cmd_str (core, inp);
		if (filter) *filter = '~';
		r_cons_break (NULL, NULL);
		if (ptr)
		for (;;) {
			if (r_cons_singleton()->breaked) break;
			eol = strchr (ptr, '\n');
			if (eol) *eol = '\0';
			if (*ptr) {
				char *p = r_str_concat (strdup (ptr), filter);
				r_core_cmd0 (core, p);
				free (p);
			}
			if (!eol) break;
			ptr = eol+1;
		}
		r_cons_break_end ();
		free (str);
		free (inp);
		break;
	}
	return 0;
}

static int cmd_bsize(void *data, const char *input) {
	ut64 n;
	RFlagItem *flag;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'm':
		n = r_num_math (core->num, input+1);
		if (n>1) core->blocksize_max = n;
		else r_cons_printf ("0x%x\n", (ut32)core->blocksize_max);
		break;
	case '+':
		n = r_num_math (core->num, input+1);
		r_core_block_size (core, core->blocksize+n);
		break;
	case '-':
		n = r_num_math (core->num, input+1);
		r_core_block_size (core, core->blocksize-n);
		break;
	case 'f':
		if (input[1]==' ') {
			flag = r_flag_get (core->flags, input+2);
			if (flag)
				r_core_block_size (core, flag->size);
			else eprintf ("bf: cannot find flag named '%s'\n", input+2);
		} else eprintf ("Usage: bf [flagname]\n");
		break;
	case '\0':
		r_cons_printf ("0x%x\n", core->blocksize);
		break;
	case '?':
		r_cons_printf ("|Usage: b[f] [arg]\n"
			"| b         display current block size\n"
			"| b+3       increase blocksize by 3\n"
			"| b-16      decrement blocksize by 3\n"
			"| b 33      set block size to 33\n"
			"| b eip+4   numeric argument can be an expression\n"
			"| bf foo    set block size to flag size\n"
			"| bm 1M     set max block size\n");
		break;
	default:
		//input = r_str_clean(input);
		r_core_block_size (core, r_num_math (core->num, input));
		break;
	}
	return 0;
}

static int cmd_resize(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 oldsize, newsize=0;
	st64 delta = 0;
	int grow;

	oldsize = core->file->size;
	while (*input==' ')
		input++;
	switch (*input) {
		case 'm':
			if (input[1]==' ')
				r_file_rm (input+2);
			else eprintf ("Usage: rm [file]   # removes a file\n");
			break;
		case '+':
		case '-':
			delta = (st64)r_num_math (core->num, input);
			newsize = oldsize + delta;
			break;
		case '\0':
		case '?':
			r_cons_printf (
				"|Usage: r[+-][ size]\n"
				"| r size    expand or truncate file to given size\n"
				"| r-num     remove num bytes, move following data down\n"
				"| r+num     insert num bytes, move following data up\n"
				"| rm [file] remove file\n");
			return R_TRUE;
		default:
			newsize = r_num_math (core->num, input);
	}

	grow = (newsize > oldsize);
	if (grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (delta && core->offset < newsize)
		r_io_shift (core->io, core->offset, grow?newsize:oldsize, delta);

	if (!grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (newsize < core->offset+core->blocksize ||
			oldsize < core->offset+core->blocksize) {
		r_core_block_read (core, 0);
	}
	return R_TRUE;
}

static int cmd_eval(void *data, const char *input) {
	char *p;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'n': // env
		if (!strchr (input, '=')) {
			char *var, *p;
			var = strchr (input, ' ');
			if (var) while (*var==' ') var++;
			p = r_sys_getenv (var);
			if (p) {
				r_cons_printf ("%s\n", p);
				free (p);
			} else {
				char **e = r_sys_get_environ ();
				while (e && *e) {
					r_cons_printf ("%s\n", *e);
					e++;
				}
			}
		} else
		if (strlen (input)>3) {
			char *v, *k = strdup (input+3);
			if (!k) break;
			v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				r_sys_setenv (k, v);
			}
			free (k);
		}
		return R_TRUE;
	case 'x': // exit
		return cmd_quit (data, "");
	case '\0':
		r_config_list (core->config, NULL, 0);
		break;
	case 'c':
		switch (input[1]) {
		case 'h': // echo
			p = strchr (input, ' ');
			if (p) {
				r_cons_strcat (p+1);
				r_cons_newline ();
			}
			break;
		case 'd':
			r_cons_pal_init (NULL);
			break;
		case '?':
			r_cons_printf ("|Usage: ec[s?] [key][[=| ]fg] [bg]\n"
			"|  ec                list all color keys\n"
			"|  ec*       (TODO)  same as above, but using r2 commands\n"
			"|  ecd               set default palette\n"
			"|  ecr               set random palette\n"
			"|  ecs               show a colorful palette\n"
			"|  ecf dark|white    load white color scheme template\n"
			"|  ec prompt red     change color of prompt\n"
			"|Available colors:\n"
			"|  rgb:000           24 bit hexadecimal rgb color\n"
			"|  red|green|blue|.  well known ansi colors\n"
			"|See:\n"
			"|  e scr.rgbcolor    = true|false for 256 color cube\n"
			"|  e scr.truecolor   = true|false for 256*256*256 colors\n"
			"|  $DATADIR/radare2/cons ~/.config/radare2/cons ./\n");
			break;
		case 'f':
			if (input[2] == ' ') {
				char *home, path[512];
				snprintf (path, sizeof (path), ".config/radare2/cons/%s", input+3);
				home = r_str_home (path);
				snprintf (path, sizeof (path), R2_DATDIR"/radare2/"
					R2_VERSION"/cons/%s", input+3);
				if (!r_core_cmd_file (core, home))
					if (!r_core_cmd_file (core, path)) 
						if (!r_core_cmd_file (core, input+3))
							eprintf ("ecf: cannot open colorscheme profile\n");
				free (home);
			} else {
				// TODO: lof stuff
				eprintf ("Usage: ecf [themename].\n");
			}
			break;
		case 's': r_cons_pal_show (); break;
		case '*': r_cons_pal_list (1); break;
		case '\0': r_cons_pal_list (0); break;
		case 'r': r_cons_pal_random (); break;
		default: {
			char *p = strdup (input+2);
			char *q = strchr (p, '=');
			if (!q) q = strchr (p, ' ');
			if (q) {
				// set
				*q++ = 0;
				r_cons_pal_set (p, q);
			} else {
				const char *k = r_cons_pal_get (p);
				if (k) eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, k);
			}
		}
		}
		break;
	case 'e':
		if (input[1]==' ') {
			char *p;
			const char *val;
			const char *input2 = strchr (input+2, ' ');
			if (input2) input2++; else input2 = input+2;
			val = r_config_get (core->config, input2);
			p = r_core_editor (core, val);
			if (p) {
				r_str_replace_char (p, '\n', ';');
				r_config_set (core->config, input2, p);
			}
		} else eprintf ("Usage: ee varname\n");
		break;
	case '!':
		input = r_str_chop_ro (input+1);
		if (!r_config_swap (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init (core);
		eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case 'v': eprintf ("Invalid command '%s'. Use 'e?'\n", input); break;
	case '*': r_config_list (core->config, NULL, 1); break;
	case '?':
		switch (input[1]) {
		case '?': r_config_list (core->config, input+2, 2); break;
		default: r_config_list (core->config, input+1, 2); break;
		case 0:
			r_cons_printf (
			"|Usage: e[?] [var[=value]]\n"
			"| e?              show this help\n"
			"| e?asm.bytes     show description\n"
			"| e??             list config vars with description\n"
			"| e               list config vars\n"
			"| e-              reset config vars\n"
			"| e*              dump config vars in r commands\n"
			"| e!a             invert the boolean value of 'a' var\n"
			"| er [key]        set config key as readonly. no way back\n"
			"| ec [k] [color]  set color for given key (prompt, offset, ...)\n"
			"| e a             get value of var 'a'\n"
			"| e a=b           set var 'a' the 'b' value\n"
			"| env [k[=v]]     get/set environment variable\n");
		}
		break;
	case 'r':
		if (input[1]) {
			const char *key = input+((input[1]==' ')?2:1);
			if (!r_config_readonly (core->config, key))
				eprintf ("cannot find key '%s'\n", key);
		} else eprintf ("Usage: er [key]\n");
		break;
	case ' ': r_config_eval (core->config, input+1); break;
	default: r_config_eval (core->config, input); break;
	}
	return 0;
}

static int cmd_visual(void *data, const char *input) {
	RCore *core = (RCore*) data;
	int ret;
	if (core->http_up)
		return R_FALSE;
	if (!r_config_get_i (core->config, "scr.interactive"))
		return R_FALSE;
	ret = r_core_visual ((RCore *)data, input);
	return ret;
}

static int cmd_pointer(void *data, const char *input) {
	int ret = R_TRUE;
	char *str, *eq;
	while (*input==' ') input++;
	if (!*input || *input=='?') {
		eprintf ("|Usage: *<addr>[=[0x]value]\n"
			"| *entry0=cc           # write trap in entrypoint\n"
			"| *entry0+10=0x804800  # write value in delta address\n"
			"| *entry0              # read byte at given address\n"
			"|TODO: last command should honor asm.bits\n");
		return ret;
	}
	str = strdup (input);
	eq = strchr (str, '=');
	if (eq) {
		*eq++ = 0;
		if (!strncmp (eq, "0x", 2)) {
			ret = r_core_cmdf ((RCore*)data, "wv %s@%s", eq, str);
		} else {
			ret = r_core_cmdf ((RCore*)data, "wx %s@%s", eq, str);
		}
	} else {
		ret = r_core_cmdf ((RCore*)data, "?v [%s]", input);
	}
	free (str);
	return ret;
}

static int cmd_env(void *data, const char *input) {
	return r_core_cmdf ((RCore*)data, "env %s", input);
}

static int cmd_system(void *data, const char *input) {
	RCore *core = (RCore*)data;
	ut64 n;
	int ret = 0;
	switch (*input) {
	case '!': 
		if (input[1]) {
			int olen;
			char *out = NULL;
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				ret = r_sys_cmd_str_full (cmd+1, NULL, &out, &olen, NULL);
				r_core_sysenv_end (core, input);
				r_cons_memcat (out, olen);
				free (out);
				free (cmd);
			} //else eprintf ("Error setting up system environment\n");
		} else {
			eprintf ("History saved to "R2_HOMEDIR"/history\n");
			r_line_hist_save (R2_HOMEDIR"/history");
		}
		break;
	case '\0':
		r_line_hist_list ();
		break;
	case '?':
		r_core_sysenv_help ();
		break;
	default:
		n = atoi (input);
		if (*input=='0' || n>0) {
			const char *cmd = r_line_hist_get (n);
			if (cmd) r_core_cmd0 (core, cmd);
			//else eprintf ("Error setting up system environment\n");
		} else {
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				ret = r_sys_cmd (cmd);
				r_core_sysenv_end (core, input);
				free (cmd);
			} else eprintf ("Error setting up system environment\n");
		}
		break;
	}
	return ret;
}

R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
	char *_ptr;
#if __UNIX__
	int fds[2];
	int stdout_fd;
#endif
	int olen, ret = -1, pipecolor = -1;
	char *str, *out = NULL;
	if (!r_config_get_i (core->config, "scr.pipecolor")) {
		pipecolor = r_config_get_i (core->config, "scr.color");
		r_config_set_i (core->config, "scr.color", 0);
	}
	if (*shell_cmd=='!') {
		_ptr = (char *)r_str_lastbut (shell_cmd, '~', "\"");
		//ptr = strchr (cmd, '~');
		if (_ptr) {
			*_ptr = '\0';
			_ptr++;
		}
		olen = 0;
		out = NULL;
		// TODO: implement foo
		str = r_core_cmd_str (core, radare_cmd);
		r_sys_cmd_str_full (shell_cmd+1, str, &out, &olen, NULL);
		r_cons_memcat (out, olen);
		if (_ptr)
			r_cons_grep (_ptr);
		free (out);
		ret = 0;
	}
#if __UNIX__
	radare_cmd = (char*)r_str_trim_head (radare_cmd);
	shell_cmd = (char*)r_str_trim_head (shell_cmd);

	signal (SIGPIPE, SIG_IGN);
	stdout_fd = dup (1);
	if (stdout_fd != -1) {
		pipe (fds);
		if (fork ()) {
			dup2 (fds[1], 1);
			close (fds[1]);
			close (fds[0]);
			r_core_cmd (core, radare_cmd, 0);
			r_cons_flush ();
			close (1);
			wait (&ret);
			dup2 (stdout_fd, 1);
			close (stdout_fd);
		} else {
			close (fds[1]);
			dup2 (fds[0], 0);
			//dup2 (1, 2); // stderr goes to stdout
			r_sandbox_system (shell_cmd, 0);
			close (stdout_fd);
		}
	}
#else
#warning r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
	eprintf ("r_core_cmd_pipe: unimplemented for this platform\n");
#endif
	if (pipecolor != -1)
		r_config_set_i (core->config, "scr.color", pipecolor);
	return ret;
}

static int r_core_cmd_subst_i(RCore *core, char *cmd);
static int r_core_cmd_subst(RCore *core, char *cmd) {
	int ret = 0, rep = atoi (cmd);
	char *cmt, *colon, *icmd = strdup (cmd);
	cmd = r_str_trim_head_tail (icmd);
	if (!icmd || !strncmp (cmd, "# ", 2))
		goto beach;
	cmt = *icmd ? strchr (icmd+1, '#'): NULL;
	if (cmt && cmt[1]==' ')
		*cmt = 0;
	if (*cmd != '"') {
		if ((colon = strchr (icmd, ';')))
			*colon = 0;
	} else colon = NULL;
	if (rep>0) {
		while (*cmd>='0' && *cmd<='9')
			cmd++;
		// do not repeat null cmd
		if (!*cmd) goto beach;
	} 
	if (rep<1) rep = 1;
	while (rep-- && *cmd) {
		ret = r_core_cmd_subst_i (core, cmd);
		if (ret && *cmd=='q')
			goto beach;
	}
	if (colon && colon[1]) {
		for (++colon; *colon==';'; colon++);
		r_core_cmd_subst (core, colon);
	} else {
		if (!*icmd)
			r_core_cmd_nullcallback (core);
	}
beach:
	free (icmd);
	return ret;
}

static char *find_eoq (char *p) {
	for (; *p; p++) {
		if (*p=='"') break;
		if (*p=='\\' && p[1]=='"')
			p++;
	}
	return p;
}

static int r_core_cmd_subst_i(RCore *core, char *cmd) {
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	int i, ret = 0, pipefd;
	int usemyblock = 0;

	if (!cmd) return 0;
	cmd = r_str_trim_head_tail (cmd);

	/* quoted / raw command */
	switch (*cmd) {
	case '.':
		if (cmd[1] == '"') /* interpret */
			return r_cmd_call (core->rcmd, cmd);
		break;
	case '"':
		for (cmd++; *cmd; ) {
			int pipefd = -1;
			ut64 oseek = UT64_MAX;
			char *line, *p = find_eoq (cmd);
			if (!p || !*p) {
				eprintf ("Missing \" in (%s).", cmd);
				return R_FALSE;
			}
			*p = 0;
			// SKIPSPACES in p+1
			while (IS_WHITESPACE (p[1])) p++;
			if (p[1]=='@' || (p[1] && p[2]=='@')) {
				char *q = strchr (p+1, '"');
				if (q) *q = 0;
				oseek = core->offset;
				r_core_seek (core, r_num_math (
					core->num, p+2), 1);
				if (q) {
					*p = '"';
					p = q;
				} else p = NULL;
			}
			if (p && *p && p[1]=='>') {
				str = p+2;
				while (*str=='>') str++;
				while (IS_WHITESPACE (*str)) str++;
				r_cons_flush ();
				pipefd = r_cons_pipe_open (str, 1, p[2]=='>');
			}
			line = strdup (cmd);
			line = r_str_replace (line, "\\\"", "\"", R_TRUE);
			if (p && p[1]=='|') {
				str = p+2;
				while (IS_WHITESPACE (*str)) str++;
				r_core_cmd_pipe (core, cmd, str);
			} else {
				r_cmd_call (core->rcmd, line);
			}
			free (line);
			if (oseek != UT64_MAX) {
				r_core_seek (core, oseek, 1);
				oseek = UT64_MAX;
			}
			if (pipefd != -1) {
				r_cons_flush ();
				r_cons_pipe_close (pipefd);
			}
			if (!p) break;
			*p = '"';
			cmd = p+1;
		}
		return R_TRUE;
	case '(':
		if (cmd[1] != '*')
			return r_cmd_call (core->rcmd, cmd);
	}

// TODO must honor " and `
	/* comments */
	if (*cmd!='#') {
		ptr = (char *)r_str_lastbut (cmd, '#', quotestr);
		if (ptr && ptr[1]==' ') *ptr = '\0';
	}

	/* multiple commands */
// TODO: must honor " and ` boundaries
	//ptr = strrchr (cmd, ';');
	if (*cmd!='#') {
		ptr = (char *)r_str_lastbut (cmd, ';', quotestr);
		if (ptr) {
			int ret ;
			*ptr = '\0';
			if (r_core_cmd_subst (core, cmd) == -1)
				return -1;
			cmd = ptr+1;
			ret = r_core_cmd_subst (core, cmd);
			*ptr = ';';
			return ret;
			//r_cons_flush ();
		}
	}

	// TODO must honor " and `
	/* pipe console to shell process */
	//ptr = strchr (cmd, '|');
	ptr = (char *)r_str_lastbut (cmd, '|', quotestr);
	if (ptr) {
		char *ptr2 = strchr (cmd, '`');
		if (!ptr2 || (ptr2 && ptr2>ptr)) {
			if (!tick || (tick && tick > ptr)) {
				*ptr = '\0';
				cmd = r_str_clean (cmd);
int value = core->num->value;
				if (*cmd) r_core_cmd_pipe (core, cmd, ptr+1);
				else r_io_system (core->io, ptr+1);
core->num->value = value;
				return 0;
			}
		}
	}

	// TODO must honor " and `
	/* bool conditions */
	ptr = (char *)r_str_lastbut (cmd, '&', quotestr);
	//ptr = strchr (cmd, '&');
	while (ptr && ptr[1]=='&') {
		*ptr = '\0';
		ret = r_cmd_call (core->rcmd, cmd);
		if (ret == -1) {
			eprintf ("command error(%s)\n", cmd);
			return ret;
		}
		for (cmd=ptr+2; cmd && *cmd==' '; cmd++);
		ptr = strchr (cmd, '&');
	}

	/* Out Of Band Input */
	free (core->oobi);
	core->oobi = NULL;

	ptr = strchr (cmd, '<');
	if (ptr) {
		ptr[0] = '\0';
		if (ptr[1]=='<') {
			/* this is a bit mess */
			//const char *oprompt = strdup (r_line_singleton ()->prompt);
			//oprompt = ">";
			for (str=ptr+2; str[0]==' '; str++);
			eprintf ("==> Reading from stdin until '%s'\n", str);
			free (core->oobi);
			core->oobi = malloc (1);
			if (core->oobi)
				core->oobi[0] = '\0';
			core->oobi_len = 0;
			for (;;) {
				char buf[1024];
				int ret;
				write (1, "> ", 2);
				fgets (buf, sizeof (buf)-1, stdin); // XXX use r_line ??
				if (feof (stdin))
					break;
				buf[strlen (buf)-1]='\0';
				ret = strlen (buf);
				core->oobi_len += ret;
				core->oobi = realloc (core->oobi, core->oobi_len+1);
				if (core->oobi) {
					if (!strcmp (buf, str))
						break;
					strcat ((char *)core->oobi, buf);
				}
			}
			//r_line_set_prompt (oprompt);
		} else {
			for (str=ptr+1; *str== ' '; str++);
			if (!*str) goto next;
			eprintf ("Slurping file '%s'\n", str);
			free (core->oobi);
			core->oobi = (ut8*)r_file_slurp (str, &core->oobi_len);
			if (core->oobi == NULL)
				eprintf ("cannot open file\n");
			else if (ptr == cmd)
				return r_core_cmd_buffer (core, (const char *)core->oobi);
		}
	}
next:

// TODO must honor " and `
	/* pipe console to file */
	ptr = strchr (cmd, '>');
	if (ptr) {
		int fdn = 1;
		int pipecolor = r_config_get_i (core->config, "scr.pipecolor");
		int use_editor = R_FALSE;
		//int scrint = r_cons_singleton()->is_interactive;
		int ocolor = r_config_get_i (core->config, "scr.color");
		*ptr = '\0';
		str = r_str_trim_head_tail (ptr+1+(ptr[1]=='>'));
		if (!*str) goto next2;
		/* r_cons_flush() handles interactive output (to the terminal)
		 * differently (e.g. asking about too long output). This conflicts
		 * with piping to a file. Disable it while piping. */
		if (ptr>cmd) {
			char *fdnum = ptr-1;
			if (*fdnum >= '0' && *fdnum <= '9')
				fdn = *fdnum - '0';
			*fdnum = 0;
		}
		r_cons_set_interactive (R_FALSE);
		if (!strcmp (str, "-")) {
			use_editor = R_TRUE;
			str = r_file_temp ("dumpedit");
			r_config_set (core->config, "scr.color", "false");
		}
		pipefd = r_cons_pipe_open (str, fdn, ptr[1]=='>');
		if (pipefd != -1) {
			if (!pipecolor)
				r_config_set_i (core->config, "scr.color", 0);

			ret = r_core_cmd_subst (core, cmd);
			r_cons_flush ();
			r_cons_pipe_close (pipefd);
		}
		r_cons_set_last_interactive ();
		if (!pipecolor)
			r_config_set_i (core->config, "scr.color", ocolor);
		if (use_editor) {
			const char *editor = r_config_get (core->config, "cfg.editor");
			if (editor && *editor)
				r_sys_cmdf ("%s '%s'", editor, str);
			else eprintf ("No cfg.editor configured\n");
			r_config_set_i (core->config, "scr.color", ocolor);
			r_file_rm (str);
			free (str);
		}
		return ret;
	}
next2:
	/* sub commands */
	ptr = strchr (cmd, '`');
	if (ptr) {
		int empty = 0;
		int oneline = 1;
		if (ptr[1]=='`') {
			memmove (ptr, ptr+1, strlen (ptr));
			oneline = 0;
			empty = 1;
		}
		ptr2 = strchr (ptr+1, '`');
		if (empty) {
			/* do nothing */
		} else
		if (!ptr2) {
			eprintf ("parse: Missing backtick in expression.\n");
			return -1;
		} else {
			int value = core->num->value;
			*ptr = '\0';
			*ptr2 = '\0';
			if (ptr[1] == '!') {
				str = r_core_cmd_str_pipe (core, ptr+1);
			} else {
				str = r_core_cmd_str (core, ptr+1);
			}
			if (!str)
				return -1;
			// ignore contents if first char is pipe or comment
			if (*str=='|' || *str=='*') {
				eprintf ("r_core_cmd_subst_i: invalid backticked command\n");
				free (str);
				return -1;
			}
			if (oneline && str)
				for (i=0; str[i]; i++)
					if (str[i]=='\n')
						str[i]=' ';
			str = r_str_concat (str, ptr2+1);
			cmd = r_str_concat (strdup (cmd), str);
			core->num->value = value;
			ret = r_core_cmd_subst (core, cmd);
			free (cmd);
			free (str);
			return ret;
		}
	}
	// TODO must honor " and `

	/* grep the content */
	if (*cmd!='?')
		ptr = (char *)r_str_lastbut (cmd, '~', quotestr);
	if (*cmd!='.' && ptr) {
		*ptr = '\0';
		ptr++;
		r_cons_grep (ptr);
	}

	/* temporary seek commands */
	if (*cmd!='(' && *cmd!='"') {
		ptr = strchr (cmd, '@');
		if (ptr == cmd+1 && *cmd=='?')
			ptr = NULL;
	} else ptr = NULL;
	core->tmpseek = ptr? R_TRUE: R_FALSE;
	if (ptr) {
		ut64 tmpoff, tmpbsz, addr;
		ut8 *buf;
		const char *offstr;
		char *f, *ptr2 = strchr (ptr+1, '!');
		int sz, len;
		addr = 0LL;
		tmpoff = core->offset;
		tmpbsz = core->blocksize;

		*ptr = '\0';
		for (ptr++; *ptr== ' '; ptr++);
		ptr--;

		arroba = strchr (ptr+2, '@');
repeat_arroba:
		if (arroba)
			*arroba = 0;
		if (ptr[2]==':') {
			usemyblock = 1;
			switch (ptr[1]) {
			case 'f':
				f = r_file_slurp (ptr+3, &sz);
				if (f) {
					buf = malloc (sz);
					if (buf) {
						free (core->block);
						core->block = buf;
						core->blocksize = sz;
						memcpy (core->block, f, sz);
					} else eprintf ("cannot alloc %d", sz);
					free (f);
				} else eprintf ("cannot open '%s'\n", ptr+3);
				break;
			case '8':
			case 'b':
				buf = malloc (strlen (ptr+2)+1);
				if (!buf) {
					eprintf ("cannot allocate\n");
					return R_FALSE;
				}
				len = r_hex_str2bin (ptr+3, buf);
				r_core_block_size (core, len);
				memcpy (core->block, buf, core->blocksize);
				free (buf);
				break;
			case 's':
				len = strlen (ptr+3);
				r_core_block_size (core, len);
				memcpy (core->block, ptr+3, len);
				break;
			default:
				goto ignore;
			}
			*ptr = '@';
			goto next_arroba; //ignore; //return ret;
		}
ignore:
		for (ptr++;*ptr== ' ';ptr++); ptr--;
		cmd = r_str_clean (cmd);
		if (ptr2) {
			if (strlen (ptr+1)==13 && strlen (ptr2+1)==6 && \
				!memcmp (ptr+1,"0x", 2) && !memcmp (ptr2+1, "0x", 2)) {
				/* 0xXXXX:0xYYYY */
			} else
			if (strlen (ptr+1)==9 && strlen (ptr2+1)==4) {
				/* XXXX:YYYY */
			} else {
				*ptr2 = '\0';
				r_core_block_size (core, r_num_math (core->num, ptr2+1));
			}
		}

		offstr = r_str_trim_head (ptr+1);

		addr = r_num_math (core->num, offstr);
                if (isalpha (ptr[1]) && addr== 0) {
                        if (!r_flag_get (core->flags, ptr+1)) {
                                eprintf ("Invalid address (%s)\n", ptr+1);
                                return R_FALSE;
                        }
                } else {
			char ch = *offstr;
			if (ch=='-' || ch=='+')
				addr = core->offset+addr;
		}
next_arroba:
		if (arroba) {
			ptr = arroba; //-3;
			arroba = NULL;
			goto repeat_arroba;
		}
		if (ptr[1]=='@') {
			// TODO: remove temporally seek (should be done by cmd_foreach)
			ret = r_core_cmd_foreach (core, cmd, ptr+2);
			//ret = -1; /* do not run out-of-foreach cmd */
		} else {
			if (usemyblock) {
				core->offset = addr;
				ret = r_cmd_call (core->rcmd, r_str_trim_head (cmd));
			} else {
				if (!ptr[1] || r_core_seek (core, addr, 1)) {
					r_core_block_read (core, 0);
					ret = r_cmd_call (core->rcmd, r_str_trim_head (cmd));
				} else ret = 0;
			}
		}
		if (ptr2) {
			*ptr2 = '!';
			r_core_block_size (core, tmpbsz);
		}
		r_core_seek (core, tmpoff, 1);
		*ptr = '@';
		return ret;
	}

	return cmd? r_cmd_call (core->rcmd, r_str_trim_head (cmd)): R_FALSE;
}

R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each) {
	int i, j;
	char ch;
	char *word = NULL;
	char *str, *ostr;
	RListIter *iter;
	RFlagItem *flag;
	ut64 oseek, addr;

	for (; *each==' '; each++);
	for (; *cmd==' '; cmd++);

	oseek = core->offset;
	ostr = str = strdup(each);
	//r_cons_break();

	switch (each[0]) {
	case '?':
		r_cons_printf (
		"|Foreach '@@' iterator command:\n"
		"| Repeat a command over a list of offsets.\n"
		"| x @@ sym.*          Run 'x' over all flags matching 'sym.' in current flagspace\n"
		"| x @@.file           \"\" over the offsets specified in the file (one offset per line)\n"
		"| x @@=off1 off2 ..   Manual list of offsets\n"
		"| x @@=`pdf~call[0]`  Run 'x' at every call offset of the current function\n");
		break;
	case '=':
		/* foreach list of items */
		each = str+1;
		do {
			while (*each==' ') each++;
			if (!*each) break;
			str = strchr (each, ' ');
			if (str) {
				*str = '\0';
				addr = r_num_math (core->num, each);
				*str = ' ';
			} else addr = r_num_math (core->num, each);
			//eprintf ("; 0x%08"PFMT64x":\n", addr);
			each = str+1;
			r_core_seek (core, addr, 1);
			r_core_cmd (core, cmd, 0);
			r_cons_flush ();
		} while (str != NULL);
		break;
	case '.':
		if (each[1]=='(') {
			char cmd2[1024];
			// TODO: use r_cons_break() here
			// XXX whats this 999 ?
			i = 0;
			r_cons_break (NULL, NULL);
			for (core->rcmd->macro.counter=0;i<999;core->rcmd->macro.counter++) {
				if (r_cons_singleton ()->breaked)
					break;
				r_cmd_macro_call (&core->rcmd->macro, each+2);
				if (core->rcmd->macro.brk_value == NULL)
					break;

				addr = core->rcmd->macro._brk_value;
				sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
				eprintf ("0x%08"PFMT64x" (%s)\n", addr, cmd2);
				r_core_seek (core, addr, 1);
				r_core_cmd (core, cmd2, 0);
				i++;
			}
			r_cons_break_end();
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = r_sandbox_fopen (each+1, "r");
			if (fd) {
				core->rcmd->macro.counter=0;
				while (!feof (fd)) {
					buf[0] = '\0';
					if (fgets (buf, sizeof (buf), fd) == NULL)
						break;
					addr = r_num_math (core->num, buf);
					eprintf ("0x%08"PFMT64x": %s\n", addr, cmd);
					sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
					r_core_seek (core, addr, 1); // XXX
					r_core_cmd (core, cmd2, 0);
					core->rcmd->macro.counter++;
				}
				fclose (fd);
			} else eprintf ("cannot open file '%s' to read offsets\n", each+1);
		}
		break;
	default:
		core->rcmd->macro.counter = 0;
		//while(str[i]) && !core->interrupted) {
		// split by keywords
		i = 0;
		while (str[i]) {
			j = i;
			for (;str[j]&&str[j]==' ';j++); // skip spaces
			for (i=j;str[i]&&str[i]!=' ';i++); // find EOS
			ch = str[i];
			str[i] = '\0';
			word = strdup (str+j);
			if (word == NULL)
				break;
			str[i] = ch;
			{
				/* for all flags in current flagspace */
				// XXX: dont ask why, but this only works with _prev..
				r_list_foreach_prev (core->flags->flags, iter, flag) {
					if (r_cons_singleton()->breaked)
						break;
					/* filter per flag spaces */
					if ((core->flags->space_idx != -1) && (flag->space != core->flags->space_idx))
						continue;
					if (r_str_glob (flag->name, word)) {
						r_core_seek (core, flag->offset, 1);
						//r_cons_printf ("# @@ 0x%08"PFMT64x" (%s)\n", core->offset, flag->name);
					//	r_cons_printf ("0x%08"PFMT64x" %s\n", core->offset, flag->name);
						eprintf ("# 0x%08"PFMT64x": %s\n", flag->offset, cmd);
						r_core_cmd (core, cmd, 0);
					}
				}
				r_cons_break (NULL, NULL);

				core->rcmd->macro.counter++ ;
				free (word);
				word = NULL;
			}
		}
	}
	r_cons_break_end ();
	// XXX: use r_core_seek here
	core->offset = oseek;

	free (word);
	free (ostr);
	return R_TRUE;
}

R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
	char *cmd, *ocmd, *ptr, *rcmd;
	int ret = R_FALSE;

	if (cstr==NULL)
		return R_FALSE;
	if (*cstr == '|') {
		// RAW COMMENT
		return R_FALSE;
	}
	if (log && *cstr && *cstr!='.') {
		free (core->lastcmd);
		core->lastcmd = strdup (cstr);
	}
	/* list r_cmd plugins */
	if (!strcmp (cstr, ":")) {
		RListIter *iter;
		RCmdPlugin *cp;
		r_list_foreach (core->rcmd->plist, iter, cp) {
			r_cons_printf ("%s: %s\n", cp->name, cp->desc);
		}
		return 0;
	}
	ocmd = cmd = malloc (strlen (cstr)+4096);
	if (ocmd == NULL)
		return R_FALSE;
	r_str_cpy (cmd, cstr);

	if (log) r_line_hist_add (cstr);

//eprintf ("DEPTH %d (%s)\n", core->cmd_depth, cstr);
	if (core->cmd_depth<1) {
		eprintf ("r_core_cmd: That was too deep (%s)...\n", cmd);
		free (ocmd);
		free (core->oobi);
		core->oobi = NULL;
		core->oobi_len = 0;
		return 0;
	}
	core->cmd_depth --;
	for (rcmd = cmd;;) {
		ptr = strstr (rcmd, "\n");
		if (ptr) *ptr = '\0';
		ret = r_core_cmd_subst (core, rcmd);
		if (ret == -1) {
			eprintf ("|ERROR| Invalid command '%s'\n", rcmd);
			break;
		}
		if (!ptr) break;
		rcmd = ptr+1;
	}
	core->cmd_depth ++;
	free (ocmd);
	free (core->oobi);
	core->oobi = NULL;
	core->oobi_len = 0;
	return ret;
}

R_API int r_core_cmd_lines(RCore *core, const char *lines) {
	int r, ret = R_TRUE;
	char *nl, *data, *odata;

	if (!lines || !*lines) return R_TRUE;
	data = odata = strdup (lines);
	nl = strchr (odata, '\n');
	if (nl) {
		do {
			*nl = '\0';
			r = r_core_cmd (core, data, 0);
			if (r == -1) {
				ret = R_FALSE;
				break;
			}
			r_cons_flush ();
			if (data[0]=='q') {
				if (data[1]=='!')
					ret = -1;
				else eprintf ("'q': quit ignored. Use 'q!'\n");
				break;
			}
			data = nl+1;
		} while ((nl = strchr (data, '\n')));
	}
	if (data && *data)
		r_core_cmd (core, data, 0);
	free (odata);
	return ret;
}

R_API int r_core_cmd_file(RCore *core, const char *file) {
	char *data, *odata;
	data = r_file_abspath (file);
	if (!data) return R_FALSE;
	odata = r_file_slurp (data, NULL);
	free (data);
	if (!odata) return R_FALSE;
	if (!r_core_cmd_lines (core, odata)) {
		eprintf ("Failed to run script '%s'\n", file);
		return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_core_cmd_command(RCore *core, const char *command) {
	int ret, len;
	char *buf, *rcmd, *ptr;
	rcmd = ptr = buf = r_sys_cmd_str (command, 0, &len);
	if (buf == NULL)
		return -1;
	ret = r_core_cmd (core, rcmd, 0);
	free (buf);
	return ret;
}

//TODO: Fix disasm loop is mandatory
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l) {
	char *cmd, *ret = NULL;
	cmd = r_str_newf ("pd %i @ 0x%08"PFMT64x, l, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b) {
	char *cmd, *ret = NULL;
	cmd = r_str_newf ("pD %i @ 0x%08"PFMT64x, b, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API int r_core_cmd_buffer(void *user, const char *buf) {
	char *ptr, *optr, *str = strdup (buf);
	optr = str;
	ptr = strchr (str, '\n');
	while (ptr) {
		*ptr = '\0';
		r_core_cmd (user, optr, 0);
		optr = ptr+1;
		ptr = strchr (str, '\n');
	}
	r_core_cmd (user, optr, 0);
	free (str);
	return R_TRUE;
}

R_API int r_core_cmdf(void *user, const char *fmt, ...) {
	char string[4096];
	int ret;
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_core_cmd ((RCore *)user, string, 0);
	va_end (ap);
	return ret;
}

R_API int r_core_cmd0(void *user, const char *cmd) {
	return r_core_cmd ((RCore *)user, cmd, 0);
}

R_API int r_core_flush(void *user, const char *cmd) {
	int ret = r_core_cmd ((RCore *)user, cmd, 0);
	r_cons_flush ();
	return ret;
}

R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd) {
	char *s, *tmp;
	r_sandbox_disable (1);
	if (r_sandbox_enable (0))
		return r_core_cmd_str (core, cmd);
	r_cons_reset ();
	if (r_file_mkstemp ("cmd", &tmp)) {
		char *_cmd = strdup (cmd);
		int pipefd = r_cons_pipe_open (tmp, 1, 0);
		r_sandbox_disable (0);
		r_core_cmd_subst (core, _cmd);
		r_cons_flush ();
		r_cons_pipe_close (pipefd);
		r_sandbox_disable (1);
		s = r_file_slurp (tmp, NULL);
		r_file_rm (tmp);
		r_sandbox_disable (0);
		free (tmp);
		free (_cmd);
		return s;
	}
	r_sandbox_disable (0);
	return NULL;
}

R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...) {
	char string[4096];
	char *ret;
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_core_cmd_str (core, string);
	va_end (ap);
	return ret;
}

/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	const char *static_str;
	char *retstr = NULL;
	r_cons_reset ();
	if (r_core_cmd (core, cmd, 0) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		return NULL;
	}
	r_cons_filter ();
	static_str = r_cons_get_buffer ();
	retstr = strdup (static_str? static_str: "");
	r_cons_reset ();
	return retstr;
}

R_API void r_core_cmd_repeat(RCore *core, int next) {
	// Fix for backtickbug px`~`
	if (core->cmd_depth+1<R_CORE_CMD_DEPTH)
		return;
	if (core->lastcmd)
	switch (*core->lastcmd) {
	case 'd': // debug
		r_core_cmd0 (core, core->lastcmd);
		switch (core->lastcmd[1]) {
		case 's':
		case 'c':
			r_core_cmd0 (core, "sr pc && pd 1");
		}
		break;
	case 'p': // print
	case 'x':
		r_core_cmd0 (core, next? "s++": "s--");
		r_core_cmd0 (core, core->lastcmd);
		break;
	}
}

static int cmd_ox(void *data, const char *input) {
	return r_core_cmdf ((RCore*)data, "s 0%s", input);
}

R_API void r_core_cmd_init(RCore *core) {
	core->rcmd = r_cmd_new ();
	core->rcmd->macro.user = core;
	core->rcmd->macro.num = core->num;
	core->rcmd->macro.cmd = r_core_cmd0;
	core->rcmd->nullcallback = r_core_cmd_nullcallback;
	core->rcmd->macro.printf = (PrintfCallback)r_cons_printf;
	r_cmd_set_data (core->rcmd, core);
	r_cmd_add (core->rcmd, "0x",       "alias for px", &cmd_ox);
	r_cmd_add (core->rcmd, "x",        "alias for px", &cmd_hexdump);
	r_cmd_add (core->rcmd, "mount",    "mount filesystem", &cmd_mount);
	r_cmd_add (core->rcmd, "analysis", "analysis", &cmd_anal);
	r_cmd_add (core->rcmd, "flag",     "get/set flags", &cmd_flag);
	r_cmd_add (core->rcmd, "g",        "egg manipulation", &cmd_egg);
	r_cmd_add (core->rcmd, "debug",    "debugger operations", &cmd_debug);
	r_cmd_add (core->rcmd, "info",     "get file info", &cmd_info);
	r_cmd_add (core->rcmd, "cmp",      "compare memory", &cmd_cmp);
	r_cmd_add (core->rcmd, "seek",     "seek to an offset", &cmd_seek);
	r_cmd_add (core->rcmd, "log",      "log utility", &cmd_log);
	r_cmd_add (core->rcmd, "t",        "type information (cparse)", &cmd_type);
	r_cmd_add (core->rcmd, "zign",     "zignatures", &cmd_zign);
	r_cmd_add (core->rcmd, "Section",  "setup section io information", &cmd_section);
	r_cmd_add (core->rcmd, "bsize",    "change block size", &cmd_bsize);
	r_cmd_add (core->rcmd, "eval",     "evaluate configuration variable", &cmd_eval);
	r_cmd_add (core->rcmd, "print",    "print current block", &cmd_print);
	r_cmd_add (core->rcmd, "write",    "write bytes", &cmd_write);
	r_cmd_add (core->rcmd, "Code",     "code metadata", &cmd_meta);
	r_cmd_add (core->rcmd, "Project",  "project", &cmd_project);
	r_cmd_add (core->rcmd, "open",     "open or map file", &cmd_open);
	r_cmd_add (core->rcmd, "yank",     "yank bytes", &cmd_yank);
	r_cmd_add (core->rcmd, "resize",   "change file size", &cmd_resize);
	r_cmd_add (core->rcmd, "Visual",   "enter visual mode", &cmd_visual);
	r_cmd_add (core->rcmd, "*",        "pointer read/write", &cmd_pointer);
	r_cmd_add (core->rcmd, "%",        "short version of 'env' command", &cmd_env);
	r_cmd_add (core->rcmd, "!",        "run system command", &cmd_system);
	r_cmd_add (core->rcmd, "=",        "io pipe", &cmd_rap);
	r_cmd_add (core->rcmd, "#",        "calculate hash", &cmd_hash);
	r_cmd_add (core->rcmd, "?",        "help message", &cmd_help);
	r_cmd_add (core->rcmd, "$",        "alias", &cmd_alias);
	r_cmd_add (core->rcmd, ".",        "interpret", &cmd_interpret);
	r_cmd_add (core->rcmd, "/",        "search kw, pattern aes", &cmd_search);
	r_cmd_add (core->rcmd, "-",        "open cfg.editor and run script", &cmd_stdin);
	r_cmd_add (core->rcmd, "(",        "macro", &cmd_macro);
	r_cmd_add (core->rcmd, "quit",     "exit program session", &cmd_quit);
}
