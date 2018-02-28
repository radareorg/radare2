/* radare - LGPL - Copyright 2009-2017 - nibble, pancake */
#if 0
* Use RList
* Support callback for null command (why?)
* Show help of commands
  - long commands not yet tested at all
  - added interface to export command list into an autocompletable
    argc, argv for dietline
* r_cmd must provide a nesting char table indexing for commands
  - this is already partially done
  - this is pretty similar to r_db
  - every module can register their own commands
  - commands can be listed like in a tree
#endif

#define INTERACTIVE_MAX_REP 1024

#include <r_core.h>
#include <r_anal.h>
#include <r_cons.h>
#include <r_cmd.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#if __UNIX__
#include <sys/utsname.h>
#endif

#define DEFINE_CMD_DESCRIPTOR(core, cmd_) \
	{ \
		RCmdDescriptor *d = R_NEW0 (RCmdDescriptor); \
		if (d) { \
			d->cmd = #cmd_; \
			d->help_msg = help_msg_##cmd_; \
			r_list_append (core->cmd_descriptors, d); \
		} \
	}

#define DEFINE_CMD_DESCRIPTOR_WITH_DETAIL(core, cmd_) \
	{ \
		RCmdDescriptor *d = R_NEW0 (RCmdDescriptor); \
		if (d) { \
			d->cmd = #cmd_; \
			d->help_msg = help_msg_##cmd_; \
			d->help_detail = help_detail_##cmd_; \
			r_list_append (core->cmd_descriptors, d); \
		} \
	}

#define DEFINE_CMD_DESCRIPTOR_WITH_DETAIL2(core, cmd_) \
	{ \
		RCmdDescriptor *d = R_NEW0 (RCmdDescriptor); \
		if (d) { \
			d->cmd = #cmd_; \
			d->help_msg = help_msg_##cmd_; \
			d->help_detail = help_detail_##cmd_; \
			d->help_detail2 = help_detail2_##cmd_; \
			r_list_append (core->cmd_descriptors, d); \
		} \
	}

#define DEFINE_CMD_DESCRIPTOR_SPECIAL(core, cmd_, named_cmd) \
	{ \
		RCmdDescriptor *d = R_NEW0 (RCmdDescriptor); \
		if (d) { \
			d->cmd = #cmd_; \
			d->help_msg = help_msg_##named_cmd; \
			r_list_append (core->cmd_descriptors, d); \
		} \
	}

static void cmd_debug_reg(RCore *core, const char *str);
#include "cmd_quit.c"
#include "cmd_hash.c"
#include "cmd_debug.c"
#include "cmd_log.c"
#include "cmd_zign.c"
#include "cmd_section.c"
#include "cmd_flag.c"
#include "cmd_project.c"
#include "cmd_write.c"
#include "cmd_cmp.c"
#include "cmd_eval.c"
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

static const char *help_msg_dollar[] = {
	"Usage:", "$alias[=cmd] [args...]", "Alias commands",
	"$", "", "list all defined aliases",
	"$*", "", "same as above, but using r2 commands",
	"$", "dis='af;pdf'", "create command - analyze to show function",
	"$", "test=#!pipe node /tmp/test.js", "create command - rlangpipe script",
	"$", "dis=", "undefine alias",
	"$", "dis", "execute the previously defined alias",
	"$", "dis?", "show commands aliased by 'analyze'",
	NULL
};

static const char *help_msg_percent[] = {
	"Usage:", "%[name[=value]]", "Set each NAME to VALUE in the environment",
	"%", "", "list all environment variables",
	"%", "SHELL", "prints SHELL value",
	"%", "TMPDIR=/tmp", "sets TMPDIR value to \"/tmp\"",
	NULL
};

static const char *help_msg_star[] = {
	"Usage:", "*<addr>[=[0x]value]", "Pointer read/write data/values",
	"*", "entry0=cc", "write trap in entrypoint",
	"*", "entry0+10=0x804800", "write value in delta address",
	"*", "entry0", "read byte at given address",
	"TODO: last command should honor asm.bits", "", "",
	NULL
};

static const char *help_msg_dot[] = {
	"Usage:", ".[r2cmd] | [file] | [!command] | [(macro)]", " # define macro or load r2, cparse or rlang file",
	".", "", "repeat last command backward",
	".", "r2cmd", "interpret the output of the command as r2 commands",
	"..", " [file]", "run the output of the execution of a script as r2 commands",
	"...", "", "repeat last command forward (same as \\n)",
	".:", "8080", "listen for commands on given tcp port",
	".--", "", "terminate tcp server for remote commands",
	".", " foo.r2", "interpret r2 script",
	".-", "", "open cfg.editor and interpret tmp file",
	".!", "rabin -ri $FILE", "interpret output of command",
	".", "(foo 1 2 3)", "run macro 'foo' with args 1, 2, 3",
	"./", " ELF", "interpret output of command /m ELF as r. commands",
	NULL
};

static const char *help_msg_equal[] = {
	"Usage:", " =[:!+-=hH] [...]", " # radare remote command execution protocol",
	"\nrap commands:", "", "",
	"=", "", "list all open connections",
	"=<", "[fd] cmd", "send output of local command to remote fd",
	"=", "[fd] cmd", "exec cmd at remote 'fd' (last open is default one)",
	"=!", " cmd", "run command via r_io_system",
	"=+", " [proto://]host", "add host (default=rap://, tcp://, udp://)",
	"=-", "[fd]", "remove all hosts or host 'fd'",
	"==", "[fd]", "open remote session with host 'fd', 'q' to quit",
	"=!=", "", "disable remote cmd mode",
	"!=!", "", "enable remote cmd mode",
	"\nrap server:","","",
	"=", ":port", "listen on given port using rap protocol (o rap://9999)",
	"=&", ":port", "start rap server in background",
	"=", ":host:port cmd", "run 'cmd' command on remote server",
	"\nother servers:","","",
	"=h", "[?]", "listen for http connections",
	"=g", "[?]", "using gdbserver",
	NULL
};

#if 0
static const char *help_msg_equalh[] = {
	"Usage:",  "=h[---*&] [port]", " # manage http connections",
	"=h", " port", "listen for http connections (r2 -qc=H /bin/ls)",
	"=h-", "", "stop background webserver",
	"=h--", "", "stop foreground webserver",
	"=h*", "", "restart current webserver",
	"=h&", " port", "start http server in background",
	NULL
};
#endif

static const char *help_msg_equalh[] = {
	"Usage:", " =[hH] [...]", " # http server",
	"http server:", "", "",
	"=h", " port", "listen for http connections (r2 -qc=H /bin/ls)",
	"=h-", "", "stop background webserver",
	"=h--", "", "stop foreground webserver",
	"=h*", "", "restart current webserver",
	"=h&", " port", "start http server in background",
	"=H", " port", "launch browser and listen for http",
	"=H&", " port", "launch browser and listen for http in background",
	NULL
};

static const char *help_msg_equalg[] = {
	"Usage:", " =[g] [...]", " # gdb server",
	"gdbserver:", "", "",
	"=g", " port file [args]", "listen on 'port' debugging 'file' using gdbserver",
	"=g!", " port file [args]", "same as above, but debug protocol messages (like gdbserver --remote-debug)",
	NULL
};

static const char *help_msg_b[] = {
	"Usage:",  "b[f] [arg]\n", "Get/Set block size",
	"b", "", "display current block size",
	"b", " 33", "set block size to 33",
	"b", "+3", "increase blocksize by 3",
	"b", "-16", "decrease blocksize by 16",
	"b", " eip+4", "numeric argument can be an expression",
	"bf", " foo", "set block size to flag size",
	"bm", " 1M", "set max block size",
	NULL
};

static const char *help_msg_k[] = {
	"Usage:", "k[s] [key[=value]]", "Sdb Query",
	"k", " foo=bar", "set value",
	"k", " foo", "show value",
	"k", "", "list keys",
	"ko", " [file.sdb] [ns]", "open file into namespace",
	"kd", " [file.sdb] [ns]", "dump namespace to disk",
	"ks", " [ns]", "enter the sdb query shell",
	"k", " anal/meta/*", "ist kv from anal > meta namespaces",
	"k", " anal/**", "list namespaces under anal",
	"k", " anal/meta/meta.0x80404", "get value for meta.0x80404 key",
	//"kl", " ha.sdb", "load keyvalue from ha.sdb",
	//"ks", " ha.sdb", "save keyvalue to ha.sdb",
	NULL,
};

static const char *help_msg_r[] = {
	"Usage:", "r[+-][ size]", "Resize file",
	"r", "", "display file size",
	"r", " size", "expand or truncate file to given size",
	"r-", "num", "remove num bytes, move following data down",
	"r+", "num", "insert num bytes, move following data up",
	"rm" ," [file]", "remove file",
	"rh" ,"", "show size in human format",
	"r2" ," [file]", "launch r2",
	NULL
};

static const char *help_msg_u[] = {
	"Usage:", "u", "uname or undo write/seek",
	"u", "", "show system uname",
	"uw", "", "alias for wc (requires: e io.cache=true)",
	"us", "", "alias for s- (seek history)",
	NULL
};

static const char *help_msg_y[] = {
	"Usage:", "y[ptxy] [len] [[@]addr]", " # See wd? for memcpy, same as 'yf'.",
	"y", "", "show yank buffer information (srcoff len bytes)",
	"y", " 16", "copy 16 bytes into clipboard",
	"y", " 16 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16 @ 0x200", "copy 16 bytes into clipboard from 0x200",
	"yz", "", "copy up to blocksize zero terminated string bytes into clipboard",
	"yz", " 16", "copy up to 16 zero terminated string bytes into clipboard",
	"yz", " @ 0x200", "copy up to blocksize zero terminated string bytes into clipboard from 0x200",
	"yz", " 16 @ 0x200", "copy up to 16 zero terminated string bytes into clipboard from 0x200",
	"yp", "", "print contents of clipboard",
	"yx", "", "print contents of clipboard in hexadecimal",
	"ys", "", "print contents of clipboard as string",
	"yt", " 64 0x200", "copy 64 bytes from current seek to 0x200",
	"ytf", " file", "dump the clipboard to given file",
	"yf", " 64 0x200", "file copy 64 bytes from 0x200 from file (opens w/ io), use -1 for all bytes",
	"yfa", " file copy", "copy all bytes from file (opens w/ io)",
	"yy", " 0x3344", "paste clipboard",
	NULL
};

R_API void r_core_cmd_help(const RCore *core, const char *help[]) {
	r_cons_cmd_help (help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static void recursive_help_go(RCore *core, int detail, RCmdDescriptor *desc) {
	int i;
	if (desc->help_msg) {
		r_core_cmd_help (core, desc->help_msg);
	}
	if (detail >= 1) {
		if (desc->help_detail) {
			r_core_cmd_help (core, desc->help_detail);
		}
		if (detail >= 2 && desc->help_detail2) {
			r_core_cmd_help (core, desc->help_detail2);
		}
	}
	for (i = 32; i < R_ARRAY_SIZE (desc->sub); i++)
		if (desc->sub[i]) {
			recursive_help_go (core, detail, desc->sub[i]);
		}
}

static void recursive_help(RCore *core, int detail, const char *cmd_prefix) {
	const ut8 *p;
	RCmdDescriptor *desc = &core->root_cmd_descriptor;
	for (p = (const ut8 *)cmd_prefix; *p && *p < R_ARRAY_SIZE (desc->sub); p++) {
		if (!(desc = desc->sub[*p])) {
			return;
		}
	}
	recursive_help_go (core, detail, desc);
}

static int r_core_cmd_nullcallback(void *data) {
	RCore *core = (RCore*) data;
	if (core->cons->breaked) {
		core->cons->breaked = false;
		return 0;
	}
	if (!core->cmdrepeat) {
		return 0;
	}
	r_core_cmd_repeat (core, true);
	return 1;
}

// TODO: move somewhere else
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr) {
	int delta;
	ut8 buf[128];
	static RBuffer *b = NULL; // XXX: never freed and non-thread safe. move to RCore
	RAsmOp *op;
	if (!b) {
		b = r_buf_new ();
		if (!b || !r_core_read_at (core, addr, buf, sizeof (buf))) {
			return NULL;
		}
		b->base = addr;
		r_buf_set_bytes (b, buf, sizeof (buf));
	} else {
		if ((addr < b->base) || addr > (b->base + b->length - 32)) {
			if (!r_core_read_at (core, addr, buf, sizeof (buf))) {
				return NULL;
			}
			b->base = addr;
			r_buf_set_bytes (b, buf, sizeof (buf));
		}
	}
	delta = addr - b->base;
	op = R_NEW0 (RAsmOp);
	r_asm_set_pc (core->assembler, addr);
	if (r_asm_disassemble (core->assembler, op, b->buf + delta, b->length) < 1) {
		free (op);
		return NULL;
	}
	return op;
}

static int cmd_uname(void *data, const char *input) {
	switch (input[0]) {
	case '?': // "u?"
		r_core_cmd_help (data, help_msg_u);
		return 1;
	case 's': // "us"
		r_core_cmdf (data, "s-%s", input + 1);
		return 1;
	case 'w': // "uw"
		r_core_cmdf (data, "wc%s", input + 1);
		return 1;
	}
#if __UNIX__
	struct utsname un;
	uname (&un);
	r_cons_printf ("%s %s %s %s\n", un.sysname,
		un.nodename, un.release, un.machine);
#elif __WINDOWS__
	r_cons_printf ("windows\n");
#else
	r_cons_printf ("unknown\n");
#endif
	return 0;
}

static int cmd_alias(void *data, const char *input) {
	int i;
	char *def, *q, *desc, *buf;
	RCore *core = (RCore *)data;
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_dollar);
		return 0;
	}
	i = strlen (input);
	buf = malloc (i + 2);
	if (!buf) {
		return 0;
	}
	*buf = '$'; // prefix aliases with a dash
	memcpy (buf + 1, input, i + 1);
	q = strchr (buf, ' ');
	def = strchr (buf, '=');
	desc = strchr (buf, '?');

	/* create alias */
	if ((def && q && (def < q)) || (def && !q)) {
		*def++ = 0;
		size_t len = strlen (def);
		/* Remove quotes */
		if ((def[0] == '\'') && (def[len - 1] == '\'')) {
			def[len - 1] = 0x00;
			def++;
		}
		if (!q || (q && q>def)) {
			if (*def) r_cmd_alias_set (core->rcmd, buf, def, 0);
			else r_cmd_alias_del (core->rcmd, buf);
		}
	/* Show command for alias */
	} else if (desc && !q) {
		*desc = 0;
		char *v = r_cmd_alias_get (core->rcmd, buf, 0);
		if (v) {
			r_cons_println (v);
			free (buf);
			return 1;
		} else {
			eprintf ("unknown key '%s'\n", buf);
		}
	} else if (buf[1] == '*') {
		/* Show aliases */
		int i, count = 0;
		char **keys = r_cmd_alias_keys (core->rcmd, &count);
		for (i = 0; i < count; i++) {
			const char *v = r_cmd_alias_get (core->rcmd, keys[i], 0);
			r_cons_printf ("%s=%s\n", keys[i], v);
		}
	} else if (!buf[1]) {
		int i, count = 0;
		char **keys = r_cmd_alias_keys (core->rcmd, &count);
		for (i = 0; i < count; i++) {
			r_cons_println (keys[i]);
		}
	} else {
		/* Execute alias */
		if (q) {
			*q = 0;
		}
		char *v = r_cmd_alias_get (core->rcmd, buf, 0);
		if (v) {
			if (q) {
				char *out, *args = q + 1;
				out = malloc (strlen (v) + strlen (args) + 2);
				if (out) { //XXX slow
					strcpy (out, v);
					strcat (out, " ");
					strcat (out, args);
					r_core_cmd0 (core, out);
					free (out);
				} else {
					eprintf ("cannot malloc\n");
				}
			} else {
				r_core_cmd0 (core, v);
			}
		} else {
			eprintf ("unknown key '%s'\n", buf);
		}
	}
	free (buf);
	return 0;
}

static int getArg(char ch, int def) {
	switch (ch) {
	case '&':
	case '-':
		return ch;
	}
	return def;
}

static void aliascmd(RCore *core, const char *str) {
	switch (str[0]) {
	case '\0': // "=$"
		r_core_cmd0 (core, "$");
		break;
	case '-': // "=$-"
		if (str[1]) {
			r_cmd_alias_del (core->rcmd, str + 2);
		} else {
			r_cmd_alias_del (core->rcmd, NULL);
		//	r_cmd_alias_reset (core->rcmd);
		}
		break;
	case '?': // "=$?"
		eprintf ("Usage: =$[-][remotecmd]  # remote command alias\n");
		eprintf (" =$dr   # makes 'dr' alias for =!dr\n");
		eprintf (" =$-dr  # unset 'dr' alias\n");
		break;
	default:
		r_cmd_alias_set (core->rcmd, str, "", 1);
		break;
	}
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0': // "="
		r_core_rtr_list (core);
		break;
	case '!': // "=!"
		if (input[1] == '=') {
			// swap core->cmdremote = core->cmdremote? 0: 1;
			core->cmdremote = input[2]? 1: 0;
			r_cons_println (r_str_bool (core->cmdremote));
		} else {
			char *res = r_io_system (core->io, input + 1);
			if (res) {
				r_cons_printf ("%s\n", res);
				free (res);
			}
		}
		break;
	case '$': // "=$"
		aliascmd (core, input + 1);
		break;
	case '+': // "=+"
		r_core_rtr_add (core, input + 1);
		break;
	case '-': // "=-"
		r_core_rtr_remove (core, input + 1);
		break;
	//case ':': r_core_rtr_cmds (core, input + 1); break;
	case '<': // "=<"
		r_core_rtr_pushout (core, input + 1);
		break;
	case '=': // "=="
		r_core_rtr_session (core, input + 1);
		break;
	case 'g': // "=g"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_equalg);
		} else {
			r_core_rtr_gdb (core, getArg (input[1], 'g'), input + 1);
		}
		break;
	case 'h': // "=h"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_equalh);
		} else {
			r_core_rtr_http (core, getArg (input[1], 'h'), input + 1);
		}
		break;
	case 'H': // "=H"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_equalh);
		} else {
			while (input[1] == ' ') {
				input++;
			}
			r_core_rtr_http (core, getArg (input[1], 'H'), input + 1);
		}
		break;
	case '?': // "=?"
		r_core_cmd_help (core, help_msg_equal);
		break;
	default:
		r_core_rtr_cmd (core, input);
		break;
	}
	return 0;
}

static int cmd_rap_run(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *res = r_io_system (core->io, input);
	if (res) {
		int ret = atoi (res);
		free (res);
		return ret;
	}
	return false;
}

static int cmd_yank(void *data, const char *input) {
	ut64 n;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ': // "y "
		r_core_yank (core, core->offset, r_num_math (core->num, input + 1));
		break;
	case 'l': // "yl"
		core->num->value = core->yank_buf->length;
		break;
	case 'y': // "yy"
		while (input[1] == ' ') {
			input++;
		}
		n = input[1]? r_num_math (core->num, input + 1): core->offset;
		r_core_yank_paste (core, n, 0);
		break;
	case 'x': // "yx"
		r_core_yank_hexdump (core, r_num_math (core->num, input + 1));
		break;
	case 'z': // "yz"
		r_core_yank_string (core, core->offset, r_num_math (core->num, input + 1));
		break;
	case 'w': // "yw"
		switch (input[1]) {
		case ' ':
			r_core_yank_set (core, 0, (const ut8*)input + 2, strlen (input + 2));
			break;
		case 'x':
			if (input[2] == ' ') {
				char *out = strdup (input + 3);
				int len = r_hex_str2bin (input + 3, (ut8*)out);
				if (len> 0) {
					r_core_yank_set (core, 0LL, (const ut8*)out, len);
				} else {
					eprintf ("Invalid length\n");
				}
				free (out);
			} else {
				eprintf ("Usage: ywx [hexpairs]\n");
			}
			// r_core_yank_write_hex (core, input + 2);
			break;
		}
		break;
	case 'p': // "yp"
		r_core_yank_cat (core, r_num_math (core->num, input + 1));
		break;
	case 's': // "ys"
		r_core_yank_cat_string (core, r_num_math (core->num, input + 1));
		break;
	case 't': // "wt"
		if (input[1] == 'f') { // "wtf"
			const char *file = r_str_trim_ro (input + 2);
			if (!r_file_dump (file, core->yank_buf->buf, core->yank_buf->length, false)) {
				eprintf ("Cannot dump to '%s'\n", file);
			}
		} else {
			r_core_yank_to (core, input + 1);
		}
		break;
	case 'f': // "yf"
		switch (input[1]) {
		case ' ': // "wf"
			r_core_yank_file_ex (core, input + 1);
			break;
		case 'a': // "wfa"
			r_core_yank_file_all (core, input + 2);
			break;
		}
		break;
	case '\0': // "y"
		r_core_yank_dump (core, r_num_math (core->num, ""));
		break;
	default:
		r_core_cmd_help (core, help_msg_y);
		break;
	}
	return true;
}

R_API int r_core_run_script (RCore *core, const char *file) {
	int ret = false;
	RListIter *iter;
	RLangPlugin *p;
	char *name;

	r_list_foreach (core->scriptstack, iter, name) {
		if (!strcmp (file, name)) {
			eprintf ("WARNING: ignored nested source: %s\n", file);
			return false;
		}
	}
	r_list_push (core->scriptstack, strdup (file));

	if (!strcmp (file, "-")) {
		char *out = r_core_editor (core, NULL, NULL);
		if (out) {
			ret = r_core_cmd_lines (core, out);
			free (out);
		}
	} else if (r_parse_is_c_file (file)) {
		char *out = r_parse_c_file (core->anal, file);
		if (out) {
			r_cons_strcat (out);
			sdb_query_lines (core->anal->sdb_types, out);
			free (out);
		}
		ret = out? true: false;
	} else {
		p = r_lang_get_by_extension (core->lang, file);
		r_core_sysenv_begin (core, NULL);
		if (p) {
			r_lang_use (core->lang, p->name);
			ret = r_lang_run_file (core->lang, file);
		} else {
#if __WINDOWS__
#define cmdstr(x) r_str_newf (x" %s", file);
#else
#define cmdstr(x) r_str_newf (x" '%s'", file);
#endif
			const char *p = r_str_lchr (file, '.');
			if (p) {
				const char *ext = p + 1;
				/* TODO: handle this inside r_lang_pipe with new APIs */
				if (!strcmp (ext, "js")) {
					char *cmd = cmdstr ("node");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "exe")) {
#if __WINDOWS__
					char *cmd = r_str_newf ("%s", file);
#else
					char *cmd = cmdstr ("wine");
#endif
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "d")) {
					char *cmd = cmdstr ("dmd -run");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "lsp")) {
					char *cmd = cmdstr ("newlisp -n");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "go")) {
					char *cmd = cmdstr ("go run");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "es6")) {
					char *cmd = cmdstr ("babel-node");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "rb")) {
					char *cmd = cmdstr ("ruby");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "vala")) {
					r_lang_use (core->lang, "vala");
					r_lang_run_file (core->lang, file);
					ret = 1;
				} else if (!strcmp (ext, "pl")) {
					char *cmd = cmdstr ("perl");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "py")) {
					char *cmd = cmdstr ("python");
					r_lang_use (core->lang, "pipe");
					r_lang_run_file (core->lang, cmd);
					free (cmd);
					ret = 1;
				}
			}
			if (!ret) {
				ret = r_core_cmd_file (core, file);
			}
		}
	}
	free (r_list_pop (core->scriptstack));
	return ret;
}

static int cmd_ls(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (*input) {
		const char *path = r_str_trim_ro (input + 1);
		if (r_fs_check (core->fs, path)) {
			r_core_cmdf (core, "md %s", path);
		} else {
			char *res = r_syscmd_ls (path);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
	}
	return 0;
}

static int cmd_stdin(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == '?') {
		r_cons_printf ("Usage: '-' '.-' '. -' do the same\n");
		return false;
	}
	return r_core_run_script (core, "-");
}

static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol, *rbuf, *filter, *inp;
	const char *host, *port, *cmd;
	RCore *core = (RCore *)data;

	switch (*input) {
	case '\0': // "."
		r_core_cmd_repeat (core, 0);
		break;
	case ':': // ".:"
		if ((ptr = strchr (input + 1, ' '))) {
			/* .:port cmd */
			/* .:host:port cmd */
			cmd = ptr + 1;
			*ptr = 0;
			eol = strchr (input + 1, ':');
			if (eol) {
				*eol = 0;
				host = input + 1;
				port = eol + 1;
			} else {
				host = "localhost";
				port = input + ((input[1] == ':')? 2: 1);
			}
			rbuf = r_core_rtr_cmds_query (core, host, port, cmd);
			if (rbuf) {
				r_cons_print (rbuf);
				free (rbuf);
			}
		} else {
			r_core_rtr_cmds (core, input + 1);
		}
		break;
	case '.': // ".." same as \n
		if (input[1] == '.') { // ... same as \n with e cmd.repeat=true
			r_core_cmd_repeat (core, 1);
		} else {
			char *str = r_core_cmd_str_pipe (core, input);
			if (str) {
				r_core_cmd (core, str, 0);
				free (str);
			}
		}
		break;
	case '-': // ".-"
		if (input[1] == '?') {
			r_cons_printf ("Usage: '-' '.-' '. -' do the same\n");
		} else {
			r_core_run_script (core, "-");
		}
		break;
	case ' ': // ". "
		if (!r_core_run_script (core, input + 1)) {
			eprintf ("Cannot find script '%s'\n", input + 1);
			core->num->value = 1;
		} else {
			core->num->value = 0;
		}
		break;
	case '!': // ".!"
		/* from command */
		r_core_cmd_command (core, input + 1);
		break;
	case '(': // ".("
		r_cmd_macro_call (&core->rcmd->macro, input + 1);
		break;
	case '?': // ".?"
		r_core_cmd_help (core, help_msg_dot);
		break;
	default:
		if (*input >= 0 && *input <= 9) {
			eprintf ("|ERROR| No .[0..9] to avoid infinite loops\n");
			break;
		}
		inp = strdup (input);
		filter = strchr (inp, '~');
		if (filter) {
			*filter = 0;
		}
		ptr = str = r_core_cmd_str (core, inp);
		if (filter) {
			*filter = '~';
		}
		r_cons_break_push (NULL, NULL);
		if (ptr) {
			for (;;) {
				if (r_cons_is_breaked ()) {
					break;
				}
				eol = strchr (ptr, '\n');
				if (eol) {
					*eol = '\0';
				}
				if (*ptr) {
					char *p = r_str_append (strdup (ptr), filter);
					r_core_cmd0 (core, p);
					free (p);
				}
				if (!eol) {
					break;
				}
				ptr = eol + 1;
			}
		}
		r_cons_break_pop ();
		free (str);
		free (inp);
		break;
	}
	return 0;
}

static int callback_foreach_kv (void *user, const char *k, const char *v) {
	r_cons_printf ("%s=%s\n", k, v);
	return 1;
}

static int cmd_kuery(void *data, const char *input) {
	char buf[1024], *out;
	RCore *core = (RCore*)data;
	const char *sp, *p = "[sdb]> ";
	const int buflen = sizeof (buf) - 1;
	Sdb *s = core->sdb;

	switch (input[0]) {
	case ' ':
		out = sdb_querys (s, NULL, 0, input + 1);
		if (out) {
			r_cons_println (out);
		}
		free (out);
		break;
	//case 's': r_pair_save (s, input + 3); break;
	//case 'l': r_pair_load (sdb, input + 3); break;
	case '\0':
		sdb_foreach (s, callback_foreach_kv, NULL);
		break;
	// TODO: add command to list all namespaces // sdb_ns_foreach ?
	case 's':
		if (core->http_up) {
			return false;
		}
		if (!r_config_get_i (core->config, "scr.interactive")) {
			return false;
		}
		if (input[1] == ' ') {
			char *n, *o, *p = strdup (input + 2);
			// TODO: slash split here? or inside sdb_ns ?
			for (n = o = p; n; o = n) {
				n = strchr (o, '/'); // SDB_NS_SEPARATOR NAMESPACE
				if (n) *n++ = 0;
				s = sdb_ns (s, o, 1);
			}
			free (p);
		}
		if (!s) s = core->sdb;
		for (;;) {
			r_line_set_prompt (p);
			if (r_cons_fgets (buf, buflen, 0, NULL) < 1) {
				break;
			}
			if (!*buf) {
				break;
			}
			out = sdb_querys (s, NULL, 0, buf);
			if (out) {
				r_cons_println (out);
			}
		}
		break;
	case 'o':
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == ' ') {
			char *fn = strdup (input + 2);
			if (!fn) {
				eprintf("Unable to allocate memory\n");
				return 0;
			}
			char *ns = strchr (fn, ' ');
			if (ns) {
				Sdb *db;
				*ns++ = 0;
				if (r_file_exists (fn)) {
					db = sdb_ns_path (core->sdb, ns, 1);
					if (db) {
						Sdb *newdb = sdb_new (NULL, fn, 0);
						if (newdb) {
							sdb_drain  (db, newdb);
						} else {
							eprintf ("Cannot open sdb '%s'\n", fn);
						}
					} else eprintf ("Cannot find sdb '%s'\n", ns);
				} else eprintf ("Cannot open file\n");
			} else eprintf ("Missing sdb namespace\n");
			free (fn);
		} else {
			eprintf ("Usage: ko [file] [namespace]\n");
		}
		break;
	case 'd':
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == ' ') {
			char *fn = strdup (input + 2);
			char *ns = strchr (fn, ' ');
			if (ns) {
				*ns++ = 0;
				Sdb *db = sdb_ns_path (core->sdb, ns, 0);
				if (db) {
					sdb_file (db, fn);
					sdb_sync (db);
				} else eprintf ("Cannot find sdb '%s'\n", ns);
			} else eprintf ("Missing sdb namespace\n");
			free (fn);
		} else {
			eprintf ("Usage: kd [file] [namespace]\n");
		}
		break;
	case '?': {
			r_core_cmd_help (core, help_msg_k);
		}
		break;
	}

	if (input[0] == '\0') {
		/* nothing more to do, the command has been parsed. */
		return 0;
	}

	sp = strchr (input + 1, ' ');
	if (sp) {
		char *inp = strdup (input);
		inp [(size_t)(sp - input)] = 0;
		s = sdb_ns (core->sdb, inp + 1, 1);
		out = sdb_querys (s, NULL, 0, sp + 1);
		if (out) {
			r_cons_println (out);
			free (out);
		}
		free (inp);
		return 0;
	}
	return 0;
}

static int cmd_bsize(void *data, const char *input) {
	ut64 n;
	RFlagItem *flag;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'm': // "bm"
		n = r_num_math (core->num, input + 1);
		if (n > 1) core->blocksize_max = n;
		else r_cons_printf ("0x%x\n", (ut32)core->blocksize_max);
		break;
	case '+': // "b+"
		n = r_num_math (core->num, input + 1);
		r_core_block_size (core, core->blocksize + n);
		break;
	case '-': // "b-"
		n = r_num_math (core->num, input + 1);
		r_core_block_size (core, core->blocksize - n);
		break;
	case 'f': // "bf"
		if (input[1] == ' ') {
			flag = r_flag_get (core->flags, input + 2);
			if (flag) {
				r_core_block_size (core, flag->size);
			} else {
				eprintf ("bf: cannot find flag named '%s'\n", input + 2);
			}
		} else {
			eprintf ("Usage: bf [flagname]\n");
		}
		break;
	case '\0': // "b"
		r_cons_printf ("0x%x\n", core->blocksize);
		break;
	case '?': // "b?"
		r_core_cmd_help (core, help_msg_b);
		break;
	default:
		r_core_block_size (core, r_num_math (core->num, input));
		break;
	}
	return 0;
}

static int cmd_resize(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 newsize = 0;
	st64 delta = 0;
	int grow, ret;

	ut64 oldsize = (core->file) ? r_io_fd_size (core->io, core->file->fd): 0;
	switch (*input) {
	case '2': // "r2"
		// TODO: use argv[0] instead of 'radare2'
		r_sys_cmdf ("radare%s", input);
		return true;
	case 'm': // "rm"
		if (input[1] == ' ') {
			r_file_rm (input + 2);
		} else {
			eprintf ("Usage: rm [file]   # removes a file\n");
		}
		return true;
	case '\0':
		if (core->file) {
			if (oldsize != -1) {
				r_cons_printf ("%"PFMT64d"\n", oldsize);
			}
		}
		return true;
	case 'h':
		if (core->file) {
			if (oldsize != -1) {
				char *s = r_num_units (NULL, oldsize);
				r_cons_printf ("%s\n", s);
				free (s);
			}
		}
		return true;
	case '+': // "r+"
	case '-': // "r-"
		delta = (st64)r_num_math (core->num, input);
		newsize = oldsize + delta;
		break;
	case ' ': // "r "
		newsize = r_num_math (core->num, input + 1);
		if (newsize == 0) {
			if (input[1] == '0') {
				eprintf ("Invalid size\n");
			}
			return false;
		}
		break;
	case '?': // "r?"
	default:
		r_core_cmd_help (core, help_msg_r);
		return true;
	}

	grow = (newsize > oldsize);
	if (grow) {
		ret = r_io_resize (core->io, newsize);
		if (ret < 1) {
			eprintf ("r_io_resize: cannot resize\n");
		}
	}

	if (delta && core->offset < newsize)
		r_io_shift (core->io, core->offset, grow?newsize:oldsize, delta);

	if (!grow) {
		ret = r_io_resize (core->io, newsize);
		if (ret < 1) {
			eprintf ("r_io_resize: cannot resize\n");
		}
	}

	if (newsize < core->offset+core->blocksize || oldsize < core->offset + core->blocksize) {
		r_core_block_read (core);
	}
	return true;
}

static int cmd_visual(void *data, const char *input) {
	RCore *core = (RCore*) data;
	if (core->http_up) {
		return false;
	}
	if (!r_config_get_i (core->config, "scr.interactive")) {
		return false;
	}
#if 0
	char *buf = strdup (input);
	int len = r_str_unescape (buf);
	r_cons_readpush (buf, len);
	free (buf);
	int res = r_core_visual ((RCore *)data, ""); //input);
	r_cons_readflush ();
	return res;
#else
	return r_core_visual ((RCore *)data, input);
#endif
}

static int cmd_pipein(void *user, const char *input) {
	char *buf = strdup (input);
	int len = r_str_unescape (buf);
	r_cons_readpush (buf, len);
	free (buf);
	return 0;
}

static int task_finished(void *user, void *data) {
	eprintf ("TASK FINISHED\n");
	return 0;
}

static int taskbgrun(RThread *th) {
	char *res;
	RCoreTask *task = th->user;
	RCore *core = task->core;
	close (2); // no stderr
	res = r_core_cmd_str (core, task->msg->text);
	task->msg->res = res;
	task->state = 'd';
	eprintf ("Task %d finished\n", task->id);
// TODO: run callback and pass result
	return 0;
}

static int cmd_thread(void *data, const char *input) {
	RCore *core = (RCore*) data;
	if (r_sandbox_enable (0)) {
		eprintf ("This command is disabled in sandbox mode\n");
		return 0;
	}
	switch (input[0]) {
	case '\0':
	case 'j':
		r_core_task_list (core, *input);
		break;
	case '&':
		if (input[1] == '&') {
			// wait until ^C
		} else {
			int tid = r_num_math (core->num, input + 1);
			if (tid) {
				RCoreTask *task = r_core_task_get (core, tid);
				if (task) {
					r_core_task_join (core, task);
				} else {
					eprintf ("Cannot find task\n");
				}
			} else {
				r_core_task_run (core, NULL);
			}
		}
		break;
	case '=': {
		int tid = r_num_math (core->num, input + 1);
		if (tid) {
			RCoreTask *task = r_core_task_get (core, tid);
			if (task) {
				r_cons_printf ("Task %d Status %c Command %s\n",
					task->id, task->state, task->msg->text);
				if (task->msg->res)
					r_cons_println (task->msg->res);
			} else eprintf ("Cannot find task\n");
		} else {
			r_core_task_list (core, 1);
		}}
		break;
	case '+':
		r_core_task_add (core, r_core_task_new (core, input + 1, (RCoreTaskCallback)task_finished, core));
		break;
	case '-':
		if (input[1] == '*') {
			r_core_task_del (core, -1);
		} else {
			r_core_task_del (core, r_num_math (core->num, input + 1));
		}
		break;
	case '?':
		helpCmdTasks (core);
		break;
	case ' ':
		{
			int tid = r_num_math (core->num, input + 1);
			if (tid) {
				RCoreTask *task = r_core_task_get (core, tid);
				if (task) {
					r_core_task_join (core, task);
				} else {
					eprintf ("Cannot find task\n");
				}
			} else {
				RCoreTask *task = r_core_task_add (core, r_core_task_new (
							core, input + 1, (RCoreTaskCallback)task_finished, core));
				RThread *th = r_th_new (taskbgrun, task, 0);
				task->msg->th = th;
			}
			//r_core_cmd0 (core, task->msg->text);
			//r_core_task_del (core, task->id);
		}
		break;
	default:
		eprintf ("&?\n");
		break;
	}
	return 0;
}

static int cmd_pointer(void *data, const char *input) {
	RCore *core = (RCore*) data;
	int ret = true;
	char *str, *eq;
	input = r_str_trim_ro (input);
	while (*input == ' ') {
		input++;
	}
	if (!*input || *input == '?') {
		r_core_cmd_help (core, help_msg_star);
		return ret;
	}
	str = strdup (input);
	eq = strchr (str, '=');
	if (eq) {
		*eq++ = 0;
		if (!strncmp (eq, "0x", 2)) {
			ret = r_core_cmdf (core, "wv %s@%s", eq, str);
		} else {
			ret = r_core_cmdf (core, "wx %s@%s", eq, str);
		}
	} else {
		ret = r_core_cmdf (core, "?v [%s]", input);
	}
	free (str);
	return ret;
}

static int cmd_env(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int ret = true;
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_percent);
		break;
	default:
		ret = r_core_cmdf (core, "env %s", input);
	}
	return ret;
}

static int cmd_system(void *data, const char *input) {
	RCore *core = (RCore*)data;
	ut64 n;
	int ret = 0;
	switch (*input) {
	case '-':
		if (input[1]) {
			r_line_hist_free();
			r_line_hist_save (R2_HOMEDIR"/history");
		} else {
			r_line_hist_free();
		}
		break;
	case '=':
		if (input[1] == '?') {
			r_cons_printf ("Usage: !=[!]  - enable/disable remote commands\n");
		} else {
			if (!r_sandbox_enable (0)) {
				core->cmdremote = input[1]? 1: 0;
				r_cons_println (r_str_bool (core->cmdremote));
			}
		}
		break;
	case '!':
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1]) {
			int olen;
			char *out = NULL;
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				ret = r_sys_cmd_str_full (cmd + 1, NULL, &out, &olen, NULL);
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
		r_core_sysenv_help (core);
		break;
	default:
		n = atoi (input);
		if (*input == '0' || n > 0) {
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

#if __WINDOWS__ && !__CYGWIN__
static void r_w32_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	SECURITY_ATTRIBUTES sa;
	HANDLE pipe[2] = {NULL, NULL};
	int fd_out = -1, cons_out = -1;
	char *_shell_cmd;
	LPTSTR _shell_cmd_ = NULL;

	sa.nLength = sizeof (SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
   	if (!CreatePipe (&pipe[0], &pipe[1], &sa, 0)) {
		r_sys_perror ("r_w32_cmd_pipe/CreatePipe");
		goto err_r_w32_cmd_pipe;
	}
	if (!SetHandleInformation (pipe[1], HANDLE_FLAG_INHERIT, 0)) {
		r_sys_perror ("r_w32_cmd_pipe/SetHandleInformation");
		goto err_r_w32_cmd_pipe;
	}
	si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
	si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
	si.hStdInput = pipe[0];
	si.dwFlags |= STARTF_USESTDHANDLES;
	si.cb = sizeof (si);
	_shell_cmd = shell_cmd;
	while (*_shell_cmd && isspace (*_shell_cmd)) {
		_shell_cmd++;
	}
	_shell_cmd_ = r_sys_conv_utf8_to_utf16 (_shell_cmd);
	// exec windows process
	if (!CreateProcess (NULL, _shell_cmd_, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		r_sys_perror ("r_w32_cmd_pipe/CreateProcess");
		goto err_r_w32_cmd_pipe;
	}
	fd_out = _open_osfhandle ((intptr_t)pipe[1], _O_WRONLY|_O_TEXT);
	if (fd_out == -1) {
		perror ("_open_osfhandle");
		goto err_r_w32_cmd_pipe;
	}
	cons_out = dup (1);
	dup2 (fd_out, 1);
	// exec radare command
	r_core_cmd (core, radare_cmd, 0);
	r_cons_flush ();
	close (1);
	close (fd_out);
	fd_out = -1;
	WaitForSingleObject (pi.hProcess, INFINITE);
err_r_w32_cmd_pipe:
	if (pi.hProcess) {
		CloseHandle (pi.hProcess);
	}
	if (pi.hThread) {
		CloseHandle (pi.hThread);
	}
	if (pipe[0]) {
		CloseHandle (pipe[0]);
	}
	if (pipe[1]) {
		CloseHandle (pipe[1]);
	}
	if (fd_out != -1) {
		close (fd_out);
	}
	if (cons_out != -1) {
		dup2 (cons_out, 1);
		close (cons_out);
	}
	free (_shell_cmd_);
}
#endif

R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
#if __UNIX__ || __CYGWIN__
	int stdout_fd, fds[2];
	int child;
#endif
	int si, olen, ret = -1, pipecolor = -1;
	char *str, *out = NULL;

	if (r_sandbox_enable (0)) {
		eprintf ("Pipes are not allowed in sandbox mode\n");
		return -1;
	}
	si = r_config_get_i (core->config, "scr.interactive");
	r_config_set_i (core->config, "scr.interactive", 0);
	if (!r_config_get_i (core->config, "scr.pipecolor")) {
		pipecolor = r_config_get_i (core->config, "scr.color");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}
	if (*shell_cmd=='!') {
		r_cons_grep_parsecmd (shell_cmd, "\"");
		olen = 0;
		out = NULL;
		// TODO: implement foo
		str = r_core_cmd_str (core, radare_cmd);
		r_sys_cmd_str_full (shell_cmd + 1, str, &out, &olen, NULL);
		free (str);
		r_cons_memcat (out, olen);
		free (out);
		ret = 0;
	}
#if __UNIX__ || __CYGWIN__
	radare_cmd = (char*)r_str_trim_head (radare_cmd);
	shell_cmd = (char*)r_str_trim_head (shell_cmd);

	signal (SIGPIPE, SIG_IGN);
	stdout_fd = dup (1);
	if (stdout_fd != -1) {
		pipe (fds);
		child = r_sys_fork ();
		if (child == -1) {
			eprintf ("Cannot fork\n");
			close (stdout_fd);
		} else if (child) {
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
#elif __WINDOWS__
	r_w32_cmd_pipe (core, radare_cmd, shell_cmd);
#else
#ifdef _MSC_VER
#pragma message ("r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM")
#else
#warning r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
#endif
	eprintf ("r_core_cmd_pipe: unimplemented for this platform\n");
#endif
	if (pipecolor != -1) {
		r_config_set_i (core->config, "scr.color", pipecolor);
	}
	r_config_set_i (core->config, "scr.interactive", si);
	return ret;
}

static char *parse_tmp_evals(RCore *core, const char *str) {
	char *s = strdup (str);
	int i, argc = r_str_split (s, ',');
	char *res = strdup ("");
	if (!s || !res) {
		free (s);
		free (res);
		return NULL;
	}
	for (i = 0; i < argc; i++) {
		char *eq, *kv = (char *)r_str_word_get0 (s, i);
		if (!kv) {
			break;
		}
		eq = strchr (kv, '=');
		if (eq) {
			*eq = 0;
			const char *ov = r_config_get (core->config, kv);
			if (!ov) {
				continue;
			}
			char *cmd = r_str_newf ("e %s=%s;", kv, ov);
			if (!cmd) {
				free (s);
				free (res);
				return NULL;
			}
			res = r_str_prefix (res, cmd);
			free (cmd);
			r_config_set (core->config, kv, eq + 1);
			*eq = '=';
		} else {
			eprintf ("Missing '=' in e: expression (%s)\n", kv);
		}
	}
	free (s);
	return res;
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char* colon);
static int r_core_cmd_subst(RCore *core, char *cmd) {
	int ret = 0, rep = atoi (cmd), orep;
	char *cmt, *colon = NULL, *icmd = strdup (cmd);
	const char *cmdrep = NULL;
	bool tmpseek = false;
	ut64 orig_offset;

	cmd = r_str_trim_head_tail (icmd);
	// lines starting with # are ignored (never reach cmd_hash()), except #! and #?
	if (!*cmd) {
		if (r_config_get_i (core->config, "cmd.repeat")) {
			r_core_cmd_repeat (core, true);
			ret = r_core_cmd_nullcallback (core);
		}
		goto beach;
	}
	if (!icmd || (cmd[0] == '#' && cmd[1] != '!' && cmd[1] != '?')) {
		goto beach;
	}
	cmt = *icmd ? (char *)r_str_firstbut (icmd + 1, '#', "\""): NULL;
	if (cmt && (cmt[1] == ' ' || cmt[1] == '\t')) {
		*cmt = 0;
	}
	if (*cmd != '"') {
		if (!strchr (cmd, '\'')) { // allow | awk '{foo;bar}' // ignore ; if there's a single quote
			if ((colon = strchr (cmd, ';'))) {
				*colon = 0;
			}
		}
	} else {
		colon = NULL;
	}
	if (rep > 0) {
		while (IS_DIGIT (*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
			goto beach;
		}
	}
	if (rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we dont want to be interactive
	if (rep > 1 && r_sandbox_enable (0)) {
		eprintf ("Command repeat sugar disabled in sandbox mode (%s)\n", cmd);
		goto beach;
	} else {
		if (rep > INTERACTIVE_MAX_REP) {
			if (r_config_get_i (core->config, "scr.interactive")) {
				if (!r_cons_yesno ('n', "Are you sure to repeat this %d times? (y/N)", rep)) {
					goto beach;
				}
			}
		}
	}
	// TODO: store in core->cmdtimes to speedup ?
	cmdrep = r_config_get (core->config, "cmd.times");
	if (!cmdrep) {
		cmdrep = "";
	}
	orep = rep;

	int ocur_enabled = core->print && core->print->cur_enabled;
	orig_offset = core->offset;
	while (rep-- && *cmd) {
		if (core->print) {
			core->print->cur_enabled = false;
			if (ocur_enabled && core->seltab >= 0) {
				if (core->seltab == core->curtab) {
					core->print->cur_enabled = true;
				}
			}
		}
		char *cr = strdup (cmdrep);
		core->break_loop = false;
		ret = r_core_cmd_subst_i (core, cmd, colon);
		/*
		 * r_core_cmd_subst_i will set core->tmpseek when run cmd the first time
		 * if `@ tmpoff` is used, keep core->tmpseek in the remaining runs
		 */
		if (core->tmpseek) {
			tmpseek = true;
		}
		if (ret && *cmd == 'q') {
			free (cr);
			goto beach;
		}
		if (core->break_loop) {
			break;
		}
		if (cr && *cr) {
			if (orep > 1) {
				// XXX: do not flush here, we need r_cons_push () and r_cons_pop()
				r_cons_flush ();
				// XXX: we must import register flags in C
				(void)r_core_cmd0 (core, ".dr*");
				(void)r_core_cmd0 (core, cr);
			}
		}
		free (cr);
	}
	if (tmpseek) {
		r_core_seek (core, orig_offset, 1);
	}
	if (core->print) {
		core->print->cur_enabled = ocur_enabled;
	}
	if (colon && colon[1]) {
		for (++colon; *colon == ';'; colon++);
		r_core_cmd_subst (core, colon);
	} else {
		if (!*icmd) {
			r_core_cmd_nullcallback (core);
		}
	}
beach:
	free (icmd);
	return ret;
}

static char *find_eoq(char *p) {
	for (; *p; p++) {
		if (*p == '"') {
			break;
		}
		if (*p == '\\' && p[1] == '"') {
			p++;
		}
	}
	return p;
}

static char* findSeparator(char *p) {
	char *q = strchr (p, '+');
	if (q) {
		return q;
	}
	return strchr (p, '-');
}

static void tmpenvs_free(void *item) {
	r_sys_setenv (item, NULL);
	free (item);
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon) {
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;

	if (!cmd) {
		return 0;
	}
	cmd = r_str_trim_head_tail (cmd);

	char *$0 = strstr (cmd, "$(");
	if ($0) {
		char *$1 = strchr ($0 + 2, ')');
		if ($1) {
			*$0 = '`';
			*$1 = '`';
			memmove ($0 + 1, $0 + 2, strlen ($0 + 2) + 1);
		} else {
			eprintf ("Unterminated $() block\n");
		}
	}

	/* quoted / raw command */
	switch (*cmd) {
	case '.':
		if (cmd[1] == '"') { /* interpret */
			return r_cmd_call (core->rcmd, cmd);
		}
		break;
	case '"':
		for (; *cmd; ) {
			int pipefd = -1;
			ut64 oseek = UT64_MAX;
			char *line, *p;
			haveQuote = *cmd == '"';
			if (haveQuote) {
			//	*cmd = 0;
				cmd++;
				p = cmd[0] ? find_eoq (cmd + 1) : NULL;
				if (!p || !*p) {
					eprintf ("Missing \" in (%s).", cmd);
					return false;
				}
				*p++ = 0;
				if (!*p) {
					eos = true;
				}
			} else {
				char *sc = strchr (cmd, ';');
				if (sc) {
					*sc = 0;
				}
				r_core_cmd0 (core, cmd);
				if (!sc) {
					break;
				}
				cmd = sc + 1;
				continue;
			}
			if (p[0]) {
				// workaround :D
				if (p[0] == '@') {
					p--;
				}
				while (p[1] == ';' || IS_WHITESPACE (p[1])) {
					p++;
				}
				if (p[1] == '@' || (p[1] && p[2] == '@')) {
					char *q = strchr (p + 1, '"');
					if (q) {
						*q = 0;
					}
					haveQuote = q != NULL;
					oseek = core->offset;
					r_core_seek (core, r_num_math (core->num, p + 2), 1);
					if (q) {
						*p = '"';
						p = q;
					} else {
						p = strchr (p + 1, ';');
					}
				}
				if (p && *p && p[1] == '>') {
					str = p + 2;
					while (*str == '>') {
						str++;
					}
					while (IS_WHITESPACE (*str)) {
						str++;
					}
					r_cons_flush ();
					pipefd = r_cons_pipe_open (str, 1, p[2] == '>');
				}
			}
			line = strdup (cmd);
			line = r_str_replace (line, "\\\"", "\"", true);
			if (p && *p && p[1] == '|') {
				str = p + 2;
				while (IS_WHITESPACE (*str)) {
					str++;
				}
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
			if (!p) {
				break;
			}
			if (eos) {
				break;
			}
			if (haveQuote) {
				if (*p == ';') {
					cmd = p + 1;
				} else {
					if (*p == '"') {
						cmd = p + 1;
					} else {
						*p = '"';
						cmd = p;
					}
				}
			} else {
				cmd = p + 1;
			}
		}
		return true;
	case '(':
		if (cmd[1] != '*' && !strstr (cmd, ")()")) {
			return r_cmd_call (core->rcmd, cmd);
		}
		break;
	}

// TODO must honor `
	/* comments */
	if (*cmd != '#') {
		ptr = (char *)r_str_firstbut (cmd, '#', "`\""); // TODO: use quotestr here
		if (ptr && (ptr[1] == ' ' || ptr[1] == '\t')) {
			*ptr = '\0';
		}
	}

	/* multiple commands */
	// TODO: must honor " and ` boundaries
	//ptr = strrchr (cmd, ';');
	if (*cmd != '#') {
		ptr = (char *)r_str_lastbut (cmd, ';', quotestr);
		if (colon && ptr) {
			int ret ;
			*ptr = '\0';
			if (r_core_cmd_subst (core, cmd) == -1) {
				return -1;
			}
			cmd = ptr + 1;
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
		if (!ptr2 || (ptr2 && ptr2 > ptr)) {
			if (!tick || (tick && tick > ptr)) {
				*ptr = '\0';
				cmd = r_str_trim_nc (cmd);
				if (!strcmp (ptr + 1, "?")) { // "|?"
					// TODO: should be disable scr.color in pd| ?
					eprintf ("Usage: <r2command> | <program|H|>\n");
					eprintf (" pd|?   - show this help\n");
					eprintf (" pd|    - disable scr.html and scr.color\n");
					eprintf (" pd|H   - enable scr.html, respect scr.color\n");
					eprintf (" pi 1|T - use scr.tts to speak out the stdout\n");
					return ret;
				} else if (!strcmp (ptr + 1, "H")) { // "|H"
					scr_html = r_config_get_i (core->config, "scr.html");
					r_config_set_i (core->config, "scr.html", true);
				} else if (!strcmp (ptr + 1, "T")) { // "|T"
					scr_color = r_config_get_i (core->config, "scr.color");
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
					core->cons->use_tts = true;
				} else if (ptr[1]) { // "| grep .."
					int value = core->num->value;
					if (*cmd) {
						r_core_cmd_pipe (core, cmd, ptr + 1);
					} else {
						char *res = r_io_system (core->io, ptr + 1);
						if (res) {
							r_cons_printf ("%s\n", res);
							free (res);
						}
						free (res);
					}
					core->num->value = value;
					return 0;
				} else { // "|"
					scr_html = r_config_get_i (core->config, "scr.html");
					r_config_set_i (core->config, "scr.html", 0);
					scr_color = r_config_get_i (core->config, "scr.color");
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
				}
			}
		}
	}

	// TODO must honor " and `
	/* bool conditions */
	ptr = (char *)r_str_lastbut (cmd, '&', quotestr);
	//ptr = strchr (cmd, '&');
	while (ptr && ptr[1] == '&') {
		*ptr = '\0';
		ret = r_cmd_call (core->rcmd, cmd);
		if (ret == -1) {
			eprintf ("command error(%s)\n", cmd);
			if (scr_html != -1) {
				r_config_set_i (core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				r_config_set_i (core->config, "scr.color", scr_color);
			}
			return ret;
		}
		for (cmd = ptr + 2; cmd && *cmd == ' '; cmd++);
		ptr = strchr (cmd, '&');
	}

	/* Out Of Band Input */
	free (core->oobi);
	core->oobi = NULL;

	ptr = strstr (cmd, "?*");
	if (ptr && (ptr == cmd || ptr[-1] != '~')) {
		ptr[0] = 0;
		if (*cmd != '#') {
			int detail = 0;
			if (cmd < ptr && ptr[-1] == '?') {
				detail++;
				if (cmd < ptr - 1 && ptr[-2] == '?') {
					detail++;
				}
			}
			r_cons_break_push (NULL, NULL);
			recursive_help (core, detail, cmd);
			r_cons_break_pop ();
			r_cons_grep_parsecmd (ptr + 2, "`");
			if (scr_html != -1) {
				r_config_set_i (core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				r_config_set_i (core->config, "scr.color", scr_color);
			}
			return 0;
		}
	}

#if 0
	ptr = strchr (cmd, '<');
	if (ptr) {
		ptr[0] = '\0';
		if (r_cons_singleton()->is_interactive) {
			if (ptr[1] == '<') {
				/* this is a bit mess */
				//const char *oprompt = strdup (r_line_singleton ()->prompt);
				//oprompt = ">";
				for (str = ptr + 2; str[0] == ' '; str++) {
					//nothing to see here
				}
				eprintf ("==> Reading from stdin until '%s'\n", str);
				free (core->oobi);
				core->oobi = malloc (1);
				if (core->oobi) {
					core->oobi[0] = '\0';
				}
				core->oobi_len = 0;
				for (;;) {
					char buf[1024];
					int ret;
					write (1, "> ", 2);
					fgets (buf, sizeof (buf) - 1, stdin); // XXX use r_line ??
					if (feof (stdin)) {
						break;
					}
					if (*buf) buf[strlen (buf) - 1]='\0';
					ret = strlen (buf);
					core->oobi_len += ret;
					core->oobi = realloc (core->oobi, core->oobi_len + 1);
					if (core->oobi) {
						if (!strcmp (buf, str)) {
							break;
						}
						strcat ((char *)core->oobi, buf);
					}
				}
				//r_line_set_prompt (oprompt);
			} else {
				for (str = ptr + 1; *str == ' '; str++) {
					//nothing to see here
				}
				if (!*str) {
					goto next;
				}
				eprintf ("Slurping file '%s'\n", str);
				free (core->oobi);
				core->oobi = (ut8*)r_file_slurp (str, &core->oobi_len);
				if (!core->oobi) {
					eprintf ("cannot open file\n");
				} else if (ptr == cmd) {
					return r_core_cmd_buffer (core, (const char *)core->oobi);
				}
			}
		} else {
			eprintf ("Cannot slurp with << in non-interactive mode\n");
			return 0;
		}
	}
next:
#endif
	/* pipe console to file */
	ptr = (char *)r_str_firstbut (cmd, '>', "\"");
	// TODO honor `
	if (ptr) {
		int fdn = 1;
		int pipecolor = r_config_get_i (core->config, "scr.pipecolor");
		int use_editor = false;
		int ocolor = r_config_get_i (core->config, "scr.color");
		*ptr = '\0';
		str = r_str_trim_head_tail (ptr + 1 + (ptr[1] == '>'));
		if (!*str) {
			eprintf ("No output?\n");
			goto next2;
		}
		/* r_cons_flush() handles interactive output (to the terminal)
		 * differently (e.g. asking about too long output). This conflicts
		 * with piping to a file. Disable it while piping. */
		if (ptr > (cmd + 1) && ISWHITECHAR (ptr[-2])) {
			char *fdnum = ptr - 1;
			if (*fdnum == 'H') { // "H>"
				scr_html = r_config_get_i (core->config, "scr.html");
				r_config_set_i (core->config, "scr.html", true);
				pipecolor = true;
				*fdnum = 0;
			} else {
				if (IS_DIGIT(*fdnum)) {
					fdn = *fdnum - '0';
				}
				*fdnum = 0;
			}
		}
		r_cons_set_interactive (false);
		if (!strcmp (str, "-")) {
			use_editor = true;
			str = r_file_temp ("dumpedit");
			r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
		}
		if (fdn > 0) {
			pipefd = r_cons_pipe_open (str, fdn, ptr[1] == '>');
			if (pipefd != -1) {
				if (!pipecolor) {
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
				}
				ret = r_core_cmd_subst (core, cmd);
				r_cons_flush ();
				r_cons_pipe_close (pipefd);
			}
		}
		r_cons_set_last_interactive ();
		if (!pipecolor) {
			r_config_set_i (core->config, "scr.color", ocolor);
		}
		if (use_editor) {
			const char *editor = r_config_get (core->config, "cfg.editor");
			if (editor && *editor) {
				r_sys_cmdf ("%s '%s'", editor, str);
				r_file_rm (str);
			} else {
				eprintf ("No cfg.editor configured\n");
			}
			r_config_set_i (core->config, "scr.color", ocolor);
			free (str);
		}
		if (scr_html != -1) {
			r_config_set_i (core->config, "scr.html", scr_html);
		}
		if (scr_color != -1) {
			r_config_set_i (core->config, "scr.color", scr_color);
		}
		core->cons->use_tts = false;
		return ret;
	}
next2:
	/* sub commands */
	ptr = strchr (cmd, '`');
	if (ptr) {
		bool empty = false;
		int oneline = 1;
		if (ptr[1] == '`') {
			memmove (ptr, ptr + 1, strlen (ptr));
			oneline = 0;
			empty = true;
		}
		ptr2 = strchr (ptr + 1, '`');
		if (empty) {
			/* do nothing */
		} else if (!ptr2) {
			eprintf ("parse: Missing backtick in expression.\n");
			goto fail;
		} else {
			int value = core->num->value;
			*ptr = '\0';
			*ptr2 = '\0';
			if (ptr[1] == '!') {
				str = r_core_cmd_str_pipe (core, ptr + 1);
			} else {
				str = r_core_cmd_str (core, ptr + 1);
			}
			if (!str) {
				goto fail;
			}
			// ignore contents if first char is pipe or comment
			if (*str == '|' || *str == '*') {
				eprintf ("r_core_cmd_subst_i: invalid backticked command\n");
				free (str);
				goto fail;
			}
			if (oneline && str) {
				for (i = 0; str[i]; i++) {
					if (str[i] == '\n') {
						str[i] = ' ';
					}
				}
			}
			str = r_str_append (str, ptr2 + 1);
			cmd = r_str_append (strdup (cmd), str);
			core->num->value = value;
			ret = r_core_cmd_subst (core, cmd);
			free (cmd);
			if (scr_html != -1) {
				r_config_set_i (core->config, "scr.html", scr_html);
			}
			free (str);
			return ret;
		}
	}
	// TODO must honor " and `
	core->fixedblock = false;

	if (r_str_endswith (cmd, "~?") && cmd[2] == '\0') {
		r_cons_grep_help ();
		return true;
	}
	if (*cmd != '.') {
		grep = r_cons_grep_strip (cmd, quotestr);
	}

	/* temporary seek commands */
	// if (*cmd != '(' && *cmd != '"') {
	if (*cmd != '"') {
		ptr = strchr (cmd, '@');
		if (ptr == cmd + 1 && *cmd == '?') {
			ptr = NULL;
		}
	} else {
		ptr = NULL;
	}

	core->tmpseek = ptr? true: false;
	int rc = 0;
	if (ptr) {
		char *f, *ptr2 = strchr (ptr + 1, '!');
		ut64 addr = core->offset;
		bool addr_is_set = false;
		char *tmpbits = NULL;
		const char *offstr = NULL;
		ut64 tmpbsz = core->blocksize;
		char *tmpeval = NULL;
		char *tmpasm = NULL;
		int flgspc = -123;
		int tmpfd = -1;
		int sz, len;
		ut8 *buf;

		*ptr++ = '\0';
repeat_arroba:
		arroba = (ptr[0] && ptr[1] && ptr[2])?
				 strchr (ptr + 2, '@'): NULL;
		if (arroba) {
			*arroba = 0;
		}

		for (; *ptr == ' '; ptr++) {
			//nothing to see here
		}
		if (*ptr && ptr[1] == ':') {
			/* do nothing here */
		} else {
			ptr--;
		}

		ptr = r_str_trim_tail (ptr);

		if (ptr[1] == '?') {
			r_core_cmd_help (core, help_msg_at);
		} else if (ptr[1] == '%') { // "@%"
			char *k = strdup (ptr + 2);
			char *v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				r_sys_setenv (k, v);
				r_list_append (tmpenvs, k);
			}
		} else if (ptr[1] == '.') { // "@."
			if (ptr[2] == '.') { // "@.."
				if (ptr[3] == '.') { // "@..."
					ut64 addr = r_num_tail (core->num, core->offset, ptr + 4);
					r_core_block_size (core, R_ABS (addr - core->offset));
					goto fuji;
				} else {
					addr = r_num_tail (core->num, core->offset, ptr + 3);
					r_core_seek (core, addr, 1);
					core->tmpseek = true;
					goto fuji;
				}
			} else {
				// WAT DU
				eprintf ("TODO: what do you expect for @. import offset from file maybe?\n");
			}
		} else if (ptr[0] && ptr[1] == ':' && ptr[2]) {
			usemyblock = true;
			switch (ptr[0]) {
			case 'F': // "@F:" // temporary flag space
				flgspc = r_flag_space_get (core->flags, ptr + 2);
				r_flag_space_set (core->flags, ptr + 2);
				break;
			case 'B': // "@B:#" // seek to the last instruction in current bb
				{
					int index = (int)r_num_math (core->num, ptr + 2);
					// XXX this is slow, can be optimized to just retreive the bb we want
					RListIter *iter;
					RAnalBlock *bb;
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
					if (fcn) {
						r_list_foreach (fcn->bbs, iter, bb) {
							if ((core->offset >= bb->addr) && (core->offset < (bb->addr + bb->size))) {
								int count = bb->op_pos_size / sizeof (bb->op_pos[0]);
								int pos = (index < 0) ? count + index + 1: index;
								if (pos < 0) {
									pos = 0;
								}
								if (pos > count) {
									pos = count;
								}
								int lastOp = bb->op_pos[pos];
								for (i = 0; i < count; i++) {
									eprintf ("%d 0x%llx %d\n", pos, core->offset + bb->op_pos[i], i);
								}
								r_core_seek (core, core->offset + lastOp, 1);
								core->tmpseek = true;
								goto fuji;
								break;
							}
						}
					} else {
						eprintf ("Cant find a function for 0x%08"PFMT64x"\n", core->offset);
					}
				}
				break;
			case 'f': // "@f:" // slurp file in block
				f = r_file_slurp (ptr + 2, &sz);
				if (f) {
					buf = malloc (sz);
					if (buf) {
						free (core->block);
						core->block = buf;
						core->blocksize = sz;
						memcpy (core->block, f, sz);
					} else {
						eprintf ("cannot alloc %d", sz);
					}
					free (f);
				} else {
					eprintf ("cannot open '%s'\n", ptr + 3);
				}
				break;
			case 'r': // "@r:" // regname
				if (ptr[1] == ':') {
					ut64 regval;
					char *mander = strdup (ptr + 2);
					char *sep = findSeparator (mander);
					if (sep) {
						char ch = *sep;
						*sep = 0;
						regval = r_debug_reg_get (core->dbg, mander);
						*sep = ch;
						char *numexpr = r_str_newf ("0x%"PFMT64x"%s", regval, sep);
						regval = r_num_math (core->num, numexpr);
						free (numexpr);
					} else {
						regval = r_debug_reg_get (core->dbg, ptr + 2);
					}
					r_core_seek (core, regval, 1);
					free (mander);
				}
				break;
			case 'b': // "@b:" // bits
				tmpbits = strdup (r_config_get (core->config, "asm.bits"));
				r_config_set_i (core->config, "asm.bits",
					r_num_math (core->num, ptr + 2));
				break;
			case 'i': // "@i:"
				{
					ut64 addr = r_num_math (core->num, ptr + 2);
					if (addr) {
						r_core_cmdf (core, "so %s", ptr + 2);
					}
				}
				break;
			case 'e': // "@e:"
				{
					char *cmd = parse_tmp_evals (core, ptr + 2);
					if (!tmpeval) {
						tmpeval = cmd;
					} else {
						tmpeval = r_str_prefix (tmpeval, cmd);
						free (cmd);
					}
				}
				break;
			case 'x': // "@x:" // hexpairs
				if (ptr[1] == ':') {
					buf = malloc (strlen (ptr + 2) + 1);
					if (buf) {
						len = r_hex_str2bin (ptr + 2, buf);
						r_core_block_size (core, R_ABS(len));
						memcpy (core->block, buf, core->blocksize);
						core->fixedblock = true;
						free (buf);
					} else {
						eprintf ("cannot allocate\n");
					}
				} else {
					eprintf ("Invalid @x: syntax\n");
				}
				break;
			case 'k': // "@k"
				 {
					char *out = sdb_querys (core->sdb, NULL, 0, ptr + ((ptr[1])? 2: 1));
					if (out) {
						r_core_seek (core, r_num_math (core->num, out), 1);
						free (out);
					}
				 }
				break;
			case 'o': // "@o:3"
				if (ptr[1] == ':') {
					tmpfd = core->io->desc ? core->io->desc->fd : -1;
					r_io_use_fd (core->io, atoi (ptr + 2));
				}
				break;
			case 'a': // "@a:"
				if (ptr[1] == ':') {
					char *q = strchr (ptr + 2, ':');
					tmpasm = strdup (r_config_get (core->config, "asm.arch"));
					if (q) {
						*q++ = 0;
						tmpbits = strdup (r_config_get (core->config, "asm.bits"));
						r_config_set (core->config, "asm.bits", q);
					}
					r_config_set (core->config, "asm.arch", ptr + 2);
					// TODO: handle asm.bits
				} else {
					eprintf ("Usage: pd 10 @a:arm:32\n");
				}
				break;
			case 's': // "@s:"
				len = strlen (ptr + 2);
				r_core_block_size (core, len);
				memcpy (core->block, ptr + 2, len);
				break;
			default:
				goto ignore;
			}
			*ptr = '@';
			goto next_arroba; //ignore; //return ret;
		}
ignore:
		ptr = r_str_trim_head (ptr + 1);
		ptr--;

		cmd = r_str_trim_nc (cmd);
		if (ptr2) {
			if (strlen (ptr + 1) == 13 && strlen (ptr2 + 1) == 6 &&
			    !memcmp (ptr + 1, "0x", 2) &&
			    !memcmp (ptr2 + 1, "0x", 2)) {
				/* 0xXXXX:0xYYYY */
			} else if (strlen (ptr + 1) == 9 && strlen (ptr2 + 1) == 4) {
				/* XXXX:YYYY */
			} else {
				*ptr2 = '\0';
				if (!ptr2[1]) {
					goto fail;
				}
				r_core_block_size (
					core, r_num_math (core->num, ptr2 + 1));
			}
		}

		offstr = r_str_trim_head (ptr + 1);

		addr = r_num_math (core->num, offstr);
		addr_is_set = true;
		if (isalpha ((ut8)ptr[1]) && !addr) {
			if (!r_flag_get (core->flags, ptr + 1)) {
				eprintf ("Invalid address (%s)\n", ptr + 1);
				goto fail;
			}
		} else {
			char ch = *offstr;
			if (ch == '-' || ch == '+') {
				addr = core->offset + addr;
			}
		}
next_arroba:
		if (arroba) {
			ptr = arroba + 1;
			*arroba = '@';
			arroba = NULL;
			goto repeat_arroba;
		}
		if (ptr[1] == '@') {
			if (ptr[2] == '@') {
				char *rule = ptr + 3;
				while (*rule && *rule == ' ') rule++;
				ret = r_core_cmd_foreach3 (core, cmd, rule);
			} else {
				ret = r_core_cmd_foreach (core, cmd, ptr + 2);
			}
		} else {
			bool tmpseek = false;
			const char *fromvars[] = { "anal.from", "diff.from", "graph.from",
				"io.buffer.from", "lines.from", "search.from", "zoom.from", NULL };
			const char *tovars[] = { "anal.to", "diff.to", "graph.to",
				"io.buffer.to", "lines.to", "search.to", "zoom.to", NULL };
			ut64 curfrom[R_ARRAY_SIZE (fromvars) - 1], curto[R_ARRAY_SIZE (tovars) - 1];

			// "@(A B)"
			if (ptr[1] == '(') {
				char *range = ptr + 3;
				char *p = strchr (range, ' ');
				if (!p) {
					eprintf ("Usage: / ABCD @..0x1000 0x3000\n");
					free (tmpeval);
					free (tmpasm);
					free (tmpbits);
					goto fail;
				}
				*p = '\x00';
				ut64 from = r_num_math (core->num, range);
				ut64 to = r_num_math (core->num, p + 1);
				// save current ranges
				for (i = 0; fromvars[i]; i++) {
					curfrom[i] = r_config_get_i (core->config, fromvars[i]);
				}
				for (i = 0; tovars[i]; i++) {
					curto[i] = r_config_get_i (core->config, tovars[i]);
				}
				// set new ranges
				for (i = 0; fromvars[i]; i++) {
					r_config_set_i (core->config, fromvars[i], from);
				}
				for (i = 0; tovars[i]; i++) {
					r_config_set_i (core->config, tovars[i], to);
				}
				tmpseek = true;
			}
			if (usemyblock) {
				if (addr_is_set) {
					core->offset = addr;
				}
				ret = r_cmd_call (core->rcmd, r_str_trim_head (cmd));
			} else {
				if (addr_is_set) {
					if (ptr[1]) {
						r_core_seek (core, addr, 1);
						r_core_block_read (core);
					}
					ret = r_cmd_call (core->rcmd, r_str_trim_head (cmd));
				}
			}
			if (tmpseek) {
				// restore ranges
				for (i = 0; fromvars[i]; i++) {
					r_config_set_i (core->config, fromvars[i], curfrom[i]);
				}
				for (i = 0; tovars[i]; i++) {
					r_config_set_i (core->config, tovars[i], curto[i]);
				}
			}
		}
		if (ptr2) {
			*ptr2 = '!';
			r_core_block_size (core, tmpbsz);
		}
		if (tmpasm) {
			r_config_set (core->config, "asm.arch", tmpasm);
			tmpasm = NULL;
		}
		if (tmpfd != -1) {
			r_io_use_fd (core->io, tmpfd);
		}
		if (tmpbits) {
			r_config_set (core->config, "asm.bits", tmpbits);
			tmpbits = NULL;
		}
		if (tmpeval) {
			r_core_cmd0 (core, tmpeval);
			R_FREE (tmpeval);
		}
		if (flgspc != -123) {
			r_flag_space_set_i (core->flags, flgspc);
			flgspc = -123;
		}
		*ptr = '@';
		rc = ret;
		goto beach;
	}
fuji:
	rc = cmd? r_cmd_call (core->rcmd, r_str_trim_head (cmd)): false;
beach:
	r_cons_grep_process (grep);
	if (scr_html != -1) {
		r_cons_flush ();
		r_config_set_i (core->config, "scr.html", scr_html);
	}
	if (scr_color != -1) {
		r_config_set_i (core->config, "scr.color", scr_color);
	}
	r_list_free (tmpenvs);
	core->fixedblock = false;
	return rc;
fail:
	rc = -1;
	goto beach;
}

static int foreach_comment(void *user, const char *k, const char *v) {
	RAnalMetaUserItem *ui = user;
	RCore *core = ui->anal->user;
	const char *cmd = ui->user;
	if (!strncmp (k, "meta.C.", 7)) {
		char *cmt = (char *)sdb_decode (v, 0);
		if (!cmt) cmt = strdup ("");
		//eprintf ("--> %s = %s\n", k + 7, cmt);
		r_core_cmdf (core, "s %s", k + 7);
		r_core_cmd0 (core, cmd);
		free (cmt);
	}
	return 1;
}

R_API int r_core_cmd_foreach3(RCore *core, const char *cmd, char *each) {
	RDebug *dbg = core->dbg;
	RList *list, *head;
	RListIter *iter;
	RFlagItem *flg;
	int i;

	switch (each[0]) {
	case '=':
		{
		char *arg;
		for (arg = each + 1; ; ) {
			char *next = strchr (arg, ' ');
			if (next) {
				*next = 0;
			}
			if (arg && *arg) {
				r_core_cmdf (core, "%s %s", cmd, arg);
			}
			if (!next) {
				break;
			}
			arg = next + 1;
		}
		}
		break;
	case '?':
		r_cons_printf ("Usage: @@@ [type]     # types:\n"
			" symbols\n"
			" sections\n"
			" imports\n"
			" regs\n"
			" threads\n"
			" comments\n"
			" functions\n"
			" flags\n");
		break;
	case 'c':
		switch (each[1]) {
		case 'a': // call
			break;
		default:
			r_meta_list_cb (core->anal, R_META_TYPE_COMMENT, 0, foreach_comment, (void*)cmd, UT64_MAX);
			break;
		}
		break;
	case 't':
		// iterate over all threads
		if (dbg && dbg->h && dbg->h->threads) {
			int origpid = dbg->pid;
			RDebugPid *p;
			list = dbg->h->threads (dbg, dbg->pid);
			if (!list)
				return false;
			r_list_foreach (list, iter, p) {
				r_core_cmdf (core, "dp %d", p->pid);
				r_cons_printf ("PID %d\n", p->pid);
				r_core_cmd0 (core, cmd);
			}
			r_core_cmdf (core, "dp %d", origpid);
			r_list_free (list);
		}
		break;
	case 'r':
		// registers
		{
			ut64 offorig = core->offset;
			for (i = 0; i < 128; i++) {
				RRegItem *item;
				ut64 value;
				head = r_reg_get_list (dbg->reg, i);
				if (!head) {
					continue;
				}
				r_list_foreach (head, iter, item) {
					if (item->size != core->anal->bits) {
						continue;
					}
					value = r_reg_get_value (dbg->reg, item);
					r_core_seek (core, value, 1);
					r_cons_printf ("%s: ", item->name);
					r_core_cmd0 (core, cmd);
				}
			}
			r_core_seek (core, offorig, 1);
		}
		break;
	case 'i':
		// imports
		{
			RBinImport *imp;
			ut64 offorig = core->offset;
			list = r_bin_get_imports (core->bin);
			r_list_foreach (list, iter, imp) {
				char *impflag = r_str_newf ("sym.imp.%s", imp->name);
				ut64 addr = r_num_math (core->num, impflag);
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, 1);
					r_core_cmd0 (core, cmd);
				}
			}
			r_core_seek (core, offorig, 1);
		}
		break;
	case 's':
		if (each[1] == 'e') {
			RBinObject *obj = r_bin_cur_object (core->bin);
			if (obj) {
				ut64 offorig = core->offset;
				ut64 bszorig = core->blocksize;
				RBinSection *sec;
				RListIter *iter;
				r_list_foreach (obj->sections, iter, sec) {
					r_core_seek (core, sec->vaddr, 1);
					r_core_block_size (core, sec->vsize);
					r_core_cmd0 (core, cmd);
				}
				r_core_seek (core, offorig, 1);
				r_core_block_size (core, bszorig);
			}
		} else {
			// symbols
			RBinSymbol *sym;
			ut64 offorig = core->offset;
			list = r_bin_get_symbols (core->bin);
			r_list_foreach (list, iter, sym) {
				r_core_seek (core, sym->vaddr, 1);
				r_core_cmd0 (core, cmd);
			}
			r_core_seek (core, offorig, 1);
		}
		break;
	case 'f':
		switch (each[1]) {
		case 'l': // flags
			r_list_foreach (core->flags->flags, iter, flg) {
				r_core_seek (core, flg->offset, 1);
				r_core_cmd0 (core, cmd);
			}
			break;
		case 'u': // functions
			{
				ut64 offorig = core->offset;
				RAnalFunction *fcn;
				list = core->anal->fcns;
				r_list_foreach (list, iter, fcn) {
					r_cons_printf ("[0x%08"PFMT64x"  %s\n", fcn->addr, fcn->name);
					r_core_seek (core, fcn->addr, 1);
					r_core_cmd0 (core, cmd);
				}
				r_core_seek (core, offorig, 1);
			}
			break;
		}
		break;
	}
	return 0;
}

static void foreachOffset (RCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup (_cmd);
	char *str = cmd;
	char *nextLine = NULL;
	ut64 addr;
	/* foreach list of items */
	while (each) {
		// skip spaces
		while (*each == ' ') {
			each++;
		}
		// stahp if empty string
		if (!*each) {
			break;
		}
		// find newline
		char *nl = strchr (each, '\n');
		if (nl) {
			*nl = 0;
			nextLine = nl + 1;
		} else {
			nextLine = NULL;
		}
		// chop comment in line
		nl = strchr (each, '#');
		if (nl) {
			*nl = 0;
		}
		// space separated numbers
		while (each && *each) {
			// find spaces
			while (*each== ' ') each++;
			str = strchr (each, ' ');
			if (str) {
				*str = '\0';
				addr = r_num_math (core->num, each);
				*str = ' ';
				each = str + 1;
			} else {
				if (!*each) {
					break;
				}
				addr = r_num_math (core->num, each);
				each = NULL;
			}
			r_core_seek (core, addr, 1);
			r_core_cmd (core, cmd, 0);
			r_cons_flush ();
		}
		each = nextLine;
	}
	free (cmd);
}

R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each) {
	int i, j;
	char ch;
	char *word = NULL;
	char *str, *ostr = NULL;
	RListIter *iter;
	RFlagItem *flag;
	ut64 oseek, addr;

	for (; *cmd == ' '; cmd++);

	oseek = core->offset;
	ostr = str = strdup (each);
	r_cons_break_push (NULL, NULL); //pop on return
	switch (each[0]) {
	case '/': // "@@/"
		{
		char *cmdhit = strdup (r_config_get (core->config, "cmd.hit"));
		r_config_set (core->config, "cmd.hit", cmd);
		r_core_cmd0 (core, each);
		r_config_set (core->config, "cmd.hit", cmdhit);
		free (cmdhit);
		}
		return 0;
	case '?': // "@@?"
		r_core_cmd_help (core, help_msg_at_at);
		break;
	case 'b': // "@@b" - function basic blocks
		{
			RListIter *iter;
			RAnalBlock *bb;
			RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, core->offset, 0);
			int bs = core->blocksize;
			if (fcn) {
				r_list_sort (fcn->bbs, bb_cmp);
				r_list_foreach (fcn->bbs, iter, bb) {
					r_core_block_size (core, bb->size);
					r_core_seek (core, bb->addr, 1);
					r_core_cmd (core, cmd, 0);
					if (r_cons_is_breaked ()) {
						break;
					}
				}
			}
			r_core_block_size (core, bs);
			goto out_finish;
		}
		break;
	case 's': // "@@s" - sequence
		{
			char *str = each + 1;
			if (*str == ':' || *str == ' ') {
				str++;
			}
			int count = r_str_split (str, ' ');
			if (count == 3) {
				ut64 cur;
				ut64 from = r_num_math (core->num, r_str_word_get0 (str, 0));
				ut64 to = r_num_math (core->num, r_str_word_get0 (str, 1));
				ut64 step = r_num_math (core->num, r_str_word_get0 (str, 2));
				for (cur = from; cur < to; cur += step) {
					(void)r_core_seek (core, cur, 1);
					r_core_cmd (core, cmd, 0);
					if (r_cons_is_breaked ()) {
						break;
					}
				}
			} else {
				eprintf ("Usage: cmd @@s:from to step\n");
			}
			goto out_finish;
		}
		break;
	case 'i': // "@@i" - function instructions
		if (each[1] == 'S') {
			RListIter *it;
			RBinSection *sec;
			RBinObject *obj = r_bin_cur_object (core->bin);
			int cbsz = core->blocksize;
			r_list_foreach (obj->sections, it, sec){
				ut64 addr = sec->vaddr;
				ut64 size = sec->vsize;
				// TODO: 
				//if (R_BIN_SCN_EXECUTABLE & sec->srwx) {
				//	continue;
				//}
				r_core_seek_size (core, addr, size);
				r_core_cmd (core, cmd, 0);
			}
			r_core_block_size (core, cbsz);
		} else {
			RListIter *iter;
			RAnalBlock *bb;
			int i;
			RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, core->offset, 0);
			if (fcn) {
				r_list_sort (fcn->bbs, bb_cmp);
				r_list_foreach (fcn->bbs, iter, bb) {
					for (i = 0; i < bb->op_pos_size; i++) {
						ut64 addr = bb->addr + bb->op_pos[i];
						r_core_seek (core, addr, 1);
						r_core_cmd (core, cmd, 0);
						if (r_cons_is_breaked ()) {
							break;
						}
					}
				}
			}
			goto out_finish;
		}
		break;
	case 'f': // "@@f"
		if (each[1] == ':') {
			RAnalFunction *fcn;
			RListIter *iter;
			if (core->anal) {
				r_list_foreach (core->anal->fcns, iter, fcn) {
					if (each[2] && strstr (fcn->name, each + 2)) {
						r_core_seek (core, fcn->addr, 1);
						r_core_cmd (core, cmd, 0);
						if (r_cons_is_breaked ()) {
							break;
						}
					}
				}
			}
			goto out_finish;
		} else {
			RAnalFunction *fcn;
			RListIter *iter;
			if (core->anal) {
				RConsGrep grep = core->cons->grep;
				r_list_foreach (core->anal->fcns, iter, fcn) {
					char *buf;
					r_core_seek (core, fcn->addr, 1);
					r_cons_push ();
					r_core_cmd (core, cmd, 0);
					buf = (char *)r_cons_get_buffer ();
					if (buf) {
						buf = strdup (buf);
					}
					r_cons_pop ();
					r_cons_strcat (buf);
					free (buf);
					if (r_cons_is_breaked ()) {
						break;
					}
				}
				core->cons->grep = grep;
			}
			goto out_finish;
		}
		break;
	case 't': // "@@t"
		{
			RDebugPid *p;
			int pid = core->dbg->pid;
			if (core->dbg->h && core->dbg->h->pids) {
				RList *list = core->dbg->h->pids (core->dbg, R_MAX (0, pid));
				r_list_foreach (list, iter, p) {
					r_cons_printf ("# PID %d\n", p->pid);
					r_debug_select (core->dbg, p->pid, p->pid);
					r_core_cmd (core, cmd, 0);
					r_cons_newline ();
				}
				r_list_free (list);
			}
			r_debug_select (core->dbg, pid, pid);
			goto out_finish;
		}
		break;
	case 'c': // "@@c:"
		if (each[1] == ':') {
			char *arg = r_core_cmd_str (core, each + 2);
			if (arg) {
				foreachOffset (core, cmd, arg);
			}
		}
		break;
	case '=': // "@@="
		foreachOffset (core, cmd, str + 1);
		break;
	case 'd': // "@@d"
		if (each[1] == 'b' && each[2] == 't') {
			ut64 oseek = core->offset;
			RDebugFrame *frame;
			RListIter *iter;
			RList *list;
			list = r_debug_frames (core->dbg, UT64_MAX);
			i = 0;
			r_list_foreach (list, iter, frame) {
				switch (each[3]) {
				case 'b':
					r_core_seek (core, frame->bp, 1);
					break;
				case 's':
					r_core_seek (core, frame->sp, 1);
					break;
				default:
				case 'a':
					r_core_seek (core, frame->addr, 1);
					break;
				}
				r_core_cmd (core, cmd, 0);
				r_cons_newline ();
				i++;
			}
			r_core_seek (core, oseek, 0);
			r_list_free (list);
		} else {
			eprintf("Invalid for-each statement. Use @@=dbt[abs]\n");
		}
		break;
	case 'k': // "@@k"
		/* foreach list of items */
		{
		char *out = sdb_querys (core->sdb, NULL, 0, str + ((str[1])? 2: 1));
		if (out) {
			each = out;
			do {
				while (*each == ' ') each++;
				if (!*each) {
					break;
				}
				str = strchr (each, ' ');
				if (str) {
					*str = '\0';
					addr = r_num_math (core->num, each);
					*str = ' ';
				} else {
					addr = r_num_math (core->num, each);
				}
				//eprintf ("; 0x%08"PFMT64x":\n", addr);
				each = str + 1;
				r_core_seek (core, addr, 1);
				r_core_cmd (core, cmd, 0);
				r_cons_flush ();
			} while (str != NULL);
			free (out);
		}
		}
		break;
	case '.': // "@@."
		if (each[1] == '(') {
			char cmd2[1024];
			// XXX whats this 999 ?
			i = 0;
			for (core->rcmd->macro.counter = 0; i < 999; core->rcmd->macro.counter++) {
				if (r_cons_is_breaked ()) {
					break;
				}
				r_cmd_macro_call (&core->rcmd->macro, each + 2);
				if (!core->rcmd->macro.brk_value) {
					break;
				}
				addr = core->rcmd->macro._brk_value;
				sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
				eprintf ("0x%08"PFMT64x" (%s)\n", addr, cmd2);
				r_core_seek (core, addr, 1);
				r_core_cmd (core, cmd2, 0);
				i++;
			}
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = r_sandbox_fopen (each + 1, "r");
			if (fd) {
				core->rcmd->macro.counter=0;
				while (!feof (fd)) {
					buf[0] = '\0';
					if (!fgets (buf, sizeof (buf), fd)) {
						break;
					}
					addr = r_num_math (core->num, buf);
					eprintf ("0x%08"PFMT64x": %s\n", addr, cmd);
					sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
					r_core_seek (core, addr, 1); // XXX
					r_core_cmd (core, cmd2, 0);
					core->rcmd->macro.counter++;
				}
				fclose (fd);
			} else {
				eprintf ("cannot open file '%s' to read offsets\n", each + 1);
			}
		}
		break;
	default:
		core->rcmd->macro.counter = 0;
		for (; *each == ' '; each++);
		i = 0;
		while (str[i]) {
			j = i;
			for (; str[j] && str[j] == ' '; j++); // skip spaces
			for (i = j; str[i] && str[i] != ' '; i++); // find EOS
			ch = str[i];
			str[i] = '\0';
			word = strdup (str + j);
			if (!word) {
				break;
			}
			str[i] = ch;
			{
				int flagspace = core->flags->space_idx;
				/* for all flags in current flagspace */
				// XXX: dont ask why, but this only works with _prev..
				r_list_foreach (core->flags->flags, iter, flag) {
					if (r_cons_is_breaked ()) {
						break;
					}
					/* filter per flag spaces */
					if ((flagspace != -1) && (flag->space != flagspace)) {
						continue;
					}
					if (r_str_glob (flag->name, word)) {
						char *buf = NULL;
						const char *tmp = NULL;
						r_core_seek (core, flag->offset, 1);
						r_cons_push ();
						r_core_cmd (core, cmd, 0);
						tmp = r_cons_get_buffer ();
						buf = tmp? strdup (tmp): NULL;
						r_cons_pop ();
						r_cons_strcat (buf);
						free (buf);
					}
				}
				core->flags->space_idx = flagspace;
				core->rcmd->macro.counter++ ;
				free (word);
				word = NULL;
			}
		}
	}
	r_cons_break_pop ();
	// XXX: use r_core_seek here
	core->offset = oseek;

	free (word);
	free (ostr);
	return true;
out_finish:
	free (ostr);
	r_cons_break_pop ();
	return false;
}

R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
	char *cmd, *ocmd, *ptr, *rcmd;
	int ret = false, i;

	r_th_lock_enter (core->lock);
	if (core->cmdfilter) {
		const char *invalid_chars = ";|>`@";
		for (i = 0; invalid_chars[i]; i++) {
			if (strchr (cstr, invalid_chars[i])) {
				ret = true;
				goto beach;
			}
		}
		if (strncmp (cstr, core->cmdfilter, strlen (core->cmdfilter))) {
			ret = true;
			goto beach;
		}
	}
	if (core->cmdremote) {
		if (*cstr != '=' && *cstr != 'q' && strncmp (cstr, "!=", 2)) {
			char *res = r_io_system (core->io, cstr);
			if (res) {
				r_cons_printf ("%s\n", res);
				free (res);
			}
			goto beach; // false
		}
	}

	if (!cstr || (*cstr == '|' && cstr[1] != '?')) {
		// raw comment syntax
		goto beach; // false;
	}
	if (!strncmp (cstr, "/*", 2)) {
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			goto beach; // false
		}
		core->incomment = true;
	} else if (!strncmp (cstr, "*/", 2)) {
		core->incomment = false;
		goto beach; // false
	}
	if (core->incomment) {
		goto beach; // false
	}
	if (log && (*cstr && (*cstr != '.' || !strncmp (cstr, ".(", 2)))) {
		free (core->lastcmd);
		core->lastcmd = strdup (cstr);
	}

	ocmd = cmd = malloc (strlen (cstr) + 4096);
	if (!ocmd) {
		goto beach;
	}
	r_str_cpy (cmd, cstr);
	if (log) {
		r_line_hist_add (cstr);
	}

	if (core->cmd_depth < 1) {
		eprintf ("r_core_cmd: That was too deep (%s)...\n", cmd);
		free (ocmd);
		free (core->oobi);
		core->oobi = NULL;
		core->oobi_len = 0;
		goto beach;
	}
	core->cmd_depth--;
	for (rcmd = cmd;;) {
		ptr = strchr (rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);
		if (ret == -1) {
			eprintf ("|ERROR| Invalid command '%s' (0x%02x)\n", rcmd, *rcmd);
			break;
		}
		if (!ptr) {
			break;
		}
		rcmd = ptr + 1;
	}
	r_th_lock_leave (core->lock);
	/* run pending analysis commands */
	if (core && core->anal && core->anal->cmdtail) {
		char *res = core->anal->cmdtail;
		core->anal->cmdtail = NULL;
		r_core_cmd_lines (core, res);
		free (res);
	}
	core->cmd_depth++;
	free (ocmd);
	free (core->oobi);
	core->oobi = NULL;
	core->oobi_len = 0;
	return ret;
beach:
	r_th_lock_leave (core->lock);
	/* run pending analysis commands */
	if (core->anal->cmdtail) {
		char *res = core->anal->cmdtail;
		core->anal->cmdtail = NULL;
		r_core_cmd0 (core, res);
		free (res);
	}
	return ret;
}

R_API int r_core_cmd_lines(RCore *core, const char *lines) {
	int r, ret = true;
	char *nl, *data, *odata;

	if (!lines || !*lines) {
		return true;
	}
	data = odata = strdup (lines);
	if (!odata) {
		return false;
	}
	nl = strchr (odata, '\n');
	if (nl) {
		r_cons_break_push (NULL, NULL);
		do {
			if (r_cons_is_breaked ()) {
				free (odata);
				r_cons_break_pop ();
				return ret;
			}
			*nl = '\0';
			r = r_core_cmd (core, data, 0);
			if (r < 0) { //== -1) {
				data = nl + 1;
				ret = -1; //r; //false;
				break;
			}
			r_cons_flush ();
			if (data[0] == 'q') {
				if (data[1] == '!') {
					ret = -1;
				} else {
					eprintf ("'q': quit ignored. Use 'q!'\n");
				}
				data = nl + 1;
				break;
			}
			data = nl + 1;
		} while ((nl = strchr (data, '\n')));
		r_cons_break_pop ();
	}
	if (ret >= 0 && data && *data) {
		r_core_cmd (core, data, 0);
	}
	free (odata);
	return ret;
}

R_API int r_core_cmd_file(RCore *core, const char *file) {
	char *data = r_file_abspath (file);
	if (!data) {
		return false;
	}
	char *odata = r_file_slurp (data, NULL);
	free (data);
	if (!odata) {
		return false;
	}
	if (!r_core_cmd_lines (core, odata)) {
		eprintf ("Failed to run script '%s'\n", file);
		free (odata);
		return false;
	}
	free (odata);
	return true;
}

R_API int r_core_cmd_command(RCore *core, const char *command) {
	int ret, len;
	char *buf, *rcmd, *ptr;
	char *cmd = r_core_sysenv_begin (core, command);
	rcmd = ptr = buf = r_sys_cmd_str (cmd, 0, &len);
	if (!buf) {
		free (cmd);
		return -1;
	}
	ret = r_core_cmd (core, rcmd, 0);
	r_core_sysenv_end (core, command);
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
	if (!str) return false;
	optr = str;
	ptr = strchr (str, '\n');
	while (ptr) {
		*ptr = '\0';
		r_core_cmd (user, optr, 0);
		optr = ptr + 1;
		ptr = strchr (str, '\n');
	}
	r_core_cmd (user, optr, 0);
	free (str);
	return true;
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
	char *s, *tmp = NULL;
	if (r_sandbox_enable (0)) {
		char *p = (*cmd != '"')? strchr (cmd, '|'): NULL;
		if (p) {
			// This code works but its pretty ugly as its a workaround to
			// make the webserver work as expected, this was broken some
			// weeks. let's use this hackaround for now
			char *c = strdup (cmd);
			c[p - cmd] = 0;
			if (!strcmp (p + 1, "H")) {
				char *res = r_core_cmd_str (core, c);
				free (c);
				char *hres = r_cons_html_filter (res, NULL);
				free (res);
				return hres;
			} else {
				int sh = r_config_get_i (core->config, "scr.color");
				r_config_set_i (core->config, "scr.color", 0);
				char *ret = r_core_cmd_str (core, c);
				r_config_set_i (core->config, "scr.color", sh);
				free (c);
				return ret;
			}
		}
		return r_core_cmd_str (core, cmd);
	}
	r_cons_reset ();
	r_sandbox_disable (1);
	if (r_file_mkstemp ("cmd", &tmp) != -1) {
		int pipefd = r_cons_pipe_open (tmp, 1, 0);
		if (pipefd == -1) {
			r_file_rm (tmp);
			r_sandbox_disable (0);
			free (tmp);
			return r_core_cmd_str (core, cmd);
		}
		char *_cmd = strdup (cmd);
		r_core_cmd_subst (core, _cmd);
		r_cons_flush ();
		r_cons_pipe_close (pipefd);
		s = r_file_slurp (tmp, NULL);
		if (s) {
			r_file_rm (tmp);
			r_sandbox_disable (0);
			free (tmp);
			free (_cmd);
			return s;
		}
		eprintf ("slurp %s fails\n", tmp);
		r_file_rm (tmp);
		free (tmp);
		free (_cmd);
		r_sandbox_disable (0);
		return r_core_cmd_str (core, cmd);
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
	r_cons_push ();
	if (r_core_cmd (core, cmd, 0) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		return NULL;
	}
	r_cons_filter ();
	static_str = r_cons_get_buffer ();
	retstr = strdup (static_str? static_str: "");
	r_cons_pop ();
	return retstr;
}

R_API void r_core_cmd_repeat(RCore *core, int next) {
	// Fix for backtickbug px`~`
	if (!core->lastcmd || core->cmd_depth < 1) {
		return;
	}
	switch (*core->lastcmd) {
	case '.':
		if (core->lastcmd[1] == '(') { // macro call
			r_core_cmd0 (core, core->lastcmd);
		}
		break;
	case 'd': // debug
		r_core_cmd0 (core, core->lastcmd);
		switch (core->lastcmd[1]) {
		case 's':
		case 'c':
			r_core_cmd0 (core, "sr PC;pd 1");
		}
		break;
	case 'p': // print
	case 'x':
	case '$':
		if (!strncmp (core->lastcmd, "pd", 2)) {
			if (core->lastcmd[2]== ' ') {
				r_core_cmdf (core, "so %s", core->lastcmd + 3);
			} else {
				r_core_cmd0 (core, "so `pi~?`");
			}
		} else {
			if (next) {
				r_core_seek (core, core->offset + core->blocksize, 1);
			} else {
				if (core->blocksize > core->offset) {
					r_core_seek (core, 0, 1);
				} else {
					r_core_seek (core, core->offset - core->blocksize, 1);
				}
			}
		}
		r_core_cmd0 (core, core->lastcmd);
		break;
	}
}

static int cmd_ox(void *data, const char *input) {
	return r_core_cmdf ((RCore*)data, "s 0%s", input);
}

static int compare_cmd_descriptor_name(const void *a, const void *b) {
	return strcmp (((RCmdDescriptor *)a)->cmd, ((RCmdDescriptor *)b)->cmd);
}

static void cmd_descriptor_init(RCore *core) {
	const ut8 *p;
	RListIter *iter;
	RCmdDescriptor *x, *y;
	int n = core->cmd_descriptors->length;
	r_list_sort (core->cmd_descriptors, compare_cmd_descriptor_name);
	r_list_foreach (core->cmd_descriptors, iter, y) {
		if (--n < 0) {
			break;
		}
		x = &core->root_cmd_descriptor;
		for (p = (const ut8 *)y->cmd; *p; p++) {
			if (!x->sub[*p]) {
				if (p[1]) {
					RCmdDescriptor *d = R_NEW0 (RCmdDescriptor);
					r_list_append (core->cmd_descriptors, d);
					x->sub[*p] = d;
				} else {
					x->sub[*p] = y;
				}
			} else if (!p[1]) {
				eprintf ("Command '%s' is duplicated, please check\n", y->cmd);
			}
			x = x->sub[*p];
		}
	}
}

R_API void r_core_cmd_init(RCore *core) {
	struct {
		const char *cmd;
		const char *description;
		r_cmd_callback(cb);
		void (*descriptor_init)(RCore *core);
	} cmds[] = {
		{"!",        "run system command", cmd_system},
		{"#",        "calculate hash", cmd_hash},
		{"$",        "alias", cmd_alias},
		{"%",        "short version of 'env' command", cmd_env},
		{"&",        "threading capabilities", cmd_thread},
		{"(",        "macro", cmd_macro, cmd_macro_init},
		{"*",        "pointer read/write", cmd_pointer},
		{"-",        "open cfg.editor and run script", cmd_stdin},
		{".",        "interpret", cmd_interpret},
		{"/",        "search kw, pattern aes", cmd_search, cmd_search_init},
		{"=",        "io pipe", cmd_rap},
		{"?",        "help message", cmd_help, cmd_help_init},
		{"\\",       "alias for =!", cmd_rap_run},
		{"0x",       "alias for s 0x", cmd_ox},
		{"analysis", "analysis", cmd_anal, cmd_anal_init},
		{"bsize",    "change block size", cmd_bsize},
		{"cmp",      "compare memory", cmd_cmp, cmd_cmp_init},
		{"Code",     "code metadata", cmd_meta, cmd_meta_init},
		{"debug",    "debugger operations", cmd_debug, cmd_debug_init},
		{"eval",     "evaluate configuration variable", cmd_eval, cmd_eval_init},
		{"flag",     "get/set flags", cmd_flag, cmd_flag_init},
		{"g",        "egg manipulation", cmd_egg, cmd_egg_init},
		{"info",     "get file info", cmd_info, cmd_info_init},
		{"kuery",    "perform sdb query", cmd_kuery},
		{"ls",       "list files and directories", cmd_ls},
		{"L",        "manage dynamically loaded plugins", cmd_plugins},
		{"mount",    "mount filesystem", cmd_mount, cmd_mount_init},
		{"open",     "open or map file", cmd_open, cmd_open_init},
		{"print",    "print current block", cmd_print, cmd_print_init},
		{"Project",  "project", cmd_project, cmd_project_init},
		{"quit",     "exit program session", cmd_quit, cmd_quit_init},
		{"Q",        "alias for q!", cmd_Quit},
		{"resize",   "change file size", cmd_resize},
		{"seek",     "seek to an offset", cmd_seek, cmd_seek_init},
		{"Section",  "setup section io information", cmd_section, cmd_section_init},
		{"t",        "type information (cparse)", cmd_type, cmd_type_init},
		{"Text",     "Text log utility", cmd_log, cmd_log_init},
		{"u",        "uname/undo", cmd_uname},
		{"visual",   "enter visual mode", cmd_visual},
		{"<",        "pipe into RCons.readChar", cmd_pipein},
		{"Visual",   "enter visual mode", cmd_visual},
		{"write",    "write bytes", cmd_write, cmd_write_init},
		{"x",        "alias for px", cmd_hexdump},
		{"yank",     "yank bytes", cmd_yank},
		{"zign",     "zignatures", cmd_zign, cmd_zign_init},
	};

	core->rcmd = r_cmd_new ();
	core->rcmd->macro.user = core;
	core->rcmd->macro.num = core->num;
	core->rcmd->macro.cmd = r_core_cmd0;
	core->rcmd->nullcallback = r_core_cmd_nullcallback;
	core->rcmd->macro.cb_printf = (PrintfCallback)r_cons_printf;
	r_cmd_set_data (core->rcmd, core);
	core->cmd_descriptors = r_list_newf (free);
	int i;
	for (i = 0; i < R_ARRAY_SIZE (cmds); i++) {
		r_cmd_add (core->rcmd, cmds[i].cmd, cmds[i].description, cmds[i].cb);
		if (cmds[i].descriptor_init) {
			cmds[i].descriptor_init (core);
		}
	}
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, $, dollar);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, %, percent);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, *, star);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, ., dot);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, =, equal);
	DEFINE_CMD_DESCRIPTOR (core, b);
	DEFINE_CMD_DESCRIPTOR (core, k);
	DEFINE_CMD_DESCRIPTOR (core, r);
	DEFINE_CMD_DESCRIPTOR (core, u);
	DEFINE_CMD_DESCRIPTOR (core, y);
	cmd_descriptor_init (core);
}
