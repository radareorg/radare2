/* radare - LGPL - Copyright 2009-2022 - nibble, pancake */

#define INTERACTIVE_MAX_REP 1024

#include <r_core.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#if __UNIX__
#include <sys/utsname.h>
#ifndef __wasi__
#include <pwd.h>
#endif
#endif

static const char *SPECIAL_CHARS_REGULAR = "@;~$#|`\"'()<>";

static bool isAnExport(RBinSymbol *s) {
	/* workaround for some bin plugs */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp (s->bind, R_BIN_BIND_GLOBAL_STR));
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char* colon, bool *tmpseek);

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

static void cmd_debug_reg(RCore *core, const char *str);

#include "cmd_quit.c"
#include "cmd_hash.c"
#include "cmd_debug.c"
#include "cmd_log.c"
#include "cmd_flag.c"
#include "cmd_zign.c"
#include "cmd_project.c"
#include "cmd_write.c"
#include "cmd_cmp.c"
#include "cmd_eval.c"
#include "cmd_type.c"
#include "cmd_anal.c"
#include "cmd_open.c"
#include "cmd_meta.c"
#include "cmd_egg.c"
#include "cmd_info.c"
#include "cmd_macro.c"
#include "cmd_magic.c"
#include "cmd_mount.c"
#include "cmd_seek.c"
#include "cmd_search.c" // defines incDigitBuffer... used by cmd_print
#include "cmd_print.c"
#include "cmd_help.c"

static const char *help_msg_dollar[] = {
	"Usage:", "$alias[=cmd] [args...]", "Alias commands and strings (See ?$? for help on $variables)",
	"$", "", "list all defined aliases",
	"$*", "", "list all defined aliases and their respective values, unprintable characters escaped",
	"$**", "", "same as above, but if an alias has unprintable characters, b64 encode it",
	"$", "foo:=123", "alias for 'f foo=123'",
	"$", "foo-=4", "alias for 'f foo-=4'",
	"$", "foo+=4", "alias for 'f foo+=4'",
	"$", "foo", "alias for 's foo' (note that command aliases can override flag resolution)",
	"$", "dis=base64:AAA=", "alias $dis to the raw byte output from decoding this base64 string",
	"$", "dis=$hello world", "alias $dis to the string after '$' (accepts double-backslash and hex escaping)",
	"$", "dis=-", "edit $dis in cfg.editor (accepts backslash and hex escaping)",
	"$", "dis=af", "alias $dis to the af command",
	"$", "dis=af;pdf", "alias $dis to the af command, then run pdf",
	"$", "test=#!pipe node /tmp/test.js", "create command - rlangpipe script",
	"$", "dis=", "undefine alias",
	"$", "dis", "execute a defined command alias, or print a data alias with unprintable characters escaped",
	"$", "dis?", "show commands aliased by $dis",
	NULL
};

static const char *help_msg_l[] = {
	"Usage:", "l[erls] [arg]", "Internal less (~..) and file listing (!ls)",
	"ll", " [path]", "same as ls -l",
	"lr", " [path]", "same as ls -r",
	"ls", " [-e,-l,-j,-q] [path]", "list files in current or given directory",
	"ls", " -e [path]", "list files using emojis",
	"ls", " -l [path]", "same as ll (list files with details)",
	"ls", " -j [path]", "list files in json format",
	"ls", " -q [path]", "quiet output (one file per line)",
	"le", "[ss] [path]", "same as cat file~.. (or less)",
	"TODO: last command should honor asm.bits", "", "",
	NULL
};

static const char *help_msg_plus[] = {
	"Usage:", "+", "seek forward, same as s+X (see s? and -? for more help)",
	"+", "8", "seek 8 bytes forward, same as s+8",
	"++", "", "seek one block forward. Same as s++ (see `b` command)",
	NULL
};

static const char *help_msg_dash[] = {
	"Usage:", "-", "open editor and run the r2 commands in the saved document",
	"", "'-' '.-' '. -'", " those three commands do the same",
	"-", "8", "same as s-8, but shorter to type (see +? command)",
	"--", "", "seek one block backward. Same as s-- (see `b` command)",
	NULL
};

static const char *help_msg_star[] = {
	"Usage:", "*<addr>[=[0x]value]", "Pointer read/write data/values",
	"*", "entry0=cc", "write trap in entrypoint",
	"*", "entry0+10=0x804800", "write value in delta address",
	"*", "entry0", "read byte at given address",
	"*", "/", "end multiline comment. (use '/*' to start mulitiline comment",
	"TODO: last command should honor asm.bits", "", "",
	NULL
};

static const char *cmd_table_help[] = {
	"Usage:", ",[,.-/*jhr] [file]", "# load table data",
	",", "", "display table",
	", ", "[table-query]", "filter and print table. See ,? for more details",
	",.", " file.csv", "load table from CSV file (comma dot)",
	",,", "", "print table in csv format (comma comma)",
	",-", "", "reset table",
	",/", "?", "query/filter current table (non-destructive)",
	",*", ">$foo", "print table as r2 commands",
	",j", "", "print table in json format",
	",h", " xxd foo bar cow", "define header column names and types",
	",r", " 1 2 foo", "adds a row using the given format string",
	NULL
};

static const char *help_msg_dot[] = {
	"Usage:", ".[r2cmd] | [file] | [!command] | [(macro)]", "# define macro or interpret r2, r_lang,\n"
	"    cparse, d, es6, exe, go, js, lsp, pl, py, rb, sh, vala or zig file",
	".", "", "repeat last command backward",
	".", "C*", "run 'C*' command and interpret the printed commands",
	"..", "123", "alias for s..123 (notice the lack of space)",
	"..", " [file]", "run the output of the execution of a script as r2 commands",
	"...", "", "repeat last command forward (same as \\n)",
	// ".:", "8080", "listen for commands on given tcp port",
	".--", "", "terminate tcp server for remote commands",
	".", " foo.r2", "interpret script",
	".", " foo.py", "also works for running r2pipe and rlang scripts",
	".-", "", "open cfg.editor and interpret tmp file",
	".*", " file ...", "same as #!pipe open cfg.editor and interpret tmp file",
	".!", "rabin -ri $FILE", "interpret output of command",
	".", "(foo 1 2 3)", "run macro 'foo' with args 1, 2, 3",
	"./", " ELF", "interpret output of command /m ELF as r. commands",
	NULL
};

static const char *help_msg_equal[] = {
	"Usage:", " =[:!+-=ghH] [...]", " # connect with other instances of r2",
	"\nremote commands:", "", "",
	"=", "", "list all open connections",
	"=<", "[fd] cmd", "send output of local command to remote fd", // XXX may not be a special char
	"=", "[fd] cmd", "exec cmd at remote 'fd' (last open is default one)",
	"=!", " cmd", "run command via r_io_system",
	"=+", " [proto://]host:port", "connect to remote host:port (*rap://, raps://, tcp://, udp://, http://)",
	"=-", "[fd]", "remove all hosts or host 'fd'",
	"==", "[fd]", "open remote session with host 'fd', 'q' to quit",
	"=!=", "", "disable remote cmd mode",
	"!=!", "", "enable remote cmd mode",
	"\nservers:","","",
	// ".:", "9000", "start the tcp server (echo x|nc ::1 9090 or curl ::1:9090/cmd/x)",
	"=t", "port", "start the tcp server (echo x|nc ::1 9090 or curl ::1:9090/cmd/x)",
	"=r", "port", "start the rap server (o rap://9999)",
	"=g", "[?]", "start the gdbserver",
	"=h", "[?]", "start the http webserver",
	"=H", "[?]", "start the http webserver (and launch the web browser)",
	"\nother:","","",
	"=&", ":port", "start rap server in background (same as '&_=h')",
	"=", ":host:port cmd", "run 'cmd' command on remote server",
	"\nexamples:","","",
	"=+", "tcp://localhost:9090/", "connect to: r2 -c.:9090 ./bin",
	// "=+", "udp://localhost:9090/", "connect to: r2 -c.:9090 ./bin",
	"=+", "rap://localhost:9090/", "connect to: r2 rap://:9090",
	"=+", "http://localhost:9090/cmd/", "connect to: r2 -c'=h 9090' bin",
	"o ", "rap://:9090/", "start the rap server on tcp port 9090",
	NULL
};

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

static const char *help_msg_equal_equal[] = {
	"Usage:", " ==[=] ", "# add connection to remote r2",
	"==", "[fd]", "shell to send to the nth remote (see '=1 x' / '==1'",
	"===", "event", "returns socket file or udp port to read events from",
	NULL
};

static const char *help_msg_equal_more[] = {
	"Usage:", " =+ [proto://][host]:[port](/[path])", " # add connection to remote r2",
	"=+", "tcp://localhost:9090", "communicates with another instance running '& .:9090'",
	"=+", "http://localhost:9090/cmd", "talks to remote r2 webserver '& =h'",
	"=+", "rap://localhost:9090/cmd", "talks to remote r2 webserver 'r2 rap://:9090'",
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
	"b", " 33", "set block size to 33",
	"b", " eip+4", "numeric argument can be an expression",
	"b", "", "display current block size",
	"b", "+3", "increase blocksize by 3",
	"b", "-16", "decrease blocksize by 16",
	"b*", "", "display current block size in r2 command",
	"bf", " foo", "set block size to flag size",
	"bj", "", "display block size information in JSON",
	"bm", " 1M", "set max block size",
	NULL
};

static const char *help_msg_k[] = {
	"Usage:", "k[s] [key[=value]]", "Sdb Query",
	"k", " anal/**", "list namespaces under anal",
	"k", " anal/meta/*", "list kv from anal > meta namespaces",
	"k", " anal/meta/meta.0x80404", "get value for meta.0x80404 key",
	"k", " foo", "show value",
	"k", " foo=bar", "set value",
	"k", "", "list keys",
	"kd", " [file.sdb] [ns]", "dump namespace to disk",
	"kj", "", "List all namespaces and sdb databases in JSON format",
	"ko", " [file.sdb] [ns]", "open file into namespace",
	"ks", " [ns]", "enter the sdb query shell",
	//"kl", " ha.sdb", "load keyvalue from ha.sdb",
	//"ks", " ha.sdb", "save keyvalue to ha.sdb",
	NULL,
};

static const char *help_msg_r[] = {
	"Usage:", "r[+-][ size]", "Resize file",
	"r", "", "display file size",
	"rj", "", "display the file size in JSON format",
	"r", " size", "expand or truncate file to given size",
	"r-", "num", "remove num bytes, move following data down",
	"r+", "num", "insert num bytes, move following data up",
	"r2pm", " [...]", "run r2pm's main",
	"rabin2", " [...]", "run rabin2's main",
	"radare2", " [...]", "run radare2's main",
	"radiff2", " [...]", "run radiff2's main",
	"rafind2", " [...]", "run rafind2's main",
	"rahash2", " [...]", "run rahash2's main",
	"rasm2", " [...]", "run rasm2's main",
	"rax2", " [...]", "run rax2's main",
	"rb", "oldbase @ newbase", "rebase all flags, bin.info, breakpoints and analysis",
	"rm" ," [file]", "remove file",
	"rh" ,"", "show size in human format",
	"r2" ," [file]", "launch r2 (same for rax2, rasm2, ...)",
	"reset" ,"", "reset console settings (clear --hard)",
	NULL
};

static const char *help_msg_u[] = {
	"Usage:", "u", "uname or undo write/seek",
	"u", "", "show system uname",
	"uw", "", "alias for wc (requires: e io.cache=true)",
	"us", "", "alias for s- (seek history)",
	"uc", "[?]", "undo core commands (uc?, ucl, uc*, ..)",
	"uid", "", "display numeric user id",
	"uniq", "", "filter rows to avoid duplicates",
	"uname", "", "uname - show system information",
	NULL
};

static const char *help_msg_uc[] = {
	"Usage:", "uc [cmd] [revert-cmd]", "undo core commands",
	"uc", "", "list all core undos",
	"uc*", "", "list all core undos as r2 commands",
	"uc-", "", "undo last action",
	"uc.", "", "list all reverts in current",
	NULL
};

static const char *help_msg_y[] = {
	"Usage:", "y[ptxy] [len] [[@]addr]", " # See wd? for memcpy, same as 'yf'.",
	"y!", "", "open cfg.editor to edit the clipboard",
	"y", " 16 @ 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16", "copy 16 bytes into clipboard",
	"y", "", "show yank buffer information (origin len bytes)",
	"y*", "", "print in r2 commands what's been yanked",
	"yf", " 64 0x200", "copy file 64 bytes from 0x200 from file",
	"yfa", " file copy", "copy all bytes from file (opens w/ io)",
	"yfx", " 10203040", "yank from hexpairs (same as ywx)",
	"yj", "", "print in JSON commands what's been yanked",
	"yp", "", "print contents of clipboard",
	"yq", "", "print contents of clipboard in hexpairs",
	"ys", "", "print contents of clipboard as string",
	"yt", " 64 0x200", "copy 64 bytes from current seek to 0x200",
	"ytf", " file", "dump the clipboard to given file",
	"yw", " hello world", "yank from string",
	"ywx", " 10203040", "yank from hexpairs (same as yfx)",
	"yx", "", "print contents of clipboard in hexadecimal",
	"yy", " @ 0x3344", "paste contents of clipboard to 0x3344",
	"yy", " 0x3344", "paste contents of clipboard to 0x3344",
	"yy", "", "paste contents of clipboard at current seek",
	"yz", " [len]", "copy nul-terminated string (up to blocksize) into clipboard",
	NULL
};

static const char *help_msg_triple_exclamation[] = {
	"Usage:", "!!![-*][cmd] [arg|$type...]", " # user-defined autocompletion for commands",
	"!!!", "", "list all autocompletions",
	"!!!?", "", "show this help",
	"!!!", "-*", "remove all user-defined autocompletions",
	"!!!", "-\\*", "remove autocompletions matching this glob expression",
	"!!!", "-foo", "remove autocompletion named 'foo'",
	"!!!", "foo", "add 'foo' for autocompletion",
	"!!!", "bar $flag", "add 'bar' for autocompletion with $flag as argument",
	"Types:", "", "",
	NULL
};

static const char *help_msg_vertical_bar[] = {
	"Usage:", "[cmd] | [program|H|T|.|]", "",
	"", "[cmd] |?", "show this help",
	"", "[cmd] |", "disable scr.html and scr.color",
	"", "[cmd] |H", "enable scr.html, respect scr.color",
	"", "[cmd] |T", "use scr.tts to speak out the stdout",
	"", "[cmd] | [program]", "pipe output of command to program",
	"", "[cmd] |.", "alias for .[cmd]",
	NULL
};

static const char *help_msg_v[] = {
	"Usage:", "v[*i]", "",
	"v", "", "open visual panels",
	"v", " test", "load saved layout with name test",
	"v.", " [file]", "load visual script (also known as slides)",
	"v=", " test", "save current layout with name test",
	"vi", " test", "open the file test in 'cfg.editor'",
	NULL
};

R_API void r_core_cmd_help(const RCore *core, const char *help[]) {
	r_cons_cmd_help (help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

R_API void r_core_cmd_help_match(const RCore *core, const char *help[], R_BORROW R_NONNULL char *cmd, bool exact) {
	r_cons_cmd_help_match (help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, 0, exact);
}

R_API void r_core_cmd_help_match_spec(const RCore *core, const char *help[], R_BORROW R_NONNULL char *cmd, char spec, bool exact) {
	r_cons_cmd_help_match (help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, spec, exact);
}

struct duplicate_flag_t {
	RList *ret;
	const char *word;
};

static bool duplicate_flag(RFlagItem *flag, void *u) {
	struct duplicate_flag_t *user = (struct duplicate_flag_t *)u;
	/* filter per flag spaces */
	bool valid = strchr (user->word, '*')
		? r_str_glob (flag->name, user->word)
		: strstr (flag->name, user->word) != NULL;
	if (valid) {
		RFlagItem *cloned_item = r_flag_item_clone (flag);
		if (!cloned_item) {
			return false;
		}
		r_list_append (user->ret, cloned_item);
	}
	return true;
}

static bool foreach_newline(RCore *core) {
	bool nl = r_config_get_b (core->config, "scr.loopnl");
	if (nl) {
		r_cons_newline ();
	}
	return !r_cons_is_breaked ();
}

static void recursive_help(RCore *core, int detail, const char *cmd_prefix) {
	if (R_STR_ISEMPTY (cmd_prefix)) {
		recursive_help (core, detail, "%");
		recursive_help (core, detail, "(");
		recursive_help (core, detail, "@");
		recursive_help (core, detail, "!");
		recursive_help (core, detail, "=");
		recursive_help (core, detail, "??");
		recursive_help (core, detail, "~");
	}

	char *s = r_core_cmd_strf (core, "%s?", cmd_prefix);
	RList *pending = r_list_newf (free);
	r_cons_print (s);
	RList *rows = r_str_split_list (s, "\n", 0);

	RListIter *iter;
	char *row;
	r_list_foreach (rows, iter, row) {
		if (strstr (row, "Usage:")) {
			continue;
		}
		char *ch = strstr (row, "[?]");
		if (ch) {
			*ch = 0;
			char *sp = strchr (row, ' ');
			if (sp) {
				bool key_found = false;
				char *k = strdup (sp + 1);
				r_str_ansi_filter (k, NULL, NULL, -1);
				if (strcmp (cmd_prefix, k)) {
					if (!r_list_find (pending, k, (RListComparator)strcmp)) {
						r_list_append (pending, k);
						key_found = true;
					}
				}

				if (!key_found) {
					free (k);
				}
			}
		}
	}
	r_list_free (rows);
	free (s);
	r_list_foreach (pending, iter, row) {
		recursive_help (core, detail, row);
	}
	r_list_free (pending);
}

static bool lastcmd_repeat(RCore *core, int next) {
	int res = -1;
	// Fix for backtickbug px`~`
	if (!core->lastcmd || core->cons->context->cmd_depth < 1) {
		return false;
	}
	switch (*core->lastcmd) {
	case '.':
		if (core->lastcmd[1] == '(') { // macro call
			res = r_core_cmd0 (core, core->lastcmd);
		}
		break;
	case 'd': // debug
		res = r_core_cmd0 (core, core->lastcmd);
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
				r_core_seek (core, core->offset + core->blocksize, true);
			} else {
				if (core->blocksize > core->offset) {
					r_core_seek (core, 0, true);
				} else {
					r_core_seek (core, core->offset - core->blocksize, true);
				}
			}
		}
		res = r_core_cmd0 (core, core->lastcmd);
		break;
	}
	return res != -1;
}

static int r_core_cmd_nullcallback(void *data) {
	RCore *core = (RCore*) data;
	if (core->cons->context->breaked) {
		core->cons->context->breaked = false;
		return 0;
	}
	if (!core->cmdrepeat) {
		return 0;
	}
	lastcmd_repeat (core, true);
	return 1;
}

/* Escape raw bytes if not using b64 */
static bool print_aliases(void *use_b64, const void *key, const void *val){
	const char *k = (char *) key;
	RCmdAliasVal *v = (RCmdAliasVal *) val;
	bool base64 = *(bool *)use_b64;
	if (v->is_str) {
		r_cons_printf ("$%s=%s\n", k, (char *)v->data);
	} else {
		char *val_str = base64
			? r_cmd_alias_val_strdup_b64 (v)
			: r_cmd_alias_val_strdup (v);

		r_cons_printf ("$%s=%s%s\n", k, base64? "base64:": "", val_str);
		free (val_str);
	}
	return true;
}

static int cmd_uname(void *data, const char *input) { // "uniq"
	RSysInfo *si = r_sys_info();
	if (si) {
		r_cons_printf ("%s", si->sysname);
		if (strstr (input, "-r")) {
			r_cons_printf (" %s", si->release);
		}
		r_cons_newline ();
		r_sys_info_free (si);
	}
	return 0;
}

static int cmd_uniq(void *data, const char *input) { // "uniq"
	RCore *core = (RCore *)data;
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg = r_str_trim_head_ro (arg + 1);
	}
	switch (*input) {
	case '?': // "uniq?"
		eprintf ("Usage: uniq # uniq to list unique strings in file\n");
		break;
	default: // "uniq"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_uniq (arg);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	}
	return 0;
}

static int cmd_head(void *data, const char *_input) { // "head"
	RCore *core = (RCore *)data;
	int lines = 5;
	char *input = strdup (_input);
	char *arg = strchr (input, ' ');
	char *tmp, *count;
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg + 1); // contains "count filename"
		count = strchr (arg, ' ');
		if (count) {
			*count = 0;	// split the count and file name
			tmp = (char *)r_str_trim_head_ro (count + 1);
			lines = atoi (arg);
			arg = tmp;
		}
	}
	switch (*input) {
	case '?': // "head?"
		eprintf ("Usage: head [file] # to list first n lines in file\n");
		break;
	default: // "head"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_head (arg, lines);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	}
	free (input);
	return 0;
}

static int cmd_undo(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'c': // "uc"
		switch (input[1]) {
		case ' ': {
			char *cmd = strdup (input + 2);
			char *rcmd = strchr (cmd, ',');
			if (rcmd) {
				*rcmd++ = 0;
				RCoreUndo *undo = r_core_undo_new (core->offset, cmd, rcmd);
				r_core_undo_push (core, undo);
			} else {
				eprintf ("Usage: uc [cmd] [revert-cmd]");
			}
			free (cmd);
			}
			break;
		case '?': // "uc?"
			r_core_cmd_help (core, help_msg_uc);
			break;
		case '.': { // "uc."
			RCoreUndoCondition cond = {
				.addr = core->offset,
				.minstamp = 0,
				.glob = NULL
			};
			r_core_undo_print (core, 1, &cond);
			break;
		}
		case '*': // "uc*"
			r_core_undo_print (core, 1, NULL);
			break;
		case '-': // "uc-"
			r_core_undo_pop (core);
			break;
		default:
			r_core_undo_print (core, 0, NULL);
			break;
		}
		return 1;
	case 'i': // "ui"
		r_cons_printf ("%d\n", r_sys_uid ());
		return 1;
	case 's': // "us"
		r_core_cmdf (data, "s-%s", input + 1);
		return 1;
	case 'w': // "uw"
		r_core_cmdf (data, "wc%s", input + 1);
		return 1;
	case 'n': // "un"
		if (input[1] == 'a') { // "uname"
			(void)cmd_uname (core, input);
		} else if (input[1] == 'i' && input[2] == 'q') {
			(void)cmd_uniq (core, input);
		}
		return 1;
	default:
	case '?': // "u?"
		r_core_cmd_help (data, help_msg_u);
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
	RCore *core = (RCore *)data;
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_dollar);
		return 0;
	}
	char *buf = strdup (input);
	if (!buf) {
		return 0;
	}
	char *q = strchr (buf, ' ');
	char *def = strchr (buf, '=');
	char *desc = strchr (buf, '?');

	if (buf == def) {
		eprintf ("No alias name given.\n");
		free (buf);
		return 0;
	}

	int defmode = 0;
	if (def && def > buf) {
		char *prev = def - 1;
		switch (*prev) {
		case ':':
			defmode = *prev;
			*prev = 0;
			break;
		case '+':
			defmode = *prev;
			*prev = 0;
			break;
		case '-':
			defmode = *prev;
			*prev = 0;
			break;
		}
	}

	/* create alias */
	if ((def && q && (def < q)) || (def && !q)) {
		*def++ = 0;
		size_t len = strlen (def);
		if (defmode) {
			ut64 at = r_num_math (core->num, def);
			switch (defmode) {
			case ':':
				r_flag_set (core->flags, buf, at, 1);
				return 1;
			case '+':
				at = r_num_get (core->num, buf + 1) + at;
				r_flag_set (core->flags, buf, at, 1);
				return 1;
			case '-':
				at = r_num_get (core->num, buf + 1) - at;
				r_flag_set (core->flags, buf, at, 1);
				return 1;
			}
		}
		/* Remove quotes */
		if (len > 0 && (def[0] == '\'') && (def[len - 1] == '\'')) {
			def[len - 1] = 0x00;
			def++;
		}
		r_str_arg_unescape (def);
		if (!q || (q && q > def)) {
			if (*def) {
				if (!strcmp (def, "-")) {
					RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, buf);
					char *n;
					if (v) {
						char *v_str = r_cmd_alias_val_strdup (v);
						n = r_cons_editor (NULL, v_str);
						free (v_str);
					} else {
						n = r_cons_editor (NULL, NULL);
					}

					if (n) {
						int l = r_str_unescape (n);
						r_cmd_alias_set_raw (core->rcmd, buf, (ut8 *)n, l);
						free (n);
					}
				} else if (*def == '$') {
					char *s = strdup (def+1);
					int l = r_str_unescape (s);
					r_cmd_alias_set_raw (core->rcmd, buf, (ut8 *)s, l);
					free (s);
				} else if (!strncmp (def, "base64:", 7)) {
					int b64_len = strlen (def + 7);
					if (b64_len > 0 && b64_len % 4 == 0) {
						/* b64 decode result is always shorter
						 * than strlen() of input */
						ut8* decoded = malloc (b64_len);
						if (decoded) {
							int decoded_sz = r_base64_decode (decoded, def+7, b64_len);
							if (decoded_sz > 0) {
								r_cmd_alias_set_raw (core->rcmd, buf, decoded, decoded_sz);
							} else {
								eprintf ("Invalid base64.\n");
							}
							free (decoded);
						}
					} else {
						eprintf ("Invalid base64.\n");
					}
				} else {
					r_cmd_alias_set_cmd (core->rcmd, buf, def);
				}
			} else {
				r_cmd_alias_del (core->rcmd, buf);
			}
		}
	/* Show command for alias */
	} else if (desc && !q) {
		*desc = 0;
		RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, buf);
		if (v && !v->is_data) {
			/* Commands are always strings */
			r_cons_println ((char *)v->data);
			r_cons_flush ();

			free (buf);
			return 1;
		} else if (v) {
			eprintf ("Alias \"$%s\" is not a command\n", buf);
		} else {
			eprintf ("No such alias \"$%s\"\n", buf);
		}
	} else if (*buf == '*') {
		bool use_b64 = (buf[1] == '*');
		ht_pp_foreach (core->rcmd->aliases, print_aliases, &use_b64);
	} else if (!*buf) {
		RList *keys = r_cmd_alias_keys (core->rcmd);
		if (keys) {
			RListIter *it;
			r_list_foreach_iter (keys, it) {
				r_cons_printf ("$%s\n", (char *)it->data);
			}
			r_list_free (keys);
		}
	} else {
		/* Execute or evaluate alias */
		if (q) {
			*q = 0;
		}
		RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, buf);
		if (v) {
			if (v->is_data) {
				char *v_str = r_cmd_alias_val_strdup (v);
				r_cons_strcat (v_str);
				r_cons_newline ();
				free (v_str);
			} else if (q) {
				char *out = r_str_newf ("%s %s", (char *)v->data, q + 1);
				r_core_cmd0 (core, out);
				free (out);
			} else {
				r_core_cmd0 (core, (char *)v->data);
			}
		} else {
			eprintf ("No such alias \"$%s\"\n", buf);
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

static void cmd_remote(RCore *core, const char *input, bool retry) {
	if (!*input) {
		return;
	}
	if (*input == '?') {
		r_cons_printf ("Usage: =r localhost:9999\n");
		return;
	}
	char *host = strdup (input);
	char *port = strchr (host, ':');
	if (port) {
		*port++ = 0;
	}
	RSocket *s = r_socket_new (false);
repeat:
	if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 1500)) {
		const size_t buf_size = 1024;
		char *buf = calloc (buf_size, 1);
		if (!buf) {
			return;
		}
		void *bed = r_cons_sleep_begin ();
		r_cons_break_push (NULL, NULL);
		for (;;) {
			if (r_cons_is_breaked ()) {
				break;
			}
			r_socket_printf (s, "[0x%08"PFMT64x"]> ", core->offset);
			r_socket_flush (s);
			memset (buf, 0, buf_size);
			r_socket_block_time (s, true, 99999, 0);
			if (r_socket_read (s, (ut8*)buf, buf_size - 1) < 1) {
				break;
			}
			if (*buf == 'q') {
				break;
			}
			const bool orig = r_config_get_b (core->config, "scr.interactive");
			r_config_set_b (core->config, "scr.interactive", false);
			char *res = r_core_cmd_str (core, buf);
			r_config_set_b (core->config, "scr.interactive", orig);
			r_socket_printf (s, "%s\n", res);
			r_socket_flush (s);
			free (res);
		}
		r_cons_break_pop ();
		r_cons_sleep_end (bed);
		free (buf);
	} else {
		if (retry) {
			r_sys_sleep (1);
			goto repeat;
		}
	}
	r_socket_close (s);
	r_socket_free (s);
	free (host);
}

static void cmd_tcp_server(RCore *core, const char *input) {
	char *ptr;
	if ((ptr = strchr (input, ' '))) {
		/* .:port cmd */
		/* .:host:port cmd */
		const char *host, *port;
		char *cmd = ptr + 1;
		*ptr = 0;
		char *eol = strchr (input, ':');
		if (eol) {
			*eol = 0;
			host = input;
			port = eol + 1;
		} else {
			host = "localhost";
			port = input + ((input[0] == ':')? 1: 0);
		}
		char *rbuf = r_core_rtr_cmds_query (core, host, port, cmd);
		if (rbuf) {
			r_cons_print (rbuf);
			free (rbuf);
		}
	} else {
		r_core_rtr_cmds (core, input);
	}
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0': // "="
		r_core_rtr_list (core);
		break;
	case 't': // "=t" // tcp
		cmd_tcp_server (core, r_str_trim_head_ro (input + 1));
		break;
	case 'r': // "=r"
		cmd_remote (core, r_str_trim_head_ro (input + 1), false);
		break;
	case 'R': // "=R"
		cmd_remote (core, r_str_trim_head_ro (input + 1), true);
		break;
	case 'j': // "=j"
		eprintf ("TODO: list connections in json\n");
		break;
	case '!': // "=!"
		if (input[1] == 'q') {
			R_FREE (core->cmdremote);
		} else if (input[1] == '=') { // =!=0 or =!= for iosystem
			R_FREE (core->cmdremote);
			core->cmdremote = r_str_trim_dup (input + 2);
		} else {
			char *res = r_io_system (core->io, input + 1);
			if (res) {
				r_cons_printf ("%s\n", res);
				free (res);
			}
		}
		break;
	case '+': // "=+"
		if (input[1] && input[1] != '?') {
			r_core_rtr_add (core, input + 1);
		} else {
			r_core_cmd_help (core, help_msg_equal_more);
		}
		break;
	case '-': // "=-"
		r_core_rtr_remove (core, input + 1);
		break;
	//case ':': r_core_rtr_cmds (core, input + 1); break;
	case '<': // "=<"
		r_core_rtr_pushout (core, input + 1);
		break;
	case '=': // "=="
		if (input[1] == '=') { // ===
			r_core_rtr_event (core, input + 2);
		} else if (input[1] != '?') {
			r_core_rtr_session (core, input + 1);
		} else {
			r_core_cmd_help (core, help_msg_equal_equal);
		}
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
			r_core_rtr_http (core, getArg (input[1], 'h'), 'h', input + 1);
		}
		break;
	case 'H': // "=H"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_equalh);
		} else {
			const char *arg = r_str_trim_head_ro (input + 1);
			r_core_rtr_http (core, getArg (input[1], 'H'), 'H', arg);
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
		r_core_return_code (core, ret);
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
		r_core_return_code (core, r_buf_size (core->yank_buf));
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
	case 'w': // "yw" ... we have yf which makes more sense than 'w'
		switch (input[1]) {
		case ' ':
			r_core_yank_set (core, 0, (const ut8*)input + 2, strlen (input + 2));
			break;
		case 'x':
			if (input[2] == ' ') {
				char *out = strdup (input + 3);
				int len = r_hex_str2bin (input + 3, (ut8*)out);
				if (len > 0) {
					r_core_yank_set (core, core->offset, (const ut8*)out, len);
				} else {
					eprintf ("Invalid length\n");
				}
				free (out);
			} else {
				eprintf ("Usage: ywx [hexpairs]\n");
			}
			// r_core_yank_write_hex (core, input + 2);
			break;
		default:
			eprintf ("Usage: ywx [hexpairs]\n");
			break;
		}
		break;
	case 'p': // "yp"
		r_core_yank_cat (core, r_num_math (core->num, input + 1));
		break;
	case 's': // "ys"
		r_core_yank_cat_string (core, r_num_math (core->num, input + 1));
		break;
	case 't': // "yt"
		if (input[1] == 'f') { // "ytf"
			ut64 tmpsz;
			const char *file = r_str_trim_head_ro (input + 2);
			const ut8 *tmp = r_buf_data (core->yank_buf, &tmpsz);

			if (!tmpsz) {
				eprintf ("No buffer yanked already\n");
				break;
			}

			if (*file == '$') {
				r_cmd_alias_set_raw (core->rcmd, file+1, tmp, tmpsz);
			} else if (*file == '?' || !*file) {
				r_core_cmd_help_match (core, help_msg_y, "ytf", true);
			} else {
				if (!r_file_dump (file, tmp, tmpsz, false)) {
					eprintf ("Cannot dump to '%s'\n", file);
				}
			}
		} else if (input[1] == ' ') {
			r_core_yank_to (core, input + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_y, "yt", false);
		}
		break;
	case 'f': // "yf"
		switch (input[1]) {
		case ' ': // "yf"
			r_core_yank_file_ex (core, input + 1);
			break;
		case 'x': // "yfx"
			r_core_yank_hexpair (core, input + 2);
			break;
		case 'a': // "yfa"
			r_core_yank_file_all (core, input + 2);
			break;
		default:
			eprintf ("Usage: yf[xa] [arg]\n");
			eprintf ("yf [file]     - copy blocksize from file into the clipboard\n");
			eprintf ("yfa [path]    - yank the whole file\n");
			eprintf ("yfx [hexpair] - yank from hexpair string\n");
			break;
		}
		break;
	case '!': // "y!"
		{
			char *sig = r_core_cmd_str (core, "y*");
			if (!sig || !*sig) {
				free (sig);
				sig = strdup ("wx 10203040");
			}
			char *data = r_core_editor (core, NULL, sig);
			(void) strtok (data, ";\n");
			r_core_cmdf (core, "y%s", data);
			free (sig);
			free (data);
		}
		break;
	case '*': // "y*"
	case 'j': // "yj"
	case 'q': // "yq"
	case '\0': // "y"
		r_core_yank_dump (core, 0, input[0]);
		break;
	default:
		r_core_cmd_help (core, help_msg_y);
		break;
	}
	return true;
}

static int lang_run_file(RCore *core, RLang *lang, const char *file) {
	r_core_sysenv_begin (core, NULL);
	return r_lang_run_file (core->lang, file);
}

static char *langFromHashbang(RCore *core, const char *file) {
	int fd = r_sandbox_open (file, O_RDONLY, 0);
	if (fd != -1) {
		char firstLine[128] = {0};
		int len = r_sandbox_read (fd, (ut8*)firstLine, sizeof (firstLine) - 1);
		firstLine[len] = 0;
		if (!strncmp (firstLine, "#!/", 3)) {
			// I CAN HAS A HASHBANG
			char *nl = strchr (firstLine, '\n');
			if (nl) {
				*nl = 0;
			}
			nl = strchr (firstLine, ' ');
			if (nl) {
				*nl = 0;
			}
			nl = strdup (firstLine + 2);
			r_sandbox_close (fd);
			return nl;
		}
		r_sandbox_close (fd);
	}
	return NULL;
}

R_API bool r_core_run_script(RCore *core, const char *file) {
	bool ret = false;
	RListIter *iter;
	RLangPlugin *p;
	char *name;

	r_list_foreach (core->scriptstack, iter, name) {
		if (!strcmp (file, name)) {
			eprintf ("Warning: ignored nested source: %s\n", file);
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
	} else if (r_str_endswith (file, ".html")) {
		const bool httpSandbox = r_config_get_i (core->config, "http.sandbox");
		char *httpIndex = strdup (r_config_get (core->config, "http.index"));
		r_config_set_b (core->config, "http.sandbox", false);
		char *absfile = r_file_abspath (file);
		r_config_set (core->config, "http.index", absfile);
		free (absfile);
		r_core_cmdf (core, "=H");
		r_config_set_b (core->config, "http.sandbox", httpSandbox);
		r_config_set (core->config, "http.index", httpIndex);
		free (httpIndex);
		ret = true;
	} else if (r_str_endswith (file, ".c")) {
		r_core_cmd_strf (core, "#!c %s", file);
		ret = true;
	} else if (r_file_is_c (file)) { // ".h" ".cparse"
		const char *dir = r_config_get (core->config, "dir.types");
		char *out = r_parse_c_file (core->anal, file, dir, NULL);
		if (out) {
			r_cons_strcat (out);
			sdb_query_lines (core->anal->sdb_types, out);
			free (out);
		}
		ret = out;
	} else {
		p = r_lang_get_by_extension (core->lang, file);
		if (p) {
			r_lang_use (core->lang, p->name);
			ret = lang_run_file (core, core->lang, file);
		} else {
// XXX this is an ugly hack, we need to use execve here and specify args properly
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
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "exe")) {
#if __WINDOWS__
					char *cmd = r_str_newf ("%s", file);
#else
					char *cmd = cmdstr ("wine");
#endif
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "rexx")) {
					r_lang_use (core->lang, "pipe");
					char *cmd = cmdstr ("rexx");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "zig")) {
					char *cmd = cmdstr ("zig run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "d")) {
					char *cmd = cmdstr ("dmd -run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "lsp")) {
					char *cmd = cmdstr ("newlisp -n");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "go")) {
					char *cmd = cmdstr ("go run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "es6")) {
					char *cmd = cmdstr ("babel-node");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "rb")) {
					char *cmd = cmdstr ("ruby");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "vala")) {
					r_lang_use (core->lang, "vala");
					lang_run_file (core, core->lang, file);
					ret = 1;
				} else if (!strcmp (ext, "sh")) {
					char *shell = r_sys_getenv ("SHELL");
					if (!shell) {
						shell = strdup ("sh");
					}
					if (shell) {
						r_lang_use (core->lang, "pipe");
						char *cmd = r_str_newf ("%s '%s'", shell, file);
						if (cmd) {
							lang_run_file (core, core->lang, cmd);
							free (cmd);
						}
						free (shell);
					}
					ret = 1;
				} else if (!strcmp (ext, "r2s")) {
					r_core_visual_slides (core, file);
					ret = 1;
				} else if (!strcmp (ext, "qjs")) {
					if (r_lang_use (core->lang, "qjs")) {
						r_lang_run_file (core->lang, file);
					} else {
						eprintf ("Error: r2pm -ci rlang-qjs\n");
					}
					ret = 1;
				} else if (!strcmp (ext, "wren")) {
					if (r_lang_use (core->lang, "wren")) {
						r_lang_run_file (core->lang, file);
					} else {
						eprintf ("Error: r2pm -ci rlang-wren\n");
					}
					ret = 1;
				} else if (!strcmp (ext, "pl")) {
					char *cmd = cmdstr ("perl");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				} else if (!strcmp (ext, "py")) {
					char *cmd = cmdstr ("python");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = 1;
				}
			} else {
				char *abspath = r_file_path (file);
				char *lang = langFromHashbang (core, file);
				if (lang) {
					r_lang_use (core->lang, "pipe");
					char *cmd = r_str_newf ("%s '%s'", lang, file);
					lang_run_file (core, core->lang, cmd);
					free (lang);
					free (cmd);
					ret = 1;
				}
				free (abspath);
			}
			if (!ret) {
				ret = r_core_cmd_file (core, file);
			}
		}
	}
	free (r_list_pop (core->scriptstack));
	return ret;
}

static int cmd_lr(RCore *core, const char *input) { // "lr"
	const char *path;
	RListIter *iter;
	const char *arg = R_STR_ISEMPTY (input)? ".": input;
	RList *files = r_file_lsrf (arg);
	if (!files) {
		eprintf ("Failed to read directories\n");
		return 0;
	}
	r_list_sort (files, (RListComparator)strcmp);
	r_list_foreach (files, iter, path) {
		r_cons_println (path);
	}
	r_list_free (files);
	return 0;
}

static int cmd_l(void *data, const char *input) { // "l"
	RCore *core = (RCore *)data;
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg = r_str_trim_head_ro (arg + 1);
	}
	arg = r_str_get (arg);
	switch (*input) {
	case 'l': // "ll"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "ll", true);
			break;
		}
		{
			char *carg = r_str_newf ("-l %s", arg);
			int w = r_cons_get_size (NULL) - 8;
			char *res = r_syscmd_ls (carg, w);
			if (res) {
				r_cons_print (res);
				free (res);
			}
			free (carg);
		}
		break;
	case 'e': // "le"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "le", true);
			break;
		}

		if (*arg) {
			r_core_cmdf (core, "cat %s~..", arg);
		} else {
			r_core_cmd_help_match (core, help_msg_l, "le", true);
		}
		break;
	case 'r': // "lr"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "lr", true);
			break;
		}
		cmd_lr (core, arg);
		break;
	case 's': // "ls"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "ls", true);
			break;
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			int w = r_cons_get_size (NULL) - 8;
			char *res;

			if (*arg) {
				//arg++;
			}

			res = r_syscmd_ls (arg, w);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	case '?': // "l?"
	default:
		r_core_cmd_help (core, help_msg_l);
		break;
	}
	return 0;
}

static int cmd_join(void *data, const char *input) { // "join"
	RCore *core = (RCore *)data;
	char *tmp = strdup (input);
	const char *arg1 = strchr (tmp, ' ');
	if (!arg1) {
		goto beach;
	}
	arg1 = r_str_trim_head_ro (arg1);
	if (!arg1) {
		goto beach;
	}
	char *end = strchr (arg1, ' ');
	if (!end) {
		goto beach;
	}
	*end = '\0';
	const char *arg2 = end+1;
	if (!arg2) {
		goto beach;
	}
	arg2 = r_str_trim_head_ro (arg2);
	switch (*input) {
	case '?': // "join?"
		goto beach;
	default: // "join"
		if (!arg1) {
			arg1 = "";
		}
		if (!arg2) {
			arg2 = "";
		}
		if (!r_fs_check (core->fs, arg1) && !r_fs_check (core->fs, arg2)) {
			char *res = r_syscmd_join (arg1, arg2);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	}
	free (tmp);
	return 0;
beach:
	eprintf ("Usage: join [file1] [file2] # join the contents of the two files\n");
	free (tmp);
	return 0;
}

static int cmd_plus(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0]) {
		r_core_cmdf (core, "s+%s", r_str_trim_head_ro (input));
		return 0;
	}
	r_core_cmd_help (core, help_msg_plus);
	return false;
}

static int cmd_stdin(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == '?') {
		r_core_cmd_help (core, help_msg_dash);
		return false;
	} else if (input[0]) {
		r_core_cmdf (core, "s-%s", r_str_trim_head_ro (input));
		return 0;
	}
	return r_core_run_script (core, "-");
}

static void load_table_json(RCore *core, RTable *t, char *data) {
	// parse json file and iterate over all the entries
	// RTableRow *row = r_table_row_new (items);
	// r_list_append (t->rows, row);
	eprintf ("TODO: Loading tables from JSON is not yet implemented\n");
}

static const char *get_type_string(const char *s) {
	if (!strncmp (s, "0x", 2)) {
		return "x";
	}
	if (*s == '0' || atoi (s)) {
		return "d";
	}
	return "s";
}

static void load_table_csv(RCore *core, RTable *t, RList *lines) {
	RListIter *iter;
	char *line;
	int row = 0;

	RList *cols = NULL;
	r_list_foreach (lines, iter, line) {
		char *word;
		RListIter *iter2;
		RList *words = r_str_split_list (line, ",", 0);
		if (r_list_length (words) > 0) {
			switch (row) {
			case 0:
				cols = words;
				words = NULL;
				break;
			case 1:
				{
				RStrBuf *b = r_strbuf_new (",h ");
				RStrBuf *args = r_strbuf_new ("");
				r_list_foreach (words, iter2, word) {
					const char *type = get_type_string (word);
					r_strbuf_append (b, type);
				}
				r_list_foreach (cols, iter2, word) {
					r_strbuf_append (b , " ");
					r_strbuf_append (b, word);
				}
				r_core_cmd0 (core, r_strbuf_get (b));
				r_strbuf_free (args);
				r_strbuf_free (b);
				}
				/* fallthrough */
			default:
				{
				RStrBuf *b = r_strbuf_new (",r ");
				r_list_foreach (words, iter2, word) {
					r_strbuf_append (b, " ");
					r_strbuf_append (b, word);
				}
				r_core_cmd0 (core, r_strbuf_get (b));
				r_strbuf_free (b);
				}
				break;
			}
		}
		r_list_free (words);
		row++;
	}
}

static void load_table_asciiart(RCore *core, RTable *t, RList *lines) {
	RListIter *iter;
	char *line;
	const char *separator = "|";
	int ncols = 0;
	bool expect_header = false;
	bool expect_rows = false;
	r_list_foreach (lines, iter, line) {
		if (!expect_rows) {
			if (r_str_startswith (line, ".--")) {
				expect_header = true;
				separator = "|";
				continue;
			}
			if (r_str_startswith (line, "┌")) {
				expect_header = true;
				separator = "│";
				continue;
			}
			if (r_str_startswith (line, ")-")) {
				expect_rows = true;
				separator = "|";
				continue;
			}
			if (r_str_startswith (line, "│─")) {
				expect_rows = true;
				separator = "│";
				continue;
			}
		}

		RTableColumnType *typeString = r_table_type ("string");
		RTableColumnType *typeNumber = r_table_type ("number");
		if (expect_header) {
			char *arg;
			RList *args = r_str_split_list (line + strlen (separator), separator, 0);
			RListIter *iter2;
			ncols = 0;
			if (r_list_length (t->cols) > 0) {
				eprintf ("Warning: Not re-adding headers. Use ,- to reset the table.\n");
				continue;
			}
			r_list_foreach (args, iter2, arg) {
				char *s = strchr (arg, ' ');
				char *ss = r_str_trim_dup (s? s + 1: arg);
				if (!*ss) {
					free (ss);
					continue;
				}
				r_table_add_column (t, typeString, ss, 0);
				ncols ++;
			}
			expect_header = false;
		} else if (expect_rows) {
			char *arg;
			size_t line_len = strlen (line);
			size_t separator_len = strlen (separator);
			size_t pos = (line_len < separator_len)? line_len: separator_len;
			RList *args = r_str_split_list (line + pos, separator, 0);
			RList *items = r_list_newf (free);
			RListIter *iter2;
			if (r_list_length (args) < ncols) {
				// dowarn?
				continue;
			}
			r_list_foreach (args, iter2, arg) {
				char *ss = r_str_trim_dup (arg);
				if (!*ss) {
					free (ss);
					continue;
				}
				if (isdigit ((unsigned char)*ss)) {
					int col = r_list_length (items);
					RTableColumn *c = r_list_get_n (t->cols, col);
					if (c) {
						c->type = typeNumber;
					}
				}
				r_list_append (items, ss);
			}
			RTableRow *row = r_table_row_new (items);
			r_list_append (t->rows, row);
		}
	}
}

static void load_table(RCore *core, RTable *t, char *data) {
	r_return_if_fail (core && t && data);
	if (*data == '[') {
		load_table_json (core, t, data);
	} else {
		RList *lines = r_str_split_list (data, "\n", 0);
		if (strchr (data, ',')) {
			load_table_csv (core, t, lines);
		} else {
			load_table_asciiart (core, t, lines);
		}
		r_list_free (lines);
	}
	free (data);
}

static void display_table(char *ts) {
	if (ts) {
		r_cons_printf ("%s\n", ts);
		free (ts);
	}
}

static void cmd_table_header(RCore *core, char *s) {
	RList *list = r_str_split_list (s, " ", 0); // owns *s
	RListIter *iter;
	char *format = r_list_pop_head (list);
	if (!format) {
		return;
	}
	if (!core->table) {
		core->table = r_core_table (core, "header");
	}
	size_t i = 0;
	r_list_foreach (list, iter, s) {
		const char type_char = format[i];
		if (!type_char) {
			break;
		}
		const char *type_name = (type_char == 's')
			? "string": "number";
		RTableColumnType *typeString = r_table_type (type_name);
		r_table_add_column (core->table, typeString, s, 0);
		i++;
	}
	r_list_free (list);
	free (format);
}

static bool display_table_filter(RCore *core, const char *input) {
	r_return_val_if_fail (core && input, false);
	if (!core->table) {
		return false;
	}
	int skip = (*input == ' ')? 1: (*input&&input[1])? 2: 0;
	if (skip) {
		const char *q = r_str_trim_head_ro (input + skip);
		return r_table_query (core->table, q);
	}
	return true;
}

static int cmd_table(void *data, const char *input) {
	RCore *core = (RCore*)data;
	if (!core->table) {
		core->table = r_table_new ("table");
	}
	switch (*input) {
	case 'h': // table header columns
	case 'c': // table columns
		cmd_table_header (core, r_str_trim_dup (input + 1));
		break;
	case 'r': // add row
		{
			if (!core->table) {
				core->table = r_table_new ("table");
			}
			char *args = r_str_trim_dup (input + 1);
			if (*args) {
				RList *list = r_str_split_list (args, " ", 0);
				if (list) {
					r_table_add_row_list (core->table, list);
				}
			}
		}
		break;
	case '-':
		r_table_free (core->table);
		core->table = r_table_new ("table");
		break;
	case '/':
		// query here
		{
			RTable *ot = r_table_clone (core->table);
			if (display_table_filter (core, input)) {
				display_table (r_table_tostring (core->table));
			}
			r_table_free (core->table);
			core->table = ot;
		}
		break;
	case '.': // ",."
		if (R_STR_ISEMPTY (input + 1)) {
			eprintf ("Usage: ,. [file | $alias]\n");
		} else {
			const char *file = r_str_trim_head_ro (input + 1);
			if (*file == '$' && !file[1]) {
				eprintf ("No alias name given.\n");
			} else if (*file == '$') {
				RCmdAliasVal *file_data = r_cmd_alias_get (core->rcmd, file+1);
				if (file_data) {
					char *file_data_str = r_cmd_alias_val_strdup (file_data);
					load_table (core, core->table, strdup (file_data_str));
					free (file_data_str);
				} else {
					eprintf ("No such alias \"$%s\"\n", file+1);
				}
			} else {
				char *file_data = r_file_slurp (file, NULL);
				if (file_data) {
					load_table (core, core->table, file_data);
				} else {
					eprintf ("Cannot open file.\n");
				}
			}
		}
		break;
	case ' ':
		if (display_table_filter (core, input)) {
			display_table (r_table_tostring (core->table));
		}
		break;
	case ',':
		if (display_table_filter (core, input)) {
			display_table (r_table_tocsv (core->table));
		}
		break;
	case '*':
		if (display_table_filter (core, input)) {
			display_table (r_table_tor2cmds (core->table));
		}
		break;
	case 'j':
		if (display_table_filter (core, input)) {
			display_table (r_table_tojson (core->table));
		}
		break;
	case 0:
		if (core->table) {
			display_table (r_table_tofancystring (core->table));
		}
		break;
	case '?':
		r_core_cmd_help (core, cmd_table_help);
		r_cons_printf ("%s\n", r_table_help ());
		break;
	default:
		r_core_cmd_help (core, cmd_table_help);
		break;
	}
	return 0;
}

static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol, *filter, *inp;
	RCore *core = (RCore *)data;

	if (!strcmp (input, "?")) {
		r_core_cmd_help (core, help_msg_dot);
		return 0;
	}
	switch (*input) {
	case '\0': // "."
		lastcmd_repeat (core, 0);
		break;
#if 0
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
#endif
	case '.': // ".." same as \n
		if (input[1] == '.') { // "..." run the last command repeated
			// same as \n with e cmd.repeat=true
			lastcmd_repeat (core, 1);
		} else if (input[1] == ' ') {
			char *str = r_core_cmd_str_pipe (core, r_str_trim_head_ro (input));
			if (str) {
				r_core_cmd (core, str, 0);
				free (str);
			}
		} else if (input[1] && input[1] != '?') {
			r_core_cmdf (core, "s%s", input);
		} else {
			r_core_cmd_help (core, help_msg_dot);
		}
		break;
	case '*': // ".*"
		{
			const char *a = r_str_trim_head_ro (input + 1);
			char *s = strdup (a);
			char *sp = strchr (s, ' ');
			if (sp) {
				*sp = 0;
			}
			if (R_STR_ISNOTEMPTY (s)) {
				r_core_run_script (core, s);
			}
			free (s);
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
		{
			const char *script_file = r_str_trim_head_ro (input + 1);
			if (*script_file == '$' && !script_file[1]) {
				eprintf ("No alias name given.\n");
			} else if (*script_file == '$') {
				RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, script_file+1);
				if (v) {
					char *cmd_text = r_cmd_alias_val_strdup (v);
					r_core_cmd0 (core, cmd_text);
					free (cmd_text);
				} else {
					eprintf ("No such alias \"$%s\"\n", script_file+1);
				}
			} else {
				if (!r_core_run_script (core, script_file)) {
					eprintf ("Cannot find script '%s'\n", script_file);
					r_core_return_code (core, R_CMD_RC_FAILURE);
				} else {
					r_core_return_code (core, R_CMD_RC_SUCCESS);
				}
			}
		}
		break;
	case '!': // ".!"
		/* from command */
		r_core_cmd_command (core, input + 1);
		break;
	case '(': // ".("
		r_cmd_macro_call (&core->rcmd->macro, input + 1);
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
		int tmp_html = r_cons_context ()->is_html;
		r_cons_context ()->is_html = false;
		ptr = str = r_core_cmd_str (core, inp);
		r_cons_context ()->is_html = tmp_html;

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

static bool callback_foreach_kv(void *user, const char *k, const char *v) {
	r_cons_printf ("%s=%s\n", k, v);
	return true;
}

R_API int r_line_hist_sdb_up(RLine *line) {
	if (!line->sdbshell_hist_iter || !line->sdbshell_hist_iter->n) {
		return false;
	}
	line->sdbshell_hist_iter = line->sdbshell_hist_iter->n;
	strncpy (line->buffer.data, line->sdbshell_hist_iter->data, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	return true;
}

R_API int r_line_hist_sdb_down(RLine *line) {
	if (!line->sdbshell_hist_iter || !line->sdbshell_hist_iter->p) {
		return false;
	}
	line->sdbshell_hist_iter = line->sdbshell_hist_iter->p;
	strncpy (line->buffer.data, line->sdbshell_hist_iter->data, R_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen (line->buffer.data);
	return true;
}

static int cmd_kuery(void *data, const char *input) {
	char *out;
	RCore *core = (RCore*)data;
	const char *sp, *p = "[sdb]> ";
	Sdb *s = core->sdb;

	char *cur_pos = NULL, *cur_cmd = NULL, *next_cmd = NULL;
	char *temp_pos = NULL, *temp_cmd = NULL;

	switch (input[0]) {
	case 'j':
		out = sdb_querys (s, NULL, 0, "anal/**");
		if (!out) {
			r_cons_println ("No Output from sdb");
			break;
		}
		PJ * pj = pj_new ();
		if (!pj) {
  			free (out);
  			break;
		}
		pj_o (pj);
		pj_ko (pj, "anal");
		pj_ka (pj, "cur_cmd");

		while (*out) {
			cur_pos = strchr (out, '\n');
			if (!cur_pos) {
					break;
			}
			cur_cmd = r_str_ndup (out, cur_pos - out);
			pj_s (pj, cur_cmd);

			free (next_cmd);
			next_cmd = r_str_newf ("anal/%s/*", cur_cmd);
			char *query_result = sdb_querys (s, NULL, 0, next_cmd);

			if (!query_result) {
				out = cur_pos + 1;
				continue;
			}

			char *temp = query_result;
			while (*temp) {
				temp_pos = strchr (temp, '\n');
				if (!temp_pos) {
					break;
				}
				temp_cmd = r_str_ndup (temp, temp_pos - temp);
				pj_s (pj, temp_cmd);
				temp = temp_pos + 1;
			}
			out = cur_pos + 1;
			free (query_result);
		}
		pj_end (pj);
		pj_end (pj);
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		R_FREE (next_cmd);
		free (next_cmd);
		free (cur_cmd);
		break;
	case ' ':
		if (s) {
			out = sdb_querys (s, NULL, 0, input + 1);
			if (out) {
				r_cons_print (out);
			}
			R_FREE (out);
		}
		break;
	//case 's': r_pair_save (s, input + 3); break;
	//case 'l': r_pair_load (sdb, input + 3); break;
	case '\0':
		sdb_foreach (s, callback_foreach_kv, NULL);
		break;
	// TODO: add command to list all namespaces // sdb_ns_foreach ?
	case 's': // "ks"
		if (core->http_up) {
			return false;
		}
		if (!r_cons_is_interactive ()) {
			return false;
		}
		if (input[1] == ' ') {
			char *n, *o, *p = strdup (input + 2);
			// TODO: slash split here? or inside sdb_ns ?
			for (n = o = p; n; o = n) {
				n = strchr (o, '/'); // SDB_NS_SEPARATOR NAMESPACE
				if (n) {
					*n++ = 0;
				}
				s = sdb_ns (s, o, 1);
			}
			free (p);
		}
		if (!s) {
			s = core->sdb;
		}
		RLine *line = core->cons->line;
		if (!line->sdbshell_hist) {
			line->sdbshell_hist = r_list_newf (free);
			r_list_append (line->sdbshell_hist, r_str_new ("\0"));
		}
		RList *sdb_hist = line->sdbshell_hist;
		r_line_set_hist_callback (line, &r_line_hist_sdb_up, &r_line_hist_sdb_down);
		const size_t buf_size = 1024;
		char *buf = malloc (1024);
		while (buf) {
			r_line_set_prompt (p);
			*buf = 0;
			if (r_cons_fgets (buf, buf_size, 0, NULL) < 1) {
				break;
			}
			if (!*buf) {
				break;
			}
			if (sdb_hist) {
				if ((r_list_length (sdb_hist) == 1) || (r_list_length (sdb_hist) > 1 && strcmp (r_list_get_n (sdb_hist, 1), buf))) {
					r_list_insert (sdb_hist, 1, strdup (buf));
				}
				line->sdbshell_hist_iter = sdb_hist->head;
			}
			out = sdb_querys (s, NULL, 0, buf);
			if (out) {
				r_cons_println (out);
				r_cons_flush ();
			}
		}
		free (buf);
		r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
		break;
	case 'o': // "ko"
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
					} else {
						eprintf ("Cannot find sdb '%s'\n", ns);
					}
				} else {
					eprintf ("Cannot open file\n");
				}
			} else {
				eprintf ("Missing sdb namespace\n");
			}
			free (fn);
		} else {
			eprintf ("Usage: ko [file] [namespace]\n");
		}
		break;
	case 'd': // "kd"
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
				} else {
					eprintf ("Cannot find sdb '%s'\n", ns);
				}
			} else {
				eprintf ("Missing sdb namespace\n");
			}
			free (fn);
		} else {
			eprintf ("Usage: kd [file] [namespace]\n");
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_k);
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
		if (n > 1) {
			core->blocksize_max = n;
		} else {
			r_cons_printf ("0x%x\n", (ut32)core->blocksize_max);
		}
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
	case 'j': { // "bj"
		PJ * pj = pj_new ();
		if (!pj) {
			break;
		}
		pj_o (pj);
		pj_ki (pj, "blocksize", core->blocksize);
		pj_ki (pj, "blocksize_limit", core->blocksize_max);
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		break;
	}
	case '*': // "b*"
		r_cons_printf ("b 0x%x\n", core->blocksize);
		break;
	case '\0': // "b"
		r_cons_printf ("0x%x\n", core->blocksize);
		break;
	case ' ':
		r_core_block_size (core, r_num_math (core->num, input));
		break;
	default:
	case '?': // "b?"
		r_core_cmd_help (core, help_msg_b);
		break;
	}
	return 0;
}

static int __runMain(RMainCallback cb, const char *arg) {
	char *a = r_str_trim_dup (arg);
	int argc = 0;
	char **args = r_str_argv (a, &argc);
	int res = cb (argc, (const char **)args);
	free (args);
	free (a);
	return res;
}

static bool cmd_r2cmd(RCore *core, const char *_input) {
	char *input = r_str_newf ("r%s", _input);
	int rc = 0;
	if (r_str_startswith (input, "rax2")) {
		rc = __runMain (core->r_main_rax2, input);
	} else if (r_str_startswith (input, "r2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (core->r_main_radare2, input);
	} else if (r_str_startswith (input, "radare2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (core->r_main_radare2, input);
	} else if (r_str_startswith (input, "rasm2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (core->r_main_rasm2, input);
	} else if (r_str_startswith (input, "rabin2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (core->r_main_rabin2, input);
	} else if (r_str_startswith (input, "ragg2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (core->r_main_ragg2, input);
	} else if (r_str_startswith (input, "r2pm")) {
		rc = __runMain (core->r_main_r2pm, input);
	} else if (r_str_startswith (input, "radiff2")) {
		rc = __runMain (core->r_main_radiff2, input);
	} else {
		const char *r2cmds[] = {
			"rax2", "r2pm", "rasm2", "rabin2", "rahash2", "rafind2", "rarun2", "ragg2", "radare2", "r2", NULL
		};
		int i;
		for (i = 0; r2cmds[i]; i++) {
			if (r_str_startswith (input, r2cmds[i])) {
				free (input);
				return true;
			}
		}
		free (input);
		return false;
	}
	free (input);
	r_core_return_code (core, rc);
	return true;
}

static int cmd_rebase(RCore *core, const char *input) {
	ut64 addr = r_num_math (core->num, input);
	if (!addr) {
		r_cons_printf ("Usage: rb oldbase @ newbase\n");
		return 0;
	}
	// old base = addr
	// new base = core->offset
	r_debug_bp_rebase (core->dbg, addr, core->offset);
	r_bin_set_baddr (core->bin, core->offset);
	r_flag_move (core->flags, addr, core->offset);
	r_core_cmd0 (core, ".is*");
	r_core_cmd0 (core, ".iM*");
	r_core_cmd0 (core, ".ii*");
	r_core_cmd0 (core, ".iz*");
	// TODO: r_anal_move :??
	// TODO: differentiate analysis by map ranges (associated with files or memory maps)
	return 0;
}

static int cmd_resize(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 newsize = 0;
	st64 delta = 0;
	int grow, ret;

	if (cmd_r2cmd (core, input)) {
		return true;
	}

	ut64 oldsize = (core->io->desc) ? r_io_fd_size (core->io, core->io->desc->fd): 0;
	switch (*input) {
	case 'b': // "rb" rebase
		return cmd_rebase (core, input + 1);
	case '2': // "r2" // XXX should be handled already in cmd_r2cmd()
		// TODO: use argv[0] instead of 'radare2'
		// TODO: { char **argv = { "r2", NULL }; r_main_radare2 (1, argv); }
		r_sys_cmdf ("radare%s", input);
		return true;
	case 'm': // "rm"
		if (!r_str_cmp (input, "mrf", 3)) {
			if (input[3] == ' ')  {
				const char *file = r_str_trim_head_ro (input + 3);
				return r_file_rm_rf (file);
			}
			eprintf ("Usage rr <directory>\n");
			return false;
		}
		if (input[1] == ' ') {
			const char *file = r_str_trim_head_ro (input + 2);
			if (*file == '$') {
				r_cmd_alias_del (core->rcmd, file);
			} else {
				r_file_rm (file);
			}
		} else {
			eprintf ("Usage: rm [file]   # removes a file\n");
		}
		return true;
	case '\0':
		if (core->io->desc) {
			if (oldsize != -1) {
				r_cons_printf ("%"PFMT64d"\n", oldsize);
			}
		}
		return true;
	case 'j': { // "rj"
			PJ * pj = pj_new ();
			pj_o (pj);
			if (oldsize != -1) {
				pj_kn (pj, "size", oldsize);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_println (s);
			free (s);
			return true;
		}
	case 'h':
		if (core->io->desc) {
			if (oldsize != -1) {
				char humansz[8];
				r_num_units (humansz, sizeof (humansz), oldsize);
				r_cons_printf ("%s\n", humansz);
			}
		}
		return true;
	case '+': // "r+"
	case '-': // "r-"
		delta = (st64)r_num_math (core->num, input);
		newsize = oldsize + delta;
		break;
	case '0':
		if (input[1] == 'x') {
			newsize = r_num_math (core->num, input);
		} else {
			r_core_cmd_help (core, help_msg_r);
		}
		break;
	case ' ': // "r " "r +" "r -"
		{
			const char *arg = r_str_trim_head_ro (input + 1);
			if (*arg == '-' || *arg == '+') {
				delta = (st64)r_num_math (core->num, input);
				newsize = oldsize + delta;
			} else {
				newsize = r_num_math (core->num, arg);
				if (newsize == 0) {
					if (arg[1] == '0') {
						eprintf ("Invalid size\n");
					}
					return false;
				}
			}
		}
		break;
	case 'e':
		{
			int rc = write (1, Color_RESET_TERMINAL, strlen (Color_RESET_TERMINAL));
			if (rc == -1) {
				return false;
			}
		}
		return true;
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
	if (delta && core->offset < newsize) {
		r_io_shift (core->io, core->offset, grow?newsize:oldsize, delta);
	}
	if (!grow) {
		ret = r_io_resize (core->io, newsize);
		if (ret < 1) {
			eprintf ("r_io_resize: cannot resize\n");
		}
	}
	if (newsize < (core->offset + core->blocksize) || oldsize < (core->offset + core->blocksize)) {
		r_core_block_read (core);
	}
	return true;
}

static int cmd_panels(void *data, const char *input) {
	RCore *core = (RCore*) data;
	if (core->vmode) {
		return false;
	}
	if (*input == '.') {
		const char *f = r_str_trim_head_ro (input + 1);
		if (*f) {
			r_core_visual_slides (core, f);
		}
		return false;
	}
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_v);
		return false;
	}
	if (!r_cons_is_interactive ()) {
		eprintf ("Panel mode requires scr.interactive=true.\n");
		return false;
	}
	if (*input == ' ') {
		if (core->panels) {
			r_core_panels_load (core, input + 1);
		}
		r_config_set (core->config, "scr.layout", input + 1);
		return true;
	}
	if (*input == '=') {
		r_core_panels_save (core, input + 1);
		r_config_set (core->config, "scr.layout", input + 1);
		return true;
	}
	if (*input == 'i') {
		char *sp = strchr (input, ' ');
		if (sp) {
			char *r = r_core_editor (core, sp + 1, NULL);
			if (r) {
				free (r);
			} else {
				eprintf ("Cannot open file (%s)\n", sp + 1);
			}
		}
		////r_sys_cmdf ("v%s", input);
		return false;
	}
	r_core_panels_root (core, core->panels_root);
	return true;
}

static int cmd_visual(void *data, const char *input) {
	RCore *core = (RCore*) data;
	if (core->http_up) {
		return false;
	}
	if (!r_cons_is_interactive ()) {
		eprintf ("Visual mode requires scr.interactive=true.\n");
		return false;
	}
	return r_core_visual ((RCore *)data, input);
}

static int cmd_pipein(void *user, const char *input) {
	char *buf = strdup (input);
	int len = r_str_unescape (buf);
	r_cons_readpush (buf, len);
	free (buf);
	return 0;
}

static int cmd_tasks(void *data, const char *input) {
	RCore *core = (RCore*) data;
	switch (input[0]) {
	case '\0': // "&"
	case 'j': // "&j"
		r_core_task_list (core, *input);
		break;
	case ':': // "&:"
		r_core_cmd_queue (core, input + 1);
		break;
	case 'w': // "&w"
		r_core_cmd_queue_wait (core);
		break;
	case 'b': { // "&b"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		int tid = r_num_math (core->num, input + 1);
		if (tid) {
			r_core_task_break (&core->tasks, tid);
		}
		break;
	}
	case '&': { // "&&"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		int tid = r_num_math (core->num, input + 1);
		r_core_task_join (&core->tasks, core->tasks.current_task, tid ? tid : -1);
		break;
	}
	case '=': { // "&="
		// r_core_task_list (core, '=');
		int tid = r_num_math (core->num, input + 1);
		if (tid) {
			RCoreTask *task = r_core_task_get_incref (&core->tasks, tid);
			if (task) {
				if (task->res) {
					r_cons_println (task->res);
				}
				r_core_task_decref (task);
			} else {
				eprintf ("Cannot find task\n");
			}
		}
		break;
	}
	case '-': // "&-"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == '*') {
			r_core_task_del_all_done (&core->tasks);
		} else {
			r_core_task_del (&core->tasks, r_num_math (core->num, input + 1));
		}
		break;
	case '?': // "&?"
	default:
		r_core_cmd_help (core, help_msg_amper);
		break;
	case ' ': // "& "
	case '_': // "&_"
	case 't': { // "&t"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		RCoreTask *task = r_core_task_new (core, true, input + 1, NULL, core);
		if (!task) {
			break;
		}
		task->transient = input[0] == 't';
		r_core_task_enqueue (&core->tasks, task);
		break;
	}
	}
	return 0;
}

static int cmd_pointer(void *data, const char *input) {
	RCore *core = (RCore*) data;
	int ret = true;
	char *str, *eq;
	input = r_str_trim_head_ro (input);
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
		cmd_help_percent (core);
		break;
	default:
		ret = r_core_cmdf (core, "env %s", input);
	}
	return ret;
}

static struct autocomplete_flag_map_t {
	const char* name;
	const char* desc;
	int type;
} autocomplete_flags [] = {
	{ "$dflt", "default autocomplete flag", R_CORE_AUTOCMPLT_DFLT },
	{ "$flag", "shows known flag hints", R_CORE_AUTOCMPLT_FLAG },
	{ "$flsp", "shows known flag-spaces hints", R_CORE_AUTOCMPLT_FLSP },
	{ "$seek", "shows the seek hints", R_CORE_AUTOCMPLT_SEEK },
	{ "$fcn", "shows the functions hints", R_CORE_AUTOCMPLT_FCN },
	{ "$vars", "autocomplete function varnames", R_CORE_AUTOCMPLT_VARS },
	{ "$zign", "shows known zignatures hints", R_CORE_AUTOCMPLT_ZIGN },
	{ "$eval", "shows known evals hints", R_CORE_AUTOCMPLT_EVAL },
	{ "$prjt", "shows known projects hints", R_CORE_AUTOCMPLT_PRJT },
	{ "$mins", NULL, R_CORE_AUTOCMPLT_MINS },
	{ "$brkp", "shows known breakpoints hints", R_CORE_AUTOCMPLT_BRKP },
	{ "$macro", NULL, R_CORE_AUTOCMPLT_MACR },
	{ "$file", "hints file paths", R_CORE_AUTOCMPLT_FILE },
	{ "$thme", "shows known themes hints", R_CORE_AUTOCMPLT_THME },
	{ "$optn", "allows the selection for multiple options", R_CORE_AUTOCMPLT_OPTN },
	{ "$ms", "shows mount hints", R_CORE_AUTOCMPLT_MS},
	{ "$sdb", "shows sdb hints", R_CORE_AUTOCMPLT_SDB},
	{ NULL, NULL, 0 }
};

static inline void print_dict(RCoreAutocomplete* a, int sub) {
	if (!a) {
		return;
	}
	int i, j;
	const char* name = "unknown";
	for (i = 0; i < a->n_subcmds; i++) {
		RCoreAutocomplete* b = a->subcmds[i];
		if (b->locked) {
			continue;
		}
		for (j = 0; j < R_CORE_AUTOCMPLT_END; j++) {
			if (b->type == autocomplete_flags[j].type) {
				name = autocomplete_flags[j].name;
				break;
			}
		}
		eprintf ("[%3d] %s: '%s'\n", sub, name, b->cmd);
		print_dict (a->subcmds[i], sub + 1);
	}
}

static int autocomplete_type(const char* strflag) {
	int i;
	for (i = 0; i < R_CORE_AUTOCMPLT_END; i++) {
		if (autocomplete_flags[i].desc && !strncmp (strflag, autocomplete_flags[i].name, 5)) {
			return autocomplete_flags[i].type;
		}
	}
	eprintf ("Invalid flag '%s'\n", strflag);
	return R_CORE_AUTOCMPLT_END;
}

static void cmd_autocomplete_help(RCore *core) {
	r_core_cmd_help (core, help_msg_triple_exclamation);
	// non-zero-cost survival without iterators 101
	char const **help = calloc (R_CORE_AUTOCMPLT_END + 1, 3 * sizeof (char *));
	int i;
	size_t n;
	for (i = 0, n = 0; i < R_CORE_AUTOCMPLT_END; i++) {
		if (autocomplete_flags[i].desc) {
			// highlight "$" as cmd and the rest of the name as args
			help[n + 0] = "$";
			help[n + 1] = autocomplete_flags[i].name + 1;
			help[n + 2] = autocomplete_flags[i].desc;
			n += 3;
		}
	}
	r_core_cmd_help (core, help);
	free (help);
}

static void cmd_autocomplete(RCore *core, const char *input) {
	RCoreAutocomplete* b = core->autocomplete;
	input = r_str_trim_head_ro (input);
	char arg[256];
	if (!*input) {
		print_dict (core->autocomplete, 0);
		return;
	}
	if (*input == '?') {
		cmd_autocomplete_help (core);
		return;
	}
	if (*input == '-') {
		const char *arg = input + 1;
		if (!*input) {
			eprintf ("Use !!!-* or !!!-<cmd>\n");
			return;
		}
		r_core_autocomplete_remove (b, arg);
		return;
	}
	while (b) {
		const char* end = r_str_trim_head_wp (input);
		if (!end) {
			break;
		}
		if ((end - input) >= sizeof (arg)) {
			// wtf?
			eprintf ("Exceeded the max arg length (255).\n");
			return;
		}
		if (end == input) {
			break;
		}
		memcpy (arg, input, end - input);
		arg[end - input] = 0;
		RCoreAutocomplete* a = r_core_autocomplete_find (b, arg, true);
		input = r_str_trim_head_ro (end);
		if (input && *input && !a) {
			if (b->type == R_CORE_AUTOCMPLT_DFLT && !(b = r_core_autocomplete_add (b, arg, R_CORE_AUTOCMPLT_DFLT, false))) {
				eprintf ("ENOMEM\n");
				return;
			} else if (b->type != R_CORE_AUTOCMPLT_DFLT) {
				eprintf ("Cannot add autocomplete to '%s'. type not $dflt\n", b->cmd);
				return;
			}
		} else if ((!input || !*input) && !a) {
			if (arg[0] == '$') {
				int type = autocomplete_type (arg);
				if (type != R_CORE_AUTOCMPLT_END && !b->locked && !b->n_subcmds) {
					b->type = type;
				} else if (b->locked || b->n_subcmds) {
					if (!b->cmd) {
						return;
					}
					eprintf ("Changing type of '%s' is forbidden.\n", b->cmd);
				}
			} else {
				if (!r_core_autocomplete_add (b, arg, R_CORE_AUTOCMPLT_DFLT, false)) {
					eprintf ("ENOMEM\n");
					return;
				}
			}
			return;
		} else if ((!input || !*input) && a) {
			// eprintf ("Cannot add '%s'. Already exists.\n", arg);
			return;
		} else {
			b = a;
		}
	}
	eprintf ("Invalid usage of !!!\n");
}

static int cmd_last(void *data, const char *input) {
	switch (*input) {
	case 0:
		r_cons_last ();
		break;
	default:
		r_cons_printf ("Usage: _  print last output\n");
	}
	return 0;
}

static int cmd_system(void *data, const char *input) {
	RCore *core = (RCore*)data;
	ut64 n;
	int ret = 0;
	switch (*input) {
	case '-': //!-
		if (input[1]) {
			r_line_hist_free();
			r_line_hist_save (R2_HOME_HISTORY);
		} else {
			r_line_hist_free();
		}
		break;
	case '=': //!=
		if (input[1] == '?') {
			r_cons_printf ("Usage: !=[!]  - enable/disable remote commands\n");
		} else {
			if (!r_sandbox_enable (0)) {
				R_FREE (core->cmdremote);
			}
		}
		break;
	case '!': //!!
		if (input[1] == '!') { // !!! & !!!-
			cmd_autocomplete (core, input + 2);
		} else if (input[1] == '?') {
			cmd_help_exclamation (core);
		} else if (input[1] == '*') {
			char *cmd = r_str_trim_dup (input + 1);
			(void)r_core_cmdf (core, "\"#!pipe %s\"", cmd);
			free (cmd);
		} else {
			if (r_sandbox_enable (0)) {
				eprintf ("This command is disabled in sandbox mode\n");
				return 0;
			}
			if (input[1]) {
				int olen;
				char *out = NULL;
				char *cmd = r_core_sysenv_begin (core, input);
				if (cmd) {
					void *bed = r_cons_sleep_begin ();
					ret = r_sys_cmd_str_full (cmd + 1, NULL, 0, &out, &olen, NULL);
					r_cons_sleep_end (bed);
					r_core_sysenv_end (core, input);
					r_cons_write (out, olen);
					free (out);
					free (cmd);
				} //else eprintf ("Error setting up system environment\n");
			} else {
				eprintf ("History saved to "R2_HOME_HISTORY"\n");
				r_line_hist_save (R2_HOME_HISTORY);
			}
		}
		break;
	case '\0':
		r_line_hist_list ();
		break;
	case '?': //!?
		cmd_help_exclamation (core);
		break;
	case '*':
		// TODO: use the api
		{
		char *cmd = r_str_trim_dup (input + 1);
		cmd = r_str_replace (cmd, " ", "\\ ", true);
		cmd = r_str_replace (cmd, "\\ ", " ", false);
		cmd = r_str_replace (cmd, "\"", "'", false);
		ret = r_core_cmdf (core, "\"#!pipe %s\"", cmd);
		free (cmd);
		}
		break;
	default:
		n = atoi (input);
		if (*input == '0' || n > 0) {
			const char *cmd = r_line_hist_get (n);
			if (cmd) {
				r_core_cmd0 (core, cmd);
			}
			//else eprintf ("Error setting up system environment\n");
		} else {
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				void *bed = r_cons_sleep_begin ();
				ret = r_sys_cmd (cmd);
				if (ret != 0) {
					r_cons_singleton()->context->was_breaked = true;
				}
				r_cons_sleep_end (bed);
				r_core_sysenv_end (core, input);
				free (cmd);
			} else {
				eprintf ("Error setting up system environment\n");
			}
		}
		break;
	}
	return ret;
}

static char *unescape_special_chars(const char *s, const char *special_chars) {
	char *dst = R_NEWS (char, strlen (s) + 1);
	int i, j = 0;

	for (i = 0; s[i]; i++) {
		if (s[i] != '\\' || !strchr (special_chars, s[i + 1])) {
			dst[j++] = s[i];
			continue;
		}

		if (!s[i + 1]) {
			break;
		}

		dst[j++] = s[i + 1];
		i++;
	}
	dst[j++] = '\0';
	return dst;
}

#if __WINDOWS__
#include <tchar.h>
#define __CLOSE_DUPPED_PIPES() \
		close (1);             \
		close (fd_out);        \
		fd_out = -1;

static void r_w32_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	SECURITY_ATTRIBUTES sa;
	HANDLE pipe[2] = {NULL, NULL};
	int fd_out = -1, cons_out = -1;
	char *_shell_cmd = NULL;
	LPTSTR _shell_cmd_ = NULL;
	DWORD mode;
	TCHAR *systemdir = NULL;
	GetConsoleMode (GetStdHandle (STD_OUTPUT_HANDLE), &mode);

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
	while (*_shell_cmd && isspace ((ut8)*_shell_cmd)) {
		_shell_cmd++;
	}
	char *tmp = r_str_newf ("/Q /c \"%s\"", _shell_cmd);
	if (!tmp) {
		goto err_r_w32_cmd_pipe;
	}
	_shell_cmd = tmp;
	_shell_cmd_ = r_sys_conv_utf8_to_win (_shell_cmd);
	free (tmp);
	if (!_shell_cmd_) {
		goto err_r_w32_cmd_pipe;
	}
	systemdir = calloc (MAX_PATH, sizeof (TCHAR));
	if (!systemdir) {
		goto err_r_w32_cmd_pipe;
	}
	int ret = GetSystemDirectory (systemdir, MAX_PATH);
	if (!ret) {
		r_sys_perror ("r_w32_cmd_pipe/systemdir");
		goto err_r_w32_cmd_pipe;
	}
	_tcscat_s (systemdir, MAX_PATH, TEXT("\\cmd.exe"));
	// exec windows process
	if (!CreateProcess (systemdir, _shell_cmd_, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		r_sys_perror ("r_w32_cmd_pipe/CreateProcess");
		goto err_r_w32_cmd_pipe;
	}
	fd_out = _open_osfhandle ((intptr_t)pipe[1], _O_WRONLY|_O_TEXT);
	if (fd_out == -1) {
		r_sys_perror ("_open_osfhandle");
		goto err_r_w32_cmd_pipe;
	}
	cons_out = dup (1);
	dup2 (fd_out, 1);
	// exec radare command
	r_core_cmd (core, radare_cmd, 0);

	HANDLE th = CreateThread (NULL, 0,(LPTHREAD_START_ROUTINE) r_cons_flush, NULL, 0, NULL);
	if (!th) {
		__CLOSE_DUPPED_PIPES ();
		goto err_r_w32_cmd_pipe;
	}
	while (true) {
		int ret = WaitForSingleObject (th, 50);
		if (!ret) {
			// Successfully written everything to pipe
			__CLOSE_DUPPED_PIPES ();
			WaitForSingleObject (pi.hProcess, INFINITE);
			break;
		}
		ret = WaitForSingleObject (pi.hProcess, 50);
		if (!ret) {
			// Process exited before we finished writing to pipe
			DWORD exit;
			if (GetExitCodeThread (th, &exit) && exit == STILL_ACTIVE) {
				r_w32_CancelSynchronousIo (th);
			}
			// Windows XP
			WaitForSingleObject (th, INFINITE);
			__CLOSE_DUPPED_PIPES ();
			break;
		}
	}
	CloseHandle (th);
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
	if (fd_out != -1) {
		close (fd_out);
	}
	if (cons_out != -1) {
		dup2 (cons_out, 1);
		close (cons_out);
	}
	free (systemdir);
	free (_shell_cmd_);
	SetConsoleMode (GetStdHandle (STD_OUTPUT_HANDLE), mode);
}
#undef __CLOSE_DUPPED_PIPES
#endif

R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
#if __UNIX__ && !__wasi__ && HAVE_FORK
	int stdout_fd, fds[2];
	int child;
#endif
	int si, olen, ret = -1, pipecolor = -1;
	char *str, *out = NULL;

	if (r_sandbox_enable (0)) {
		eprintf ("Pipes are not allowed in sandbox mode\n");
		return -1;
	}
	si = r_cons_is_interactive ();
	r_config_set_b (core->config, "scr.interactive", false);
	if (!r_config_get_i (core->config, "scr.color.pipe")) {
		pipecolor = r_config_get_i (core->config, "scr.color");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}
	if (*shell_cmd == '!') {
		r_cons_grep_parsecmd (shell_cmd, "\"");
		olen = 0;
		out = NULL;
		// TODO: implement foo
		str = r_core_cmd_str (core, radare_cmd);
		r_sys_cmd_str_full (shell_cmd + 1, str, -1, &out, &olen, NULL);
		free (str);
		r_cons_write (out, olen);
		free (out);
		ret = 0;
	}
#if !HAVE_FORK
	// nothing
#elif __UNIX__
	r_str_trim_head (radare_cmd);
	r_str_trim_head (shell_cmd);

	r_sys_signal (SIGPIPE, SIG_IGN);
	stdout_fd = dup (1);
	if (stdout_fd != -1) {
		if (pipe (fds) == 0) {
			child = r_sys_fork ();
			if (child == -1) {
				eprintf ("Cannot fork\n");
			} else if (child) {
				dup2 (fds[1], 1);
				close (fds[1]);
				close (fds[0]);
				r_core_cmd (core, radare_cmd, 0);
				r_cons_flush ();
				close (1);
				wait (&ret);
				dup2 (stdout_fd, 1);
			} else {
				close (fds[1]);
				dup2 (fds[0], 0);
				//dup2 (1, 2); // stderr goes to stdout
				r_sandbox_system (shell_cmd, 0);
			}
		} else {
			eprintf ("r_core_cmd_pipe: Could not pipe\n");
		}
		close (stdout_fd);
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
			res = r_str_prepend (res, cmd);
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

static bool is_macro_command(const char *ptr) {
	ptr = r_str_trim_head_ro (ptr);
	while (IS_DIGIT (*ptr)) {
		ptr++;
	}
	return *ptr == '(';
}

static char *find_ch_after_macro(char *ptr, char ch) {
	int depth = 0;
	while (*ptr) {
		if (depth == 0 && *ptr == ch) {
			return ptr;
		}
		if (*ptr == '(') {
			depth++;
		} else if (*ptr == ')') {
			depth--;
		}
		ptr++;
	}
	return NULL;
}

static int r_core_cmd_subst(RCore *core, char *cmd) {
	ut64 rep = strtoull (cmd, NULL, 10);
	int ret = 0, orep;
	char *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	if (r_str_startswith (cmd, "GET /cmd/")) {
		memmove (cmd, cmd + 9, strlen (cmd + 9) + 1);
		char *http = strstr (cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		r_cons_printf ("HTTP/1.0 %d %s\r\n%s"
				"Connection: close\r\nContent-Length: %d\r\n\r\n",
				200, "OK", "", -1);
		return r_core_cmd0 (core, cmd);
	}

	/* must store a local orig_offset because there can be
	 * nested call of this function */
	ut64 orig_offset = core->offset;
	icmd = strdup (cmd);
	if (!icmd) {
		goto beach;
	}

	if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
		core->prompt_offset = core->offset;
	}
	cmd = (char *)r_str_trim_head_ro (icmd);
	r_str_trim_tail (cmd);
	// lines starting with # are ignored (never reach cmd_hash()), except #! and #?
	if (!*cmd) {
		if (core->cmdrepeat > 0) {
			lastcmd_repeat (core, true);
			ret = r_core_cmd_nullcallback (core);
		}
		goto beach;
	}
	if (!icmd || (cmd[0] == '#' && cmd[1] != '!' && cmd[1] != '?')) {
		goto beach;
	}
	if (*cmd) {
		char *hash = (char *) r_str_firstbut_escape (cmd, '#', "'\"");
		if (hash && hash != cmd) {
			*hash = 0;
			r_str_trim_tail (cmd);
		}
	}
	if (*cmd != '"') {
		if (is_macro_command (cmd)) {
			colon = find_ch_after_macro (cmd, ';');
		} else {
			colon = (char *) r_str_firstbut_escape (cmd, ';', "'\"");
		}
		if (colon) {
			*colon = 0;
		}
	} else {
		colon = NULL;
	}
	// repeat command N times
	if ((st64)rep > 0) {
		while (IS_DIGIT (*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
			goto beach;
		}
	}
	if ((st64)rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we don't want to be interactive
	if ((st64)rep > 1 && r_sandbox_enable (0)) {
		eprintf ("The command repeat syntax sugar is disabled in sandbox mode (%s)\n", cmd);
		goto beach;
	}
	if ((st64)rep > 1 && rep > INTERACTIVE_MAX_REP) {
		if (r_cons_is_interactive ()) {
			if (!r_cons_yesno ('n', "Are you sure to repeat this %"PFMT64d" times? (y/N)", rep)) {
				goto beach;
			}
		}
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = r_str_get (core->cmdtimes);
	orep = rep;

	bool is_root_cmd = core->cons->context->cmd_depth + 1 == core->max_cmd_depth;
	if (is_root_cmd) {
		r_cons_break_clear ();
	}
	r_cons_break_push (NULL, NULL);

	bool ocur_enabled = core->print && core->print->cur_enabled;
	while (rep-- && *cmd) {
		if (r_cons_was_breaked ()) {
			break;
		}
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
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);
		if (*cmd == 's') {
			// do not restore tmpseek if the command executed is the 's'eek
			tmpseek = false;
		}
		if (ret && *cmd == 'q') {
			free (cr);
			goto beach;
		}
		if (core->break_loop) {
			free (cr);
			break;
		}
		if (colon) {
			r_cons_flush ();
		}
		if (cr && *cr && orep > 1) {
			// XXX: do not flush here, we need r_cons_push () and r_cons_pop()
			r_cons_flush ();
			// XXX: we must import register flags in C
			(void)r_core_cmd0 (core, ".dr*");
			(void)r_core_cmd0 (core, cr);
		}
		free (cr);
	}
	r_cons_break_pop ();
	if (is_root_cmd) {
		r_cons_break_clear ();
	}

	if (tmpseek) {
		r_core_seek (core, orig_offset, true);
		core->tmpseek = original_tmpseek;
	}
	if (core->print) {
		core->print->cur_enabled = ocur_enabled;
	}
	if (colon && colon[1]) {
		for (++colon; *colon == ';'; colon++) {
			;
		}
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

static bool set_tmp_arch(RCore *core, char *arch, char **tmparch) {
	r_return_val_if_fail (tmparch, false);
	*tmparch = strdup (r_config_get (core->config, "asm.arch"));
	r_config_set (core->config, "asm.arch", arch);
	core->fixedarch = true;
	return true;
}

static bool set_tmp_bits(RCore *core, int bits, char **tmpbits, int *cmd_ignbithints) {
	r_return_val_if_fail (tmpbits, false);
	*tmpbits = strdup (r_config_get (core->config, "asm.bits"));
	r_config_set_i (core->config, "asm.bits", bits);
	core->fixedbits = true;
	// XXX: why?
	*cmd_ignbithints = r_config_get_i (core->config, "anal.ignbithints");
	r_config_set_b (core->config, "anal.ignbithints", true);
	return true;
}

static char *r_core_cmd_find_subcmd_begin(char *cmd) {
	int quote = 0;
	char *p;
	for (p = cmd; *p; p++) {
		if (*p == '\\') {
			p++;
			if (*p == '\'') {
				continue;
			} else if (!*p) {
				break;
			}
		}
		if (*p == '\'') {
			quote ^= 1;
			continue;
		}
		if (*p == '`' && !quote) {
			return p;
		}
		if (*p == '$' && *(p + 1) == '(' && !quote) {
			return p;
		}
	}
	return NULL;
}

static char *r_core_cmd_find_subcmd_end(char *cmd, bool backquote) {
	return (char *)r_str_firstbut_escape (cmd, backquote ? '`' : ')', "'");
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RIODesc *tmpdesc = NULL;
	int pamode = !core->io->va;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;
	bool oldfixedarch = core->fixedarch;
	bool oldfixedbits = core->fixedbits;
	bool cmd_tmpseek = false;
	ut64 tmpbsz = core->blocksize;
	int cmd_ignbithints = -1;
	if (!cmd) {
		r_list_free (tmpenvs);
		return 0;
	}
	r_str_trim (cmd);

	/* quoted / raw command */
	switch (*cmd) {
	case '.':
		if (cmd[1] == '"') { /* interpret */
			r_list_free (tmpenvs);
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
				cmd++;
				p = *cmd ? find_eoq (cmd) : NULL;
				if (!p || !*p) {
					eprintf ("Missing \" in (%s).", cmd);
					r_list_free (tmpenvs);
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
			char op0 = 0;
			if (*p) {
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
						op0 = *q;
						*q = 0;
					}
					haveQuote = q;
					oseek = core->offset;
					r_core_seek (core, r_num_math (core->num, p + 2), true);
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
					str = (char *)r_str_trim_head_ro (str);
					r_cons_flush ();
					const bool append = p[2] == '>';
					pipefd = r_cons_pipe_open (str, 1, append);
				}
			}
			line = strdup (cmd);
			line = r_str_replace (line, "\\\"", "\"", true);
			if (p && *p && p[1] == '|') {
				str = (char *)r_str_trim_head_ro (p + 2);
				r_core_cmd_pipe (core, cmd, str);
			} else {
				r_cmd_call (core->rcmd, line);
			}
			free (line);
			if (oseek != UT64_MAX) {
				r_core_seek (core, oseek, true);
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
						cmd = p;
					} else {
						*p = op0;
						cmd = p;
					}
				}
			} else {
				cmd = p + 1;
			}
		}
		r_list_free (tmpenvs);
		return true;
	case '(':
		if (cmd[1] != '*' && !strstr (cmd, ")()")) {
			r_list_free (tmpenvs);
			return r_cmd_call (core->rcmd, cmd);
		}
		break;
	case '?':
		if (cmd[1] == '>') {
			r_core_cmd_help (core, help_msg_greater_sign);
			r_list_free (tmpenvs);
			return true;
		}
	}

	/* multiple commands */
	// TODO: must honor " and ` boundaries
	//ptr = strrchr (cmd, ';');
	if (*cmd != '#') {
		if (is_macro_command (cmd)) {
			ptr = find_ch_after_macro (cmd, ';');
		} else {
			ptr = (char *)r_str_lastbut (cmd, ';', quotestr);
		}
		if (colon && ptr) {
			int ret ;
			*ptr = '\0';
			if (r_core_cmd_subst (core, cmd) == -1) {
				r_list_free (tmpenvs);
				return -1;
			}
			cmd = ptr + 1;
			ret = r_core_cmd_subst (core, cmd);
			*ptr = ';';
			r_list_free (tmpenvs);
			return ret;
			//r_cons_flush ();
		}
	}

	// TODO must honor " and `
	/* pipe console to shell process */
	ptr = (char *)r_str_lastbut (cmd, '|', quotestr);
	if (ptr) {
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove (ch, ptr, strlen (ptr) + 1);
				goto escape_pipe;
			}
		}
		char *ptr2 = strchr (cmd, '`');
		if (!ptr2 || (ptr2 && ptr2 > ptr)) {
			if (!tick || (tick && tick > ptr)) {
				*ptr = '\0';
				cmd = r_str_trim_nc (cmd);
				if (!strcmp (ptr + 1, "?")) { // "|?"
					r_core_cmd_help (core, help_msg_vertical_bar);
					r_list_free (tmpenvs);
					return ret;
				} else if (ptr[1] == 'H') { // "|H"
					scr_html = r_config_get_b (core->config, "scr.html");
					r_config_set_b (core->config, "scr.html", true);
					r_cons_context ()->is_html = true;
					r_cons_context ()->was_html = false;
					return r_core_cmd0 (core, cmd);
				} else if (!ptr[1] || !strcmp (ptr + 1, "T")) { // "|T"
					scr_html = r_config_get_b (core->config, "scr.html");
					r_config_set_b (core->config, "scr.html", false);
					scr_color = r_config_get_i (core->config, "scr.color");
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
					core->cons->context->use_tts = true;
				} else if (!strcmp (ptr + 1, ".")) { // "|."
					ret = *cmd ? r_core_cmdf (core, ".%s", cmd) : 0;
					r_list_free (tmpenvs);
					return ret;
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
					}
					r_core_return_code (core, value);
					r_list_free (tmpenvs);
					return 0;
				} else { // "|"
					scr_html = r_config_get_b (core->config, "scr.html");
					r_config_set_b (core->config, "scr.html", false);
					scr_color = r_config_get_i (core->config, "scr.color");
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
				}
			}
		}
	}
escape_pipe:

	// TODO must honor " and `
	/* bool conditions */
	ptr = (char *)r_str_lastbut (cmd, '&', quotestr);
	//ptr = strchr (cmd, '&');
	while (ptr && *ptr && ptr[1] == '&') {
		*ptr = '\0';
		ret = r_cmd_call (core->rcmd, cmd);
		if (ret == -1) {
			eprintf ("command error(%s)\n", cmd);
			if (scr_html != -1) {
				r_config_set_b (core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				r_config_set_i (core->config, "scr.color", scr_color);
			}
			r_list_free (tmpenvs);
			return ret;
		}
		for (cmd = ptr + 2; cmd && *cmd == ' '; cmd++) {
			;
		}
		ptr = strchr (cmd, '&');
	}

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
				r_config_set_b (core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				r_config_set_i (core->config, "scr.color", scr_color);
			}
			r_list_free (tmpenvs);
			return 0;
		}
	}

	/* pipe console to file */
	ptr = (char *)r_str_firstbut (cmd, '>', "\"");
	// TODO honor `
	if (ptr) {
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove (ch, ptr, strlen (ptr) + 1);
				goto escape_redir;
			}
		}
		if (ptr[0] && ptr[1] == '?') {
			r_core_cmd_help (core, help_msg_greater_sign);
			r_list_free (tmpenvs);
			return true;
		}
		int fdn = 1;
		int pipecolor = r_config_get_i (core->config, "scr.color.pipe");
		int use_editor = false;
		int ocolor = r_config_get_i (core->config, "scr.color");
		*ptr = '\0';
		str = ptr + 1 + (ptr[1] == '>');
		r_str_trim (str);
		if (!*str) {
			eprintf ("No output?\n");
			goto next2;
		}
		/* r_cons_flush() handles interactive output (to the terminal)
		 * differently (e.g. asking about too long output). This conflicts
		 * with piping to a file. Disable it while piping. */
		if (ptr > (cmd + 1) && IS_WHITECHAR (ptr[-2])) {
			char *fdnum = ptr - 1;
			if (*fdnum == 'H') { // "H>"
				scr_html = r_cons_context ()->is_html;
				r_config_set_b (core->config, "scr.html", true);
				pipecolor = true;
				*fdnum = 0;
			} else {
				if (IS_DIGIT (*fdnum)) {
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
		const bool appendResult = (ptr[1] == '>');
		if (*str == '$' && !str[1]) {
			eprintf ("No alias name given.\n");
		} else if (*str == '$') {
			// pipe to alias variable
			// register output of command as an alias

			r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
			RBuffer *cmd_out = r_core_cmd_tobuf (core, cmd);
			int alias_len;
			ut8 *alias_data = r_buf_read_all (cmd_out, &alias_len);
			if (appendResult) {
				if (r_cmd_alias_append_raw (core->rcmd, str+1, alias_data, alias_len)) {
					eprintf ("Alias \"$%s\" is a command - will not attempt to append.\n", str+1);
				} else {
					/* No existing alias */
					r_cmd_alias_set_raw (core->rcmd, str+1, alias_data, alias_len);
				}
			} else {
				r_cmd_alias_set_raw (core->rcmd, str+1, alias_data, alias_len);
			}
			ret = 0;
			r_buf_free (cmd_out);
			free (alias_data);
		} else if (fdn > 0) {
			// pipe to file (or append)
			pipefd = r_cons_pipe_open (str, fdn, appendResult);
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
			r_config_set_b (core->config, "scr.html", scr_html);
		}
		if (scr_color != -1) {
			r_config_set_i (core->config, "scr.color", scr_color);
		}
		core->cons->context->use_tts = false;
		r_list_free (tmpenvs);
		return ret;
	}
escape_redir:
next2:
	/* sub commands */
	ptr = r_core_cmd_find_subcmd_begin (cmd);
	if (ptr) {
		bool backquote = false;
		if (*ptr == '`') {
			backquote = true;
		}
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove (ch, ptr, strlen (ptr) + 1);
				goto escape_backtick;
			}
		}
		if (!backquote) {
			memmove (ptr + 1, ptr + 2, strlen (ptr) - 1);
		}
		if ((ptr[1] == '`' && backquote) ||
				(ptr[1] == ')' && !backquote)) {
			memmove (ptr, ptr + 2, strlen (ptr) - 1);
			goto escape_backtick;
		}
		ptr2 = r_core_cmd_find_subcmd_end (ptr + 1, backquote);
		if (!ptr2) {
			eprintf ("parse: Missing sub-command closing in expression.\n");
			goto fail;
		} else {
			int value = core->num->value;
			*ptr = '\0';
			*ptr2 = '\0';
			if (ptr[1] == '!') {
				str = r_core_cmd_str_pipe (core, ptr + 1);
			} else {
				// Color disabled when doing backticks ?e `pi 1`
				int ocolor = r_config_get_i (core->config, "scr.color");
				r_config_set_i (core->config, "scr.color", 0);
				core->cmd_in_backticks = true;
				str = r_core_cmd_str (core, ptr + 1);
				core->cmd_in_backticks = false;
				r_config_set_i (core->config, "scr.color", ocolor);
			}
			if (!str) {
				goto fail;
			}
			// ignore contents if first char is pipe or comment
			if (*str == '|' || *str == '*') {
				eprintf ("r_core_cmd_subst_i: invalid sub-command\n");
				free (str);
				goto fail;
			}
			if (str) {
				for (i = 0; str[i]; i++) {
					if (str[i] == '\n') {
						str[i] = ' ';
					}
				}
			}
			str = r_str_append (str, ptr2 + 1);
			cmd = r_str_append (strdup (cmd), str);
			r_core_return_code (core, value);
			ret = r_core_cmd_subst (core, cmd);
			free (cmd);
			if (scr_html != -1) {
				r_config_set_i (core->config, "scr.html", scr_html);
			}
			free (str);
			r_list_free (tmpenvs);
			return ret;
		}
	}
escape_backtick:
	// TODO must honor " and `
	if (*cmd != '"' && *cmd) {
		const char *s = strstr (cmd, "~?");
		if (s) {
			bool showHelp = false;
			if (cmd == s) {
				// ~?
				// ~??
				showHelp = true;
			} else {
				// pd~?
				// pd~??
				if (!strcmp (s, "~??")) {
					showHelp = true;
				}
			}
			if (showHelp) {
				r_cons_grep_help ();
				r_list_free (tmpenvs);
				return true;
			}
		}
	}
	if (*cmd != '.') {
		grep = r_cons_grep_strip (cmd, quotestr);
	}

	/* temporary seek commands */
	// if (*cmd != '(' && *cmd != '"')
	if (*cmd != '"') {
		ptr = (char *)r_str_firstbut_escape (cmd, '@', "\"'");
		if (ptr == cmd + 1 && *cmd == '?') {
			ptr = NULL;
		}
	} else {
		ptr = NULL;
	}

	cmd_tmpseek = core->tmpseek = ptr;
	int rc = 0;
	if (ptr) {
		char *f, *ptr2 = strchr (ptr + 1, '!');
		ut64 addr = core->offset;
		bool addr_is_set = false;
		char *tmpbits = NULL;
		const char *offstr = NULL;
		bool is_bits_set = false;
		bool is_arch_set = false;
		char *tmpeval = NULL;
		char *tmpasm = NULL;
		bool flgspc_changed = false;
		int tmpfd = -1;
		size_t sz;
		int len;
		ut8 *buf;

		*ptr++ = '\0';
repeat_arroba:
		arroba = (ptr[0] && ptr[1] && ptr[2])?  strchr (ptr + 2, '@'): NULL;
		if (!strncmp (ptr, "@@@", 3)) { // "@@@@"
			eprintf ("Cannot iterate that much.\n");
			goto fuji;
		}
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

		r_str_trim_tail (ptr);

		if (ptr[1] == '?') {
			r_core_cmd_help (core, help_msg_at);
		} else if (ptr[1] == '%') { // "@%"
			char *k = strdup (ptr + 2);
			char *v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				r_str_trim (k);
				r_str_trim (v);
				if (*k) {
					char *last = k + strlen (k) - 1;
					if (*last == '%') {
						*last = 0;
						r_str_trim (k);
					}
					r_sys_setenv (k, v);
					r_list_append (tmpenvs, k);
				}
			}
			free (k);
		} else if (ptr[1] == '.') { // "@."
			if (ptr[2] == '.') { // "@.."
				if (ptr[3] == '.') { // "@..."
					ut64 addr = r_num_tail (core->num, core->offset, ptr + 4);
					r_core_block_size (core, R_ABS ((st64)addr - (st64)core->offset));
					goto fuji;
				} else {
					addr = r_num_tail (core->num, core->offset, ptr + 3);
					r_core_seek (core, addr, true);
					cmd_tmpseek = core->tmpseek = true;
					goto fuji;
				}
			} else {
				// WAT DU
				eprintf ("TODO: what do you expect for @. import offset from file maybe?\n");
			}
		} else if (ptr[0] && ptr[1] == ':' && ptr[2]) {
			switch (ptr[0]) {
			case 'F': // "@F:" // temporary flag space
				flgspc_changed = r_flag_space_push (core->flags, ptr + 2);
				break;
			case 'B': // "@B:#" // seek to the last instruction in current bb
				{
					int index = (int)r_num_math (core->num, ptr + 2);
					RAnalBlock *bb = r_anal_bb_from_offset (core->anal, core->offset);
					if (bb) {
						// handle negative indices
						if (index < 0) {
							index = bb->ninstr + index;
						}

						if (index >= 0 && index < bb->ninstr) {
							ut16 inst_off = r_anal_bb_offset_inst (bb, index);
							r_core_seek (core, bb->addr + inst_off, true);
							cmd_tmpseek = core->tmpseek = true;
						} else {
							eprintf ("The current basic block has %d instructions\n", bb->ninstr);
						}
					} else {
						eprintf ("Can't find a basic block for 0x%08"PFMT64x"\n", core->offset);
					}
					break;
				}
				break;
			case 'f': // "@f:" // slurp file in block
				f = r_file_slurp (ptr + 2, &sz);
				if (f) {
					{
						RBuffer *b = r_buf_new_with_bytes ((const ut8*)f, (ut64)sz);
						RIODesc *d = r_io_open_buffer (core->io, b, R_PERM_RWX, 0);
						if (d) {
							if (tmpdesc) {
								r_io_desc_close (tmpdesc);
							}
							tmpdesc = d;
							if (pamode) {
								r_config_set_b (core->config, "io.va", true);
							}
							r_io_map_add (core->io, d->fd, d->perm, 0, core->offset, r_buf_size (b));
						}
					}
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
					r_core_seek (core, regval, true);
					cmd_tmpseek = core->tmpseek = true;
					free (mander);
				}
				break;
			case 'b': // "@b:" // bits
				is_bits_set = set_tmp_bits (core, r_num_math (core->num, ptr + 2), &tmpbits, &cmd_ignbithints);
				break;
			case 'i': // "@i:"
				{
					ut64 addr = r_num_math (core->num, ptr + 2);
					if (addr) {
						r_core_cmdf (core, "so %s", ptr + 2);
						cmd_tmpseek = core->tmpseek = true;
					}
				}
				break;
			case 'c': // "@c:"
				{
					char *s = r_core_cmd_str (core, ptr + 2);
					if (*s) {
						ut64 addr = r_num_math (core->num, s);
						if (core->num->nc.errors == 0) {
							r_core_seek (core, addr, true);
							cmd_tmpseek = core->tmpseek = true;
						}
					}
					free (s);
				}
				break;
			case 'e': // "@e:"
				{
					char *cmd = parse_tmp_evals (core, ptr + 2);
					if (!tmpeval) {
						tmpeval = cmd;
					} else {
						tmpeval = r_str_prepend (tmpeval, cmd);
						free (cmd);
					}
				}
				break;
			case 'v': // "@v:" // value (honors asm.bits and cfg.bigendian)
				if (ptr[1] == ':') {
					ut8 buf[8] = {0};
					ut64 v = r_num_math (core->num, ptr + 2);
					int be = r_config_get_i (core->config, "cfg.bigendian");
					int bi = r_config_get_i (core->config, "asm.bits");
					if (bi == 64) {
						r_write_ble64 (buf, v, be);
						len = 8;
					} else {
						r_write_ble32 (buf, v, be);
						len = 4;
					}
					tmpfd = r_io_fd_get_current(core->io);
					r_core_block_size (core, R_ABS (len));
					RBuffer *b = r_buf_new_with_bytes (buf, len);
					RIODesc *d = r_io_open_buffer (core->io, b, R_PERM_RWX, 0);
					if (d) {
						if (tmpdesc) {
							r_io_desc_close (tmpdesc);
						}
						tmpdesc = d;
						if (pamode) {
							r_config_set_b (core->config, "io.va", true);
						}
						r_io_map_add (core->io, d->fd, d->perm, 0, core->offset, r_buf_size (b));
						r_core_block_size (core, len);
						r_core_block_read (core);
					}
				} else {
					eprintf ("Invalid @v: syntax\n");
				}
				break;
			case 'x': // "@x:" // hexpairs
				if (ptr[1] == ':') {
					buf = malloc (strlen (ptr + 2) + 1);
					if (buf) {
						len = r_hex_str2bin (ptr + 2, buf);
						r_core_block_size (core, R_ABS (len));
						if (len > 0) {
							RBuffer *b = r_buf_new_with_bytes (buf, len);
							RIODesc *d = r_io_open_buffer (core->io, b, R_PERM_RWX, 0);
							if (d) {
								if (tmpdesc) {
									r_io_desc_close (tmpdesc);
								}
								tmpdesc = d;
								if (pamode) {
									r_config_set_b (core->config, "io.va", true);
								}
								r_io_map_add (core->io, d->fd, d->perm, 0, core->offset, r_buf_size (b));
								r_core_block_size (core, len);
								r_core_block_read (core);
							}
						} else {
							eprintf ("Error: Invalid hexpairs for @x:\n");
						}
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
						r_core_seek (core, r_num_math (core->num, out), true);
						free (out);
						usemyblock = true;
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
					if (q) {
						*q++ = 0;
						int bits = r_num_math (core->num, q);
						is_bits_set = set_tmp_bits (core, bits, &tmpbits, &cmd_ignbithints);
					}
					is_arch_set = set_tmp_arch (core, ptr + 2, &tmpasm);
				} else {
					eprintf ("Usage: pd 10 @a:arm:32\n");
				}
				break;
			case 's': // "@s:" // wtf syntax
				{
					len = strlen (ptr + 2);
					r_core_block_size (core, len);
					const ut8 *buf = (const ut8*)r_str_trim_head_ro (ptr + 2);

					if (len > 0) {
						RBuffer *b = r_buf_new_with_bytes (buf, len);
						RIODesc *d = r_io_open_buffer (core->io, b, R_PERM_RWX, 0);
						if (!core->io->va) {
							r_config_set_b (core->config, "io.va", true);
						}
						if (d) {
							if (tmpdesc) {
								r_io_desc_close (tmpdesc);
							}
							tmpdesc = d;
							if (pamode) {
								r_config_set_b (core->config, "io.va", true);
							}
							r_io_map_add (core->io, d->fd, d->perm, 0, core->offset, r_buf_size (b));
							r_core_block_size (core, len);
							// r_core_block_read (core);
						}
					}
				}
break;
			default:
				goto ignore;
			}
			*ptr = '@';
			/* trim whitespaces before the @ */
			/* Fixes pd @x:9090 */
			char *trim = ptr - 2;
			while (trim > cmd) {
				if (!IS_WHITESPACE (*trim)) {
					break;
				}
				*trim = 0;
				trim--;
			}
			goto next_arroba;
		}
ignore:
		r_str_trim_head (ptr + 1);
		cmd = r_str_trim_nc (cmd);
		if (ptr2) {
			if (strlen (ptr + 1) == 13 && strlen (ptr2 + 1) == 6 &&
				!strncmp (ptr + 1, "0x", 2) &&
				!strncmp (ptr2 + 1, "0x", 2)) {
				/* 0xXXXX:0xYYYY */
			} else if (strlen (ptr + 1) == 9 && strlen (ptr2 + 1) == 4) {
				/* XXXX:YYYY */
			} else {
				*ptr2 = '\0';
				if (!ptr2[1]) {
					goto fail;
				}
				r_core_block_size (core, r_num_math (core->num, ptr2 + 1));
			}
		}

		r_str_trim_head (ptr + 1);
		offstr = ptr + 1;

		addr = (*offstr == '{')? core->offset: r_num_math (core->num, offstr);
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
		// remap thhe tmpdesc if any
		if (addr) {
			RIODesc *d = tmpdesc;
			if (d) {
				r_io_map_add (core->io, d->fd, d->perm, 0, addr, r_io_desc_size (d));
			}
		}
next_arroba:
		if (arroba) {
			ptr = arroba + 1;
			*arroba = '@';
			arroba = NULL;
			goto repeat_arroba;
		}
		core->fixedblock = !!tmpdesc;
		if (core->fixedblock) {
			r_core_block_read (core);
		}
		if (ptr[1] == '@') { // @@
			if (ptr[2] == '@') { // @@@
				char *rule = ptr + 3;
				while (*rule && *rule == ' ') {
					rule++;
				}
				ret = r_core_cmd_foreach3 (core, cmd, rule);
			} else {
				ret = r_core_cmd_foreach (core, cmd, ptr + 2);
			}
		} else {
			bool tmpseek = false;
			const char *fromvars[] = { "anal.from", "diff.from", "graph.from", "search.from", "zoom.from", NULL };
			const char *tovars[] = { "anal.to", "diff.to", "graph.to", "search.to", "zoom.to", NULL };
			ut64 curfrom[R_ARRAY_SIZE (fromvars) - 1], curto[R_ARRAY_SIZE (tovars) - 1];

			// "@{A B}"
			if (ptr[1] == '{') {
				char *range = ptr + 2;
				char *p = strchr (range, ' ');
				if (!p) {
					eprintf ("Usage: / ABCD @{0x1000 0x3000}\n");
					eprintf ("Run command and define the following vars:\n");
					eprintf (" (anal|diff|graph|search|zoom).{from,to}\n");
					free (tmpeval);
					free (tmpasm);
					free (tmpbits);
					goto fail;
				}
				char *arg = p + 1;
				int arg_len = strlen (arg);
				if (arg_len > 0) {
					arg[arg_len - 1] = 0;
				}
				*p = '\x00';
				ut64 from = r_num_math (core->num, range);
				ut64 to = r_num_math (core->num, arg);
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
			} else {
				if (addr_is_set && ptr[1]) {
					r_core_seek (core, addr, true);
					r_core_block_read (core);
				}
			}
			ret = r_cmd_call (core->rcmd, r_str_trim_head_ro (cmd));
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
		if (is_arch_set) {
			core->fixedarch = oldfixedarch;
			r_config_set (core->config, "asm.arch", tmpasm);
			R_FREE (tmpasm);
		}
		if (tmpdesc) {
			if (pamode) {
				r_config_set_b (core->config, "io.va", false);
			}
			r_io_desc_close (tmpdesc);
			tmpdesc = NULL;
		}
		if (tmpfd != -1) {
			// TODO: reuse tmpfd instead of
			r_io_use_fd (core->io, tmpfd);
			tmpfd = -1;
		}
		if (is_bits_set) {
			r_config_set (core->config, "asm.bits", tmpbits);
			core->fixedbits = oldfixedbits;
		}
		if (tmpbsz != core->blocksize) {
			r_core_block_size (core, tmpbsz);
		}
		if (tmpeval) {
			r_core_cmd0 (core, tmpeval);
			R_FREE (tmpeval);
		}
		if (flgspc_changed) {
			r_flag_space_pop (core->flags);
		}
		*ptr = '@';
		rc = ret;
		free (tmpbits);
		goto beach;
	}
fuji:
	if (cmd) {
		r_str_trim_head (cmd);
		rc = r_cmd_call (core->rcmd, cmd);
	} else {
		rc = 0;
	}
	if (rc == 1) {
		r_core_return_code (core, rc);
	}
beach:
	if (grep) {
		char *old_grep = grep;
		grep = unescape_special_chars (old_grep, SPECIAL_CHARS_REGULAR);
		free (old_grep);
	}
	r_cons_grep_process (grep);
	if (scr_html != -1) {
		r_cons_flush ();
		r_config_set_i (core->config, "scr.html", scr_html);
	}
	if (scr_color != -1) {
		r_config_set_i (core->config, "scr.color", scr_color);
	}
	r_list_free (tmpenvs);
	if (tmpdesc) {
		r_io_desc_close (tmpdesc);
		tmpdesc = NULL;
	}
	core->fixedarch = oldfixedarch;
	core->fixedbits = oldfixedbits;
	if (tmpseek) {
		*tmpseek = cmd_tmpseek;
	}
	if (cmd_ignbithints != -1) {
		r_config_set_i (core->config, "anal.ignbithints", cmd_ignbithints);
	}
	return rc;
fail:
	rc = -1;
	goto beach;
}

struct exec_command_t {
	RCore *core;
	const char *cmd;
};

typedef struct {
	char *name;
	ut64 addr;
	ut64 size;
} ForeachListItem;

static void foreach3list_free(void* u) {
	ForeachListItem *fli = (ForeachListItem*)u;
	free (fli->name);
	free (fli);
}

static void append_item(RList *list, const char *name, ut64 addr, ut64 size) {
	ForeachListItem *fli = R_NEW0 (ForeachListItem);
	if (fli) {
		if (name) {
			fli->name = strdup (name);
		}
		fli->addr = addr;
		fli->size = size;
		r_list_append (list, fli);
	}
}

static bool copy_into_flagitem_list(RFlagItem *item, void *u) {
	RList *list = (RList*)u;
	append_item (list, item->name, item->offset, item->size);
	return true;
}

static void foreach_pairs(RCore *core, const char *cmd, const char *each) {
	const char *arg;
	int pair = 0;
	for (arg = each ; ; ) {
		char *next = strchr (arg, ' ');
		if (next) {
			*next = 0;
		}
		if (arg && *arg) {
			ut64 n = r_num_get (NULL, arg);
			if (pair % 2) {
				r_core_block_size (core, n);
				r_core_cmd0 (core, cmd);
			} else {
				r_core_seek (core, n, true);
			}
			pair++;
		}
		if (!next) {
			break;
		}
		arg = next + 1;
	}
}

static RList *foreach3list(RCore *core, char type, const char *glob) {
	bool va = r_config_get_b (core->config, "io.va");
	RList *list = r_list_newf (foreach3list_free);
	RListIter *iter;
	int i;
	switch (type) {
	case 'C':
		{
			RIntervalTreeIter it;
			RAnalMetaItem *meta;
			r_interval_tree_foreach (&core->anal->meta, it, meta) {
				if (meta->type != R_META_TYPE_COMMENT) {
					continue;
				}
				if (!glob || (meta->str && r_str_glob (meta->str, glob))) {
					ut64 addr = r_interval_tree_iter_get (&it)->start;
					append_item (list, NULL, addr, UT64_MAX);
				}
			}
		}
		break;
	case 'm': // @@@m
		{
			int fd = r_io_fd_get_current (core->io);
			// only iterate maps of current fd
			RList *maps = r_io_map_get_by_fd (core->io, fd);
			RIOMap *map;
			if (maps) {
				RListIter *iter;
				r_list_foreach (maps, iter, map) {
					append_item (list, NULL, r_io_map_begin (map), r_io_map_size (map));
				}
				r_list_free (maps);
			}
		}
		break;
	case 'M': // @@@M
		if (core->dbg && core->dbg->h && core->dbg->maps) {
			RDebugMap *map;
			r_list_foreach (core->dbg->maps, iter, map) {
				append_item (list, NULL, map->addr, map->size);
			}
		}
		break;
	case 'e': // @@@e
		{
			RBinAddr *entry;
			RList *elist = r_bin_get_entries (core->bin);
			r_list_foreach (elist, iter, entry) {
				ut64 addr = va? entry->vaddr: entry->paddr;
				append_item (list, NULL, addr, UT64_MAX);
			}
			r_list_free (elist);
		}
		break;
	case 't': // @@@t
		// iterate over all threads
		if (core->dbg && core->dbg->h && core->dbg->h->threads) {
			RDebugPid *p;
			RList *thlist = core->dbg->h->threads (core->dbg, core->dbg->pid);
			r_list_foreach (thlist, iter, p) {
				append_item (list, NULL, (ut64)p->pid, UT64_MAX);
			}
			r_list_free (thlist);
		}
		break;
	case 'i': // @@@i
		{
			RBinImport *imp;
			const RList *implist = r_bin_get_imports (core->bin);
			r_list_foreach (implist, iter, imp) {
				char *impflag = r_str_newf ("sym.imp.%s", imp->name);
				ut64 addr = r_num_math (core->num, impflag);
				if (addr != 0 && addr != UT64_MAX) {
					append_item (list, NULL, addr, UT64_MAX);
				}
				free (impflag);
			}
		}
		break;
	case 'E':
		{
			RBinSymbol *sym;
			RList *symlist = r_bin_get_symbols (core->bin);
			bool va = r_config_get_b (core->config, "io.va");
			r_list_foreach (symlist, iter, sym) {
				if (!isAnExport (sym)) {
					continue;
				}
				ut64 addr = va? sym->vaddr: sym->paddr;
				append_item (list, NULL, addr, UT64_MAX);
			}
		}
		break;
	case 's': // @@@s symbols
		{
			RBinSymbol *sym;
			RList *syms = r_bin_get_symbols (core->bin);
			r_list_foreach (syms, iter, sym) {
				ut64 addr = va? sym->vaddr: sym->paddr;
				append_item (list, NULL, addr, sym->size);
			}
		}
		break;
	case 'S': // "@@@S"
		{
			RBinObject *obj = r_bin_cur_object (core->bin);
			if (obj) {
				RBinSection *sec;
				r_list_foreach (obj->sections, iter, sec) {
					ut64 addr = va ? sec->vaddr: sec->paddr;
					ut64 size = va ? sec->vsize: sec->size;
					append_item (list, NULL, addr, size);
				}
			}
		}
		break;
	case 'z':
		{
			RList *zlist = r_bin_get_strings (core->bin);
			if (zlist) {
				RBinString *s;
				r_list_foreach (zlist, iter, s) {
					ut64 addr = va? s->vaddr: s->paddr;
					append_item (list, NULL, addr, s->size);
				}
			}
		}
		break;
	case 'b':
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				RListIter *iter;
				RAnalBlock *bb;
				r_list_foreach (fcn->bbs, iter, bb) {
					append_item (list, NULL, bb->addr, bb->size);
				}
			}
		}
		break;
	case 'F':
		{
			RAnalFunction *fcn;
			r_list_foreach (core->anal->fcns, iter, fcn) {
				if (!glob || r_str_glob (fcn->name, glob)) {
					ut64 size = r_anal_function_linear_size (fcn);
					append_item (list, NULL, fcn->addr, size);
				}
			}
		}
		break;
	case 'R': // relocs
		{
			RRBTree *rels = r_bin_get_relocs (core->bin);
			if (rels) {
				RRBNode *node = r_crbtree_first_node (rels);
				while (node) {
					RBinReloc *rel = (RBinReloc *)node->data;
					ut64 addr = va? rel->vaddr: rel->paddr;
					append_item (list, NULL, addr, UT64_MAX);
					node = r_rbnode_next (node);
				}
			}
		}
		break;
	case 'r': // registers
		{
			const int bits = core->anal->config->bits;
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
				RRegItem *item;
				RList *head = r_reg_get_list (core->dbg->reg, i);
				r_list_foreach (head, iter, item) {
					if (item->size != bits) {
						continue;
					}
					if (item->type != i) {
						continue;
					}
					ut64 addr = r_reg_getv (core->dbg->reg, item->name);
					append_item (list, item->name, addr, item->size);
				}
			}
		}
		break;
	case 'f':
		r_flag_foreach_glob (core->flags, glob, copy_into_flagitem_list, list);
		break;
	}
	return list;
}

R_API int r_core_cmd_foreach3(RCore *core, const char *cmd, char *each) { // "@@@"
	ForeachListItem *item;
	RListIter *iter;
	char *glob = (each[0] && each[1] == ':')
		? r_str_trim_dup (each + 2): NULL;

	RList *list = foreach3list (core, *each, glob);

	switch (each[0]) {
	case '=':
		foreach_pairs (core, cmd, each + 1);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_at_at_at);
		break;
	case 'c':
		if (glob) {
			char *arg = r_core_cmd_str (core, glob);
			if (arg) {
				foreach_pairs (core, cmd, arg);
				free (arg);
			}
		} else {
			eprintf ("Usage: @@@c:command   # same as @@@=`command`\n");
		}
		break;
	case 'C':
	case 's':
	case 'm':
	case 'M':
	case 'e':
	case 'E':
	case 'f':
	case 'F':
	case 'b':
	case 'z':
	case 'R':
	case 'S':
	case 'r':
	case 'i':
		{
			ut64 offorig = core->offset;
			ut64 bszorig = core->blocksize;
			r_cons_break_push (NULL, NULL);
			r_list_foreach (list, iter, item) {
				if (r_cons_is_breaked ()) {
					break;
				}
				if (item->addr == UT64_MAX) {
					continue;
				}
				if (item->name) {
					r_cons_printf ("%s: ", item->name);
				}
				r_core_seek (core, item->addr, true);
				if (item->size) {
					r_core_block_size (core, item->size);
				}
				r_core_cmd0 (core, cmd);
				if (!foreach_newline (core)) {
					break;
				}
			}
			r_core_seek (core, offorig, true);
			r_core_block_size (core, bszorig);
			r_cons_break_pop ();
		}
		break;
	case 't':
		// TODO: generalize like the rest, just call dp before and after
		if (core->dbg && core->dbg->h && core->dbg->h->threads) {
			int origpid = core->dbg->pid;
			r_list_foreach (list, iter, item) {
				int curpid = (int) item->addr;
				r_core_cmdf (core, "dp %d", curpid);
				r_cons_printf ("# PID %d\n", curpid);
				r_core_cmd0 (core, cmd);
				if (!foreach_newline (core)) {
					break;
				}
			}
			r_core_cmdf (core, "dp %d", origpid);
		}
		break;
	case 0:
		eprintf ("Nothing to repeat. Check @@@?\n");
		break;
	case '@':
		eprintf ("I can't iterate that much!\n");
		break;
	default:
		eprintf ("Invalid repeat type, Check @@@? for help\n");
		break;
	}
	r_list_free (list);
	free (glob);
	return 0;
}

static void foreachWord(RCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup (_cmd);
	char *nextLine = NULL;
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
			while (*each == ' ') {
				each++;
			}
			char *curword = NULL;
			char *str = strchr (each, ' ');
			if (str) {
				*str = '\0';
				curword = strdup (each);
				*str = ' ';
				each = str + 1;
			} else {
				if (!*each) {
					break;
				}
				curword = strdup (each);
				each = NULL;
			}
			r_core_cmdf (core, "%s %s", cmd, curword);
			R_FREE (curword);
			if (!foreach_newline (core)) {
				break;
			}
			r_cons_flush ();
		}
		each = nextLine;
	}
	free (cmd);
}

static void foreachOffset(RCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup (_cmd);
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
			while (*each == ' ') {
				each++;
			}
			char *str = strchr (each, ' ');
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
			r_core_seek (core, addr, true);
			r_core_cmd (core, cmd, 0);
			foreach_newline (core);
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

	for (; *cmd == ' '; cmd++) {
		;
	}

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
		free (ostr);
		return 0;
	case 0:
		eprintf ("Nothing to repeat. Check @@?\n");
		break;
	case '?': // "@@?"
		r_core_cmd_help (core, help_msg_at_at);
		break;
	case 'b': // "@@b" - function basic blocks
		{
			RListIter *iter;
			RAnalBlock *bb;
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);
			int bs = core->blocksize;
			if (fcn) {
				r_list_sort (fcn->bbs, bb_cmp);
				r_list_foreach (fcn->bbs, iter, bb) {
					r_core_block_size (core, bb->size);
					r_core_seek (core, bb->addr, true);
					r_core_cmd (core, cmd, 0);
					if (!foreach_newline (core)) {
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
				for (cur = from; cur <= to; cur += step) {
					(void) r_core_seek (core, cur, true);
					r_core_cmd (core, cmd, 0);
					if (!foreach_newline (core)) {
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
		{
			RListIter *iter;
			RAnalBlock *bb;
			int i;
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);
			if (fcn) {
				r_list_sort (fcn->bbs, bb_cmp);
				r_list_foreach (fcn->bbs, iter, bb) {
					for (i = 0; i < bb->op_pos_size; i++) {
						ut64 addr = bb->addr + bb->op_pos[i];
						r_core_seek (core, addr, true);
						r_core_cmd (core, cmd, 0);
						if (!foreach_newline (core)) {
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
						r_core_seek (core, fcn->addr, true);
						r_core_cmd (core, cmd, 0);
						if (!foreach_newline (core)) {
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
				RConsGrep grep = core->cons->context->grep;
				r_list_foreach (core->anal->fcns, iter, fcn) {
					char *buf;
					r_core_seek (core, fcn->addr, true);
					r_cons_push ();
					r_core_cmd (core, cmd, 0);
					buf = (char *)r_cons_get_buffer ();
					if (buf) {
						buf = strdup (buf);
					}
					r_cons_pop ();
					r_cons_strcat (buf);
					free (buf);
					if (!foreach_newline (core)) {
						break;
					}
				}
				core->cons->context->grep = grep;
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
					if (!foreach_newline (core)) {
						break;
					}
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
				free (arg);
			}
		}
		break;
	case '=': // "@@="
		if (each[1] == '=') {
			foreachWord (core, cmd, r_str_trim_head_ro (str + 2));
		} else {
			foreachOffset (core, cmd, r_str_trim_head_ro (str + 1));
		}
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
					r_core_seek (core, frame->bp, true);
					break;
				case 's':
					r_core_seek (core, frame->sp, true);
					break;
				default:
				case 'a':
					r_core_seek (core, frame->addr, true);
					break;
				}
				r_core_cmd (core, cmd, 0);
				if (!foreach_newline (core)) {
					break;
				}
				i++;
			}
			r_core_seek (core, oseek, false);
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
				while (*each == ' ') {
					each++;
				}
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
				r_core_seek (core, addr, true);
				r_core_cmd (core, cmd, 0);
				if (!foreach_newline (core)) {
					break;
				}
				r_cons_flush ();
			} while (str);
			free (out);
		}
		}
		break;
	case '.': // "@@."
		if (each[1] == '(') {
			// XXX what's this 999 ?
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
				r_core_seek (core, addr, true);
				r_core_cmdf (core, "%s @ 0x%08"PFMT64x"", cmd, addr);
				if (!foreach_newline (core)) {
					break;
				}
				i++;
			}
		} else {
			FILE *fd = r_sandbox_fopen (each + 1, "r");
			if (fd) {
				core->rcmd->macro.counter = 0;
				size_t buf_size = 1024;
				char *buf = calloc (buf_size, 1);
				if (buf) {
					while (!feof (fd)) {
						buf[0] = '\0';
						if (!fgets (buf, buf_size, fd)) {
							break;
						}
						if (*buf) {
							addr = r_num_math (core->num, buf);
							r_core_seek (core, addr, true); // XXX
							r_core_cmdf (core, "%s @ 0x%08"PFMT64x"", cmd, addr);
							if (!foreach_newline (core)) {
								break;
							}
							core->rcmd->macro.counter++;
						}
					}
				}
				free (buf);
				fclose (fd);
			} else {
				eprintf ("cannot open file '%s' to read offsets\n", each + 1);
			}
		}
		break;
	default:
		core->rcmd->macro.counter = 0;
		for (; *each == ' '; each++) {
			;
		}
		i = 0;
		while (str[i]) {
			j = i;
			for (; str[j] && str[j] == ' '; j++) {
				; // skip spaces
			}
			for (i = j; str[i] && str[i] != ' '; i++) {
				; // find EOS
			}
			ch = str[i];
			str[i] = '\0';
			word = strdup (str + j);
			if (!word) {
				break;
			}
			str[i] = ch;
			{
				const RSpace *flagspace = r_flag_space_cur (core->flags);
				RList *match_flag_items = r_list_newf ((RListFree)r_flag_item_free);
				if (!match_flag_items) {
					break;
				}

				/* duplicate flags that match word, to be sure
				   the command is going to be executed on flags
				   values at the moment the command is called
				   (without side effects) */
				struct duplicate_flag_t u = {
					.ret = match_flag_items,
					.word = word,
				};
				r_flag_foreach_space (core->flags, flagspace, duplicate_flag, &u);

				/* for all flags that match */
				r_list_foreach (match_flag_items, iter, flag) {
					if (r_cons_is_breaked ()) {
						break;
					}

					char *buf = NULL;
					const char *tmp = NULL;
					r_core_seek (core, flag->offset, true);
					r_cons_push ();
					r_core_cmd (core, cmd, 0);
					tmp = r_cons_get_buffer ();
					buf = tmp? strdup (tmp): NULL;
					r_cons_pop ();
					r_cons_strcat (buf);
					free (buf);
					if (!foreach_newline (core)) {
						break;
					}
					r_core_task_yield (&core->tasks);
				}

				r_list_free (match_flag_items);
				core->rcmd->macro.counter++ ;
				R_FREE (word);
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

static int run_cmd_depth(RCore *core, char *cmd) {
	char *rcmd;
	int ret = false;

	if (core->cons->context->cmd_depth < 1) {
		eprintf ("r_core_cmd: That was too deep (%s)...\n", cmd);
		return false;
	}
	core->cons->context->cmd_depth--;
	for (rcmd = cmd;;) {
		char *ptr = strchr (rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);
		if (ret == -1) {
			r_cons_eprintf ("|ERROR| Invalid command '%s' (0x%02x)\n", rcmd, *rcmd);
			break;
		}
		if (!ptr) {
			break;
		}
		rcmd = ptr + 1;
	}
	core->cons->context->cmd_depth++;
	return ret;
}

R_API int r_core_cmd(RCore *core, const char *cstr, bool log) {
	int ret = false;
	size_t i;
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
		if (*cstr == 'q') {
			R_FREE (core->cmdremote);
			goto beach; // false
		} else if (*cstr != '=' && strncmp (cstr, "!=", 2)) {
			if (core->cmdremote[0]) {
				char *s = r_str_newf ("%s %s", core->cmdremote, cstr);
				r_core_rtr_cmd (core, s);
				free (s);
			} else {
				char *res = r_io_system (core->io, cstr);
				if (res) {
					r_cons_printf ("%s\n", res);
					free (res);
				}
			}
			if (log) {
				r_line_hist_add (cstr);
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

	char *cmd = malloc (strlen (cstr) + 4096);
	if (!cmd) {
		goto beach;
	}
	r_str_cpy (cmd, cstr);
	if (log) {
		r_line_hist_add (cstr);
	}
	ret = run_cmd_depth (core, cmd);
	free (cmd);
beach:
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
	size_t line_count = r_str_char_count(lines, '\n');

#if __UNIX__
	const bool istty = r_cons_is_tty ();
#else
	const bool istty = true;
#endif
	const bool show_progress_bar = core->print->enable_progressbar && r_config_get_b (core->config, "scr.interactive") && r_config_get_i (core->config, "scr.progressbar") && istty;
	size_t current_line = 0;
	nl = strchr (odata, '\n');
	if (nl) {
		r_cons_break_push (NULL, NULL);
		do {
			if (show_progress_bar) {
				r_print_progressbar_with_count (core->print, current_line++, line_count, 80, true);
			}
			if (r_cons_is_breaked ()) {
				free (odata);
				r_cons_break_pop ();
				return ret;
			}
			*nl = '\0';
			r = r_core_cmd (core, data, 0);
			if (r < 0) {
				data = nl + 1;
				ret = -1;
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
			r_core_task_yield (&core->tasks);
		} while ((nl = strchr (data, '\n')));
		r_cons_break_pop ();
		if (show_progress_bar) {
			r_print_progressbar_with_count (core->print, line_count, line_count, 80, true);
			r_cons_newline ();
		}
	}
	if (ret >= 0 && data && *data) {
		r_core_cmd (core, data, 0);
		r_cons_flush ();
		r_core_task_yield (&core->tasks);
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

R_API int r_core_cmd_buffer(RCore *core, const char *buf) {
	char *ptr, *optr, *str = strdup (buf);
	if (!str) {
		return false;
	}
	optr = str;
	ptr = strchr (str, '\n');
	while (ptr) {
		*ptr = '\0';
		r_core_cmd (core, optr, 0);
		optr = ptr + 1;
		ptr = strchr (str, '\n');
	}
	r_core_cmd (core, optr, 0);
	free (str);
	return true;
}

R_API int r_core_cmdf(RCore *core, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *cmd = r_str_newvf (fmt, ap);
	int ret = r_core_cmd (core, cmd, 0);
	free (cmd);
	va_end (ap);
	return ret;
}

R_API int r_core_cmd0(RCore *core, const char *cmd) {
	return r_core_cmd (core, cmd, 0);
}

R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd) {
	char *tmp = NULL;
	char *p = (*cmd != '"')? strchr (cmd, '|'): NULL;
	if (!p && *cmd != '!' && *cmd != '.') {
		return r_core_cmd_str (core, cmd);
	}
	r_cons_reset ();
	r_sandbox_disable (true);
	if (r_file_mkstemp ("cmd", &tmp) != -1) {
		int pipefd = r_cons_pipe_open (tmp, 1, 0);
		if (pipefd == -1) {
			r_file_rm (tmp);
			r_sandbox_disable (false);
			free (tmp);
			return r_core_cmd_str (core, cmd);
		}
		char *_cmd = strdup (cmd);
		r_core_cmd (core, _cmd, 0);
		r_cons_flush ();
		r_cons_pipe_close (pipefd);
		if (r_file_exists (tmp)) {
			char *s = r_file_slurp (tmp, NULL);
			r_file_rm (tmp);
			r_sandbox_disable (false);
			free (tmp);
			free (_cmd);
			return s? s: strdup ("");
		}
		eprintf ("slurp %s fails\n", tmp);
		r_file_rm (tmp);
		free (tmp);
		free (_cmd);
		r_sandbox_disable (false);
		return r_core_cmd_str (core, cmd);
	}
	r_sandbox_disable (0);
	return NULL;
}

R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *cmd = r_str_newvf (fmt, ap);
	char *ret = r_core_cmd_str (core, cmd);
	free (cmd);
	va_end (ap);
	return ret;
}

/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	r_cons_push ();
	core->cons->context->noflush = true;
	core->cons->context->cmd_str_depth++;
	if (r_core_cmd (core, cmd, 0) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		if (--core->cons->context->cmd_str_depth == 0) {
			core->cons->context->noflush = false;
			r_cons_flush ();
		}
		r_cons_pop ();
		return NULL;
	}
	if (--core->cons->context->cmd_str_depth == 0) {
		core->cons->context->noflush = false;
	}
	r_cons_filter ();
	const char *static_str = r_cons_get_buffer ();
	char *retstr = strdup (r_str_get (static_str));
	r_cons_pop ();
	r_cons_echo (NULL);
	return retstr;
}

/* get command output in raw bytes */
R_API RBuffer *r_core_cmd_tobuf(RCore *core, const char *cmd) {
	r_cons_push ();
	core->cons->context->noflush = true;

	core->cons->context->cmd_str_depth++;
	if (r_core_cmd0 (core, cmd) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		if (--core->cons->context->cmd_str_depth == 0) {
			core->cons->context->noflush = false;
			r_cons_flush ();
		}
		r_cons_pop ();
		return NULL;
	}

	if (--core->cons->context->cmd_str_depth == 0) {
		core->cons->context->noflush = false;
	}

	r_cons_filter ();
	RBuffer *out = r_buf_new_with_bytes ((const ut8*)r_cons_get_buffer (), r_cons_get_buffer_len ());

	r_cons_pop ();
	r_cons_echo (NULL);
	return out;
}

/* run cmd in the main task synchronously */
R_API int r_core_cmd_task_sync(RCore *core, const char *cmd, bool log) {
	RCoreTask *task = core->tasks.main_task;
	char *s = strdup (cmd);
	if (!s) {
		return 0;
	}
	task->cmd = s;
	task->cmd_log = log;
	task->state = R_CORE_TASK_STATE_BEFORE_START;
	int res = r_core_task_run_sync (&core->tasks, task);
	free (s);
	return res;
}

static int cmd_ox(void *data, const char *input) {
	return r_core_cmdf ((RCore*)data, "s 0%s", input);
}

static int core_cmd0_wrapper(void *core, const char *cmd) {
	return r_core_cmd0 ((RCore *)core, cmd);
}

R_API void r_core_cmd_init(RCore *core) {
	struct {
		const char *cmd;
		const char *description;
		RCmdCb cb;
	} cmds[] = {
		{"!", "run system command", cmd_system },
		{"_", "print last output", cmd_last },
		{"#", "calculate hash", cmd_hash },
		{"$", "alias", cmd_alias },
		{"%", "short version of 'env' command", cmd_env },
		{"&", "tasks", cmd_tasks },
		{"(", "macro", cmd_macro },
		{"*", "pointer read/write", cmd_pointer },
		{"+", "relative seek forward", cmd_plus },
		{"-", "open cfg.editor and run script", cmd_stdin },
		{".", "interpret", cmd_interpret },
		{",", "create and manipulate tables", cmd_table },
		{"/", "search kw, pattern aes", cmd_search },
		{"=", "io pipe", cmd_rap },
		{"?", "help message", cmd_help },
		{":", "alias for =!", cmd_rap_run },
		{"0", "alias for s 0x", cmd_ox },
		{"a", "analysis", cmd_anal },
		{"b", "change block size", cmd_bsize },
		{"c", "compare memory", cmd_cmp },
		{"C", "code metadata", cmd_meta },
		{"d", "debugger operations", cmd_debug },
		{"e", "evaluate configuration variable", cmd_eval },
		{"f", "get/set flags", cmd_flag },
		{"g", "egg manipulation", cmd_egg },
		{"i", "get file info", cmd_info },
		{"k", "perform sdb query", cmd_kuery },
		{"l", "list files and directories", cmd_l },
		{"j", "join the contents of the two files", cmd_join },
		{"h", "show the top n number of line in file", cmd_head },
		{"L", "manage dynamically loaded plugins", cmd_plugins },
		{"m", "mount filesystem", cmd_mount },
		{"o", "open or map file", cmd_open },
		{"p", "print current block", cmd_print },
		{"P", "project", cmd_project },
		{"q", "exit program session", cmd_quit },
		{"Q", "alias for q!", cmd_Quit },
		{"r", "change file size", cmd_resize },
		{"s", "seek to an offset", cmd_seek },
		{"t", "type information (cparse)", cmd_type },
		{"T", "Text log utility", cmd_log },
		{"u", "uname/undo", cmd_undo },
		{"<", "pipe into RCons.readChar", cmd_pipein },
		{"V", "enter visual mode", cmd_visual },
		{"v", "enter visual panels", cmd_panels },
		{"w", "write bytes", cmd_write },
		{"x", "alias for px", cmd_hexdump },
		{"y", "yank bytes", cmd_yank },
		{"z", "zignatures", cmd_zign },
	};

	core->rcmd = r_cmd_new ();
	if (core->rcmd) {
		core->rcmd->macro.user = core;
		core->rcmd->macro.num = core->num;
		core->rcmd->macro.cmd = core_cmd0_wrapper;
		core->rcmd->nullcallback = r_core_cmd_nullcallback;
		core->rcmd->macro.cb_printf = (PrintfCallback)r_cons_printf;
		r_cmd_set_data (core->rcmd, core);
		core->cmd_descriptors = r_list_newf (free);

		// RCmdDesc *root = r_cmd_get_root (core->rcmd);
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (cmds); i++) {
			r_cmd_add (core->rcmd, cmds[i].cmd, cmds[i].cb);
		}
	}
}
