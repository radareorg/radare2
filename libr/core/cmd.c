/* radare - LGPL - Copyright 2009-2025 - nibble, pancake */

#define INTERACTIVE_MAX_REP 1024

#include <r_core.h>
#include <r_vec.h>
#include <r_util/r_json.h>
#if R2__UNIX__
#include <sys/utsname.h>
#ifndef __wasi__
#include <pwd.h>
#endif
#endif

#define SPECIAL_CHARS "@;~$#|`\"'()<>"

static const char help_message[] = \
"\nWelcome to radare2!\n" \
"\n" \
"* Type `?` for the root list of commands. \n" \
"* Append the `?` to any command to list the sub-commands.\n" \
"* Prefix the command with `'` to avoid evaluating special chars\n" \
"* The `@` modifier can be used for temporal seeks\n" \
"* The `~` represents the internal grep. System pipes also work `|`.\n" \
"* Multiple commands can be chained with `;`.\n" \
"* Run external scripts with the `.` source command (r2, r2js, python, ..) \n" \
"* Use the `?*~...` command to inspect all the commands in visual mode\n" \
"\n" \
"Use the `e` command to change the configuration options.\n" \
"* Run `edit` to tweak your ~/.radare2rc script\n" \
"\n" \
"Basic commands:\n" \
"\n" \
"* s [addr] - seek to a different address\n" \
"* px, pd  - print hexadecimal, disassembly (pdf/pdr the whole function)\n" \
"* wx, wa  - write hexpairs, write assembly (w - write string)\n" \
"* aaa, af - analyze the whole program or function\n" \
"* /, /x   - search for strings or hexadecimal patterns\n" \
"* f~...   - search for strings or hexadecimal patterns\n" \
"* q       - quit (alias for ^D or exit)\n";

static bool isAnExport(RBinSymbol *s) {
	/* workaround for some bin plugs */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp (s->bind, R_BIN_BIND_GLOBAL_STR));
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char* colon, bool *tmpseek);

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a;
	const RAnalBlock *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

static void cmd_debug_reg(RCore *core, const char *str);

R_VEC_TYPE(RVecAnalRef, RAnalRef);

#define R_INCLUDE_BEGIN 1
#include "cmd_quit.inc.c"
#include "cmd_hash.inc.c"
#include "cmd_debug.inc.c"
#include "cmd_log.inc.c"
#include "cmd_yank.inc.c"
#include "cmd_flag.inc.c"
#include "cmd_zign.inc.c"
#include "cmd_project.inc.c"
#include "cmd_write.inc.c"
#include "cmd_cmp.inc.c"
#include "cmd_eval.inc.c"
#include "cmd_type.inc.c"
#include "cmd_anal.inc.c"
#include "cmd_open.inc.c"
#include "cmd_meta.inc.c"
#include "cmd_egg.inc.c"
#include "cmd_info.inc.c"
#include "cmd_macro.inc.c"
#include "cmd_magic.inc.c"
#include "cmd_mount.inc.c"
#include "cmd_seek.inc.c"
#include "cmd_search.inc.c" // defines incDigitBuffer... used by cmd_print
#include "cmd_print.inc.c"
#include "cmd_help.inc.c"

#undef R_INCLUDE_BEGIN

static const RCoreHelpMessage help_msg_equal_l = {
	"Usage:", "=l", " [..] list, create and destroy r2 sessions",
	"=l", "", "list all available sessions",
	"=l", " [name]", "give a name to the current session",
	"=l", "-", "stop listening in background",
	"=l", "l", "start a new session: listening for commands in background",
	NULL
};
static const RCoreHelpMessage help_msg_dollar = {
	"Usage:", "$alias[=cmd] [args...]", "Alias commands and data (See ?$? for help on $variables)",
	"$", "", "list all defined aliases",
	"$*", "", "list all defined aliases and their values, with unprintable characters escaped",
	"$**", "", "same as above, but if an alias contains unprintable characters, b64 encode it",
	"$", "foo:=123", "alias for 'f foo=123'",
	"$", "foo-=4", "alias for 'f foo-=4'",
	"$", "foo+=4", "alias for 'f foo+=4'",
	"$", "foo", "alias for 's foo' (note that command aliases can override flag resolution)",
	"$", "dis=base64:AAA=", "alias $dis to the raw bytes from decoding this base64 string",
	"$", "dis=$hello world", "alias $dis to the string after '$'",
	"$", "dis=$hello\\\\nworld\\\\0a", "string aliases accept double-backslash and hex escaping",
	"$", "dis=-", "edit $dis in cfg.editor (use single-backslashes for escaping)",
	"$", "dis=af", "alias $dis to the af command",
	"\"$", "dis=af;pdf\"", "alias $dis to run af, then pdf. you must quote the whole command.",
	"$", "test=. /tmp/test.js", "create command - rlangpipe script",
	"$", "dis=", "undefine alias",
	"$", "dis", "execute a defined command alias, or print a data alias with unprintable characters escaped",
	"$", "dis?", "show commands aliased by $dis",
	NULL
};

static const RCoreHelpMessage help_msg_l = {
	"Usage:", "l[erls] [arg]", "Internal less (~..) and file listing (!ls)",
	"lu", " [path]", "same as #!lua",
	"ll", " [path]", "same as ls -l",
	"lr", " [path]", "same as ls -r",
	"li", "", "list source of current function (like gdb's 'list' command)",
	"ls", " [-e,-l,-j,-q] [path]", "list files in current or given directory",
	"ls", " -e [path]", "list files using emojis",
	"ls", " -l [path]", "same as ll (list files with details)",
	"ls", " -j [path]", "list files in json format",
	"ls", " -q [path]", "quiet output (one file per line)",
	"le", "[ss] [path]", "same as cat file~.. (or less)",
	NULL
};

static const RCoreHelpMessage help_msg_quote = {
	"Usage:", "\"[\"..|..\"]", "quote the command to avoid evaluating special characters",
	"\"?", "", "show this help, NOTE that a single quote is simpler and works the same",
	"\"", "?e hello \\\"world\\\"\"", "print (hello \"world\")",
	"\"", "?e x;y\";\"?e y;x\"", "run two commands (prints x;y\ny;x)",
	"\"\"", "[cmd]", "directly call a command ignoring all special chars (fast)",
	"\"\"@addr\"\"", "[cmd]", "call a command with a temporal seek (EXPERIMENTAL)",
	"\"\"?e x;y\";\"?e y;x", "", "run two commands ignoring special chars (prints x;y\";\"?e y;x) ",
	NULL
};

static const RCoreHelpMessage help_msg_plus = {
	"Usage:", "+", "seek forward, same as s+X (see s? and -? for more help)",
	"+", "8", "seek 8 bytes forward, same as s+8",
	"++", "", "seek one block forward. Same as s++ (see `b` command)",
	NULL
};

static const RCoreHelpMessage help_msg_j = {
	"Usage:", "j[:o]in", "run command with json facilities or join two files",
	"j:", "?e", "run '?e' command and show the result stats in json",
	"ji:", "[cmd]", "run command and indent it as json like (cmd~{})",
	"jq", " [...]", "same as !jq",
	"js", " [expr]", "run given javascript expression ('expr' can start with base64:)",
	"js-", "", "read from stdin until ^D",
	"js!", "", "reset js vm (same as #!!)",
	"js:", "", "enter the interactive repl with autocompletion and colors",
	"js:", "[file]", "interpret javascript file",
	"join", " f1 f2", "join the contents of two files",
	NULL
};

static const RCoreHelpMessage help_msg_dash = {
	"Usage:", "-", "open editor and run the r2 commands in the saved document",
	"", "'-' '.-' '. -'", " those three commands do the same",
	"-", "8", "same as s-8, but shorter to type (see +? command)",
	"-a", " x86", "same as r2 -a x86 or e asm.arch=x86",
	"-A", "[?]", "same as r2 -A or aaa",
	"-b", " 32", "same as e or r2 -e",
	"-c", " cpu", "same as r2 -e asm.cpu=",
	"-e", " k=v", "same as r2 -b or e asm.bits",
	"-h", "", "show this help (same as -?)",
	"-H", " key", "same as r2 -H",
	"-k", " kernel", "same as r2 -k or e asm.os",
	"-f", "", "block size = file size (b $s)",
	"-j", "", "enter the js: repl",
	"-i", " [file]", "same as . [file], to run a script",
	"-s", " [addr]", "same as r2 -e asm.cpu=",
	"-L", "", "same as Lo (or r2 -L)",
	"-p", " project", "same as 'P [prjname]' to load a project",
	"-P", " patchfile", "apply given patch file (see doc/rapatch2.md)",
	"-v", "", "same as -V",
	"-V", "", "show r2 version, same as ?V",
	"--", "", "seek one block backward. Same as s-- (see `b` command)",
	NULL
};

static const RCoreHelpMessage help_msg_star = {
	"Usage:", "*<addr>[=[0x]value]", "Pointer read/write data/values",
	"*", "entry0=cc", "write trap in entrypoint",
	"*", "entry0+10=0x804800", "write value in delta address",
	"*", "entry0", "read byte at given address",
	"*", "/", "end multiline comment. (use '/*' to start mulitiline comment",
	NULL
};

static const RCoreHelpMessage help_msg_comma = {
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

static const RCoreHelpMessage help_msg_dot = {
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

static const RCoreHelpMessage help_msg_equal = {
	"Usage:", " =[:!+-=ghH] [...]", " # connect with other instances of r2",
	"\nremote commands:", "", "",
	"=", "[*j]", "list all open connections",
	"=<", "[fd] cmd", "send output of local command to remote fd", // XXX may not be a special char
	"=", "[fd] cmd", "exec cmd at remote 'fd' (last open is default one)",
	"=!", " cmd", "run command via r_io_system",
	"=+", " [proto://]host:port", "connect to remote host:port (*rap://, raps://, tcp://, udp://, http://)",
	"=-", "[fd]", "remove all hosts or host 'fd'",
	"==", "[fd]", "open remote session with host 'fd', 'q' to quit",
	"=!=", "", "disable remote cmd mode",
	"!=!", "", "enable remote cmd mode",
	"\nservers:", "", "",
	// ".:", "9000", "start the tcp server (echo x|nc ::1 9090 or curl ::1:9090/cmd/x)",
	"=l", "[?]", "list, create or destroy background session server",
	"=t", "port", "start the tcp server (echo x|nc ::1 9090 or curl ::1:9090/cmd/x)",
	"=r", "port", "start the rap server (o rap://9999)",
	"=g", "[?]", "start the gdbserver",
	"=h", " port", "start the http webserver on 'port'",
	"=H", " port", "start the http webserver on 'port' (launch browser)",
	"\nother:", "", "",
	"=&", ":port", "start rap server in background (same as '&_=h')",
	"=", ":host:port cmd", "run 'cmd' command on remote server",
	"\nexamples:", "", "",
	"=+", "tcp://localhost:9090/", "connect to: r2 -c.:9090 ./bin",
	// "=+", "udp://localhost:9090/", "connect to: r2 -c.:9090 ./bin",
	"=+", "rap://localhost:9090/", "connect to: r2 rap://:9090",
	"=+", "http://localhost:9090/cmd/", "connect to: r2 -c'=h 9090' bin",
	"o ", "rap://:9090/", "start the rap server on tcp port 9090",
	NULL
};

static const RCoreHelpMessage help_msg_equalh = {
	"Usage:", " =[hH] [...]", " # http server",
	"http server:", "", "",
	"=h", " port", "listen for http connections (r2 -qc=H /bin/ls)",
	"=h-", "", "stop background webserver",
	"=h--", "", "stop foreground webserver",
	"=h*", "", "restart current webserver",
	"=h&", " port", "start http server on 'port' in background",
	"=H", " port", "start http server on 'port' (launch browser)",
	"=H&", " port", "start http server on 'port' in background (launch browser)",
	NULL
};

static const RCoreHelpMessage help_msg_equal_equal = {
	"Usage:", " ==[=] ", "# add connection to remote r2",
	"==", "[fd]", "shell to send to the nth remote (see '=1 x' / '==1'",
	"===", "event", "returns socket file or udp port to read events from",
	NULL
};

static const RCoreHelpMessage help_msg_equal_more = {
	"Usage:", " =+ [proto://][host]:[port](/[path])", " # add connection to remote r2",
	"=+", "tcp://localhost:9090", "communicates with another instance running '& .:9090'",
	"=+", "http://localhost:9090/cmd", "talks to remote r2 webserver '& =h'",
	"=+", "rap://localhost:9090/cmd", "talks to remote r2 webserver 'r2 rap://:9090'",
	NULL
};

static const RCoreHelpMessage help_msg_equalg = {
	"Usage:", " =[g] [...]", " # gdb server",
	"gdbserver:", "", "",
	"=g", " port file [args]", "listen on 'port' debugging 'file' using gdbserver",
	NULL
};

static const RCoreHelpMessage help_msg_b = {
	"Usage:",  "b[f] [arg]", "change working block size",
	"b", " 32", "set block size to 33",
	"b", "=32", "same as 'b 32'",
	"b", " eip+4", "numeric argument can be an expression",
	"b", "", "display current block size",
	"b", "+3", "increase blocksize by 3",
	"b", "-16", "decrease blocksize by 16",
	"b*", "", "display current block size in r2 command",
	"b64:", "AA=", "receive a base64 string that is executed without evaluating special chars",
	"bf", " foo", "set block size to flag size",
	"bj", "", "display block size information in JSON",
	"bm", " 1M", "set max block size",
	NULL
};

static const RCoreHelpMessage help_msg_k = {
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

static const RCoreHelpMessage help_msg_r = {
	"Usage:", "r[+-][ size]", "Resize file",
	"r", "", "display file size in decimal",
	"r-", "num", "remove num bytes, move following data down",
	"r+", "num", "insert num bytes, move following data up",
	"r", " size", "expand or truncate file to given size",
	"rb", " oldbase @ newbase", "rebase all flags, bin.info, breakpoints and analysis",
	"reset" ,"", "reset console settings (clear --hard)",
	"rh" ,"", "show size in human format",
	"rj", "", "display the file size in JSON format",
	"rm" ," [file]", "remove file",
	"rmrf", " [file|dir]", "recursive remove",
	"rx", "", "display file size in hexadecimal",
//
	"r2" ," [file]", "launch r2 (same for rax2, rasm2, ...)",
	"r2pm", " [...]", "run r2pm's main",
	"rabin2", " [...]", "run rabin2's main",
	"radare2", " [...]", "run radare2's main",
	"radiff2", " [...]", "run radiff2's main",
	"rafind2", " [...]", "run rafind2's main",
	"rahash2", " [...]", "run rahash2's main",
	"rasm2", " [...]", "run rasm2's main",
	"ravc2", " [...]", "run ravc2's main",
	"rax2", " [...]", "run rax2's main",
	NULL
};

static const RCoreHelpMessage help_msg_u = {
	"Usage:", "u", "uname or undo write/seek",
	"u", "", "show system uname (alias for uname)",
	"uw", "", "alias for wc (requires: e io.cache=true)",
	"us", "", "alias for s- (seek history)",
	"uc", "[?]", "undo core commands (uc?, ucl, uc*, ..) (see `e cmd.undo`)",
	"uid", "", "display numeric user id",
	"uniq", "", "filter rows to avoid duplicates",
	"uname", "[?]", "uname - show system information",
	NULL
};

static const RCoreHelpMessage help_msg_uname = {
	"Usage:", "uname", "show information about the current system",
	"uname", "", "show host operating system",
	"uname", " -a", "show more system details",
	"uname", " -j", "show uname information in JSON",
	"uname", " -b", "show machine cpu register bits size",
	"uname", " -m", "show machine cpu architecture name",
	"uname", " -r", "show operating system version",
	NULL
};

static const RCoreHelpMessage help_msg_uc = {
	"Usage:", "uc [cmd],[revert-cmd]", "undo core commands (see `e cmd.undo`)",
	"uc", " w hello,w world", "add a new undo command manually",
	"uc", "", "list all core undos commands",
	"uc*", "", "list all core undos as r2 commands",
	"ucu", "", "up : undo previous action",
	"ucd", "", "down : redo action",
	"uc-", "", "undo last action",
	"uc.", "", "list all reverts in current",
	NULL
};

static const RCoreHelpMessage help_msg_triple_exclamation = {
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

static const RCoreHelpMessage help_msg_vertical_bar = {
	"Usage:", "[cmd] | [program|H|T|.|]", "",
	"|", " [program]", "pipe output of command to program",
	"|", "", "disable scr.html and scr.color",
	"|.", "", "alias for .[cmd]",
	"|?", "", "show this help",
	"|H", "", "enable scr.html, respect scr.color",
	"|J", "", "same as j:cmd",
	"|E", "", "base64 encode the output of the command",
	"|D", "", "decode the output of the command as base64",
	"|T", "", "use scr.tts to speak out the stdout",
	NULL
};

static const RCoreHelpMessage help_msg_v = {
	"Usage:", "v[*i]", "",
	"v", "", "open visual panels",
	"v", " test", "load saved layout with name test",
	"ve", " [fg] [bg]", "define foreground and background for current panel",
	"v.", " [file]", "load visual script (also known as slides)",
	"v=", " test", "save current layout with name test",
	"vi", " test", "open the file test in 'cfg.editor'",
	NULL
};

R_API void r_core_cmd_help(const RCore *core, RCoreHelpMessage help) {
	r_cons_cmd_help (core->cons, help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

R_API void r_core_cmd_help_json(const RCore *core, RCoreHelpMessage help) {
	r_cons_cmd_help_json (core->cons, help);
}

R_API void r_core_cmd_help_match(const RCore *core, RCoreHelpMessage help, R_BORROW char * R_NONNULL cmd) {
	r_cons_cmd_help_match (core->cons, help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, 0, true);
}

R_API void r_core_cmd_help_contains(const RCore *core, RCoreHelpMessage help, R_BORROW char * R_NONNULL cmd) {
	r_cons_cmd_help_match (core->cons, help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, 0, false);
}

R_API void r_core_cmd_help_match_spec(const RCore *core, RCoreHelpMessage help, R_BORROW char * R_NONNULL cmd, char spec) {
	r_cons_cmd_help_match (core->cons, help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, spec, true);
}

R_API void r_core_cmd_help_contains_spec(const RCore *core, RCoreHelpMessage help, R_BORROW char * R_NONNULL cmd, char spec) {
	r_cons_cmd_help_match (core->cons, help, core->print->flags & R_PRINT_FLAGS_COLOR, cmd, spec, false);
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
		r_cons_newline (core->cons);
	}
	return !r_cons_is_breaked (core->cons);
}

static void recursive_help(RCore *core, int detail, const char *cmd_prefix) {
// eprintf ("JAJ %s %d\n", cmd_prefix, core->cons->context->buffer_len);

	if (R_STR_ISEMPTY (cmd_prefix)) {
		recursive_help (core, detail, "%");
		recursive_help (core, detail, "(");
		recursive_help (core, detail, "@");
		recursive_help (core, detail, "'?'");
		recursive_help (core, detail, "!");
		recursive_help (core, detail, "=");
		recursive_help (core, detail, "??");
		recursive_help (core, detail, "~");
		recursive_help (core, detail, "$?");
		recursive_help (core, detail, "?$?");
	}
	if (strchr (cmd_prefix, '[')) {
		R_LOG_WARN ("Invalid char in command, help message must be fixed: %s", cmd_prefix);
		return;
	}
	R_LOG_DEBUG ("[recursive help] %s", cmd_prefix);
// eprintf ("ejej %s\n", cmd_prefix);
	char *s = r_core_cmd_strf (core, "%s?", cmd_prefix);
// eprintf ("eqeq %s\n", s);
	if (R_STR_ISEMPTY (s)) {
		free (s);
		return;
	}
	RList *pending = r_list_newf (free);
	r_kons_print (core->cons, s);
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
	if (!core->lastcmd || core->cur_cmd_depth < 1) {
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
				r_core_cmd_callf (core, "so %s", r_str_trim_head_ro (core->lastcmd + 3));
			} else {
				r_core_cmd0 (core, "so `pi~?`");
			}
		} else {
			if (next) {
				r_core_seek (core, core->addr + core->blocksize, true);
			} else {
				if (core->blocksize > core->addr) {
					r_core_seek (core, 0, true);
				} else {
					r_core_seek (core, core->addr - core->blocksize, true);
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
static bool print_aliases(void *use_b64, const void *key, const void *val) {
	RCons *cons = r_cons_singleton ();
	const char *k = (char *) key;
	RCmdAliasVal *v = (RCmdAliasVal *) val;
	bool base64 = *(bool *)use_b64;
	if (v->is_str) {
		r_kons_printf (cons, "$%s=%s\n", k, (char *)v->data);
	} else {
		char *val_str = base64
			? r_cmd_alias_val_strdup_b64 (v)
			: r_cmd_alias_val_strdup (v);
		r_kons_printf (cons, "$%s=%s%s\n", k, base64? "base64:": "", val_str);
		free (val_str);
	}
	return true;
}

static int cmd_uname(void *data, const char *input) { // "uniq"
	RCore *core = (RCore *)(data);
	if (strstr (input, "-h") || strstr (input, "?")) {
		r_core_cmd_help (data, help_msg_uname);
		return 0;
	}
	RSysInfo *si = r_sys_info ();
	if (si) {
		const int sysbits = R_SYS_BITS_CHECK (R_SYS_BITS, 64)? 64: 32;
		if (strstr (input, "-a")) {
			r_kons_printf (core->cons, "%s %s %s-%d", si->sysname, si->release,
				R_SYS_ARCH, sysbits);
		} else if (strstr (input, "-j")) {
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			pj_ks (pj, "platform", si->sysname);
			pj_ks (pj, "arch", R_SYS_ARCH);
			pj_kn (pj, "bits", sysbits);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_kons_printf (core->cons, "%s", s);
			free (s);
		} else if (strstr (input, "-m")) {
			r_kons_printf (core->cons, "%s", R_SYS_ARCH);
		} else if (strstr (input, "-b")) {
			r_kons_printf (core->cons, "%d", sysbits);
		} else {
			r_kons_printf (core->cons, "%s", si->sysname);
			if (strstr (input, "-r")) {
				r_kons_printf (core->cons, " %s", si->release);
			}
		}
		r_cons_newline (core->cons);
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
		r_core_cmd_help_match (core, help_msg_u, "uniq");
		break;
	default: // "uniq"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmd_callf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_uniq (arg);
			if (res) {
				r_kons_print (core->cons, res);
				free (res);
			}
		}
		break;
	}
	return 0;
}

static int cmd_undo(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'c': // "uc"
		switch (input[1]) {
		case ' ': {
			char *cmd = r_str_trim_dup (input + 2);
			char *rcmd = strchr (cmd, ',');
			if (rcmd) {
				*rcmd++ = 0;
				RCoreUndo *undo = r_core_undo_new (core->addr, cmd, rcmd);
				r_core_undo_push (core, undo);
			} else {
				r_core_cmd_help_match (core, help_msg_uc, "uc");
			}
			free (cmd);
			}
			break;
		case '?': // "uc?"
			r_core_cmd_help (core, help_msg_uc);
			break;
		case '.': { // "uc."
			RCoreUndoCondition cond = {
				.addr = core->addr,
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
		case 'u': // "ucu"
			r_core_undo_up (core);
			break;
		case 'd': // "ucd"
			r_config_set_b (core->config, "cmd.undo", false);
			r_core_undo_down (core);
			r_config_set_b (core->config, "cmd.undo", true);
			break;
		default:
			r_core_undo_print (core, 0, NULL);
			break;
		}
		return 1;
	case 'i': // "ui"
		r_kons_printf (core->cons, "%d\n", r_sys_uid ());
		return 1;
	case 's': // "us"
		r_core_cmdf (data, "s-%s", input + 1);
		return 1;
	case 'w': // "uw"
		r_core_cmdf (data, "wc%s", input + 1);
		return 1;
	case 0:
	case ' ':
		(void)cmd_uname (core, input);
		return 1;
	case 'n': // "un"
		if (input[1] == 'a') { // "uname"
			(void)cmd_uname (core, input);
		} else if (input[1] == 'i' && input[2] == 'q') {
			(void)cmd_uniq (core, input);
		} else {
			r_core_cmd_help (data, help_msg_uname);
		}
		return 1;
	case '?': // "u?"
		if (*input && input[1] == 'j') {
			r_core_cmd_help_json (core, help_msg_u);
		} else {
			r_core_cmd_help (data, help_msg_u);
		}
		return 1;
	default:
		r_core_return_invalid_command (core, "u", *input);
		return 1;
	}
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
		R_LOG_ERROR ("No alias name given");
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
				at = r_num_get (core->num, buf) + at;
				r_flag_set (core->flags, buf, at, 1);
				return 1;
			case '-':
				at = r_num_get (core->num, buf) - at;
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
						n = r_cons_editor (core->cons, NULL, v_str);
						free (v_str);
					} else {
						n = r_cons_editor (core->cons, NULL, NULL);
					}

					if (n) {
						int l = r_str_unescape (n);
						r_cmd_alias_set_raw (core->rcmd, buf, (ut8 *)n, l);
						free (n);
					}
				} else if (*def == '$') {
					char *s = strdup (def + 1);
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
								R_LOG_ERROR ("Invalid base64 string");
							}
							free (decoded);
						}
					} else {
						R_LOG_ERROR ("Invalid base64 string");
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
			r_cons_println (core->cons, (char *)v->data);
			r_cons_flush (core->cons);
			free (buf);
			return 1;
		} else if (v) {
			R_LOG_ERROR ("Alias \"$%s\" is not a command", buf);
		} else {
			R_LOG_ERROR ("No such alias \"$%s\"", buf);
		}
	} else if (*buf == '*') {
		bool use_b64 = (buf[1] == '*');
		ht_pp_foreach (core->rcmd->aliases, print_aliases, &use_b64);
	} else if (!*buf) {
		char **keys = (char **)r_cmd_alias_keys (core->rcmd);
		if (keys) {
			int i;
			const int count = core->rcmd->aliases->count;
			for (i = 0; i < count; i++) {
				r_kons_printf (core->cons, "$%s\n", keys[i]);
			}
			free (keys);
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
				if (v_str) {
					r_kons_print (core->cons, v_str);
					r_cons_newline (core->cons);
					free (v_str);
				}
			} else if (q) {
				char *out = r_str_newf ("%s %s", (char *)v->data, q + 1);
				r_core_cmd0 (core, out);
				free (out);
			} else {
				r_core_cmd0 (core, (char *)v->data);
			}
			r_core_return_value (core, 0);
		} else {
			R_LOG_ERROR ("No such alias \"$%s\"", buf);
			r_core_return_value (core, 1);
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
		r_core_cmd_help_match (core, help_msg_equal, "=r");
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
		void *bed = r_cons_sleep_begin (core->cons);
		r_cons_break_push (core->cons, NULL, NULL);
		for (;;) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			r_socket_printf (s, "[0x%08"PFMT64x"]> ", core->addr);
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
		r_cons_break_pop (core->cons);
		r_cons_sleep_end (core->cons, bed);
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
	char *ptr = strchr (input, ' ');
	if (!ptr) {
		r_core_rtr_cmds (core, input);
		return;
	}
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
		r_kons_print (core->cons, rbuf);
		free (rbuf);
	}
}

static void session_stop(RCore *core) {
	if (core->http_up) {
		r_core_rtr_http_stop (core);
	} else {
		R_LOG_INFO ("Nothing to do");
	}
}

static void session_listen(RCore *core) {
	if (core->http_up) {
		R_LOG_ERROR ("Daemon already running");
		return;
	}
	const int minport = r_config_get_i (core->config, "http.port");
	const int maxport = r_config_get_i (core->config, "http.maxport");
	if (minport >= maxport) {
		R_LOG_ERROR ("minport >= maxport");
		return;
	}
	int port = minport + r_num_rand (maxport - minport);
	r_strf_var (sport, 80, "%d", port);
	r_config_set (core->config, "http.port", sport);
	r_config_set_b (core->config, "http.sandbox", false);
	int pid = r_sys_getpid ();
	char *tmpdir = r_file_tmpdir ();
	char *tmpdir_r2 = r_str_newf ("%s/r2", tmpdir);
	r_sys_mkdir (tmpdir_r2);
	char *fn = r_str_newf ("%s/%d.pid", tmpdir_r2, pid);
	char *s = r_str_newf ("r2web://127.0.0.1:%d/cmd", port);
	if (r_file_dump (fn, (const ut8*)s, strlen (s), false)) {
		r_core_cmd0 (core, "=h&");
	} else {
		R_LOG_ERROR ("Cannot create socket file %s", s);
	}
	free (s);
	free (fn);
	free (tmpdir_r2);
	free (tmpdir);
}

static void session_list(RCore *core, int mode) {
	char *tmpdir = r_file_tmpdir ();
	char *tmpdir_r2 = r_str_newf ("%s/r2", tmpdir);
	char *file;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	RListIter *iter;
	RList *files = r_sys_dir (tmpdir_r2);
	r_list_foreach (files, iter, file) {
		if (r_str_endswith (file, ".pid")) {
			char *ffn = r_str_newf ("%s/%s", tmpdir_r2, file);
			// TODO: curl to get filename or session name via "/cmd/k%20name"
			char *data = r_file_slurp (ffn, NULL);
			int fpid = atoi (file);
			if (data) {
				bool show = true;
#if R2__UNIX__ && !__wasi__
				if (kill (fpid, 0)) {
					r_file_rm (ffn);
					show = false;
				}
#endif
				if (show) {
					if (pj) {
						pj_o (pj);
						pj_ks (pj, "uri", data);
						pj_kn (pj, "pid", fpid);
						pj_end (pj);
					} else {
						r_kons_printf (core->cons, "r2 %s # pid %d\n", data, fpid);
					}
				}
			}
			free (ffn);
		}
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	}
	r_list_free (files);
	free (tmpdir_r2);
	free (tmpdir);
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0': // "="
	case 'j': // "=j"
	case '*': // "=*"
		r_core_rtr_list (core, *input);
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
	case 'l': // "=l"
		switch (input[1]) {
		case ' ': // "=l " - set session name here
			r_core_cmdf (core, "k name=%s", r_str_trim_head_ro (input + 2));
			break;
		case 0: // "=l"
			session_list (core, 0);
			break;
		case 'j': // "=lj"
			session_list (core, 'j');
			break;
		case 'l': // "=ll"
			session_listen (core);
			break;
		case '-': // "=l-"
			session_stop (core);
			break;
		case '?': // "=l?"
			r_core_cmd_help (core, help_msg_equal_l);
			break;
		default:
			r_core_return_invalid_command (core, "=l", input[1]);
			break;
		}
		break;
	case '!': // "=!"
		if (input[1] == 'q') {
			R_FREE (core->cmdremote);
		} else if (input[1] == '=') { // =!= or =!= for iosystem
			R_FREE (core->cmdremote);
			core->cmdremote = r_str_trim_dup (input + 2);
		} else {
			char *res = r_io_system (core->io, input + 1);
			if (res) {
				r_kons_printf (core->cons, "%s\n", res);
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

static int cmd_iosys(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == ':') {
		char *s = r_core_cmd_str_r (core, r_str_trim_head_ro (input + 1));
		if (s) {
			r_str_trim_tail (s);
			r_kons_printf (core->cons, "%s\n", s);
			free (s);
		}
		return 0;
	}
	char *res = r_io_system (core->io, input);
	if (res) {
		r_str_trim (res);
		int ret = 0;
		if (*res) {
			ret = atoi (res);
			r_kons_printf (core->cons, "%s\n", res);
		}
		free (res);
		r_core_return_value (core, ret);
		return ret;
	}
	return false;
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
		if (r_str_startswith (firstLine, "#!/")) {
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
	R_RETURN_VAL_IF_FAIL (core && file, false);
	bool ret = false;
	RListIter *iter;
	RLangPlugin *p;
	char *name;

	r_list_foreach (core->scriptstack, iter, name) {
		if (!strcmp (file, name)) {
			R_LOG_WARN ("ignored nested source: %s", file);
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
	} else if (r_str_endswith (file, ".pk")) {
		r_core_cmdf (core, "'poke -f %s", file);
		ret = true;
	} else if (r_str_endswith (file, ".html")) {
		const bool httpSandbox = r_config_get_b (core->config, "http.sandbox");
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
		r_core_cmdf (core, "#!c %s", file);
		ret = true;
	} else if (r_file_is_c (file)) { // ".h" ".cparse"
		const char *dir = r_config_get (core->config, "dir.types");
		char *out = r_anal_cparse_file (core->anal, file, dir, NULL);
		if (out) {
			ret = true;
			r_kons_print (core->cons, out);
			sdb_query_lines (core->anal->sdb_types, out);
			free (out);
		}
	} else {
		p = r_lang_get_by_extension (core->lang, file);
		if (p) {
			r_lang_use (core->lang, p->meta.name);
			ret = lang_run_file (core, core->lang, file);
		} else {
// XXX this is an ugly hack, we need to use execve here and specify args properly
#if R2__WINDOWS__
#define cmdstr(x) r_str_newf (x" %s", file);
#else
#define cmdstr(x) r_str_newf (x" '%s'", file);
#endif
			const char *ext = r_file_extension (file);
			if (ext) {
				/* TODO: handle this inside r_lang_pipe with new APIs */
				if (!strcmp (ext, "js")) {
					if (r_str_endswith (file, ".r2.js")) {
						if (r_lang_use (core->lang, "qjs")) {
							ret = r_lang_run_file (core->lang, file);
						} else {
							R_LOG_ERROR ("Cannot instantiate the quickjs runtime");
							ret = false;
						}
					} else {
						char *cmd = cmdstr ("node");
						r_lang_use (core->lang, "pipe");
						lang_run_file (core, core->lang, cmd);
						free (cmd);
						ret = true;
					}
				} else if (!strcmp (ext, "exe")) {
#if R2__WINDOWS__
					char *cmd = r_str_newf ("%s", file);
#else
					char *cmd = cmdstr ("wine");
#endif
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "rexx")) {
					r_lang_use (core->lang, "pipe");
					char *cmd = cmdstr ("rexx");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "zig")) {
					char *cmd = cmdstr ("zig run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "d")) {
					char *cmd = cmdstr ("dmd -run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "lsp")) {
					char *cmd = cmdstr ("newlisp -n");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "go")) {
					char *cmd = cmdstr ("go run");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "es6")) {
					char *cmd = cmdstr ("babel-node");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "rb")) {
					char *cmd = cmdstr ("ruby");
					r_lang_use (core->lang, "pipe");
					lang_run_file (core, core->lang, cmd);
					free (cmd);
					ret = true;
				} else if (!strcmp (ext, "nim")) {
					r_lang_use (core->lang, "nim");
					lang_run_file (core, core->lang, file);
					ret = true;
				} else if (!strcmp (ext, "vala")) {
					r_lang_use (core->lang, "vala");
					lang_run_file (core, core->lang, file);
					ret = true;
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
					ret = true;
				} else if (!strcmp (ext, "r2s")) {
					r_core_visual_slides (core, file);
					ret = true;
				} else if (!strcmp (ext, "qjs")) {
					if (r_lang_use (core->lang, "qjs")) {
						ret = r_lang_run_file (core->lang, file);
					} else {
						R_LOG_ERROR ("Cannot instantiate the quickjs runtime");
						ret = false;
					}
				} else if (!strcmp (ext, "wren")) {
					if (r_lang_use (core->lang, "wren")) {
						ret = r_lang_run_file (core->lang, file);
					} else {
						R_LOG_ERROR ("r2pm -ci rlang-wren");
						ret = false;
					}
				} else if (!strcmp (ext, "tiny")) {
					if (r_lang_use (core->lang, "tiny")) {
						ret = r_lang_run_file (core->lang, file);
					} else {
						R_LOG_ERROR ("r2pm -ci rlang-tiny");
						ret = false;
					}
				} else if (!strcmp (ext, "pl")) {
					char *cmd = cmdstr ("perl");
					r_lang_use (core->lang, "pipe");
					ret = lang_run_file (core, core->lang, cmd);
					free (cmd);
				} else if (!strcmp (ext, "py")) {
					static const char *python_bins[] = {
						"python3",
						"python",
						"python2",
						NULL
					};
					const char *bin;
					char *bin_path;
					int i;
					for (i = 0; python_bins[i]; i++) {
						bin = python_bins[i];
						bin_path = r_file_path (bin);
						if (bin_path) {
							break;
						}
						free (bin_path);
					}

					if (bin_path) {
#if R2__WINDOWS__
						char *cmd = r_str_newf ("%s %s", bin_path, file);
#else
						char *cmd = r_str_newf ("%s '%s'", bin_path, file);
#endif
						r_lang_use (core->lang, "pipe");
						ret = lang_run_file (core, core->lang, cmd);
						free (cmd);
						free (bin_path);
					} else {
						R_LOG_ERROR ("Cannot find python in PATH");
						ret = false;
					}
				} else {
					if (r_file_is_executable (file)) {
						r_core_cmdf (core, "#!pipe %s%s", (*file == '/')?"":"./", file);
						ret = true;
					} else {
						ret = r_core_cmd_file (core, file);
					}
				}
			} else {
				char *lang = langFromHashbang (core, file);
				if (lang) {
					r_lang_use (core->lang, "pipe");
					char *cmd = r_str_newf ("%s '%s'", lang, file);
					lang_run_file (core, core->lang, cmd);
					free (lang);
					free (cmd);
					ret = true;
				} else {
					if (r_file_is_executable (file)) {
						r_core_cmdf (core, "#!pipe %s%s", (*file == '/')?"":"./", file);
						ret = true;
					}
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

static int cmd_lr(RCore *core, const char *input) { // "lr"
	const char *path;
	RListIter *iter;
	const char *arg = R_STR_ISEMPTY (input)? ".": input;
	RList *files = r_file_lsrf (arg);
	if (!files) {
		R_LOG_ERROR ("Failed to read directories");
		return 0;
	}
	r_list_sort (files, (RListComparator)strcmp);
	r_list_foreach (files, iter, path) {
		r_cons_println (core->cons, path);
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
			r_core_cmd_help_match (core, help_msg_l, "ll");
			break;
		}
		{
			char *carg = r_str_newf ("-l %s", arg);
			int w = r_cons_get_size (core->cons, NULL) - 8;
			char *res = r_syscmd_ls (carg, w);
			if (res) {
				r_kons_print (core->cons, res);
				free (res);
			}
			free (carg);
		}
		break;
	case 'e': // "le"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "le");
			break;
		}

		if (*arg) {
			r_core_cmdf (core, "cat %s~..", arg);
		} else {
			r_core_cmd_help_match (core, help_msg_l, "le");
		}
		break;
	case 'i': // "li"
		r_core_cmd0 (core, "CLL@@c:afbo");
		break;
	case 'r': // "lr"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "lr");
			break;
		}
		cmd_lr (core, arg);
		break;
	case 'u': // "lu"(a) - short for #!lua
		{
			const char *arg = strchr (input, ' ');
			if (arg) {
				char *cmd = r_str_newf ("#!lua %s", r_str_trim_head_ro (arg + 1));
				r_core_cmd0 (core, cmd);
				free (cmd);
			} else {
				r_core_cmd0 (core, "#!lua");
			}
		}
		break;
	case 's': // "ls"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_l, "ls");
			break;
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			int w = r_cons_get_size (core->cons, NULL) - 8;
			char *res = r_syscmd_ls (arg, w);
			if (res) {
				r_kons_print (core->cons, res);
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

#include "../../shlr/qjs/js_repl.c"

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
	const char *arg2 = end + 1;
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
				r_kons_print (core->cons, res);
				free (res);
			}
		}
		break;
	}
	free (tmp);
	return R_CMD_RC_SUCCESS;
beach:
	r_core_cmd_help (core, help_msg_j);
	free (tmp);
	return R_CMD_RC_SUCCESS;
}

static int cmd_j(void *data, const char *input) { // "j"
	RCore *core = (RCore *)data;
	if (r_str_startswith (input, "oin")) {
		return cmd_join (data, input);
	}
	if (r_str_startswith (input, "i:")) {
		char *res = r_core_cmd_str (core, input + 2);
		char *indented = r_print_json_indent (res, true, "  ", NULL);
		r_kons_printf (core->cons, "%s\n", indented);
		free (indented);
		free (res);
		return R_CMD_RC_SUCCESS;
	}
	if (input[0] == 'q') { // "jq"
		r_core_cmd_callf (core, "!jq%s", input + 1);
		return R_CMD_RC_SUCCESS;
	}
	if (input[0] == 's') { // "js"
		if (input[1] == ':' || input[1] == '.') { // "js:"
			if (input[2]) {
				if (r_lang_use (core->lang, "qjs")) {
					const char *fn = r_str_trim_head_ro (input + 2);
					if (!r_lang_run_file (core->lang, fn)) {
						R_LOG_ERROR ("Cannot find %s", fn);
					}
				}
			} else {
				if (r_config_get_b (core->config, "scr.interactive")) {
					if (r_lang_use (core->lang, "qjs")) {
						r_lang_run (core->lang, js_repl_qjs, strlen (js_repl_qjs));
					} else {
						R_LOG_ERROR ("Requires lang.qjs");
					}
				} else {
					R_LOG_ERROR ("Requires scr.interactive");
				}
			}
		} else if (input[1] == '!') { // "js!"
			r_lang_setup (core->lang);
		} else if (input[1] == '-') { // "js-"
			if (r_config_get_b (core->config, "scr.interactive")) {
				int sz;
				char *data = r_stdin_slurp (&sz);
				if (data) {
					char *code = r_str_newf ("(function() { %s })()", data);
					if (r_lang_use (core->lang, "qjs")) {
						r_lang_run (core->lang, code, sz);
					} else {
						R_LOG_ERROR ("Requires mujs");
					}
					free (code);
					free (data);
				}
			} else {
				R_LOG_ERROR ("requires scr.interactive");
			}
		} else if (input[1] == ' ') { // "js "
			if (r_lang_use (core->lang, "qjs")) {
				const char *arg = r_str_trim_head_ro (input + 1);
				if (r_str_startswith (arg, "base64:")) {
					char *script = (char *)r_base64_decode_dyn (arg + 7, -1, NULL);
					if (script) {
						r_lang_run (core->lang, script, -1);
						free (script);
					}
				} else {
					r_lang_run (core->lang, input + 1, -1);
				}
			} else {
				r_core_cmdf (core, "#!pipe node -e '%s'", input + 1);
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_j, "js");
		}
		return R_CMD_RC_SUCCESS;
	}
	if (input[0] == ':') {
		PJ *pj = r_core_pj_new (core);
		// buffer rlog calls into a string
		char *s = r_core_cmd_str (core, input + 1);
		pj_o (pj);
		pj_ks (pj, "command", input + 1);
		pj_ks (pj, "output", s);
		pj_ki (pj, "offset", core->addr);
		pj_ki (pj, "blocksize", core->blocksize);
		pj_ks (pj, "log", ""); // TODO: use r_log api here
		pj_ki (pj, "rc", core->rc); // XXX always 0?
		pj_ki (pj, "value", core->num->value);
		pj_end (pj);
		free (s);
		s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
		return R_CMD_RC_SUCCESS;
	}
	return R_CMD_RC_FASTQUIT;
}

static int cmd_plus(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (*input) {
		r_core_cmdf (core, "s+%s", r_str_trim_head_ro (input));
	} else {
		r_core_cmd_help (core, help_msg_plus);
	}
	return 0;
}

static int cmd_stdin(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (*input) {
		const char *arg = r_str_trim_head_ro (input + 1);
		switch (*input) {
		case '?': // "-?"
		case 'h': // "-h"
			r_core_cmd_help (core, help_msg_dash);
			break;
		case 'v': // "-v"
		case 'V': // "-V"
			if (input[1] == 'j') {
				r_core_cmd_call (core, "?Vj");
			} else {
				r_core_cmd_call (core, "?V");
			}
			break;
		case 'L': // "-L"
			if (input[1]) {
				r_core_cmd_callf (core, "L%c", input[1]);
			} else {
				r_core_cmd_call (core, "Lo");
			}
			break;
		case 'P': // "-P"
			{
				const char *patchfile = r_str_trim_head_ro (input + 1);
				char *data = r_file_slurp (patchfile, NULL);
				if (data) {
					int ret = r_core_patch (core, data);
					if (ret != 0) {
						R_LOG_ERROR ("Cannot apply patch");
					}
					free (data);
				} else {
					R_LOG_ERROR ("Cannot open '%s'", patchfile);
				}
			}
			break;
		case 'p': // "-p"
			if (input[1]) {
				r_core_cmd_callf (core, "P %s", r_str_trim_head_ro (input + 1));
			} else {
				r_core_cmd_call (core, "P");
			}
			break;
		case 'H': // "-H"
			r_core_cmd_callf (core, "r2 -H%s", input + 1);
			break;
		case 'D': // "-a"
			r_core_cmd_callf (core, "iD%s", input + 1);
			break;
		case 'a': // "-a"
			if (R_STR_ISEMPTY (arg)) {
				const char *arch = r_config_get (core->config, "asm.arch");
				r_kons_printf (core->cons, "%s\n", arch);
			} else {
				if (r_config_set (core->config, "asm.arch", arg)) {
					r_config_set (core->config, "anal.arch", arg);
				}
			}
			break;
		case 'i': // "-i"
			r_core_cmdf (core, ". %s", arg);
			break;
		case 's': // "-s"
			r_core_cmdf (core, "'s %s", arg);
			break;
		case 'f': // "-f"
			r_core_cmd0 (core, "b $s");
			break;
		case 'b': // "-b"
			if (R_STR_ISEMPTY (arg)) {
				const int bits = r_config_get_i (core->config, "asm.bits");
				r_kons_printf (core->cons, "%d\n", bits);
			} else {
				r_config_set_i (core->config, "asm.bits", r_num_math (core->num, arg));
			}
			break;
		case 'j': // "-j"
			r_core_cmd_call (core, "js:");
			break;
		case 'c': // "-c"
			r_core_cmdf (core, "e asm.cpu=%s", arg);
			break;
		case 'k': // "-k"
			if (R_STR_ISEMPTY (arg)) {
				const char *os = r_config_get (core->config, "asm.os");
				r_kons_printf (core->cons, "%s\n", os);
			} else {
				r_config_set (core->config, "asm.os", arg);
			}
			break;
		case 'e': // "-e"
			if (*arg == '?') {
				r_core_cmd_call (core, "e");
			} else {
				r_core_cmdf (core, "e %s", arg);
			}
			break;
		case 'A': // -A
			if (*arg == '?') {
				r_core_cmd_call (core, "aaa?");
			} else {
				if (R_STR_ISEMPTY (arg)) {
					r_core_cmd_call (core, "aaa");
				} else if (!strcmp (arg, "A")) {
					r_core_cmd_call (core, "aaaa");
				} else if (!strcmp (arg, "AA")) {
					r_core_cmd_call (core, "aaaaa");
				} else {
					r_core_cmd_call (core, "aaa?");
				}
			}
			break;
		default:
			if (isdigit (*input)) {
				r_core_cmdf (core, "s-%s", r_str_trim_head_ro (input));
			} else {
				r_core_cmd_help (core, help_msg_dash);
			}
			break;
		}
		return 0;
	}
	return r_core_run_script (core, "-");
}

static void load_table_json(RCore *core, RTable *t, char *data) {
	// parse json file and iterate over all the entries
	// RTableRow *row = r_table_row_new (items);
	// r_list_append (t->rows, row);
	R_LOG_TODO ("Loading tables from JSON is not yet implemented");
}

static const char *get_type_string(const char *s) {
	if (r_str_startswith (s, "0x")) {
		return "x";
	}
	if (*s == '0' || isdigit (s[1])) {
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
				R_LOG_WARN ("Not re-adding headers. Use ,- to reset the table");
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
	R_RETURN_IF_FAIL (core && t && data);
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

static void display_table(RCore *core, char *ts) {
	if (ts) {
		r_cons_println (core->cons, ts);
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
		core->table = r_core_table_new (core, "header");
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
	R_RETURN_VAL_IF_FAIL (core && input, false);
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
		core->table = r_core_table_new (core, "table");
	}
	switch (*input) {
	case 'h': // table header columns
	case 'c': // table columns
		cmd_table_header (core, r_str_trim_dup (input + 1));
		break;
	case 'r': // add row
		{
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
		core->table = r_core_table_new (core, "table");
		break;
	case '/':
		// query here
		{
			RTable *ot = r_table_clone (core->table);
			if (display_table_filter (core, input)) {
				display_table (core, r_table_tostring (core->table));
			}
			r_table_free (core->table);
			core->table = ot;
		}
		break;
	case '.': // ",."
		if (R_STR_ISEMPTY (input + 1)) {
			r_core_cmd_help_match (core, help_msg_comma, ",.");
		} else {
			const char *file = r_str_trim_head_ro (input + 1);
			if (*file == '$' && !file[1]) {
				R_LOG_ERROR ("No alias name given");
			} else if (*file == '$') {
				RCmdAliasVal *file_data = r_cmd_alias_get (core->rcmd, file + 1);
				if (file_data) {
					char *file_data_str = r_cmd_alias_val_strdup (file_data);
					load_table (core, core->table, strdup (file_data_str));
					free (file_data_str);
				} else {
					R_LOG_ERROR ("No such alias '$%s'", file+1);
				}
			} else {
				char *file_data = r_file_slurp (file, NULL);
				if (file_data) {
					load_table (core, core->table, file_data);
				} else {
					R_LOG_ERROR ("Cannot open file");
				}
			}
		}
		break;
	case ' ':
		if (display_table_filter (core, input)) {
			display_table (core, r_table_tostring (core->table));
		}
		break;
	case ',':
		if (display_table_filter (core, input)) {
			display_table (core, r_table_tocsv (core->table));
		}
		break;
	case '*':
		if (display_table_filter (core, input)) {
			display_table (core, r_table_tor2cmds (core->table));
		}
		break;
	case 'j':
		if (display_table_filter (core, input)) {
			display_table (core, r_table_tojson (core->table));
		}
		break;
	case 0:
		if (core->table) {
			display_table (core, r_table_tostring (core->table));
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_comma);
		r_kons_printf (core->cons, "%s\n", r_table_help ());
		break;
	default:
		r_core_cmd_help (core, help_msg_comma);
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
				r_kons_print (core->cons, rbuf);
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
			r_core_cmd_help_match (core, help_msg_dot, ".-");
		} else {
			r_core_run_script (core, "-");
		}
		break;
	case ' ': // ". "
		{
			const char *script_file = r_str_trim_head_ro (input + 1);
			if (*script_file == '$' && !script_file[1]) {
				R_LOG_ERROR ("No alias name given");
			} else if (*script_file == '$') {
				RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, script_file + 1);
				if (v) {
					char *cmd_text = r_cmd_alias_val_strdup (v);
					r_core_cmd0 (core, cmd_text);
					free (cmd_text);
				} else {
					R_LOG_ERROR ("No such alias \"$%s\"", script_file+1);
				}
			} else {
				if (!r_core_run_script (core, script_file)) {
					R_LOG_ERROR ("Cannot find script '%s'", script_file);
					r_core_return_value (core, R_CMD_RC_FAILURE);
				} else {
					r_core_return_value (core, R_CMD_RC_SUCCESS);
				}
			}
		}
		break;
	case '!': // ".!"
		r_core_cmd_command (core, r_str_trim_head_ro (input + 1));
		break;
	case '(': // ".("
		if (input[1] == '*') {
			goto bypass;
		}
		r_cmd_macro_call (&core->rcmd->macro, input + 1);
		break;
	default:
		if (*input >= 0 && *input <= 9) {
			R_LOG_ERROR ("No .[0..9] to avoid infinite loops");
			break;
		}
bypass:
		inp = strdup (input);
		filter = strchr (inp, '~');
		if (filter) {
			*filter = 0;
		}
		int tmp_html = core->cons->context->is_html;
		core->cons->context->is_html = false;
		ptr = str = r_core_cmd_str (core, inp);
		core->cons->context->is_html = tmp_html;

		if (filter) {
			*filter = '~';
		}
		r_cons_break_push (core->cons, NULL, NULL);
		if (ptr) {
			for (;;) {
				if (r_cons_is_breaked (core->cons)) {
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
		r_cons_break_pop (core->cons);
		free (str);
		free (inp);
		break;
	}
	return 0;
}

static bool callback_foreach_kv(void *user, const char *k, const char *v) {
	RCore *core = (RCore *)user;
	r_kons_printf (core->cons, "%s=%s\n", k, v);
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
			r_cons_println (core->cons, "No Output from sdb");
			break;
		}
		PJ *pj = r_core_pj_new (core);
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
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
		R_FREE (next_cmd);
		free (next_cmd);
		free (cur_cmd);
		break;
	case ' ':
		if (s) {
			out = sdb_querys (s, NULL, 0, input + 1);
			if (out) {
				r_kons_print (core->cons, out);
			}
			R_FREE (out);
		}
		break;
	//case 's': r_pair_save (s, input + 3); break;
	//case 'l': r_pair_load (sdb, input + 3); break;
	case '\0':
		sdb_foreach (s, callback_foreach_kv, core);
		break;
	// TODO: add command to list all namespaces // sdb_ns_foreach ?
	case 's': // "ks"
		if (core->http_up) {
			return false;
		}
		if (!r_cons_is_interactive (core->cons)) {
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
		}
		RList *sdb_hist = line->sdbshell_hist;
		r_line_set_hist_callback (line, &r_line_hist_sdb_up, &r_line_hist_sdb_down);
		const size_t buf_size = 1024;
		char *buf = malloc (1024);
		while (buf) {
			r_line_set_prompt (core->cons->line, p);
			*buf = 0;
			if (r_cons_fgets (core->cons, buf, buf_size, 0, NULL) < 1) {
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
				r_cons_println (core->cons, out);
				r_cons_flush (core->cons);
			}
		}
		free (buf);
		r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
		break;
	case 'o': // "ko"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("This command is disabled in sandbox mode");
			return 0;
		}
		if (input[1] == ' ') {
			char *fn = strdup (input + 2);
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
							R_LOG_ERROR ("Cannot open sdb '%s'", fn);
						}
					} else {
						R_LOG_ERROR ("Cannot find sdb '%s'", ns);
					}
				} else {
					R_LOG_ERROR ("Cannot open file");
				}
			} else {
				R_LOG_ERROR ("Missing sdb namespace");
			}
			free (fn);
		} else {
			r_core_cmd_help_match (core, help_msg_k, "ko");
		}
		break;
	case 'd': // "kd"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("The 'kd' command is disabled in sandbox mode");
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
					R_LOG_ERROR ("Cannot find sdb '%s'", ns);
				}
			} else {
				R_LOG_ERROR ("Missing sdb namespace");
			}
			free (fn);
		} else {
			r_core_cmd_help_match (core, help_msg_k, "kd");
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_k);
		break;
	default:
		r_core_return_invalid_command (core, "k", *input);
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
			r_cons_println (core->cons, out);
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
	case '6': // "b6"
		if (r_str_startswith (input, "64:")) {
			int len = 0;
			char *cmd = (char *)sdb_decode (input + 3, &len);
			if (cmd) {
				cmd[len] = 0;
				r_core_cmd_call (core, cmd);
				free (cmd);
			} else {
				R_LOG_ERROR ("Missing base64 string after b64:");
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_b, "b64:");
		}
		break;
	case 'm': // "bm"
		n = r_num_math (core->num, input + 1);
		if (n > 1) {
			core->blocksize_max = n;
		} else {
			r_kons_printf (core->cons, "0x%x\n", (ut32)core->blocksize_max);
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
				R_LOG_ERROR ("bf: cannot find flag named '%s'", input + 2);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_b, "bf");
		}
		break;
	case 'j': { // "bj"
		PJ *pj = r_core_pj_new (core);
		if (!pj) {
			break;
		}
		pj_o (pj);
		pj_ki (pj, "blocksize", core->blocksize);
		pj_ki (pj, "blocksize_limit", core->blocksize_max);
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
		break;
	}
	case '*': // "b*"
		r_kons_printf (core->cons, "b 0x%x\n", core->blocksize);
		break;
	case '\0': // "b"
		r_kons_printf (core->cons, "0x%x\n", core->blocksize);
		break;
	case '=':
	case ' ':
		r_core_block_size (core, r_num_math (core->num, input + 1));
		break;
	case '?': // "b?"
		r_core_cmd_help (core, help_msg_b);
		break;
	default:
		r_core_return_invalid_command (core, "b", *input);
		break;
	}
	return 0;
}

static int __runMain(RMainCallback cb, const char *arg) {
	char *a = r_str_trim_dup (arg);
	int argc = 0;
	char **args = r_str_argv (a, &argc);
	int res = cb? cb (argc, (const char **)args): -1;
	free (args);
	free (a);
	return res;
}

static bool cmd_r2cmd(RCore *core, const char *_input) {
	char *input = r_str_newf ("r%s", _input);
	int rc = 0;
	if (r_str_startswith (input, "rax2")) {
		rc = __runMain (core->r_main_rax2, input);
	} else if (r_str_startswith (input, "rapatch2")) {
		r_sys_cmdf ("%s", input);
		// rc = __runMain (r_main_rapatch2, input);
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
	} else if (r_str_startswith (input, "ravc2")) {
		rc = __runMain (core->r_main_ravc2, input);
	} else if (r_str_startswith (input, "r2pm")) {
		rc = __runMain (core->r_main_r2pm, input);
	} else if (r_str_startswith (input, "radiff2")) {
		rc = __runMain (core->r_main_radiff2, input);
	} else if (r_str_startswith (input, "r2.")) {
		r_core_cmdf (core, "'js console.log(r2.%s)", input + 3);
	} else if (r_str_startswith (input, "r2")) {
		if (input[2] == ' ' || input[2] == 0) {
			r_sys_cmdf ("%s", input);
		} else {
			R_LOG_ERROR ("Invalid command");
		}
		// rc = __runMain (core->r_main_radare2, input);
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
	r_core_return_value (core, rc);
	// r_core_return_code (core, rc);
	return true;
}

static int cmd_rebase(RCore *core, const char *input) {
	ut64 addr = r_num_math (core->num, input);
	if (!addr) {
		r_core_cmd_help_match (core, help_msg_r, "rb");
		return 0;
	}
	// old base = addr
	// new base = core->addr
	r_debug_bp_rebase (core->dbg, addr, core->addr);
	r_bin_set_baddr (core->bin, core->addr);
	r_flag_move (core->flags, addr, core->addr);
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
	int ret;

	if (cmd_r2cmd (core, input)) {
		return true;
	}

	ut64 oldsize = (core->io->desc) ? r_io_fd_size (core->io, core->io->desc->fd): 0;
	switch (*input) {
	case 'b': // "rb" rebase
		return cmd_rebase (core, input + 1);
	case '2': // "r2" // XXX should be handled already in cmd_r2cmd()
		if (r_str_startswith (input + 1, "ai")) {
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2yara");
			r_core_return_code (core, 1);
			return true;
		}
		// TODO: use argv[0] instead of 'radare2'
		// TODO: { char **argv = { "r2", NULL }; r_main_radare2 (1, argv); }
		r_sys_cmdf ("radare%s", input);
		return true;
	case 'm': // "rm"
		if (r_str_startswith (input, "mrf")) {
			if (input[3] == ' ')  {
				const char *file = r_str_trim_head_ro (input + 3);
				return r_file_rm_rf (file);
			}
			r_core_cmd_help_match (core, help_msg_r, "rmrf");
			return false;
		}
		if (input[1] == ' ') {
			const char *file = r_str_trim_head_ro (input + 2);
			if (*file == '$') {
				if (!r_cmd_alias_del (core->rcmd, file + 1)) {
					R_LOG_ERROR ("Cannot find alias file %s", file);
				}
			} else {
				r_file_rm (file);
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_r, "rm");
		}
		return true;
	case 'x':
		if (core->io->desc) {
			if (oldsize != -1) {
				r_kons_printf (core->cons, "0x%"PFMT64x"\n", oldsize);
			}
		}
		return true;
	case '\0':
		if (core->io->desc) {
			if (oldsize != -1) {
				r_kons_printf (core->cons, "%"PFMT64d"\n", oldsize);
			}
		}
		return true;
	case 'j': { // "rj"
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			if (oldsize != -1) {
				pj_kn (pj, "size", oldsize);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_println (core->cons, s);
			free (s);
			return true;
		}
	case 'h': // "rh"
		if (core->io->desc) {
			if (oldsize != -1) {
				char humansz[8];
				r_num_units (humansz, sizeof (humansz), oldsize);
				r_kons_printf (core->cons, "%s\n", humansz);
			}
		}
		return true;
	case '+': // "r+"
	case '-': // "r-"
		delta = (st64)r_num_math (core->num, input);
		if (delta < 0 && -(st64)delta > oldsize) {
			R_LOG_WARN ("Cannot resize below zero %lld %lld", delta, oldsize);
			r_core_return_code (core, 1);
			return true;
		}
		r_core_return_code (core, 0);
		newsize = oldsize + delta;
		break;
	case '0': // "r0"
		if (input[1] == 'x') { // "r0x"
			newsize = r_num_math (core->num, input);
			if ((st64)newsize < 1) {
				R_LOG_ERROR ("Invalid hex size");
				r_core_return_code (core, 1);
				return true;
			}
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
						r_core_return_code (core, 1);
						R_LOG_ERROR ("Invalid size");
					}
					return false;
				}
			}
		}
		break;
	case 'e': // "re"
		{
			int rc = write (1, Color_RESET_TERMINAL, strlen (Color_RESET_TERMINAL));
			if (rc == -1) {
				return false;
			}
		}
		return true;
	case '?': // "r?"
		r_core_cmd_help (core, help_msg_r);
		return true;
	default:
		r_core_return_invalid_command (core, "r", *input);
		return true;
	}

	bool grow = (newsize > oldsize);
	if (grow) {
		ret = r_io_resize (core->io, newsize);
		if (ret < 1) {
			R_LOG_ERROR ("r_io_resize: cannot resize");
			r_core_return_code (core, 1);
			return true;
		}
	}
	if (delta && core->addr < newsize) {
		r_io_shift (core->io, core->addr, grow? newsize: oldsize, delta);
	}
	if (!grow) {
		ret = r_io_resize (core->io, newsize);
		if (ret < 1) {
			R_LOG_ERROR ("cannot resize");
			r_core_return_code (core, 1);
			return true;
		}
	}
	if (newsize < (core->addr + core->blocksize) || oldsize < (core->addr + core->blocksize)) {
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
	if (!r_cons_is_interactive (core->cons)) {
		R_LOG_ERROR ("Panel mode requires scr.interactive=true");
		return false;
	}
	if (*input == ' ') {
		if (core->panels) {
			r_core_panels_load (core, input + 1);
		}
		r_config_set (core->config, "scr.layout", input + 1);
		return true;
	}
	if (*input == 'e') {
		if (input[1] == ' ') {
#define getpanel(x,y) ((x) && (y) < 16)? (x)->panel[y]: NULL
			RPanel *pan = getpanel (core->panels, core->panels->curnode);
#undef getpanel
			if (pan) {
				char *r = r_cons_pal_parse (core->cons, r_str_trim_head_ro (input + 2), NULL);
				if (r) {
					free (pan->model->bgcolor);
					pan->model->bgcolor = r_str_newf (Color_RESET"%s", r);
					free (r);
				} else {
					R_LOG_ERROR ("Invalid color %sXXX"Color_RESET, r);
				}
			}
		} else {
			r_core_cmd_help_match (core, help_msg_v, "ve");
		}
		return true;
	}
	if (*input == '=') {
		if (input[1]) {
			r_core_panels_save (core, input + 1);
			r_config_set (core->config, "scr.layout", input + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_v, "v=");
		}
		return true;
	}
	if (*input == 'i') {
		char *sp = strchr (input, ' ');
		if (sp) {
			char *r = r_core_editor (core, sp + 1, NULL);
			if (r) {
				free (r);
			} else {
				R_LOG_ERROR ("Cannot open file (%s)", sp + 1);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_v, "vi");
		}
		return false;
	}
	if (*input) {
		r_core_cmd_help (core, help_msg_v);
	} else {
		r_core_panels_root (core, core->panels_root);
	}
	return true;
}

static int cmd_visual(void *data, const char *input) {
	RCore *core = (RCore*) data;
	if (*input == '?') { // "mL?"
		r_core_cmd_help_match_spec (core, help_msg_root, "V", 0);
		return true;
	}
#if 0
	if (core->http_up) {
		return false;
	}
#endif
	if (!r_cons_is_interactive (core->cons)) {
		R_LOG_ERROR ("Visual mode requires scr.interactive=true");
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
			R_LOG_ERROR ("The &b command is disabled in sandbox mode");
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
			R_LOG_ERROR ("The && command is disabled in sandbox mode");
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
					r_cons_println (core->cons, task->res);
				}
				r_core_task_decref (task);
			} else {
				R_LOG_ERROR ("Cannot find task");
			}
		}
		break;
	}
	case '-': // "&-"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("The &- command is disabled in sandbox mode");
			return 0;
		}
		if (input[1] == '*') {
			r_core_task_del_all_done (&core->tasks);
		} else {
			r_core_task_del (&core->tasks, r_num_math (core->num, input + 1));
		}
		break;
	case '?': // "&?"
		r_core_cmd_help (core, help_msg_amper);
		break;
	case ' ': // "& "
	case '_': // "&_"
	case 't': { // "&t"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("This command is disabled in sandbox mode");
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
	default:
		r_core_return_invalid_command (core, "&", *input);
		break;
	}
	return 0;
}

static int cmd_pointer(void *data, const char *input) {
	RCore *core = (RCore*) data;
	int ret = 0;
	input = r_str_trim_head_ro (input);
	if (!*input || *input == '?') {
		r_core_cmd_help (core, help_msg_star);
		return ret;
	}
	char *str = strdup (input);
	char *eq = strchr (str, '=');
	if (eq) {
		*eq++ = 0;
		ret = r_core_cmdf (core, "wv %s@%s", eq, str);
	} else {
		ret = r_core_cmdf (core, "?v [%s]", input);
	}
	free (str);
	return ret;
}

static int cmd_env(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int ret = 1;
	switch (*input) {
	case 'j':
	case '*':
		ret = r_core_cmdf (core, "env%c", *input);
		break;
	case '?':
		cmd_help_percent (core);
		break;
	default:
		ret = r_core_cmdf (core, "env %s", input);
		break;
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
	R_LOG_ERROR ("Invalid flag '%s'", strflag);
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
	free ((void*)help);
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
			R_LOG_ERROR ("Use !!!-* or !!!-<cmd> to delete an autocompletion");
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
			R_LOG_ERROR ("Exceeded the max arg length (255)");
			return;
		}
		if (end == input) {
			break;
		}
		memcpy (arg, input, end - input);
		arg[end - input] = 0;
		RCoreAutocomplete* a = r_core_autocomplete_find (b, arg, true);
		input = r_str_trim_head_ro (end);
		if (R_STR_ISNOTEMPTY (input) && !a) {
			if (b->type == R_CORE_AUTOCMPLT_DFLT && !(b = r_core_autocomplete_add (b, arg, R_CORE_AUTOCMPLT_DFLT, false))) {
				R_LOG_ERROR ("ENOMEM");
				return;
			} else if (b->type != R_CORE_AUTOCMPLT_DFLT) {
				R_LOG_ERROR ("Cannot add autocomplete to '%s'. type not $dflt", b->cmd);
				return;
			}
		} else if (R_STR_ISEMPTY (input) && !a) {
			if (arg[0] == '$') {
				int type = autocomplete_type (arg);
				if (type != R_CORE_AUTOCMPLT_END && !b->locked && !b->n_subcmds) {
					b->type = type;
				} else if (b->locked || b->n_subcmds) {
					if (!b->cmd) {
						return;
					}
					R_LOG_ERROR ("Changing type of '%s' is forbidden", b->cmd);
				}
			} else {
				if (!r_core_autocomplete_add (b, arg, R_CORE_AUTOCMPLT_DFLT, false)) {
					R_LOG_ERROR ("ENOMEM");
					return;
				}
			}
			return;
		} else if (R_STR_ISEMPTY (input) && a) {
			R_LOG_WARN ("Cannot add '%s'. Already exists", arg);
			return;
		} else {
			b = a;
		}
	}
	R_LOG_ERROR ("Invalid usage of !!!");
}

static int cmd_last(void *user, const char *input) {
	RCore *core = (RCore *)user;
	static RCoreHelpMessage help_msg_last = {
		"_", "", "print last output",
		NULL
	};
	switch (*input) {
	case 0:
		r_cons_last (core->cons);
		break;
	default:
		r_core_cmd_help (core, help_msg_last);
	}
	return 0;
}

static bool stderr_cb(void *user, int type, const char *origin, const char *msg) {
	RList *stderr_list = (RList*)user;
	if (!msg) {
		return false;
	}
	PJ *j = pj_new ();
	pj_o (j);
	pj_ks (j, "type", r_log_level_tostring (type));
	if (origin) {
		pj_ks (j, "origin", origin);
	}
	if (msg) {
		pj_ks (j, "message", msg);
	}
	pj_end (j);
	r_list_append (stderr_list, pj_drain (j));
	return true;
}

static int cmd_json(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (*input == '?') {
		r_kons_printf (core->cons, "Usage: {\"cmd\":\"...\",\"json\":false,\"trim\":true} # `cmd` is required\n");
		return 0;
	}
	char *s_input = strdup (input - 1);
	const RJson *j_cmd = NULL;
	RJson *j = r_json_parse (s_input);
	if (j) {
		j_cmd = r_json_get (j, "cmd");
	}
	PJ *pj = r_core_pj_new (core);
	pj_o (pj);
	if (j_cmd) {
		const RJson *j_json = r_json_get (j, "json");
		const RJson *j_trim = r_json_get (j, "trim");
		bool is_json = false;
		if (j_json && j_json->type == R_JSON_BOOLEAN) {
			is_json = j_json->num.u_value == 1;
		}
		bool is_trim = false;
		if (j_trim && j_trim->type == R_JSON_BOOLEAN) {
			is_trim = j_trim->num.u_value == 1;
		}
		const char *r_cmd = j_cmd->str_value;
		RList *stderr_list = r_list_newf (free);
		// capture stderr
		r_log_add_callback (stderr_cb, stderr_list);
		char *res = r_core_cmd_str (core, r_cmd);
		r_log_del_callback (stderr_cb);
		if (res) {
			if (is_trim || is_json) {
				r_str_trim (res);
			}
			if (is_json) {
				pj_k (pj, "res");
				pj_raw (pj, res);
			} else {
				pj_ks (pj, "res", res);
			}
			free (res);
			pj_kb (pj, "error", false);
		} else {
			pj_kb (pj, "error", true);
		}
		pj_kn (pj, "value", core->num->value);
		pj_kn (pj, "code", core->rc);
		if (!r_list_empty (stderr_list)) {
			pj_ka (pj, "logs");
			char *m;
			RListIter *iter;
			r_list_foreach (stderr_list, iter, m) {
				pj_raw (pj, m);
				if (iter->n) {
					pj_raw (pj, ",");
				}
			}
			pj_end (pj);
		}
		r_list_free (stderr_list);
		pj_kn (pj, "code", core->rc);
	} else {
		pj_ks (pj, "res", "");
		pj_kb (pj, "error", true);
		pj_kn (pj, "value", core->num->value);
		pj_kn (pj, "code", core->rc);
	}
	pj_end (pj);
	char *j_res = pj_drain (pj);
	r_kons_printf (core->cons, "%s\n", j_res);
	free (j_res);
	r_json_free (j);
	free (s_input);
	return 0;
}

static int cmd_system(void *data, const char *input) {
	RCore *core = (RCore*)data;
	ut64 n;
	int ret = 0;
	switch (*input) {
	case '-': //!-
		r_line_hist_free (core->cons->line);
		if (input[1]) {
			char *history_file = r_xdg_cachedir ("history");
			r_line_hist_save (core->cons->line, history_file);
			free (history_file);
		}
		break;
	case '=': //!=
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_exclamation, "!=!");
			r_core_cmd_help_match (core, help_msg_exclamation, "=!=");
		} else {
			if (!r_sandbox_enable (0)) {
				R_FREE (core->cmdremote);
			}
		}
		break;
	case '.': // "!."
		{
			char *history_file = r_xdg_cachedir ("history");
			R_LOG_INFO ("History saved to %s", history_file);
			r_line_hist_save (core->cons->line, history_file);
			free (history_file);
		}
		break;
	case '!': // "!!"
		if (input[1] == '!') { // !!! & !!!-
			cmd_autocomplete (core, input + 2);
		} else if (input[1] == '?') {
			cmd_help_exclamation (core);
		} else if (input[1] == '*') {
			char *cmd = r_str_trim_dup (input + 1);
			(void)r_core_cmdf (core, "'#!pipe %s", cmd);
			free (cmd);
		} else {
			if (input[1]) {
				if (r_sandbox_enable (0)) {
					R_LOG_ERROR ("The !! command is disabled in sandbox mode");
					return 0;
				}
				r_cons_push (core->cons);
				int olen = 0;
				char *out = NULL;
				char *cmd = r_core_sysenv_begin (core, input);
				if (cmd) {
				//	void *bed = r_cons_sleep_begin (core->cons);
					ret = r_sys_cmd_str_full (cmd + 1, NULL, 0, &out, &olen, NULL);
				//	r_cons_sleep_end (core->cons, bed);
					r_core_sysenv_end (core, input);
					core->cons->context->noflush = false;
					free (cmd);
				}
				r_cons_pop (core->cons);
					if (out && olen > 0) {
						r_cons_write (core->cons, out, olen);
					}
					free (out);
			} else {
				r_line_hist_list (core->cons->line, false);
			}
		}
		break;
	case '\0':
		r_line_hist_list (core->cons->line, true);
		break;
	case '?': // "!?"
		cmd_help_exclamation (core);
		break;
	case '*': // "!*"
		// TODO: use the api
		{
			char *cmd = r_str_trim_dup (input + 1);
			cmd = r_str_replace (cmd, " ", "\\ ", true);
			cmd = r_str_replace (cmd, "\\ ", " ", false);
			cmd = r_str_replace (cmd, "\"", "'", false);
			ret = r_core_cmdf (core, "'#!pipe %s", cmd);
			free (cmd);
		}
		break;
	default:
		n = atoi (input);
		if (*input == '0' || n > 0) {
			const char *cmd = r_line_hist_get (core->cons->line, n);
			if (cmd) {
				r_core_cmd0 (core, cmd);
			}
		} else {
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				void *bed = r_cons_sleep_begin (core->cons);
				ret = r_sys_cmd (cmd);
				if (ret != 0) {
					core->cons->context->was_breaked = true;
				}
				r_cons_sleep_end (core->cons, bed);
				r_core_sysenv_end (core, input);
				free (cmd);
			} else {
				R_LOG_ERROR ("Cannot setup the environment");
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

#if R2__WINDOWS__
#include <tchar.h>
#define __CLOSE_DUPPED_PIPES() \
		close (1);             \
		close (fd_out);        \
		fd_out = -1;

static DWORD WINAPI flush_thread(LPVOID param) {
	RCore *core = (RCore*) param;
	r_cons_flush (core->cons);
}

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

	HANDLE th = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) flush_thread, core, 0, NULL);

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
#if R2__UNIX__ && !__wasi__ && HAVE_FORK
	int stdout_fd, fds[2];
	int child;
#endif
	int olen, ret = -1, pipecolor = -1;
	char *str, *out = NULL;

	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("Pipes are not allowed in sandbox mode");
		return -1;
	}
	bool si = r_cons_is_interactive (core->cons);
	r_config_set_b (core->config, "scr.interactive", false);
	if (!r_config_get_b (core->config, "scr.color.pipe")) {
		pipecolor = r_config_get_i (core->config, "scr.color");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	}
	if (*shell_cmd == '!') {
		r_cons_grep_parsecmd (core->cons, shell_cmd, "\"");
		olen = 0;
		out = NULL;
		// TODO: implement foo
		str = r_core_cmd_str (core, radare_cmd);
		r_sys_cmd_str_full (shell_cmd + 1, str, -1, &out, &olen, NULL);
		free (str);
		r_cons_write (core->cons, out, olen);
		free (out);
		ret = 0;
	}
#if !HAVE_FORK
	// nothing
#elif R2__UNIX__
	r_str_trim_head (radare_cmd);
	r_str_trim_head (shell_cmd);

	r_sys_signal (SIGPIPE, SIG_IGN);
	stdout_fd = dup (1);
	if (stdout_fd != -1) {
		if (pipe (fds) == 0) {
			child = r_sys_fork ();
			if (child == -1) {
				R_LOG_ERROR ("Cannot fork");
			} else if (child) {
				dup2 (fds[1], 1);
				close (fds[1]);
				close (fds[0]);
				r_core_cmd (core, radare_cmd, 0);
				r_cons_flush (core->cons);
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
			R_LOG_ERROR ("Cannot pipe");
		}
		close (stdout_fd);
	}
#elif R2__WINDOWS__
	r_w32_cmd_pipe (core, radare_cmd, shell_cmd);
#else
#ifdef _MSC_VER
#pragma message ("r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM")
#else
#warning r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
#endif
	R_LOG_ERROR ("unimplemented for this platform");
#endif
	if (pipecolor != -1) {
		r_config_set_i (core->config, "scr.color", pipecolor);
	}
	r_config_set_b (core->config, "scr.interactive", si);
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
			R_LOG_ERROR ("Missing '=' in e: expression (%s)", kv);
		}
	}
	free (s);
	return res;
}

static bool is_macro_command(const char *ptr) {
	if (!strchr (ptr, ')')) {
		return false;
	}
	ptr = r_str_trim_head_ro (ptr);
	while (isdigit (*ptr)) {
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

static int handle_command_call(RCore *core, const char *cmd) {
	const char cmd0 = *cmd;
	if (cmd0 != '\'' && cmd0 != '"') {
		return -1;
	}
	if (R_UNLIKELY (*cmd == '\'')) {
		bool isaddr = cmd[1] == '@';
		if (isaddr) {
			cmd += 2;
		} else {
			cmd++;
		}
		if (isaddr || r_str_startswith (cmd, "0x")) {
			int res = 1;
			char *arg = strdup (cmd);
			char *end = strstr (arg, "'");
			if (end) {
				*end = 0;
				cmd = end + 1;
				ut64 addr = core->addr;
				ut64 at = r_num_math (core->num, arg);
				r_core_seek (core, at, true);
				res = r_core_cmd_call (core, cmd);
				r_core_seek (core, addr, true);
				free (arg);
			} else {
				R_LOG_ERROR ("Invalid syntax, expected \"'@addr'command\"");
				free (arg);
			}
			return res;
		}
		return r_core_cmd_call (core, cmd);
	}
	if (R_UNLIKELY (r_str_startswith (cmd, "\"\""))) {
		// R2_600 - deprecate "" -> use ' <---------- discuss!
		if (cmd[2] == '@') {
			int res = 1;
			char *arg = strdup (cmd + 2);
			char *end = strstr (arg, "\"\"");
			if (!end) {
				R_LOG_ERROR ("Invalid syntax, expected \"\"@addr\"\"command");
				free (arg);
			} else {
				*end = 0;
				cmd = end + 2;
				ut64 addr = core->addr;
				ut64 at = r_num_math (core->num, arg + 1);
				r_core_seek (core, at, true);
				res = r_core_cmd_call (core, cmd);
				r_core_seek (core, addr, true);
				free (arg);
			}
			return res;
		}
		return r_core_cmd_call (core, cmd + 2);
	}
	return -1;
}

static int r_core_cmd_subst(RCore *core, char *cmd) {
	RCons *cons = core->cons;
	// PANCAKE eprintf ("subst(%s) (%s)\n", cmd, core->cons->context->grep.strings);
	ut64 rep = strtoull (cmd, NULL, 10);
	int ret = 0, orep;
	char *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	int res = handle_command_call (core, cmd);
	if (res != -1) {
		return res;
	}
	if (R_UNLIKELY (r_str_startswith (cmd, "?t"))) {
		if (r_str_startswith (cmd + 2, "\"\"")) {
			return r_core_cmd_callf (core, "?t'%s", cmd + 4);
		}
		if (r_str_startswith (cmd + 2, "'")) {
			return r_core_cmd_callf (core, "?t'%s", cmd + 3);
		}
	}

	if (R_UNLIKELY (r_str_startswith (cmd, "GET /cmd/"))) {
		memmove (cmd, cmd + 9, strlen (cmd + 9) + 1);
		char *http = strstr (cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		r_kons_printf (cons, "HTTP/1.0 %d %s\r\n%s"
				"Connection: close\r\nContent-Length: %d\r\n\r\n",
				200, "OK", "", -1);
		return r_core_cmd0 (core, cmd);
	}

	R_CRITICAL_ENTER (core);
	/* must store a local orig_offset because there can be
	 * nested call of this function */
	ut64 orig_offset = core->addr;
	icmd = strdup (cmd);
	if (!icmd) {
		goto beach;
	}

	if (core->max_cmd_depth - core->cur_cmd_depth == 1) {
		core->prompt_addr = core->addr;
	}
	cmd = (char *)r_str_trim_head_ro (icmd);
	r_str_trim_tail (cmd);
	R_CRITICAL_LEAVE (core);
	// lines starting with # are ignored (never reach cmd_hash()), except #! and #?
	if (R_STR_ISEMPTY (cmd)) {
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
		if (R_UNLIKELY (hash && hash != cmd)) {
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
		while (isdigit (*cmd)) {
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
		R_LOG_ERROR ("The command repeat syntax sugar is disabled in sandbox mode (%s)", cmd);
		goto beach;
	}
	if ((st64)rep > 1 && rep > INTERACTIVE_MAX_REP) {
		if (r_cons_is_interactive (cons)) {
			if (!r_kons_yesno (cons, 'n', "Are you sure to repeat this %"PFMT64d" times? (y/N)", rep)) {
				goto beach;
			}
		}
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = r_str_get (core->cmdtimes);
	orep = rep;

	bool is_root_cmd = core->cur_cmd_depth + 1 == core->max_cmd_depth;
	if (is_root_cmd) {
		r_cons_break_clear (core->cons);
	}
	r_cons_break_push (core->cons, NULL, NULL);
	R_CRITICAL_ENTER (core);
	const bool ocur_enabled = core->print && core->print->cur_enabled;
	R_CRITICAL_LEAVE (core);
	while (rep-- > 0 && *cmd) {
		if (r_kons_was_breaked (cons)) {
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
		R_CRITICAL_ENTER (core);
		core->break_loop = false;
		R_CRITICAL_LEAVE (core);
		if (rep > 1 && strstr (cmd, "@@")) {
			char *repcmd = r_str_newf ("%"PFMT64d"%s", rep + 1, cmd);
			ret = r_core_cmd_subst_i (core, repcmd, colon, (rep == orep - 1) ? &tmpseek : NULL);
			free (repcmd);
			rep = 0;
		} else {
			ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);
		}
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
			r_cons_flush (core->cons);
		}
		if (R_STR_ISNOTEMPTY (cr) && orep > 1) {
			// XXX: do not flush here, we need r_cons_push () and r_cons_pop()
			r_cons_flush (core->cons);
			// XXX: we must import register flags in C
			(void)r_core_cmd0 (core, ".dr*");
			(void)r_core_cmd0 (core, cr);
		}
		free (cr);
	}
	r_cons_break_pop (core->cons);
	if (is_root_cmd) {
		r_cons_break_clear (core->cons);
	}
	if (tmpseek) {
		r_core_seek (core, orig_offset, true);
		core->tmpseek = original_tmpseek;
	}
	if (core->print) {
		core->print->cur_enabled = ocur_enabled;
	}
	if (colon && colon[1]) {
		for (colon++; *colon == ';'; colon++) {
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

static void tmpenvs_free(void *item) {
	if (item) {
		r_sys_setenv (item, NULL);
		free (item);
	}
}

static bool set_tmp_arch(RCore *core, char *arch, char **tmparch) {
	R_RETURN_VAL_IF_FAIL (tmparch, false);
	*tmparch = strdup (r_config_get (core->config, "asm.arch"));
	r_config_set (core->config, "asm.arch", arch);
	core->fixedarch = true;
	return true;
}

static bool set_tmp_bits(RCore *core, int bits, char **tmpbits, int *cmd_ignbithints) {
	R_RETURN_VAL_IF_FAIL (tmpbits, false);
	*tmpbits = strdup (r_config_get (core->config, "asm.bits"));
	r_config_set_i (core->config, "asm.bits", bits);
	core->fixedbits = true;
	// XXX: why?
	*cmd_ignbithints = r_config_get_i (core->config, "anal.ignbithints");
	r_config_set_b (core->config, "anal.ignbithints", true);
	return true;
}

static char *find_subcmd_begin(char *cmd) {
	R_RETURN_VAL_IF_FAIL (cmd, NULL);
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
		if (*p == '$' && p[1] == '(' && !quote) {
			return p;
		}
	}
	return NULL;
}

static char *find_subcmd_end(char *cmd, bool backquote) {
	if (backquote) {
		return (char *)r_str_firstbut_escape (cmd, '`', "'");
	}
	char *p = cmd;
	int nest = 1;
	while (*p) {
		if (r_str_startswith (p, "$(")) {
			nest++;
			p++;
		} else {
			if (*p == ')') {
				nest--;
				if (nest == 0) {
					return p;
				}
			}
		}
		p++;
	}
	return NULL;
	// return (char *)r_str_firstbut_escape (cmd, backquote ? '`' : ')', "'");
}

static char *getarg(char *ptr) {
	if (*ptr == '{') {
		char *mander = strdup (ptr + 1);
		char *brace = strchr (mander, '}');
		if (brace) {
			*brace = 0;
		}
		return mander;
	}
	if (*ptr == ':') {
		return strdup (ptr + 1);
	}
	return NULL;
}

static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
	R_CRITICAL_ENTER (core);
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char quotestr[] = "`\"'";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RIODesc *tmpdesc = NULL;
	bool old_iova = r_config_get_b (core->config, "io.va");
	bool pamode = (core->io? !core->io->va: false);
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

	R_CRITICAL_LEAVE (core);
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
				if (R_STR_ISEMPTY (p)) {
					if (!strcmp (cmd, "?")) {
						r_core_cmd_help (core, help_msg_quote);
					} else {
						R_LOG_ERROR ("Missing \" in (%s)", cmd);
					}
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
					oseek = core->addr;
					r_core_seek (core, r_num_math (core->num, p + 2), true);
					if (q) {
						*p = '"';
						p = q;
					} else {
						p = strchr (p + 1, ';');
					}
				}
				if (R_STR_ISNOTEMPTY (p) && p[0] != '<' && p[1] == '>') {
					str = p + 2;
					while (*str == '>') {
						str++;
					}
					str = (char *)r_str_trim_head_ro (str);
					r_cons_flush (core->cons);
					const bool append = p[2] == '>';
					pipefd = r_cons_pipe_open (core->cons, str, 1, append);
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
				r_cons_flush (core->cons);
				r_cons_pipe_close (core->cons, pipefd);
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
		if (cmd[1] != '*' && cmd[1] != 'j' && !strstr (cmd, ")()")) {
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
	if (*cmd != '#') {
		ptr = (char *)(is_macro_command (cmd)
			? find_ch_after_macro (cmd, ';')
			: r_str_lastbut (cmd, ';', quotestr));
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
		}
	}
	char *backtick = find_subcmd_begin (cmd);
	if (backtick) {
		goto escape_redir;
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
				} else if (ptr[1] == 'D') { // "|D"
					char *s = r_core_cmd_str (core, cmd);
					int len;
					char *e = (char *)sdb_decode (s, &len);
					r_kons_printf (core->cons, "%s\n", e);
					free (e);
					free (s);
					return 0;
				} else if (ptr[1] == 'E') { // "|E"
					char *s = r_core_cmd_str (core, cmd);
					char *e = sdb_encode ((const ut8*)s, strlen (s));
					r_kons_printf (core->cons, "%s\n", e);
					free (e);
					free (s);
					return 0;
				} else if (ptr[1] == 'J') { // "|J" same as "j:"
					char *ncmd = r_str_newf ("j:%s", cmd);
					int ret = r_core_cmd0 (core, ncmd);
					free (ncmd);
					return ret;
				} else if (ptr[1] == 'H') { // "|H"
					scr_html = r_config_get_b (core->config, "scr.html");
					r_config_set_b (core->config, "scr.html", true);
					RConsContext *c = core->cons->context;
					c->tmp_html = true;
					c->is_html = true;
					c->was_html = scr_html;
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
							r_kons_printf (core->cons, "%s\n", res);
							free (res);
						}
					}
					r_core_return_value (core, value);
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
			R_LOG_ERROR ("command error(%s)", cmd);
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
		char *pipechar = strchr (ptr, '>');
		if (pipechar) {
			*pipechar++ = 0;
			const bool appendResult = *pipechar == '>';
			const char *pipefile = r_str_trim_head_ro (appendResult? pipechar + 1: pipechar);
			int pipefd = r_cons_pipe_open (core->cons, pipefile, 1, appendResult);
			if (pipefd != -1) {
				int scr_color = -1;
				bool pipecolor = r_config_get_b (core->config, "scr.color.pipe");
				if (!pipecolor) {
					scr_color = r_config_get_i (core->config, "scr.color");
					r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
				}
				ret = r_core_cmd_subst (core, cmd);
				r_cons_flush (core->cons);
				close (pipefd);
				r_cons_pipe_close (core->cons, pipefd);
				if (!pipecolor) {
					r_config_set_i (core->config, "scr.color", scr_color);
				}
			}
			return ret;
		}
		ptr[0] = 0;
		if (*cmd != '#') {
			int detail = 0;
			if (cmd < ptr && ptr[-1] == '?') {
				detail++;
				if (cmd < ptr - 1 && ptr[-2] == '?') {
					detail++;
				}
			}
			//r_cons_break_push (core->cons, NULL, NULL);
			recursive_help (core, detail, cmd);
			core->cons->context->noflush = false; // PANCAKE for some reason wtf
			//r_cons_break_pop (core->cons);
			r_cons_grep_parsecmd (core->cons, ptr + 2, "`");
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
	if (ptr != NULL && ptr + 2 > cmd) {
		// Handle ~<>
		char *prev = ptr - 2;
		if (r_str_startswith (prev, "~<>")) {
			ptr = NULL;
		}
	}
	int fdn = 1;
	char *next_redirect = NULL;
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
		bool pipecolor = r_config_get_b (core->config, "scr.color.pipe");
		bool use_editor = false;
		int ocolor = r_config_get_i (core->config, "scr.color");
		*ptr = '\0';
		r_cons_set_interactive (core->cons, false);
repeat:;
		str = ptr + 1 + (ptr[1] == '>');
		r_str_trim (str);
		if (!*str) {
			R_LOG_ERROR ("No output?");
			goto next2;
		}
		fdn = 1;
		// note that 'x>a' is not working .. but 'x > a' or 'x >a' is valid
		bool redirect_check = (ptr > cmd && (!ptr[-1] || !ptr[-2] || IS_WHITECHAR (ptr[-2])));
		if (redirect_check) { // R2R db/cmd/cmd_macros
			R_LOG_DEBUG ("FD FROM (%s)", ptr - 1);
			char *fdnum = ptr - 1;
			if (*fdnum == 'H') { // "H>"
				scr_html = core->cons->context->is_html;
				r_config_set_b (core->config, "scr.html", true);
				pipecolor = true;
				*fdnum = 0;
			} else {
				if (isdigit (*fdnum)) {
					fdn = *fdnum - '0';
				}
				*fdnum = 0;
			}
		}
		R_LOG_DEBUG ("FD %d", fdn);
		if (!strcmp (str, "-")) {
			use_editor = true;
			str = r_file_temp ("dumpedit");
			r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
		}

		char *nextgt = strchr (r_str_trim_head_ro (ptr + 1), '>');
		if (nextgt && nextgt[0] != '>') {
			char *back = ptr + 1;
			while (nextgt > back) {
				if (!isdigit (*nextgt) && *nextgt != 'H') {
					break;
				}
				nextgt--;
			}
			next_redirect = nextgt;
			while (nextgt > back) {
				if (*nextgt == ' ') {
					*nextgt = 0;
					break;
				}
				nextgt--;
			}
		} else {
			next_redirect = NULL;
		}
		// eprintf ("next (%s)\n", next_redirect);
		const bool appendResult = (ptr[1] == '>');
		if (*str == '$' && !str[1]) {
			R_LOG_ERROR ("No alias name given");
		} else if (*str == '$') {
			// pipe to alias variable
			// register output of command as an alias
			r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
			RBuffer *cmd_out = r_core_cmd_tobuf (core, cmd);
			if (cmd_out) {
				int alias_len;
				ut8 *alias_data = r_buf_read_all (cmd_out, &alias_len);
				const char *arg = r_str_trim_head_ro (str + 1);
				if (appendResult) {
					if (!r_cmd_alias_append_raw (core->rcmd, arg, alias_data, alias_len)) {
						R_LOG_INFO ("Alias '$%s' is a command - will not attempt to append", arg);
					}
				} else {
					r_cmd_alias_set_raw (core->rcmd, arg, alias_data, alias_len);
				}
				ret = 0;
				r_buf_free (cmd_out);
				free (alias_data);
			}
		} else if (fdn > 0) {
			// pipe to file (or append)
			pipefd = r_cons_pipe_open (core->cons, str, fdn, appendResult);
			if (pipefd == -1) {
				// R_LOG_ERROR ("Cannot open pipe with fd %d", fdn);
				// goto errorout;
			}
			*str = 0;
			if (next_redirect) {
				ptr = next_redirect;
				*next_redirect = ' ';
				next_redirect = NULL;
				goto repeat;
			}
			if (!pipecolor) {
				r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
			}
			ret = r_core_cmd_subst (core, cmd);
			r_cons_flush (core->cons);
		}
		if (!pipecolor) {
			r_config_set_i (core->config, "scr.color", ocolor);
		}
		if (use_editor) {
			const char *editor = r_config_get (core->config, "cfg.editor");
			if (R_STR_ISNOTEMPTY (editor)) {
				r_sys_cmdf ("%s '%s'", editor, str);
				r_file_rm (str);
			} else {
				R_LOG_ERROR ("No value defined for cfg.editor");
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
		r_cons_pipe_close_all (core->cons);
		r_cons_set_last_interactive (core->cons);
		return ret;
	}
escape_redir:
next2:
	/* sub commands */
	ptr = find_subcmd_begin (cmd);
	if (R_UNLIKELY (ptr)) {
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
		if ((ptr[1] == '`' && backquote) || (ptr[1] == ')' && !backquote)) {
			memmove (ptr, ptr + 2, strlen (ptr) - 1);
			goto escape_backtick;
		}
		ptr2 = find_subcmd_end (ptr + 1, backquote);
		if (!ptr2) {
			R_LOG_ERROR ("parse: Missing sub-command closing in expression");
			goto fail;
		}
		int value = core->num->value;
		*ptr = '\0';
		*ptr2 = '\0';
		if (ptr[1] == '!') {
			str = r_core_cmd_str_pipe (core, ptr + 1);
		} else {
			// Color disabled when doing backticks ?e `pi 1`
			const int ocolor = r_config_get_i (core->config, "scr.color");
			r_config_set_i (core->config, "scr.color", 0);// alloc
			str = r_core_cmd_str (core, ptr + 1); // free
			r_config_set_i (core->config, "scr.color", ocolor); // dblfree
		}
		if (!str) {
			goto fail;
		}
		// ignore contents if first char is pipe or comment
		if (*str == '|' || *str == '*') {
			R_LOG_ERROR ("invalid sub-command");
			free (str);
			goto fail;
		}
		if (str) {
			r_str_replace_ch (str, '\n', ' ', true);
		}
		str = r_str_append (str, ptr2 + 1);
		cmd = r_str_append (strdup (cmd), str);
		r_core_return_value (core, value);
		// XXX this is a hack but should be a cons_context_pop()
		// EXAMPLE: ?v `i~baddr[1]`
		// PANCAKE - context is not deinitialized properly after a subcommand
		// memset (core->cons->context, 0, sizeof (RConsContext));
		// memset (&core->cons->context->grep, 0, sizeof (core->cons->context->grep));
		// eprintf ("--> (%s)\n", cmd);
		ret = r_core_cmd_subst (core, cmd);
		free (cmd);
		if (scr_html != -1) {
			r_config_set_b (core->config, "scr.html", scr_html);
		}
		free (str);
		r_list_free (tmpenvs);
		return ret;
	}
escape_backtick:
	// TODO must honor " and `
	if (*cmd != '"' && *cmd) {
		const char *s = strstr (cmd, "~?");
		if (R_UNLIKELY (s)) {
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
				r_cons_grep_help (core->cons);
				r_list_free (tmpenvs);
				return true;
			}
		}
	}
	if (*cmd != '.') {
		grep = r_cons_grep_strip (cmd, quotestr);
	}

	/* temporary seek commands */
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
		ut64 addr = core->addr;
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
		if (r_str_startswith (ptr, "@@@")) { // "@@@@"
			R_LOG_ERROR ("Cannot iterate that much");
			goto fuji;
		}
		if (arroba) {
			*arroba = 0;
		}
		ptr = (char *)r_str_trim_head_ro (ptr);

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
			} else {
				char *n = r_sys_getenv (ptr + 2);
				if (R_STR_ISNOTEMPTY (n)) {
					ut64 v = r_num_math (core->num, n);
					if (core->num->nc.errors == 0) {
						r_core_seek (core, v, true);
						cmd_tmpseek = core->tmpseek = true;
						goto fuji;
					}
				} else {
					R_LOG_ERROR ("Unknown envvar @%");
				}
				free (n);
			}
			free (k);
		} else if (ptr[1] == '.') { // "@."
			if (ptr[2] == '.') { // "@.."
				if (ptr[3] == '.') { // "@..."
					ut64 addr = r_num_tail (core->num, core->addr, ptr + 4);
					r_core_block_size (core, R_ABS ((st64)addr - (st64)core->addr));
					goto fuji;
				} else {
					addr = r_num_tail (core->num, core->addr, ptr + 3);
					r_core_seek (core, addr, true);
					cmd_tmpseek = core->tmpseek = true;
					goto fuji;
				}
			} else {
				// WAT DU
				R_LOG_TODO ("what do you expect for @. import offset from file maybe?");
			}
		} else if (ptr[0] && ptr[1] && ptr[2]) {
			// TODO: getarg(ptr);
			// TODO move into a separate function
			switch (ptr[0]) {
			case 'F': // "@F:" // temporary flag space
				flgspc_changed = r_flag_space_push (core->flags, ptr + 2);
				break;
			case 'B': // "@B:#" // seek to the last instruction in current bb
				{
					int index = (int)r_num_math (core->num, ptr + 2);
					RAnalBlock *bb = r_anal_bb_from_offset (core->anal, core->addr);
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
							R_LOG_INFO ("Current basic block has %d instructions", bb->ninstr);
						}
					} else {
						R_LOG_ERROR ("Can't find a basic block for 0x%08"PFMT64x, core->addr);
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
							r_io_map_add (core->io, d->fd, d->perm, 0, core->addr, r_buf_size (b));
						}
					}
				} else {
					R_LOG_ERROR ("cannot open '%s'", ptr + 3);
				}
				break;
			case 'r': // "@r:" "@r{}" // regname
				{
					char *arg = getarg (ptr + 1);
					if (arg) {
						bool err = false;
						ut64 v = r_debug_reg_get_err (core->dbg, arg, &err, 0);
						free (arg);
						if (err) {
							R_LOG_ERROR ("Invalid register name for @r");
							core->num->nc.errors ++;
						} else {
							r_core_seek (core, v, true);
							cmd_tmpseek = core->tmpseek = true;
						}
					} else {
						R_LOG_ERROR ("Invalid register name for @r");
						core->num->nc.errors ++;
					}
				}
				break;
			case 'b': // "@b:" // bits
				{
					char *arg = getarg (ptr + 1);
					if (arg) {
						ut64 v = r_num_math (core->num, arg);
						if (core->num->nc.errors == 0) {
							is_bits_set = set_tmp_bits (core, v, &tmpbits, &cmd_ignbithints);
						}
					} else {
						R_LOG_ERROR ("Invalid block size @b");
						core->num->nc.errors ++;
					}
				}
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
					if (tmpeval) {
						tmpeval = r_str_prepend (tmpeval, cmd);
						free (cmd);
					} else {
						tmpeval = cmd;
					}
				}
				break;
			case 'v': // "@v:" // value (honors asm.bits and cfg.bigendian)
				if (ptr[1] == ':') {
					ut8 buf[8] = {0};
					ut64 v = r_num_math (core->num, ptr + 2);
					bool be = r_config_get_b (core->config, "cfg.bigendian");
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
						r_io_map_add (core->io, d->fd, d->perm, 0, core->addr, r_buf_size (b));
						r_core_block_size (core, len);
						r_core_block_read (core);
					}
				} else {
					R_LOG_ERROR ("Invalid @v: syntax");
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
								r_io_map_add (core->io, d->fd, d->perm, 0, core->addr, r_buf_size (b));
								r_core_block_size (core, len);
								r_core_block_read (core);
							}
						} else {
							R_LOG_ERROR ("Invalid hexpairs for @x:");
						}
						free (buf);
					} else {
						R_LOG_ERROR ("cannot allocate");
					}
				} else {
					R_LOG_ERROR ("Invalid @x: syntax");
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
						const int bits = r_num_math (core->num, q);
						is_bits_set = set_tmp_bits (core, bits, &tmpbits, &cmd_ignbithints);
					}
					is_arch_set = set_tmp_arch (core, ptr + 2, &tmpasm);
				} else {
					r_core_cmd_help_match (core, help_msg_at, "@a:");
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
							r_io_map_add (core->io, d->fd, d->perm, 0, core->addr, r_buf_size (b));
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
				r_str_startswith (ptr + 1, "0x") &&
				r_str_startswith (ptr2 + 1, "0x")) {
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

		switch (*offstr) {
		case '{':
			addr = core->addr;
			break;
		case '@':
		case '?':
			// nothing
			break;
		default:
			{
				ut64 n = r_num_math (core->num, offstr);
				if (core->num->nc.errors) {
					R_LOG_ERROR ("Invalid tmpseek address '%s'", offstr);
					goto fail;
				}
				addr = n;
			}
			break;
		}
		addr_is_set = true;

		if (isalpha ((ut8)ptr[1]) && !addr) {
			if (!r_flag_get (core->flags, ptr + 1)) {
				R_LOG_ERROR ("Invalid address (%s)", ptr + 1);
				goto fail;
			}
		} else {
			char ch = *offstr;
			if (ch == '-' || ch == '+') {
				addr = core->addr + addr;
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
		if (ptr[1] == '@') { // "@@"
			if (ptr[2] == '@') { // "@@@"
				char *rule = (char *)r_str_trim_head_ro (ptr + 3);
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
					r_core_cmd_help_match (core, help_msg_at, "@{");
					free (tmpeval);
					free (tmpasm);
					free (tmpbits);
					goto fail;
				}
				char *arg = p + 1;
				const int arg_len = strlen (arg);
				if (arg_len > 0) {
					arg[arg_len - 1] = 0;
				}
				*p = '\x00';
				ut64 from = r_num_math (core->num, range);
				ut64 to = r_num_math (core->num, arg);
				if (from >= to) {
					R_LOG_WARN ("Invalid @{from to} range");
				}
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
#if 0
				// TODO may not work well for search commands XXX
				r_core_seek (core, from, true);
				r_core_block_size (core, to - from);
#endif
			}
			if (usemyblock) {
				if (addr_is_set) {
					core->addr = addr;
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
				r_config_set_b (core->config, "io.va", old_iova);
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
		r_core_return_value (core, rc);
	}
beach:
	if (grep) {
		char *old_grep = grep;
		grep = unescape_special_chars (old_grep, SPECIAL_CHARS);
		free (old_grep);
		r_cons_grep_expression (core->cons, grep);
		free (grep);
	}
	if (scr_html != -1) {
		r_cons_flush (core->cons);
		r_config_set_b (core->config, "scr.html", scr_html);
	}
	if (scr_color != -1) {
		r_config_set_i (core->config, "scr.color", scr_color);
	}
	r_list_free (tmpenvs);
	if (tmpdesc) {
		if (pamode) {
			r_config_set_b (core->config, "io.va", old_iova);
		}
		r_io_desc_close (tmpdesc);
		tmpdesc = NULL;
	}
	if (tmpseek) {
		*tmpseek = cmd_tmpseek;
	}
	if (cmd_ignbithints != -1) {
		r_config_set_i (core->config, "anal.ignbithints", cmd_ignbithints);
	}
	return rc;
fail:
	rc = -1;
	if (tmpdesc) {
		if (pamode) {
			r_config_set_b (core->config, "io.va", old_iova);
		}
		r_io_desc_close (tmpdesc);
		tmpdesc = NULL;
	}
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
	if (name) {
		fli->name = strdup (name);
	}
	fli->addr = addr;
	fli->size = size;
	r_list_append (list, fli);
}

static bool copy_into_flagitem_list(RFlagItem *fi, void *u) {
	RList *list = (RList*)u;
	append_item (list, fi->name, fi->addr, fi->size);
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
		if (R_STR_ISNOTEMPTY (arg)) {
			ut64 n = r_num_get (NULL, arg);
			if (core->num->nc.errors != 0) {
				R_LOG_ERROR ("Invalid number '%s'", arg);
				break;
			}
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
	default:
		R_LOG_DEBUG ("Unhandled CL subcommand '%c'", type);
		break;
	case '?':
		// eprintf ("HALP\n");
		break;
	case 'C': // "@@@C"
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
	case 'm': // "@@@m"
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
		if (core->dbg && core->dbg->current && core->dbg->maps) {
			RDebugMap *map;
			r_list_foreach (core->dbg->maps, iter, map) {
				append_item (list, NULL, map->addr, map->size);
			}
		}
		break;
	case 'e': // @@@e
		{
			RBinAddr *entry;
			const RList *elist = r_bin_get_entries (core->bin);
			r_list_foreach (elist, iter, entry) {
				ut64 addr = va? entry->vaddr: entry->paddr;
				append_item (list, NULL, addr, UT64_MAX);
			}
			// NOUAF r_list_free (elist);
		}
		break;
	case 't': // @@@t
		{
			RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
			// iterate over all threads
			if (plugin && plugin->threads) {
				RDebugPid *p;
				RList *thlist = plugin->threads (core->dbg, core->dbg->pid);
				r_list_foreach (thlist, iter, p) {
					append_item (list, NULL, (ut64)p->pid, UT64_MAX);
				}
				r_list_free (thlist);
			}
		}
		break;
	case 'i': // @@@i
		{
			RBinImport *imp;
			const RList *implist = r_bin_get_imports (core->bin);
			r_list_foreach (implist, iter, imp) {
				const char *name = r_bin_name_tostring (imp->name);
				char *impflag = r_str_newf ("sym.imp.%s", name);
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
			RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
			const bool va = r_config_get_b (core->config, "io.va");
			R_VEC_FOREACH (symbols, sym) {
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
			RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
			R_VEC_FOREACH (symbols, sym) {
				ut64 addr = va? sym->vaddr: sym->paddr;
				append_item (list, NULL, addr, sym->size);
			}
		}
		break;
	case 'S': // "@@@S"
		{
			RList *sections = r_bin_get_sections (core->bin);
			if (sections) {
				RBinSection *sec;
				r_list_foreach (sections, iter, sec) {
					if (sec->is_segment) {
						continue;
					}
					ut64 addr = va ? sec->vaddr: sec->paddr;
					ut64 size = va ? sec->vsize: sec->size;
					append_item (list, NULL, addr, size);
				}
			}
		}
		break;
	case 'G': // "@@@G" // @@@SS - seGments
		{
			RList *sections = r_bin_get_sections (core->bin);
			if (sections) {
				RBinSection *sec;
				r_list_foreach (sections, iter, sec) {
					if (!sec->is_segment) {
						continue;
					}
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
	case 'b': // "@@@b"
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (fcn) {
				RListIter *iter;
				RAnalBlock *bb;
				r_list_foreach (fcn->bbs, iter, bb) {
					append_item (list, NULL, bb->addr, bb->size);
				}
			}
		}
		break;
	case 'F': // "@@@F"
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
	case 'R': // "@@@R" relocs
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
	case 'r': // "@@@r" registers
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
	case 'f': // "@@@f"
		r_flag_foreach_glob (core->flags, glob, copy_into_flagitem_list, list);
		break;
	}
	return list;
}

R_API int r_core_cmd_foreach3(RCore *core, const char *cmd, char *each) { // "@@@"
	ForeachListItem *item;
	RListIter *iter;
	char ch = each[0];
	if (r_str_startswith (each, "SS")) {
		ch = 'G'; // @@@SS = @@@G
	}
	char *glob = (each[0] && each[1] == ':')
		? r_str_trim_dup (each + 2)
		: NULL;

	RList *list = foreach3list (core, ch, glob);

	switch (ch) {
	case '=': // "@@@="
		foreach_pairs (core, cmd, each + 1);
		break;
	case '?': // "@@@?"
		r_core_cmd_help (core, help_msg_at_at_at);
		break;
	case 'c': // "@@@c"
		if (glob) {
			char *arg = r_core_cmd_str (core, glob);
			if (arg) {
				foreach_pairs (core, cmd, arg);
				free (arg);
			}
		} else {
			r_core_cmd_help (core, help_msg_at_at_at);
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
	case 'G':
	case 'r':
	case 'i':
		{
			ut64 offorig = core->addr;
			ut64 bszorig = core->blocksize;
			r_cons_break_push (core->cons, NULL, NULL);
			r_list_foreach (list, iter, item) {
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				if (item->addr == UT64_MAX) {
					continue;
				}
				if (item->name) {
					r_kons_printf (core->cons, "%s: ", item->name);
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
			r_cons_break_pop (core->cons);
		}
		break;
	case 't':
		// TODO: generalize like the rest, just call dp before and after
		{
			int origpid = core->dbg->pid;
			r_list_foreach (list, iter, item) {
				int curpid = (int) item->addr;
				r_core_cmdf (core, "dp %d", curpid);
				r_kons_printf (core->cons, "# PID %d\n", curpid);
				r_core_cmd0 (core, cmd);
				if (!foreach_newline (core)) {
					break;
				}
			}
			r_core_cmdf (core, "dp %d", origpid);
		}
		break;
	case 0:
		R_LOG_INFO ("Nothing to repeat. Check @@@?");
		break;
	case '@': // "@@@@"
		R_LOG_WARN ("I can't iterate that much!");
		break;
	default:
		R_LOG_ERROR ("Invalid repeat type, Check @@@? for help");
		break;
	}
	r_list_free (list);
	free (glob);
	return 0;
}

static void cmd_foreach_word(RCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup (_cmd);
	char *nextLine = NULL;
	/* foreach list of items */
	while (each) {
		// skip spaces
		each = r_str_trim_head_ro (each);
		// stahp on empty string
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
		while (R_STR_ISNOTEMPTY (each)) {
			each = r_str_trim_head_ro (each);
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
			r_cons_flush (core->cons);
		}
		each = nextLine;
	}
	free (cmd);
}

static void cmd_foreach_offset(RCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup (_cmd);
	char *nextLine = NULL;
	ut64 addr;
	/* foreach list of items */
	while (R_STR_ISNOTEMPTY (each)) {
		each = r_str_trim_head_ro (each);
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
		while (R_STR_ISNOTEMPTY (each)) {
			// find spaces
			while (*each == ' ') {
				each++;
			}
			char *str = strchr (each, ' ');
			if (str) {
				*str = '\0';
				addr = r_num_math (core->num, each);
				if (core->num->nc.errors != 0) {
					R_LOG_ERROR ("Invalid number '%s'", each);
					break;
				}
				*str = ' ';
				each = str + 1;
			} else {
				if (!*each) {
					break;
				}
				addr = r_num_math (core->num, each);
				if (core->num->nc.errors != 0) {
					R_LOG_ERROR ("Invalid number '%s'", each);
					break;
				}
				each = NULL;
			}
			r_core_seek (core, addr, true);
			r_core_cmd (core, cmd, 0);
			if (!foreach_newline (core)) {
				r_cons_flush (core->cons);
				break;
			}
			r_cons_flush (core->cons);
		}
		each = nextLine;
	}
	free (cmd);
}

static void atat_i(RCore *core, const char *cmd) {
	RListIter *iter;
	RAnalBlock *bb;
	int i;
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
	SetU *set = set_u_new ();
	if (fcn) {
		r_list_sort (fcn->bbs, bb_cmp);
		r_list_foreach (fcn->bbs, iter, bb) {
			r_core_seek (core, bb->addr, true);
			r_core_cmd (core, cmd, 0);
			for (i = 0; i < bb->op_pos_size; i++) {
				if (!bb->op_pos[i]) {
					break;
				}
				ut64 addr = bb->addr + bb->op_pos[i];
				if (set_u_contains (set, addr)) {
					continue;
				}
				r_core_seek (core, addr, true);
				r_core_cmd (core, cmd, 0);
				set_u_add (set, addr);
				if (!foreach_newline (core)) {
					break;
				}
			}
		}
	}
	set_u_free (set);
}

R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each) {
	int i, j;
	char ch;
	char *word = NULL;
	char *str, *ostr = NULL;
	RListIter *iter;
	RFlagItem *flag;
	ut64 oseek, addr;
	cmd = r_str_trim_head_ro (cmd);

	oseek = core->addr;
	ostr = str = strdup (each);
	r_cons_break_push (core->cons, NULL, NULL); //pop on return
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
		R_LOG_ERROR ("Nothing to repeat. Check @@?");
		break;
	case '?': // "@@?"
		r_core_cmd_help (core, help_msg_at_at);
		break;
	case 'b': // "@@b" - function basic blocks
		{
			RListIter *iter;
			RAnalBlock *bb;
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->addr);
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
	case 's': // "@@s:" - sequence
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
				r_cons_break_push (core->cons, NULL, NULL);
				r_core_return_code (core, 0);
				for (cur = from; cur <= to; cur += step) {
					if (r_cons_is_breaked (core->cons)) {
						break;
					}
					(void) r_core_seek (core, cur, true);
					r_core_cmd (core, cmd, 0);
					if (core->rc != 0) {
						R_LOG_INFO ("@@s: sequence interrupted");
						break;
					}
					if (!foreach_newline (core)) {
						break;
					}
				}
				r_cons_break_pop (core->cons);
			} else {
				R_LOG_ERROR ("Use the sequence iterator like this: 'cmd @@s:from to step'");
			}
			goto out_finish;
		}
		break;
	case 'i': // "@@i" - function instructions
		atat_i (core, cmd);
		//goto out_finish;
		break;
	case 'F': // "@@F" - alias for "@@c:afla"
		if (each[1] == 'i') { // "@@Fi" as an alias for "@@i"
			atat_i (core, cmd);
		} else {
			r_core_cmdf (core, "%s @@c:afla", cmd);
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
				RStrBuf *sb = r_strbuf_new ("");
				r_list_foreach (core->anal->fcns, iter, fcn) {
					r_core_seek (core, fcn->addr, true);
#if 0
					r_cons_push ();
					r_core_cmd (core, cmd, 0);
					char *buf = (char *)r_cons_get_buffer ();
					if (buf) {
						buf = strdup (buf);
					}
					r_cons_pop ();
					// r_kons_print (core->cons, buf);
					r_strbuf_append (sb, buf);
					free (buf);
#else
					char *buf = r_core_cmd_str (core, cmd);
					r_strbuf_appendf (sb, "%s", buf);
					free (buf);
#endif
					if (!foreach_newline (core)) {
						break;
					}
				}
				char *s = r_strbuf_drain (sb);
				if (s) {
					r_kons_print (core->cons, s);
					free (s);
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
			RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
			if (plugin && plugin->pids) {
				RList *list = plugin->pids (core->dbg, R_MAX (0, pid));
				r_list_foreach (list, iter, p) {
					r_kons_printf (core->cons, "# PID %d\n", p->pid);
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
				cmd_foreach_offset (core, cmd, arg);
				free (arg);
			}
		}
		break;
	case '=': // "@@="
		if (each[1] == '=') {
			cmd_foreach_word (core, cmd, r_str_trim_head_ro (str + 2));
		} else {
			cmd_foreach_offset (core, cmd, r_str_trim_head_ro (str + 1));
		}
		break;
	case 'd': // "@@d"
		if (each[1] == 'b' && each[2] == 't') {
			ut64 oseek = core->addr;
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
			R_LOG_ERROR ("Invalid for-each statement. Use @@=dbt[abs]");
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
				r_cons_flush (core->cons);
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
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				r_cmd_macro_call (&core->rcmd->macro, each + 2);
				if (!core->rcmd->macro.brk_value) {
					break;
				}
				addr = core->rcmd->macro._brk_value;
				r_core_seek (core, addr, true);
				r_core_cmdf (core, "%s @ 0x%08"PFMT64x, cmd, addr);
				if (!foreach_newline (core)) {
					break;
				}
				i++;
			}
		} else {
			const char *arg = r_str_trim_head_ro (each + 1);
			char *data = r_core_slurp (core, arg, NULL);
			if (data) {
				RList *rows = r_str_split_list (data, "\n", 0);
				char *row;
				RListIter *iter;
				r_list_foreach (rows, iter, row) {
					ut64 addr = r_num_math (core->num, row);
					if (core->num->nc.errors == 0) {
						r_core_cmd_call_at (core, addr, cmd);
					}
					if (!foreach_newline (core)) {
						break;
					}
					core->rcmd->macro.counter++;
				}
				r_list_free (rows);
				free (data);
			} else {
				R_LOG_ERROR ("cannot open file '%s' to read offsets", arg);
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
					if (r_cons_is_breaked (core->cons)) {
						break;
					}
					char *buf = NULL;
					const char *tmp = NULL;
					r_core_seek (core, flag->addr, true);
					r_cons_push (core->cons);
					r_core_cmd (core, cmd, 0);
					tmp = r_cons_get_buffer (core->cons, NULL);
					buf = tmp? strdup (tmp): NULL;
					r_cons_pop (core->cons);
					if (buf) {
						r_kons_print (core->cons, buf);
						free (buf);
					}
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
	r_cons_break_pop (core->cons);
	// XXX: use r_core_seek here
	core->addr = oseek;

	free (word);
	free (ostr);
	return true;
out_finish:
	free (ostr);
	r_cons_break_pop (core->cons);
	return false;
}

static int run_cmd_depth(RCore *core, char *cmd) {
	char *rcmd;
	int ret = false;
	int *depth = &core->cur_cmd_depth;
	if (depth) {
		if (*depth < 1) {
			R_LOG_ERROR ("That '%s' was too deep", cmd);
			return false;
		}
		(*depth)--;
	}
	for (rcmd = cmd;;) {
		char *ptr = strchr (rcmd, '\n');
		if (R_UNLIKELY (ptr)) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);
		if (R_UNLIKELY (ret == -1)) {
			R_LOG_ERROR ("Invalid command '%s' (0x%02x)", rcmd, *rcmd);
			break;
		}
		if (!ptr) {
			break;
		}
		rcmd = ptr + 1;
	}
	if (depth) {
		(*depth)++;
	}
	return ret;
}

R_API int r_core_cmd(RCore *core, const char *cstr, bool log) {
	R_RETURN_VAL_IF_FAIL (core && cstr, 0);
	R_LOG_DEBUG ("RCoreCmd: %s", cstr);
	int ret = 0;
	if (core->incomment) {
		if (r_str_startswith (cstr, "*/")) {
			core->incomment = false;
		}
		goto beach; // false
	}
	r_core_return_code (core, 0);
	ret = handle_command_call (core, cstr);
	if (!strcmp (cstr, "!") || !strcmp (cstr, "!!")) {
		log = false;
	}
	if (ret != -1) {
		if (log) {
			r_line_hist_add (core->cons->line, cstr);
		}
		return ret;
	}
	if (R_STR_ISNOTEMPTY (core->cmdfilter)) {
		const char invalid_chars[] = ";|>`@";
		size_t i;
		for (i = 0; invalid_chars[i]; i++) {
			if (strchr (cstr, invalid_chars[i])) {
				ret = true;
				goto beach;
			}
		}
		if (r_str_startswith (cstr, "\"\"")) {
			cstr += 2;
		}
		if (!r_str_startswith (cstr, core->cmdfilter)) {
			ret = true;
			goto beach;
		}
	}
	if (core->cmdremote) {
		if (*cstr == 'q') {
			R_FREE (core->cmdremote);
			goto beach; // false
		}
		if (*cstr != '=' && !r_str_startswith (cstr, "!=")) {
			if (core->cmdremote[0]) {
				char *s = r_str_newf ("%s %s", core->cmdremote, cstr);
				r_core_rtr_cmd (core, s);
				free (s);
			} else {
				char *res = r_io_system (core->io, cstr);
				if (res) {
					r_kons_printf (core->cons, "%s\n", res);
					free (res);
				}
			}
			if (log) {
				r_line_hist_add (core->cons->line, cstr);
			}
			goto beach; // false
		}
	}

	if (*cstr == '|' && cstr[1] != '?') {
		// raw comment syntax
		goto beach; // false;
	}
	if (r_str_startswith (cstr, "/*")) {
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("This command is disabled in sandbox mode");
			goto beach; // false
		}
		core->incomment = true;
		goto beach;
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
		r_line_hist_add (core->cons->line, cstr);
	}
	ret = run_cmd_depth (core, cmd);
	free (cmd);
beach:
	return ret;
}

R_API bool r_core_cmd_lines(RCore *core, const char *lines) {
	R_RETURN_VAL_IF_FAIL (core && lines, false);
	int r;
	char *data, *odata;

	if (R_STR_ISEMPTY (lines)) {
		return true;
	}
	data = odata = strdup (lines);
	if (!odata) {
		return false;
	}
	bool ret = true;
	size_t line_count = r_str_char_count (lines, '\n');
	const bool istty = r_cons_is_tty ();
	const bool show_progress_bar = core->print->enable_progressbar \
		&& r_config_get_b (core->config, "scr.interactive") \
		&& r_config_get_b (core->config, "scr.progressbar") && istty;
	size_t current_line = 0;
	char *nl = strchr (odata, '\n');
	if (nl) {
		r_cons_break_push (core->cons, NULL, NULL);
		do {
			if (show_progress_bar) {
				r_print_progressbar_with_count (core->print, current_line++, line_count, 80, true);
			}
			if (r_cons_is_breaked (core->cons)) {
				free (odata);
				r_cons_break_pop (core->cons);
				return ret;
			}
			*nl = '\0';
			r = r_core_cmd (core, data, 0);
			if (r < 0) {
				data = nl + 1;
				ret = true; // -1;
				break;
			}
			r_cons_flush (core->cons);
			if (data[0] == 'q') {
				if (data[1] == '!') {
					ret = true; // -1;
				} else {
					R_LOG_WARN ("'q': quit ignored. Use 'q!'");
				}
				data = nl + 1;
				break;
			}
			data = nl + 1;
			r_core_task_yield (&core->tasks);
		} while ((nl = strchr (data, '\n')));
		r_cons_break_pop (core->cons);
		if (show_progress_bar) {
			r_print_progressbar_with_count (core->print, line_count, line_count, 80, true);
			r_cons_newline (core->cons);
		}
	}
	if (ret && R_STR_ISNOTEMPTY (data)) {
		r_core_cmd (core, data, 0);
		r_cons_flush (core->cons);
		r_core_task_yield (&core->tasks);
	}
	free (odata);
	return ret;
}

R_API bool r_core_cmd_file(RCore *core, const char *file) {
	R_RETURN_VAL_IF_FAIL (core && file, false);
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
		R_LOG_ERROR ("Failed to run script '%s'", file);
		free (odata);
		return false;
	}
	free (odata);
	return true;
}

R_API bool r_core_cmd_command(RCore *core, const char *command) {
	R_RETURN_VAL_IF_FAIL (core && command, -1);
	char *cmd = r_core_sysenv_begin (core, command);
	int len;
	char *buf = r_sys_cmd_str (cmd, 0, &len);
	if (!buf) {
		free (cmd);
		return false;
	}
	bool ret = r_core_cmd_lines (core, buf);
	r_core_sysenv_end (core, command);
	free (buf);
	return ret;
}

// TODO: Fix disasm loop is mandatory
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	char *cmd, *ret = NULL;
	cmd = r_str_newf ("pi %i @ 0x%08"PFMT64x, l, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	char *ret = NULL;
	char *cmd = r_str_newf ("pD %i @ 0x%08"PFMT64x, b, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API bool r_core_cmd_buffer(RCore *core, const char *buf) {
	R_RETURN_VAL_IF_FAIL (core && buf, false);
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

R_API int r_core_cmdf_at(RCore *core, ut64 addr, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (core && fmt, -1);
	va_list ap;
	va_start (ap, fmt);
	ut64 oaddr = core->addr;
	if (oaddr != addr) {
		r_core_seek (core, addr, 1);
	}
	char *cmd = r_str_newvf (fmt, ap);
	int ret = r_core_cmd (core, cmd, 0);
	free (cmd);
	if (oaddr != addr) {
		r_core_seek (core, oaddr, 1);
	}
	va_end (ap);
	return ret;
}

R_API int r_core_cmdf(RCore *core, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (core && fmt, -1);
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
	r_cons_reset (core->cons);
	r_sandbox_disable (true);
	if (r_file_mkstemp ("cmd", &tmp) != -1) {
		int pipefd = r_cons_pipe_open (core->cons, tmp, 1, false);
		if (pipefd == -1) {
			r_file_rm (tmp);
			r_sandbox_disable (false);
			free (tmp);
			return r_core_cmd_str (core, cmd);
		}
		char *_cmd = strdup (cmd);
		r_core_cmd (core, _cmd, 0);
		r_cons_flush (core->cons);
		r_cons_pipe_close (core->cons, pipefd);
		if (r_file_exists (tmp)) {
			char *s = r_file_slurp (tmp, NULL);
			r_file_rm (tmp);
			r_sandbox_disable (false);
			free (tmp);
			free (_cmd);
			return s? s: strdup ("");
		}
		R_LOG_ERROR ("slurp %s fails", tmp);
		r_file_rm (tmp);
		free (tmp);
		free (_cmd);
		r_sandbox_disable (false);
		return r_core_cmd_str (core, cmd);
	}
	r_sandbox_disable (0);
	return NULL;
}

R_API char *r_core_cmd_strf_at(RCore *core, ut64 addr, const char *fmt, ...) {
	va_list ap;
	ut64 oaddr = core->addr;
	va_start (ap, fmt);
	if (addr != core->addr) {
		r_core_seek (core, addr, 1);
	}
	char *cmd = r_str_newvf (fmt, ap);
	char *ret = r_core_cmd_str (core, cmd);
	free (cmd);
	if (addr != core->addr) {
		r_core_seek (core, oaddr, 1);
	}
	va_end (ap);
	return ret;
}

R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (core && fmt, NULL);
	va_list ap;
	va_start (ap, fmt);
	char *cmd = r_str_newvf (fmt, ap);
	char *ret = r_core_cmd_str (core, cmd);
	free (cmd);
	va_end (ap);
	return ret;
}

R_API int r_core_cmd_call_at(RCore *core, ut64 addr, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (core && cmd, -1);
	R_LOG_DEBUG ("RCoreCallAt(0x%08"PFMT64x"): %s", addr, cmd);
	const ut64 oaddr = core->addr;
	const bool mustseek = addr != oaddr;
	if (mustseek) {
		r_core_seek (core, addr, 1);
	}
	int res = r_cmd_call (core->rcmd, cmd);
	if (mustseek) {
		r_core_seek (core, oaddr, 1);
	}
	return res;
}

// run an r2 command without evaluating any special character
R_API int r_core_cmd_call(RCore *core, const char *cmd) {
	return r_cmd_call (core->rcmd, cmd);
}

R_API int r_core_cmd_callf(RCore *core, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *cmd = r_str_newvf (fmt, ap);
	int res = r_cmd_call (core->rcmd, cmd);
	free (cmd);
	va_end (ap);
	return res;
}

R_API char *r_core_cmd_str_at(RCore *core, ut64 addr, const char *cmd) {
	ut64 oseek = core->addr;
	r_core_seek (core, addr, true);
	char *res = r_core_cmd_str (core, cmd);
	r_core_seek (core, oseek, true);
	return res;
}

/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (core, NULL);
	if (cmd && *cmd != '"' && strchr (cmd, '>')) {
		r_core_cmd0 (core, cmd); // CMD HERE
		return strdup ("");
	}
	r_cons_push (core->cons);
	core->cons->context->noflush = true; // why
	core->cons->context->cmd_str_depth++; // wat
	if (cmd && r_core_cmd (core, cmd, 0) == -1) { // dbl Free
		//eprintf ("Invalid command: %s\n", cmd);
		if (--core->cons->context->cmd_str_depth == 0) {
			core->cons->context->noflush = false;
			r_cons_flush (core->cons);
		}
		r_cons_pop (core->cons);
		return NULL;
	}
	if (--core->cons->context->cmd_str_depth == 0) {
		core->cons->context->noflush = false;
	}
	r_cons_filter (core->cons);
	const char *static_str = r_cons_get_buffer (core->cons, NULL);
	char *retstr = strdup (r_str_get (static_str));
	r_cons_pop (core->cons);
	r_cons_echo (core->cons, NULL);
	return retstr;
}

/* get command output in raw bytes */
R_API RBuffer *r_core_cmd_tobuf(RCore *core, const char *cmd) {
	r_cons_push (core->cons);
	core->cons->context->noflush = true;

	core->cons->context->cmd_str_depth++;
	if (r_core_cmd0 (core, cmd) == -1) {
		//eprintf ("Invalid command: %s\n", cmd);
		if (--core->cons->context->cmd_str_depth == 0) {
			core->cons->context->noflush = false;
			r_cons_flush (core->cons);
		}
		r_cons_pop (core->cons);
		return NULL;
	}

	if (--core->cons->context->cmd_str_depth == 0) {
		core->cons->context->noflush = false;
	}

	r_cons_filter (core->cons);
	size_t bsz;
	const char *buf = r_cons_get_buffer (core->cons, &bsz);
	RBuffer *out = r_buf_new_with_bytes ((const ut8*)buf, bsz);
	r_cons_pop (core->cons);
	r_cons_echo (core->cons, NULL);
	free ((void *)buf);
	return out;
}

/* run cmd in the main task synchronously */
R_API int r_core_cmd_task_sync(RCore *core, const char *cmd, bool log) {
	RCoreTask *task = core->tasks.main_task;
	char *s = strdup (cmd);
	if (R_LIKELY (s)) {
		task->cmd = s;
		task->cmd_log = log;
		task->state = R_CORE_TASK_STATE_BEFORE_START;
		int res = r_core_task_run_sync (&core->tasks, task);
		free (s);
		return res;
	}
	return 0;
}

static int cmd_ox(void *data, const char *input) { // "0x"
	RCore *core = (RCore*)data;
	char *s = r_str_newf ("s 0%s", input);
	int ret = r_core_cmd_call (core, s);
	free (s);
	return ret;
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
		{ "!", "run system command", cmd_system },
		{ "_", "print last output", cmd_last },
		{ "{", "run a command in json", cmd_json },
		{ "#", "calculate hash", cmd_hash },
		{ "$", "alias", cmd_alias },
		{ "%", "environment variables (same as 'env' command)", cmd_env },
		{ "&", "tasks", cmd_tasks },
		{ "(", "macro", cmd_macro },
		{ "*", "pointer read/write", cmd_pointer },
		{ "+", "relative seek forward", cmd_plus },
		{ "-", "open cfg.editor and run script", cmd_stdin },
		{ ".", "interpret", cmd_interpret },
		{ ",", "create and manipulate tables", cmd_table },
		{ "/", "search kw, pattern aes", cmd_search },
		{ "=", "io pipe", cmd_rap },
		{ "?", "help message", cmd_help },
		{ ":", "alias for =!", cmd_iosys },
		{ "0", "alias for s 0x", cmd_ox },
		{ "a", "analysis", cmd_anal },
		{ "b", "change block size", cmd_bsize },
		{ "c", "compare memory", cmd_cmp },
		{ "C", "code metadata", cmd_meta },
		{ "d", "debugger operations", cmd_debug },
		{ "e", "evaluate configuration variable", cmd_eval },
		{ "f", "get/set flags", cmd_flag },
		{ "g", "egg manipulation", cmd_egg },
		{ "i", "get file info", cmd_info },
		{ "k", "perform sdb query", cmd_kuery },
		{ "l", "list files and directories", cmd_l },
		{ "j", "join the contents of the two files", cmd_j },
		{ "h", "show the top n number of line in file", cmd_h },
		{ "L", "manage dynamically loaded plugins", cmd_plugins },
		{ "m", "mount filesystem", cmd_mount },
		{ "o", "open or map file", cmd_open },
		{ "p", "print current block", cmd_print },
		{ "P", "project", cmd_project },
		{ "q", "exit program session", cmd_quit },
		{ "Q", "alias for q!", cmd_Quit },
		{ "r", "change file size", cmd_resize },
		{ "s", "seek to an offset", cmd_seek },
		{ "t", "type information (cparse)", cmd_type },
		{ "T", "Text log utility", cmd_log },
		{ "u", "uname/undo", cmd_undo },
		{ "<", "pipe into RCons.readChar", cmd_pipein },
		{ "V", "enter visual mode", cmd_visual },
		{ "v", "enter visual panels", cmd_panels },
		{ "w", "write bytes", cmd_write },
		{ "x", "alias for px", cmd_hexdump },
		{ "y", "yank bytes", cmd_yank },
		{ "z", "zignatures", cmd_zign },
	};

	core->rcmd = r_cmd_new ();
	if (core->rcmd) {
		core->rcmd->macro.user = core;
		core->rcmd->macro.num = core->num;
		core->rcmd->macro.cmd = core_cmd0_wrapper;
		core->rcmd->nullcallback = r_core_cmd_nullcallback;
		r_cmd_set_data (core->rcmd, core);
		core->cmd_descriptors = r_list_newf (free);
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (cmds); i++) {
			r_cmd_add (core->rcmd, cmds[i].cmd, cmds[i].cb);
		}
	}
}
