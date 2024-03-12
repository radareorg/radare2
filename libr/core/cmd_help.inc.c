/* radare - LGPL - Copyright 2009-2024 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_question_t = {
	"Usage: ?t[0,1] [cmd]", "", "",
	"?t", " pd 32", "show time needed to run 'pd 32'",
	"?t0", "", "select first visual tab",
	"?t1", "", "select next visual tab",
	NULL
};

static RCoreHelpMessage help_msg_at = {
	"Usage: [.:\"][#]<cmd>[*] [`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "", "",
	"0", "", "alias for 's 0'",
	"0x", "addr", "alias for 's 0x..'",
	"#", "cmd", "if # is a number repeat the command # times",
	"/*", "", "start multiline comment",
	"*/", "", "end multiline comment",
	".", "cmd", "execute output of command as r2 script",
	".:", "8080", "wait for commands on port 8080",
	".!", "rabin2 -re $FILE", "run command output as r2 script",
	":", "cmd", "run an io command (same as =!)",
	"-", "[?]", "alias for s- aka negative relative seek and script editor",
	"+", "[?]", "alias for s+, act as a relative seek",
	"*", "", "output of command in r2 script format (CC*)",
	"j", "", "output of command in JSON format (pdj)",
	"~", "?", "count number of lines (like wc -l)",
	"~", "??", "show internal grep help",
	"~", "..", "internal less",
	"~", "{}", "json indent",
	"~", "<>", "xml indent",
	"~", "<100", "ascii-art zoom of console buffer",
	"~", "{}..", "json indent and less",
	"~", "word", "grep for lines matching word",
	"~", "!word", "grep for lines NOT matching word",
	"~", "word[2]", "grep 3rd column of lines matching word",
	"~", "word:3[0]", "grep 1st column from the 4th line matching word",
	"@", " 0x1024", "temporary seek to this address (sym.main+3)",
	"@", " [addr]!blocksize", "temporary set a new blocksize",
	"@..", "addr", "temporary partial address seek (see s..)",
	"@!", "blocksize", "temporary change the block size (p8@3!3)",
	"@{", "from to}", "temporary set from and to for commands supporting ranges",
	"@a:", "arch[:bits]", "temporary set arch and bits",
	"@b:", "bits", "temporary set asm.bits",
	"@B:", "nth", "temporary seek to nth instruction in current bb (negative numbers too)", // XXX rename to @n:
	"@c:", "cmd", "seek to the address printed by the given command. same as '@ `cmd`'",
	"@e:", "k=v,k=v", "temporary change eval vars",
	"@f:", "file", "temporary replace block with file contents",
	"@F:", "flagspace", "temporary change flag space",
	"@i:", "nth.op", "temporary seek to the Nth relative instruction",
	"@k:", "k", "temporary seek at value of sdb key `k`",
	"@o:", "fd", "temporary switch to another fd",
	"@r:", "reg", "tmp seek to reg value (f.ex pd@r:PC, see also $r{PC} and $r:PC)",
	"@s:", "string", "same as above but from a string",
	"@v:", "value", "modify the current offset to a custom value",
	"@x:", "909192", "from hex pairs string",
	"@@=", "1 2 3", "run the previous command at offsets 1, 2 and 3",
	"@@==", "foo bar", "run the previous command appending a word on each iteration",
	"@@", " hit*", "run the command on every flag matching 'hit*'",
	"@@", "[?][ktfb..]", "show help for the iterator operator",
	"@@@", "[?] [type]", "run a command on every [type] (see @@@? for help)",
	">", "file", "pipe output of command to file",
	">>", "file", "append to file",
	"H>", "file", "pipe output of command to file in HTML",
	"H>>", "file", "append to file with the output of command in HTML",
	"`", "pdi~push:0[0]`", "replace output of command inside the line",
	"|", "cmd", "pipe output to command (pd|less) (.dr*)",
	NULL
};

static RCoreHelpMessage help_msg_at_at = {
	"@@", "", " # foreach iterator command:",
	"x", " @@ sym.*", "run 'x' over all flags matching 'sym.' in current flagspace",
	"x", " @@.file", "run 'x' over the offsets specified in the file (one offset per line)",
	"x", " @@/x 9090", "temporary set cmd.hit to run a command on each search result",
	"x", " @@=`pdf~call[0]`", "run 'x' at every call offset of the current function",
	"x", " @@=off1 off2 ..", "manual list of offsets",
	"x", " @@b", "run 'x' on all basic blocks of current function (see afb)",
	"x", " @@c:cmd", "the same as @@=`` without the backticks",
	"x", " @@dbt[abs]", "run 'x' command on every backtrace address, bp or sp",
	"x", " @@f", "run 'x' on all functions (see aflq)",
	"x", " @@f:write", "run 'x' on all functions matching write in the name",
	"x", " @@i", "run 'x' on all instructions of the current function (see pdr)",
	"x", " @@iS", "run 'x' on all sections adjusting blocksize",
	"x", " @@k sdbquery", "run 'x' on all offsets returned by that sdbquery",
	"x", " @@s:from to step", "run 'x' on all offsets from, to incrementing by step",
	"x", " @@t", "run 'x' on all threads (see dp)",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

static RCoreHelpMessage help_msg_single_quote = {
	"'", "# run a command without evaluating any special character", "",
	"'", "?e hello @ world", "print the given string, including the @ sign and the rest (r2.call)",
	"'", "0x123'?v $$", "run the '?v $$' command in the 0x123 offset (same as r2.callAt)",
	NULL
};

static RCoreHelpMessage help_msg_at_at_at = {
	"@@@", "", " # foreach offset+size iterator command:",
	"x", " @@@=", "[addr] [size] ([addr] [size] ...)",
	"x", " @@@C:cmd", "comments matching",
	"x", " @@@E", "exports",
	"x", " @@@F", "functions (set fcn size which may be incorrect if not linear)",
	"x", " @@@F:glob", "functions matching glob expression",
	"x", " @@@M", "dbg.maps (See ?$?~size)",
	"x", " @@@S", "sections",
	"x", " @@@SS", "segments (same as @@@G)",
	"x", " @@@b", "basic blocks of current function",
	"x", " @@@c:cmd", "Same as @@@=`cmd`, without the backticks",
	"x", " @@@e", "entries",
	"x", " @@@f", "flags",
	"x", " @@@f:hit*", "flags matching glob expression",
	"x", " @@@i", "imports",
	"x", " @@@m", "io.maps",
	"x", " @@@r", "registers",
	"x", " @@@R", "relocs",
	"x", " @@@s", "symbols",
	"x", " @@@t", "threads",
	"x", " @@@z", "ztrings",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

static ut32 vernum(const char *s) {
	// XXX this is known to be buggy, only works for strings like "x.x.x"
	// XXX anything like "x.xx.x" will break the parsing
	// XXX -git is ignored, maybe we should shift for it
	char *a = strdup (s);
	a = r_str_replace (a, ".", "0", 1);
	char *dash = strchr (a, '-');
	if (dash) {
		*dash = 0;
	}
	ut32 res = atoi (a);
	free (a);
	return res;
}

static RCoreHelpMessage help_msg_percent = {
	"Usage:", "%[name[=value]]", "Set each NAME to VALUE in the environment",
	"%", "", "list all environment variables",
	"%", "*", "show env vars as r2 commands",
	"%", "j", "show env vars in JSON format",
	"%", "SHELL", "prints SHELL value",
	"%", "TMPDIR=/tmp", "sets TMPDIR value to \"/tmp\"",
	NULL
};

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
static RCoreHelpMessage help_msg_env = {
	"\nEnvironment:", "", "",
	"R2_FILE", "", "file name",
	"R2_OFFSET", "", "10base offset 64bit value",
	"R2_BYTES", "", "TODO: variable with bytes in curblock",
	"R2_XOFFSET", "", "same as above, but in 16 base",
	"R2_BSIZE", "", "block size",
	"R2_ENDIAN", "", "'big' or 'little'",
	"R2_IOVA", "", "is io.va true? virtual addressing (1,0)",
	"R2_DEBUG", "", "debug mode enabled? (1,0)",
	"R2_BLOCK", "", "TODO: dump current block to tmp file",
	"R2_SIZE", "","file size",
	"R2_ARCH", "", "value of asm.arch",
	"R2_BITS", "", "arch reg size (8, 16, 32, 64)",
	"RABIN2_LANG", "", "assume this lang to demangle",
	"RABIN2_DEMANGLE", "", "demangle or not",
	"RABIN2_PDBSERVER", "", "e pdb.server",
	NULL
};

static RCoreHelpMessage help_msg_exclamation = {
	"Usage:", "!<cmd>", "  Run given command as in system(3)",
	"!", "", "list all historic commands",
	"!", "ls", "execute 'ls' in shell",
	"!*", "r2p x", "run r2 command via r2pipe in current session",
	"!!", "", "save command history to hist file",
	"!!", "ls~txt", "print output of 'ls' and grep for 'txt'",
	"!!!", "cmd [args|$type]", "adds the autocomplete value",
	"!!!-", "cmd [args]", "removes the autocomplete value",
	".!", "rabin2 -rpsei ${FILE}", "run each output line as a r2 cmd",
	"!", "echo $R2_SIZE", "display file size",
	"!-", "", "clear history in current session",
	"!-*", "", "clear and save empty history log",
	"!=!", "", "enable remotecmd mode",
	"=!=", "", "disable remotecmd mode",
	NULL
};

static RCoreHelpMessage help_msg_root = {
	"%var", "=value", "alias for 'env' command",
	"\"", "[?][\"..|..\"]", "quote a command to avoid evaluaing special chars",
	"*", "[?] off[=[0x]value]", "pointer read/write data/values (see ?v, wx, wv)",
	"(macro arg0 arg1)",  "", "manage scripting macros",
	".", "[?] [-|(m)|f|!sh|cmd]", "Define macro or load r2, cparse or rlang file",
	",", "[?] [/jhr]", "create a dummy table import from file and query it to filter/sort",
	":", "cmd", "run an io command (same as =!)",
	"_", "[?]", "Print last output",
	"=","[?] [cmd]", "send/listen for remote commands (rap://, raps://, udp://, http://, <fd>)",
	"<","[...]", "push escaped string into the RCons.readChar buffer",
	"/","[?]", "search for bytes, regexps, patterns, ..",
	"!","[?] [cmd]", "run given command as in system(3)",
	"#","[?] !lang [..]", "Hashbang to run an rlang script",
	"a","[?]", "analysis commands",
	"b","[?]", "display or change the block size",
	"c","[?] [arg]", "compare block with given data",
	"C","[?]", "code metadata (comments, format, hints, ..)",
	"d","[?]", "debugger commands",
	"e","[?] [a[=b]]", "list/get/set config evaluable vars",
	"f","[?] [name][sz][at]", "add flag at current address",
	"g","[?] [arg]", "generate shellcodes with r_egg",
	"i","[?] [file]", "get info about opened file from r_bin",
	"k","[?] [sdb-query]", "run sdb-query. see k? for help, 'k *', 'k **' ...",
	"l","[?] [filepattern]", "list files and directories",
	"L","[?] [-] [plugin]", "list, unload load r2 plugins",
	"m","[?]", "mountpoint / filesystems (r_fs) related commands",
	"o","[?] [file] ([offset])", "open file at optional address",
	"p","[?] [len]", "print current block with format and length",
	"P","[?]", "project management utilities",
	"q","[?] [ret]", "quit program with a return value",
	"r","[?] [len]", "resize file",
	"s","[?] [addr]", "seek to address (also for '0x', '0x1' == 's 0x1')",
	"t","[?]", "types, noreturn, signatures, C parser and more",
	"T","[?] [-] [num|msg]", "Text log utility (used to chat, sync, log, ...)",
	"u","[?]", "uname/undo seek/write",
	"v","", "panels mode",
	"V", "", "visual mode (Vv = func/var anal, VV = graph mode, ...)",
	"w","[?] [str]", "multiple write operations",
	"x","[?] [len]", "alias for 'px' (print hexadecimal)",
	"y","[?] [len] [[[@]addr", "yank/paste bytes from/to memory",
	"z", "[?]", "zignatures management",
	"?[??]","[expr]", "Help or evaluate math expression",
	"?$?", "", "show available '$' variables and aliases",
	"?@?", "", "misc help for '@' (seek), '~' (grep) (see ~?\"\"?)",
	"?>?", "", "output redirection",
	"?|?", "", "help for '|' (pipe)",
	NULL
};

static RCoreHelpMessage help_msg_question_i = {
	"Usage: ?e[=bdgnpst] arg", "print/echo things", "",
	"?i", " ([prompt])", "inquery the user and save that text into the yank clipboard (y)",
	"?ie", " [msg]", "same as ?i, but prints the output, useful for oneliners",
	"?iy", " [question]", "dialog yes/no with default Yes",
	"?if", " [math-expr]", "evaluates math expression returns true if result is zero",
	"?in", " [question]", "dialog yes/no with default No",
	"?im", " [msg]", "like ?ie, but using RCons.message (clear-screen + press-any-key)",
	"?ik", "", "press any key",
	"?ip", " ([path])", "interactive hud mode to find files in given path",
	NULL
};

static RCoreHelpMessage help_msg_question_e = {
	"Usage: ?e[=bdgnpst] arg", "print/echo things", "",
	"?e", "", "echo message with newline",
	"?e=", " 32", "progress bar at 32 percentage",
	"?ea", " text", "ascii art echo (seven segment text, same as ~?ea",
	"?eb", " 10 20 30", "proportional segments bar",
	"?ed", " 1", "draw a 3D ascii donut at the given animation frame",
	"?ee", " msg", "stderr message",
	"?ei", " msg", "R_LOG_INFO message",
	"?eg", " 10 20", "move cursor to column 10, row 20",
	"?ef", " text", "echo text with thin ascii art frame around",
	"?en", " nonl", "echo message without ending newline",
	"?ep", " 10 20 30", "draw a pie char with given portion sizes",
	"?es", " msg", "speak message using the text-to-speech program (e cfg.tts)",
	"?et", " msg", "change terminal title",
	NULL
};

static RCoreHelpMessage help_msg_question = {
	"Usage: ?[?[?]] expression", "", "",
	"?!", " [cmd]", "run cmd if $? == 0",
	"?", " eip-0x804800", "show all representation result for this math expr",
	"?'", "", "show help for the single quote (do not evaluate special characters in command)",
	"?$", "", "show value all the variables ($)",
	"?+", " [cmd]", "run cmd if $? > 0",
	"?-", " [cmd]", "run cmd if $? < 0",
	"?=", " eip-0x804800", "update $? return code with result of operation",
	"?==", " x86 `e asm.arch`", "strcmp two strings",
	"??", " [cmd]", "run cmd if $? != 0",
	"??", "", "show value of operation",
	"?a", "", "show ascii table",
	"?B", " [elem]", "show range boundaries like 'e?search.in",
	"?b", " [num]", "show binary value of number",
	"?b64[-]", " [str]", "encode/decode in base64",
	"?btw", " num|expr num|expr num|expr", "returns boolean value of a <= b <= c",
	"?e", "[=bdgnpst] arg", "echo messages, bars, pie charts and more (see ?e? for details)",
	"?f", " [num] [str]", "map each bit of the number as flag string index",
	"?F", "", "flush cons output",
	"?h", " [str]", "calculate hash for given string",
	"?i", "[ynmkp] arg", "prompt for number or Yes,No,Msg,Key,Path and store in $$?",
	"?ik", "", "press any key input dialog",
	"?im", " message", "show message centered in screen",
	"?in", " prompt", "noyes input prompt",
	"?ip", " prompt", "path input prompt",
	"?iy", " prompt", "yesno input prompt",
	"?j", " arg", "same as '? num' but in JSON",
	"?l", "[q] str", "returns the length of string ('q' for quiet, just set $?)",
	"?o", " num", "get octal value",
	"?P", " paddr", "get virtual address for given physical one",
	"?p", " vaddr", "get physical address for given virtual address",
	"?q", " num|expr", "compute expression like ? or ?v but in quiet mode",
	"?r", " [from] [to]", "generate random number between from-to",
	"?s", " from to step", "sequence of numbers from to by steps",
	"?t", " cmd", "returns the time to run a command",
	"?T", "", "show loading times",
	"?u", " num", "get value in human units (KB, MB, GB, TB)",
	"?v", " num|expr", "show hex value of math expr (no expr prints $?)",
	"?vi", "[1248] num|expr", "show decimal value of math expr [n bytes]",
	"?vx", " num|expr", "show 8 digit padding in hex",
	"?V", "", "show library version of r_core",
	"?w", " addr", "show what's in this address (like pxr/pxq does)",
	"?X", " num|expr", "returns the hexadecimal value numeric expr",
	"?x", " str", "returns the hexpair of number or string",
	"?x", "+num", "like ?v, but in hexpairs honoring cfg.bigendian",
	"?x", "-hexst", "convert hexpair into raw string with newline",
	"?_", " hudfile", "load hud menu with given file",
	"[cmd]?*", "", "recursive help for the given cmd",
	NULL
};

static RCoreHelpMessage help_msg_question_v = {
	"Usage: ?v [$.]","","",
	"flag", "", "offset of flag",
	"$", "{ev}", "get value of eval config variable",
	"$$", "", "here (current virtual seek)",
	"$$$", "", "current non-temporary virtual seek",
	"$?", "", "last comparison value",
	"$alias", "=value", "alias commands (simple macros)",
	"$B", "", "base address (aligned lowest map address)",
	"$b", "", "block size",
	"$c", "", "get terminal width in character columns",
	"$Cn", "", "get nth call of function",
	"$D", "", "current debug map base address ?v $D @ rsp",
	"$DB", "", "same as dbg.baddr, progam base address",
	"$DD", "", "current debug map size",
	"$Dn", "", "get nth data reference in function",
	"$e", "", "1 if end of block, else 0",
	"$e", "{flag}", "end of flag (flag->offset + flag->size)",
	"$f", "", "jump fail address (e.g. jz 0x10 => next instruction)",
	"$F", "", "same as $FB",
	"$Fb", "", "begin of basic block",
	"$FB", "", "begin of function",
	"$Fe", "", "end of basic block",
	"$FE", "", "end of function",
	"$Ff", "", "function false destination",
	"$Fi", "", "basic block instructions",
	"$FI", "", "function instructions",
	"$Fj", "", "function jump destination",
	"$fl", "", "flag length (size) at current address (fla; pD $l @ entry0)",
	"$FS", "", "function size (linear length)",
	"$Fs", "", "size of the current basic block",
	"$FSS", "", "function size (sum bb sizes)",
	"$i", "{n}", "address of nth instruction forward",
	"$I", "{n}", "address of nth instruction backward (s $I1@$Fe) #last instr in bb",
	"$j", "", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
	"$Ja", "", "get nth jump of function",
	"$k", "{kv}", "get value of an sdb query value",
	"$l", "", "opcode length",
	"$M", "", "map address (lowest map address)",
	"$m", "", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
	"$MM", "", "map size (lowest map address)",
	"$O", "", "cursor here (current offset pointed by the cursor)",
	"$o", "", "here (current disk io offset)",
	"$p", "", "getpid()",
	"$P", "", "pid of children (only in debug)",
	"$r", "", "get console height (in rows, see $c for columns)",
	"$r", "{reg}", "get value of named register ($r{PC} and $r:PC syntax is supported)",
	"$s", "", "file size",
	"$S", "", "section offset",
	"$SS", "", "section size",
	"$s", "{flag}", "get size of flag",
	"$v", "", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
	"$w", "", "get word size, 4 if asm.bits=32, 8 if 64, ...",
	"$Xn", "", "get nth xref of function",
	"RNum", "", "$variables usable in math expressions",
	NULL
};

static RCoreHelpMessage help_msg_question_V = {
	"Usage: ?V[jq]","","",
	"?V", "", "show version information",
	"?V0", "", "show major version",
	"?V1", "", "show minor version",
	"?V2", "", "show patch version",
	"?Vn", "", "show numeric version (2)",
	"?Vc", "", "show numeric version",
	"?Vj", "", "same as above but in JSON",
	"?Vq", "", "quiet mode, just show the version number",
	NULL
};

static RCoreHelpMessage help_msg_greater_sign = {
	"Usage:", "[cmd]>[file]", "redirects console from 'cmd' output to 'file'",
	"[cmd] > [file]", "", "redirect STDOUT of 'cmd' to 'file'",
	"[cmd] > $alias", "", "save the output of the command as an alias (see $?)",
	"[cmd] H> [file]", "", "redirect html output of 'cmd' to 'file'",
	"[cmd] 2> [file]", "", "redirect STDERR of 'cmd' to 'file'",
	"[cmd] 2> /dev/null", "", "omit the STDERR output of 'cmd'",
	NULL
};

static RCoreHelpMessage help_msg_intro = {
	"Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...", "", "",
	"Append '?' to any char command to get detailed help", "", "",
	"Prefix with number to repeat command N times (f.ex: 3x)", "", "",
	NULL
};

static void cmd_help_exclamation(RCore *core) {
	r_core_cmd_help (core, help_msg_exclamation);
	r_core_cmd_help (core, help_msg_env);
}

static void cmd_help_percent(RCore *core) {
	r_core_cmd_help (core, help_msg_percent);
	r_core_cmd_help (core, help_msg_env);
}

static const char* findBreakChar(const char *s) {
	while (*s) {
		if (!r_name_validate_char (*s)) {
			break;
		}
		s++;
	}
	return s;
}

// XXX This is an experimental test and must be implemented in RCons directly
static void colormessage(RCore *core, const char *msg) {
	size_t msglen = strlen (msg);
	const char *pad = r_str_pad (' ', msglen + 5);
	r_cons_gotoxy (10, 10); r_cons_printf (Color_BGBLUE"%s", pad);
	r_cons_gotoxy (10, 11); r_cons_printf (Color_BGBLUE"%s", pad);
	r_cons_gotoxy (10, 12); r_cons_printf (Color_BGBLUE"%s", pad);
	r_cons_gotoxy (12, 11); r_cons_printf (Color_BGBLUE""Color_WHITE"%s", msg);
	r_cons_gotoxy (0, 0);
	r_cons_printf (Color_RESET);
}

static char *filterFlags(RCore *core, const char *msg) {
	const char *dollar, *end;
	char *word, *buf = NULL;
	for (;;) {
		dollar = strchr (msg, '$');
		if (!dollar) {
			break;
		}
		buf = r_str_appendlen (buf, msg, dollar-msg);
		if (dollar[1] == '{') {
			// find }
			end = strchr (dollar + 2, '}');
			if (end) {
				word = r_str_newlen (dollar+2, end-dollar-2);
				end++;
			} else {
				msg = dollar + 1;
				buf = r_str_append (buf, "$");
				continue;
			}
		} else if (dollar[1] == '(') {
			msg = dollar + 1;
			buf = r_str_append (buf, "$");
			continue;
		} else {
			end = findBreakChar (dollar + 1);
			if (!end) {
				end = dollar + strlen (dollar);
			}
			word = r_str_newlen (dollar+1, end-dollar-1);
		}
		if (end && word) {
			ut64 val = r_num_math (core->num, word);
			char num[32];
			snprintf (num, sizeof (num), "0x%"PFMT64x, val);
			buf = r_str_append (buf, num);
			msg = end;
		} else {
			break;
		}
		free (word);
	}
	buf = r_str_append (buf, msg);
	return buf;
}

static const char *avatar_orangg[] = {
	"      _______\n"
	"     /       \\      .-%s-.\n"
	"   _| ( o) (o)\\_    | %s |\n"
	"  / _     .\\. | \\  <| %s |\n"
	"  \\| \\   ____ / 7`  | %s |\n"
	"  '|\\|  `---'/      `-%s-'\n"
	"     | /----. \\\n"
	"     | \\___/  |___\n"
	"     `-----'`-----'\n"
};

static const char *avatar_croco[] = {
	" __   __          .-%s-.\n"
	"(o |_| o)_____    | %s |\n"
	"|  ___________)  <  %s |\n"
	"\\            /    | %s |\n"
	" \\          /     `-%s-'\n"
	"  \\________/\n"
};

static const char *avatar_clippy[] = {
	" .--.     .-%s-.\n"
	" | _|     | %s |\n"
	" | O O   <  %s |\n"
	" |  |  |  | %s |\n"
	" || | /   `-%s-'\n"
	" |`-'|\n"
	" `---'\n",
	" .--.     .-%s-.\n"
	" |   \\    | %s |\n"
	" | O o   <  %s |\n"
	" |   | /  | %s |\n"
	" |  ( /   `-%s-'\n"
	" |   / \n"
	" `--'\n",
	" .--.     .-%s-.\n"
	" | _|_    | %s |\n"
	" | O O   <  %s |\n"
	" |  ||    | %s |\n"
	" | _:|    `-%s-'\n"
	" |   |\n"
	" `---'\n",
};

static const char *avatar_clippy_utf8[] = {
	" ╭──╮    ╭─%s─╮\n"
	" │ _│    │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╭   │ %s │\n"
	" ││ ││   ╰─%s─╯\n"
	" │└─┘│\n"
	" ╰───╯\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ ╶│╶   │ %s │\n"
	" │ O o  <  %s │\n"
	" │  │  ╱ │ %s │\n"
	" │ ╭┘ ╱  ╰─%s─╯\n"
	" │ ╰ ╱\n"
	" ╰──'\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ _│_   │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╷   │ %s │\n"
	" │  ││   ╰─%s─╯\n"
	" │ ─╯│\n"
	" ╰───╯\n",
};

static const char *avatar_cybcat[] = {
"     /\\.---./\\       .-%s-.\n"
" '--           --'   | %s |\n"
"----   ^   ^   ---- <  %s |\n"
"  _.-    Y    -._    | %s |\n"
"                     `-%s-'\n",
"     /\\.---./\\       .-%s-.\n"
" '--   @   @   --'   | %s |\n"
"----     Y     ---- <  %s |\n"
"  _.-    O    -._    | %s |\n"
"                     `-%s-'\n",
"     /\\.---./\\       .-%s-.\n"
" '--   =   =   --'   | %s |\n"
"----     Y     ---- <  %s |\n"
"  _.-    U    -._    | %s |\n"
"                     `-%s-'\n",
};

enum {
	R_AVATAR_ORANGG,
	R_AVATAR_CYBCAT,
	R_AVATAR_CROCO,
	R_AVATAR_CLIPPY,
};

R_API void r_core_clippy(RCore *core, const char *msg) {
	int type = R_AVATAR_CLIPPY;
	switch (*msg) {
	case '+':
	case '3':
	case 'C':
		{
			char *space = strchr (msg, ' ');
			if (!space) {
				return;
			}
			type = (*msg == '+')? R_AVATAR_ORANGG: (*msg == 'C')? R_AVATAR_CROCO: R_AVATAR_CYBCAT;
			msg = space + 1;
		}
		break;
	}
	const char *f;
	int msglen = r_str_len_utf8 (msg);
	char *s = strdup (r_str_pad (' ', msglen));
	char *l;

	switch (type) {
	case R_AVATAR_ORANGG:
		l = strdup (r_str_pad ('-', msglen));
		f = avatar_orangg[0];
		break;
	case R_AVATAR_CROCO:
		l = strdup (r_str_pad ('-', msglen));
		f = avatar_croco[0];
		break;
	case R_AVATAR_CYBCAT:
		l = strdup (r_str_pad ('-', msglen));
		f = avatar_cybcat[r_num_rand (R_ARRAY_SIZE (avatar_cybcat))];
		break;
	default:
		if (r_config_get_b (core->config, "scr.utf8")) {
			l = (char *)r_str_repeat ("─", msglen);
			f = avatar_clippy_utf8[r_num_rand (R_ARRAY_SIZE (avatar_clippy_utf8))];
		} else {
			l = strdup (r_str_pad ('-', msglen));
			f = avatar_clippy[r_num_rand (R_ARRAY_SIZE (avatar_clippy))];
		}
		break;
	}

	r_cons_printf (f, l, s, msg, s, l);
	free (l);
	free (s);
}

static int cmd_help(void *data, const char *input) {
	r_strf_buffer (256);
	RCore *core = (RCore *)data;
	RIOMap *map;
	const char *k;
	RListIter *iter;
	char *p, out[128] = {0};
	ut64 n;
	int i;
	RList *tmp;

	switch (input[0]) {
	case ':':
		// show help for ':' command
		r_core_cmd_help_match (core, help_msg_at, ":");
		break;
	case 't': { // "?t"
		switch (input[1]) {
		case '0':
			core->curtab = 0;
			break;
		case '1':
			if (core->curtab < 0) {
				core->curtab = 0;
			}
			core->curtab ++;
			break;
		case '"':
			{
				struct r_prof_t prof;
				r_prof_start (&prof);
				if (input[1] == '"') {
					r_core_cmd_call (core, input + 3);
				} else {
					r_core_cmd (core, input + 1, 0);
				}
				r_prof_end (&prof);
				r_core_return_value (core, (ut64)(int)prof.result);
				eprintf ("%lf\n", prof.result);
			}
			break;
		case ' ':
			{
				struct r_prof_t prof;
				r_prof_start (&prof);
				r_core_cmd (core, input + 1, 0);
				r_prof_end (&prof);
				r_core_return_value (core, (ut64)(int)prof.result);
				r_cons_printf ("%lf\n", prof.result);
				break;
			}
		default:
			r_core_cmd_help (core, help_msg_question_t);
			break;
		}
		break;
		}
	case 'r': // "?r"
		{ // TODO : Add support for 64bit random numbers
		ut64 b = 0;
		ut32 r = UT32_MAX;
		if (input[1]) {
			strncpy (out, input + (input[1] == ' '? 2: 1), sizeof (out)-1);
			p = strchr (out + 1, ' ');
			if (p) {
				*p = 0;
				b = (ut32)r_num_math (core->num, out);
				r = (ut32)r_num_math (core->num, p + 1) - b;
			} else {
				r = (ut32)r_num_math (core->num, out);
			}
		} else {
			r = 0LL;
		}
		if (!r) {
			r = UT32_MAX >> 1;
		}
		ut64 n = (ut64)b + r_num_rand (r);
		r_core_return_value (core, n);
		r_cons_printf ("0x%"PFMT64x"\n", n);
		}
		break;
	case '\'': // "?'"
		r_core_cmd_help (core, help_msg_single_quote);
		break;
	case 'a': // "?a"
		r_cons_printf ("%s", r_str_asciitable ());
		break;
	case 'b': // "?b"
		if (input[1] == '6' && input[2] == '4') {
			//b64 decoding takes at most strlen(str) * 4
			const int buflen = (strlen (input + 3) * 4) + 1;
			char* buf = calloc (buflen, sizeof (char));
			if (!buf) {
				return false;
			}
			if (input[3] == '-') {
				r_base64_decode ((ut8*)buf, input + 4, -1);
			} else if (input[3] == ' ') {
				r_base64_encode (buf, (const ut8*)input + 4, -1);
			}
			r_cons_println (buf);
			free (buf);
		} else if (input[1] == 't' && input[2] == 'w') { // "?btw"
			if (r_num_between (core->num, input + 3) == -1) {
				r_core_cmd_help_match (core, help_msg_question, "?btw");
			}
		} else {
			n = r_num_math (core->num, input + 1);
			r_num_to_bits (out, n);
			r_cons_printf ("%sb\n", out);
		}
		break;
	case 'B': // "?B"
		k = r_str_trim_head_ro (input + 1);
		tmp = r_core_get_boundaries_prot (core, -1, k, "search");
		if (!tmp) {
			return false;
		}
		r_list_foreach (tmp, iter, map) {
			r_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
		}
		r_list_free (tmp);
		break;
	case 'h': // "?h"
		if (input[1] == ' ') {
			r_cons_printf ("0x%08x\n", (ut32)r_str_hash (input + 2));
		} else {
			r_core_cmd_help_contains (core, help_msg_question, "?h");
		}
		break;
	case 'F': // "?F"
		r_cons_flush ();
		break;
	case 'f': // "?f"
		if (input[1] == ' ') {
			char *q, *p = strdup (input + 2);
			if (!p) {
				R_LOG_ERROR ("Cannot strdup");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n) * 8, q + 1);
				r_cons_println (out);
			} else {
				r_core_cmd_help_match (core, help_msg_question, "?f");
			}
			free (p);
		} else {
			r_core_cmd_help_match (core, help_msg_question, "?f");
		}
		break;
	case 'o': // "?o"
		n = r_num_math (core->num, input+1);
		r_cons_printf ("0%"PFMT64o"\n", n);
		break;
	case 'T': // "?T"
		if (input[1] == 'j') {
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			pj_kn (pj, "plug.init", core->times->loadlibs_init_time);
			pj_kn (pj, "plug.load", core->times->loadlibs_time);
			pj_kn (pj, "file.load", core->times->file_open_time);
			pj_kn (pj, "file.anal", core->times->file_anal_time);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf ("%s\n", s);
			free (s);
		} else {
			r_cons_printf ("plug.init = %"PFMT64d"\n"
				"plug.load = %"PFMT64d"\n"
				"file.load = %"PFMT64d"\n"
				"file.anal = %"PFMT64d"\n",
				core->times->loadlibs_init_time,
				core->times->loadlibs_time,
				core->times->file_open_time,
				core->times->file_anal_time);
		}
		break;
	case 'u': // "?u"
		{
			char unit[8];
			n = r_num_math (core->num, input + 1);
			r_num_units (unit, sizeof (unit), n);
			r_cons_println (unit);
		}
		break;
	case 'j': // "?j"
	case ' ': // "? "
		{
			char unit[8];
			double d;
			float f;
			char * const inputs = strdup (input + 1);
			RList *list = r_num_str_split_list (inputs);
			const int list_len = r_list_length (list);
			PJ *pj = NULL;
			if (*input ==  'j') {
				pj = r_core_pj_new (core);
				pj_o (pj);
			}
			const int segbas = core->rasm->config->segbas;
			const int seggrn = core->rasm->config->seggrn;
			for (i = 0; i < list_len; i++) {
				const char *str = r_list_pop_head (list);
				if (!*str) {
					continue;
				}
				const char *err = NULL;
				n = r_num_calc (core->num, str, &err);
				if (core->num->dbz) {
					R_LOG_ERROR ("Division by Zero");
				}
				if (err) {
					R_LOG_ERROR (err);
					continue;
				}
				char *asnum  = r_num_as_string (NULL, n, false);

				ut32 s = 0, a = 0;
				r_num_segaddr (n, segbas, seggrn, &s, &a);
				r_num_units (unit, sizeof (unit), n);
				if (*input ==  'j') {
					pj_ks (pj, "int32", r_strf ("%d", (st32)(n & UT32_MAX)));
					pj_ks (pj, "uint32", r_strf ("%u", (ut32)n));
					pj_ks (pj, "int64", r_strf ("%"PFMT64d, (st64)n));
					pj_ks (pj, "uint64", r_strf ("%"PFMT64u, (ut64)n));
					pj_ks (pj, "hex", r_strf ("0x%08"PFMT64x, n));
					pj_ks (pj, "octal", r_strf ("0%"PFMT64o, n));
					pj_ks (pj, "unit", unit);
					pj_ks (pj, "segment", r_strf ("%04x:%04x", s, a));
				} else {
					if (n >> 32) {
						r_cons_printf ("int64   %"PFMT64d"\n", (st64)n);
						r_cons_printf ("uint64  %"PFMT64u"\n", (ut64)n);
					} else {
						r_cons_printf ("int32   %d\n", (st32)n);
						r_cons_printf ("uint32  %u\n", (ut32)n);
					}
					r_cons_printf ("hex     0x%"PFMT64x"\n", n);
					r_cons_printf ("octal   0%"PFMT64o"\n", n);
					r_cons_printf ("unit    %s\n", unit);
					r_cons_printf ("segment %04x:%04x\n", s, a);

					if (asnum) {
						r_cons_printf ("string  \"%s\"\n", asnum);
						free (asnum);
					}
				}
				/* binary and floating point */
				r_str_bits64 (out, n);
				f = d = core->num->fvalue;
				memcpy (&f, &n, sizeof (f));
				memcpy (&d, &n, sizeof (d));
				/* adjust sign for nan floats, different libcs are confused */
				if (isnan (f) && signbit (f)) {
					f = -f;
				}
				if (isnan (d) && signbit (d)) {
					d = -d;
				}
				if (*input ==  'j') {
					pj_ks (pj, "fvalue", r_strf ("%.1lf", core->num->fvalue));
					pj_ks (pj, "float", r_strf ("%ff", f));
					pj_ks (pj, "double", r_strf ("%lf", d));
					pj_ks (pj, "binary", r_strf ("0b%s", out));
					char b36str[16];
					b36_fromnum (b36str, n);
					pj_ks (pj, "base36", b36str);
					r_num_to_ternary (out, n);
					pj_ks (pj, "ternary", r_strf ("0t%s", out));
				} else {
					r_cons_printf ("fvalue  %.1lf\n", core->num->fvalue);
					r_cons_printf ("float   %ff\n", f);
					r_cons_printf ("double  %lf\n", d);
					r_cons_printf ("binary  0b%s\n", out);
					char b36str[16];
					b36_fromnum (b36str, n);
					r_cons_printf ("base36  %s\n", b36str);
					r_num_to_ternary (out, n);
					r_cons_printf ("ternary 0t%s\n", out);
				}
			}
			if (*input ==  'j') {
				pj_end (pj);
			}
			free (inputs);
			r_list_free (list);
			if (pj) {
				r_cons_printf ("%s\n", pj_string (pj));
				pj_free (pj);
			}
		}
		break;
	case 'q': // "?q"
		if (core->num->dbz) {
			R_LOG_ERROR ("Division by Zero");
		}
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_question, "?q");
		} else {
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else {
				n = r_num_math (core->num, "$?");
			}
			r_core_return_value (core, n);
		}
		break;
	case 'v': // "?v"
		{
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else if (input[1] == ':') {
				n = r_num_math (core->num, input + 2);
			} else if (input[1] && input[2] == ':') {
				n = r_num_math (core->num, input + 3);
			} else {
				n = r_num_math (core->num, "$?");
			}
			if (core->num->nc.errors > 0) {
				R_LOG_ERROR (core->num->nc.calc_err);
			}
			if (core->num->dbz) {
				R_LOG_ERROR ("Division by Zero");
			}
		}
		switch (input[1]) {
		case '?':
			r_core_cmd_help_contains (core, help_msg_question, "?v");
			break;
		case '\0':
			r_cons_printf ("%d\n", (st32)n);
			break;
		case 'x': // "?vx"
			r_cons_printf ("0x%08"PFMT64x"\n", n);
			break;
		case 'i': // "?vi"
			switch (input[2]) {
			case '1': // byte
				r_cons_printf ("%d\n", (st8)(n & UT8_MAX));
				break;
			case '2': // word
				r_cons_printf ("%d\n", (st16)(n & UT16_MAX));
				break;
			case '4': // dword
				r_cons_printf ("%d\n", (st32)(n & UT32_MAX));
				break;
			case '8': // qword
				r_cons_printf ("%"PFMT64d"\n", (st64)(n & UT64_MAX));
				break;
			default:
				r_cons_printf ("%"PFMT64d"\n", n);
				break;
			}
			break;
		case 'd':
			r_cons_printf ("%"PFMT64d"\n", n);
			break;
		default:
			r_cons_printf ("0x%"PFMT64x"\n", n);
		}
		r_core_return_value (core, n); // redundant
		break;
	case '=': // "?=" set num->value
		if (input[1] == '=') { // ?==
			if (input[2] == ' ') {
				char *s = strdup (input + 3);
				char *e = strchr (s, ' ');

				if (e) {
					*e++ = 0;
					e = (char *)r_str_trim_head_ro (e);
					int val = strcmp (s, e);
					r_core_return_value (core, val);
				} else {
					R_LOG_ERROR ("Missing secondary word in expression to compare");
				}
				free (s);
			} else {
				r_core_cmd_help_match (core, help_msg_question, "?==");
			}
		} else {
			if (input[1]) { // ?=
				r_num_math (core->num, input+1);
			} else {
				r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
			}
		}
		break;
	case '+': // "?+"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n > 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '-': // "?-"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n < 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '!': // "?!"
		if (input[1]) {
			if (!core->num->value) {
				if (input[1] == '?') {
					cmd_help_exclamation (core);
					return 0;
				}
				int cmdres = r_core_cmd (core, input + 1, 0);
				r_core_return_value (core, cmdres);
				return cmdres;
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '@': // "?@"
		if (input[1] == '@') {
			if (input[2] == '@') {
				r_core_cmd_help (core, help_msg_at_at_at);
			} else {
				r_core_cmd_help (core, help_msg_at_at);
			}
		} else {
			r_core_cmd_help (core, help_msg_at);
		}
		break;
	case '&': // "?&"
		r_core_cmd_help (core, help_msg_amper);
		break;
	case '%': // "?%"
		if (input[1] == '?') {
			cmd_help_percent (core);
		}
		break;
	case '$': // "?$"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_question_v);
		} else {
			int i = 0;
			const char *vars[] = {
				"$$", "$$$", "$?", "$B", "$b", "$c", "$Cn", "$D", "$DB", "$DD", "$Dn",
				"$e", "$f", "$F", "$Fb", "$FB", "$Fe", "$FE", "$Ff", "$Fi", "$FI", "$Fj",
				"$fl", "$FS", "$Fs", "$FSS", "$i", "$j", "$Ja", "$l", "$M", "$m", "$MM", "$O",
				"$o", "$p", "$P", "$r", "$s", "$S", "$SS", "$v", "$w", "$Xn", NULL
			};
			const bool wideOffsets = r_config_get_i (core->config, "scr.wideoff");
			while (vars[i]) {
				const char *pad = r_str_pad (' ', 6 - strlen (vars[i]));
				if (wideOffsets) {
					eprintf ("%s %s 0x%016"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				} else {
					eprintf ("%s %s 0x%08"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				}
				i++;
			}
		}
		return true;
	case 'V': // "?V"
		switch (input[1]) {
		case '?': // "?V?"
			r_core_cmd_help (core, help_msg_question_V);
			break;
		case 0: // "?V"
			{
				char *v = r_str_version ("radare2");
				if (v) {
					r_cons_printf ("%s\n", v);
				}
				free (v);
			}
			break;
		case 'c': // "?Vc"
			r_cons_printf ("%d\n", vernum (R2_VERSION));
			break;
		case 'j': // "?Vj"
			{
				PJ *pj = pj_new ();
				pj_o (pj);
				pj_ks (pj, "arch", R_SYS_ARCH);
				pj_ks (pj, "os", R_SYS_OS);
				pj_ki (pj, "bits", R_SYS_BITS);
				pj_ki (pj, "commit", R2_VERSION_COMMIT);
				pj_ks (pj, "tap", R2_GITTAP);
				pj_ki (pj, "major", R2_VERSION_MAJOR);
				pj_ki (pj, "minor", R2_VERSION_MINOR);
				pj_ki (pj, "patch", R2_VERSION_PATCH);
				pj_ki (pj, "number", R2_VERSION_NUMBER);
				pj_ki (pj, "nversion", vernum (R2_VERSION));
				pj_ks (pj, "version", R2_VERSION);
				pj_end (pj);
				r_cons_printf ("%s\n", pj_string (pj));
				pj_free (pj);
			}
			break;
		case 'n': // "?Vn"
			r_cons_printf ("%d\n", R2_VERSION_NUMBER);
			break;
		case 'q': // "?Vq"
			r_cons_println (R2_VERSION);
			break;
		case '0':
			r_cons_printf ("%d\n", R2_VERSION_MAJOR);
			break;
		case '1':
			r_cons_printf ("%d\n", R2_VERSION_MINOR);
			break;
		case '2':
			r_cons_printf ("%d\n", R2_VERSION_PATCH);
			break;
		}
		break;
	case 'l': // "?l"
		if (input[1] == 'q') {
			for (input += 2; input[0] == ' '; input++);
			r_core_return_value (core, strlen (input));
		} else {
			for (input++; input[0] == ' '; input++);
			r_core_return_value (core, strlen (input));
			r_cons_printf ("%" PFMT64d "\n", core->num->value);
		}
		break;
	case 'X': // "?X"
		for (input++; input[0] == ' '; input++);
		n = r_num_math (core->num, input);
		r_cons_printf ("%"PFMT64x"\n", n);
		break;
	case 'x': // "?x"
		for (input++; input[0] == ' '; input++);
		if (*input == '-') {
			ut8 *out = malloc (strlen (input) + 1);
			if (out) {
				int len = r_hex_str2bin (input + 1, out);
				if (len >= 0) {
					out[len] = 0;
					r_cons_println ((const char*)out);
				} else {
					R_LOG_ERROR ("invalid hexpair string");
				}
				free (out);
			}
		} else if (*input == '+') {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i = 0; i < bits; i++) {
				r_cons_printf ("%02x", (ut8)((n >> (i * 8)) &0xff));
			}
			r_cons_newline ();
		} else {
			if (*input == ' ') {
				input++;
			}
			for (i = 0; input[i]; i++) {
				r_cons_printf ("%02x", input[i]);
			}
			r_cons_newline ();
		}
		break;
	case 'E': // "?E" clippy echo
		r_core_clippy (core, r_str_trim_head_ro (input + 1));
		break;
	case 'e': // "?e" echo
		if (input[1] == ' ' && (input[2] == '"' || input[2] == '\'')) {
			r_str_trim_args ((char *)input);
		}
		switch (input[1]) {
		case 'a': // "?ea hello world
			{
				char *s = r_str_ss (r_str_trim_head_ro (input + 2), NULL, 0);
				r_cons_println (s);
				free (s);
			}
			break;
		case 't': // "?et" "?e=t newtitle"
			r_cons_set_title (r_str_trim_head_ro (input + 2));
			break;
		case '=': { // "?e="
			ut64 pc = r_num_math (core->num, input + 2);
			r_print_progressbar (core->print, pc, 80, NULL);
			r_cons_newline ();
			break;
		}
		case 'b': { // "?eb"
			char *arg = strdup (r_str_trim_head_ro (input + 2));
			int n = r_str_split (arg, ' ');
			ut64 *portions = calloc (n, sizeof (ut64));
			for (i = 0; i < n; i++) {
				portions[i] = r_num_math (core->num, r_str_word_get0 (arg, i));
			}
			r_print_portionbar (core->print, portions, n);
			R_FREE (arg);
			R_FREE (portions);
			break;
		}
		case 's': // "?es"
			  {
				  char *msg = strdup (input + 2);
				  r_str_trim (msg);
				  char *p = strchr (msg, '&');
				  if (p) {
					  *p = 0;
				  }
				  r_sys_tts (msg, p);
				  free (msg);
			  }
			break;
		case 'c': // "?ec" column
			r_cons_column (r_num_math (core->num, input + 2));
			break;
		case 'v':
			colormessage (core, input + 2);
			break;
		case 'g': { // "?eg" gotoxy
			int x = atoi (input + 2);
			char *arg = strchr (input + 2, ' ');
			int y = arg? atoi (arg + 1): 0;
			r_cons_gotoxy (x, y);
			}
			break;
		case 'n': { // "?en" echo -n
			const char *msg = r_str_trim_head_ro (input + 2);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_print (newmsg);
			free (newmsg);
			break;
		}
		case 'f': // "?ef"
			{
				const char *text = r_str_trim_head_ro (input + 2);
				int len = strlen (text) + 2;
				RStrBuf *b = r_strbuf_new ("");
				r_strbuf_append (b, ".");
				r_strbuf_append (b, r_str_pad('-', len));
				r_strbuf_append (b, ".\n");
				r_strbuf_append (b, "| ");
				r_strbuf_append (b, text);
				r_strbuf_append (b, " |\n");
				r_strbuf_append (b, "'");
				r_strbuf_append (b, r_str_pad('-', len));
				r_strbuf_append (b, "'\n");
				char * s = r_strbuf_drain (b);
				r_cons_print (s);
				free (s);
			}
			break;
		case 'e': // "?ee"
			eprintf ("%s\n", r_str_trim_head_ro (input + 2));
			break;
		case 'i': // "?ei"
			R_LOG_INFO ("%s", r_str_trim_head_ro (input + 2));
			break;
		case 'd': // "?ed"
			  if (input[2] == 'd') {
				  int i,j;
				  r_cons_show_cursor (0);
				  r_cons_clear00 ();
				  for (i = 1; i < 100; i++) {
					  if (r_cons_is_breaked ()) {
						  break;
					  }
					  for (j = 0; j < 20; j++) {
						  char *d = r_str_donut (i);
						  r_cons_gotoxy (0,0);
						  r_str_trim_tail (d);
						  r_cons_clear_line (0);
						  r_cons_printf ("Downloading the Gibson...\n\n");
						  r_core_cmdf (core, "?e=%d", i);
						  r_cons_print (d);
						  r_cons_clear_line (0);
						  r_cons_newline ();
						  free (d);
						  r_cons_flush ();
						  r_sys_usleep (2000);
					  }
				  }
				  r_cons_clear00();
				  r_cons_printf ("\nPayload installed. Thanks for your patience.\n\n");
			} else {
				  char *d = r_str_donut (r_num_math (core->num, input + 2));
				  r_str_trim_tail (d);
				  const char *color = (core->cons && core->cons->context->pal.flag)? core->cons->context->pal.flag: "";
				  r_cons_printf ("%s%s", color, d);
				  r_cons_newline ();
				  free (d);
			}
			break;
		case 'p':
			  {
			char *word, *str = strdup (input + 2);
				  RList *list = r_str_split_list (str, " ", 0);
				  ut64 *nums = calloc (sizeof (ut64), r_list_length (list));
				  int i = 0;
				  r_list_foreach (list, iter, word) {
					nums[i] = r_num_math (core->num, word);
					i++;
				  }
				  int size = r_config_get_i (core->config, "hex.cols");
				  r_print_pie (core->print, nums, r_list_length (list), size);
				  r_list_free (list);
			  }
			break;
		case ' ': {
			const char *msg = r_str_trim_head_ro (input+1);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_println (newmsg);
			free (newmsg);
			}
			break;
		case 0:
			r_cons_newline ();
			break;
		default:
			r_core_cmd_help (core, help_msg_question_e);
			break;
		}
		break;
	case 's': { // "?s" sequence from to step
		ut64 from, to, step;
		char *p, *p2;
		for (input++; *input == ' '; input++);
		p = strchr (input, ' ');
		if (p) {
			*p = '\0';
			from = r_num_math (core->num, input);
			p2 = strchr (p+1, ' ');
			if (p2) {
				*p2 = '\0';
				step = r_num_math (core->num, p2 + 1);
			} else {
				step = 1;
			}
			to = r_num_math (core->num, p + 1);
			for (;from <= to; from += step)
				r_cons_printf ("%"PFMT64d" ", from);
			r_cons_newline ();
		}
		break;
	}
	case 'P': // "?P"
		if (core->io->va) {
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			RIOMap *map = r_io_map_get_paddr (core->io, n);
			if (map) {
				o = n + r_io_map_begin (map) - map->delta;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf ("no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf ("0x%08"PFMT64x"\n", core->offset);
		}
		break;
	case 'p': // "?p"
		if (core->io->va) {
			// physical address
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input + 2): core->offset;
			RIOMap *map = r_io_map_get_at (core->io, n);
			if (map) {
				o = n - r_io_map_begin (map) + map->delta;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf ("no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf ("0x%08"PFMT64x"\n", core->offset);
		}
		break;
	case '_': // "?_" hud input
		r_core_yank_hud_file (core, input+1);
		break;
	case 'i': // "?i" input num
		r_cons_set_raw(0);
		if (!r_cons_is_interactive ()) {
			R_LOG_ERROR ("Not running in interactive mode");
		} else {
			switch (input[1]) {
			case '?': // "?i?"
				r_core_cmd_help (core, help_msg_question_i);
				break;
			case 'f': // "?if"
				r_core_return_value (core, !r_num_conditional (core->num, input + 2));
				eprintf ("%s\n", r_str_bool (!core->num->value));
				break;
			case 'm': // "?im"
				r_cons_message (input + 2);
				break;
			case 'p': // "?ip"
				{
					const bool interactive = r_config_get_b (core->config, "scr.interactive");
					if (interactive) {
						r_core_return_value (core, r_core_yank_hud_path (core, input + 2, 0) == true);
					} else {
						R_LOG_WARN ("?ip requires scr.interactive=true");
					}
				}
				break;
			case 'e': // "?ie"
				{
				char foo[1024];
				r_cons_flush ();
				for (input+=2; *input == ' '; input++);
				// TODO: r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (foo);
				r_cons_fgets (foo, sizeof (foo), 0, NULL);
				foo[sizeof (foo) - 1] = 0;
				r_cons_printf ("%s\n", foo);
				r_core_return_value (core, 0);
				}
				break;
			case 'k': // "?ik"
				 r_cons_any_key (NULL);
				 break;
			case 'y': // "?iy"
				 for (input += 2; *input == ' '; input++);
				 r_core_return_value (core, r_cons_yesno (1, "%s? (Y/n)", input));
				 break;
			case 'n': // "?in"
				 for (input += 2; *input == ' '; input++);
				 r_core_return_value (core, r_cons_yesno (0, "%s? (y/N)", input));
				 break;
			default: {
				char foo[1024];
				r_cons_flush ();
				for (input++; *input == ' '; input++);
				// TODO: r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (foo);
				r_cons_fgets (foo, sizeof (foo), 0, NULL);
				foo[sizeof (foo) - 1] = 0;
				r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, foo, strlen (foo) + 1);
				r_core_return_value (core, r_num_math (core->num, foo));
				}
				break;
			}
		}
		r_cons_set_raw (0);
		break;
	case 'w': // "?w"
		{
			  ut64 addr = r_num_math (core->num, input + 1);
			  char *rstr = core->print->hasrefs (core->print->user, addr, true);
			  if (!rstr) {
				  R_LOG_ERROR ("Cannot get refs at 0x%08"PFMT64x, addr);
				  break;
			  }
			  r_cons_println (rstr);
			  free (rstr);
		}
		break;
	case '?': // "??"
		if (input[1] == '?') {
			if (input[2] == '?') { // "???"
				r_core_clippy (core, "What are you doing?");
				return 0;
			}
			if (input[2]) {
				if (core->num->value) {
					r_core_cmd (core, input + 1, 0);
				}
				break;
			}
			r_core_cmd_help (core, help_msg_question);
			return 0;
		} else if (input[1]) {
			if (core->num->value) {
				r_core_return_value (core, r_core_cmd (core, input + 1, 0));
			}
		} else {
			if (core->num->dbz) {
				R_LOG_ERROR ("Division by Zero");
			}
			r_cons_printf ("%"PFMT64d"\n", core->num->value);
		}
		break;
	case '\0': // "?"
	default:
		// TODO #7967 help refactor
		r_core_cmd_help (core, help_msg_intro);
		r_core_cmd_help (core, help_msg_root);
		break;
	}
	return 0;
}
#endif
